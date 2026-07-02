use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore, mpsc};

use crate::routing::{RouteRule, Scheme, Transport, Verdict, find_matching_route};
use crate::sock_mark;
use crate::transparent::{self, Protocol};

/// Type-erased stream used for the Lens Sandbox upstream tunnel. Either a raw
/// `TcpStream` (plain HTTP CONNECT proxy) or a `TlsStream<TcpStream>` when
/// the policy URL uses `https://`. The trait alias keeps the public surface
/// short; both `AsyncRead` and `AsyncWrite` are required so the same
/// downstream pipeline (CONNECT handshake, MITM, copy_bidirectional) works
/// for both.
pub trait UpstreamStream: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> UpstreamStream for T {}

pub type BoxedSandboxStream = Box<dyn UpstreamStream + Send + Unpin>;

/// Lens Sandbox upstream extracted from the policy message.
#[derive(Debug, Clone)]
pub struct SandboxUpstream {
    pub host: String,
    pub port: u16,
    pub auth_header: Option<String>,
    /// `true` when the policy URL used `https://`. We TLS-wrap the TCP socket
    /// before writing the CONNECT envelope so the proxy-auth token doesn't
    /// ride plaintext over an untrusted path (BYOA, cross-region NLB).
    pub tls: bool,
}

/// How long to suppress duplicate audit events for the same host.
const AUDIT_DEDUP_SECS: u64 = 10;

/// A single header injection for a credential bound to a domain.
#[derive(Debug, Clone)]
pub struct CredentialInjection {
    pub header: String,
    pub value: String,
    /// Optional path rules. When present, only inject for matching requests.
    /// When empty, inject for all requests to the domain.
    pub rules: Vec<crate::policy_schema::HttpRule>,
}

/// Client certificate configuration for mTLS upstream connections.
/// Used for kubeconfig-style credentials where the proxy presents
/// client certificates to the upstream server on behalf of the agent.
///
/// `PrivateKeyDer` does not implement `Clone` — use `clone_key()` manually.
#[derive(Debug)]
pub struct ClientCertConfig {
    pub cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    pub private_key: rustls::pki_types::PrivateKeyDer<'static>,
    pub ca_certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    pub dial_addr: String,
    pub tls_server_name: String,
    /// Original Host header to send to upstream. When set, the TLS bridge
    /// rewrites the Host header in the first HTTP request to this value.
    /// Used for path-based gateways (e.g. Rancher) that route by Host.
    pub upstream_host_header: Option<String>,
}

impl Clone for ClientCertConfig {
    fn clone(&self) -> Self {
        Self {
            cert_chain: self.cert_chain.clone(),
            private_key: self.private_key.clone_key(),
            ca_certs: self.ca_certs.clone(),
            dial_addr: self.dial_addr.clone(),
            tls_server_name: self.tls_server_name.clone(),
            upstream_host_header: self.upstream_host_header.clone(),
        }
    }
}

/// Shared state for the proxy — upstream + routes can be updated at runtime.
pub struct ProxyState {
    pub upstream: Mutex<Option<SandboxUpstream>>,
    pub routes: RwLock<Vec<RouteRule>>,
    pub default_verdict: RwLock<Verdict>,
    pub default_transport: RwLock<Transport>,
    pub audit_tx: std::sync::Mutex<Option<mpsc::UnboundedSender<String>>>,
    pub(crate) deny_dedup: std::sync::Mutex<HashMap<String, Instant>>,
    /// Credential injections received via policy — maps domain to headers.
    /// Used for MITM header injection in the sandbox proxy.
    pub credential_injections: RwLock<HashMap<String, Vec<CredentialInjection>>>,
    /// Ephemeral CA for MITM TLS interception — lazily initialized on first
    /// policy with credentials or HTTP rules.
    pub ephemeral_ca: std::sync::OnceLock<Arc<crate::ca::EphemeralCa>>,
    /// Client certificate configs for mTLS upstream connections (e.g. kube API).
    /// Keyed by "host:port" (e.g. "host.docker.internal:6443").
    pub client_certs: RwLock<HashMap<String, ClientCertConfig>>,
    /// Domain-scoped credential placeholder → real value mapping for URI rewriting.
    /// Keyed by domain (lowercase). Only domains with `uriPlaceholder` injections
    /// trigger MITM for URI rewriting (not globally).
    pub uri_placeholder_injections: RwLock<HashMap<String, Vec<(String, String)>>>,
    /// Extra CA certs to trust for upstream TLS (e.g. proxy CA for self-signed Lens Sandbox).
    pub extra_ca_certs: RwLock<Vec<rustls::pki_types::CertificateDer<'static>>>,
    /// Cached `TlsConnector` for the Lens Sandbox upstream, built from webpki
    /// roots + `extra_ca_certs` on first use. Cleared whenever `extra_ca_certs`
    /// changes so the next CONNECT picks up the updated CA bundle. `TlsConnector`
    /// holds `Arc<ClientConfig>` so cloning is cheap.
    pub(crate) sandbox_tls_connector: RwLock<Option<tokio_rustls::TlsConnector>>,
    /// Paths of files written by the last policy message — cleaned up before writing new ones.
    pub previous_policy_files: RwLock<Vec<String>>,
    /// Sandbox user credentials for chowning policy files.
    pub sandbox_creds: Option<crate::privilege::SandboxCredentials>,
    /// AWS SigV4 re-sign interceptor. Owns the placeholder → real-STS-creds
    /// map and the domain patterns that trigger re-signing. Real STS session
    /// credentials live only in this process memory — they never touch the
    /// sandbox filesystem or agent process memory.
    pub aws_resign: Arc<crate::aws_resign::AwsResignInterceptor>,
    /// Just-in-time approval gate: dedup map of host → pending decision +
    /// id → host lookup for inbound `request_decision` frames.
    pub(crate) pending: std::sync::Mutex<crate::gate::PendingTable<crate::protocol::Decision>>,
    /// Sibling table for credential dialogs — see
    /// [`crate::gate::credential_gate_or_deny`].
    pub(crate) credential_pending:
        std::sync::Mutex<crate::gate::PendingTable<crate::protocol::CredentialDecisionKind>>,
    /// Map of placeholder string → credential id, populated from the
    /// policy frame's `credentials` array. The MITM scans outbound
    /// request bytes against this map's keys; a placeholder that survives
    /// injection (its credential is unarmed for the request's domain) makes
    /// the MITM call [`crate::gate::credential_gate_or_deny`] to hold the
    /// request and emit `credential_pending`. Updated atomically on every
    /// policy apply.
    pub placeholder_index: RwLock<HashMap<String, String>>,
    /// Domain patterns of credential injections that are still unarmed
    /// (empty `value`), sourced from [`crate::policy_schema::CredentialInjection::unarmed_domain`]
    /// on each policy apply. A CONNECT target matching any of these is MITM'd
    /// even with no armed injection, so the first, pre-arm use of the
    /// placeholder is decrypted and trips the credential gate instead of
    /// leaking. Scoped per-host via [`Self::intercept_for_unarmed`] rather
    /// than intercepting all egress; empties once every injection is armed.
    pub unarmed_credential_domains: RwLock<Vec<String>>,
    /// How long the gate waits for a developer response before defaulting
    /// to a deny. Mutable for tests; production callers leave it at
    /// `gate::DECISION_TIMEOUT`.
    pub(crate) decision_timeout: std::sync::RwLock<Duration>,
    /// How long [`connect_sandbox_upstream`] waits for the TCP connect and TLS
    /// handshake to the forward-proxy upstream before returning an error.
    /// Mutable for tests; production callers leave it at `UPSTREAM_CONNECT_TIMEOUT`.
    pub(crate) upstream_connect_timeout: std::sync::RwLock<Duration>,
    /// Hostnames the supervisor itself needs to resolve before any policy
    /// arrives — chiefly the Lens Sandbox host. The DNS stub checks this list
    /// before the policy-driven `routes`, so the supervisor's bootstrap
    /// `getaddrinfo()` succeeds even with an empty policy. Set once at
    /// construction; never mutated.
    pub bootstrap_dns_allowlist: Vec<String>,
    /// Hostnames the JIT approval gate has allowed this session (lowercased,
    /// bare host). The DNS stub consults this after the policy `routes`, so a
    /// just-approved host resolves immediately — without waiting for the
    /// follow-up `policy` frame (the "allow always" first-request race) and
    /// even for an "allow once" decision that never persists a route. Only a
    /// developer's gate click adds entries, so the workload can't grow it to
    /// open a DNS exfil channel for names nobody approved.
    pub(crate) gate_resolved_hosts: RwLock<HashSet<String>>,
}

impl ProxyState {
    /// Whether `target_host` matches the domain of any still-unarmed
    /// credential and so must be MITM'd to gate its first use — see
    /// [`Self::unarmed_credential_domains`].
    pub(crate) fn intercept_for_unarmed(&self, target_host: &str) -> bool {
        self.unarmed_credential_domains
            .read()
            .unwrap()
            .iter()
            .any(|pattern| crate::routing::injection_matches(pattern, target_host))
    }

    /// Override the gate timeout. Test-only seam; production keeps the
    /// `gate::DECISION_TIMEOUT` default set at construction.
    #[cfg(test)]
    pub(crate) fn decision_timeout_override(&self, d: Duration) {
        *self.decision_timeout.write().unwrap() = d;
    }
}

/// Collect URI placeholder pairs (placeholder → real value) that match the
/// given target host. Returns an empty vec if no domains match.
pub(crate) fn collect_uri_placeholders(
    state: &ProxyState,
    target_host: &str,
) -> Vec<(String, String)> {
    let map = state.uri_placeholder_injections.read().unwrap();
    let mut matched = Vec::new();
    for (pattern, pairs) in map.iter() {
        if crate::routing::injection_matches(pattern, target_host) {
            matched.extend(pairs.iter().cloned());
        }
    }
    matched
}

/// Collect header credential injections whose domain pattern matches the
/// given target host. `credential_injections` is keyed by the credential's
/// configured domain *pattern* (wildcards, port-specific, etc.), so matching
/// must go through `injection_matches`, not an exact key lookup — otherwise a
/// credential armed under `*.example.com` would never satisfy a request to
/// `api.example.com`.
pub(crate) fn collect_header_injections(
    state: &ProxyState,
    target_host: &str,
) -> Vec<CredentialInjection> {
    let map = state.credential_injections.read().unwrap();
    let mut matched = Vec::new();
    for (pattern, injs) in map.iter() {
        if crate::routing::injection_matches(pattern, target_host) {
            matched.extend(injs.iter().cloned());
        }
    }
    matched
}

/// Get or initialize the ephemeral CA for MITM TLS interception.
/// Also installs the CA cert into the system trust store (idempotent).
/// Uses `get_or_init` to ensure only one CA is created under contention.
fn get_or_init_ca(
    state: &ProxyState,
) -> Result<&Arc<crate::ca::EphemeralCa>, Box<dyn std::error::Error + Send + Sync>> {
    Ok(state.ephemeral_ca.get_or_init(|| {
        let ca = Arc::new(
            crate::ca::EphemeralCa::new()
                .unwrap_or_else(|e| panic!("failed to create ephemeral CA: {e}")),
        );
        crate::ca::install_ca_cert(ca.ca_cert_pem());
        tracing::info!("ephemeral CA generated and installed for MITM (proxy path)");
        ca
    }))
}

const MAX_CONCURRENT_CONNECTIONS: usize = 256;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound the TCP connect + TLS handshake to the forward-proxy upstream. Without
/// it, a black-holed upstream (e.g. a stale/unreachable address or a
/// security group that drops the SYN) hangs until the OS TCP stack gives up
/// (~2 min) — long past any client's patience and never reaching the per-CONNECT
/// `HEADER_READ_TIMEOUT`, which only applies once this returns. Kept under that
/// 30s budget so a dead upstream surfaces quickly as a 502 at the callers.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct ProxyServer {
    listen_addr: SocketAddr,
    transparent_listen_addr: SocketAddr,
    dns_stub_listen_addr: SocketAddr,
    state: Arc<ProxyState>,
}

impl ProxyServer {
    pub fn new(
        listen_addr: SocketAddr,
        transparent_listen_addr: SocketAddr,
        dns_stub_listen_addr: SocketAddr,
        sandbox_creds: Option<crate::privilege::SandboxCredentials>,
        bootstrap_dns_allowlist: Vec<String>,
    ) -> (Self, Arc<ProxyState>) {
        let state = Arc::new(ProxyState {
            upstream: Mutex::new(None),
            routes: RwLock::new(Vec::new()),
            default_verdict: RwLock::new(Verdict::Allow),
            default_transport: RwLock::new(Transport::Upstream),
            audit_tx: std::sync::Mutex::new(None),
            deny_dedup: std::sync::Mutex::new(HashMap::new()),
            credential_injections: RwLock::new(HashMap::new()),
            ephemeral_ca: std::sync::OnceLock::new(),
            client_certs: RwLock::new(HashMap::new()),
            uri_placeholder_injections: RwLock::new(HashMap::new()),
            extra_ca_certs: RwLock::new(Vec::new()),
            sandbox_tls_connector: RwLock::new(None),
            previous_policy_files: RwLock::new(Vec::new()),
            sandbox_creds,
            aws_resign: Arc::new(crate::aws_resign::AwsResignInterceptor::new()),
            pending: std::sync::Mutex::new(crate::gate::PendingTable::new()),
            credential_pending: std::sync::Mutex::new(crate::gate::PendingTable::new()),
            placeholder_index: RwLock::new(HashMap::new()),
            unarmed_credential_domains: RwLock::new(Vec::new()),
            decision_timeout: std::sync::RwLock::new(crate::gate::DECISION_TIMEOUT),
            upstream_connect_timeout: std::sync::RwLock::new(UPSTREAM_CONNECT_TIMEOUT),
            bootstrap_dns_allowlist: bootstrap_dns_allowlist
                .into_iter()
                .map(|h| h.to_ascii_lowercase())
                .collect(),
            gate_resolved_hosts: RwLock::new(HashSet::new()),
        });
        let server = Self {
            listen_addr,
            transparent_listen_addr,
            dns_stub_listen_addr,
            state: state.clone(),
        };
        (server, state)
    }

    pub async fn run(self) -> Result<(), String> {
        let explicit = TcpListener::bind(self.listen_addr)
            .await
            .map_err(|e| format!("proxy bind {}: {e}", self.listen_addr))?;
        tracing::info!(addr = %self.listen_addr, "local CONNECT proxy listening");

        let transparent = TcpListener::bind(self.transparent_listen_addr)
            .await
            .map_err(|e| {
                format!(
                    "transparent proxy bind {}: {e}",
                    self.transparent_listen_addr
                )
            })?;
        tracing::info!(
            addr = %self.transparent_listen_addr,
            "transparent redirect listener running"
        );

        // One semaphore spans both listeners so a burst on one path can't
        // starve the other of file descriptors or memory.
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
        let explicit_sem = semaphore.clone();
        let transparent_sem = semaphore;
        let explicit_state = self.state.clone();
        let transparent_state = self.state.clone();
        let dns_state = self.state;
        let dns_listen = self.dns_stub_listen_addr;

        let explicit_task = tokio::spawn(async move {
            loop {
                let (stream, peer) = match explicit.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(kind = "explicit", "proxy accept error: {e}");
                        continue;
                    }
                };
                let permit = match explicit_sem.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::warn!(kind = "explicit", peer = %peer, "proxy connection limit reached, dropping");
                        drop(stream);
                        continue;
                    }
                };
                let state = explicit_state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, peer, &state).await {
                        tracing::debug!(kind = "explicit", peer = %peer, "proxy connection error: {e}");
                    }
                    drop(permit);
                });
            }
        });

        let transparent_task = tokio::spawn(async move {
            loop {
                let (stream, peer) = match transparent.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(kind = "transparent", "proxy accept error: {e}");
                        continue;
                    }
                };
                let permit = match transparent_sem.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::warn!(kind = "transparent", peer = %peer, "proxy connection limit reached, dropping");
                        drop(stream);
                        continue;
                    }
                };
                let state = transparent_state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_transparent_connection(stream, peer, state).await {
                        tracing::debug!(kind = "transparent", peer = %peer, "proxy connection error: {e}");
                    }
                    drop(permit);
                });
            }
        });

        let dns_task = tokio::spawn(async move {
            // The stub is best-effort: a bind failure or missing
            // /etc/resolv.conf shouldn't take the whole proxy down, but we
            // do log loudly so the operator notices. UDP/53 from the sandbox
            // stays REDIRECTed to us — it will just start timing out for
            // the sandboxed process, which is the safe degrade.
            if let Err(e) = crate::dns::run(dns_listen, dns_state).await {
                tracing::error!("dns stub task ended: {e}");
            }
        });

        // Either TCP listener terminating is fatal. DNS stub failure degrades
        // to "no hostname resolution for sandbox user" — loud log, proxy stays
        // up so explicit-CONNECT traffic keeps flowing.
        tokio::select! {
            res = explicit_task => {
                tracing::error!("explicit proxy listener task ended: {res:?}");
            }
            res = transparent_task => {
                tracing::error!("transparent proxy listener task ended: {res:?}");
            }
        }
        dns_task.abort();
        Err("proxy listener terminated".into())
    }
}

async fn handle_connection(
    mut client: TcpStream,
    peer: SocketAddr,
    state: &Arc<ProxyState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let actor = crate::peer_process::ActorContext::resolve(peer);
    // Read the request line and headers byte-by-byte to avoid buffering past
    // the header boundary (which would lose TLS ClientHello bytes for CONNECT).
    // Timeout prevents slow-loris attacks.
    let request = match tokio::time::timeout(
        HEADER_READ_TIMEOUT,
        read_proxy_request_unbuffered(&mut client),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => {
            client
                .write_all(b"HTTP/1.1 408 Request Timeout\r\n\r\n")
                .await?;
            return Err("header read timeout".into());
        }
    };

    // Dispatch based on request type
    match request {
        ProxyRequest::Http {
            target_host,
            header_bytes,
        } => {
            return handle_http_forward(client, &target_host, header_bytes, state, Some(&actor))
                .await;
        }
        ProxyRequest::Connect {
            target: target_host,
        } => {
            return handle_connect(client, &target_host, &actor, state).await;
        }
    }
}

/// Handle an HTTP forward proxy request (plain HTTP, not CONNECT).
///
/// The client sent something like `GET http://host:port/path HTTP/1.1`.
/// We apply the same policy routing, credential injection, HTTP rules, and
/// audit as CONNECT+MITM — but without TLS termination since the traffic is
/// already plaintext.
async fn handle_http_forward(
    mut client: TcpStream,
    target_host: &str,
    header_bytes: Vec<u8>,
    state: &Arc<ProxyState>,
    actor: Option<&crate::peer_process::ActorContext>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Validate target: reject CRLF injection and loopback/link-local targets
    validate_connect_target(target_host)?;

    let header_str = String::from_utf8_lossy(&header_bytes);

    // Parse method and path from request line for HTTP rule enforcement and audit
    let request_line = header_str.lines().next().unwrap_or("UNKNOWN");
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    let method = parts.first().copied().unwrap_or("UNKNOWN");
    // Extract the path portion from the absolute URL (e.g. http://host/path → /path).
    // Handles URLs without an explicit path (e.g. http://host?q=1 → /?q=1).
    let raw_url = parts.get(1).copied().unwrap_or("/");
    let path = if let Some(rest) = raw_url.strip_prefix("http://") {
        match (rest.find('/'), rest.find('?')) {
            (Some(s), _) => rest[s..].to_string(),
            (None, Some(q)) => format!("/{}", &rest[q..]),
            (None, None) => "/".to_string(),
        }
    } else {
        raw_url.to_string()
    };
    let raw_no_query = path.split('?').next().unwrap_or(&path);
    let normalized_path = crate::routing::normalize_path(raw_no_query);

    // Find the matching route rule (same logic as CONNECT, but scheme is http
    // since the request came in as an absolute-form http:// URL).
    let (verdict, transport, _tls_terminate, domain_http_rules) = {
        let routes = state.routes.read().unwrap();
        let default_verdict = *state.default_verdict.read().unwrap();
        let default_transport = *state.default_transport.read().unwrap();
        match find_matching_route(&routes, target_host, Scheme::Http) {
            Some(rule) => (
                rule.verdict,
                rule.transport,
                rule.tls_terminate,
                rule.http_rules.clone(),
            ),
            None => (default_verdict, default_transport, false, Vec::new()),
        }
    };

    // Enforce HTTP rules — deny if rules present and no rule matches
    if !domain_http_rules.is_empty()
        && !crate::routing::http_request_matches_rules(&domain_http_rules, method, &normalized_path)
    {
        tracing::info!(
            target = %target_host,
            method = %method,
            path = %normalized_path,
            "HTTP forward proxy request denied by policy rules"
        );
        emit_policy_deny_http(state, target_host, method, &path, actor);
        client
            .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    }

    // Collect credential injections for this domain
    let injections = {
        let map = state.credential_injections.read().unwrap();
        let mut matched = Vec::new();
        for (pattern, injs) in map.iter() {
            if crate::routing::injection_matches(pattern, target_host) {
                matched.extend(injs.iter().cloned());
            }
        }
        matched
    };
    let uri_placeholders = collect_uri_placeholders(state, target_host);

    // Rewrite the request headers: convert absolute URL to relative path,
    // inject credentials, and apply URI placeholder replacements.
    let relative_request = rewrite_http_forward_request(&header_str, &path, target_host);
    let header_injected = crate::mitm::inject_headers(&relative_request, &injections);
    let modified = crate::mitm::rewrite_uri_placeholders(&header_injected, &uri_placeholders);

    // Re-validate HTTP rules after URI placeholder rewriting (same as MITM path)
    if !uri_placeholders.is_empty() && modified != header_injected && !domain_http_rules.is_empty()
    {
        let rw_line = modified.split("\r\n").next().unwrap_or(&modified);
        let rw_parts: Vec<&str> = rw_line.split_whitespace().collect();
        let rw_raw_path = rw_parts.get(1).unwrap_or(&"/");
        let rw_no_query = rw_raw_path.split('?').next().unwrap_or(rw_raw_path);
        let rw_normalized = crate::routing::normalize_path(rw_no_query);
        if !crate::routing::http_request_matches_rules(&domain_http_rules, method, &rw_normalized) {
            tracing::info!(
                target = %target_host,
                method = %method,
                path = %rw_normalized,
                "HTTP forward proxy request denied after URI placeholder rewrite"
            );
            emit_policy_deny_http(state, target_host, method, &path, actor);
            client
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                )
                .await?;
            return Ok(());
        }
    }

    let modified_bytes = format!("{modified}\r\n\r\n");

    let effective_transport = match verdict {
        Verdict::Deny => {
            client
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                )
                .await?;
            tracing::info!(target = %target_host, method = %method, "HTTP forward proxy DENIED");
            emit_policy_deny_http(state, target_host, method, &path, actor);
            return Ok(());
        }
        Verdict::Ask => {
            let action_str = format!("{method} http://{target_host}{path}");
            let key = gate_key(target_host);
            let decision =
                crate::gate::gate_or_deny(state, &key, &action_str, "policy-ambiguous").await;
            if !decision.is_allow() {
                emit_gate_denied(state, &action_str, decision);
                client
                    .write_all(
                        b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                    )
                    .await?;
                tracing::info!(target = %target_host, method = %method, reason = decision.audit_reason(), "HTTP forward proxy DENIED (gated)");
                return Ok(());
            }
            emit_gate_resolved(state, &action_str, decision);
            tracing::info!(target = %target_host, method = %method, reason = decision.audit_reason(), "HTTP forward proxy ALLOWED (gated)");
            transport
        }
        Verdict::Allow => transport,
    };

    match effective_transport {
        Transport::Direct => {
            // Direct connection to upstream — send modified request, relay response
            let mut upstream = match sock_mark::connect_tcp_resolve(target_host).await {
                Ok(t) => t,
                Err(e) => {
                    emit_http_audit(state, target_host, method, &path, "error", 502, actor);
                    client
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                        .await?;
                    return Err(
                        format!("HTTP forward proxy direct connect to {target_host}: {e}").into(),
                    );
                }
            };

            tracing::debug!(
                target = %target_host,
                method = %method,
                has_injections = !injections.is_empty(),
                "HTTP forward proxy DIRECT"
            );

            // Send modified headers to upstream
            upstream.write_all(modified_bytes.as_bytes()).await?;

            // Relay the rest bidirectionally (request body + response)
            emit_http_audit(state, target_host, method, &path, "success", 200, actor);
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        }
        Transport::Upstream => {
            // Route through Lens Sandbox — open a CONNECT tunnel, then send the HTTP request through it
            let upstream_opt = state.upstream.lock().await.clone();
            let upstream = match upstream_opt {
                Some(n) => n,
                None => {
                    client
                        .write_all(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                        .await?;
                    emit_http_audit(state, target_host, method, &path, "error", 503, actor);
                    return Err("Lens Sandbox upstream not configured yet".into());
                }
            };

            let upstream_addr = format!("{}:{}", upstream.host, upstream.port);
            let mut upstream_stream: BoxedSandboxStream = match connect_sandbox_upstream(
                state, &upstream,
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    client
                            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                            .await?;
                    emit_http_audit(state, target_host, method, &path, "error", 502, actor);
                    return Err(format!(
                        "HTTP forward proxy connect to Lens Sandbox {upstream_addr}: {e}"
                    )
                    .into());
                }
            };

            // Open a CONNECT tunnel to Lens Sandbox for the target host
            let mut connect_req =
                format!("CONNECT {target_host} HTTP/1.1\r\nHost: {target_host}\r\n");
            if let Some(auth) = &upstream.auth_header {
                connect_req.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
            }
            connect_req.push_str("\r\n");

            upstream_stream.write_all(connect_req.as_bytes()).await?;

            // Read CONNECT response from Lens Sandbox
            let status = match tokio::time::timeout(
                HEADER_READ_TIMEOUT,
                read_response_status_unbuffered(&mut upstream_stream),
            )
            .await
            {
                Ok(result) => result?,
                Err(_) => {
                    client
                        .write_all(b"HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                        .await?;
                    emit_http_audit(state, target_host, method, &path, "error", 504, actor);
                    return Err("HTTP forward proxy upstream header read timeout".into());
                }
            };

            if !status.starts_with("200") {
                client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                    .await?;
                emit_http_audit(state, target_host, method, &path, "error", 502, actor);
                return Err(format!("Lens Sandbox upstream returned: {status}").into());
            }

            tracing::debug!(
                target = %target_host,
                method = %method,
                has_injections = !injections.is_empty(),
                "HTTP forward proxy LENS (via CONNECT tunnel)"
            );

            // Send modified HTTP request through the tunnel
            upstream_stream.write_all(modified_bytes.as_bytes()).await?;

            // Relay the rest bidirectionally (request body + response)
            emit_http_audit(state, target_host, method, &path, "success", 200, actor);
            tokio::io::copy_bidirectional(&mut client, &mut upstream_stream).await?;
        }
    }

    Ok(())
}

/// Rewrite an HTTP forward proxy request from absolute URL to relative path.
/// Input:  "GET http://host:port/path HTTP/1.1\r\nHost: ...\r\n..."
/// Output: "GET /path HTTP/1.1\r\nHost: host:port\r\n..."
fn rewrite_http_forward_request(header_str: &str, path: &str, target_host: &str) -> String {
    let lines: Vec<&str> = header_str.split("\r\n").collect();
    let mut result = Vec::new();

    if let Some(request_line) = lines.first() {
        // Rewrite request line: replace absolute URL with relative path
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() >= 3 {
            result.push(format!("{} {} {}", parts[0], path, parts[2]));
        } else {
            result.push(request_line.to_string());
        }
    }

    // Overwrite Host with the target derived from the absolute URL and
    // strip Proxy-* hop-by-hop headers (RFC 7230 §6.1).
    let mut has_host = false;
    for line in lines.iter().skip(1) {
        if line.is_empty() {
            continue;
        }
        let name = line.split(':').next().unwrap_or("").trim().to_lowercase();
        if name == "host" {
            if !has_host {
                result.push(format!("Host: {target_host}"));
                has_host = true;
            }
            continue;
        }
        if name.starts_with("proxy-") {
            continue;
        }
        result.push(line.to_string());
    }

    if !has_host {
        result.insert(1, format!("Host: {target_host}"));
    }

    result.join("\r\n")
}

/// Handle a CONNECT tunnel request (existing flow).
async fn handle_connect(
    mut client: TcpStream,
    target_host: &str,
    actor: &crate::peer_process::ActorContext,
    state: &Arc<ProxyState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Validate target: reject CRLF injection and loopback/link-local targets
    validate_connect_target(target_host)?;

    // Find the matching route rule (first match wins, preserving order/specificity).
    // CONNECT is always HTTPS — plain HTTP uses the absolute-form forward path.
    let (verdict, transport, tls_terminate, domain_http_rules) = {
        let routes = state.routes.read().unwrap();
        let default_verdict = *state.default_verdict.read().unwrap();
        let default_transport = *state.default_transport.read().unwrap();
        match find_matching_route(&routes, target_host, Scheme::Https) {
            Some(rule) => (
                rule.verdict,
                rule.transport,
                rule.tls_terminate,
                rule.http_rules.clone(),
            ),
            None => (default_verdict, default_transport, false, Vec::new()),
        }
    };

    let hostname = extract_hostname(target_host);

    // Check if this target has a client cert config for mTLS upstream
    let client_cert = {
        let map = state.client_certs.read().unwrap();
        map.get(&target_host.to_lowercase()).cloned()
    };

    let effective_transport = match verdict {
        Verdict::Deny => {
            client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
            tracing::info!(target = %target_host, "proxy DENIED");
            emit_policy_deny_connect(state, target_host, Some(actor));
            return Ok(());
        }
        Verdict::Ask => {
            let action_str = format!("CONNECT {target_host}");
            let key = gate_key(target_host);
            let decision =
                crate::gate::gate_or_deny(state, &key, &action_str, "policy-ambiguous").await;
            if !decision.is_allow() {
                emit_gate_denied(state, &action_str, decision);
                client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
                tracing::info!(target = %target_host, reason = decision.audit_reason(), "proxy DENIED (gated)");
                return Ok(());
            }
            emit_gate_resolved(state, &action_str, decision);
            tracing::info!(target = %target_host, reason = decision.audit_reason(), "proxy ALLOWED (gated)");
            transport
        }
        Verdict::Allow => transport,
    };

    // Collect credential injections AFTER the gate resolves: accepting an integration
    // offer during a Verdict::Ask hold arms a credential mid-connection, and the resumed
    // request must MITM to inject it. Collecting before the gate would use a stale (empty)
    // snapshot, relay the placeholder upstream, and fail the request. Patterns with an
    // explicit port match host:port; wildcard/hostname-only patterns match on hostname
    // only (e.g. bedrock-runtime.*.amazonaws.com).
    let injections = {
        let matched = collect_header_injections(state, target_host);
        (!matched.is_empty()).then_some(matched)
    };

    match effective_transport {
        Transport::Direct => {
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;

            tracing::info!(
                target = %target_host,
                has_injections = injections.is_some(),
                has_client_cert = client_cert.is_some(),
                has_http_rules = !domain_http_rules.is_empty(),
                has_ephemeral_ca = state.ephemeral_ca.get().is_some(),
                client_cert_keys = ?state.client_certs.read().unwrap().keys().collect::<Vec<_>>(),
                "proxy DIRECT dispatch decision"
            );

            let uri_placeholders = collect_uri_placeholders(state, target_host);
            let needs_aws_resign = state.aws_resign.matches(target_host);
            let needs_mitm = injections.is_some()
                || !domain_http_rules.is_empty()
                || !uri_placeholders.is_empty()
                || state.intercept_for_unarmed(target_host);
            if needs_aws_resign {
                // AWS-resign path owns the MITM for this connection; any
                // other injections configured for the same host would be
                // silently ignored here. In practice `*.amazonaws.com`
                // doesn't carry header injections, but surface the
                // misconfiguration so it doesn't fail silently.
                if needs_mitm {
                    tracing::warn!(
                        target = %target_host,
                        has_header_injections = injections.is_some(),
                        has_http_rules = !domain_http_rules.is_empty(),
                        has_uri_placeholders = !uri_placeholders.is_empty(),
                        "aws-resign and other injections configured on same host — non-aws injections will be dropped"
                    );
                }
                let ca = get_or_init_ca(state)?;
                tracing::debug!(target = %target_host, "proxy DIRECT+AWS_RESIGN");
                let port = extract_port(target_host, 443);
                let audit_tx = state.audit_tx.lock().unwrap().clone();
                let extra_certs = state.extra_ca_certs.read().unwrap().clone();
                state
                    .aws_resign
                    .handle(client, &hostname, port, ca, &extra_certs, &audit_tx)
                    .await?;
            } else if needs_mitm {
                let ca = get_or_init_ca(state)?;
                let injs = injections.as_deref().unwrap_or(&[]);
                tracing::debug!(target = %target_host, injections = injs.len(), http_rules = domain_http_rules.len(), uri_placeholders = uri_placeholders.len(), "proxy DIRECT+MITM");
                let port = extract_port(target_host, 443);
                let audit_tx = state.audit_tx.lock().unwrap().clone();
                let mode = crate::mitm::UpstreamMode::DirectTls {
                    host: hostname.to_string(),
                    port,
                };
                let extra_certs = state.extra_ca_certs.read().unwrap().clone();
                let ctx = crate::mitm::MitmContext {
                    injections: injs,
                    http_rules: &domain_http_rules,
                    ca,
                    audit_tx: &audit_tx,
                    extra_ca_certs: &extra_certs,
                    placeholder_map: &uri_placeholders,
                    state,
                    match_host: target_host,
                    actor,
                };
                crate::mitm::handle_mitm(client, &hostname, mode, &ctx).await?;
            } else if let (Some(cc), Some(ca)) = (&client_cert, state.ephemeral_ca.get()) {
                // Has client cert (no header injections) → TLS bridge (mTLS to upstream)
                tracing::debug!(target = %target_host, dial_addr = %cc.dial_addr, "proxy DIRECT+TLS_BRIDGE");
                let hostname = extract_hostname(target_host);
                let audit_tx = state.audit_tx.lock().unwrap().clone();
                crate::mitm::handle_tls_bridge(
                    client,
                    &cc.dial_addr,
                    &cc.tls_server_name,
                    cc,
                    ca,
                    &hostname,
                    &audit_tx,
                    actor,
                )
                .await?;
            } else {
                // Neither → plain TCP relay
                let mut target = match sock_mark::connect_tcp_resolve(target_host).await {
                    Ok(t) => t,
                    Err(e) => {
                        emit_audit(state, target_host, "error", 502, Some(actor));
                        return Err(format!("direct connect to {target_host}: {e}").into());
                    }
                };
                tracing::debug!(target = %target_host, "proxy DIRECT");
                tokio::io::copy_bidirectional(&mut client, &mut target).await?;
            }
        }
        Transport::Upstream => {
            let upstream_opt = state.upstream.lock().await.clone();
            let upstream = match upstream_opt {
                Some(n) => n,
                None => {
                    client
                        .write_all(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
                        .await?;
                    emit_audit(state, target_host, "error", 503, Some(actor));
                    return Err("Lens Sandbox upstream not configured yet".into());
                }
            };

            let upstream_addr = format!("{}:{}", upstream.host, upstream.port);
            let mut upstream_stream: BoxedSandboxStream =
                match connect_sandbox_upstream(state, &upstream).await {
                    Ok(s) => s,
                    Err(e) => {
                        client
                            .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                            .await?;
                        emit_audit(state, target_host, "error", 502, Some(actor));
                        return Err(format!(
                            "connect to Lens Sandbox upstream {upstream_addr}: {e}"
                        )
                        .into());
                    }
                };

            // Send CONNECT to Lens Sandbox upstream
            let mut connect_req =
                format!("CONNECT {target_host} HTTP/1.1\r\nHost: {target_host}\r\n");
            if let Some(auth) = &upstream.auth_header {
                connect_req.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
            }
            connect_req.push_str("\r\n");

            upstream_stream.write_all(connect_req.as_bytes()).await?;

            // Read response from Lens Sandbox byte-by-byte (same reason — don't buffer past headers)
            let status = match tokio::time::timeout(
                HEADER_READ_TIMEOUT,
                read_response_status_unbuffered(&mut upstream_stream),
            )
            .await
            {
                Ok(result) => result?,
                Err(_) => {
                    client
                        .write_all(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n")
                        .await?;
                    emit_audit(state, target_host, "error", 504, Some(actor));
                    return Err("upstream header read timeout".into());
                }
            };

            if !status.starts_with("200") {
                client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    .await?;
                emit_audit(state, target_host, "error", 502, Some(actor));
                return Err(format!("Lens Sandbox upstream returned: {status}").into());
            }

            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;

            let hostname = extract_hostname(target_host);
            let audit_tx = state.audit_tx.lock().unwrap().clone();
            let injs = injections.as_deref().unwrap_or(&[]);
            // Hoist placeholder collection so ALL Lens Sandbox dispatch branches
            // can check it in their MITM guard — not just tls_terminate.
            // Without this, a domain with only uriPlaceholder injections on
            // a non-tls_terminate Lens Sandbox route would bypass MITM entirely,
            // forwarding __lens_cred:..__ upstream unchanged.
            let placeholders = collect_uri_placeholders(state, target_host);

            if tls_terminate {
                if let Some(ca) = state.ephemeral_ca.get() {
                    // Tunnel route: terminate client TLS and re-encrypt to upstream.
                    // Plain HTTP upstreams are handled by the HTTP forward proxy path.
                    tracing::debug!(
                        target = %target_host,
                        injections = injs.len(),
                        "proxy LENS+TLS_TERM"
                    );
                    let mode = crate::mitm::UpstreamMode::TunnelTls(upstream_stream);
                    let extra_certs = state.extra_ca_certs.read().unwrap().clone();
                    let ctx = crate::mitm::MitmContext {
                        injections: injs,
                        http_rules: &domain_http_rules,
                        ca,
                        audit_tx: &audit_tx,
                        extra_ca_certs: &extra_certs,
                        placeholder_map: &placeholders,
                        state,
                        match_host: target_host,
                        actor,
                    };
                    crate::mitm::handle_mitm(client, &hostname, mode, &ctx).await?;
                } else {
                    emit_audit(state, target_host, "success", 200, Some(actor));
                    tracing::debug!(target = %target_host, "proxy LENS (passthrough, no CA)");
                    tokio::io::copy_bidirectional(&mut client, &mut upstream_stream).await?;
                }
            } else if !injs.is_empty()
                || !domain_http_rules.is_empty()
                || !placeholders.is_empty()
                || state.intercept_for_unarmed(target_host)
            {
                if let Some(ca) = state.ephemeral_ca.get() {
                    // HTTPS upstream via Lens Sandbox tunnel — MITM to inject credentials,
                    // enforce HTTP rules, or rewrite URI placeholders.
                    tracing::debug!(
                        target = %target_host,
                        injections = injs.len(),
                        http_rules = domain_http_rules.len(),
                        uri_placeholders = placeholders.len(),
                        "proxy LENS+MITM (TLS upstream)"
                    );
                    let mode = crate::mitm::UpstreamMode::TunnelTls(upstream_stream);
                    let extra_certs = state.extra_ca_certs.read().unwrap().clone();
                    let ctx = crate::mitm::MitmContext {
                        injections: injs,
                        http_rules: &domain_http_rules,
                        ca,
                        audit_tx: &audit_tx,
                        extra_ca_certs: &extra_certs,
                        placeholder_map: &placeholders,
                        state,
                        match_host: target_host,
                        actor,
                    };
                    crate::mitm::handle_mitm(client, &hostname, mode, &ctx).await?;
                } else {
                    emit_audit(state, target_host, "success", 200, Some(actor));
                    tracing::debug!(target = %target_host, "proxy LENS (passthrough, no CA)");
                    tokio::io::copy_bidirectional(&mut client, &mut upstream_stream).await?;
                }
            } else {
                // No TLS termination, no injections — raw TCP passthrough
                emit_audit(state, target_host, "success", 200, Some(actor));
                tracing::debug!(target = %target_host, "proxy LENS (passthrough)");
                tokio::io::copy_bidirectional(&mut client, &mut upstream_stream).await?;
            }
        }
    }

    Ok(())
}

/// Entry point for connections redirected by nftables into the transparent
/// listener. Recovers the pre-redirect destination, classifies the first
/// bytes, and hands off to the TLS or HTTP handler. Unknown protocols are
/// dropped with an audit event — matching today's fail-closed semantics.
async fn handle_transparent_connection(
    stream: TcpStream,
    peer: SocketAddr,
    state: Arc<ProxyState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let orig_dst = match transparent::so_original_dst(&stream) {
        Ok(addr) => addr,
        Err(e) => {
            // On non-Linux, or if the connection wasn't routed through
            // the REDIRECT chain (e.g. a curl against 127.0.0.1:3129 from
            // within the container), SO_ORIGINAL_DST is not set. Nothing
            // meaningful we can do with this connection.
            tracing::debug!("transparent: SO_ORIGINAL_DST unavailable: {e}");
            return Ok(());
        }
    };

    if orig_dst.ip().is_loopback() {
        // The nat chain's `-o lo -j RETURN` rule should keep loopback
        // traffic out of the listener, but if it slips through (e.g.
        // manual connection) we drop it to avoid amplifying.
        return Ok(());
    }

    // 8 bytes covers every classifier prefix: TLS needs 3, `OPTIONS ` and
    // `CONNECT ` are 8.
    let first = transparent::peek_first_bytes(&stream, 8).await?;
    match transparent::classify(&first) {
        Protocol::Tls => handle_transparent_tls(stream, orig_dst, peer, &state).await,
        Protocol::Http => handle_transparent_http(stream, orig_dst, peer, &state).await,
        Protocol::Unknown => {
            emit_transparent_deny(&state, orig_dst, "unknown-protocol");
            // Dropping the stream closes the socket.
            Ok(())
        }
    }
}

async fn handle_transparent_tls(
    stream: TcpStream,
    orig_dst: SocketAddr,
    peer: SocketAddr,
    state: &Arc<ProxyState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let actor = crate::peer_process::ActorContext::resolve(peer);
    // LazyConfigAcceptor reads the ClientHello so we can peek SNI before
    // committing to a ServerConfig — lets us enforce the policy allowlist
    // before the ephemeral cert is generated.
    let acceptor = rustls::server::Acceptor::default();
    let start = match tokio_rustls::LazyConfigAcceptor::new(acceptor, stream).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("transparent TLS: ClientHello read failed: {e}");
            return Ok(());
        }
    };

    let sni = start.client_hello().server_name().map(|s| s.to_string());

    let sni = match sni {
        Some(s) => s,
        None => {
            // Without SNI we have no hostname to match against the
            // allowlist and no name to sign an ephemeral cert for.
            // Drop with an audit event — dropping `start` closes the
            // underlying TcpStream with a normal FIN. No TLS Alert is
            // sent (we never built a ServerConfig), which is what we
            // want: the client gets a connection close, not a leak of
            // policy state via Alert codes.
            emit_transparent_deny(state, orig_dst, "tls-no-sni");
            drop(start);
            return Ok(());
        }
    };

    let target_host = format!("{sni}:{}", orig_dst.port());

    if let Err(e) = validate_connect_target(&target_host) {
        emit_transparent_deny(state, orig_dst, &format!("blocked-target: {e}"));
        drop(start);
        return Ok(());
    }

    let (verdict, transport, _tls_terminate, domain_http_rules) = {
        let routes = state.routes.read().unwrap();
        let default_verdict = *state.default_verdict.read().unwrap();
        let default_transport = *state.default_transport.read().unwrap();
        match find_matching_route(&routes, &target_host, Scheme::Https) {
            Some(rule) => (
                rule.verdict,
                rule.transport,
                rule.tls_terminate,
                rule.http_rules.clone(),
            ),
            None => (default_verdict, default_transport, false, Vec::new()),
        }
    };

    let effective_transport = match verdict {
        Verdict::Deny => {
            emit_policy_deny_connect(state, &target_host, Some(&actor));
            drop(start);
            return Ok(());
        }
        Verdict::Ask => {
            let action_str = format!("CONNECT {target_host}");
            let key = gate_key(&target_host);
            let decision =
                crate::gate::gate_or_deny(state, &key, &action_str, "policy-ambiguous").await;
            if !decision.is_allow() {
                emit_gate_denied(state, &action_str, decision);
                tracing::info!(target = %target_host, reason = decision.audit_reason(), "transparent TLS DENIED (gated)");
                drop(start);
                return Ok(());
            }
            emit_gate_resolved(state, &action_str, decision);
            tracing::info!(target = %target_host, reason = decision.audit_reason(), "transparent TLS ALLOWED (gated)");
            transport
        }
        Verdict::Allow => transport,
    };

    // Specialised dispatch arms in the explicit-CONNECT path
    // (`handle_connect`) take a RAW TcpStream and run their own TLS accept:
    //   - aws_resign: re-signs SigV4 with the real STS creds
    //   - client_cert: presents a client cert to the upstream (kubeconfig mTLS)
    // The transparent path has already consumed the ClientHello via
    // `LazyConfigAcceptor`, so those handlers can't be reused as-is. Until
    // they learn to accept a pre-accepted TLS stream, deny the connection
    // with a specific reason so the operator is alerted instead of silently
    // getting wrong-signature or missing-cert upstream failures.
    if state.aws_resign.matches(&target_host) {
        emit_transparent_deny(state, orig_dst, "transparent-not-supported:aws-resign");
        drop(start);
        return Ok(());
    }
    let has_client_cert = {
        let map = state.client_certs.read().unwrap();
        map.contains_key(&target_host.to_lowercase())
    };
    if has_client_cert {
        emit_transparent_deny(state, orig_dst, "transparent-not-supported:client-cert");
        drop(start);
        return Ok(());
    }

    // Non-denied: complete the TLS handshake with an ephemeral cert and
    // run the MITM pipeline. Unlike the CONNECT path, transparent TLS is
    // always MITM'd — we've already committed to TLS termination by the
    // time we've peeked the ClientHello, so there is no opt-out on
    // `Transport::Direct`. Clients that pin a CA bundle excluding the
    // sandbox's ephemeral CA will fail-closed on the transparent path
    // even if the policy says `direct`. The cooperative CONNECT path
    // (`HTTPS_PROXY=http://127.0.0.1:3128`) still passes such clients
    // through untouched.
    let ca = get_or_init_ca(state)?;
    let server_config = crate::mitm::build_ephemeral_server_config(ca, &sni)?;
    let tls_client = start.into_stream(server_config).await?;

    let hostname = extract_hostname(&target_host);
    let injections = {
        let map = state.credential_injections.read().unwrap();
        let mut matched = Vec::new();
        for (pattern, injs) in map.iter() {
            if crate::routing::injection_matches(pattern, &target_host) {
                matched.extend(injs.iter().cloned());
            }
        }
        matched
    };
    let uri_placeholders = collect_uri_placeholders(state, &target_host);
    let audit_tx = state.audit_tx.lock().unwrap().clone();
    let extra_certs = state.extra_ca_certs.read().unwrap().clone();

    let ctx = crate::mitm::MitmContext {
        injections: &injections,
        http_rules: &domain_http_rules,
        ca,
        audit_tx: &audit_tx,
        extra_ca_certs: &extra_certs,
        placeholder_map: &uri_placeholders,
        state,
        match_host: &target_host,
        actor: &actor,
    };

    match effective_transport {
        Transport::Direct => {
            tracing::debug!(target = %target_host, "transparent TLS DIRECT+MITM");
            let mode = crate::mitm::UpstreamMode::DirectTls {
                host: hostname.clone(),
                port: orig_dst.port(),
            };
            crate::mitm::handle_mitm_pre_accepted(tls_client, &hostname, mode, &ctx).await?;
        }
        Transport::Upstream => {
            // Open a CONNECT tunnel through Lens Sandbox before handing the
            // pre-accepted TLS stream to the MITM pipeline.
            let upstream_opt = state.upstream.lock().await.clone();
            let upstream = match upstream_opt {
                Some(n) => n,
                None => {
                    emit_audit(state, &target_host, "error", 503, Some(&actor));
                    return Err("Lens Sandbox upstream not configured yet".into());
                }
            };
            let upstream_addr = format!("{}:{}", upstream.host, upstream.port);
            let mut upstream_stream: BoxedSandboxStream =
                match connect_sandbox_upstream(state, &upstream).await {
                    Ok(s) => s,
                    Err(e) => {
                        emit_audit(state, &target_host, "error", 502, Some(&actor));
                        return Err(format!(
                            "connect to Lens Sandbox upstream {upstream_addr}: {e}"
                        )
                        .into());
                    }
                };
            let mut connect_req =
                format!("CONNECT {target_host} HTTP/1.1\r\nHost: {target_host}\r\n");
            if let Some(auth) = &upstream.auth_header {
                connect_req.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
            }
            connect_req.push_str("\r\n");
            upstream_stream.write_all(connect_req.as_bytes()).await?;

            let status = match tokio::time::timeout(
                HEADER_READ_TIMEOUT,
                read_response_status_unbuffered(&mut upstream_stream),
            )
            .await
            {
                Ok(result) => result?,
                Err(_) => {
                    emit_audit(state, &target_host, "error", 504, Some(&actor));
                    return Err("upstream header read timeout".into());
                }
            };

            if !status.starts_with("200") {
                emit_audit(state, &target_host, "error", 502, Some(&actor));
                return Err(format!("Lens Sandbox upstream returned: {status}").into());
            }

            tracing::debug!(target = %target_host, "transparent TLS LENS+MITM");
            let mode = crate::mitm::UpstreamMode::TunnelTls(upstream_stream);
            crate::mitm::handle_mitm_pre_accepted(tls_client, &hostname, mode, &ctx).await?;
        }
    }

    Ok(())
}

async fn handle_transparent_http(
    mut stream: TcpStream,
    orig_dst: SocketAddr,
    peer: SocketAddr,
    state: &Arc<ProxyState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let actor = crate::peer_process::ActorContext::resolve(peer);
    let header_bytes = match tokio::time::timeout(
        HEADER_READ_TIMEOUT,
        read_until_double_crlf(&mut stream),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => {
            stream
                .write_all(b"HTTP/1.1 408 Request Timeout\r\n\r\n")
                .await?;
            return Err("transparent HTTP header read timeout".into());
        }
    };

    let header_str = String::from_utf8_lossy(&header_bytes);

    // Reject CONNECT on the transparent path. A client only sends raw
    // CONNECT on the wire when it thinks it's talking to a proxy — and
    // the only correct way to do that here is via HTTPS_PROXY (port 3128,
    // exempted from REDIRECT). A CONNECT arriving at 3129 means the
    // client was pointed at a non-proxy target as its proxy and got
    // REDIRECTed in. Forwarding it via `handle_http_forward` would route
    // with `Scheme::Http` — wrong scheme for the true target — and never
    // send the 200 Connection Established the client expects. Fail-closed
    // with a specific audit reason instead.
    let request_line = header_str.lines().next().unwrap_or("");
    let method = request_line.split_whitespace().next().unwrap_or("");
    if method.eq_ignore_ascii_case("CONNECT") {
        emit_transparent_deny(state, orig_dst, "http-connect-on-transparent");
        return Ok(());
    }

    // Host header is authoritative for routing — the client believes it's
    // talking directly to origin, so its Host value reflects what it intends.
    let host_value = header_str
        .lines()
        .skip(1) // skip request line
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("host") {
                Some(value.trim().to_string())
            } else {
                None
            }
        });

    let host = match host_value {
        Some(h) if !h.is_empty() => h,
        _ => {
            emit_transparent_deny(state, orig_dst, "http-no-host");
            stream
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                )
                .await?;
            return Ok(());
        }
    };

    // If the Host header already carries an explicit port, trust it.
    // Otherwise combine with the original destination port, since the
    // client dialed that port directly.
    let has_port = if host.starts_with('[') {
        host.rfind("]:").is_some()
    } else {
        host.contains(':')
    };
    let target_host = if has_port {
        host
    } else {
        format!("{host}:{}", orig_dst.port())
    };

    // `handle_http_forward` re-validates, but bail here too — a CRLF or
    // loopback target in the Host header should never reach routing, and
    // the transparent TLS branch already validates at the same stage.
    if let Err(e) = validate_connect_target(&target_host) {
        emit_transparent_deny(state, orig_dst, &format!("blocked-target: {e}"));
        stream
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            )
            .await?;
        return Ok(());
    }

    handle_http_forward(stream, &target_host, header_bytes, state, Some(&actor)).await
}

/// Audit event for a transparent connection that was dropped before reaching
/// any policy or MITM machinery (unknown protocol, missing SNI, missing Host,
/// etc.). Dedup keyed on `"t:<orig-dst-ip>:<port>"` — the `t:` prefix
/// namespaces transparent denials away from `emit_audit_action`, which uses
/// a bare hostname as its key. The port is included because a process that
/// probes `evil.com:443`, `evil.com:8443`, `evil.com:8080` in quick
/// succession generates three distinct policy-relevant events; collapsing
/// them onto a single IP-only key would leave gaps in the audit trail.
fn emit_transparent_deny(state: &Arc<ProxyState>, orig_dst: SocketAddr, reason: &str) {
    tracing::info!(target = %orig_dst, reason, "transparent redirect dropped connection");
    emit_deny_event(
        state,
        format!("t:{}:{}", orig_dst.ip(), orig_dst.port()),
        format!("TRANSPARENT {orig_dst}"),
        serde_json::json!({ "transparent": true, "reason": reason }),
    );
}

/// Shared deny-event emitter for paths that drop traffic before hitting
/// `emit_audit_action` (transparent redirect, DNS stub). Handles dedup
/// against `ProxyState.deny_dedup` and the audit-channel send. Callers own
/// the `key` prefix to avoid collisions with hostname-keyed CONNECT
/// events (see `emit_transparent_deny` for the `"t:"` convention; DNS uses
/// `"d:"`).
pub(crate) fn emit_deny_event(
    state: &Arc<ProxyState>,
    key: String,
    action: String,
    metadata: serde_json::Value,
) {
    let now = Instant::now();
    {
        let mut dedup = state.deny_dedup.lock().unwrap();
        if let Some(last) = dedup.get(&key)
            && now.duration_since(*last).as_secs() < AUDIT_DEDUP_SECS
        {
            return;
        }
        dedup.insert(key, now);
        // Clear-on-overflow rather than LRU: simple, no per-insert cost,
        // accepts that one in every-1024-distinct-keys deny gets re-emitted
        // even though the dedup window hasn't elapsed. 1024 is generous
        // enough that this is rare in practice.
        if dedup.len() > 1024 {
            dedup.clear();
        }
    }

    let tx = state.audit_tx.lock().unwrap();
    if let Some(tx) = tx.as_ref() {
        let event = serde_json::json!({
            "type": "audit_event",
            "source": "sandbox-proxy",
            "action": action,
            "result": "failure",
            "status_code": 0,
            "metadata": metadata,
        });
        let _ = tx.send(event.to_string());
    }
}

/// Emit an audit event for a CONNECT tunnel request.
fn emit_audit(
    state: &Arc<ProxyState>,
    target_host: &str,
    result: &str,
    status_code: u16,
    actor: Option<&crate::peer_process::ActorContext>,
) {
    emit_audit_action(
        state,
        target_host,
        &format!("CONNECT {target_host}"),
        result,
        status_code,
        actor,
    );
}

/// Emit an audit event for an HTTP forward proxy request.
fn emit_http_audit(
    state: &Arc<ProxyState>,
    target_host: &str,
    method: &str,
    path: &str,
    result: &str,
    status_code: u16,
    actor: Option<&crate::peer_process::ActorContext>,
) {
    emit_audit_action(
        state,
        target_host,
        &format!("{method} http://{target_host}{path}"),
        result,
        status_code,
        actor,
    );
}

/// Emit an audit event back to Lens Sandbox via the WebSocket channel.
/// Failure events are deduplicated (at most one per host per AUDIT_DEDUP_SECS)
/// to suppress retry storms. Success and error events are always emitted.
fn emit_audit_action(
    state: &Arc<ProxyState>,
    target_host: &str,
    action: &str,
    result: &str,
    status_code: u16,
    actor: Option<&crate::peer_process::ActorContext>,
) {
    emit_audit_action_with_metadata(state, target_host, action, result, status_code, None, actor);
}

/// Variant that attaches a `metadata` object to the audit_event. Used by
/// the policy-deny call sites so the relay's notify dispatcher can match
/// on `metadata.reason="policy-deny"` and surface the failure to the
/// developer as an Allow/Skip dialog.
fn emit_audit_action_with_metadata(
    state: &Arc<ProxyState>,
    target_host: &str,
    action: &str,
    result: &str,
    status_code: u16,
    metadata: Option<serde_json::Value>,
    actor: Option<&crate::peer_process::ActorContext>,
) {
    if result == "failure" {
        let hostname = if target_host.starts_with('[') {
            target_host
                .split(']')
                .next()
                .unwrap_or(target_host)
                .trim_start_matches('[')
        } else {
            target_host.split(':').next().unwrap_or(target_host)
        };

        let now = Instant::now();
        let mut dedup = state.deny_dedup.lock().unwrap();
        if let Some(last) = dedup.get(hostname)
            && now.duration_since(*last).as_secs() < AUDIT_DEDUP_SECS
        {
            return;
        }
        dedup.insert(hostname.to_string(), now);
        if dedup.len() > 1024 {
            dedup.clear();
        }
    }

    let tx = state.audit_tx.lock().unwrap();
    if let Some(tx) = tx.as_ref() {
        let mut event = serde_json::json!({
            "type": "audit_event",
            "source": "sandbox-proxy",
            "action": action,
            "result": result,
            "status_code": status_code,
        });
        if let Some(meta) = metadata {
            event["metadata"] = meta;
        }
        if let (Some(actor), Some(obj)) = (actor, event.as_object_mut()) {
            actor.augment(obj);
        }
        let _ = tx.send(event.to_string());
    }
}

/// Audit a CONNECT denied by policy. Carries `metadata.reason="policy-deny"`
/// so the relay daemon can surface it to the developer as an Allow/Skip
/// notification rather than letting it disappear into the audit log.
fn emit_policy_deny_connect(
    state: &Arc<ProxyState>,
    target_host: &str,
    actor: Option<&crate::peer_process::ActorContext>,
) {
    emit_audit_action_with_metadata(
        state,
        target_host,
        &format!("CONNECT {target_host}"),
        "failure",
        403,
        Some(serde_json::json!({"reason": "policy-deny"})),
        actor,
    );
}

/// Audit an HTTP forward request denied by policy. Same metadata as
/// emit_policy_deny_connect.
fn emit_policy_deny_http(
    state: &Arc<ProxyState>,
    target_host: &str,
    method: &str,
    path: &str,
    actor: Option<&crate::peer_process::ActorContext>,
) {
    emit_audit_action_with_metadata(
        state,
        target_host,
        &format!("{method} http://{target_host}{path}"),
        "failure",
        403,
        Some(serde_json::json!({"reason": "policy-deny"})),
        actor,
    );
}

/// Emit a decision audit event the moment the gate resolves on the
/// *allow* path. This is a policy-decision marker — "user-allowed-once"
/// / "user-allowed-persisted" — not a request-outcome event. The
/// downstream dispatch arm (MITM, AWS-resign, TLS bridge, plain relay) is
/// responsible for the request's own audit event when the transport
/// actually completes; emitting `result`/`status_code` here would
/// double-count allows and paint false successes when the upstream
/// connect later fails.
///
/// Bypasses both dedup pools intentionally: a fresh user click is not a
/// retry storm, even if a second click on the same host arrives inside
/// the storm window.
pub(crate) fn emit_gate_resolved(
    state: &Arc<ProxyState>,
    action: &str,
    decision: crate::protocol::Decision,
) {
    let tx = state.audit_tx.lock().unwrap();
    if let Some(tx) = tx.as_ref() {
        let event = serde_json::json!({
            "type": "audit_event",
            "source": "sandbox-proxy",
            "action": action,
            "metadata": {"reason": decision.audit_reason()},
        });
        let _ = tx.send(event.to_string());
    }
}

/// Audit the request-outcome failure for an `Ask`-verdict request whose
/// gate decision was a deny (user denied, or timed out). Carries
/// `result=failure, status_code=403` so audit consumers filtering on
/// `result == "failure"` see gate-denied requests the same way they see
/// policy-deny rejections; the `metadata.reason` (`user-denied-once`,
/// `decision-timeout`, …) records why the deny happened.
///
/// This is the sole audit event on the Ask→Deny path: no separate
/// marker is emitted, since the marker mapped to a synthetic
/// `result=failure` row in the audit table would double-count the same
/// denial against `WHERE result='failure'` queries.
///
/// Bypasses the failure-event dedup pool: a second user click on the
/// same host inside `AUDIT_DEDUP_SECS` is a fresh decision, not a retry
/// storm.
fn emit_gate_denied(state: &Arc<ProxyState>, action: &str, decision: crate::protocol::Decision) {
    let tx = state.audit_tx.lock().unwrap().clone();
    if let Some(tx) = tx {
        let event = serde_json::json!({
            "type": "audit_event",
            "source": "sandbox-proxy",
            "action": action,
            "result": "failure",
            "status_code": 403,
            "metadata": {"reason": decision.audit_reason()},
        });
        let _ = tx.send(event.to_string());
    }
}

/// Canonical dedup key for the JIT approval gate: bare hostname, no
/// port, no brackets. The three TCP entry points (explicit CONNECT,
/// transparent TLS, HTTP forward) hand us slightly different target
/// strings — CONNECT always carries `host:port`, HTTP forward usually
/// omits port, transparent TLS uses whatever `SO_ORIGINAL_DST` gives.
/// Normalising at the gate boundary so the same hostname reached via
/// different methods dedups onto one developer dialog instead of three.
pub(crate) fn gate_key(target: &str) -> String {
    if let Some(rest) = target.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        return rest[..end].to_string();
    }
    if let Some((host, port)) = target.rsplit_once(':')
        && !port.is_empty()
        && port.chars().all(|c| c.is_ascii_digit())
    {
        return host.to_string();
    }
    target.to_string()
}

/// Validate that a CONNECT target is safe to forward.
fn validate_connect_target(target: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Reject CRLF injection
    if target.contains('\r') || target.contains('\n') {
        return Err("CONNECT target contains CRLF".into());
    }

    // Reject loopback and link-local targets.
    // Handle bracketed IPv6 like [::1]:22
    let hostname = if target.starts_with('[') {
        target
            .split(']')
            .next()
            .unwrap_or(target)
            .trim_start_matches('[')
    } else {
        target.split(':').next().unwrap_or(target)
    };
    // Block localhost hostnames (not just IPs)
    let lower = hostname.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        return Err("CONNECT to localhost denied".into());
    }

    if let Ok(ip) = hostname.parse::<std::net::IpAddr>() {
        if ip.is_loopback() {
            return Err("CONNECT to loopback denied".into());
        }
        match ip {
            std::net::IpAddr::V4(v4) => {
                // 169.254.0.0/16
                if v4.octets()[0] == 169 && v4.octets()[1] == 254 {
                    return Err("CONNECT to link-local denied".into());
                }
            }
            std::net::IpAddr::V6(v6) => {
                // fe80::/10
                if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                    return Err("CONNECT to link-local denied".into());
                }
            }
        }
    }

    Ok(())
}

/// A parsed incoming proxy request — either CONNECT tunnel or HTTP forward proxy.
enum ProxyRequest {
    /// CONNECT host:port — tunnel mode (existing).
    Connect { target: String },
    /// HTTP forward proxy — method + absolute URL (e.g. GET http://host/path).
    /// `header_bytes` includes the full request headers (including request line).
    Http {
        target_host: String,
        header_bytes: Vec<u8>,
    },
}

/// Read an HTTP request line + headers one byte at a time so we never buffer
/// past the `\r\n\r\n` boundary. Returns either a CONNECT target or an HTTP
/// forward proxy request with the full headers preserved.
async fn read_proxy_request_unbuffered(
    stream: &mut TcpStream,
) -> Result<ProxyRequest, Box<dyn std::error::Error + Send + Sync>> {
    let header_bytes = read_until_double_crlf(stream).await?;
    let header_str = String::from_utf8_lossy(&header_bytes);

    let request_line = header_str.lines().next().ok_or("empty request")?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(format!("invalid request: {request_line}").into());
    }

    if parts[0] == "CONNECT" {
        return Ok(ProxyRequest::Connect {
            target: parts[1].to_string(),
        });
    }

    // HTTP forward proxy: method + absolute URL (e.g. "GET http://host:port/path HTTP/1.1")
    let url = parts[1];
    if let Some(target) = parse_http_forward_target(url) {
        Ok(ProxyRequest::Http {
            target_host: target,
            header_bytes,
        })
    } else {
        Err(format!("not a proxy request (relative URL or https://): {request_line}").into())
    }
}

/// Parse the `host[:port]` authority from an absolute-form HTTP URL.
/// Returns `None` for non-`http://` URLs. Handles bracketed IPv6 authorities
/// (`http://[::1]:8080/`) and URLs with a query but no path (`http://host?q=1`).
/// Defaults to port 80 when unspecified.
fn parse_http_forward_target(url: &str) -> Option<String> {
    let rest = url.strip_prefix("http://")?;
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];

    // For bracketed IPv6 (`[::1]`), the port follows the closing `]`.
    // For bare hosts, any `:` indicates a port.
    let has_explicit_port = if authority.starts_with('[') {
        authority
            .rfind(']')
            .is_some_and(|close| authority[close + 1..].starts_with(':'))
    } else {
        authority.contains(':')
    };

    Some(if has_explicit_port {
        authority.to_string()
    } else {
        format!("{authority}:80")
    })
}

/// Read an HTTP response status line + headers one byte at a time.
/// Returns the status code + reason (e.g. "200 Connection Established").
async fn read_response_status_unbuffered<S>(
    stream: &mut S,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let header_bytes = read_until_double_crlf(stream).await?;
    let header_str = String::from_utf8_lossy(&header_bytes);

    let status_line = header_str.lines().next().ok_or("empty response")?;

    // "HTTP/1.1 200 Connection Established" -> "200 Connection Established"
    let status = status_line
        .split_once(' ')
        .map(|(_, rest)| rest)
        .unwrap_or("")
        .to_string();

    Ok(status)
}

/// Read from an `AsyncRead` one byte at a time until we see `\r\n\r\n`.
/// Returns all bytes read (including the final `\r\n\r\n`).
/// Caps at 8KB to prevent abuse.
async fn read_until_double_crlf<S>(
    stream: &mut S,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + Unpin + ?Sized,
{
    use tokio::io::AsyncReadExt;

    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];

    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err("connection closed before end of headers".into());
        }
        buf.push(byte[0]);

        if buf.len() >= 4 && buf[buf.len() - 4..] == *b"\r\n\r\n" {
            return Ok(buf);
        }
        if buf.len() > 8192 {
            return Err("headers too large".into());
        }
    }
}

/// Parse an HTTPS_PROXY URL into a `SandboxUpstream`. Accepts both `http://` and
/// `https://`; the scheme is recorded in [`SandboxUpstream::tls`] and drives whether
/// [`connect_sandbox_upstream`] TLS-wraps the socket before the CONNECT envelope.
/// Returns `None` for any other scheme or a malformed authority.
pub fn parse_upstream_url(url: &str) -> Option<SandboxUpstream> {
    // Strip scheme. The scheme dictates whether the upstream connection is
    // TLS-wrapped before the CONNECT envelope is written.
    let (without_scheme, tls) = if let Some(rest) = url.strip_prefix("https://") {
        (rest, true)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (rest, false)
    } else {
        return None;
    };

    let (auth, host_port) = if let Some(at_pos) = without_scheme.rfind('@') {
        let auth_part = &without_scheme[..at_pos];
        let host_part = &without_scheme[at_pos + 1..];
        // Decode percent-encoding (e.g. %2F → /) before base64 encoding,
        // since Lens Sandbox builds the URL with encodeURIComponent(token).
        let decoded = percent_decode(auth_part);
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            decoded.as_bytes(),
        );
        (Some(format!("Basic {encoded}")), host_part)
    } else {
        (None, without_scheme)
    };

    // Strip trailing slash
    let host_port = host_port.trim_end_matches('/');

    let (host, port) = if let Some((h, p)) = host_port.rsplit_once(':') {
        let port = p.parse::<u16>().ok()?;
        (h.to_string(), port)
    } else {
        (host_port.to_string(), 3128)
    };

    Some(SandboxUpstream {
        host,
        port,
        auth_header: auth,
        tls,
    })
}

/// Dial the Lens Sandbox upstream and (optionally) TLS-wrap the socket. Returns
/// a type-erased stream so the caller can write the CONNECT envelope and feed
/// the same handle into MITM / passthrough without caring whether the wire is
/// plain HTTP or HTTPS.
///
/// Trust source: `state.extra_ca_certs` (populated by `client.rs:handle_policy`
/// from the `proxyCaCert` policy field — which the TypeScript side builds by
/// concatenating the MITM proxy CA and the Lens Sandbox self-signed CA).
pub async fn connect_sandbox_upstream(
    state: &ProxyState,
    upstream: &SandboxUpstream,
) -> Result<BoxedSandboxStream, Box<dyn std::error::Error + Send + Sync>> {
    let addr = format!("{}:{}", upstream.host, upstream.port);
    let connect_timeout = *state.upstream_connect_timeout.read().unwrap();
    let tcp =
        match tokio::time::timeout(connect_timeout, sock_mark::connect_tcp_resolve(&addr)).await {
            Ok(result) => result?,
            Err(_) => return Err(format!("upstream TCP connect to {addr} timed out").into()),
        };
    if !upstream.tls {
        return Ok(Box::new(tcp));
    }
    let connector = get_or_build_sandbox_tls_connector(state);
    let server_name = rustls::pki_types::ServerName::try_from(upstream.host.clone())?;
    let tls_stream =
        match tokio::time::timeout(connect_timeout, connector.connect(server_name, tcp)).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(
                    format!("upstream TLS handshake to {} timed out", upstream.host).into(),
                );
            }
        };
    Ok(Box::new(tls_stream))
}

/// Return the cached `TlsConnector` for the Lens Sandbox upstream, building one
/// on first use (or after a policy refresh has cleared the cache). The trust
/// store layers webpki publicly-trusted roots — so ALB/ACM-fronted deployments
/// work with no extra policy plumbing — over `extra_ca_certs`, which carries the
/// in-cluster self-signed CA from the policy frame.
fn get_or_build_sandbox_tls_connector(state: &ProxyState) -> tokio_rustls::TlsConnector {
    if let Some(connector) = state.sandbox_tls_connector.read().unwrap().as_ref() {
        return connector.clone();
    }
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for cert in state.extra_ca_certs.read().unwrap().iter() {
        if let Err(e) = root_store.add(cert.clone()) {
            tracing::warn!(error = %e, "skipping extra CA cert for Lens Sandbox upstream trust");
        }
    }
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    *state.sandbox_tls_connector.write().unwrap() = Some(connector.clone());
    connector
}

/// Decode percent-encoded strings (e.g. `%2F` → `/`).
fn percent_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2
                && let Ok(byte) = u8::from_str_radix(&hex, 16)
            {
                result.push(byte as char);
                continue;
            }
            // Malformed — keep as-is
            result.push('%');
            result.push_str(&hex);
        } else {
            result.push(c);
        }
    }
    result
}

fn extract_hostname(target: &str) -> String {
    if target.starts_with('[') {
        // IPv6 bracket notation
        target
            .split(']')
            .next()
            .unwrap_or(target)
            .trim_start_matches('[')
            .to_string()
    } else {
        target.split(':').next().unwrap_or(target).to_string()
    }
}

fn extract_port(target: &str, default: u16) -> u16 {
    if target.starts_with('[') {
        target
            .rsplit_once("]:")
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or(default)
    } else {
        target
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or(default)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn parse_upstream_with_auth() {
        let u = parse_upstream_url("http://user:pass@proxy.example.com:8080").unwrap();
        assert_eq!(u.host, "proxy.example.com");
        assert_eq!(u.port, 8080);
        assert!(u.auth_header.as_ref().unwrap().starts_with("Basic "));
        assert!(!u.tls);
    }

    #[test]
    fn parse_upstream_no_auth() {
        let u = parse_upstream_url("http://proxy.example.com:3128").unwrap();
        assert_eq!(u.host, "proxy.example.com");
        assert_eq!(u.port, 3128);
        assert!(u.auth_header.is_none());
        assert!(!u.tls);
    }

    #[test]
    fn parse_upstream_https_scheme_sets_tls_flag() {
        let u = parse_upstream_url("https://sandbox:tok@nexus.example.com:3003").unwrap();
        assert_eq!(u.host, "nexus.example.com");
        assert_eq!(u.port, 3003);
        assert!(u.tls);
        assert!(u.auth_header.is_some());
    }

    #[test]
    fn parse_upstream_no_port() {
        let u = parse_upstream_url("http://proxy.example.com").unwrap();
        assert_eq!(u.host, "proxy.example.com");
        assert_eq!(u.port, 3128);
    }

    #[test]
    fn parse_upstream_trailing_slash() {
        let u = parse_upstream_url("http://proxy.example.com:9090/").unwrap();
        assert_eq!(u.host, "proxy.example.com");
        assert_eq!(u.port, 9090);
    }

    #[test]
    fn parse_upstream_invalid() {
        assert!(parse_upstream_url("not-a-url").is_none());
    }

    #[test]
    fn parse_upstream_invalid_port_returns_none() {
        assert!(parse_upstream_url("http://proxy.example.com:abc").is_none());
    }

    #[test]
    fn parse_upstream_percent_encoded_token() {
        // Lens Sandbox builds URLs with encodeURIComponent(token), e.g. slashes become %2F
        let u = parse_upstream_url("http://user:tok%2Fen@proxy.example.com:8080").unwrap();
        assert_eq!(u.host, "proxy.example.com");
        assert_eq!(u.port, 8080);
        // The Basic header should contain the decoded "user:tok/en", not "user:tok%2Fen"
        let header = u.auth_header.unwrap();
        let b64 = header.strip_prefix("Basic ").unwrap();
        let decoded = String::from_utf8(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64).unwrap(),
        )
        .unwrap();
        assert_eq!(decoded, "user:tok/en");
    }

    #[test]
    fn percent_decode_basic() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("no%2Fslash"), "no/slash");
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("%25percent"), "%percent");
    }

    #[test]
    fn validate_rejects_crlf() {
        assert!(validate_connect_target("evil.com:443\r\nInjected: yes").is_err());
    }

    #[test]
    fn validate_rejects_loopback_v4() {
        assert!(validate_connect_target("127.0.0.1:22").is_err());
    }

    #[test]
    fn validate_rejects_loopback_v6() {
        assert!(validate_connect_target("[::1]:22").is_err());
    }

    #[test]
    fn validate_rejects_link_local() {
        assert!(validate_connect_target("169.254.169.254:80").is_err());
    }

    #[test]
    fn validate_rejects_link_local_v6() {
        assert!(validate_connect_target("[fe80::1]:80").is_err());
    }

    #[test]
    fn validate_rejects_localhost() {
        assert!(validate_connect_target("localhost:22").is_err());
    }

    #[test]
    fn validate_rejects_subdomain_localhost() {
        assert!(validate_connect_target("foo.localhost:22").is_err());
    }

    #[test]
    fn validate_accepts_normal_target() {
        assert!(validate_connect_target("api.github.com:443").is_ok());
    }

    #[test]
    fn validate_accepts_ip_target() {
        assert!(validate_connect_target("1.2.3.4:443").is_ok());
    }

    #[test]
    fn gate_key_strips_port_from_hostname() {
        assert_eq!(gate_key("evil.example.com:443"), "evil.example.com");
        assert_eq!(gate_key("evil.example.com"), "evil.example.com");
    }

    #[test]
    fn gate_key_strips_port_from_ipv4() {
        assert_eq!(gate_key("1.2.3.4:443"), "1.2.3.4");
        assert_eq!(gate_key("1.2.3.4"), "1.2.3.4");
    }

    #[test]
    fn gate_key_unwraps_bracketed_ipv6() {
        // CONNECT/transparent paths emit `[::1]:443`; the bare hostname for
        // the dedup key is `::1`, matching what the user reads in a dialog.
        assert_eq!(gate_key("[::1]:443"), "::1");
        assert_eq!(gate_key("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(gate_key("[::1]"), "::1");
    }

    #[test]
    fn gate_key_dedups_across_entry_points() {
        // CONNECT carries port, HTTP forward usually doesn't — both must
        // collapse onto the same dedup key so the developer sees one dialog
        // for the same destination, regardless of which path tripped the gate.
        assert_eq!(gate_key("api.evil.com:443"), gate_key("api.evil.com"));
    }

    pub(crate) fn test_state() -> (Arc<ProxyState>, mpsc::UnboundedReceiver<String>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let state = Arc::new(ProxyState {
            upstream: Mutex::new(None),
            routes: RwLock::new(Vec::new()),
            default_verdict: RwLock::new(Verdict::Allow),
            default_transport: RwLock::new(Transport::Upstream),
            audit_tx: std::sync::Mutex::new(Some(tx)),
            deny_dedup: std::sync::Mutex::new(HashMap::new()),
            credential_injections: RwLock::new(HashMap::new()),
            ephemeral_ca: std::sync::OnceLock::new(),
            client_certs: RwLock::new(HashMap::new()),
            uri_placeholder_injections: RwLock::new(HashMap::new()),
            extra_ca_certs: RwLock::new(Vec::new()),
            sandbox_tls_connector: RwLock::new(None),
            previous_policy_files: RwLock::new(Vec::new()),
            sandbox_creds: None,
            aws_resign: Arc::new(crate::aws_resign::AwsResignInterceptor::new()),
            pending: std::sync::Mutex::new(crate::gate::PendingTable::new()),
            credential_pending: std::sync::Mutex::new(crate::gate::PendingTable::new()),
            placeholder_index: RwLock::new(HashMap::new()),
            unarmed_credential_domains: RwLock::new(Vec::new()),
            decision_timeout: std::sync::RwLock::new(crate::gate::DECISION_TIMEOUT),
            upstream_connect_timeout: std::sync::RwLock::new(UPSTREAM_CONNECT_TIMEOUT),
            bootstrap_dns_allowlist: Vec::new(),
            gate_resolved_hosts: RwLock::new(HashSet::new()),
        });
        (state, rx)
    }

    /// A timeout must bound the upstream TLS handshake. A peer that accepts the
    /// TCP connection but never sends a ServerHello would otherwise hang the
    /// connect forever; with a small budget the call returns a `timed out`
    /// error promptly. If the timeout were removed this test would hang past
    /// its deadline instead of asserting — i.e. it fails when the guard is lost.
    #[tokio::test]
    async fn upstream_tls_handshake_times_out() {
        // Building the TLS connector needs a process-wide rustls CryptoProvider;
        // install it (no-op if another test already installed the default).
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Accept the connection but never speak TLS, stalling the client's
        // handshake until the upstream timeout fires.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _silent_peer = tokio::spawn(async move {
            let _accepted = listener.accept().await;
            std::future::pending::<()>().await;
        });

        let (state, _rx) = test_state();
        *state.upstream_connect_timeout.write().unwrap() = Duration::from_millis(50);

        let upstream = SandboxUpstream {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            auth_header: None,
            tls: true,
        };

        // `BoxedSandboxStream` isn't `Debug`, so match rather than `expect_err`.
        let err = match connect_sandbox_upstream(&state, &upstream).await {
            Ok(_) => panic!("handshake against a silent peer must time out"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("timed out"),
            "expected a timeout error, got: {err}"
        );
    }

    #[test]
    fn emit_audit_sends_connect_action_format() {
        let (state, mut rx) = test_state();
        emit_audit(&state, "api.openai.com:443", "success", 200, None);

        let msg = rx.try_recv().unwrap();
        let event: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(event["type"], "audit_event");
        assert_eq!(event["source"], "sandbox-proxy");
        assert_eq!(event["action"], "CONNECT api.openai.com:443");
        assert_eq!(event["result"], "success");
        assert_eq!(event["status_code"], 200);
    }

    #[test]
    fn emit_policy_deny_connect_carries_reason_metadata() {
        let (state, mut rx) = test_state();
        emit_policy_deny_connect(&state, "evil.example.com:443", None);

        let msg = rx.try_recv().unwrap();
        let event: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(event["action"], "CONNECT evil.example.com:443");
        assert_eq!(event["result"], "failure");
        assert_eq!(event["status_code"], 403);
        assert_eq!(event["metadata"]["reason"], "policy-deny");
    }

    #[test]
    fn emit_policy_deny_http_carries_reason_metadata() {
        let (state, mut rx) = test_state();
        emit_policy_deny_http(&state, "evil.example.com", "GET", "/x", None);

        let msg = rx.try_recv().unwrap();
        let event: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(event["action"], "GET http://evil.example.com/x");
        assert_eq!(event["result"], "failure");
        assert_eq!(event["status_code"], 403);
        assert_eq!(event["metadata"]["reason"], "policy-deny");
    }

    #[test]
    fn emit_policy_deny_http_stamps_the_client_endpoint_when_an_actor_is_supplied() {
        let (state, mut rx) = test_state();
        let actor = crate::peer_process::ActorContext::resolve("10.0.0.5:54321".parse().unwrap());
        emit_policy_deny_http(&state, "evil.example.com", "GET", "/x", Some(&actor));

        let msg = rx.try_recv().unwrap();
        let event: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(event["action"], "GET http://evil.example.com/x");
        assert_eq!(
            event["src_endpoint"],
            serde_json::json!({"ip": "10.0.0.5", "port": 54321})
        );
    }

    #[test]
    fn emit_http_audit_sends_method_and_path() {
        let (state, mut rx) = test_state();
        emit_http_audit(
            &state,
            "example.com:8080",
            "GET",
            "/api/data",
            "success",
            200,
            None,
        );

        let msg = rx.try_recv().unwrap();
        let event: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(event["action"], "GET http://example.com:8080/api/data");
        assert_eq!(event["result"], "success");
    }

    #[test]
    fn emit_audit_failure_dedup_suppresses_rapid_repeats() {
        let (state, mut rx) = test_state();
        emit_audit(&state, "evil.com:443", "failure", 403, None);
        emit_audit(&state, "evil.com:443", "failure", 403, None);

        assert!(rx.try_recv().is_ok());
        assert!(
            rx.try_recv().is_err(),
            "second failure should be deduplicated"
        );
    }

    #[test]
    fn emit_audit_success_not_deduplicated() {
        let (state, mut rx) = test_state();
        emit_audit(&state, "api.openai.com:443", "success", 200, None);
        emit_audit(&state, "api.openai.com:443", "success", 200, None);

        assert!(rx.try_recv().is_ok());
        assert!(
            rx.try_recv().is_ok(),
            "success events should not be deduplicated"
        );
    }

    #[test]
    fn emit_audit_error_not_deduplicated() {
        let (state, mut rx) = test_state();
        emit_audit(&state, "api.openai.com:443", "error", 502, None);
        emit_audit(&state, "api.openai.com:443", "error", 502, None);

        assert!(rx.try_recv().is_ok());
        assert!(
            rx.try_recv().is_ok(),
            "error events should not be deduplicated"
        );
    }

    #[test]
    fn transparent_deny_distinguishes_different_ports_on_same_ip() {
        // A process that probes `evil.com:443`, `evil.com:8443`,
        // `evil.com:8080` in quick succession produces three distinct
        // policy-relevant events. The dedup key includes the port so
        // they aren't collapsed into a single audit entry.
        let (state, mut rx) = test_state();
        emit_transparent_deny(&state, "1.2.3.4:443".parse().unwrap(), "unknown-protocol");
        emit_transparent_deny(&state, "1.2.3.4:8443".parse().unwrap(), "unknown-protocol");
        emit_transparent_deny(&state, "1.2.3.4:8080".parse().unwrap(), "unknown-protocol");

        assert!(rx.try_recv().is_ok(), "port 443 deny should emit");
        assert!(rx.try_recv().is_ok(), "port 8443 deny should emit");
        assert!(rx.try_recv().is_ok(), "port 8080 deny should emit");
    }

    #[test]
    fn transparent_deny_dedups_repeated_hits_on_same_ip_port() {
        // Same IP+port within the dedup window collapses to one event —
        // otherwise a tight retry loop would spam the audit channel.
        let (state, mut rx) = test_state();
        let orig_dst: SocketAddr = "1.2.3.4:443".parse().unwrap();
        emit_transparent_deny(&state, orig_dst, "unknown-protocol");
        emit_transparent_deny(&state, orig_dst, "unknown-protocol");

        assert!(rx.try_recv().is_ok(), "first deny emits");
        assert!(rx.try_recv().is_err(), "second deny is suppressed");
    }

    #[test]
    fn transparent_deny_does_not_suppress_connect_deny_on_same_ip() {
        // Prove the `t:` key prefix isolates the two dedup key spaces.
        // Without the prefix, a CONNECT failure to `1.2.3.4:443` would
        // share a key with a transparent denial on `1.2.3.4`, silently
        // swallowing one of the audit events.
        let (state, mut rx) = test_state();
        let orig_dst: SocketAddr = "1.2.3.4:443".parse().unwrap();
        emit_transparent_deny(&state, orig_dst, "unknown-protocol");
        emit_audit(&state, "1.2.3.4:443", "failure", 403, None);

        assert!(rx.try_recv().is_ok(), "transparent deny should emit");
        assert!(
            rx.try_recv().is_ok(),
            "connect deny on same IP must not be suppressed by transparent-deny's dedup entry"
        );
    }

    #[test]
    fn emit_deny_dedup_different_hosts_not_suppressed() {
        let (state, mut rx) = test_state();
        emit_audit(&state, "evil.com:443", "failure", 403, None);
        emit_audit(&state, "other.com:443", "failure", 403, None);

        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn emit_gate_resolved_is_decision_marker_without_result_or_status_code() {
        let (state, mut rx) = test_state();
        emit_gate_resolved(
            &state,
            "CONNECT evil.example.com:443",
            crate::protocol::Decision::AllowOnce,
        );

        let msg = rx.try_recv().unwrap();
        let event: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(event["type"], "audit_event");
        assert_eq!(event["action"], "CONNECT evil.example.com:443");
        assert_eq!(event["metadata"]["reason"], "user-allowed-once");
        assert!(
            event.get("result").is_none(),
            "gate decision must not carry result"
        );
        assert!(
            event.get("status_code").is_none(),
            "gate decision must not carry status_code"
        );
    }

    #[test]
    fn emit_gate_denied_bypasses_failure_dedup_for_repeated_user_decisions() {
        // A second user click on the same host inside AUDIT_DEDUP_SECS is a
        // real new decision, not a retry storm — both audits must surface so
        // the audit log records every distinct denial intent.
        let (state, mut rx) = test_state();
        emit_gate_denied(
            &state,
            "CONNECT evil.example.com:443",
            crate::protocol::Decision::DenyOnce,
        );
        emit_gate_denied(
            &state,
            "CONNECT evil.example.com:443",
            crate::protocol::Decision::DenyOnce,
        );

        let first: serde_json::Value = serde_json::from_str(&rx.try_recv().unwrap()).unwrap();
        assert_eq!(first["result"], "failure");
        assert_eq!(first["metadata"]["reason"], "user-denied-once");
        let second: serde_json::Value = serde_json::from_str(&rx.try_recv().unwrap()).unwrap();
        assert_eq!(second["result"], "failure");
        assert_eq!(second["metadata"]["reason"], "user-denied-once");
    }

    #[test]
    fn emit_gate_denied_does_not_consume_policy_deny_dedup_slot() {
        // The gate-deny path runs through its own emit (no shared dedup pool),
        // so a real policy-deny on the same hostname right after still emits.
        let (state, mut rx) = test_state();
        emit_gate_denied(
            &state,
            "CONNECT evil.com:443",
            crate::protocol::Decision::DenyOnce,
        );
        emit_policy_deny_connect(&state, "evil.com:443", None);

        assert!(rx.try_recv().is_ok(), "gate-denied failure emits");
        assert!(
            rx.try_recv().is_ok(),
            "policy-deny on same host must not be suppressed by gate-denied dedup",
        );
    }

    /// Helper for the Ask end-to-end tests. Installs a single `Verdict::Ask`
    /// rule (transport defaulted to `Upstream`) for `domain`.
    fn install_ask_route(state: &Arc<ProxyState>, domain: &str) {
        state
            .routes
            .write()
            .unwrap()
            .push(crate::routing::RouteRule {
                matcher: crate::routing::RouteMatcher::Domain(domain.to_string()),
                verdict: Verdict::Ask,
                transport: Transport::Upstream,
                tls_terminate: false,
                http_rules: Vec::new(),
                scheme: None,
            });
    }

    /// Drain everything currently on `rx` and decode as JSON, ignoring any
    /// line that fails to parse (e.g. test fixtures that emit non-JSON).
    fn drain_audit_lines(rx: &mut mpsc::UnboundedReceiver<String>) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        while let Ok(line) = rx.try_recv() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                out.push(v);
            }
        }
        out
    }

    #[tokio::test]
    async fn handle_connect_ask_path_denies_on_user_decision() {
        // Verdict::Ask should suspend the request, emit `request_pending`
        // keyed on the bare hostname (no port — see `gate_key`), await a
        // decision, and on Deny:
        //   - send HTTP/1.1 403 to the client
        //   - emit a single `user-denied-once` outcome event
        //     (result=failure, status=403). No decision marker — the marker
        //     would double-count the failure in audit consumers.
        let (state, mut rx) = test_state();
        install_ask_route(&state, "evil.example.com");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let state_for_handler = state.clone();
        let handler = tokio::spawn(async move {
            let actor =
                crate::peer_process::ActorContext::resolve("10.0.0.5:44000".parse().unwrap());
            handle_connect(server, "evil.example.com:443", &actor, &state_for_handler).await
        });

        let pending = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("request_pending arrived")
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&pending).unwrap();
        assert_eq!(parsed["type"], "request_pending");
        assert_eq!(parsed["host"], "evil.example.com");
        let id = parsed["id"].as_str().unwrap().to_string();

        assert!(crate::gate::resolve_pending(
            &state,
            &id,
            crate::protocol::Decision::DenyOnce,
        ));

        handler.await.unwrap().unwrap();

        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 256];
        let n = client.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "expected 403; got: {response:?}"
        );

        let events = drain_audit_lines(&mut rx);
        let user_denied: Vec<_> = events
            .iter()
            .filter(|ev| ev["metadata"]["reason"] == "user-denied-once")
            .collect();
        assert_eq!(
            user_denied.len(),
            1,
            "exactly one user-denied-once event; got {events:?}"
        );
        let failure = user_denied[0];
        assert_eq!(failure["action"], "CONNECT evil.example.com:443");
        assert_eq!(failure["result"], "failure");
        assert_eq!(failure["status_code"], 403);
    }

    #[tokio::test]
    async fn handle_connect_ask_path_emits_decision_on_user_allow() {
        // Verifies the Ask→Allow wiring: `request_pending` carries the bare
        // hostname, and a `user-allowed-once` decision marker is emitted as
        // soon as the gate resolves. The downstream forwarding attempt is
        // unobserved (covered by Direct-path tests). We abort the handler
        // once the decision lands.
        let (state, mut rx) = test_state();
        install_ask_route(&state, "evil.example.com");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let state_for_handler = state.clone();
        let handler = tokio::spawn(async move {
            let actor =
                crate::peer_process::ActorContext::resolve("10.0.0.5:44000".parse().unwrap());
            handle_connect(server, "evil.example.com:443", &actor, &state_for_handler).await
        });

        let pending = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("request_pending arrived")
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&pending).unwrap();
        assert_eq!(parsed["host"], "evil.example.com");
        let id = parsed["id"].as_str().unwrap().to_string();
        assert!(crate::gate::resolve_pending(
            &state,
            &id,
            crate::protocol::Decision::AllowOnce,
        ));

        let decision = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("decision audit arrived")
            .unwrap();
        let ev: serde_json::Value = serde_json::from_str(&decision).unwrap();
        assert_eq!(ev["metadata"]["reason"], "user-allowed-once");
        assert_eq!(ev["action"], "CONNECT evil.example.com:443");
        assert!(ev.get("result").is_none());
        assert!(ev.get("status_code").is_none());

        handler.abort();
    }

    #[tokio::test]
    async fn handle_connect_ask_then_offer_armed_credential_mitms_the_held_connection() {
        // Regression: accepting an integration offer during a Verdict::Ask hold arms a
        // credential mid-connection. The resumed request must MITM so the freshly-armed
        // token is injected — collecting the injection snapshot *before* the gate (the
        // old bug) left it empty, so the held connection was plain-relayed and the
        // placeholder leaked upstream. `ephemeral_ca` is initialised only on the MITM
        // dispatch, never on the plain relay, so its presence proves the resumed
        // connection was terminated rather than forwarded raw.
        let (state, mut rx) = test_state();
        *state.default_verdict.write().unwrap() = Verdict::Ask;
        *state.default_transport.write().unwrap() = Transport::Direct;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let state_for_handler = state.clone();
        let handler = tokio::spawn(async move {
            let actor =
                crate::peer_process::ActorContext::resolve("10.0.0.5:44000".parse().unwrap());
            handle_connect(
                server,
                "api.some-provider.example:443",
                &actor,
                &state_for_handler,
            )
            .await
        });

        let pending = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("request_pending arrived")
            .unwrap();
        let id = serde_json::from_str::<serde_json::Value>(&pending).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();

        // Accepting the offer mid-hold arms the credential for the held host.
        state.credential_injections.write().unwrap().insert(
            "api.some-provider.example".to_string(),
            vec![CredentialInjection {
                header: "Authorization".to_string(),
                value: "Bearer some-token".to_string(),
                rules: Vec::new(),
            }],
        );
        assert!(crate::gate::resolve_pending(
            &state,
            &id,
            crate::protocol::Decision::AllowOnce,
        ));

        // Reading the `200 Connection Established` means dispatch has begun; the MITM
        // arm then initialises the CA before terminating TLS.
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("proxy responded to CONNECT")
            .unwrap();
        assert!(
            String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"),
            "expected the tunnel to be established"
        );

        let mut mitmed = false;
        for _ in 0..40 {
            if state.ephemeral_ca.get().is_some() {
                mitmed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            mitmed,
            "the resumed connection must MITM so the offer-armed credential is injected; \
             a stale pre-gate injection snapshot would have plain-relayed the placeholder"
        );

        handler.abort();
    }

    #[tokio::test]
    async fn handle_http_forward_ask_path_denies_on_user_decision() {
        // Same shape as the CONNECT test, but exercising the HTTP
        // forward-proxy dispatch arm.
        let (state, mut rx) = test_state();
        install_ask_route(&state, "api.evil.example.com");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let header_bytes = b"GET http://api.evil.example.com/foo HTTP/1.1\r\n\
                             Host: api.evil.example.com\r\n\r\n"
            .to_vec();

        let state_for_handler = state.clone();
        let handler = tokio::spawn(async move {
            handle_http_forward(
                server,
                "api.evil.example.com",
                header_bytes,
                &state_for_handler,
                None,
            )
            .await
        });

        let pending = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("request_pending arrived")
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&pending).unwrap();
        assert_eq!(parsed["type"], "request_pending");
        assert_eq!(parsed["host"], "api.evil.example.com");
        let id = parsed["id"].as_str().unwrap().to_string();

        assert!(crate::gate::resolve_pending(
            &state,
            &id,
            crate::protocol::Decision::DenyAlways,
        ));

        handler.await.unwrap().unwrap();

        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 256];
        let n = client.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "expected 403; got: {response:?}"
        );

        let events = drain_audit_lines(&mut rx);
        let user_denied: Vec<_> = events
            .iter()
            .filter(|ev| ev["metadata"]["reason"] == "user-denied-persisted")
            .collect();
        assert_eq!(
            user_denied.len(),
            1,
            "exactly one user-denied-persisted event; got {events:?}"
        );
        let failure = user_denied[0];
        assert_eq!(failure["action"], "GET http://api.evil.example.com/foo");
        assert_eq!(failure["result"], "failure");
        assert_eq!(failure["status_code"], 403);
    }

    // --- collect_uri_placeholders tests ---
    // These prove the guard condition for MITM dispatch: a domain with
    // only uriPlaceholder injections (no header injections, no http rules)
    // must still trigger MITM so the placeholder gets rewritten.

    #[test]
    fn collect_uri_placeholders_returns_matching_pairs() {
        let (state, _rx) = test_state();
        {
            let mut map = state.uri_placeholder_injections.write().unwrap();
            map.insert(
                "api.telegram.org".into(),
                vec![("__lens_cred:tg__".into(), "123:ABC".into())],
            );
        }
        let result = collect_uri_placeholders(&state, "api.telegram.org:443");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "__lens_cred:tg__");
        assert_eq!(result[0].1, "123:ABC");
    }

    #[test]
    fn collect_uri_placeholders_empty_for_non_matching_domain() {
        let (state, _rx) = test_state();
        {
            let mut map = state.uri_placeholder_injections.write().unwrap();
            map.insert(
                "api.telegram.org".into(),
                vec![("__lens_cred:tg__".into(), "123:ABC".into())],
            );
        }
        let result = collect_uri_placeholders(&state, "api.openai.com:443");
        assert!(
            result.is_empty(),
            "non-matching domain should return empty: {result:?}"
        );
    }

    #[test]
    fn collect_uri_placeholders_empty_when_no_injections() {
        let (state, _rx) = test_state();
        let result = collect_uri_placeholders(&state, "api.telegram.org:443");
        assert!(result.is_empty());
    }

    // --- rewrite_http_forward_request tests ---

    #[test]
    fn rewrite_replaces_absolute_url_with_relative_path() {
        let header = "GET http://example.com:8080/api/data HTTP/1.1\r\nHost: example.com:8080\r\n";
        let result = rewrite_http_forward_request(header, "/api/data", "example.com:8080");
        assert!(result.starts_with("GET /api/data HTTP/1.1\r\n"));
        assert!(result.contains("Host: example.com:8080"));
    }

    #[test]
    fn rewrite_overwrites_host_header() {
        // Host header should always match target_host, even if the original differs
        let header = "POST http://svc.local/path HTTP/1.1\r\nHost: wrong-host\r\nContent-Type: application/json\r\n";
        let result = rewrite_http_forward_request(header, "/path", "svc.local:80");
        assert!(result.contains("Content-Type: application/json"));
        assert!(result.contains("Host: svc.local:80"));
        assert!(!result.contains("Host: wrong-host"));
    }

    #[test]
    fn rewrite_strips_proxy_headers() {
        let header = "GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic abc\r\nProxy-Connection: keep-alive\r\nAccept: */*\r\n";
        let result = rewrite_http_forward_request(header, "/path", "example.com:80");
        assert!(!result.contains("Proxy-Authorization"));
        assert!(!result.contains("Proxy-Connection"));
        assert!(result.contains("Accept: */*"));
    }

    #[test]
    fn rewrite_root_path() {
        let header = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n";
        let result = rewrite_http_forward_request(header, "/", "example.com:80");
        assert!(result.starts_with("GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn rewrite_inserts_host_header_when_missing() {
        let header = "GET http://example.com:9090/path HTTP/1.1\r\nAccept: */*\r\n";
        let result = rewrite_http_forward_request(header, "/path", "example.com:9090");
        assert!(result.contains("Host: example.com:9090"));
        let lines: Vec<&str> = result.split("\r\n").collect();
        assert_eq!(lines[1], "Host: example.com:9090");
    }

    // --- read_proxy_request_unbuffered tests (via tokio) ---

    #[tokio::test]
    async fn parse_connect_request() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            client
                .write_all(
                    b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n",
                )
                .await
                .unwrap();
        });

        // read_proxy_request_unbuffered needs a TcpStream, so we test the parsing logic
        // by directly checking header parsing instead.
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        server.read_to_end(&mut buf).await.unwrap();
        let header_str = String::from_utf8_lossy(&buf);
        let request_line = header_str.lines().next().unwrap();
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        assert_eq!(parts[0], "CONNECT");
        assert_eq!(parts[1], "api.github.com:443");
    }

    #[test]
    fn parse_http_target_explicit_port() {
        assert_eq!(
            parse_http_forward_target("http://svc.cluster.local:8080/api/v1/data").as_deref(),
            Some("svc.cluster.local:8080"),
        );
    }

    #[test]
    fn parse_http_target_defaults_port_80() {
        assert_eq!(
            parse_http_forward_target("http://example.com/path").as_deref(),
            Some("example.com:80"),
        );
    }

    #[test]
    fn parse_http_target_no_path() {
        assert_eq!(
            parse_http_forward_target("http://example.com").as_deref(),
            Some("example.com:80"),
        );
    }

    #[test]
    fn parse_http_target_query_no_path() {
        assert_eq!(
            parse_http_forward_target("http://example.com?q=1").as_deref(),
            Some("example.com:80"),
        );
    }

    #[test]
    fn parse_http_target_ipv6_default_port() {
        assert_eq!(
            parse_http_forward_target("http://[2001:db8::1]/foo").as_deref(),
            Some("[2001:db8::1]:80"),
        );
    }

    #[test]
    fn parse_http_target_ipv6_explicit_port() {
        assert_eq!(
            parse_http_forward_target("http://[2001:db8::1]:8080/foo").as_deref(),
            Some("[2001:db8::1]:8080"),
        );
    }

    #[test]
    fn parse_http_target_ipv6_no_path() {
        assert_eq!(
            parse_http_forward_target("http://[::1]").as_deref(),
            Some("[::1]:80"),
        );
    }

    #[test]
    fn parse_http_target_rejects_relative_url() {
        assert!(parse_http_forward_target("/path").is_none());
    }

    #[test]
    fn parse_http_target_rejects_https_url() {
        // HTTPS should use CONNECT, not forward proxy
        assert!(parse_http_forward_target("https://example.com/path").is_none());
    }
}
