use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore, mpsc};
use tokio::task::JoinSet;

use crate::routing::{
    HttpRule, RawTarget, RouteOutcome, RouteRule, Scheme, Transport, Verdict,
    find_matching_raw_egress, find_matching_route,
};
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

/// Well-known DNS port. The nat chain only redirects DNS over UDP to the stub, so
/// this is also the port whose TCP traffic must keep being dropped rather than
/// offered as a splice — see [`unclassified_splice_decision`].
const DNS_PORT: u16 = 53;

/// Floor and ceiling applied to a DNS record's TTL when pinning its IPs. The
/// floor keeps a 0-TTL answer usable long enough for the follow-up connect; the
/// ceiling bounds how long a stale pin outlives a policy change or a DNS
/// rebind. Values are seconds.
const PIN_TTL_FLOOR_SECS: u64 = 30;
const PIN_TTL_CAP_SECS: u64 = 3600;
/// Hard cap on the TOTAL number of pin entries across all IPs; a
/// prune-expired-then-refuse backstop against unbounded growth — whether from
/// many IPs, or from many distinct names all resolving to one IP (a wildcard
/// rule). Counting total entries rather than distinct IP keys is what bounds
/// both the store and the per-connect linear scan of a single IP's list.
///
/// One cap serves both raw tables, because one pin does: it records the name a
/// lookup was allowed for, not the rule that wanted it. So a workload resolving
/// many `egress.udp` names can crowd out `egress.tcp` pins, and the other way
/// round. What that costs is a raw splice or a datagram for a *hostname* rule,
/// never a permission — an unpinned name simply matches nothing.
const MAX_PINNED_ENTRIES: usize = 4096;

/// An IP pinned from a DNS answer for a hostname `egress.tcp` rule, plus its
/// expiry.
///
/// Stores the originating `qname`, not the winning rule: a DNS caller may skip
/// an earlier caller-scoped deny and pin from a later allow, so admitting a
/// raw-TCP connection must re-evaluate the ordered `tcp_egress` rules for this
/// name against the *connecting* caller — see [`tcp_egress_verdict`]. Storing
/// only the selected allow rule would let a different caller, one an earlier
/// deny would reject, reuse the pin.
#[derive(Debug, Clone)]
pub struct PinnedIp {
    pub qname: String,
    pub expiry: Instant,
}

/// The complete network egress policy as one atomically-published snapshot:
/// the L7 routes and their default verdict/transport, the raw-TCP rules, the
/// live DNS pins, and a generation counter. Every allow / deny / transport
/// decision reads these fields in combination (an L7 verdict falls back to the
/// default; a DNS classification pairs the L7 routes with the tcp rules and the
/// generation; a raw-TCP connect pairs the tcp rules with the pins), so they
/// must move together. Bundling them under one lock makes that consistency
/// structural rather than by-convention: a reader takes a single consistent
/// snapshot and a reload swaps the whole thing at once, so no decision can ever
/// combine fields from two different policy generations.
pub struct NetworkPolicy {
    /// Application-layer routes (`egress.http` / the deprecated `allowedRoutes`),
    /// consulted after protocol classification.
    pub routes: Vec<RouteRule>,
    /// Verdict applied when no `routes` entry matches the host.
    pub default_verdict: Verdict,
    /// Transport applied when no `routes` entry matches the host.
    pub default_transport: Transport,
    /// The `egress.tcp` rules as ONE ordered list, consulted before protocol
    /// classification. `Cidr`/`CidrPort` matchers match the resolved dst IP
    /// directly; `Domain`/`HostPort` matchers match only a dst IP that a live
    /// DNS pin bound to a name the rule covers (the raw path never sees a name,
    /// so hostname rules drive DNS-answer pinning). Both kinds are evaluated in
    /// one ordered pass by [`tcp_egress_verdict`] / `find_matching_raw_egress`,
    /// and the DNS stub gates lookups against the hostname entries of this same
    /// list via `hostname_match_for_caller`.
    pub tcp_egress: Vec<RouteRule>,
    /// The `egress.udp` rules as ONE ordered list, matched exactly as
    /// `tcp_egress` is — the same matchers, the same pins, the same ordered
    /// pass. What it governs, and what the default verdict has to do with it,
    /// is [`crate::policy_schema::Egress::udp`].
    pub udp_egress: Vec<RouteRule>,
    /// IPs pinned from DNS answers of hostname `tcp_egress` names, each carrying
    /// the originating `qname` and a TTL-bounded expiry. Consulted by
    /// [`tcp_egress_verdict`] to match hostname rules against a raw connection.
    pub pins: HashMap<IpAddr, Vec<PinnedIp>>,
    /// Optional LLM routing — where a request the sandbox addressed to one LLM
    /// API actually goes, and what it is translated into. Lives here because a
    /// redirect is an egress decision: the backend it names is judged by the
    /// same `routes` this snapshot carries, and a reload must not leave a route
    /// pointing into a superseded policy's table. `Arc` because every
    /// intercepted request reads it and none of them modifies it.
    pub llm: Arc<crate::llm::LlmRouting>,
    /// Bumped every time the policy is (re)applied. The DNS stub captures it
    /// when it authorizes a lookup and hands it back at pin-insertion time; an
    /// in-flight answer whose generation no longer matches is dropped, so a
    /// lookup authorized under a revoked policy can't reinstate a pin the new
    /// policy's tables no longer cover. Living under the same lock as the rules
    /// is what keeps the capture consistent with the rule reads.
    pub generation: u64,
}

impl NetworkPolicy {
    /// Whether two snapshots express the same egress policy.
    fn egress_eq(&self, other: &Self) -> bool {
        // Destructure so adding a NetworkPolicy field forces a decision here.
        let Self {
            routes,
            default_verdict,
            default_transport,
            tcp_egress,
            udp_egress,
            llm,
            pins: _,       // runtime state owned by apply_network_policy
            generation: _, // ditto
        } = self;
        *routes == other.routes
            && *default_verdict == other.default_verdict
            && *default_transport == other.default_transport
            && *tcp_egress == other.tcp_egress
            && *udp_egress == other.udp_egress
            && *llm == other.llm
    }
}

impl Default for NetworkPolicy {
    /// The pre-policy state: no routes or tcp rules, and an allow-all default
    /// via the upstream (matching the constructor's historical initial values;
    /// the first policy frame replaces it).
    fn default() -> Self {
        Self {
            routes: Vec::new(),
            default_verdict: Verdict::Allow,
            default_transport: Transport::Upstream,
            tcp_egress: Vec::new(),
            udp_egress: Vec::new(),
            llm: Arc::new(crate::llm::LlmRouting::default()),
            pins: HashMap::new(),
            generation: 0,
        }
    }
}

/// A single header injection for a credential bound to a domain.
#[derive(Debug, Clone)]
pub struct CredentialInjection {
    pub header: String,
    pub value: String,
    /// Optional path rules. When present, only inject for matching requests.
    /// When empty, inject for all requests to the domain.
    pub rules: Vec<crate::policy_schema::HttpRequestMatch>,
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
    /// The complete network egress policy — L7 routes + defaults, raw-TCP
    /// rules, DNS pins, and the generation — under one lock so every egress
    /// decision reads a consistent snapshot and a reload swaps it atomically.
    /// See [`NetworkPolicy`] for why these fields must live together.
    pub policy: RwLock<NetworkPolicy>,
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

    /// Whether an `llm` route could claim a request to this host, so the
    /// connection has to be intercepted for one to be able to.
    ///
    /// A route this misses is a route that never fires — the request is spliced
    /// through to the API the sandbox named, carrying the key the redirect
    /// exists to withhold.
    pub(crate) fn intercept_for_llm(&self, target_host: &str) -> bool {
        self.policy.read().unwrap().llm.claims_host(target_host)
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

/// The HTTP rules that govern a destination the proxy is about to dial on its
/// own initiative, or the reason that destination is not reachable at all.
///
/// An LLM redirect names a host the sandbox never asked for, so nothing has
/// judged it yet: the CONNECT that opened this session was judged against the
/// host the sandbox *did* name. This is where the backend answers for itself.
/// That is what makes an `llm` block a redirect and not a grant — the backend
/// still needs its own `egress.http` allow rule, and the translated request
/// still has to satisfy that route's HTTP rules.
///
/// Only an explicit `allow` counts. An `ask` would need a developer's answer,
/// and there is no request left to suspend: the sandbox is already mid-session
/// with a route that was approved for a different host.
pub(crate) fn destination_http_rules(
    state: &ProxyState,
    authority: &str,
    caller: Option<&crate::peer_process::PeerProcess>,
) -> Result<Vec<crate::routing::HttpRule>, String> {
    let policy = state.policy.read().unwrap();
    match crate::routing::find_matching_route(&policy.routes, authority, Scheme::Https, caller) {
        crate::routing::RouteOutcome::Matched(rule) if rule.verdict == Verdict::Allow => {
            Ok(rule.http_rules.clone())
        }
        crate::routing::RouteOutcome::Matched(rule) => Err(format!(
            "the egress.http rule covering {authority} says {:?}, not allow",
            rule.verdict
        )),
        crate::routing::RouteOutcome::NoMatch {
            binary_filtered: false,
        } if policy.default_verdict == Verdict::Allow => Ok(Vec::new()),
        crate::routing::RouteOutcome::NoMatch { .. } => {
            Err(format!("no egress.http rule allows {authority}"))
        }
    }
}

/// Get or initialize the ephemeral CA for MITM TLS interception.
/// Also installs the CA cert into the system trust store (idempotent).
/// Uses `get_or_init` to ensure only one CA is created under contention.
pub(crate) fn get_or_init_ca(
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
    extra_listen_ips: Vec<IpAddr>,
    state: Arc<ProxyState>,
}

/// Which handler an accepted connection goes to. The two lanes differ only in
/// that, so they share one accept loop.
#[derive(Clone, Copy)]
enum Lane {
    Explicit,
    Transparent,
}

impl Lane {
    fn kind(self) -> &'static str {
        match self {
            Lane::Explicit => "explicit",
            Lane::Transparent => "transparent",
        }
    }

    /// What a listener on this lane says when it comes up. The two read
    /// differently because operators grep supervisor logs for them.
    fn listening_message(self) -> &'static str {
        match self {
            Lane::Explicit => "local CONNECT proxy listening",
            Lane::Transparent => "transparent redirect listener running",
        }
    }
}

/// Every address a listener binds: the primary first, then one per extra IP on
/// the primary's port.
///
/// Duplicates are folded away. The extra IPs come from configuration, nothing
/// stops that configuration repeating loopback or an address twice, and the
/// second `bind` of the same address fails — which would take the whole proxy
/// down for a harmless mistake.
fn listen_addrs(primary: SocketAddr, extra: &[IpAddr]) -> Vec<SocketAddr> {
    let mut addrs = vec![primary];
    for ip in extra {
        let addr = SocketAddr::new(*ip, primary.port());
        if !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }
    addrs
}

/// Bind every address, or fail naming the one that would not bind.
///
/// All or nothing: a listener that is silently missing is a cage with a hole in
/// it, so a partial success is reported as a failure.
async fn bind_all(addrs: &[SocketAddr], lane: Lane) -> Result<Vec<TcpListener>, String> {
    let kind = lane.kind();
    let mut listeners = Vec::with_capacity(addrs.len());
    for addr in addrs {
        let listener =
            crate::listen::tcp(*addr).map_err(|e| format!("{kind} proxy bind {addr}: {e}"))?;
        tracing::info!(kind, addr = %addr, "{}", lane.listening_message());
        listeners.push(listener);
    }
    Ok(listeners)
}

/// True when no redirect rewrote this connection, so its reported "original
/// destination" is not a destination at all.
///
/// Two shapes, both reachable only by dialling the listener directly:
///
///  * Loopback. The nat chain's `oifname "lo" return` rule should keep it out
///    of here; this catches what slips through, such as a manual
///    `curl 127.0.0.1:3129`.
///  * The listener's own address. Conntrack has no rewritten tuple to report,
///    so it reports where the packet actually went — here. Treating that as a
///    destination would splice the listener to itself, once per dial, until the
///    connection semaphore saturates. Only reachable since the listener may
///    bind an address other than loopback (see `config::EXTRA_LISTEN_IPS_ENV`).
///
/// A redirected connection always names a destination that is not the listener,
/// so nothing legitimate is refused here.
fn is_unredirected(orig_dst: SocketAddr, local: Option<SocketAddr>) -> bool {
    orig_dst.ip().is_loopback() || local == Some(orig_dst)
}

/// Accept forever on one listener, handing each connection to its lane.
async fn accept_loop(
    listener: TcpListener,
    lane: Lane,
    semaphore: Arc<Semaphore>,
    state: Arc<ProxyState>,
) {
    let kind = lane.kind();
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(kind, "proxy accept error: {e}");
                continue;
            }
        };
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(kind, peer = %peer, "proxy connection limit reached, dropping");
                drop(stream);
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            let result = match lane {
                Lane::Explicit => handle_connection(stream, peer, &state).await,
                Lane::Transparent => handle_transparent_connection(stream, peer, state).await,
            };
            if let Err(e) = result {
                tracing::debug!(kind, peer = %peer, "proxy connection error: {e}");
            }
            drop(permit);
        });
    }
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
            policy: RwLock::new(NetworkPolicy::default()),
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
            extra_listen_ips: Vec::new(),
            state: state.clone(),
        };
        (server, state)
    }

    /// Also accept redirected traffic on these local addresses, on the same
    /// ports. See `config::EXTRA_LISTEN_IPS_ENV` for why a nested namespace
    /// needs it. The explicit CONNECT proxy is deliberately not included.
    pub fn with_extra_listen_ips(mut self, ips: Vec<IpAddr>) -> Self {
        self.extra_listen_ips = ips;
        self
    }

    pub async fn run(self) -> Result<(), String> {
        let explicit = bind_all(&[self.listen_addr], Lane::Explicit).await?;
        let transparent = bind_all(
            &listen_addrs(self.transparent_listen_addr, &self.extra_listen_ips),
            Lane::Transparent,
        )
        .await?;
        let dns_listen = listen_addrs(self.dns_stub_listen_addr, &self.extra_listen_ips);

        // One semaphore spans every listener so a burst on one path can't
        // starve the others of file descriptors or memory.
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
        let dns_state = self.state.clone();

        let mut lanes = JoinSet::new();
        for (listener, lane) in explicit
            .into_iter()
            .map(|l| (l, Lane::Explicit))
            .chain(transparent.into_iter().map(|l| (l, Lane::Transparent)))
        {
            lanes.spawn(accept_loop(
                listener,
                lane,
                semaphore.clone(),
                self.state.clone(),
            ));
        }

        // The UDP relay runs on its own thread, not a task: it judges each
        // datagram synchronously against the kernel queue. Failing to start is
        // not fatal and not a way through — with nothing reading the queue, the
        // filter chain keeps dropping UDP.
        crate::udp_egress::spawn(dns_state.clone());

        let dns_task = tokio::spawn(async move {
            // The stub is best-effort: a bind failure or missing
            // /etc/resolv.conf shouldn't take the whole proxy down, but we
            // do log loudly so the operator notices. UDP/53 from the sandbox
            // stays REDIRECTed to us — it will just start timing out for
            // the sandboxed process, which is the safe degrade.
            if let Err(e) = crate::dns::run(&dns_listen, dns_state).await {
                tracing::error!("dns stub task ended: {e}");
            }
        });

        // Any TCP listener terminating is fatal, and dropping the set aborts
        // the rest. DNS stub failure degrades to "no hostname resolution for
        // sandbox user" — loud log, proxy stays up so explicit-CONNECT traffic
        // keeps flowing.
        let ended = lanes.join_next().await;
        tracing::error!("proxy listener task ended: {ended:?}");
        dns_task.abort();
        Err("proxy listener terminated".into())
    }
}

async fn handle_connection(
    mut client: TcpStream,
    peer: SocketAddr,
    state: &Arc<ProxyState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let actor = crate::peer_process::ActorContext::resolve_offloaded(peer).await;
    // Read unbuffered: for a CONNECT the bytes right after the header are the
    // client's TLS ClientHello, which the tunnel must forward verbatim — a
    // buffered reader would consume and drop them. The timeout is slow-loris defense.
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
            return handle_http_forward(client, &target_host, header_bytes, state, &actor).await;
        }
        ProxyRequest::Connect {
            target: target_host,
        } => {
            return handle_connect(client, &target_host, &actor, state).await;
        }
    }
}

/// The effective policy decision for a target: `(verdict, transport,
/// tls_terminate, http_rules)`.
type RouteDecision = (Verdict, Transport, bool, Vec<HttpRule>);

/// Resolve `host` against the route table for `caller`, collapsing the
/// lock-guarded lookup the three proxy handlers share. Returns the effective
/// decision — falling back to the default verdict/transport on a plain host
/// miss — or `None` when a host-matching rule's `binaries` filter excluded the
/// caller, which the handler must fail closed.
fn resolve_route(
    state: &Arc<ProxyState>,
    host: &str,
    scheme: Scheme,
    caller: Option<&crate::peer_process::PeerProcess>,
) -> Option<RouteDecision> {
    // One snapshot: the routes and the defaults they fall back to must come
    // from the same policy generation.
    let policy = state.policy.read().unwrap();
    let default_verdict = policy.default_verdict;
    let default_transport = policy.default_transport;
    match find_matching_route(&policy.routes, host, scheme, caller) {
        RouteOutcome::Matched(rule) => Some((
            rule.verdict,
            rule.transport,
            rule.tls_terminate,
            rule.http_rules.clone(),
        )),
        RouteOutcome::NoMatch {
            binary_filtered: false,
        } => Some((default_verdict, default_transport, false, Vec::new())),
        // Host matched but the rule's `binaries` filter excluded the caller:
        // fail closed rather than fall through to the default action.
        RouteOutcome::NoMatch {
            binary_filtered: true,
        } => None,
    }
}

/// What a client is told when policy refuses its request. Shared with the TLS
/// door so both refusals look identical from outside.
pub(crate) const FORBIDDEN_RESPONSE: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

/// The facts every refusal on this door records, collected once.
struct ForwardRequest<'a> {
    state: &'a Arc<ProxyState>,
    target_host: &'a str,
    method: &'a str,
    path: &'a str,
    actor: &'a crate::peer_process::ActorContext,
}

impl ForwardRequest<'_> {
    /// Refuse this request: record it, tell the client, end the connection.
    ///
    /// The audit reason stays `policy-deny` whatever the detail, because the
    /// relay's notify dispatcher matches on that exact value to raise the
    /// developer's Allow/Skip dialog. `detail` says which rule refused, in the
    /// log.
    async fn deny(
        &self,
        client: &mut TcpStream,
        detail: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!(
            target = %self.target_host,
            method = %self.method,
            path = %self.path,
            detail,
            "HTTP forward proxy request denied by policy rules"
        );
        emit_policy_deny_http(
            self.state,
            self.target_host,
            self.method,
            self.path,
            "policy-deny",
            self.actor,
        );
        client.write_all(FORBIDDEN_RESPONSE).await?;
        Ok(())
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
    actor: &crate::peer_process::ActorContext,
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
    let refusal = ForwardRequest {
        state,
        target_host,
        method,
        path: &path,
        actor,
    };

    // An `llm` route claims this request and this door cannot honour it: there is
    // no TLS session to redirect, and cleartext is no place to put a backend
    // credential anyway. Refusing is the whole point — passing it on would send
    // the request, with the key the proxy injects, to the very API the redirect
    // exists to withhold it from. Checked before the raw `egress.tcp`
    // passthrough below, which is otherwise final on every door: a claim the
    // proxy cannot honour must never become one it ignores.
    if state
        .policy
        .read()
        .unwrap()
        .llm
        .claims(target_host, &normalized_path)
    {
        return refusal
            .deny(
                &mut client,
                "an llm route claims this request, and it cannot be redirected over cleartext \
                 http; address the api over https so the proxy can intercept it",
            )
            .await;
    }

    // `egress.tcp` claims are final on every door — see `tcp_egress_verdict`.
    // Absolute-form `http://` is port 80, not 443.
    if let Some(decision) = tcp_egress_verdict_for_hostport(state, target_host, 80, actor.process())
    {
        let head =
            rewrite_http_forward_request(&header_str, &path, target_host, Reuse::OneRequestOnly);
        return http_forward_raw_passthrough(client, target_host, &head, &decision, state, actor)
            .await;
    }

    // Find the matching route rule (same logic as CONNECT, but scheme is http
    // since the request came in as an absolute-form http:// URL). It comes
    // first because whether the route carries HTTP rules decides how the head
    // below is framed.
    let (verdict, transport, _tls_terminate, domain_http_rules) = match resolve_route(
        state,
        target_host,
        Scheme::Http,
        actor.process(),
    ) {
        Some(decision) => decision,
        None => {
            tracing::info!(target = %target_host, method = %method, "HTTP forward proxy DENIED (binary not allowed)");
            emit_policy_deny_http(
                state,
                target_host,
                method,
                &path,
                "binary-not-allowed",
                actor,
            );
            client.write_all(FORBIDDEN_RESPONSE).await?;
            return Ok(());
        }
    };

    // Origin-form rewrite: proxy framing for the inspected path.
    //
    // This door judges the first request on a connection and then splices the
    // rest of it (`copy_bidirectional` below). So where rules apply, the client
    // must not keep the connection for a second request that nothing would
    // judge — `OneRequestOnly` makes the origin close after one response.
    let reuse = if domain_http_rules.is_empty() {
        Reuse::AsClientSent
    } else {
        Reuse::OneRequestOnly
    };

    // Forcing the origin to close is not enough on its own: an upgrade the
    // origin accepts with a 101 turns the rest of this connection into a pipe
    // that `copy_bidirectional` splices unread. Refuse it outright, as the TLS
    // door does, rather than depend on the origin declining.
    if !domain_http_rules.is_empty() && crate::mitm::is_upgrade_request(&header_str) {
        return refusal
            .deny(
                &mut client,
                "connection upgrade is not allowed on a route that carries HTTP rules",
            )
            .await;
    }

    let relative_request = rewrite_http_forward_request(&header_str, &path, target_host, reuse);

    // Enforce HTTP rules. A body-reading rule reads the body, which is still on
    // the socket: the head was read one byte at a time, up to its terminator.
    let mut buffered_body: Option<Vec<u8>> = None;
    let mut mcp_request: Option<crate::mcp::RequestInfo> = None;
    match crate::routing::classify_http_request(&domain_http_rules, method, &normalized_path) {
        crate::routing::HttpRuleOutcome::Allow => {}
        crate::routing::HttpRuleOutcome::NoMatch => {
            return refusal
                .deny(&mut client, "no HTTP rule permits this method and path")
                .await;
        }
        crate::routing::HttpRuleOutcome::Conflict => {
            return refusal
                .deny(&mut client, crate::routing::CONFLICT_REASON)
                .await;
        }
        crate::routing::HttpRuleOutcome::Graphql(matchers) => {
            let framing = crate::http_body::determine_body_framing(&header_str);
            let body = match crate::graphql::read_body_for_inspection(
                &mut client,
                &header_str,
                method,
                framing,
            )
            .await
            {
                Ok(body) => body,
                Err(detail) => {
                    return refusal.deny(&mut client, &detail).await;
                }
            };
            // `path` still carries the query string that `normalized_path` drops,
            // and a GraphQL GET puts its document there.
            if let Err(detail) = crate::graphql::check_request(method, &path, &body, &matchers) {
                return refusal.deny(&mut client, &detail).await;
            }
            buffered_body = Some(body);
        }
        crate::routing::HttpRuleOutcome::Mcp(matchers) => {
            let framing = crate::http_body::determine_body_framing(&header_str);
            let body = match crate::mcp::read_body_for_inspection(
                &mut client,
                &header_str,
                method,
                framing,
            )
            .await
            {
                Ok(body) => body,
                Err(detail) => {
                    return refusal.deny(&mut client, &detail).await;
                }
            };
            match crate::mcp::judge(&header_str, &body, &matchers) {
                Ok(info) => mcp_request = Some(info),
                Err(detail) => return refusal.deny(&mut client, &detail).await,
            }
            buffered_body = Some(body);
        }
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

    // Inject credentials and apply URI placeholder replacements.
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
        let denial =
            match crate::routing::classify_http_request(&domain_http_rules, method, &rw_normalized)
            {
                crate::routing::HttpRuleOutcome::Allow => None,
                crate::routing::HttpRuleOutcome::NoMatch => {
                    Some("rewritten URI does not match policy rules".to_string())
                }
                crate::routing::HttpRuleOutcome::Conflict => {
                    Some(crate::routing::CONFLICT_REASON.to_string())
                }
                // The credential value moved the request onto a GraphQL rule. The
                // rewrite does not touch the body, so the one already read answers
                // for it; without one there is nothing to judge the new path with.
                crate::routing::HttpRuleOutcome::Graphql(matchers) => match &buffered_body {
                    Some(body) => {
                        crate::graphql::check_request(method, rw_raw_path, body, &matchers).err()
                    }
                    None => Some(
                        "rewritten URI reaches a GraphQL rule, but the body was not read"
                            .to_string(),
                    ),
                },
                // The same for an MCP rule, but the mirrored headers are re-read
                // from the head that will be sent, not the one that arrived.
                crate::routing::HttpRuleOutcome::Mcp(matchers) => match &buffered_body {
                    Some(body) => match crate::mcp::judge(&modified, body, &matchers) {
                        Ok(info) => {
                            mcp_request = Some(info);
                            None
                        }
                        Err(detail) => Some(detail),
                    },
                    None => Some(
                        "rewritten URI reaches an MCP rule, but the body was not read".to_string(),
                    ),
                },
            };
        if let Some(detail) = denial {
            return refusal.deny(&mut client, &detail).await;
        }
    }

    // Credential injection runs after the rule judged the head, and an injected
    // `Mcp-Name` or `Mcp-Method` would otherwise reach upstream unread. Upstream
    // acts on the head it receives, so that is the one the agreement binds.
    if let Some(info) = &mcp_request
        && let Err(detail) = crate::mcp::check_headers_agree(&modified, info)
    {
        return refusal.deny(&mut client, &detail).await;
    }

    // A body that policy had to read is no longer on the socket to relay, so the
    // head must describe it and the bytes must be replayed with it.
    let modified_bytes: Vec<u8> = match &buffered_body {
        Some(body) => {
            let head = crate::http_body::reframe_head_as_content_length(&modified, body.len());
            let mut bytes = format!("{head}\r\n\r\n").into_bytes();
            bytes.extend_from_slice(body);
            bytes
        }
        None => format!("{modified}\r\n\r\n").into_bytes(),
    };

    let effective_transport = match verdict {
        Verdict::Deny => {
            client
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                )
                .await?;
            tracing::info!(target = %target_host, method = %method, "HTTP forward proxy DENIED");
            emit_policy_deny_http(state, target_host, method, &path, "policy-deny", actor);
            return Ok(());
        }
        Verdict::Ask => {
            let action_str = format!("{method} http://{target_host}{path}");
            let key = gate_key(target_host);
            let decision = crate::gate::gate_or_deny(
                state,
                &key,
                &action_str,
                "policy-ambiguous",
                crate::protocol::Treatment::Inspected,
            )
            .await;
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
            let mut upstream = match connect_egress_under_policy(
                state,
                target_host,
                80,
                actor.process(),
                Gated::NotAsked,
            )
            .await
            {
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
            upstream.write_all(&modified_bytes).await?;

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
            upstream_stream.write_all(&modified_bytes).await?;

            // Relay the rest bidirectionally (request body + response)
            emit_http_audit(state, target_host, method, &path, "success", 200, actor);
            tokio::io::copy_bidirectional(&mut client, &mut upstream_stream).await?;
        }
    }

    Ok(())
}

/// Whether the rewritten head keeps the client's connection semantics or forces
/// the origin to close after one response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reuse {
    /// Leave `Connection`/`Keep-Alive` as the client sent them. Safe wherever
    /// the proxy stays in the loop and judges every request on the connection.
    AsClientSent,
    /// Force `Connection: close`. Required wherever the proxy splices after the
    /// head: everything past it is opaque, so a second request would reach the
    /// origin with its `Proxy-*` headers intact, still in absolute form, and
    /// judged by nothing.
    OneRequestOnly,
}

/// Rewrite an HTTP forward proxy request from absolute URL to relative path.
/// Input:  "GET http://host:port/path HTTP/1.1\r\nHost: ...\r\n..."
/// Output: "GET /path HTTP/1.1\r\nHost: host:port\r\n..."
fn rewrite_http_forward_request(
    header_str: &str,
    path: &str,
    target_host: &str,
    reuse: Reuse,
) -> String {
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
        // Dropped so the forced `Connection: close` below is the only one.
        if reuse == Reuse::OneRequestOnly && (name == "connection" || name == "keep-alive") {
            continue;
        }
        result.push(line.to_string());
    }

    if !has_host {
        result.insert(1, format!("Host: {target_host}"));
    }

    if reuse == Reuse::OneRequestOnly {
        result.push("Connection: close".to_string());
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

    // `egress.tcp` claims are final on every door — see `tcp_egress_verdict`.
    if let Some(decision) =
        tcp_egress_verdict_for_hostport(state, target_host, 443, actor.process())
    {
        return connect_raw_passthrough(client, target_host, &decision, state, actor).await;
    }

    // Find the matching route rule (first match wins, preserving order/specificity).
    // CONNECT is always HTTPS — plain HTTP uses the absolute-form forward path.
    let (verdict, transport, tls_terminate, domain_http_rules) =
        match resolve_route(state, target_host, Scheme::Https, actor.process()) {
            Some(decision) => decision,
            None => {
                client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
                tracing::info!(target = %target_host, "proxy DENIED (binary not allowed)");
                emit_policy_deny_connect(state, target_host, "binary-not-allowed", actor);
                return Ok(());
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
            emit_policy_deny_connect(state, target_host, "policy-deny", actor);
            return Ok(());
        }
        Verdict::Ask => {
            let action_str = format!("CONNECT {target_host}");
            let key = gate_key(target_host);
            let decision = crate::gate::gate_or_deny(
                state,
                &key,
                &action_str,
                "policy-ambiguous",
                crate::protocol::Treatment::Inspected,
            )
            .await;
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
            // The re-sign path owns whatever it matches: it knows nothing of
            // `llm` and delivers to the host the sandbox named. Going on would
            // send the request to the API the redirect exists to keep it away
            // from, signed. Said before the tunnel is established, so the client
            // is refused rather than left holding an open connection. A claim
            // this door cannot honour must never become one it ignores.
            if state.intercept_for_llm(target_host) && state.aws_resign.matches(target_host) {
                client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    .await?;
                // `error`, not `failure`: this is a misconfiguration and every
                // occurrence of it should be visible. A `failure` is deduped per
                // host, so the second attempt would leave no trace at all.
                emit_audit(state, target_host, "error", 502, actor);
                return Err(format!(
                    "an llm route covers {target_host}, which the aws re-sign path also owns; \
                     one connection cannot be both"
                )
                .into());
            }

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
                || state.intercept_for_unarmed(target_host)
                || state.intercept_for_llm(target_host);
            if needs_aws_resign {
                // AWS-resign path owns the MITM for this connection; any
                // other injections configured for the same host would be
                // silently ignored here. In practice `*.amazonaws.com`
                // doesn't carry header injections, but surface the
                // misconfiguration so it doesn't fail silently.
                //
                // HTTP rules are the exception: they are handed to the re-sign
                // path below, which applies them itself.
                if needs_mitm {
                    tracing::warn!(
                        target = %target_host,
                        has_header_injections = injections.is_some(),
                        has_uri_placeholders = !uri_placeholders.is_empty(),
                        "aws-resign and other injections configured on same host — non-aws injections will be dropped"
                    );
                }
                tracing::debug!(target = %target_host, "proxy DIRECT+AWS_RESIGN");
                let port = extract_port(target_host, 443);
                state
                    .aws_resign
                    .handle(client, &hostname, port, state, actor, &domain_http_rules)
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
                let mut target = match connect_egress_under_policy(
                    state,
                    target_host,
                    443,
                    actor.process(),
                    Gated::NotAsked,
                )
                .await
                {
                    Ok(t) => t,
                    Err(e) => {
                        emit_audit(state, target_host, "error", 502, actor);
                        return Err(format!("direct connect to {target_host}: {e}").into());
                    }
                };
                tracing::debug!(target = %target_host, "proxy DIRECT");
                tokio::io::copy_bidirectional(&mut client, &mut target).await?;
            }
        }
        Transport::Upstream => {
            // Every branch below terminates the connection only where a CA
            // already exists and splices it otherwise, and a redirect cannot
            // survive a splice: it reaches the API the route exists to keep it
            // away from. So the CA is made here if it has to be, exactly as the
            // direct door makes it. In a sandbox it is there already — the
            // policy message that carries the `llm` block installs one with it —
            // and this only repairs a proxy that was given a route before one.
            if state.intercept_for_llm(target_host) {
                get_or_init_ca(state)?;
            }

            let upstream_opt = state.upstream.lock().await.clone();
            let upstream = match upstream_opt {
                Some(n) => n,
                None => {
                    client
                        .write_all(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
                        .await?;
                    emit_audit(state, target_host, "error", 503, actor);
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
                        emit_audit(state, target_host, "error", 502, actor);
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
                    emit_audit(state, target_host, "error", 504, actor);
                    return Err("upstream header read timeout".into());
                }
            };

            if !status.starts_with("200") {
                client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    .await?;
                emit_audit(state, target_host, "error", 502, actor);
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
                    emit_audit(state, target_host, "success", 200, actor);
                    tracing::debug!(target = %target_host, "proxy LENS (passthrough, no CA)");
                    tokio::io::copy_bidirectional(&mut client, &mut upstream_stream).await?;
                }
            } else if !injs.is_empty()
                || !domain_http_rules.is_empty()
                || !placeholders.is_empty()
                || state.intercept_for_unarmed(target_host)
                || state.intercept_for_llm(target_host)
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
                    emit_audit(state, target_host, "success", 200, actor);
                    tracing::debug!(target = %target_host, "proxy LENS (passthrough, no CA)");
                    tokio::io::copy_bidirectional(&mut client, &mut upstream_stream).await?;
                }
            } else {
                // No TLS termination, no injections — raw TCP passthrough
                emit_audit(state, target_host, "success", 200, actor);
                tracing::debug!(target = %target_host, "proxy LENS (passthrough)");
                tokio::io::copy_bidirectional(&mut client, &mut upstream_stream).await?;
            }
        }
    }

    Ok(())
}

/// Entry point for connections redirected by nftables into the transparent
/// listener. Recovers the pre-redirect destination, classifies the first
/// bytes, and hands off to the TLS or HTTP handler. A connection it cannot
/// classify is offered to the developer as a raw splice, unless the default
/// verdict already denies what no rule names, or the destination is one this crate
/// filters itself — see [`unclassified_splice_decision`].
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

    if is_unredirected(orig_dst, stream.local_addr().ok()) {
        return Ok(());
    }

    // Resolve the caller once, up front, and thread it into the l7 handlers:
    // the `egress.tcp` binary filter needs it, and one `/proc` read per
    // connection is the budget.
    let actor = crate::peer_process::ActorContext::resolve_offloaded(peer).await;

    // Raw TCP egress: an `egress.tcp` rule matching the raw destination splices
    // bytes through untouched — no protocol peek, no TLS interception. Decided
    // before classification so TLS-speaking databases are not MITM'd.
    if let Some(decision) = tcp_egress_verdict(
        &state,
        &orig_dst.ip().to_string(),
        orig_dst.port(),
        actor.process(),
    ) {
        return handle_raw_passthrough(stream, orig_dst, &decision, &state, &actor).await;
    }

    // 8 bytes covers every classifier prefix: TLS needs 3, `OPTIONS ` and
    // `CONNECT ` are 8.
    let first = transparent::peek_first_bytes(&stream, 8).await?;
    match transparent::classify(&first) {
        Protocol::Tls => handle_transparent_tls(stream, orig_dst, actor, &state).await,
        Protocol::Http => handle_transparent_http(stream, orig_dst, actor, &state).await,
        Protocol::Unknown => match unclassified_splice_decision(&state, orig_dst) {
            Some(decision) => {
                handle_raw_passthrough(stream, orig_dst, &decision, &state, &actor).await
            }
            None => {
                emit_transparent_deny(&state, orig_dst, "unknown-protocol");
                // Dropping the stream closes the socket.
                Ok(())
            }
        },
    }
}

/// A raw table's verdict and the destination as the policy author wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawDecision {
    pub(crate) verdict: Verdict,
    /// `name:port` when the rule bound through a name, `None` when it matched
    /// by address. Feeds the ask dialog and, via `gate_key`, the QNAME-keyed
    /// approval set — never the audit trail, which names the real address.
    /// Owned: the name may come from a pin borrowed under the policy lock, and
    /// re-deriving it later could observe a different pin after a reload.
    pub(crate) matched_target: Option<String>,
    /// The policy generation this verdict was read from. Stamped under the same
    /// lock that produced the verdict, so a reload landing between the two
    /// cannot leave a stale verdict wearing the current generation.
    pub(crate) generation: u64,
    /// Why a dialog is being raised, for the card to explain itself with: a rule
    /// asked, or the protocol could not be classified.
    pub(crate) reason: &'static str,
    /// Whether the caller decided this, rather than the destination alone. Such
    /// a verdict is the asking process's and no other's, so nothing may reuse it
    /// for a second caller — see [`crate::udp_egress`], the only place that
    /// would want to. Carried from [`crate::routing::RawMatch::caller_scoped`].
    pub(crate) caller_scoped: bool,
}

/// The `egress.tcp` table's decision for one destination, or `None` when no
/// rule claims it — the connection then falls through to the `egress.http`
/// routes. Every door asks this same question, in the one ordered pass
/// [`parse_tcp_egress`] built the list for.
///
/// A `Cidr`/`CidrPort` rule binds by address, so on the doors that name their
/// destination it has nothing to match until [`connect_egress_under_policy`]
/// re-asks after resolution — where it can only refuse, never authorize a
/// splice. A CIDR *allow* therefore reaches only the transparent door.
///
/// `hostname` is a name or an IP literal; `port` is the destination port, the
/// scheme default already applied. A rule that claimed the target but excluded
/// the caller fails closed as a deny, same as [`find_matching_route`]. Raw TCP
/// always egresses directly, so no transport is returned.
fn tcp_egress_verdict(
    state: &Arc<ProxyState>,
    hostname: &str,
    port: u16,
    caller: Option<&crate::peer_process::PeerProcess>,
) -> Option<RawDecision> {
    // Rules and pins come from one snapshot (see `NetworkPolicy`), so a
    // connection never pairs new rules with a superseded policy's pins.
    let policy = state.policy.read().unwrap();
    raw_egress_verdict(&policy, &policy.tcp_egress, hostname, port, caller)
}

/// The `egress.udp` table's decision for one datagram's destination.
///
/// Unlike [`tcp_egress_verdict`] this always answers. A connection the tcp table
/// does not claim falls through to the `egress.http` routes; a datagram has
/// nowhere to fall to, so the table is the whole of the policy and silence from
/// it is a refusal. That is what makes UDP deny-by-default without the default
/// verdict — which governs the connection tables — having to say anything.
///
/// The relay holds an address, never a name, so a hostname rule binds here only
/// through a live DNS pin, exactly as it does on the transparent door.
// Its only caller is the relay, which runs on Linux alone — see `udp_egress`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn udp_egress_verdict(
    state: &Arc<ProxyState>,
    dst: SocketAddr,
    caller: Option<&crate::peer_process::PeerProcess>,
) -> RawDecision {
    let policy = state.policy.read().unwrap();
    let hostname = dst.ip().to_string();
    raw_egress_verdict(&policy, &policy.udp_egress, &hostname, dst.port(), caller).unwrap_or(
        RawDecision {
            verdict: Verdict::Deny,
            matched_target: None,
            generation: policy.generation,
            reason: "no-udp-rule",
            // An empty table refuses every caller alike.
            caller_scoped: false,
        },
    )
}

/// One ordered pass over one raw table, against the pins and generation of the
/// snapshot the caller already holds. `None` means no rule claimed the
/// destination; what that silence means belongs to the table, so the two
/// callers above answer it themselves.
fn raw_egress_verdict(
    policy: &NetworkPolicy,
    rules: &[RouteRule],
    hostname: &str,
    port: u16,
    caller: Option<&crate::peer_process::PeerProcess>,
) -> Option<RawDecision> {
    let pinned_qnames = live_pinned_qnames(policy, hostname);
    let target = RawTarget::at(hostname, &pinned_qnames);
    let found = find_matching_raw_egress(rules, target, port, caller);
    let matched_target = found.matched_name.map(|n| format!("{n}:{port}"));
    let generation = policy.generation;
    match found.outcome {
        RouteOutcome::Matched(rule) => Some(RawDecision {
            verdict: rule.verdict,
            matched_target,
            generation,
            reason: "policy-ambiguous",
            caller_scoped: found.caller_scoped,
        }),
        RouteOutcome::NoMatch {
            binary_filtered: true,
        } => Some(RawDecision {
            verdict: Verdict::Deny,
            matched_target,
            generation,
            reason: "policy-ambiguous",
            caller_scoped: found.caller_scoped,
        }),
        RouteOutcome::NoMatch { .. } => None,
    }
}

/// The live (unexpired) qnames pinned to `host`, empty unless it is an IP
/// literal. Storing only the name is what lets the ordered rules — including any
/// earlier caller-scoped deny — be re-evaluated against the *connecting* caller
/// rather than the DNS caller.
///
/// The key is canonicalized because pins are recorded under the A record's IPv4
/// address: a client-supplied mapped literal addresses the same host and must
/// reach the same pins.
fn live_pinned_qnames<'p>(policy: &'p NetworkPolicy, host: &str) -> Vec<&'p str> {
    let Ok(ip) = host.parse::<IpAddr>() else {
        return Vec::new();
    };
    let now = Instant::now();
    policy
        .pins
        .get(&ip.to_canonical())
        .map(|entries| {
            entries
                .iter()
                .filter(|p| p.expiry > now)
                .map(|p| p.qname.as_str())
                .collect()
        })
        .unwrap_or_default()
}

/// [`tcp_egress_verdict`] for a target still written as `host:port`, applying
/// `default_port` when the target carries no explicit one (443 for `CONNECT`,
/// 80 for absolute-form `http://`).
fn tcp_egress_verdict_for_hostport(
    state: &Arc<ProxyState>,
    target_host: &str,
    default_port: u16,
    caller: Option<&crate::peer_process::PeerProcess>,
) -> Option<RawDecision> {
    let hostname = extract_hostname(target_host);
    let port = extract_port(target_host, default_port);
    tcp_egress_verdict(state, &hostname, port, caller)
}

/// Dial a sandbox-egress target, re-running the `egress.tcp` table on the
/// resolved address. A CIDR rule can match a named target only once the name has
/// resolved, so a `CONNECT internal.example:22` that the L7 table admits is
/// checked here against a `10.0.0.0/8:22` rule it could not be tested against
/// before.
///
/// `already_gated` carries whether a developer has already answered for this
/// connection — see [`tcp_egress_admits`] for what that changes.
///
/// Every outbound dial goes through here — the raw doors, the MITM upstream,
/// and the AWS-resign upstream — so no path reaches the network with the tcp
/// table unread.
pub(crate) async fn connect_egress_under_policy(
    state: &Arc<ProxyState>,
    target_host: &str,
    default_port: u16,
    caller: Option<&crate::peer_process::PeerProcess>,
    already_gated: Gated,
) -> std::io::Result<TcpStream> {
    let port = extract_port(target_host, default_port);
    sock_mark::connect_tcp_egress_where(&extract_hostname(target_host), port, |ip| {
        tcp_egress_admits(state, ip, port, caller, already_gated)
    })
    .await
}

/// Whether *this* connection already carries a developer's answer, which is
/// what decides how the dial guard may treat an `ask` it finds on the resolved
/// address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gated {
    /// A gate ran for this connection and the developer allowed it.
    ByTheDeveloper,
    /// No gate ran. An `ask` here has never been seen by anyone — an `allow`
    /// on the name was never put to a human, so a CIDR `ask` waiting on the
    /// resolved address is still an unanswered question.
    NotAsked,
}

/// Whether the `egress.tcp` table, as it stands *now*, admits this resolved
/// address. This guards a dial against a rule the target could not be tested
/// against while it was still a name. It is not what keeps an approval from
/// outliving its policy — see the generation check in [`raw_verdict_admits`].
///
/// No claim at all admits: the destination was authorized by the L7 table and
/// the tcp table has nothing to say about it.
///
/// An `ask` depends on whether this connection already carries an answer. No
/// gate can run inside a dial, so an ungated connection must refuse rather than
/// answer more permissively than the door that puts it to a human. But an
/// approval is never written back into the table, so a gated connection meets
/// the very rule it was just approved under — refusing there would make `ask`
/// unusable on every door that resolves a name.
fn tcp_egress_admits(
    state: &Arc<ProxyState>,
    ip: IpAddr,
    port: u16,
    caller: Option<&crate::peer_process::PeerProcess>,
    already_gated: Gated,
) -> bool {
    match tcp_egress_verdict(state, &ip.to_string(), port, caller).map(|d| d.verdict) {
        None | Some(Verdict::Allow) => true,
        Some(Verdict::Ask) => already_gated == Gated::ByTheDeveloper,
        Some(Verdict::Deny) => false,
    }
}

/// (Re)apply the entire network egress policy in one atomic swap: publish the
/// L7 `routes` and their `default_verdict`/`default_transport`, the ordered
/// `tcp_egress` rules, drop every pin the new tables no longer cover, and bump
/// the generation — all under one `policy` write lock. This is the ONLY entry
/// point for changing the egress policy; it is what makes the snapshot
/// `NetworkPolicy` promises actually atomic. Pass empty vectors / the deny
/// defaults to reset.
///
/// The pins are filtered, not cleared: a pin survives exactly when a hostname
/// matcher in the new `tcp_egress` or `udp_egress` still covers its `qname` —
/// see [`pins_the_next_tables_still_cover`].
///
/// Bumping the generation in the same swap that filters the pins is what makes
/// [`pin_dns_answers`]'s check race-free: an in-flight answer from the old
/// generation either inserted before this ran (and is filtered here against the
/// new tables) or runs after (and is rejected by the check), never landing a
/// name the new policy does not cover.
///
/// Takes the next policy as a whole `NetworkPolicy` value so callers name every
/// field — the rules, defaults, and tcp lists can't be transposed at a call
/// site the way positional same-typed `Vec`s could. Whatever `next` carries for
/// `pins`/`generation` is ignored: the surviving pins come from the previous
/// snapshot filtered against `next`'s raw tables, and the generation always
/// advances monotonically, controlled here.
///
/// Re-applying an unchanged egress policy is a no-op — policy frames also carry
/// periodic credential refreshes, so this runs routinely with identical rules.
pub fn apply_network_policy(state: &ProxyState, next: NetworkPolicy) {
    let mut policy = state.policy.write().unwrap();
    if policy.egress_eq(&next) {
        return;
    }
    for (tcp, http) in crate::routing::overlapping_http_rules(&next.tcp_egress, &next.routes) {
        tracing::warn!(
            ?tcp,
            ?http,
            "egress.tcp claims this port, so the egress.http rule for the same host is not applied: \
             traffic is spliced raw, with no HTTP rules, credential injection, or inspection"
        );
    }
    // A UDP rule shadows nothing — it opens a second door. The http rule still
    // governs TCP, but an HTTP/3 client offered a datagram path to the same host
    // takes it, and everything that door applies is skipped.
    for (udp, http) in crate::routing::overlapping_http_rules(&next.udp_egress, &next.routes) {
        tracing::warn!(
            ?udp,
            ?http,
            "egress.udp opens a datagram path to a host the egress.http table governs: an HTTP/3 \
             client can take it and skip the HTTP rules, credential injection, and inspection that \
             apply over TCP"
        );
    }
    let pins = pins_the_next_tables_still_cover(&policy.pins, &next);
    *policy = NetworkPolicy {
        generation: policy.generation + 1,
        pins,
        ..next
    };
}

/// The subset of `pins` whose `qname` a hostname rule of the next raw tables
/// still covers. A name neither table names loses its binding, so a revoked
/// hostname rule takes its IPs with it; a name still covered keeps a binding the
/// next lookup would re-establish unchanged, because a pin carries a name and no
/// verdict.
fn pins_the_next_tables_still_cover(
    pins: &HashMap<IpAddr, Vec<PinnedIp>>,
    next: &NetworkPolicy,
) -> HashMap<IpAddr, Vec<PinnedIp>> {
    let covered = |qname: &str| {
        crate::routing::any_rule_covers_qname(&next.tcp_egress, qname)
            || crate::routing::any_rule_covers_qname(&next.udp_egress, qname)
    };
    pins.iter()
        .filter_map(|(ip, entries)| {
            let kept: Vec<PinnedIp> = entries
                .iter()
                .filter(|p| covered(&p.qname))
                .cloned()
                .collect();
            (!kept.is_empty()).then_some((*ip, kept))
        })
        .collect()
}

/// Record `ips` (from a DNS answer) against `qname` (the normalized name whose
/// lookup was authorized), expiring after `ttl_secs` clamped to
/// [`PIN_TTL_FLOOR_SECS`, `PIN_TTL_CAP_SECS`]. Called by the DNS stub after it
/// forwards an allowed answer. A no-op when there are no IPs.
///
/// Only the name is stored — not the `tcp_egress` rule it matched — so the
/// connect path re-evaluates the ordered rules against the *connecting* caller
/// (see [`tcp_egress_verdict`]) rather than trusting the DNS caller's verdict.
///
/// `generation` is the policy generation in force when the lookup was
/// authorized; if a policy has since been applied (bumping the generation and
/// filtering the pins) the answer is stale and dropped, so a lookup authorized
/// under a now-revoked policy can't reinstate its pin.
///
/// Re-resolving the same name refreshes an existing pin's expiry rather than
/// appending a duplicate, so a hot name's per-IP list stays bounded by the
/// number of *distinct* names that resolve to it, not the resolve rate.
pub(crate) fn pin_dns_answers(
    state: &Arc<ProxyState>,
    ips: &[IpAddr],
    qname: &str,
    ttl_secs: u32,
    generation: u64,
) {
    if ips.is_empty() {
        return;
    }
    let ttl = (ttl_secs as u64).clamp(PIN_TTL_FLOOR_SECS, PIN_TTL_CAP_SECS);
    let expiry = Instant::now() + Duration::from_secs(ttl);

    let mut policy = state.policy.write().unwrap();
    // Reject an answer whose authorizing policy has since been replaced. The
    // check and the generation bump happen under the same `policy` lock, so
    // there is no window where a stale pin slips in between the bump and the
    // filter.
    if policy.generation != generation {
        return;
    }
    // Backstop against unbounded growth (see MAX_PINNED_ENTRIES): once at the
    // cap, drop everything expired; if still at the cap, refuse to grow. A
    // hostname `egress.tcp` rule still binds without a pin, because both the
    // CONNECT/forward doors and the transparent TLS door match it against the
    // name the client supplied; what a missing pin costs is the raw splice, not
    // the rule.
    let total_entries =
        |pins: &HashMap<IpAddr, Vec<PinnedIp>>| pins.values().map(Vec::len).sum::<usize>();
    if total_entries(&policy.pins) >= MAX_PINNED_ENTRIES {
        let now = Instant::now();
        policy.pins.retain(|_, v| {
            v.retain(|p| p.expiry > now);
            !v.is_empty()
        });
        if total_entries(&policy.pins) >= MAX_PINNED_ENTRIES {
            return;
        }
    }
    for &ip in ips {
        let entry = policy.pins.entry(ip).or_default();
        match entry.iter_mut().find(|p| p.qname == qname) {
            Some(existing) => existing.expiry = expiry,
            None => entry.push(PinnedIp {
                qname: qname.to_owned(),
                expiry,
            }),
        }
    }
}

/// Open an opaque CONNECT tunnel to `target` through the Lens Sandbox upstream
/// and return the stream once the upstream answers `200`. On any failure a
/// matching audit event is emitted and the error returned. Shared by the raw
/// passthrough and transparent-TLS upstream paths, which then splice or MITM
/// the returned stream.
///
/// The explicit-CONNECT path deliberately does NOT use this: it must write HTTP
/// status lines back to its own client on failure, which this helper can't do.
async fn open_upstream_tunnel(
    state: &Arc<ProxyState>,
    target: &str,
    actor: &crate::peer_process::ActorContext,
) -> Result<BoxedSandboxStream, Box<dyn std::error::Error + Send + Sync>> {
    let upstream = match state.upstream.lock().await.clone() {
        Some(n) => n,
        None => {
            emit_audit(state, target, "error", 503, actor);
            return Err("Lens Sandbox upstream not configured yet".into());
        }
    };
    let upstream_addr = format!("{}:{}", upstream.host, upstream.port);
    let mut upstream_stream: BoxedSandboxStream = match connect_sandbox_upstream(state, &upstream)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            emit_audit(state, target, "error", 502, actor);
            return Err(format!("connect to Lens Sandbox upstream {upstream_addr}: {e}").into());
        }
    };
    let mut connect_req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
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
            emit_audit(state, target, "error", 504, actor);
            return Err("upstream header read timeout".into());
        }
    };
    if !status.starts_with("200") {
        emit_audit(state, target, "error", 502, actor);
        return Err(format!("Lens Sandbox upstream returned: {status}").into());
    }
    Ok(upstream_stream)
}

/// Splice a policy-approved raw TCP connection to its original destination
/// without interpreting the payload. Raw TCP always egresses directly: a
/// SO_MARK'd socket dials the destination, bypassing the nftables cage, and the
/// bytes are spliced through untouched. Honors `deny`/`ask` exactly as the
/// transparent TLS path does. `orig_dst` is the pre-redirect destination.
async fn handle_raw_passthrough(
    mut stream: TcpStream,
    orig_dst: SocketAddr,
    decision: &RawDecision,
    state: &Arc<ProxyState>,
    actor: &crate::peer_process::ActorContext,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let raw_target = orig_dst.to_string();
    // Same destination guard the L7 CONNECT/TLS paths run: a raw connection
    // egresses directly via SO_MARK, so a loopback or link-local target (e.g. a
    // pinned or CIDR-matched `169.254.169.254`) would reach the host itself or
    // cloud metadata, bypassing the cage. Reject before any dial, regardless of
    // verdict — this is not policy, it is a hard floor.
    if let Err(e) = validate_connect_target(&raw_target) {
        emit_policy_deny_connect(state, &raw_target, "blocked-destination", actor);
        tracing::debug!(target = %raw_target, "raw passthrough blocked: {e}");
        return Ok(());
    }

    // No `Gated` to carry: this door already holds the resolved address, so
    // there is no post-resolution re-check for an approval to have to survive.
    if raw_verdict_admits(state, &raw_target, decision, actor)
        .await
        .is_none()
    {
        return Ok(());
    }

    // Raw TCP always egresses directly: SO_MARK bypasses the nftables cage and
    // the bytes are spliced through untouched.
    let mut upstream =
        match sock_mark::connect_tcp_egress(&orig_dst.ip().to_string(), orig_dst.port()).await {
            Ok(s) => s,
            Err(e) => {
                emit_audit(state, &raw_target, "error", 502, actor);
                return Err(format!("passthrough connect to {raw_target}: {e}").into());
            }
        };
    tracing::debug!(target = %raw_target, "transparent passthrough DIRECT");
    emit_audit(state, &raw_target, "success", 200, actor);
    tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
    Ok(())
}

/// Whether an `egress.tcp` verdict admits the splice, running the developer
/// gate for `Ask` and emitting the deny audit. How a refusal reaches the client
/// — a 403 on the explicit-proxy doors, a silent close on the transparent one —
/// is the caller's business.
///
/// The admitting answer carries the [`Gated`] the dial then needs, because that
/// value is only meaningful once the verdict has been resolved here: deriving
/// it separately would let the two drift apart.
async fn raw_verdict_admits(
    state: &Arc<ProxyState>,
    target: &str,
    decision: &RawDecision,
    actor: &crate::peer_process::ActorContext,
) -> Option<Gated> {
    match decision.verdict {
        Verdict::Allow => Some(Gated::NotAsked),
        Verdict::Deny => {
            emit_policy_deny_connect(state, target, "policy-deny", actor);
            None
        }
        Verdict::Ask => {
            // The dialog names the destination the way the policy author wrote
            // it, so the gate events carry that name and stay correlated with
            // the prompt. That name is not enough on its own: on the transparent
            // door it came from a DNS pin, and several names can share one
            // address, so it attributes the attempt to an arbitrary one of them.
            // An allow is followed by a success audit naming the address; a
            // denial has to record it here or the trail never says where the
            // workload was going.
            let shown = decision.matched_target.as_deref().unwrap_or(target);
            let action_str = format!("CONNECT {shown}");
            let answer = crate::gate::gate_or_deny(
                state,
                &gate_key(shown),
                &action_str,
                decision.reason,
                crate::protocol::Treatment::Raw,
            )
            .await;
            if !answer.is_allow() {
                emit_gate_denied(state, &action_str, answer);
                emit_audit(state, target, "failure", 403, actor);
                tracing::info!(target = %target, reason = answer.audit_reason(), "raw passthrough DENIED (gated)");
                return None;
            }
            emit_gate_resolved(state, &action_str, answer);
            // The gate can hold a connection for `DECISION_TIMEOUT`, long enough
            // for a policy to land. Consent belongs to the generation that
            // granted it, so a moved policy is re-read rather than trusted: the
            // rule may have been deleted, narrowed, or turned into a deny.
            //
            // Re-reading, not refusing, is what lets an answer be remembered at
            // all — writing the approval back as a rule is itself a reload, so a
            // bare generation check would deny the request that raised the card.
            // The fresh verdict must be an allow on its own account; anything
            // else leaves this connection unauthorized and consent stays void.
            if state.policy.read().unwrap().generation != decision.generation
                && !reallows_after_reload(state, decision, target, actor)
            {
                emit_policy_deny_connect(state, target, "policy-changed", actor);
                tracing::info!(target = %target, "raw passthrough DENIED (policy changed under the dialog)");
                return None;
            }
            tracing::info!(target = %target, reason = answer.audit_reason(), "raw passthrough ALLOWED (gated)");
            Some(Gated::ByTheDeveloper)
        }
    }
}

/// The decision for a connection the classifier reported as neither TLS nor HTTP,
/// on a destination the `egress.tcp` table did not claim: ask whether to splice it
/// raw, or `None` to drop it as this door always did.
///
/// This is the only place a raw splice is discovered rather than declared, and it
/// has to be: an unclassified connection cannot be matched against `egress.http`
/// rules or carry credential injection, so dropping it left the developer with a
/// dead connection and no way to allow it except to hand-write a rule for a
/// destination they had not been told about. Nothing reaching here can be
/// classified, so no inspectable destination is diverted into an opaque splice.
///
/// A `deny` default is the one answer that is already given: it says block what no
/// rule names and do not ask, so raising a card would overrule it. Every other
/// default asks -- including `allow`, because a default is not consent to splice a
/// connection nothing can inspect, and this door dropped it until now.
///
/// Port 53 is never asked about. Asking is only safe where being unclassifiable is
/// the whole of what is wrong with a connection, and DNS is the one protocol this
/// crate filters in its own right: [`crate::dns`] gates every lookup against the
/// same allowlist, because a QNAME carries data out whether or not a connection to
/// that name is permitted. The stub is UDP-only and relies on this branch dropping
/// DNS over TCP (see its module docs). A card offering to splice port 53 would
/// offer to reopen the covert channel the stub exists to close, and nothing on the
/// card could convey that.
fn unclassified_splice_decision(
    state: &Arc<ProxyState>,
    orig_dst: SocketAddr,
) -> Option<RawDecision> {
    if orig_dst.port() == DNS_PORT {
        return None;
    }
    let policy = state.policy.read().unwrap();
    if policy.default_verdict == Verdict::Deny {
        return None;
    }
    Some(RawDecision {
        verdict: Verdict::Ask,
        // The table named nothing here, so the address is all the card can show —
        // and a raw rule must carry a port, which the door's target has.
        matched_target: None,
        generation: policy.generation,
        reason: "unknown-protocol",
        caller_scoped: false,
    })
}

/// Whether the reloaded table allows this destination on its own account, asked
/// about the destination the door holds: the name the rule bound through when
/// there was one — which a hostname rule can be re-read by without the pins the
/// reload cleared — else the address itself.
fn reallows_after_reload(
    state: &Arc<ProxyState>,
    decision: &RawDecision,
    target: &str,
    actor: &crate::peer_process::ActorContext,
) -> bool {
    let shown = decision.matched_target.as_deref().unwrap_or(target);
    // Bracket-aware, so an IPv6 address reaches the table as the address it is
    // rather than as a hostname no address rule could ever match.
    let port = extract_port(shown, 0);
    if port == 0 {
        return false;
    }
    tcp_egress_verdict(state, &extract_hostname(shown), port, actor.process())
        .is_some_and(|fresh| fresh.verdict == Verdict::Allow)
}

/// Serve a `CONNECT` whose destination the `egress.tcp` table claimed: refuse
/// it, or open the tunnel and splice the bytes through untouched. No protocol
/// peek, no TLS interception, no credential injection — claiming a port in the
/// tcp table is what opts it out of all of that.
///
/// The dial re-runs the table on the resolved address, so a CIDR deny the client
/// could not be tested against while it was still a name still binds.
async fn connect_raw_passthrough(
    mut client: TcpStream,
    target_host: &str,
    decision: &RawDecision,
    state: &Arc<ProxyState>,
    actor: &crate::peer_process::ActorContext,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(gated) = raw_verdict_admits(state, target_host, decision, actor).await else {
        tracing::info!(target = %target_host, "proxy DENIED (egress.tcp)");
        client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
        return Ok(());
    };

    let mut upstream =
        match connect_egress_under_policy(state, target_host, 443, actor.process(), gated).await {
            Ok(s) => s,
            Err(e) => {
                emit_audit(state, target_host, "error", 502, actor);
                client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    .await?;
                return Err(format!("raw passthrough connect to {target_host}: {e}").into());
            }
        };

    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    tracing::debug!(target = %target_host, "proxy RAW passthrough");
    emit_audit(state, target_host, "success", 200, actor);
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// Serve an absolute-form `http://` request whose destination the `egress.tcp`
/// table claimed: refuse it, or send the origin-form rewrite of the request head
/// upstream and splice the rest through untouched. The rewrite is proxy framing,
/// not inspection — no HTTP rules, no credential injection, no URI placeholder
/// rewriting.
///
/// `request_head` must be built with [`Reuse::OneRequestOnly`]: the rewrite
/// (which strips `Proxy-*`) reaches only the first request, and everything
/// after it is spliced verbatim.
///
/// The refusal is audited as a connect rather than an HTTP transaction: the tcp
/// table judged the destination, not the request line.
async fn http_forward_raw_passthrough(
    mut client: TcpStream,
    target_host: &str,
    request_head: &str,
    decision: &RawDecision,
    state: &Arc<ProxyState>,
    actor: &crate::peer_process::ActorContext,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(gated) = raw_verdict_admits(state, target_host, decision, actor).await else {
        tracing::info!(target = %target_host, "HTTP forward proxy DENIED (egress.tcp)");
        client
            .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    };

    let mut upstream =
        match connect_egress_under_policy(state, target_host, 80, actor.process(), gated).await {
            Ok(s) => s,
            Err(e) => {
                emit_audit(state, target_host, "error", 502, actor);
                client
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                )
                .await?;
                return Err(format!("raw passthrough connect to {target_host}: {e}").into());
            }
        };

    upstream
        .write_all(format!("{request_head}\r\n\r\n").as_bytes())
        .await?;
    tracing::debug!(target = %target_host, "HTTP forward proxy RAW passthrough");
    emit_audit(state, target_host, "success", 200, actor);
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

async fn handle_transparent_tls(
    stream: TcpStream,
    orig_dst: SocketAddr,
    actor: crate::peer_process::ActorContext,
    state: &Arc<ProxyState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Peek the SNI before committing to a ServerConfig, so a policy-denied host
    // is rejected before we mint an ephemeral cert for it. (LazyConfigAcceptor
    // is what lets us read the ClientHello without accepting the connection yet.)
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

    // `egress.tcp` claims are final on every door — see `tcp_egress_verdict`.
    // The check in `handle_transparent_connection` had only the address, so a
    // hostname rule bound there only through a live DNS pin. The SNI is the
    // same client-supplied name the CONNECT door matches by, so the rule has
    // to bind here too — otherwise a name whose pin has lapsed slips past a
    // deny this door alone would miss, and the workload picks the door.
    //
    // A claim can only refuse here: the ClientHello is already consumed, so
    // there is nothing left to splice. That includes an allow — the developer
    // asked for a raw splice, and MITM-ing it instead is the wrong answer.
    // Re-resolving the name repins it and the pre-classification check takes
    // the connection down the raw path where it belongs.
    if let Some(decision) =
        tcp_egress_verdict_for_hostport(state, &target_host, 443, actor.process())
    {
        // A deny is a deny on whichever door the workload picked, so it audits
        // as one here too. The other verdicts would have been spliced had the
        // pin been live, and the trail should say that is what they lost.
        let reason = match decision.verdict {
            Verdict::Deny => "policy-deny",
            _ => "egress-tcp-unpinned",
        };
        tracing::info!(
            target = %target_host,
            verdict = ?decision.verdict,
            reason,
            "transparent TLS DENIED (egress.tcp claims this name)"
        );
        emit_policy_deny_connect(state, &target_host, reason, &actor);
        drop(start);
        return Ok(());
    }

    let (verdict, transport, _tls_terminate, domain_http_rules) = match resolve_route(
        state,
        &target_host,
        Scheme::Https,
        actor.process(),
    ) {
        Some(decision) => decision,
        None => {
            tracing::info!(target = %target_host, "transparent TLS DENIED (binary not allowed)");
            emit_policy_deny_connect(state, &target_host, "binary-not-allowed", &actor);
            drop(start);
            return Ok(());
        }
    };

    let effective_transport = match verdict {
        Verdict::Deny => {
            emit_policy_deny_connect(state, &target_host, "policy-deny", &actor);
            drop(start);
            return Ok(());
        }
        Verdict::Ask => {
            let action_str = format!("CONNECT {target_host}");
            let key = gate_key(&target_host);
            let decision = crate::gate::gate_or_deny(
                state,
                &key,
                &action_str,
                "policy-ambiguous",
                crate::protocol::Treatment::Inspected,
            )
            .await;
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
            // pre-accepted TLS stream to the MITM pipeline. No success audit
            // here — the MITM pipeline audits per request.
            let upstream_stream = open_upstream_tunnel(state, &target_host, &actor).await?;
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
    actor: crate::peer_process::ActorContext,
    state: &Arc<ProxyState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

    handle_http_forward(stream, &target_host, header_bytes, state, &actor).await
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

/// The audit facts for one egress request: the legacy combined `action` string
/// plus the structured fields the host reads instead of re-parsing it. `host`
/// is the bare hostname (no port) and doubles as the failure-dedup key; `path`
/// is `None` for CONNECT tunnels, which have none.
struct RequestFacts<'a> {
    action: &'a str,
    method: &'a str,
    host: &'a str,
    path: Option<&'a str>,
}

/// Emit an audit event for a CONNECT tunnel request.
pub(crate) fn emit_audit(
    state: &Arc<ProxyState>,
    target_host: &str,
    result: &str,
    status_code: u16,
    actor: &crate::peer_process::ActorContext,
) {
    let host = extract_hostname(target_host);
    emit_audit_action(
        state,
        result,
        status_code,
        RequestFacts {
            action: &format!("CONNECT {target_host}"),
            method: "CONNECT",
            host: &host,
            path: None,
        },
        actor,
    );
}

fn emit_http_audit(
    state: &Arc<ProxyState>,
    target_host: &str,
    method: &str,
    path: &str,
    result: &str,
    status_code: u16,
    actor: &crate::peer_process::ActorContext,
) {
    let host = extract_hostname(target_host);
    emit_audit_action(
        state,
        result,
        status_code,
        RequestFacts {
            action: &format!("{method} http://{target_host}{path}"),
            method,
            host: &host,
            path: Some(path),
        },
        actor,
    );
}

/// Emit an audit event back to Lens Sandbox via the WebSocket channel.
/// Failure events are deduplicated (at most one per host per AUDIT_DEDUP_SECS)
/// to suppress retry storms. Success and error events are always emitted.
fn emit_audit_action(
    state: &Arc<ProxyState>,
    result: &str,
    status_code: u16,
    facts: RequestFacts<'_>,
    actor: &crate::peer_process::ActorContext,
) {
    emit_audit_action_with_metadata(state, result, status_code, None, facts, actor);
}

/// Variant that attaches a `metadata` object to the audit_event. Used by
/// the policy-deny call sites so the relay's notify dispatcher can match
/// on `metadata.reason="policy-deny"` and surface the failure to the
/// developer as an Allow/Skip dialog.
fn emit_audit_action_with_metadata(
    state: &Arc<ProxyState>,
    result: &str,
    status_code: u16,
    metadata: Option<serde_json::Value>,
    facts: RequestFacts<'_>,
    actor: &crate::peer_process::ActorContext,
) {
    if result == "failure" {
        let now = Instant::now();
        let mut dedup = state.deny_dedup.lock().unwrap();
        if let Some(last) = dedup.get(facts.host)
            && now.duration_since(*last).as_secs() < AUDIT_DEDUP_SECS
        {
            return;
        }
        dedup.insert(facts.host.to_string(), now);
        if dedup.len() > 1024 {
            dedup.clear();
        }
    }

    let tx = state.audit_tx.lock().unwrap();
    if let Some(tx) = tx.as_ref() {
        let mut event = serde_json::json!({
            "type": "audit_event",
            "source": "sandbox-proxy",
            "action": facts.action,
            "method": facts.method,
            "host": facts.host,
            "result": result,
            "status_code": status_code,
        });
        if let Some(path) = facts.path {
            event["path"] = serde_json::Value::from(path);
        }
        if let Some(meta) = metadata {
            event["metadata"] = meta;
        }
        if let Some(obj) = event.as_object_mut() {
            actor.augment(obj);
        }
        let _ = tx.send(event.to_string());
    }
}

/// Audit a CONNECT denied by policy. `reason` (`policy-deny` for a verdict
/// deny, `binary-not-allowed` for a `binaries`-filter miss) rides in
/// `metadata.reason` so the relay daemon can surface it to the developer as an
/// Allow/Skip notification rather than letting it disappear into the audit log.
pub(crate) fn emit_policy_deny_connect(
    state: &Arc<ProxyState>,
    target_host: &str,
    reason: &str,
    actor: &crate::peer_process::ActorContext,
) {
    let host = extract_hostname(target_host);
    emit_audit_action_with_metadata(
        state,
        "failure",
        403,
        Some(serde_json::json!({ "reason": reason })),
        RequestFacts {
            action: &format!("CONNECT {target_host}"),
            method: "CONNECT",
            host: &host,
            path: None,
        },
        actor,
    );
}

/// Audit a re-signed request denied by the route's HTTP rules. The reason is
/// always `policy-deny`; `detail` says which rule refused it.
pub(crate) fn emit_policy_deny_resigned(
    state: &Arc<ProxyState>,
    target_host: &str,
    method: &str,
    path: &str,
    detail: &str,
    actor: &crate::peer_process::ActorContext,
) {
    let host = extract_hostname(target_host);
    emit_audit_action_with_metadata(
        state,
        "failure",
        403,
        Some(serde_json::json!({
            "host": target_host,
            "mitm": true,
            "aws_resign": true,
            "reason": "policy-deny",
            "detail": detail,
        })),
        RequestFacts {
            action: &format!("{method} https://{target_host}{path}"),
            method,
            host: &host,
            path: Some(path),
        },
        actor,
    );
}

/// Audit an HTTP forward request denied by policy. `reason` semantics match
/// emit_policy_deny_connect.
fn emit_policy_deny_http(
    state: &Arc<ProxyState>,
    target_host: &str,
    method: &str,
    path: &str,
    reason: &str,
    actor: &crate::peer_process::ActorContext,
) {
    let host = extract_hostname(target_host);
    emit_audit_action_with_metadata(
        state,
        "failure",
        403,
        Some(serde_json::json!({ "reason": reason })),
        RequestFacts {
            action: &format!("{method} http://{target_host}{path}"),
            method,
            host: &host,
            path: Some(path),
        },
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
pub(crate) fn emit_gate_denied(
    state: &Arc<ProxyState>,
    action: &str,
    decision: crate::protocol::Decision,
) {
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

    if let Ok(ip) = hostname.parse::<std::net::IpAddr>()
        && sock_mark::is_disallowed_egress_ip(ip)
    {
        return Err("CONNECT to loopback/link-local/unspecified denied".into());
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
    } else {
        // Anything but http:// (and the https:// handled above) is not an
        // upstream we can speak — bail. `?` keeps clippy's question_mark
        // lint happy on newer toolchains.
        (url.strip_prefix("http://")?, false)
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
    let tcp = match tokio::time::timeout(
        connect_timeout,
        sock_mark::connect_tcp_resolve(&upstream.host, upstream.port),
    )
    .await
    {
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

pub(crate) fn extract_hostname(target: &str) -> String {
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

pub(crate) fn extract_port(target: &str, default: u16) -> u16 {
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
    fn listen_addrs_keeps_loopback_first_and_reuses_its_port() {
        let primary = SocketAddr::from(([127, 0, 0, 1], 3129));
        let extra = vec!["169.254.32.1".parse().unwrap()];
        assert_eq!(
            listen_addrs(primary, &extra),
            vec![primary, SocketAddr::from(([169, 254, 32, 1], 3129))]
        );
    }

    #[test]
    fn listen_addrs_without_extras_is_just_the_primary() {
        let primary = SocketAddr::from(([127, 0, 0, 1], 3129));
        assert_eq!(listen_addrs(primary, &[]), vec![primary]);
    }

    #[test]
    fn listen_addrs_drops_a_repeat_of_the_primary() {
        // The provisioner names the veth address, and nothing stops it naming
        // loopback too. Binding the same address twice fails, and that failure
        // is fatal to the proxy — so fold the duplicate away instead.
        let primary = SocketAddr::from(([127, 0, 0, 1], 3129));
        let extra = vec![
            "127.0.0.1".parse().unwrap(),
            "169.254.32.1".parse().unwrap(),
            "169.254.32.1".parse().unwrap(),
        ];
        assert_eq!(
            listen_addrs(primary, &extra),
            vec![primary, SocketAddr::from(([169, 254, 32, 1], 3129))]
        );
    }

    #[test]
    fn a_dial_straight_at_the_listener_is_not_a_destination() {
        let veth: SocketAddr = "169.254.32.1:3129".parse().unwrap();
        assert!(is_unredirected(veth, Some(veth)));
        assert!(is_unredirected(
            "127.0.0.1:3129".parse().unwrap(),
            Some(veth)
        ));
    }

    #[test]
    fn a_redirected_connection_still_names_its_destination() {
        let veth: SocketAddr = "169.254.32.1:3129".parse().unwrap();
        let real: SocketAddr = "93.184.216.34:443".parse().unwrap();
        assert!(!is_unredirected(real, Some(veth)));
        // A listener address we could not read is not evidence of a direct
        // dial, so the connection proceeds to policy rather than being dropped.
        assert!(!is_unredirected(real, None));
    }

    #[tokio::test]
    async fn bind_all_opens_every_address() {
        let addrs = vec![
            SocketAddr::from(([127, 0, 0, 1], 0)),
            SocketAddr::from(([127, 0, 0, 1], 0)),
        ];
        let listeners = bind_all(&addrs, Lane::Transparent).await.expect("bind");
        assert_eq!(listeners.len(), 2);
    }

    #[tokio::test]
    async fn bind_all_reports_the_address_that_failed() {
        let taken = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind");
        let addr = taken.local_addr().expect("local addr");
        let err = bind_all(
            &[SocketAddr::from(([127, 0, 0, 1], 0)), addr],
            Lane::Transparent,
        )
        .await
        .expect_err("second bind must fail");
        assert!(err.contains(&addr.to_string()), "{err}");
    }

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
    fn validate_rejects_unspecified() {
        assert!(validate_connect_target("0.0.0.0:80").is_err());
    }

    #[test]
    fn validate_rejects_mapped_loopback() {
        // IPv4-mapped IPv6 must canonicalize to its v4 form before the check.
        assert!(validate_connect_target("[::ffff:127.0.0.1]:80").is_err());
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
            policy: RwLock::new(NetworkPolicy::default()),
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

    /// One `egress.tcp` rule, built through the real parser so a test can only
    /// construct shapes a policy could actually carry. Hand-assembling a
    /// `RouteRule` here would let a test exercise a matcher the port requirement
    /// rules out, and keep the matching code for it alive on that basis alone.
    fn tcp_rule(pattern: &str, verdict: Verdict, binaries: Option<Vec<&str>>) -> RouteRule {
        let mut obj = serde_json::json!({
            "match": pattern,
            "verdict": serde_json::to_value(verdict).unwrap(),
        });
        if let Some(paths) = binaries {
            obj["binaries"] = serde_json::json!(paths);
        }
        crate::routing::parse_tcp_egress(&serde_json::json!([obj]))
            .expect("test rule must be a shape production accepts")
            .pop()
            .expect("one rule in, one rule out")
    }

    /// [`tcp_rule`] for the common hostname case.
    fn fqdn_rule(host: &str, port: u16, verdict: Verdict) -> RouteRule {
        tcp_rule(&format!("{host}:{port}"), verdict, None)
    }

    /// A throwaway actor for the `emit_*` unit tests. Off a booted Linux guest
    /// the `/proc` walk finds nothing, so `process` stays `None` — the tests
    /// that care about attribution assert on `src_endpoint`, which is always
    /// stamped.
    fn test_actor() -> crate::peer_process::ActorContext {
        crate::peer_process::ActorContext::resolve("10.0.0.5:54321".parse().unwrap())
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
        emit_audit(&state, "api.openai.com:443", "success", 200, &test_actor());

        let msg = rx.try_recv().unwrap();
        let event: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(event["type"], "audit_event");
        assert_eq!(event["source"], "sandbox-proxy");
        assert_eq!(event["action"], "CONNECT api.openai.com:443");
        assert_eq!(event["method"], "CONNECT");
        assert_eq!(event["host"], "api.openai.com");
        assert!(
            event.get("path").is_none(),
            "a CONNECT tunnel has no HTTP path"
        );
        assert_eq!(event["result"], "success");
        assert_eq!(event["status_code"], 200);
    }

    #[test]
    fn emit_policy_deny_connect_carries_reason_metadata() {
        let (state, mut rx) = test_state();
        emit_policy_deny_connect(&state, "evil.example.com:443", "policy-deny", &test_actor());

        let msg = rx.try_recv().unwrap();
        let event: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(event["action"], "CONNECT evil.example.com:443");
        assert_eq!(event["method"], "CONNECT");
        assert_eq!(event["host"], "evil.example.com");
        assert_eq!(event["result"], "failure");
        assert_eq!(event["status_code"], 403);
        assert_eq!(event["metadata"]["reason"], "policy-deny");
    }

    #[test]
    fn resolve_route_fails_closed_when_the_binaries_filter_excludes_the_caller() {
        let (state, _rx) = test_state();
        // One rule, matching the host but only for /usr/bin/curl.
        state.policy.write().unwrap().routes = vec![crate::routing::RouteRule {
            matcher: crate::routing::RouteMatcher::Domain("api.openai.com".to_string()),
            verdict: Verdict::Allow,
            transport: Transport::Direct,
            tls_terminate: false,
            http_rules: Vec::new(),
            scheme: None,
            binaries: Some(vec![std::path::PathBuf::from("/usr/bin/curl")]),
        }];

        let curl = crate::peer_process::PeerProcess {
            pid: 100,
            name: "curl".to_string(),
            exe: Some(std::path::PathBuf::from("/usr/bin/curl")),
            ancestors: Vec::new(),
        };
        let wget = crate::peer_process::PeerProcess {
            pid: 101,
            name: "wget".to_string(),
            exe: Some(std::path::PathBuf::from("/usr/bin/wget")),
            ancestors: Vec::new(),
        };

        // The allowed binary resolves to the rule's Allow verdict.
        let (verdict, ..) =
            resolve_route(&state, "api.openai.com:443", Scheme::Https, Some(&curl)).unwrap();
        assert_eq!(verdict, Verdict::Allow);

        // A different binary matches the host but not the filter: the handler
        // sees None and must fail closed, not fall through to the default. Each
        // handler turns this None into a 403 audited `binary-not-allowed`.
        assert!(
            resolve_route(&state, "api.openai.com:443", Scheme::Https, Some(&wget)).is_none(),
            "an excluded caller must not fall through to the default verdict",
        );
    }

    #[test]
    fn pinned_dns_answer_resolves_the_raw_target() {
        let (state, _rx) = test_state();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        // A port-scoped fqdn allow rule for the resolved name, plus its pin.
        state.policy.write().unwrap().tcp_egress =
            vec![fqdn_rule("db.example.com", 5432, Verdict::Allow)];
        pin_dns_answers(&state, &[ip], "db.example.com", 300, 0);

        // A connect to the pinned ip:port re-evaluates the rule and admits it.
        let verdict = tcp_verdict(&state, "203.0.113.7:5432", None).expect("pin should match");
        assert_eq!(verdict, Verdict::Allow);

        // A different port on the same ip is not covered by the port-scoped rule.
        assert!(tcp_verdict(&state, "203.0.113.7:6379", None).is_none());
        // An ip that was never pinned does not match.
        assert!(tcp_verdict(&state, "198.51.100.1:5432", None).is_none());
    }

    #[test]
    fn expired_pins_do_not_resolve() {
        let (state, _rx) = test_state();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        // Insert a pin that is already expired. Its name still has a live allow
        // rule, so only the expiry — checked before re-evaluation — keeps it out.
        {
            let mut policy = state.policy.write().unwrap();
            policy.tcp_egress = vec![fqdn_rule("db.example.com", 5432, Verdict::Allow)];
            policy.pins.insert(
                ip,
                vec![PinnedIp {
                    qname: "db.example.com".to_string(),
                    expiry: Instant::now() - Duration::from_secs(1),
                }],
            );
        }

        // An expired pin is skipped at connect time, so the connection is
        // denied. The read path no longer prunes — storage is reclaimed at
        // insert time and on reload — so the entry may still be present.
        assert!(tcp_verdict(&state, "203.0.113.9:5432", None).is_none());
    }

    #[test]
    fn pin_dns_answers_is_a_noop_without_ips() {
        let (state, _rx) = test_state();

        pin_dns_answers(&state, &[], "db.example.com", 300, 0);
        assert!(state.policy.read().unwrap().pins.is_empty());
    }

    #[test]
    fn pin_dns_answers_refreshes_expiry_instead_of_duplicating() {
        let (state, _rx) = test_state();
        let ip: IpAddr = "203.0.113.30".parse().unwrap();

        // Re-resolving the same name to the same IP must not grow the per-IP list.
        pin_dns_answers(&state, &[ip], "db.example.com", 300, 0);
        pin_dns_answers(&state, &[ip], "db.example.com", 300, 0);
        pin_dns_answers(&state, &[ip], "db.example.com", 300, 0);

        let policy = state.policy.read().unwrap();
        assert_eq!(policy.pins.get(&ip).map(Vec::len), Some(1));
    }

    #[test]
    fn pin_dns_answers_bounds_growth_at_the_cap() {
        let (state, _rx) = test_state();
        // Fill the store to the cap with distinct, unexpired IPs.
        {
            let mut policy = state.policy.write().unwrap();
            let expiry = Instant::now() + Duration::from_secs(300);
            for i in 0..MAX_PINNED_ENTRIES {
                let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000u32 + i as u32));
                policy.pins.insert(
                    ip,
                    vec![PinnedIp {
                        qname: "db.example.com".to_string(),
                        expiry,
                    }],
                );
            }
        }

        // A fresh IP over the cap (nothing expired to reclaim) must be refused,
        // not appended — the map stays bounded.
        let overflow: IpAddr = "203.0.113.250".parse().unwrap();
        pin_dns_answers(&state, &[overflow], "db.example.com", 300, 0);

        let policy = state.policy.read().unwrap();
        assert!(policy.pins.values().map(Vec::len).sum::<usize>() <= MAX_PINNED_ENTRIES);
        assert!(!policy.pins.contains_key(&overflow));
    }

    #[test]
    fn pin_dns_answers_bounds_total_entries_for_a_hot_ip() {
        // Many distinct qnames resolving to one constant IP (wildcard rule) must
        // still be bounded: the cap counts entries, not distinct IP keys.
        let (state, _rx) = test_state();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        for i in 0..(MAX_PINNED_ENTRIES + 50) {
            let qname = format!("sub{i}.evil.example");
            pin_dns_answers(&state, &[ip], &qname, 300, 0);
        }
        let policy = state.policy.read().unwrap();
        let total: usize = policy.pins.values().map(Vec::len).sum();
        assert!(
            total <= MAX_PINNED_ENTRIES,
            "one IP's pin list must be bounded by the cap, got {total}"
        );
    }

    #[test]
    fn reapplying_an_unchanged_policy_keeps_the_pins() {
        let (state, _rx) = test_state();
        let egress = || NetworkPolicy {
            tcp_egress: vec![fqdn_rule("db.internal", 5432, Verdict::Allow)],
            ..Default::default()
        };
        apply_network_policy(&state, egress());
        let generation = state.policy.read().unwrap().generation;

        let ip: IpAddr = "203.0.113.90".parse().unwrap();
        pin_dns_answers(&state, &[ip], "db.internal", 300, generation);
        assert_eq!(state.policy.read().unwrap().pins.len(), 1);

        // A byte-identical egress policy — the credential-refresh case.
        apply_network_policy(&state, egress());

        let policy = state.policy.read().unwrap();
        assert_eq!(
            policy.pins.len(),
            1,
            "an unchanged policy must keep its pins"
        );
        assert_eq!(
            policy.generation, generation,
            "an unchanged policy must not invalidate in-flight answers"
        );
    }

    #[test]
    fn applying_a_changed_policy_drops_a_pin_the_new_table_no_longer_covers() {
        let (state, _rx) = test_state();
        apply_network_policy(
            &state,
            NetworkPolicy {
                tcp_egress: vec![fqdn_rule("db.internal", 5432, Verdict::Allow)],
                ..Default::default()
            },
        );
        let generation = state.policy.read().unwrap().generation;
        let ip: IpAddr = "203.0.113.91".parse().unwrap();
        pin_dns_answers(&state, &[ip], "db.internal", 300, generation);
        assert_eq!(state.policy.read().unwrap().pins.len(), 1);

        apply_network_policy(
            &state,
            NetworkPolicy {
                tcp_egress: vec![fqdn_rule("other.internal", 5432, Verdict::Allow)],
                ..Default::default()
            },
        );

        let policy = state.policy.read().unwrap();
        assert!(policy.pins.is_empty(), "a revoked policy's pins must go");
        assert!(policy.generation > generation);
    }

    #[test]
    fn applying_a_changed_policy_keeps_a_pin_the_new_table_still_covers() {
        // The ordinary "Allow always" click adds a rule and leaves the rest of
        // the table standing. A raw-TCP connection to an already-resolved IP
        // must keep matching its hostname rule across that reload.
        let (state, _rx) = test_state();
        apply_network_policy(
            &state,
            NetworkPolicy {
                tcp_egress: vec![fqdn_rule("db.internal", 5432, Verdict::Allow)],
                ..Default::default()
            },
        );
        let generation = state.policy.read().unwrap().generation;
        let ip: IpAddr = "203.0.113.92".parse().unwrap();
        pin_dns_answers(&state, &[ip], "db.internal", 300, generation);
        assert_eq!(
            tcp_verdict(&state, "203.0.113.92:5432", None),
            Some(Verdict::Allow)
        );

        apply_network_policy(
            &state,
            NetworkPolicy {
                tcp_egress: vec![
                    fqdn_rule("db.internal", 5432, Verdict::Allow),
                    fqdn_rule("api.example.com", 443, Verdict::Allow),
                ],
                ..Default::default()
            },
        );

        assert!(
            state.policy.read().unwrap().generation > generation,
            "a changed policy must still bump the generation"
        );
        assert_eq!(
            tcp_verdict(&state, "203.0.113.92:5432", None),
            Some(Verdict::Allow),
            "a pin the new table still covers must survive the reload"
        );
    }

    #[test]
    fn applying_a_changed_policy_keeps_a_pin_the_new_udp_table_still_covers() {
        // One pin serves both raw tables, so the udp table alone is enough to
        // keep a name's binding alive.
        let (state, _rx) = test_state();
        apply_network_policy(
            &state,
            NetworkPolicy {
                tcp_egress: vec![fqdn_rule("db.internal", 5432, Verdict::Allow)],
                ..Default::default()
            },
        );
        let generation = state.policy.read().unwrap().generation;
        let ip: IpAddr = "203.0.113.93".parse().unwrap();
        pin_dns_answers(&state, &[ip], "db.internal", 300, generation);

        apply_network_policy(
            &state,
            NetworkPolicy {
                udp_egress: vec![fqdn_rule("db.internal", 5432, Verdict::Allow)],
                ..Default::default()
            },
        );

        assert!(
            state.policy.read().unwrap().pins.contains_key(&ip),
            "a name the new udp table covers must keep its pin"
        );
    }

    #[test]
    fn applying_a_changed_policy_drops_only_the_pins_the_new_table_lost() {
        let (state, _rx) = test_state();
        apply_network_policy(
            &state,
            NetworkPolicy {
                tcp_egress: vec![
                    fqdn_rule("db.internal", 5432, Verdict::Allow),
                    fqdn_rule("gone.internal", 5432, Verdict::Allow),
                ],
                ..Default::default()
            },
        );
        let generation = state.policy.read().unwrap().generation;
        let shared: IpAddr = "203.0.113.94".parse().unwrap();
        pin_dns_answers(&state, &[shared], "db.internal", 300, generation);
        pin_dns_answers(&state, &[shared], "gone.internal", 300, generation);

        apply_network_policy(
            &state,
            NetworkPolicy {
                tcp_egress: vec![fqdn_rule("db.internal", 5432, Verdict::Allow)],
                ..Default::default()
            },
        );

        let policy = state.policy.read().unwrap();
        let names: Vec<&str> = policy
            .pins
            .get(&shared)
            .map(|e| e.iter().map(|p| p.qname.as_str()).collect())
            .unwrap_or_default();
        assert_eq!(
            names,
            vec!["db.internal"],
            "only the name the new table dropped loses its pin"
        );
    }

    #[test]
    fn a_revoked_lookup_cannot_reinstate_its_pin_even_when_the_name_survives() {
        // Pin retention must not weaken the generation guard: an in-flight
        // answer authorized under the old policy is still refused, whether or
        // not the new table happens to cover the same name.
        let (state, _rx) = test_state();
        apply_network_policy(
            &state,
            NetworkPolicy {
                tcp_egress: vec![fqdn_rule("db.internal", 5432, Verdict::Allow)],
                ..Default::default()
            },
        );
        let stale_generation = state.policy.read().unwrap().generation;

        apply_network_policy(
            &state,
            NetworkPolicy {
                tcp_egress: vec![
                    fqdn_rule("db.internal", 5432, Verdict::Allow),
                    fqdn_rule("api.example.com", 443, Verdict::Allow),
                ],
                ..Default::default()
            },
        );

        let ip: IpAddr = "203.0.113.95".parse().unwrap();
        pin_dns_answers(&state, &[ip], "db.internal", 300, stale_generation);

        assert!(
            state.policy.read().unwrap().pins.is_empty(),
            "an answer from a superseded generation must never land"
        );
    }

    #[test]
    fn pin_dns_answers_drops_a_stale_generation_insert() {
        let (state, _rx) = test_state();
        let ip: IpAddr = "203.0.113.30".parse().unwrap();

        // An in-flight DNS response was classified under generation 0, but a
        // policy revocation cleared the pins and bumped the generation before
        // its answer landed. The stale insert must be dropped, not applied.
        apply_network_policy(
            &state,
            NetworkPolicy {
                default_verdict: Verdict::Deny,
                ..Default::default()
            },
        );
        pin_dns_answers(&state, &[ip], "db.example.com", 300, 0);

        assert!(state.policy.read().unwrap().pins.is_empty());
    }

    #[test]
    fn pin_dns_answers_applies_a_current_generation_insert() {
        let (state, _rx) = test_state();
        let ip: IpAddr = "203.0.113.31".parse().unwrap();

        // After a revocation, a response classified under the new generation
        // still pins normally.
        apply_network_policy(
            &state,
            NetworkPolicy {
                default_verdict: Verdict::Deny,
                ..Default::default()
            },
        );
        let generation = state.policy.read().unwrap().generation;
        pin_dns_answers(&state, &[ip], "db.example.com", 300, generation);

        assert!(state.policy.read().unwrap().pins.contains_key(&ip));
    }

    #[test]
    fn reload_supersedes_old_pins() {
        let (state, _rx) = test_state();
        let target = "203.0.113.40:5432";
        let x: IpAddr = "203.0.113.40".parse().unwrap();

        // Policy A: a CIDR deny covering X listed BEFORE a hostname allow for
        // the name that resolves into it. First-match by policy order means the
        // earlier deny wins, so X is denied under the complete policy.
        state.policy.write().unwrap().tcp_egress = vec![
            tcp_rule("203.0.113.0/24:5432", Verdict::Deny, None),
            fqdn_rule("db.example.com", 5432, Verdict::Allow),
        ];
        let generation = state.policy.read().unwrap().generation;
        pin_dns_answers(&state, &[x], "db.example.com", 300, generation);
        assert_eq!(tcp_verdict(&state, target, None), Some(Verdict::Deny));

        // Reload to policy B (no static rules, default deny). Publishing the
        // empty rules and clearing the pin happen together, so the allow-pin
        // from A can never combine with B's empty rules to open a splice.
        apply_network_policy(
            &state,
            NetworkPolicy {
                default_verdict: Verdict::Deny,
                ..Default::default()
            },
        );
        assert_eq!(tcp_verdict(&state, target, None), None);
        assert!(state.policy.read().unwrap().pins.is_empty());
    }

    #[test]
    fn a_wildcard_hostname_rule_does_not_reach_an_unpinned_ip_literal() {
        // An IP literal is not a name, on any door: hostname rules reach it only
        // through a DNS pin. See `RawTarget::at`.
        let (state, _rx) = test_state();
        install_tcp_rules(&state, r#"[{"match": "*:443", "verdict": "deny"}]"#);
        assert_eq!(tcp_verdict(&state, "203.0.113.7:443", None), None);
    }

    #[test]
    fn pinned_binaries_filter_is_rechecked_at_connect() {
        let (state, _rx) = test_state();
        let ip: IpAddr = "203.0.113.20".parse().unwrap();
        // A binary-scoped fqdn allow rule; the pin only stores the name, so the
        // filter is applied fresh against the connecting caller.
        state.policy.write().unwrap().tcp_egress = vec![tcp_rule(
            "db.example.com:5432",
            Verdict::Allow,
            Some(vec!["/usr/bin/psql"]),
        )];
        pin_dns_answers(&state, &[ip], "db.example.com", 300, 0);

        let psql = crate::peer_process::PeerProcess {
            pid: 200,
            name: "psql".to_string(),
            exe: Some(std::path::PathBuf::from("/usr/bin/psql")),
            ancestors: Vec::new(),
        };
        let curl = crate::peer_process::PeerProcess {
            pid: 201,
            name: "curl".to_string(),
            exe: Some(std::path::PathBuf::from("/usr/bin/curl")),
            ancestors: Vec::new(),
        };

        // The listed binary is admitted by the pin.
        assert_eq!(
            tcp_verdict(&state, "203.0.113.20:5432", Some(&psql)),
            Some(Verdict::Allow)
        );
        // A different binary is not — the pin's filter fails closed.
        assert_eq!(
            tcp_verdict(&state, "203.0.113.20:5432", Some(&curl)),
            Some(Verdict::Deny)
        );
    }

    #[test]
    fn a_binary_scoped_rule_denies_an_unresolvable_caller_instead_of_deferring() {
        let (state, _rx) = test_state();
        install_tcp_rules(
            &state,
            r#"[{"match": "10.0.0.0/8:5432", "verdict": "deny",
                 "binaries": ["/usr/bin/curl"]}]"#,
        );
        assert_eq!(
            tcp_verdict(&state, "10.0.0.5:5432", None),
            Some(Verdict::Deny),
            "an unresolvable caller must not slip past a binary-scoped deny"
        );
    }

    #[test]
    fn binary_scoped_static_rule_is_not_reopened_by_a_pin() {
        let (state, _rx) = test_state();
        let ip: IpAddr = "203.0.113.50".parse().unwrap();

        // A static CIDR rule allows the IP, but only for /usr/bin/psql, listed
        // BEFORE an unrestricted hostname rule that resolves to the same IP. The
        // binary-excluded match must not be re-opened by the later unrestricted
        // rule — the no-reopen guard runs across the single ordered list.
        state.policy.write().unwrap().tcp_egress = vec![
            tcp_rule(
                "203.0.113.0/24:5432",
                Verdict::Allow,
                Some(vec!["/usr/bin/psql"]),
            ),
            fqdn_rule("db.example.com", 5432, Verdict::Allow),
        ];
        pin_dns_answers(&state, &[ip], "db.example.com", 300, 0);

        let curl = crate::peer_process::PeerProcess {
            pid: 201,
            name: "curl".to_string(),
            exe: Some(std::path::PathBuf::from("/usr/bin/curl")),
            ancestors: Vec::new(),
        };
        let psql = crate::peer_process::PeerProcess {
            pid: 200,
            name: "psql".to_string(),
            exe: Some(std::path::PathBuf::from("/usr/bin/psql")),
            ancestors: Vec::new(),
        };

        // curl is excluded by the static rule's binary filter. The unrestricted
        // pin must NOT re-open the connection — the binary-excluded match fails
        // closed rather than falling through to the pin.
        assert_eq!(
            tcp_verdict(&state, "203.0.113.50:5432", Some(&curl)),
            Some(Verdict::Deny)
        );
        // psql is admitted by the static rule directly.
        assert_eq!(
            tcp_verdict(&state, "203.0.113.50:5432", Some(&psql)),
            Some(Verdict::Allow)
        );
    }

    #[test]
    fn pin_reevaluates_an_earlier_caller_scoped_deny() {
        // Ordered fqdn rules: deny for anything under `bad-parent`, then allow
        // `client`. A direct client skips the deny and creates a pin; a client
        // launched under `bad-parent` must still hit the earlier deny at
        // connect, not ride the pin the direct client left behind. The pin
        // stores only the QNAME, so the ordered rules are re-evaluated against
        // the connecting caller's ancestry.
        let (state, _rx) = test_state();
        let ip: IpAddr = "203.0.113.60".parse().unwrap();
        state.policy.write().unwrap().tcp_egress = vec![
            tcp_rule(
                "db.example.com:5432",
                Verdict::Deny,
                Some(vec!["/usr/bin/bad-parent"]),
            ),
            tcp_rule(
                "db.example.com:5432",
                Verdict::Allow,
                Some(vec!["/usr/bin/client"]),
            ),
        ];

        // The direct client's DNS lookup lands on the allow rule and pins the IP.
        let direct = crate::peer_process::PeerProcess {
            pid: 300,
            name: "client".to_string(),
            exe: Some(std::path::PathBuf::from("/usr/bin/client")),
            ancestors: Vec::new(),
        };
        pin_dns_answers(&state, &[ip], "db.example.com", 300, 0);

        // Direct client connecting is admitted by the allow rule.
        assert_eq!(
            tcp_verdict(&state, "203.0.113.60:5432", Some(&direct)),
            Some(Verdict::Allow)
        );

        // A client under `bad-parent` matches the earlier deny at connect and is
        // refused with an explicit Deny, even though the direct client's pin
        // already exists — the name-scoped deny is terminal, not a fall-through.
        let under_bad_parent = crate::peer_process::PeerProcess {
            pid: 301,
            name: "client".to_string(),
            exe: Some(std::path::PathBuf::from("/usr/bin/client")),
            ancestors: vec![std::path::PathBuf::from("/usr/bin/bad-parent")],
        };
        assert_eq!(
            tcp_verdict(&state, "203.0.113.60:5432", Some(&under_bad_parent)),
            Some(Verdict::Deny),
            "the earlier caller-scoped deny must apply to the reused pin"
        );
    }

    #[test]
    fn pin_resolves_per_destination_port_across_rules() {
        // Two allows for the same host on different ports. Connect-time
        // evaluation must pick the rule matching the actual destination port,
        // not just the first hostname match — otherwise the second port is
        // wrongly denied.
        let (state, _rx) = test_state();
        let ip: IpAddr = "203.0.113.70".parse().unwrap();
        state.policy.write().unwrap().tcp_egress = vec![
            fqdn_rule("db.example.com", 5432, Verdict::Allow),
            fqdn_rule("db.example.com", 6379, Verdict::Allow),
        ];
        pin_dns_answers(&state, &[ip], "db.example.com", 300, 0);

        assert_eq!(
            tcp_verdict(&state, "203.0.113.70:5432", None),
            Some(Verdict::Allow),
            "the first port-scoped allow must admit its port"
        );
        assert_eq!(
            tcp_verdict(&state, "203.0.113.70:6379", None),
            Some(Verdict::Allow),
            "a later port-scoped allow must admit its port too"
        );
        // A port neither rule covers stays unmatched.
        assert!(tcp_verdict(&state, "203.0.113.70:9999", None).is_none());
    }

    #[test]
    fn pin_honors_a_port_scoped_deny_before_an_allow() {
        // Ordered deny :5432 then allow :6379 for one host. The name resolves
        // and pins (DNS is port-blind), but at connect the deny binds :5432 and
        // the allow binds :6379.
        let (state, _rx) = test_state();
        let ip: IpAddr = "203.0.113.71".parse().unwrap();
        state.policy.write().unwrap().tcp_egress = vec![
            fqdn_rule("db.example.com", 5432, Verdict::Deny),
            fqdn_rule("db.example.com", 6379, Verdict::Allow),
        ];
        pin_dns_answers(&state, &[ip], "db.example.com", 300, 0);

        assert_eq!(
            tcp_verdict(&state, "203.0.113.71:5432", None),
            Some(Verdict::Deny),
            "the port-scoped deny must bind its port"
        );
        assert_eq!(
            tcp_verdict(&state, "203.0.113.71:6379", None),
            Some(Verdict::Allow),
            "the later allow must bind its own port"
        );
    }

    #[test]
    fn pin_shared_ip_resolves_by_policy_order_not_insertion_order() {
        // Two names resolve to one IP (CDN-style). The rules are ordered deny
        // `blocked` BEFORE allow `db`, so the earlier deny wins — and that
        // outcome must not depend on which name's answer was pinned first.
        let rules = || {
            vec![
                fqdn_rule("blocked.example.com", 5432, Verdict::Deny),
                fqdn_rule("db.example.com", 5432, Verdict::Allow),
            ]
        };
        let ip: IpAddr = "203.0.113.80".parse().unwrap();

        for order in [
            ["blocked.example.com", "db.example.com"],
            ["db.example.com", "blocked.example.com"],
        ] {
            let (state, _rx) = test_state();
            state.policy.write().unwrap().tcp_egress = rules();
            for name in order {
                pin_dns_answers(&state, &[ip], name, 300, 0);
            }
            assert_eq!(
                tcp_verdict(&state, "203.0.113.80:5432", None),
                Some(Verdict::Deny),
                "the earlier deny rule wins regardless of pin insertion order"
            );
        }
    }

    #[test]
    fn earlier_hostname_rule_beats_a_later_ip_rule() {
        // One ordered pass, so an earlier rule wins whatever its matcher kind:
        // a hostname `ask` listed before a CIDR `allow` covering the resolved IP
        // still decides.
        let (state, _rx) = test_state();
        let ip: IpAddr = "203.0.113.90".parse().unwrap();
        state.policy.write().unwrap().tcp_egress = vec![
            fqdn_rule("db.example.com", 5432, Verdict::Ask),
            RouteRule {
                matcher: crate::routing::RouteMatcher::CidrPort(
                    "203.0.113.0/24".parse().unwrap(),
                    5432,
                ),
                verdict: Verdict::Allow,
                transport: Transport::Direct,
                tls_terminate: false,
                http_rules: Vec::new(),
                scheme: None,
                binaries: None,
            },
        ];
        pin_dns_answers(&state, &[ip], "db.example.com", 300, 0);

        assert_eq!(
            tcp_verdict(&state, "203.0.113.90:5432", None),
            Some(Verdict::Ask),
            "the earlier hostname rule must win over the later CIDR allow"
        );
    }

    #[test]
    fn earlier_ip_rule_beats_a_later_hostname_rule() {
        // The mirror of the above: a CIDR `allow` listed BEFORE a hostname
        // `deny` for a name resolving into it. Global first-match means the
        // earlier IP allow wins, so the pinned deny does not apply.
        let (state, _rx) = test_state();
        let ip: IpAddr = "203.0.113.95".parse().unwrap();
        state.policy.write().unwrap().tcp_egress = vec![
            RouteRule {
                matcher: crate::routing::RouteMatcher::CidrPort(
                    "203.0.113.0/24".parse().unwrap(),
                    5432,
                ),
                verdict: Verdict::Allow,
                transport: Transport::Direct,
                tls_terminate: false,
                http_rules: Vec::new(),
                scheme: None,
                binaries: None,
            },
            fqdn_rule("db.example.com", 5432, Verdict::Deny),
        ];
        pin_dns_answers(&state, &[ip], "db.example.com", 300, 0);

        assert_eq!(
            tcp_verdict(&state, "203.0.113.95:5432", None),
            Some(Verdict::Allow),
            "the earlier CIDR allow must win over the later hostname deny"
        );
    }

    #[test]
    fn emit_policy_deny_http_carries_reason_metadata() {
        let (state, mut rx) = test_state();
        emit_policy_deny_http(
            &state,
            "evil.example.com",
            "GET",
            "/x",
            "policy-deny",
            &test_actor(),
        );

        let msg = rx.try_recv().unwrap();
        let event: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(event["action"], "GET http://evil.example.com/x");
        assert_eq!(event["result"], "failure");
        assert_eq!(event["status_code"], 403);
        assert_eq!(event["metadata"]["reason"], "policy-deny");
    }

    #[test]
    fn emit_policy_deny_http_stamps_the_client_endpoint() {
        let (state, mut rx) = test_state();
        emit_policy_deny_http(
            &state,
            "evil.example.com",
            "GET",
            "/x",
            "policy-deny",
            &test_actor(),
        );

        let msg = rx.try_recv().unwrap();
        let event: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(event["action"], "GET http://evil.example.com/x");
        assert_eq!(event["method"], "GET");
        assert_eq!(event["host"], "evil.example.com");
        assert_eq!(event["path"], "/x");
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
            &test_actor(),
        );

        let msg = rx.try_recv().unwrap();
        let event: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(event["action"], "GET http://example.com:8080/api/data");
        assert_eq!(event["method"], "GET");
        // `host` is the bare hostname — the port is dropped, matching the MITM path.
        assert_eq!(event["host"], "example.com");
        assert_eq!(event["path"], "/api/data");
        assert_eq!(event["result"], "success");
    }

    #[test]
    fn emit_audit_failure_dedup_suppresses_rapid_repeats() {
        let (state, mut rx) = test_state();
        emit_audit(&state, "evil.com:443", "failure", 403, &test_actor());
        emit_audit(&state, "evil.com:443", "failure", 403, &test_actor());

        assert!(rx.try_recv().is_ok());
        assert!(
            rx.try_recv().is_err(),
            "second failure should be deduplicated"
        );
    }

    #[test]
    fn emit_audit_success_not_deduplicated() {
        let (state, mut rx) = test_state();
        emit_audit(&state, "api.openai.com:443", "success", 200, &test_actor());
        emit_audit(&state, "api.openai.com:443", "success", 200, &test_actor());

        assert!(rx.try_recv().is_ok());
        assert!(
            rx.try_recv().is_ok(),
            "success events should not be deduplicated"
        );
    }

    #[test]
    fn emit_audit_error_not_deduplicated() {
        let (state, mut rx) = test_state();
        emit_audit(&state, "api.openai.com:443", "error", 502, &test_actor());
        emit_audit(&state, "api.openai.com:443", "error", 502, &test_actor());

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
        emit_audit(&state, "1.2.3.4:443", "failure", 403, &test_actor());

        assert!(rx.try_recv().is_ok(), "transparent deny should emit");
        assert!(
            rx.try_recv().is_ok(),
            "connect deny on same IP must not be suppressed by transparent-deny's dedup entry"
        );
    }

    #[test]
    fn emit_deny_dedup_different_hosts_not_suppressed() {
        let (state, mut rx) = test_state();
        emit_audit(&state, "evil.com:443", "failure", 403, &test_actor());
        emit_audit(&state, "other.com:443", "failure", 403, &test_actor());

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
        emit_policy_deny_connect(&state, "evil.com:443", "policy-deny", &test_actor());

        assert!(rx.try_recv().is_ok(), "gate-denied failure emits");
        assert!(
            rx.try_recv().is_ok(),
            "policy-deny on same host must not be suppressed by gate-denied dedup",
        );
    }

    /// The shape an operator writes when `egress.tcp` is meant to carve denies
    /// out of a broad L7 allowance.
    fn install_catch_all_allow(state: &Arc<ProxyState>) {
        state
            .policy
            .write()
            .unwrap()
            .routes
            .push(crate::routing::RouteRule {
                matcher: crate::routing::RouteMatcher::Domain("*".to_string()),
                verdict: Verdict::Allow,
                transport: Transport::Direct,
                tls_terminate: false,
                http_rules: Vec::new(),
                scheme: None,
                binaries: None,
            });
    }

    /// A catch-all allow whose HTTP rules permit read-only GraphQL only.
    fn install_graphql_read_allow(state: &Arc<ProxyState>) {
        state
            .policy
            .write()
            .unwrap()
            .routes
            .push(crate::routing::RouteRule {
                matcher: crate::routing::RouteMatcher::Domain("*".to_string()),
                verdict: Verdict::Allow,
                transport: Transport::Direct,
                tls_terminate: false,
                http_rules: vec![crate::policy_schema::HttpRule {
                    method: Some("POST".to_string()),
                    path: Some("/graphql".to_string()),
                    graphql: Some(crate::policy_schema::GraphqlMatcher {
                        operation_type: crate::policy_schema::GraphqlOperationTypeMatcher::Query,
                        operation_name: None,
                        fields: vec!["viewer".to_string()],
                        arguments: vec![],
                    }),
                    mcp: None,
                }],
                scheme: None,
                binaries: None,
            });
    }

    /// A catch-all allow whose HTTP rules permit read-only MCP tools only.
    fn install_mcp_read_allow(state: &Arc<ProxyState>) {
        state
            .policy
            .write()
            .unwrap()
            .routes
            .push(crate::routing::RouteRule {
                matcher: crate::routing::RouteMatcher::Domain("*".to_string()),
                verdict: Verdict::Allow,
                transport: Transport::Direct,
                tls_terminate: false,
                http_rules: vec![crate::policy_schema::HttpRule {
                    method: Some("POST".to_string()),
                    path: Some("/mcp".to_string()),
                    graphql: None,
                    mcp: Some(crate::policy_schema::McpMatcher {
                        method: "tools/call".to_string(),
                        tool: Some("read_*".to_string()),
                        uri: None,
                        arguments: Vec::new(),
                    }),
                }],
                scheme: None,
                binaries: None,
            });
    }

    /// Drive the forward-proxy door with an MCP body and return its answer.
    ///
    /// The plaintext door enforces the same rules as the MITM one; a rule that
    /// governed only HTTPS would leave `http://` unjudged.
    async fn forward_mcp(state: &Arc<ProxyState>, body: &'static str) -> String {
        let head = format!(
            "POST http://10.0.0.5/mcp HTTP/1.1\r\nHost: 10.0.0.5\r\nMCP-Protocol-Version: 2026-07-28\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        let (mut client, server) = socket_pair().await;
        let state_for_handler = state.clone();
        tokio::spawn(async move {
            let actor = test_actor();
            handle_http_forward(server, "10.0.0.5:80", head, &state_for_handler, &actor).await
        });
        client.write_all(body.as_bytes()).await.unwrap();
        read_response(&mut client).await
    }

    /// Two MCP rules, one for the path carrying the placeholder and one for the
    /// path the credential produces, plus the placeholder that moves between them.
    fn install_mcp_rewrite_allow(state: &Arc<ProxyState>, permit_after_rewrite: &str) {
        {
            let mut map = state.uri_placeholder_injections.write().unwrap();
            map.insert(
                "10.0.0.5".into(),
                vec![("__lens_cred:tok__".into(), "real-token".into())],
            );
        }
        let rule = |path: &str, tool: &str| crate::policy_schema::HttpRule {
            method: Some("POST".to_string()),
            path: Some(path.to_string()),
            graphql: None,
            mcp: Some(crate::policy_schema::McpMatcher {
                method: "tools/call".to_string(),
                tool: Some(tool.to_string()),
                uri: None,
                arguments: Vec::new(),
            }),
        };
        state
            .policy
            .write()
            .unwrap()
            .routes
            .push(crate::routing::RouteRule {
                matcher: crate::routing::RouteMatcher::Domain("*".to_string()),
                verdict: Verdict::Allow,
                transport: Transport::Direct,
                tls_terminate: false,
                http_rules: vec![
                    rule("/mcp/__lens_cred:tok__", "*"),
                    rule("/mcp/real-token", permit_after_rewrite),
                ],
                scheme: None,
                binaries: None,
            });
    }

    /// Drive the forward-proxy door with a placeholder in the path.
    async fn forward_mcp_with_placeholder(state: &Arc<ProxyState>, body: &'static str) -> String {
        let head = format!(
            "POST http://10.0.0.5/mcp/__lens_cred:tok__ HTTP/1.1\r\nHost: 10.0.0.5\r\nMCP-Protocol-Version: 2026-07-28\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        let (mut client, server) = socket_pair().await;
        let state_for_handler = state.clone();
        tokio::spawn(async move {
            let actor = test_actor();
            handle_http_forward(server, "10.0.0.5:80", head, &state_for_handler, &actor).await
        });
        client.write_all(body.as_bytes()).await.unwrap();
        read_response(&mut client).await
    }

    #[tokio::test]
    async fn http_forward_re_judges_a_rewritten_path_against_the_mcp_rules_it_reaches() {
        // The rule for the placeholder path permits any tool; the one the
        // credential produces permits only `read_*`. The body must answer to the
        // rules the rewritten path actually reaches.
        let (state, _rx) = test_state();
        install_mcp_rewrite_allow(&state, "read_*");

        let response = forward_mcp_with_placeholder(
            &state,
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"write_file"}}"#,
        )
        .await;
        assert!(
            response.contains("403"),
            "the post-rewrite rule must decide; got {response:?}"
        );
    }

    #[tokio::test]
    async fn http_forward_denies_a_tool_no_mcp_rule_names() {
        let (state, _rx) = test_state();
        install_mcp_read_allow(&state);

        let response = forward_mcp(
            &state,
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"write_file"}}"#,
        )
        .await;
        assert!(
            response.contains("403"),
            "the plaintext door must judge the body too; got {response:?}"
        );
    }

    #[tokio::test]
    async fn http_forward_denies_a_batch_body() {
        let (state, _rx) = test_state();
        install_mcp_read_allow(&state);

        let response = forward_mcp(
            &state,
            r#"[{"method":"tools/call","params":{"name":"read_file"}}]"#,
        )
        .await;
        assert!(response.contains("403"), "got {response:?}");
    }

    /// The head of an absolute-form forward-proxy GraphQL request.
    ///
    /// Head only: this door is handed the head that was already read off the
    /// socket, and the body is still on the socket for a rule to read.
    fn graphql_forward_head(body_len: usize) -> Vec<u8> {
        format!(
            "POST http://10.0.0.5/graphql HTTP/1.1\r\nHost: 10.0.0.5\r\nContent-Type: application/json\r\nContent-Length: {body_len}\r\n\r\n"
        )
        .into_bytes()
    }

    /// Drive the forward-proxy door with a GraphQL body and return its answer.
    async fn forward_graphql(state: &Arc<ProxyState>, body: &'static str) -> String {
        let (mut client, server) = socket_pair().await;
        let state_for_handler = state.clone();
        tokio::spawn(async move {
            let actor = test_actor();
            handle_http_forward(
                server,
                "10.0.0.5:80",
                graphql_forward_head(body.len()),
                &state_for_handler,
                &actor,
            )
            .await
        });
        client.write_all(body.as_bytes()).await.unwrap();
        read_response(&mut client).await
    }

    #[tokio::test]
    async fn http_forward_refuses_a_request_an_llm_route_claims() {
        // The redirect needs a TLS session it can point elsewhere. This door has
        // none, so passing the request on would send it — with the key the proxy
        // injects — to the very API the redirect exists to withhold it from.
        let (state, _rx) = test_state();
        let llm = crate::llm::LlmRouting::from_policy(
            &serde_json::from_str(
                r#"{
                    "backends": [{ "id": "b", "url": "https://vllm.internal/v1/chat/completions" }],
                    "routes": [{ "match": { "domain": "10.0.0.5", "path": "/v1/messages" },
                        "translate": { "from": "anthropicMessages", "to": "openaiChat" }, "backend": "b" }]
                }"#,
            )
            .unwrap(),
        )
        .unwrap();
        apply_network_policy(
            &state,
            NetworkPolicy {
                default_verdict: Verdict::Allow,
                default_transport: Transport::Direct,
                llm: Arc::new(llm),
                ..Default::default()
            },
        );

        let (mut client, server) = socket_pair().await;
        let state_for_handler = state.clone();
        tokio::spawn(async move {
            handle_http_forward(
                server,
                "10.0.0.5:80",
                b"POST http://10.0.0.5/v1/messages HTTP/1.1\r\nHost: 10.0.0.5\r\n\r\n".to_vec(),
                &state_for_handler,
                &test_actor(),
            )
            .await
        });
        let response = read_response(&mut client).await;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "a claimed request must not leave over cleartext; got {response:?}"
        );
    }

    #[tokio::test]
    async fn http_forward_denies_a_mutation_where_only_queries_are_permitted() {
        let (state, _rx) = test_state();
        install_graphql_read_allow(&state);

        let response =
            forward_graphql(&state, r#"{"query":"mutation { deleteRepository }"}"#).await;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "a mutation must be denied on the plaintext door too; got {response:?}"
        );
    }

    #[tokio::test]
    async fn http_forward_denies_a_forbidden_field_on_a_permitted_operation() {
        let (state, _rx) = test_state();
        install_graphql_read_allow(&state);

        let response = forward_graphql(&state, r#"{"query":"{ viewer secrets }"}"#).await;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "containment applies on this door too; got {response:?}"
        );
    }

    #[tokio::test]
    async fn http_forward_denies_an_upgrade_on_a_rule_carrying_route() {
        // Closing the connection after one response is not enough: a 101 from a
        // lenient origin would turn the rest of it into a spliced pipe that no
        // rule judged. Parity with the TLS door.
        let (state, _rx) = test_state();
        install_graphql_read_allow(&state);

        let (mut client, server) = socket_pair().await;
        let state_for_handler = state.clone();
        tokio::spawn(async move {
            let actor = test_actor();
            let headers = b"GET http://10.0.0.5/graphql HTTP/1.1\r\nHost: 10.0.0.5\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".to_vec();
            handle_http_forward(server, "10.0.0.5:80", headers, &state_for_handler, &actor).await
        });

        let response = read_response(&mut client).await;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "an upgrade must not be granted where rules apply; got {response:?}"
        );
    }

    #[tokio::test]
    async fn http_forward_denies_a_path_no_rule_covers() {
        let (state, _rx) = test_state();
        install_graphql_read_allow(&state);

        let (mut client, server) = socket_pair().await;
        let state_for_handler = state.clone();
        tokio::spawn(async move {
            let actor = test_actor();
            let headers =
                b"GET http://10.0.0.5/rest/things HTTP/1.1\r\nHost: 10.0.0.5\r\n\r\n".to_vec();
            handle_http_forward(server, "10.0.0.5:80", headers, &state_for_handler, &actor).await
        });

        let response = read_response(&mut client).await;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "only the GraphQL rule is installed; got {response:?}"
        );
    }

    #[test]
    fn a_rule_carrying_route_forces_the_origin_to_close_after_one_response() {
        // This door judges the first request and then splices, so a client must
        // not be able to keep the connection for a second, unjudged one.
        let head = "GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n";
        let rewritten =
            rewrite_http_forward_request(head, "/x", "example.com:80", Reuse::OneRequestOnly);
        let lower = rewritten.to_ascii_lowercase();
        assert!(lower.contains("connection: close"), "{rewritten}");
        assert!(!lower.contains("keep-alive"), "{rewritten}");
    }

    /// The tcp table's verdict for `target`; tests that also care about the
    /// name the rule bound through call `tcp_egress_verdict_for_hostport`.
    fn tcp_verdict(
        state: &Arc<ProxyState>,
        target: &str,
        caller: Option<&crate::peer_process::PeerProcess>,
    ) -> Option<Verdict> {
        tcp_egress_verdict_for_hostport(state, target, 0, caller).map(|d| d.verdict)
    }

    fn install_tcp_rules(state: &Arc<ProxyState>, json: &str) {
        let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
        state.policy.write().unwrap().tcp_egress =
            crate::routing::parse_tcp_egress(&parsed).unwrap();
    }

    /// Publish a new tcp table through the real reload entry point, so the
    /// policy generation advances exactly as it does for an operator's frame.
    /// `install_tcp_rules` writes the field directly and deliberately does not.
    fn reload_tcp_rules(state: &Arc<ProxyState>, json: &str) {
        let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
        apply_network_policy(
            state,
            NetworkPolicy {
                tcp_egress: crate::routing::parse_tcp_egress(&parsed).unwrap(),
                ..Default::default()
            },
        );
    }

    fn install_tcp_deny(state: &Arc<ProxyState>, pattern: &str) {
        install_tcp_rules(
            state,
            &format!(r#"[{{"match": "{pattern}", "verdict": "deny"}}]"#),
        );
    }

    /// A loopback socket pair plus the client end, for driving one handler.
    async fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    /// Read the handler's first response. The timeout is the assertion that
    /// matters for the tcp-deny tests: a handler that ignores the deny goes on
    /// to *dial* the denied destination, which never answers.
    async fn read_response(client: &mut TcpStream) -> String {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("handler must answer from policy, not dial the denied target")
            .unwrap();
        String::from_utf8_lossy(&buf[..n]).to_string()
    }

    /// Helper for the Ask end-to-end tests. Installs a single `Verdict::Ask`
    /// rule (transport defaulted to `Upstream`) for `domain`.
    fn install_ask_route(state: &Arc<ProxyState>, domain: &str) {
        state
            .policy
            .write()
            .unwrap()
            .routes
            .push(crate::routing::RouteRule {
                matcher: crate::routing::RouteMatcher::Domain(domain.to_string()),
                verdict: Verdict::Ask,
                transport: Transport::Upstream,
                tls_terminate: false,
                http_rules: Vec::new(),
                scheme: None,
                binaries: None,
            });
    }

    /// Install one allow rule with `transport` for `domain`, and an `llm` route
    /// that claims every request to it.
    fn install_llm_route(state: &Arc<ProxyState>, domain: &str, transport: Transport) {
        let llm = crate::llm::LlmRouting::from_policy(
            &serde_json::from_str(&format!(
                r#"{{
                    "backends": [{{ "id": "b", "url": "https://vllm.internal/v1/chat/completions" }}],
                    "routes": [{{ "match": {{ "domain": "{domain}", "path": "/v1/**" }},
                        "translate": {{ "from": "anthropicMessages", "to": "openaiChat" }},
                        "backend": "b" }}]
                }}"#,
            ))
            .unwrap(),
        )
        .unwrap();
        apply_network_policy(
            state,
            NetworkPolicy {
                default_verdict: Verdict::Allow,
                default_transport: transport,
                llm: Arc::new(llm),
                ..Default::default()
            },
        );
    }

    /// Drive the CONNECT door and read what it answered the client.
    async fn connect_answer(state: &Arc<ProxyState>, target: &'static str) -> (String, String) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let state_for_handler = state.clone();
        let handler = tokio::spawn(async move {
            handle_connect(server, target, &test_actor(), &state_for_handler).await
        });

        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("the door answers rather than dialling")
            .unwrap();
        let reason = handler
            .await
            .unwrap()
            .expect_err("the connection is refused")
            .to_string();
        (String::from_utf8_lossy(&buf[..n]).to_string(), reason)
    }

    #[tokio::test]
    async fn connect_refuses_an_llm_claim_the_aws_resign_path_would_swallow() {
        // The re-sign path delivers to the host the sandbox named and knows
        // nothing of `llm`. Letting it have the connection would send the
        // request — signed — to the API the redirect exists to withhold it from.
        let (state, mut rx) = test_state();
        install_llm_route(&state, "bedrock.example.com", Transport::Direct);
        state
            .aws_resign
            .update(Default::default(), vec!["bedrock.example.com".to_string()]);

        let (answer, reason) = connect_answer(&state, "bedrock.example.com:443").await;
        assert!(answer.starts_with("HTTP/1.1 502"), "{answer}");
        assert!(reason.contains("aws re-sign"), "{reason}");
        let events = drain_audit_lines(&mut rx);
        assert!(
            events.iter().any(|ev| ev["result"] == "error"),
            "every occurrence of a misconfiguration is recorded: {events:?}"
        );
    }

    #[tokio::test]
    async fn a_tunnelled_llm_claim_is_given_the_ca_it_needs() {
        // Without one this branch splices the connection, and a spliced
        // connection carries the request to the API the route claims it from.
        let (state, _rx) = test_state();
        install_llm_route(&state, "api.anthropic.com", Transport::Upstream);
        assert!(
            state.ephemeral_ca.get().is_none(),
            "the fixture must start without one"
        );

        // No upstream is configured, so the connection ends there — after the
        // door has decided what this route needs.
        let _ = connect_answer(&state, "api.anthropic.com:443").await;
        assert!(state.ephemeral_ca.get().is_some());
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
    async fn connect_is_denied_by_a_tcp_rule_despite_a_catch_all_http_allow() {
        // Without the tcp check on this door, the catch-all `egress.http` allow
        // that the deny was written to carve into opens an uninspected tunnel
        // straight to the denied destination.
        let (state, _rx) = test_state();
        install_catch_all_allow(&state);
        install_tcp_deny(&state, "10.0.0.0/8:22");

        let (mut client, server) = socket_pair().await;
        let state_for_handler = state.clone();
        tokio::spawn(async move {
            let actor = test_actor();
            handle_connect(server, "10.0.0.5:22", &actor, &state_for_handler).await
        });

        let response = read_response(&mut client).await;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "tcp deny must be terminal on CONNECT; got {response:?}"
        );
    }

    #[tokio::test]
    async fn connect_to_a_denied_hostname_needs_no_dns_pin() {
        // On this door the client names the destination, so hostname rules match
        // the name directly — the pinning machinery exists only because the
        // transparent path loses the name.
        let (state, _rx) = test_state();
        install_catch_all_allow(&state);
        install_tcp_deny(&state, "db.internal:5432");

        let (mut client, server) = socket_pair().await;
        let state_for_handler = state.clone();
        tokio::spawn(async move {
            let actor = test_actor();
            handle_connect(server, "db.internal:5432", &actor, &state_for_handler).await
        });

        let response = read_response(&mut client).await;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "hostname tcp deny must be terminal on CONNECT; got {response:?}"
        );
    }

    #[tokio::test]
    async fn http_forward_applies_the_tcp_deny_on_port_80() {
        // `parse_http_forward_target` appends `:80` when the URL carries no
        // port, so this is the shape real absolute-form traffic arrives in —
        // resolving it as CONNECT's 443 would miss every :80 rule.
        let (state, _rx) = test_state();
        install_catch_all_allow(&state);
        install_tcp_deny(&state, "10.0.0.0/8:80");

        let (mut client, server) = socket_pair().await;
        let state_for_handler = state.clone();
        tokio::spawn(async move {
            let actor = test_actor();
            let headers = b"GET http://10.0.0.5/ HTTP/1.1\r\nHost: 10.0.0.5\r\n\r\n".to_vec();
            handle_http_forward(server, "10.0.0.5:80", headers, &state_for_handler, &actor).await
        });

        let response = read_response(&mut client).await;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "tcp deny must be terminal on the http forward path; got {response:?}"
        );
    }

    #[tokio::test]
    async fn transparent_tls_applies_a_hostname_tcp_deny_without_a_pin() {
        // The other doors read the name off the request; this one reads it off
        // the SNI. Binding hostname rules only through a live DNS pin would
        // make a lapsed pin — a long-TTL name, or a pin store the workload
        // filled — the difference between a deny and an MITM'd allow, and the
        // workload picks the door. A deny audits as one wherever it lands.
        assert_eq!(
            transparent_tls_deny_reason(r#"[{"match": "db.internal:443", "verdict": "deny"}]"#)
                .await,
            Some("policy-deny".to_string())
        );
    }

    #[tokio::test]
    async fn transparent_tls_refuses_even_a_tcp_allow_it_cannot_splice() {
        // The ClientHello is spent by the time the SNI is readable, so an allow
        // has no raw splice left to grant. MITM-ing it instead would inspect
        // exactly the traffic the rule opted out of inspecting; the audit says
        // what the connection actually lost.
        assert_eq!(
            transparent_tls_deny_reason(r#"[{"match": "db.internal:443", "verdict": "allow"}]"#)
                .await,
            Some("egress-tcp-unpinned".to_string())
        );
    }

    /// Drive `handle_transparent_tls` with SNI `db.internal` against a tcp
    /// table that claims the name but not the address, and report the audited
    /// deny reason. The catch-all http allow is what the refusal has to beat:
    /// without the SNI check the handler MITMs the connection instead.
    async fn transparent_tls_deny_reason(tcp_rules: &str) -> Option<String> {
        let (state, mut rx) = test_state();
        install_catch_all_allow(&state);
        install_tcp_rules(&state, tcp_rules);
        // No `pin_dns_answers`: the address is unknown to the tcp table, so the
        // pre-classification check in `handle_transparent_connection` passes.
        assert!(
            tcp_egress_verdict(&state, "203.0.113.9", 443, None).is_none(),
            "the address alone must not match, or the test proves nothing"
        );

        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let name = rustls::pki_types::ServerName::try_from("db.internal").unwrap();
            // The handler closes on us; we only need the ClientHello on the wire.
            let _ = connector.connect(name, stream).await;
        });

        let (server, peer) = listener.accept().await.unwrap();
        let actor = crate::peer_process::ActorContext::resolve(peer);
        let orig_dst: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            handle_transparent_tls(server, orig_dst, actor, &state),
        )
        .await
        .expect("handler must not park on an upstream dial");

        let reason = drain_audit(&mut rx)
            .iter()
            .find_map(|e| e["metadata"]["reason"].as_str().map(str::to_string));
        // A refusal closes the socket and returns. Reaching the MITM pipeline
        // instead is the regression this test exists for, and it surfaces here:
        // the client trusts no CA, so the ephemeral cert draws an alert.
        outcome.expect("the connection must be refused, not intercepted");
        reason
    }

    #[tokio::test]
    async fn a_pinned_hostname_ask_names_the_host_in_the_dialog() {
        // The transparent door has only SO_ORIGINAL_DST, but the rule bound
        // through a DNS pin, so the name is known. Ask about the name the
        // policy author wrote, not the address it happened to resolve to —
        // and record that name, since the set it lands in is keyed by QNAME.
        let (state, mut rx) = test_state();
        install_tcp_rules(
            &state,
            r#"[{"match": "db.internal:5432", "verdict": "ask"}]"#,
        );
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        pin_dns_answers(&state, &[ip], "db.internal", 300, 0);

        // Straight from the table, exactly as the transparent door gets it.
        let decision = tcp_egress_verdict_for_hostport(&state, "203.0.113.9:5432", 0, None)
            .expect("the pinned hostname rule must claim this address");

        let (_client, server) = socket_pair().await;
        let state_for_handler = state.clone();
        tokio::spawn(async move {
            let actor = test_actor();
            handle_raw_passthrough(
                server,
                "203.0.113.9:5432".parse().unwrap(),
                &decision,
                &state_for_handler,
                &actor,
            )
            .await
        });

        let pending = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("a dialog must be raised")
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&pending).unwrap();
        assert_eq!(parsed["host"], "db.internal");
        assert_eq!(parsed["action"], "CONNECT db.internal:5432");
        // A raw splice is opaque: nothing about it will be inspected, logged
        // per-request, or credential-injected. The dialog must say so.
        assert_eq!(parsed["treatment"], "raw");

        // An approval is recorded under that same name. The DNS stub compares
        // this set against QNAMEs, so an address here would never match.
        let id = parsed["id"].as_str().unwrap().to_string();
        assert!(crate::gate::resolve_pending(
            &state,
            &id,
            crate::protocol::Decision::AllowOnce,
        ));
        let resolved = tokio::time::timeout(Duration::from_secs(2), async {
            while !state
                .gate_resolved_hosts
                .read()
                .unwrap()
                .contains("db.internal")
            {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(resolved.is_ok(), "the approved name must be recorded");
    }

    /// Every audit event queued so far, parsed. Assertions read better against
    /// the whole batch than against a positional `try_recv` chain.
    fn drain_audit(rx: &mut mpsc::UnboundedReceiver<String>) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            out.push(serde_json::from_str(&msg).unwrap());
        }
        out
    }

    /// Drive `handle_raw_passthrough` to completion, answering its dialog with
    /// `answer` once the prompt appears. `before_answer` runs while the prompt
    /// is still open, which is where a policy reload lands.
    async fn raw_passthrough_answering(
        state: &Arc<ProxyState>,
        rx: &mut mpsc::UnboundedReceiver<String>,
        dst: SocketAddr,
        answer: crate::protocol::Decision,
        before_answer: impl FnOnce(),
    ) {
        let decision = tcp_egress_verdict(state, &dst.ip().to_string(), dst.port(), None)
            .expect("the rule under test must claim this address");
        let (_client, server) = socket_pair().await;
        let state_for_handler = state.clone();
        let handler = tokio::spawn(async move {
            let actor = test_actor();
            handle_raw_passthrough(server, dst, &decision, &state_for_handler, &actor).await
        });

        let prompt = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("a dialog must be raised")
            .unwrap();
        let id = serde_json::from_str::<serde_json::Value>(&prompt).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();

        before_answer();
        assert!(crate::gate::resolve_pending(state, &id, answer));

        // A handler that gets past policy parks on the dial — for an approval
        // that *is* the success case, so completion is not required. Every audit
        // the callers assert on is emitted before any dial is attempted.
        let _ = tokio::time::timeout(Duration::from_millis(500), handler).await;
    }

    #[tokio::test]
    async fn a_policy_reload_during_the_dialog_refuses_the_approved_splice() {
        // The gate parks the connection for up to DECISION_TIMEOUT and a policy
        // can land in that window. The proxy doors re-read the table at their
        // dial; this door resolves nothing, so it has to re-read explicitly.
        // Otherwise an approval outlives the rule that prompted it — and the
        // workload, which picks its own door, would pick this one.
        let (state, mut rx) = test_state();
        install_tcp_rules(
            &state,
            r#"[{"match": "203.0.113.0/24:5432", "verdict": "ask"}]"#,
        );

        raw_passthrough_answering(
            &state,
            &mut rx,
            "203.0.113.9:5432".parse().unwrap(),
            crate::protocol::Decision::AllowAlways,
            // The operator revokes the rule while the prompt is still on screen.
            || {
                reload_tcp_rules(
                    &state,
                    r#"[{"match": "203.0.113.0/24:5432", "verdict": "deny"}]"#,
                )
            },
        )
        .await;

        let events = drain_audit(&mut rx);
        assert!(
            events
                .iter()
                .any(|e| e["metadata"]["reason"] == "policy-changed"),
            "the revoked rule must refuse the approved splice; got {events:#?}"
        );
        assert!(
            !events.iter().any(|e| e["result"] == "success"),
            "nothing may splice under a rule that no longer exists; got {events:#?}"
        );
    }

    #[tokio::test]
    async fn a_rule_deleted_during_the_dialog_refuses_on_the_proxy_door_too() {
        // The transparent door refuses this. The workload picks its door, so
        // the CONNECT door must not be the softer one — its dial guard asks
        // about the resolved address, and a table that no longer claims that
        // address reads as "not my business" rather than "the grant is gone".
        let (state, mut rx) = test_state();
        install_tcp_rules(
            &state,
            r#"[{"match": "203.0.113.0/24:5432", "verdict": "ask"}]"#,
        );
        let decision = tcp_egress_verdict_for_hostport(&state, "203.0.113.9:5432", 443, None)
            .expect("the cidr rule must claim this address");

        let (mut client, server) = socket_pair().await;
        let state_for_handler = state.clone();
        tokio::spawn(async move {
            let actor = test_actor();
            connect_raw_passthrough(
                server,
                "203.0.113.9:5432",
                &decision,
                &state_for_handler,
                &actor,
            )
            .await
        });

        let prompt = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("a dialog must be raised")
            .unwrap();
        let id = serde_json::from_str::<serde_json::Value>(&prompt).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();

        reload_tcp_rules(&state, "[]");
        assert!(crate::gate::resolve_pending(
            &state,
            &id,
            crate::protocol::Decision::AllowAlways
        ));

        let response = read_response(&mut client).await;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "a deleted rule must refuse before the dial; got {response:?}"
        );
    }

    #[tokio::test]
    async fn a_rule_deleted_during_the_dialog_refuses_the_approved_splice() {
        // Revoking by deletion is the ordinary way to withdraw a grant, and it
        // must land as hard as swapping in a deny. Silence from the new table is
        // not consent: the rule that justified splicing this raw is gone.
        let (state, mut rx) = test_state();
        install_tcp_rules(
            &state,
            r#"[{"match": "203.0.113.0/24:5432", "verdict": "ask"}]"#,
        );

        raw_passthrough_answering(
            &state,
            &mut rx,
            "203.0.113.9:5432".parse().unwrap(),
            crate::protocol::Decision::AllowAlways,
            || reload_tcp_rules(&state, "[]"),
        )
        .await;

        let events = drain_audit(&mut rx);
        assert!(
            events
                .iter()
                .any(|e| e["metadata"]["reason"] == "policy-changed"),
            "a deleted rule must refuse the approved splice; got {events:#?}"
        );
        assert!(
            !events.iter().any(|e| e["result"] == "success"),
            "nothing may splice once the rule is gone; got {events:#?}"
        );
    }

    #[tokio::test]
    async fn the_rule_an_approval_writes_does_not_void_that_approval() {
        // "Always allow" is answered by writing the rule, which reloads the
        // policy and advances the generation — so a bare generation check refuses
        // the very request that raised the card, and remembering a decision reads
        // as denying it. The held connection must complete, not just a redial.
        let (state, mut rx) = test_state();
        install_tcp_rules(
            &state,
            r#"[{"match": "203.0.113.0/24:5432", "verdict": "ask"}]"#,
        );

        raw_passthrough_answering(
            &state,
            &mut rx,
            "203.0.113.9:5432".parse().unwrap(),
            crate::protocol::Decision::AllowAlways,
            // The approval lands as a rule ahead of the ask that raised it.
            || {
                reload_tcp_rules(
                    &state,
                    r#"[
                        {"match": "203.0.113.9:5432", "verdict": "allow"},
                        {"match": "203.0.113.0/24:5432", "verdict": "ask"}
                    ]"#,
                )
            },
        )
        .await;

        let events = drain_audit(&mut rx);
        assert!(
            !events
                .iter()
                .any(|e| e["metadata"]["reason"] == "policy-changed"),
            "the approval's own rule must not read as a revocation; got {events:#?}"
        );
    }

    #[tokio::test]
    async fn the_rule_an_approval_writes_does_not_void_it_for_an_ipv6_destination() {
        // The re-read has to reach the table as an address, and an IPv6 door
        // target is bracketed — split naively it arrives as a hostname that no
        // address rule can match, so every v6 approval would refuse itself.
        let (state, mut rx) = test_state();
        install_tcp_rules(
            &state,
            r#"[{"match": "[2001:db8::/32]:5432", "verdict": "ask"}]"#,
        );

        raw_passthrough_answering(
            &state,
            &mut rx,
            "[2001:db8::1]:5432".parse().unwrap(),
            crate::protocol::Decision::AllowAlways,
            || {
                reload_tcp_rules(
                    &state,
                    r#"[
                        {"match": "[2001:db8::1]:5432", "verdict": "allow"},
                        {"match": "[2001:db8::/32]:5432", "verdict": "ask"}
                    ]"#,
                )
            },
        )
        .await;

        let events = drain_audit(&mut rx);
        assert!(
            !events
                .iter()
                .any(|e| e["metadata"]["reason"] == "policy-changed"),
            "a v6 approval's own rule must not read as a revocation; got {events:#?}"
        );
    }

    #[tokio::test]
    async fn a_narrowing_reload_still_refuses_the_approved_splice() {
        // The re-check admits only what the fresh table allows: a reload that
        // keeps the destination claimed but narrows the grant to another caller
        // leaves this connection unauthorized, so consent stays void.
        let (state, mut rx) = test_state();
        install_tcp_rules(
            &state,
            r#"[{"match": "203.0.113.0/24:5432", "verdict": "ask"}]"#,
        );

        raw_passthrough_answering(
            &state,
            &mut rx,
            "203.0.113.9:5432".parse().unwrap(),
            crate::protocol::Decision::AllowAlways,
            || {
                reload_tcp_rules(
                    &state,
                    r#"[{"match": "203.0.113.9:5432", "verdict": "allow",
                          "binaries": ["/usr/bin/psql"]}]"#,
                )
            },
        )
        .await;

        let events = drain_audit(&mut rx);
        assert!(
            events
                .iter()
                .any(|e| e["metadata"]["reason"] == "policy-changed"),
            "a grant that no longer covers this caller must refuse; got {events:#?}"
        );
    }

    #[tokio::test]
    async fn the_card_for_an_unclassified_connection_names_the_address_and_port() {
        // Postgres and SSH are not HTTP, so the classifier reports neither TLS nor
        // HTTP and no `egress.http` rule can apply. Dropping the connection left
        // the developer with no way to allow it but to hand-write a rule; the
        // question is raised on its own now, and an approval writes the
        // destination it was shown — which a raw rule needs a port for.
        let (state, mut rx) = test_state();
        let dst: SocketAddr = "203.0.113.7:4444".parse().unwrap();
        let decision = unclassified_splice_decision(&state, dst).expect("the default asks");
        assert_eq!(decision.verdict, Verdict::Ask);

        let (_client, server) = socket_pair().await;
        let state_for_handler = state.clone();
        tokio::spawn(async move {
            handle_raw_passthrough(server, dst, &decision, &state_for_handler, &test_actor()).await
        });

        let pending = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("a dialog must be raised")
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&pending).unwrap();
        assert_eq!(parsed["action"], "CONNECT 203.0.113.7:4444");
        assert_eq!(parsed["host"], "203.0.113.7");
        assert_eq!(parsed["treatment"], "raw");
        assert_eq!(parsed["reason"], "unknown-protocol");
    }

    #[test]
    fn dns_over_tcp_is_dropped_rather_than_offered_as_a_splice() {
        // The stub filters every lookup because a QNAME carries data out whether
        // or not a connection to that name is permitted — and it is UDP-only, so
        // DNS over TCP is blocked by this branch dropping it. A card here would
        // offer to reopen that channel, and no wording on it could convey what
        // approving means.
        let (state, _rx) = test_state();
        for dst in ["192.168.64.1:53", "1.1.1.1:53", "[2001:db8::1]:53"] {
            assert!(
                unclassified_splice_decision(&state, dst.parse().unwrap()).is_none(),
                "{dst} must be dropped, not asked about"
            );
        }
        // The neighbouring port is ordinary traffic and still asks.
        assert!(unclassified_splice_decision(&state, "192.168.64.1:54".parse().unwrap()).is_some());
    }

    #[test]
    fn a_deny_default_drops_an_unclassified_connection_rather_than_asking() {
        // `defaultVerdict: deny` is an answer already given — block what no rule
        // names, and do not ask. Raising a card would overrule it and prompt the
        // one operator who said they never wanted prompting.
        let (state, _rx) = test_state();
        state.policy.write().unwrap().default_verdict = Verdict::Deny;
        assert!(
            unclassified_splice_decision(&state, "203.0.113.7:4444".parse().unwrap()).is_none()
        );
    }

    #[test]
    fn every_other_default_asks_about_an_unclassified_connection() {
        // `allow` asks too: a default is not consent to splice a connection
        // nothing can inspect, and this door dropped it until now — so the answer
        // moves from dropped to a question, never straight to spliced.
        for default in [Verdict::Ask, Verdict::Allow] {
            let (state, _rx) = test_state();
            state.policy.write().unwrap().default_verdict = default;
            let decision =
                unclassified_splice_decision(&state, "203.0.113.7:4444".parse().unwrap())
                    .unwrap_or_else(|| panic!("{default:?} must raise a question"));
            assert_eq!(decision.verdict, Verdict::Ask);
        }
    }

    #[tokio::test]
    async fn the_destination_floor_beats_the_card_for_an_unclassified_connection() {
        // Asking about an undeclared destination is only safe while the hard floor
        // runs first: a metadata or link-local address reaches the host itself
        // past the cage, so it must never be offered to a human to approve.
        let (state, mut rx) = test_state();
        let dst: SocketAddr = "169.254.169.254:80".parse().unwrap();
        let decision = unclassified_splice_decision(&state, dst).expect("the default asks");

        let (_client, server) = socket_pair().await;
        handle_raw_passthrough(server, dst, &decision, &state, &test_actor())
            .await
            .unwrap();

        let events = drain_audit(&mut rx);
        assert!(
            events
                .iter()
                .any(|e| e["metadata"]["reason"] == "blocked-destination"),
            "the floor must refuse it; got {events:#?}"
        );
        assert!(
            !events.iter().any(|e| e["type"] == "request_pending"),
            "no dialog may be raised for a blocked destination; got {events:#?}"
        );
    }

    #[tokio::test]
    async fn an_approved_ask_still_splices_when_the_policy_has_not_moved() {
        // The rule stays `ask` after the click — an approval is not written back
        // into the table. A re-check that simply re-asks the table would refuse
        // every connection the developer just allowed.
        let (state, mut rx) = test_state();
        install_tcp_rules(
            &state,
            r#"[{"match": "203.0.113.0/24:5432", "verdict": "ask"}]"#,
        );

        raw_passthrough_answering(
            &state,
            &mut rx,
            "203.0.113.9:5432".parse().unwrap(),
            crate::protocol::Decision::AllowAlways,
            || {},
        )
        .await;

        let events = drain_audit(&mut rx);
        assert!(
            !events
                .iter()
                .any(|e| e["metadata"]["reason"] == "policy-deny"),
            "an approval under an unchanged policy must be honored; got {events:#?}"
        );
    }

    #[tokio::test]
    async fn a_gate_denied_raw_connection_audits_the_address_it_was_reaching() {
        // The dialog names the pinned hostname, because that is the rule the
        // author wrote. The trail must still name the address: several names can
        // pin to one address and `matching_name` takes the first, so the name
        // alone attributes a denied attempt to an arbitrary one of them.
        let (state, mut rx) = test_state();
        install_tcp_rules(
            &state,
            r#"[{"match": "db.internal:5432", "verdict": "ask"}]"#,
        );
        pin_dns_answers(
            &state,
            &["203.0.113.9".parse().unwrap()],
            "db.internal",
            300,
            0,
        );

        raw_passthrough_answering(
            &state,
            &mut rx,
            "203.0.113.9:5432".parse().unwrap(),
            crate::protocol::Decision::DenyOnce,
            || {},
        )
        .await;

        let events = drain_audit(&mut rx);
        assert!(
            events
                .iter()
                .any(|e| e["action"] == "CONNECT db.internal:5432"
                    && e["metadata"]["reason"] == "user-denied-once"),
            "the gate event must stay correlated with the prompt; got {events:#?}"
        );
        assert!(
            events
                .iter()
                .any(|e| e["action"] == "CONNECT 203.0.113.9:5432" && e["result"] == "failure"),
            "the denied attempt must record the address; got {events:#?}"
        );
    }

    #[test]
    fn a_cidr_rule_names_no_host_even_when_the_address_is_pinned() {
        // The dialog must fall back to the address. Surfacing the pin here
        // "for consistency" would ask about — and then record as approved — a
        // name the policy author never wrote a rule about.
        let (state, _rx) = test_state();
        install_tcp_rules(
            &state,
            r#"[{"match": "203.0.113.0/24:5432", "verdict": "ask"}]"#,
        );
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        pin_dns_answers(&state, &[ip], "db.internal", 300, 0);

        let decision = tcp_egress_verdict_for_hostport(&state, "203.0.113.9:5432", 0, None)
            .expect("the cidr rule must claim this address");
        assert_eq!(decision.verdict, Verdict::Ask);
        assert_eq!(decision.matched_target, None);
    }

    #[test]
    fn the_raw_forward_head_forces_one_request_per_connection() {
        let header = "GET http://api.example.com/x HTTP/1.1\r\n\
                      Host: api.example.com\r\n\
                      Proxy-Authorization: Basic c2VjcmV0\r\n\
                      Connection: keep-alive\r\n";

        let raw =
            rewrite_http_forward_request(header, "/x", "api.example.com:80", Reuse::OneRequestOnly);
        assert!(raw.contains("Connection: close"), "got {raw:?}");
        assert!(!raw.to_lowercase().contains("keep-alive"), "got {raw:?}");
        assert!(
            !raw.to_lowercase().contains("proxy-authorization"),
            "the strip must not be undone by a reused connection; got {raw:?}"
        );

        // The inspected path judges every request on the connection, so reuse
        // stays the client's call there.
        let inspected =
            rewrite_http_forward_request(header, "/x", "api.example.com:80", Reuse::AsClientSent);
        assert!(
            inspected.contains("Connection: keep-alive"),
            "got {inspected:?}"
        );
    }

    #[tokio::test]
    async fn a_tcp_allow_splices_raw_on_the_http_forward_door() {
        // Same pre-filter rule as the CONNECT door. The destination is
        // unresolvable, so 502 (the splice tried to dial) distinguishes the raw
        // path from the l7 default deny, which would answer 403 without dialing.
        let (state, _rx) = test_state();
        state.policy.write().unwrap().default_verdict = Verdict::Deny;
        install_tcp_rules(
            &state,
            r#"[{"match": "nonexistent.invalid:80", "verdict": "allow"}]"#,
        );

        let (mut client, server) = socket_pair().await;
        let state_for_handler = state.clone();
        tokio::spawn(async move {
            let actor = test_actor();
            let headers =
                b"GET http://nonexistent.invalid/ HTTP/1.1\r\nHost: nonexistent.invalid\r\n\r\n"
                    .to_vec();
            handle_http_forward(
                server,
                "nonexistent.invalid:80",
                headers,
                &state_for_handler,
                &actor,
            )
            .await
        });

        let response = read_response(&mut client).await;
        assert!(
            response.starts_with("HTTP/1.1 502"),
            "a tcp allow must take the raw path, not the l7 table; got {response:?}"
        );
    }

    #[tokio::test]
    async fn connect_to_a_pinned_ip_still_hits_the_hostname_tcp_deny() {
        // A port-scoped deny alongside an allow on another port: the name still
        // resolves (the :443 allow survives the DNS gate) and pins its IP. The
        // transparent door then catches a :5432 connect through that pin, so the
        // proxy door must too — otherwise the workload just resolves the name
        // and reconnects to the bare IP.
        let (state, _rx) = test_state();
        install_catch_all_allow(&state);
        install_tcp_rules(
            &state,
            r#"[{"match": "db.internal:5432", "verdict": "deny"},
                {"match": "db.internal:443",  "verdict": "allow"}]"#,
        );
        let ip: IpAddr = "203.0.113.80".parse().unwrap();
        pin_dns_answers(&state, &[ip], "db.internal", 300, 0);

        // The transparent door already refuses it.
        assert_eq!(
            tcp_verdict(&state, "203.0.113.80:5432", None),
            Some(Verdict::Deny)
        );

        let (mut client, server) = socket_pair().await;
        let state_for_handler = state.clone();
        tokio::spawn(async move {
            let actor = test_actor();
            handle_connect(server, "203.0.113.80:5432", &actor, &state_for_handler).await
        });

        let response = read_response(&mut client).await;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "a pinned name's deny must bind on the proxy door too; got {response:?}"
        );
    }

    #[tokio::test]
    async fn connect_to_a_mapped_pinned_ip_still_hits_the_hostname_tcp_deny() {
        // Pins are keyed by the A record's IPv4 address, so the mapped spelling
        // of the same host must canonicalize before the lookup or the pins come
        // back empty and the hostname deny is evaded by spelling alone.
        let (state, _rx) = test_state();
        install_catch_all_allow(&state);
        install_tcp_rules(
            &state,
            r#"[{"match": "db.internal:5432", "verdict": "deny"},
                {"match": "db.internal:443",  "verdict": "allow"}]"#,
        );
        let ip: IpAddr = "203.0.113.80".parse().unwrap();
        pin_dns_answers(&state, &[ip], "db.internal", 300, 0);

        let (mut client, server) = socket_pair().await;
        let state_for_handler = state.clone();
        tokio::spawn(async move {
            let actor = test_actor();
            handle_connect(
                server,
                "[::ffff:203.0.113.80]:5432",
                &actor,
                &state_for_handler,
            )
            .await
        });

        let response = read_response(&mut client).await;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "the mapped spelling must reach the same pins; got {response:?}"
        );
    }

    #[tokio::test]
    async fn a_tcp_allow_splices_raw_on_the_proxy_door() {
        // The tcp table is the pre-filter: what it claims, it governs. A default
        // deny in the l7 table is not consulted for a destination a tcp allow
        // already claimed, exactly as on the transparent door.
        //
        // The destination is unresolvable, so the splice reports 502 rather than
        // opening. That is the assertion: the l7 default deny would have answered
        // 403 without ever dialing.
        let (state, _rx) = test_state();
        state.policy.write().unwrap().default_verdict = Verdict::Deny;
        install_tcp_rules(
            &state,
            r#"[{"match": "nonexistent.invalid:22", "verdict": "allow"}]"#,
        );

        let (mut client, server) = socket_pair().await;
        let state_for_handler = state.clone();
        tokio::spawn(async move {
            let actor = test_actor();
            handle_connect(server, "nonexistent.invalid:22", &actor, &state_for_handler).await
        });

        let response = read_response(&mut client).await;
        assert!(
            response.starts_with("HTTP/1.1 502"),
            "a tcp allow must take the raw path, not the l7 table; got {response:?}"
        );
    }

    #[tokio::test]
    async fn a_tcp_ask_gates_before_splicing_on_the_proxy_door() {
        // `ask` reaches the developer on this door too; a refusal is a 403, not
        // a fall-through to the l7 table.
        let (state, mut rx) = test_state();
        install_catch_all_allow(&state);
        install_tcp_rules(&state, r#"[{"match": "10.0.0.0/8:22", "verdict": "ask"}]"#);

        let (mut client, server) = socket_pair().await;
        let state_for_handler = state.clone();
        let handler = tokio::spawn(async move {
            let actor = test_actor();
            handle_connect(server, "10.0.0.5:22", &actor, &state_for_handler).await
        });

        let pending = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("request_pending arrived")
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&pending).unwrap();
        assert_eq!(parsed["type"], "request_pending");
        let id = parsed["id"].as_str().unwrap().to_string();
        assert!(crate::gate::resolve_pending(
            &state,
            &id,
            crate::protocol::Decision::DenyOnce,
        ));

        let response = read_response(&mut client).await;
        let _ = handler.await;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "a refused gate must deny the splice; got {response:?}"
        );
    }

    #[tokio::test]
    async fn an_approved_ask_still_splices_on_the_proxy_door() {
        // The allow side of the test above. An approval is not written back into
        // the table, so the rule is still `ask` when the dial re-reads it — a
        // guard that simply refuses every `ask` refuses every connection the
        // developer just allowed, and `ask` becomes unusable on this door.
        let (state, mut rx) = test_state();
        install_catch_all_allow(&state);
        install_tcp_rules(
            &state,
            r#"[{"match": "203.0.113.0/24:5432", "verdict": "ask"}]"#,
        );

        let (_client, server) = socket_pair().await;
        let state_for_handler = state.clone();
        let handler = tokio::spawn(async move {
            let actor = test_actor();
            handle_connect(server, "203.0.113.9:5432", &actor, &state_for_handler).await
        });

        let pending = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("request_pending arrived")
            .unwrap();
        let id = serde_json::from_str::<serde_json::Value>(&pending).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(crate::gate::resolve_pending(
            &state,
            &id,
            crate::protocol::Decision::AllowAlways,
        ));

        // Reaching the dial is the whole assertion, and what TEST-NET-3 does
        // with a SYN is the platform's business — refused on one, swallowed on
        // the next. So a handler still parked in `connect` has already made the
        // point; only the guard's own refusal fails, and it names itself.
        let outcome = match tokio::time::timeout(Duration::from_secs(2), handler).await {
            Ok(joined) => format!("{:?}", joined.expect("handler must not panic")),
            Err(_) => String::new(),
        };
        assert!(
            !outcome.contains("denied by policy"),
            "the approved ask must reach the dial, not be refused by it; got {outcome}"
        );
    }

    #[tokio::test]
    async fn an_allow_carries_no_developer_answer_into_the_dial() {
        // The dial guard relaxes only for an `ask`, because that is the one
        // verdict a developer actually answered. An `allow` answered nothing,
        // so a CIDR `ask` waiting on the resolved address is still unseen and
        // must refuse — treating every raw door as "gated" would reopen exactly
        // that hole. The `ask` half is
        // `an_approved_ask_still_splices_on_the_proxy_door`, which needs a
        // live gate.
        let (state, _rx) = test_state();
        let at = |verdict| RawDecision {
            verdict,
            matched_target: None,
            generation: state.policy.read().unwrap().generation,
            reason: "policy-ambiguous",
            caller_scoped: false,
        };
        let actor = test_actor();
        assert_eq!(
            raw_verdict_admits(&state, "10.0.0.5:5432", &at(Verdict::Allow), &actor).await,
            Some(Gated::NotAsked)
        );
        assert_eq!(
            raw_verdict_admits(&state, "10.0.0.5:5432", &at(Verdict::Deny), &actor).await,
            None
        );
    }

    #[tokio::test]
    async fn connect_egress_under_policy_refuses_a_post_resolution_ask() {
        // No gate can run inside the dial, and admitting would let this door
        // skip a decision the transparent door asks a human for — the workload
        // chooses the door, so the permissive answer must not be reachable.
        let (state, _rx) = test_state();
        install_tcp_rules(
            &state,
            r#"[{"match": "10.0.0.0/8:5432", "verdict": "ask"}]"#,
        );
        let dial =
            connect_egress_under_policy(&state, "10.0.0.5:5432", 5432, None, Gated::NotAsked);
        let err = tokio::time::timeout(Duration::from_secs(2), dial)
            .await
            .expect("policy must refuse before dialing")
            .expect_err("an ask that cannot be gated must not admit");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn connect_egress_under_policy_applies_an_ipv6_cidr_deny() {
        // The post-resolution re-check has to survive the round trip through an
        // `ip:port` string, which for IPv6 only parses back when bracketed.
        let (state, _rx) = test_state();
        install_tcp_rules(
            &state,
            r#"[{"match": "[2001:db8::/32]:443", "verdict": "deny"}]"#,
        );
        let dial =
            connect_egress_under_policy(&state, "[2001:db8::1]:443", 443, None, Gated::NotAsked);
        let err = tokio::time::timeout(Duration::from_secs(2), dial)
            .await
            .expect("policy must refuse before dialing")
            .expect_err("the v6 CIDR deny must apply");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn connect_fails_closed_when_a_binary_scoped_rule_excludes_the_caller() {
        // The same fail-closed rule `tcp_egress_verdict` applies must hold on
        // the door the workload is actually pointed at by HTTPS_PROXY.
        let (state, _rx) = test_state();
        install_catch_all_allow(&state);
        install_tcp_rules(
            &state,
            r#"[{"match": "10.0.0.0/8:22", "verdict": "deny",
                 "binaries": ["/usr/bin/curl"]}]"#,
        );

        let (mut client, server) = socket_pair().await;
        let state_for_handler = state.clone();
        tokio::spawn(async move {
            // `test_actor` resolves no process off a Linux guest, so this is the
            // unresolvable-caller case.
            let actor = test_actor();
            handle_connect(server, "10.0.0.5:22", &actor, &state_for_handler).await
        });

        let response = read_response(&mut client).await;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "a binary-excluded caller must not fall through to the l7 allow; got {response:?}"
        );
    }

    #[tokio::test]
    async fn connect_reaches_the_l7_table_when_no_tcp_rule_claims_the_destination() {
        // The tcp rule covers a different host, so it claims nothing here and
        // the l7 table governs in full — an `ask` route still suspends.
        let (state, mut rx) = test_state();
        install_ask_route(&state, "evil.example.com");
        install_tcp_deny(&state, "10.0.0.0/8:22");

        let (_client, server) = socket_pair().await;
        let state_for_handler = state.clone();
        tokio::spawn(async move {
            let actor = test_actor();
            handle_connect(server, "evil.example.com:443", &actor, &state_for_handler).await
        });

        let pending = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("the L7 ask path must still run")
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&pending).unwrap();
        assert_eq!(parsed["type"], "request_pending");
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
        assert_eq!(parsed["treatment"], "inspected");
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
        state.policy.write().unwrap().default_verdict = Verdict::Ask;
        state.policy.write().unwrap().default_transport = Transport::Direct;

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
            let actor = test_actor();
            handle_http_forward(
                server,
                "api.evil.example.com",
                header_bytes,
                &state_for_handler,
                &actor,
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
        let result = rewrite_http_forward_request(
            header,
            "/api/data",
            "example.com:8080",
            Reuse::AsClientSent,
        );
        assert!(result.starts_with("GET /api/data HTTP/1.1\r\n"));
        assert!(result.contains("Host: example.com:8080"));
    }

    #[test]
    fn rewrite_overwrites_host_header() {
        // Host header should always match target_host, even if the original differs
        let header = "POST http://svc.local/path HTTP/1.1\r\nHost: wrong-host\r\nContent-Type: application/json\r\n";
        let result =
            rewrite_http_forward_request(header, "/path", "svc.local:80", Reuse::AsClientSent);
        assert!(result.contains("Content-Type: application/json"));
        assert!(result.contains("Host: svc.local:80"));
        assert!(!result.contains("Host: wrong-host"));
    }

    #[test]
    fn rewrite_strips_proxy_headers() {
        let header = "GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic abc\r\nProxy-Connection: keep-alive\r\nAccept: */*\r\n";
        let result =
            rewrite_http_forward_request(header, "/path", "example.com:80", Reuse::AsClientSent);
        assert!(!result.contains("Proxy-Authorization"));
        assert!(!result.contains("Proxy-Connection"));
        assert!(result.contains("Accept: */*"));
    }

    #[test]
    fn rewrite_root_path() {
        let header = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n";
        let result =
            rewrite_http_forward_request(header, "/", "example.com:80", Reuse::AsClientSent);
        assert!(result.starts_with("GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn rewrite_inserts_host_header_when_missing() {
        let header = "GET http://example.com:9090/path HTTP/1.1\r\nAccept: */*\r\n";
        let result =
            rewrite_http_forward_request(header, "/path", "example.com:9090", Reuse::AsClientSent);
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
