use std::collections::HashMap;
use std::io;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderValue, Uri};
use tokio_tungstenite::tungstenite::protocol::Message;

use crate::activity::ActivityStream;
use crate::config::{CoreConfig, SandboxMode};
use crate::connector;
use crate::gate;
use crate::protocol::{CredentialDecision, MessagePeek, RequestDecision};
use crate::proxy::ProxyState;
use crate::routing::parse_proxy_routes;

const DEFAULT_WATCH_WAIT_MS: u64 = 5_000;

/// Factory that creates per-session handlers.
pub trait SandboxDispatcher: Send + Sync + 'static {
    fn new_session(&self) -> Box<dyn SessionHandler>;
}

/// Handles messages for a single WebSocket session.
#[async_trait]
pub trait SessionHandler: Send + Sync {
    /// Returns the session's activity stream for watch mode support.
    fn activity(&self) -> &ActivityStream;

    /// Dispatch a message the core client didn't handle (not policy, not watch).
    /// raw_text is the original JSON. tx sends serialized JSON string responses.
    async fn dispatch(&self, raw_text: &str, tx: &mpsc::UnboundedSender<String>);

    /// Called after a policy message is applied (proxy upstream, routes, CA cert).
    /// `env` contains project-level environment variables from Lens Sandbox.
    /// Default is a no-op.
    async fn on_policy(&self, _env: HashMap<String, String>) {}

    /// Cleanup on session end (kill processes, abort tasks).
    async fn shutdown(&self);
}

pub async fn run(
    config: &CoreConfig,
    proxy_state: &Option<Arc<ProxyState>>,
    dispatcher: &dyn SandboxDispatcher,
) {
    let (ws_url, token) = match &config.mode {
        SandboxMode::Server { ws_url, token } => (ws_url.as_str(), token.as_str()),
        SandboxMode::Standalone { .. } => panic!("client::run() requires server mode"),
    };

    let mut reconnect_delay = Duration::from_secs(5);
    let max_delay = Duration::from_secs(60);
    let last_activity = Arc::new(Mutex::new(Instant::now()));

    // Idle timeout checker — only spawned when the caller explicitly enabled
    // the timer via IDLE_TIMEOUT_MS. The library default is "stay running" so
    // managed-lifecycle sandboxes (agent) don't self-terminate; the
    // shell-sandbox provisioner opts in by setting the env var.
    if let Some(idle_timeout) = config.idle_timeout {
        let last_activity_idle = last_activity.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let last = *last_activity_idle.lock().await;
                if last.elapsed() >= idle_timeout {
                    tracing::info!("Idle for {}s, shutting down", idle_timeout.as_secs());
                    std::process::exit(0);
                }
            }
        });
    }

    loop {
        let session = dispatcher.new_session();
        match connect_and_run(ws_url, token, &last_activity, proxy_state, session).await {
            ConnectionResult::Rejected => {
                tracing::error!("Connection rejected before handshake, exiting");
                std::process::exit(1);
            }
            ConnectionResult::VersionMismatch => {
                // Detailed mismatch already logged by handle_policy
                std::process::exit(1);
            }
            ConnectionResult::Disconnected(code) => {
                tracing::info!(code = ?code, "Disconnected");
                let jitter = rand::random_range(0u64..1000);
                let delay = reconnect_delay.min(max_delay) + Duration::from_millis(jitter);
                tracing::info!("Reconnecting in {}ms...", delay.as_millis());
                tokio::time::sleep(delay).await;
                reconnect_delay = (reconnect_delay * 2).min(max_delay);
            }
            ConnectionResult::Connected => {
                reconnect_delay = Duration::from_secs(5);
            }
        }
    }
}

#[allow(dead_code)]
pub enum ConnectionResult {
    Connected,
    Rejected,
    Disconnected(Option<u16>),
    VersionMismatch,
}

async fn connect_and_run(
    ws_url: &str,
    token: &str,
    last_activity: &Arc<Mutex<Instant>>,
    proxy_state: &Option<Arc<ProxyState>>,
    session: Box<dyn SessionHandler>,
) -> ConnectionResult {
    tracing::info!("Connecting to Lens Sandbox: {}", ws_url);

    // Parse the URL up front so we can dispatch on scheme. `http::Uri`
    // accepts any scheme; the scheme check below is ours and is more
    // useful than tungstenite's "ws/wss only" rejection because it
    // covers vsock:// too.
    let uri = match Uri::from_str(ws_url) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("Invalid URL: {e}");
            return ConnectionResult::Rejected;
        }
    };
    // RFC 3986 §3.1: scheme is case-insensitive. Normalise once here so
    // every downstream comparison (the `vsock` branch below, `for_scheme`,
    // `bootstrap_dns_hosts`) sees the same lower-cased value.
    let scheme = uri.scheme_str().unwrap_or("").to_ascii_lowercase();
    let connector = match connector::for_scheme(&scheme) {
        Some(c) => c,
        None => {
            tracing::error!("Unsupported URL scheme: {scheme:?}");
            return ConnectionResult::Rejected;
        }
    };

    // Tungstenite's `IntoClientRequest` only accepts ws:// / wss:// — for
    // vsock we hand it a ws:// stand-in with the same authority + path.
    // The actual bytes travel over whatever stream the connector returns;
    // the URL just populates the handshake's Host + Request-URI lines.
    // A missing authority is a configuration bug, not a transient I/O
    // failure — reject up front so the reconnect loop doesn't spin.
    let handshake_url = if scheme == "vsock" {
        let Some(auth) = uri.authority().map(|a| a.as_str()) else {
            tracing::error!("vsock URL missing CID:PORT authority: {ws_url}");
            return ConnectionResult::Rejected;
        };
        let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        format!("ws://{auth}{pq}")
    } else {
        ws_url.to_string()
    };
    let mut request = match handshake_url.into_client_request() {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Invalid WebSocket URL: {e}");
            return ConnectionResult::Rejected;
        }
    };

    let auth_value = match HeaderValue::from_str(&format!("Bearer {token}")) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Invalid token for header: {e}");
            return ConnectionResult::Rejected;
        }
    };
    request.headers_mut().insert("Authorization", auth_value);

    // Open the byte transport. For ws:// / wss:// this is a DNS-resolved,
    // SO_MARK'd TCP socket (same iptables-bypass dance as before the seam
    // existed); for vsock:// it's a direct AF_VSOCK connection.
    // `InvalidInput` means the URL itself is malformed (no host, missing
    // vsock port, unknown CID alias) — Reject instead of retrying.
    let stream = match connector.connect(&uri).await {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::InvalidInput => {
            tracing::error!("Transport rejected URL: {e}");
            return ConnectionResult::Rejected;
        }
        Err(e) => {
            tracing::warn!("Transport connect failed (will retry): {e}");
            return ConnectionResult::Disconnected(None);
        }
    };

    // `client_async_tls_with_config` is TLS-on-demand: it only wraps the
    // stream in TLS when the request URI is wss://. ws:// and our
    // ws://-rewritten vsock URLs go through it as plain MaybeTlsStream,
    // so the wss production path is bit-for-bit identical to pre-seam.
    let ws_stream =
        match tokio_tungstenite::client_async_tls_with_config(request, stream, None, None).await {
            Ok((stream, _response)) => stream,
            Err(e) => {
                let is_auth_rejection = matches!(
                    &e,
                    tokio_tungstenite::tungstenite::Error::Http(response)
                        if response.status() == 401 || response.status() == 403
                );
                if is_auth_rejection {
                    tracing::error!("WebSocket connection rejected (auth): {e}");
                    return ConnectionResult::Rejected;
                }
                tracing::warn!("WebSocket connection failed (will retry): {e}");
                return ConnectionResult::Disconnected(None);
            }
        };

    tracing::info!("Connected to Lens Sandbox");

    let (mut write, mut read) = ws_stream.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    // Wire audit sender so the proxy can emit audit events back to Lens Sandbox
    if let Some(state) = proxy_state {
        *state.audit_tx.lock().unwrap() = Some(tx.clone());
    }

    let writer_task = tokio::spawn(async move {
        while let Some(text) = rx.recv().await {
            if write.send(Message::Text(text.into())).await.is_err() {
                break;
            }
        }
    });

    let mut close_code = None;

    while let Some(msg_result) = read.next().await {
        match msg_result {
            Ok(Message::Text(text)) => {
                // Peek at the type field to decide core vs delegate
                let msg_type = match serde_json::from_str::<MessagePeek>(&text) {
                    Ok(peek) => peek.msg_type,
                    Err(e) => {
                        tracing::error!("Failed to parse message: {e}");
                        tracing::debug!("Raw message: {text}");
                        continue;
                    }
                };

                match msg_type.as_str() {
                    "policy" => match handle_policy(&text, proxy_state).await {
                        // Policy messages (initial policy on connect + periodic
                        // credential refresh) are deliberately NOT counted as activity
                        // so idle sandboxes still hit the shutdown timer.
                        PolicyResult::Ok(env) => session.on_policy(env).await,
                        PolicyResult::VersionMismatch { server_min, client } => {
                            tracing::error!(
                                %server_min, %client,
                                "sandbox protocol too old — exiting for recycle"
                            );
                            session.shutdown().await;
                            drop(tx);
                            writer_task.abort();
                            clear_audit_tx(proxy_state);
                            return ConnectionResult::VersionMismatch;
                        }
                    },
                    "watch" => {
                        *last_activity.lock().await = Instant::now();
                        let activity = session.activity().clone();
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            handle_watch(&tx, &activity, &text).await;
                        });
                    }
                    "request_decision" => {
                        if let Some(state) = proxy_state {
                            handle_request_decision(state, &text);
                        } else {
                            tracing::warn!("request_decision received without proxy state");
                        }
                    }
                    "credential_decision" => {
                        if let Some(state) = proxy_state {
                            handle_credential_decision(state, &text);
                        } else {
                            tracing::warn!("credential_decision received without proxy state");
                        }
                    }
                    _ => {
                        *last_activity.lock().await = Instant::now();
                        session.dispatch(&text, &tx).await;
                    }
                }
            }
            Ok(Message::Close(frame)) => {
                close_code = frame.map(|f| f.code.into());
                break;
            }
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {}
            Ok(_) => {}
            Err(e) => {
                tracing::error!("WebSocket error: {e}");
                break;
            }
        }
    }

    session.shutdown().await;
    drop(tx);
    writer_task.abort();
    clear_audit_tx(proxy_state);

    ConnectionResult::Disconnected(close_code)
}

/// Drop the audit-channel sender clone held in `ProxyState` so the next
/// gate call sees an unwired channel and fails closed immediately. The
/// sender clone outlives the writer task (which owned the matching
/// receiver), and without this clear it would keep `audit_tx.is_some()`
/// while every `send()` errors silently — parking gate requests for the
/// full `DECISION_TIMEOUT` until the next reconnect overwrites it.
fn clear_audit_tx(proxy_state: &Option<Arc<ProxyState>>) {
    if let Some(state) = proxy_state {
        *state.audit_tx.lock().unwrap() = None;
    }
}

/// Rewrite proxy env vars in incoming messages to point at the local proxy.
/// Ensure proxy env vars point at the local proxy in every message.
/// If the message has no env map, create one. Always sets HTTPS_PROXY/HTTP_PROXY
/// so child processes route through the local proxy regardless of what Lens Sandbox sent.
pub fn rewrite_proxy_env(env: &mut Option<HashMap<String, String>>, proxy_addr: &str) {
    let env_map = env.get_or_insert_with(HashMap::new);

    // Set both HTTPS_PROXY and HTTP_PROXY — the sandbox proxy handles both
    // CONNECT tunnels (HTTPS) and HTTP forward proxy requests (plain HTTP).
    let local_proxy = format!("http://{proxy_addr}");
    for key in &["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
        env_map.insert(key.to_string(), local_proxy.clone());
    }
    env_map.remove("NO_PROXY");
    env_map.remove("no_proxy");
}

/// Bridge a typed message channel to the core's `String` WebSocket sender.
/// Spawns a task that serializes each outgoing message to JSON.
pub fn bridge_tx<T: serde::Serialize + Send + 'static>(
    core_tx: &mpsc::UnboundedSender<String>,
) -> mpsc::UnboundedSender<T> {
    let (msg_tx, mut msg_rx) = mpsc::unbounded_channel::<T>();
    let core_tx = core_tx.clone();
    tokio::spawn(async move {
        while let Some(msg) = msg_rx.recv().await {
            match serde_json::to_string(&msg) {
                Ok(text) => {
                    if core_tx.send(text).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to serialize outgoing message: {e}");
                }
            }
        }
    });
    msg_tx
}

/// Parse a `request_decision` frame and resolve the matching gate entry.
/// No reply is sent back: the held request waits on the gate's watch
/// channel and resumes itself once the decision lands.
fn handle_request_decision(state: &Arc<ProxyState>, raw_text: &str) {
    let parsed: RequestDecision = match serde_json::from_str(raw_text) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("failed to parse request_decision: {e}");
            return;
        }
    };
    if !gate::resolve_pending(state, &parsed.id, parsed.decision) {
        tracing::warn!(id = %parsed.id, "request_decision had no matching pending entry");
    }
}

/// Parse a `credential_decision` frame and resolve the matching credential
/// gate entry. Mirror of [`handle_request_decision`] — on `Allow`, the held
/// request waits for the follow-up `policy` frame that arms
/// `Credential.injections` for the credential before forwarding; on
/// `Deny` / `Timeout` the held request fails closed.
fn handle_credential_decision(state: &Arc<ProxyState>, raw_text: &str) {
    let parsed: CredentialDecision = match serde_json::from_str(raw_text) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("failed to parse credential_decision: {e}");
            return;
        }
    };
    if !gate::resolve_credential_pending(state, &parsed.id, parsed.decision) {
        tracing::warn!(
            id = %parsed.id,
            "credential_decision had no matching pending entry"
        );
    }
}

/// Handle a watch request: subscribe to the activity stream, collect events until
/// the deadline, and send back a watch_result with the accumulated output.
async fn handle_watch(
    tx: &mpsc::UnboundedSender<String>,
    activity: &ActivityStream,
    raw_text: &str,
) {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct WatchMessage {
        id: String,
        #[serde(default)]
        wait_ms: Option<u64>,
    }

    let msg: WatchMessage = match serde_json::from_str(raw_text) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("Failed to parse watch message: {e}");
            return;
        }
    };

    let mut rx = activity.subscribe();
    let deadline = tokio::time::Instant::now()
        + Duration::from_millis(msg.wait_ms.unwrap_or(DEFAULT_WATCH_WAIT_MS));
    let mut output = String::new();
    const MAX_WATCH_OUTPUT: usize = 256 * 1024; // 256 KB cap

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        if output.len() >= MAX_WATCH_OUTPUT {
            output.push_str("\x1b[90m[...output truncated...]\x1b[0m\n");
            break;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(event)) => {
                output.push_str(&event.summary);
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(n))) => {
                output.push_str(&format!("\x1b[90m[...{n} events skipped...]\x1b[0m\n"));
            }
            Ok(Err(_)) | Err(_) => break,
        }
    }

    let result = serde_json::json!({
        "type": "watch_result",
        "id": msg.id,
        "output": output,
    });
    let _ = tx.send(result.to_string());
}

enum PolicyResult {
    Ok(HashMap<String, String>),
    VersionMismatch { server_min: String, client: String },
}

/// Per-credential state that injections mutate. Keeps `apply_injection`
/// free of the orchestration noise and makes testing individual injection
/// kinds easier.
struct CredentialApply<'a> {
    injection_map: &'a mut HashMap<String, Vec<crate::proxy::CredentialInjection>>,
    uri_placeholder_map: &'a mut HashMap<String, Vec<(String, String)>>,
    aws_config_map: &'a mut HashMap<String, crate::aws_sigv4::AwsSigv4Config>,
    aws_domains: &'a mut Vec<String>,
    header_count: &'a mut usize,
}

/// Route a single [`CredentialInjection`] variant to the matching runtime
/// state map. The compiler enforces that every variant is handled — adding
/// a new `InjectionType` will surface here as a missing match arm.
fn apply_injection(
    cred_id: &str,
    cred_placeholder: Option<&str>,
    inj: &crate::policy_schema::CredentialInjection,
    state: &mut CredentialApply<'_>,
) {
    match inj {
        crate::policy_schema::CredentialInjection::Header {
            domain,
            header,
            value,
            rules,
        } => {
            state
                .injection_map
                .entry(domain.to_lowercase())
                .or_default()
                .push(crate::proxy::CredentialInjection {
                    header: header.clone(),
                    value: value.clone(),
                    rules: rules.clone(),
                });
            *state.header_count += 1;
        }
        crate::policy_schema::CredentialInjection::UriPlaceholder { domain, value, .. } => {
            let domain = domain.to_lowercase();
            let Some(placeholder) = cred_placeholder else {
                tracing::error!(
                    cred_id,
                    domain = %domain,
                    "dropping uriPlaceholder injection: parent credential has no placeholder"
                );
                return;
            };
            if value.is_empty() {
                tracing::error!(
                    cred_id,
                    domain = %domain,
                    "dropping uriPlaceholder injection: value is empty"
                );
                return;
            }
            state
                .uri_placeholder_map
                .entry(domain)
                .or_default()
                .push((placeholder.to_string(), value.clone()));
        }
        crate::policy_schema::CredentialInjection::AwsSigv4 {
            domain,
            access_key_id,
            secret_access_key,
            session_token,
            ..
        } => {
            let domain = domain.to_lowercase();
            let Some(placeholder) = cred_placeholder else {
                tracing::error!(
                    cred_id,
                    domain = %domain,
                    "dropping awsSigv4 injection: parent credential has no placeholder \
                     (sandbox needs it as the fake access key ID)"
                );
                return;
            };
            if access_key_id.is_empty() || secret_access_key.is_empty() {
                tracing::error!(
                    cred_id,
                    domain = %domain,
                    "dropping awsSigv4 injection: AWS credentials are empty"
                );
                return;
            }
            // Placeholders are derived deterministically from connectionId,
            // so collisions shouldn't happen. Surface the misbehavior if the
            // derivation ever regresses and collapses two connections onto
            // the same key — silent overwrite would be harder to diagnose.
            if state.aws_config_map.contains_key(placeholder) {
                tracing::warn!(
                    cred_id,
                    placeholder,
                    "awsSigv4 injection overwrites existing config for placeholder — connectionId derivation may have collided"
                );
            }
            state.aws_config_map.insert(
                placeholder.to_string(),
                crate::aws_sigv4::AwsSigv4Config {
                    access_key_id: access_key_id.clone(),
                    secret_access_key: secret_access_key.clone(),
                    session_token: session_token.clone(),
                },
            );
            if !state.aws_domains.contains(&domain) {
                state.aws_domains.push(domain);
            }
        }
    }
}

/// Map a policy's `network.defaultVerdict` string to a [`Verdict`].
///
/// Deserializing through `Verdict`'s own serde impl keeps this parser pinned to
/// the published policy schema (the same `Verdict` type generates that schema),
/// so the parser and the schema cannot silently drift apart. Unknown or missing
/// input is fail-closed to `Deny`.
fn parse_default_verdict(raw: Option<&str>) -> crate::routing::Verdict {
    let Some(raw) = raw else {
        tracing::warn!("network.defaultVerdict missing; defaulting to deny");
        return crate::routing::Verdict::Deny;
    };
    match serde_json::from_value::<crate::routing::Verdict>(serde_json::Value::String(
        raw.to_string(),
    )) {
        Ok(verdict) => verdict,
        Err(_) => {
            tracing::error!(
                verdict = raw,
                "unknown network.defaultVerdict in policy; defaulting to deny"
            );
            crate::routing::Verdict::Deny
        }
    }
}

/// Parse and apply a policy message. Returns the env vars for the session handler,
/// or a version mismatch if the sandbox protocol date is too old.
async fn handle_policy(raw_text: &str, proxy_state: &Option<Arc<ProxyState>>) -> PolicyResult {
    // Transport wrapper — adds server-only fields to the policy document.
    // NetworkPolicy is kept as serde_json::Value for fault-tolerant route parsing
    // (a single bad route should not reject the entire policy message).
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct PolicyMessage {
        #[serde(default)]
        proxy_upstream: Option<String>,
        #[serde(default)]
        proxy_ca_cert: Option<String>,
        #[serde(default)]
        network: Option<NetworkPolicyRaw>,
        #[serde(default)]
        env: Option<HashMap<String, String>>,
        #[serde(default)]
        credentials: Option<Vec<crate::policy_schema::Credential>>,
        #[serde(default)]
        files: Option<Vec<crate::protocol::TempFile>>,
    }

    // Loose deserialization — allowed_routes stays as Value so individual
    // route errors are handled gracefully in parse_proxy_routes.
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NetworkPolicyRaw {
        #[serde(default)]
        allowed_routes: serde_json::Value,
        #[serde(default)]
        default_verdict: Option<String>,
        #[serde(default)]
        default_transport: Option<String>,
    }

    // Parsed first, alone — the version gate must fire before the full typed
    // parse so a future shape that serde can't decode surfaces
    // `VersionMismatch`, not a silent drop.
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct VersionHeader {
        #[serde(default)]
        min_protocol_date: Option<String>,
    }

    let header: VersionHeader = match serde_json::from_str(raw_text) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("Failed to parse policy version header: {e}");
            return PolicyResult::Ok(HashMap::new());
        }
    };

    // Check protocol version compatibility (YYYY-MM-DD lexicographic comparison)
    let client_date = crate::protocol::SANDBOX_PROTOCOL_DATE;
    match &header.min_protocol_date {
        Some(server_min) if !crate::protocol::is_valid_protocol_date(server_min) => {
            tracing::warn!(
                server_min = %server_min,
                "invalid minProtocolDate format — assuming compatible"
            );
        }
        Some(server_min) if client_date < server_min.as_str() => {
            tracing::error!(
                server_min = %server_min,
                client = %client_date,
                "sandbox protocol date too old"
            );
            return PolicyResult::VersionMismatch {
                server_min: server_min.clone(),
                client: client_date.to_string(),
            };
        }
        Some(server_min) => {
            tracing::debug!(
                server_min = %server_min,
                client = %client_date,
                "protocol date compatible"
            );
        }
        None => {
            tracing::warn!(
                "Lens Sandbox did not send minProtocolDate in policy — assuming compatible"
            );
        }
    }

    let msg: PolicyMessage = match serde_json::from_str(raw_text) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("Failed to parse policy message: {e}");
            return PolicyResult::Ok(HashMap::new());
        }
    };

    let mut policy_env = msg.env.unwrap_or_default();

    let Some(state) = proxy_state else {
        tracing::debug!("proxy not enabled — skipping proxy config from policy");
        return PolicyResult::Ok(policy_env);
    };

    // Update upstream
    if let Some(url) = msg.proxy_upstream {
        match crate::proxy::parse_upstream_url(&url) {
            Some(upstream) => {
                tracing::info!(
                    host = %upstream.host,
                    port = upstream.port,
                    has_auth = upstream.auth_header.is_some(),
                    "proxy upstream configured from policy"
                );
                *state.upstream.lock().await = Some(upstream);
            }
            None => {
                // Redact credentials from the URL before logging.
                let redacted = url.find('@').map_or(url.as_str(), |at| &url[at..]);
                tracing::error!("invalid proxyUpstream URL in policy: ...{redacted}");
            }
        }
    }

    // Update routes, default verdict/transport, and forward configs from nested
    // network policy. Routes with a `forward` field carry mTLS config inline —
    // we parse PEM from the forward config and populate state.client_certs. If
    // PEM parsing fails, the route verdict is overridden to Deny (fail-closed).
    let mut routes_valid = false;
    match msg.network {
        Some(network) => {
            if network.allowed_routes.is_array() {
                match parse_proxy_routes(&network.allowed_routes) {
                    Ok(parsed_routes) => {
                        let mut route_rules = Vec::with_capacity(parsed_routes.len());
                        let mut cert_map: HashMap<String, crate::proxy::ClientCertConfig> =
                            HashMap::new();

                        for mut parsed in parsed_routes {
                            if let Some(fwd) = parsed.forward.take() {
                                let key = match &parsed.rule.matcher {
                                    crate::routing::RouteMatcher::HostPort(h, p) => {
                                        format!("{h}:{p}")
                                    }
                                    other => {
                                        tracing::error!(
                                            matcher = ?other,
                                            "forward config on non-HostPort route; denying route"
                                        );
                                        parsed.rule.verdict = crate::routing::Verdict::Deny;
                                        route_rules.push(parsed.rule);
                                        continue;
                                    }
                                };

                                match parse_forward_certs(&fwd) {
                                    Ok(cc) => {
                                        tracing::info!(
                                            domain_port = %key,
                                            dial_addr = %fwd.dial_addr,
                                            tls_server_name = %fwd.tls_server_name,
                                            "forward cert config parsed from route"
                                        );
                                        cert_map.insert(key, cc);
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            domain_port = %key,
                                            "forward cert parse failed: {e}; denying route"
                                        );
                                        parsed.rule.verdict = crate::routing::Verdict::Deny;
                                    }
                                }
                            }
                            route_rules.push(parsed.rule);
                        }

                        tracing::info!(
                            route_count = route_rules.len(),
                            client_cert_count = cert_map.len(),
                            client_cert_keys = ?cert_map.keys().collect::<Vec<_>>(),
                            "proxy routes and forward certs updated from policy"
                        );
                        *state.client_certs.write().unwrap() = cert_map;
                        *state.routes.write().unwrap() = route_rules;
                        routes_valid = true;
                    }
                    Err(e) => {
                        tracing::error!(
                            "invalid network.allowedRoutes in policy: {e}; clearing routes and forcing deny"
                        );
                        state.routes.write().unwrap().clear();
                        state.client_certs.write().unwrap().clear();

                        *state.default_verdict.write().unwrap() = crate::routing::Verdict::Deny;
                        *state.default_transport.write().unwrap() =
                            crate::routing::Transport::Upstream;
                    }
                }
            } else {
                tracing::info!(
                    "network.allowedRoutes missing or not an array; clearing routes and forcing deny"
                );
                state.routes.write().unwrap().clear();
                state.client_certs.write().unwrap().clear();
                *state.default_verdict.write().unwrap() = crate::routing::Verdict::Deny;
                *state.default_transport.write().unwrap() = crate::routing::Transport::Upstream;
            }

            // Only apply defaultVerdict/defaultTransport when routes parsed
            // successfully. Otherwise the fallback above already forced Deny.
            if routes_valid {
                let verdict = parse_default_verdict(network.default_verdict.as_deref());
                // Transport is required per schema. Missing OR malformed means
                // we don't know what the operator chose; on a non-deny verdict
                // that's a fail-closed downgrade so we never silently pick a
                // transport for them.
                let (transport, transport_valid) = match network.default_transport.as_deref() {
                    Some("upstream") => (crate::routing::Transport::Upstream, true),
                    Some("direct") => (crate::routing::Transport::Direct, true),
                    Some(other) => {
                        if matches!(verdict, crate::routing::Verdict::Deny) {
                            tracing::warn!(
                                transport = other,
                                "unknown network.defaultTransport in policy; ignored (deny verdict)"
                            );
                        } else {
                            tracing::error!(
                                transport = other,
                                "unknown network.defaultTransport in policy; forcing deny"
                            );
                        }
                        (crate::routing::Transport::Upstream, false)
                    }
                    None => {
                        if !matches!(verdict, crate::routing::Verdict::Deny) {
                            tracing::error!(
                                "network.defaultTransport missing with non-deny verdict; forcing deny"
                            );
                        }
                        (crate::routing::Transport::Upstream, false)
                    }
                };
                let effective_verdict = if matches!(
                    verdict,
                    crate::routing::Verdict::Allow | crate::routing::Verdict::Ask
                ) && !transport_valid
                {
                    crate::routing::Verdict::Deny
                } else {
                    verdict
                };
                tracing::info!(
                    verdict = ?effective_verdict,
                    transport = ?transport,
                    "proxy default verdict/transport updated from policy"
                );
                *state.default_verdict.write().unwrap() = effective_verdict;
                *state.default_transport.write().unwrap() = transport;
            }
        }
        None => {
            // No network field means no domain restrictions — reset to allow-all via Lens Sandbox.
            tracing::info!("network policy absent; resetting to allow-all via lens");
            state.routes.write().unwrap().clear();
            state.client_certs.write().unwrap().clear();
            *state.default_verdict.write().unwrap() = crate::routing::Verdict::Allow;
            *state.default_transport.write().unwrap() = crate::routing::Transport::Upstream;
        }
    }

    // Install proxy CA cert into system trust store (once per process)
    // and store parsed DER certs for MITM upstream TLS verification.
    if let Some(pem) = msg.proxy_ca_cert {
        crate::ca::install_ca_cert(&pem);
        if let Ok(certs) =
            CertificateDer::pem_slice_iter(pem.as_bytes()).collect::<Result<Vec<_>, _>>()
        {
            tracing::info!(
                count = certs.len(),
                "parsed extra CA certs from proxy CA PEM"
            );
            if !certs.is_empty() {
                *state.extra_ca_certs.write().unwrap() = certs;
                // Drop the cached Lens Sandbox TlsConnector so the next CONNECT
                // rebuilds it against the freshly-installed CA bundle.
                *state.sandbox_tls_connector.write().unwrap() = None;
            }
        }
    }

    // Initialize ephemeral CA on first policy. Needed for:
    // - MITM credential injection on proxied connections
    // - TLS termination on Lens Sandbox-routed tunnels (upstream K8s services speak HTTP)
    // - Client certificate forwarding
    state
        .ephemeral_ca
        .get_or_init(|| match crate::ca::EphemeralCa::new() {
            Ok(ca) => {
                crate::ca::install_ca_cert(ca.ca_cert_pem());
                tracing::info!("ephemeral CA generated and installed");
                Arc::new(ca)
            }
            Err(e) => {
                panic!("ephemeral CA generation failed: {e}");
            }
        });

    // Process credentials: each injection carries its own `injectionType`
    // discriminator. The match inside `apply_injection` is exhaustive — when
    // a new injection type is added, the compiler forces us to handle it.
    if let Some(credentials) = msg.credentials {
        let mut injection_map: HashMap<String, Vec<crate::proxy::CredentialInjection>> =
            HashMap::new();
        let mut uri_placeholder_map: HashMap<String, Vec<(String, String)>> = HashMap::new();
        let mut aws_config_map: HashMap<String, crate::aws_sigv4::AwsSigv4Config> = HashMap::new();
        let mut aws_domains: Vec<String> = Vec::new();
        let mut placeholder_index: HashMap<String, String> = HashMap::new();
        let mut unarmed_domains: Vec<String> = Vec::new();
        let mut header_count = 0;

        for cred in &credentials {
            let mut apply = CredentialApply {
                injection_map: &mut injection_map,
                uri_placeholder_map: &mut uri_placeholder_map,
                aws_config_map: &mut aws_config_map,
                aws_domains: &mut aws_domains,
                header_count: &mut header_count,
            };
            for inj in &cred.injections {
                // An injection with an empty `value` is unarmed: register its
                // domain so the proxy MITMs that host to gate the placeholder's
                // first use, but don't add it to the substitution maps (there's
                // no secret to inject yet, and the placeholder must survive so
                // the gate scan trips). Arming = a follow-up policy resends the
                // same injection with the real value. See
                // `ProxyState::unarmed_credential_domains`.
                if let Some(domain) = inj.unarmed_domain() {
                    unarmed_domains.push(domain.to_lowercase());
                    continue;
                }
                apply_injection(&cred.id, cred.placeholder.as_deref(), inj, &mut apply);
            }

            if let (Some(env_var), Some(placeholder)) = (&cred.env_var, &cred.placeholder) {
                policy_env.insert(env_var.clone(), placeholder.clone());
            }

            // Index every known placeholder so the MITM scan can map a
            // surviving placeholder back to its credential, even while the
            // credential is unarmed. Indexed regardless of `env_var`: future
            // credential types may surface placeholders through means other
            // than env (config files, MCP, etc). Last-write-wins on duplicates.
            if let Some(placeholder) = &cred.placeholder
                && let Some(prior) = placeholder_index.insert(placeholder.clone(), cred.id.clone())
            {
                tracing::warn!(
                    placeholder,
                    prior_credential = prior,
                    next_credential = cred.id,
                    "duplicate placeholder across credentials; later credential wins"
                );
            }
        }

        *state.credential_injections.write().unwrap() = injection_map;
        *state.placeholder_index.write().unwrap() = placeholder_index;
        *state.unarmed_credential_domains.write().unwrap() = unarmed_domains;
        tracing::info!(
            count = header_count,
            "credential injections updated from policy"
        );

        if !uri_placeholder_map.is_empty() {
            tracing::info!(
                count = uri_placeholder_map.values().map(|v| v.len()).sum::<usize>(),
                domains = uri_placeholder_map.len(),
                "URI placeholder injections updated from policy"
            );
        }
        *state.uri_placeholder_injections.write().unwrap() = uri_placeholder_map;

        tracing::info!(
            count = aws_config_map.len(),
            domains = aws_domains.len(),
            "aws_sigv4 configs updated from policy"
        );
        state.aws_resign.update(aws_config_map, aws_domains);
    }

    // Write persistent files from policy (e.g. AWS credential files, synthetic kubeconfig).
    // Remove every previously-written file before recreating so the symlink-safe
    // O_EXCL create never collides with a file we ourselves own from the last refresh;
    // a residual collision then means a hostile pre-plant and fails closed.
    {
        let old_paths = state.previous_policy_files.read().unwrap().clone();
        for old in &old_paths {
            let _ = tokio::fs::remove_file(old).await;
        }

        if let Some(files) = msg.files
            && !files.is_empty()
        {
            match crate::temp_files::write_temp_files(&files, state.sandbox_creds.as_ref()).await {
                Ok(paths) => {
                    tracing::info!(count = paths.len(), "wrote policy files");
                    *state.previous_policy_files.write().unwrap() = paths;
                }
                Err(e) => {
                    tracing::warn!("Failed to write policy files: {e}");
                }
            }
        } else {
            *state.previous_policy_files.write().unwrap() = Vec::new();
        }
    }

    if !policy_env.is_empty() {
        tracing::info!(
            count = policy_env.len(),
            "received project env vars from policy"
        );
    }
    PolicyResult::Ok(policy_env)
}

/// Run in standalone mode: apply policy JSON to proxy, return env vars.
/// The policy JSON is read from a Docker volume by the config loader and passed here.
pub async fn apply_local_policy(
    policy_json: &str,
    proxy_state: &Option<Arc<ProxyState>>,
) -> HashMap<String, String> {
    // Parse, add type field, re-serialize (safe regardless of whitespace)
    let mut policy: serde_json::Value =
        serde_json::from_str(policy_json).unwrap_or_else(|e| panic!("Invalid policy JSON: {e}"));
    policy
        .as_object_mut()
        .expect("policy must be a JSON object")
        .insert("type".into(), serde_json::Value::String("policy".into()));
    let msg = serde_json::to_string(&policy).unwrap();

    // Wire audit to tracing instead of WebSocket.
    // In standalone mode, audit events go to tracing (visible when RUST_LOG is set).
    // The proxy already logs DENIED events via tracing::info!, but this captures
    // the structured JSON audit events for all connection types.
    if let Some(state) = proxy_state {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        *state.audit_tx.lock().unwrap() = Some(tx);
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                tracing::debug!(target: "lens::audit", "{}", event);
            }
        });
    }

    match handle_policy(&msg, proxy_state).await {
        PolicyResult::Ok(env) => env,
        PolicyResult::VersionMismatch { server_min, client } => {
            // Standalone mode — version mismatch shouldn't happen (no server),
            // but if the policy JSON somehow includes minProtocolDate, log and continue.
            tracing::warn!(%server_min, %client, "standalone policy has minProtocolDate; ignoring");
            HashMap::new()
        }
    }
}

/// Parse PEM-encoded certs and key from a raw forward config into a `ClientCertConfig`.
fn parse_forward_certs(
    fwd: &crate::policy_schema::ForwardConfig,
) -> Result<crate::proxy::ClientCertConfig, String> {
    // Parse client cert chain
    let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(fwd.cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("failed to parse cert_pem: {e}"))?;
    if cert_chain.is_empty() {
        return Err("no certificates found in cert_pem".to_string());
    }

    // Parse private key
    let private_key = PrivateKeyDer::from_pem_slice(fwd.key_pem.as_bytes())
        .map_err(|e| format!("failed to parse key_pem: {e}"))?;

    // Parse CA certs (optional)
    let ca_certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        if let Some(ca_pem) = &fwd.ca_pem {
            CertificateDer::pem_slice_iter(ca_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("failed to parse ca_pem: {e}"))?
        } else {
            Vec::new()
        };

    Ok(crate::proxy::ClientCertConfig {
        cert_chain,
        private_key,
        ca_certs,
        dial_addr: fwd.dial_addr.clone(),
        tls_server_name: fwd.tls_server_name.clone(),
        upstream_host_header: fwd.upstream_host_header.clone(),
    })
}

#[cfg(test)]
#[allow(clippy::result_large_err)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
    use tokio_tungstenite::tungstenite::http;

    #[test]
    fn runtime_default_verdict_parser_matches_the_schema_enum() {
        use crate::policy_schema::Verdict;
        // parse_default_verdict deserializes through Verdict's own serde impl —
        // the same impl that generates the published policy schema — so the
        // parser cannot diverge from the schema by construction. This exhaustive
        // match is a tripwire: adding a Verdict variant fails to compile here
        // until it is listed, prompting a review of the round-trip below.
        fn schema_string(v: Verdict) -> &'static str {
            match v {
                Verdict::Allow => "allow",
                Verdict::Deny => "deny",
                Verdict::Ask => "ask",
            }
        }
        for v in [Verdict::Allow, Verdict::Deny, Verdict::Ask] {
            let s = schema_string(v);
            // The schema string equals serde's serialization...
            assert_eq!(
                serde_json::to_value(v).unwrap(),
                serde_json::json!(s),
                "schema_string must equal serde's serialization for {v:?}"
            );
            // ...and the runtime parser maps it back to the same variant.
            assert_eq!(
                parse_default_verdict(Some(s)),
                v,
                "the runtime parser must map the schema string back to {v:?}"
            );
        }
        // Unknown, wrong-case, and missing input all stay fail-closed (deny).
        assert_eq!(parse_default_verdict(Some("nonsense")), Verdict::Deny);
        assert_eq!(parse_default_verdict(Some("Allow")), Verdict::Deny);
        assert_eq!(parse_default_verdict(None), Verdict::Deny);
    }

    struct TestDispatcher;

    impl SandboxDispatcher for TestDispatcher {
        fn new_session(&self) -> Box<dyn SessionHandler> {
            Box::new(TestSession {
                activity: ActivityStream::new(),
            })
        }
    }

    struct TestSession {
        activity: ActivityStream,
    }

    #[async_trait]
    impl SessionHandler for TestSession {
        fn activity(&self) -> &ActivityStream {
            &self.activity
        }

        async fn dispatch(&self, raw_text: &str, tx: &mpsc::UnboundedSender<String>) {
            // Parse exec messages and respond — spawn so dispatch returns immediately
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw_text)
                && v["type"] == "exec"
            {
                let id = v["id"].as_str().unwrap_or("").to_string();
                let command = v["command"].as_str().unwrap_or("").to_string();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let output = tokio::process::Command::new("/bin/bash")
                        .arg("-c")
                        .arg(&command)
                        .output()
                        .await;
                    let (stdout, stderr, exit_code) = match output {
                        Ok(o) => (
                            String::from_utf8_lossy(&o.stdout).to_string(),
                            String::from_utf8_lossy(&o.stderr).to_string(),
                            o.status.code().unwrap_or(1),
                        ),
                        Err(e) => (String::new(), e.to_string(), 1),
                    };
                    let resp = serde_json::json!({
                        "type": "exec_result",
                        "id": id,
                        "stdout": stdout,
                        "stderr": stderr,
                        "exitCode": exit_code,
                    });
                    let _ = tx.send(resp.to_string());
                });
            }
        }

        async fn shutdown(&self) {}
    }

    async fn bind_server() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, addr)
    }

    fn make_config(addr: SocketAddr) -> (String, String) {
        (format!("ws://{addr}/v1/sandbox"), "test-token".into())
    }

    // Invalid WebSocket URL → Rejected immediately, no connection attempted
    #[tokio::test]
    async fn rejected_on_invalid_url() {
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();

        let result =
            connect_and_run("not a url %%", "test-token", &last_activity, &None, session).await;

        assert!(matches!(result, ConnectionResult::Rejected));
    }

    // Unknown scheme → Rejected (no connector matches, no retry).
    #[tokio::test]
    async fn rejected_on_unknown_scheme() {
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();

        let result = connect_and_run(
            "ftp://lens.example.com/v1/sandbox",
            "test-token",
            &last_activity,
            &None,
            session,
        )
        .await;

        assert!(matches!(result, ConnectionResult::Rejected));
    }

    // `vsock://` without a CID:PORT authority is a configuration bug, not a
    // transient I/O failure. It must Reject cleanly so the reconnect loop
    // doesn't spin forever; the prior code forged a placeholder host that
    // got past `into_client_request` and then failed later as InvalidInput.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn rejected_on_vsock_url_missing_authority() {
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();

        // `Uri::from_str` accepts this — the authority is None, port is None.
        let result = connect_and_run(
            "vsock:///v1/sandbox",
            "test-token",
            &last_activity,
            &None,
            session,
        )
        .await;

        assert!(matches!(result, ConnectionResult::Rejected));
    }

    // `vsock://2/v1/sandbox` parses but lacks a port; the connector returns
    // InvalidInput. That must surface as Rejected, not Disconnected — a
    // retry can't supply a missing port.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn rejected_when_connector_returns_invalid_input() {
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();

        let result = connect_and_run(
            "vsock://2/v1/sandbox",
            "test-token",
            &last_activity,
            &None,
            session,
        )
        .await;

        assert!(matches!(result, ConnectionResult::Rejected));
    }

    // 401 → Rejected (auth failure, no retry)
    #[tokio::test]
    async fn rejected_on_401() {
        let (listener, addr) = bind_server().await;

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let reject = |_req: &Request, _resp: Response| -> Result<Response, ErrorResponse> {
                Err(http::Response::builder()
                    .status(401)
                    .body(Some("Unauthorized".into()))
                    .unwrap())
            };
            let _ = tokio_tungstenite::accept_hdr_async(stream, reject).await;
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();

        let result = connect_and_run(&ws_url, &token, &last_activity, &None, session).await;

        assert!(matches!(result, ConnectionResult::Rejected));
    }

    // 403 → Rejected (auth failure, no retry)
    #[tokio::test]
    async fn rejected_on_403() {
        let (listener, addr) = bind_server().await;

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let reject = |_req: &Request, _resp: Response| -> Result<Response, ErrorResponse> {
                Err(http::Response::builder()
                    .status(403)
                    .body(Some("Forbidden".into()))
                    .unwrap())
            };
            let _ = tokio_tungstenite::accept_hdr_async(stream, reject).await;
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();

        let result = connect_and_run(&ws_url, &token, &last_activity, &None, session).await;

        assert!(matches!(result, ConnectionResult::Rejected));
    }

    // Non-auth HTTP errors (e.g. 503) → Disconnected(None) (retryable)
    #[tokio::test]
    async fn disconnected_when_server_returns_503() {
        let (listener, addr) = bind_server().await;

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let reject = |_req: &Request, _resp: Response| -> Result<Response, ErrorResponse> {
                Err(http::Response::builder()
                    .status(503)
                    .body(Some("Service Unavailable".into()))
                    .unwrap())
            };
            let _ = tokio_tungstenite::accept_hdr_async(stream, reject).await;
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();

        let result = connect_and_run(&ws_url, &token, &last_activity, &None, session).await;

        assert!(matches!(result, ConnectionResult::Disconnected(None)));
    }

    // Server sends a close frame → Disconnected carries the close code
    #[tokio::test]
    async fn disconnected_with_close_code_when_server_closes() {
        use tokio_tungstenite::tungstenite::protocol::CloseFrame;
        use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

        let (listener, addr) = bind_server().await;

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut write, _read) = ws.split();
            write
                .send(Message::Close(Some(CloseFrame {
                    code: CloseCode::Normal,
                    reason: "bye".into(),
                })))
                .await
                .unwrap();
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();

        let result = connect_and_run(&ws_url, &token, &last_activity, &None, session).await;

        // CloseCode::Normal = 1000
        assert!(matches!(result, ConnectionResult::Disconnected(Some(1000))));
    }

    // TCP drop before WS handshake → Disconnected(None), not Rejected
    #[tokio::test]
    async fn disconnected_when_tcp_drops_before_handshake() {
        let (listener, addr) = bind_server().await;

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            drop(stream);
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();

        let result = connect_and_run(&ws_url, &token, &last_activity, &None, session).await;

        assert!(matches!(result, ConnectionResult::Disconnected(None)));
    }

    // exec message → exec_result with captured stdout
    #[tokio::test]
    async fn exec_message_returns_exec_result() {
        use serde_json::Value;

        let (listener, addr) = bind_server().await;

        let server = tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut write, mut read) = ws.split();

            let exec_msg = serde_json::json!({
                "type": "exec",
                "id": "req-1",
                "command": "echo hello"
            });
            write
                .send(Message::Text(exec_msg.to_string().into()))
                .await
                .unwrap();

            let reply = loop {
                match read.next().await.unwrap().unwrap() {
                    Message::Text(t) => break serde_json::from_str::<Value>(&t).unwrap(),
                    _ => continue,
                }
            };

            write.send(Message::Close(None)).await.ok();
            reply
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();

        connect_and_run(&ws_url, &token, &last_activity, &None, session).await;

        let reply = server.await.unwrap();
        assert_eq!(reply["type"], "exec_result");
        assert_eq!(reply["id"], "req-1");
        assert_eq!(reply["stdout"].as_str().unwrap().trim(), "hello");
        assert_eq!(reply["exitCode"], 0);
    }

    // Mid-session connection drop → Disconnected(None)
    #[tokio::test]
    async fn disconnected_when_connection_drops_mid_session() {
        let (listener, addr) = bind_server().await;

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            // Drop the WebSocket after handshake without sending a close frame.
            drop(ws);
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();

        let result = connect_and_run(&ws_url, &token, &last_activity, &None, session).await;

        assert!(matches!(result, ConnectionResult::Disconnected(None)));
    }

    // Disconnect must clear `state.audit_tx` so the next gate call sees an
    // unwired channel and fails closed. The sender clone in state outlives
    // the writer task that owned the matching receiver; without an
    // explicit clear, `audit_tx.is_some()` stays true while every send
    // errors silently — parking gated requests for DECISION_TIMEOUT.
    #[tokio::test]
    async fn audit_tx_is_cleared_on_disconnect() {
        let (listener, addr) = bind_server().await;
        let state = test_proxy_state();

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            drop(ws);
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();
        let proxy_state = Some(state.clone());

        let result = connect_and_run(&ws_url, &token, &last_activity, &proxy_state, session).await;

        assert!(matches!(result, ConnectionResult::Disconnected(_)));
        assert!(
            state.audit_tx.lock().unwrap().is_none(),
            "audit_tx must be cleared after disconnect so the next gate call fails closed",
        );
    }

    // Unparseable message → loop continues, connection stays alive
    #[tokio::test]
    async fn unparseable_message_does_not_break_connection() {
        use serde_json::Value;

        let (listener, addr) = bind_server().await;

        let server = tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut write, mut read) = ws.split();

            // Send garbage first.
            write
                .send(Message::Text("this is not valid json {{{{".into()))
                .await
                .unwrap();

            // Then send a valid exec — if the loop survived, we get a result.
            let exec_msg = serde_json::json!({
                "type": "exec",
                "id": "req-2",
                "command": "echo still alive"
            });
            write
                .send(Message::Text(exec_msg.to_string().into()))
                .await
                .unwrap();

            let reply = loop {
                match read.next().await.unwrap().unwrap() {
                    Message::Text(t) => break serde_json::from_str::<Value>(&t).unwrap(),
                    _ => continue,
                }
            };

            write.send(Message::Close(None)).await.ok();
            reply
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();

        connect_and_run(&ws_url, &token, &last_activity, &None, session).await;

        let reply = server.await.unwrap();
        assert_eq!(reply["type"], "exec_result");
        assert_eq!(reply["id"], "req-2");
        assert_eq!(reply["stdout"].as_str().unwrap().trim(), "still alive");
    }

    // Policy message with credentials populates ProxyState credential_injections
    #[tokio::test]
    async fn policy_credentials_populate_proxy_state() {
        let (listener, addr) = bind_server().await;
        let (_proxy_server, state) = crate::proxy::ProxyServer::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            Vec::new(),
        );

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut write, _read) = ws.split();

            let policy = serde_json::json!({
                "type": "policy",
                "credentials": [
                    {
                        "id": "cred-1",
                        "envVar": "GH_TOKEN",
                        "placeholder": "__lens_cred:cred-1__",
                        "injections": [
                            {
                                "injectionType": "header",
                                "domain": "api.github.com",
                                "header": "Authorization",
                                "value": "token ghp_real"
                            }
                        ]
                    }
                ]
            });
            write
                .send(Message::Text(policy.to_string().into()))
                .await
                .unwrap();

            write.send(Message::Close(None)).await.ok();
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();
        let proxy_state = Some(state.clone());

        connect_and_run(&ws_url, &token, &last_activity, &proxy_state, session).await;

        let injections = state.credential_injections.read().unwrap();
        assert!(injections.contains_key("api.github.com"));
        let entries = &injections["api.github.com"];
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header, "Authorization");
        assert_eq!(entries[0].value, "token ghp_real");
        // An armed credential registers no unarmed domains, so MITM stays
        // narrowed to hosts that actually carry an injection.
        assert!(!state.intercept_for_unarmed("api.github.com"));
    }

    // An injection with an empty `value` is unarmed — only its declared
    // domain is MITM'd to gate the first (pre-arm) use; unrelated hosts stay
    // passthrough, and nothing is added to the substitution map.
    #[tokio::test]
    async fn policy_unarmed_injection_scopes_mitm_to_its_domain() {
        let (listener, addr) = bind_server().await;
        let (_proxy_server, state) = crate::proxy::ProxyServer::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            Vec::new(),
        );

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut write, _read) = ws.split();

            let policy = serde_json::json!({
                "type": "policy",
                "credentials": [
                    {
                        "id": "cred-unarmed",
                        "envVar": "GH_TOKEN",
                        "placeholder": "__lens_cred:cred-unarmed__",
                        "injections": [
                            {
                                "injectionType": "header",
                                "domain": "api.github.com",
                                "header": "Authorization",
                                "value": ""
                            }
                        ]
                    }
                ]
            });
            write
                .send(Message::Text(policy.to_string().into()))
                .await
                .unwrap();

            write.send(Message::Close(None)).await.ok();
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();
        let proxy_state = Some(state.clone());

        connect_and_run(&ws_url, &token, &last_activity, &proxy_state, session).await;

        // The declared domain is intercepted; an unrelated host is not.
        assert!(state.intercept_for_unarmed("api.github.com"));
        assert!(!state.intercept_for_unarmed("example.com"));
        // The unarmed injection must NOT enter the substitution map — there's
        // no secret to inject, and the placeholder must survive to trip the gate.
        assert!(
            !state
                .credential_injections
                .read()
                .unwrap()
                .contains_key("api.github.com")
        );
        // The placeholder is still indexed so the MITM scan can match it.
        assert!(
            state
                .placeholder_index
                .read()
                .unwrap()
                .contains_key("__lens_cred:cred-unarmed__")
        );
    }

    // A credential with no injections at all declares no domain, so there is
    // nothing to gate — the proxy registers no unarmed domain and must not
    // fall back to broadly intercepting all egress.
    #[tokio::test]
    async fn policy_credential_with_no_injections_intercepts_nothing() {
        let (listener, addr) = bind_server().await;
        let (_proxy_server, state) = crate::proxy::ProxyServer::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            Vec::new(),
        );

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut write, _read) = ws.split();

            let policy = serde_json::json!({
                "type": "policy",
                "credentials": [
                    {
                        "id": "cred-unarmed",
                        "envVar": "GH_TOKEN",
                        "placeholder": "__lens_cred:cred-unarmed__",
                        "injections": []
                    }
                ]
            });
            write
                .send(Message::Text(policy.to_string().into()))
                .await
                .unwrap();

            write.send(Message::Close(None)).await.ok();
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();
        let proxy_state = Some(state.clone());

        connect_and_run(&ws_url, &token, &last_activity, &proxy_state, session).await;

        assert!(!state.intercept_for_unarmed("api.github.com"));
        assert!(state.unarmed_credential_domains.read().unwrap().is_empty());
    }

    // Arming a credential on a refresh policy drops its domain from the
    // unarmed set, so interception narrows back to armed hosts.
    #[tokio::test]
    async fn policy_arming_credential_clears_unarmed_domains() {
        let (listener, addr) = bind_server().await;
        let (_proxy_server, state) = crate::proxy::ProxyServer::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            Vec::new(),
        );

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut write, _read) = ws.split();

            let unarmed = serde_json::json!({
                "type": "policy",
                "credentials": [
                    {
                        "id": "cred-1",
                        "envVar": "GH_TOKEN",
                        "placeholder": "__lens_cred:cred-1__",
                        "injections": [
                            {
                                "injectionType": "header",
                                "domain": "api.github.com",
                                "header": "Authorization",
                                "value": ""
                            }
                        ]
                    }
                ]
            });
            write
                .send(Message::Text(unarmed.to_string().into()))
                .await
                .unwrap();

            let armed = serde_json::json!({
                "type": "policy",
                "credentials": [
                    {
                        "id": "cred-1",
                        "envVar": "GH_TOKEN",
                        "placeholder": "__lens_cred:cred-1__",
                        "injections": [
                            {
                                "injectionType": "header",
                                "domain": "api.github.com",
                                "header": "Authorization",
                                "value": "token ghp_real"
                            }
                        ]
                    }
                ]
            });
            write
                .send(Message::Text(armed.to_string().into()))
                .await
                .unwrap();

            write.send(Message::Close(None)).await.ok();
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();
        let proxy_state = Some(state.clone());

        connect_and_run(&ws_url, &token, &last_activity, &proxy_state, session).await;

        assert!(!state.intercept_for_unarmed("api.github.com"));
    }

    #[tokio::test]
    async fn policy_rotation_replaces_credentials() {
        let (listener, addr) = bind_server().await;
        let (_proxy_server, state) = crate::proxy::ProxyServer::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            Vec::new(),
        );

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut write, _read) = ws.split();

            let policy_v1 = serde_json::json!({
                "type": "policy",
                "credentials": [{
                    "id": "cluster-c1",
                    "placeholder": "__lens_cred:cluster-c1__",
                    "injections": [{
                        "injectionType": "header",
                        "domain": "lens.example.com",
                        "header": "Authorization",
                        "value": "Bearer lnsc_old",
                        "rules": [{ "path": "/v1/clusters/c1/proxy/**" }]
                    }]
                }]
            });
            let policy_v2 = serde_json::json!({
                "type": "policy",
                "credentials": [{
                    "id": "cluster-c1",
                    "placeholder": "__lens_cred:cluster-c1__",
                    "injections": [{
                        "injectionType": "header",
                        "domain": "lens.example.com",
                        "header": "Authorization",
                        "value": "Bearer lnsc_new",
                        "rules": [{ "path": "/v1/clusters/c1/proxy/**" }]
                    }]
                }]
            });

            write
                .send(Message::Text(policy_v1.to_string().into()))
                .await
                .unwrap();
            write
                .send(Message::Text(policy_v2.to_string().into()))
                .await
                .unwrap();
            write.send(Message::Close(None)).await.ok();
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();
        let proxy_state = Some(state.clone());

        connect_and_run(&ws_url, &token, &last_activity, &proxy_state, session).await;

        let injections = state.credential_injections.read().unwrap();
        let entries = &injections["lens.example.com"];
        assert_eq!(entries.len(), 1, "rotation must overwrite, not append");
        assert_eq!(entries[0].value, "Bearer lnsc_new");
    }

    #[tokio::test]
    async fn policy_rotation_replaces_aws_sigv4_configs() {
        let (listener, addr) = bind_server().await;
        let (_proxy_server, state) = crate::proxy::ProxyServer::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            Vec::new(),
        );

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut write, _read) = ws.split();

            let policy_v1 = serde_json::json!({
                "type": "policy",
                "credentials": [{
                    "id": "aws-prod",
                    "placeholder": "LENSFAKE00AABB0000CC",
                    "injections": [{
                        "injectionType": "awsSigv4",
                        "domain": "s3.us-east-1.amazonaws.com",
                        "accessKeyId": "ASIAOLD",
                        "secretAccessKey": "old-secret",
                        "sessionToken": "old-token",
                        "region": "us-east-1"
                    }]
                }]
            });
            let policy_v2 = serde_json::json!({
                "type": "policy",
                "credentials": [{
                    "id": "aws-prod",
                    "placeholder": "LENSFAKE00AABB0000CC",
                    "injections": [{
                        "injectionType": "awsSigv4",
                        "domain": "s3.us-east-1.amazonaws.com",
                        "accessKeyId": "ASIANEW",
                        "secretAccessKey": "new-secret",
                        "sessionToken": "new-token",
                        "region": "us-east-1"
                    }]
                }]
            });

            write
                .send(Message::Text(policy_v1.to_string().into()))
                .await
                .unwrap();
            write
                .send(Message::Text(policy_v2.to_string().into()))
                .await
                .unwrap();
            write.send(Message::Close(None)).await.ok();
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();
        let proxy_state = Some(state.clone());

        connect_and_run(&ws_url, &token, &last_activity, &proxy_state, session).await;

        let configs = state.aws_resign.configs_snapshot();
        assert_eq!(configs.len(), 1, "rotation must overwrite, not append");
        let cfg = configs
            .get("LENSFAKE00AABB0000CC")
            .expect("config keyed by placeholder access key id");
        assert_eq!(cfg.access_key_id, "ASIANEW");
        assert_eq!(cfg.secret_access_key, "new-secret");
        assert_eq!(cfg.session_token, "new-token");
    }

    // Policy message without credentials leaves ProxyState credential_injections empty
    #[tokio::test]
    async fn policy_without_credentials_leaves_injections_empty() {
        let (listener, addr) = bind_server().await;
        let (_proxy_server, state) = crate::proxy::ProxyServer::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            Vec::new(),
        );

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut write, _read) = ws.split();

            let policy = serde_json::json!({
                "type": "policy",
                "env": { "FOO": "bar" }
            });
            write
                .send(Message::Text(policy.to_string().into()))
                .await
                .unwrap();

            write.send(Message::Close(None)).await.ok();
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();
        let proxy_state = Some(state.clone());

        connect_and_run(&ws_url, &token, &last_activity, &proxy_state, session).await;

        let injections = state.credential_injections.read().unwrap();
        assert!(injections.is_empty());
    }

    // Credentials with multiple domains populate the map for each domain
    #[tokio::test]
    async fn policy_credentials_multiple_domains() {
        let (listener, addr) = bind_server().await;
        let (_proxy_server, state) = crate::proxy::ProxyServer::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            Vec::new(),
        );

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut write, _read) = ws.split();

            let policy = serde_json::json!({
                "type": "policy",
                "credentials": [
                    {
                        "id": "cred-1",
                        "envVar": "GH_TOKEN",
                        "placeholder": "__lens_cred:cred-1__",
                        "injections": [
                            {
                                "injectionType": "header",
                                "domain": "api.github.com",
                                "header": "Authorization",
                                "value": "token ghp_real"
                            },
                            {
                                "injectionType": "header",
                                "domain": "github.com",
                                "header": "Authorization",
                                "value": "token ghp_real"
                            }
                        ]
                    }
                ]
            });
            write
                .send(Message::Text(policy.to_string().into()))
                .await
                .unwrap();

            write.send(Message::Close(None)).await.ok();
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();
        let proxy_state = Some(state.clone());

        connect_and_run(&ws_url, &token, &last_activity, &proxy_state, session).await;

        let injections = state.credential_injections.read().unwrap();
        assert!(injections.contains_key("api.github.com"));
        assert!(injections.contains_key("github.com"));

        let api_entries = &injections["api.github.com"];
        assert_eq!(api_entries.len(), 1);
        assert_eq!(api_entries[0].header, "Authorization");
        assert_eq!(api_entries[0].value, "token ghp_real");

        let gh_entries = &injections["github.com"];
        assert_eq!(gh_entries.len(), 1);
        assert_eq!(gh_entries[0].header, "Authorization");
        assert_eq!(gh_entries[0].value, "token ghp_real");
    }

    // Policy with allow + direct sets proxy default to allow-direct
    #[tokio::test]
    async fn policy_default_allow_direct() {
        let (listener, addr) = bind_server().await;
        let (_proxy_server, state) = crate::proxy::ProxyServer::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            Vec::new(),
        );

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut write, _read) = ws.split();

            let policy = serde_json::json!({
                "type": "policy",
                "network": {
                    "allowedRoutes": [],
                    "defaultVerdict": "allow",
                    "defaultTransport": "direct"
                }
            });
            write
                .send(Message::Text(policy.to_string().into()))
                .await
                .unwrap();

            write.send(Message::Close(None)).await.ok();
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();
        let proxy_state = Some(state.clone());

        connect_and_run(&ws_url, &token, &last_activity, &proxy_state, session).await;

        assert_eq!(
            *state.default_verdict.read().unwrap(),
            crate::routing::Verdict::Allow
        );
        assert_eq!(
            *state.default_transport.read().unwrap(),
            crate::routing::Transport::Direct
        );
    }

    // Policy with unknown defaultVerdict falls back to Deny (fail-closed)
    #[tokio::test]
    async fn policy_unknown_default_verdict_falls_back_to_deny() {
        let (listener, addr) = bind_server().await;
        let (_proxy_server, state) = crate::proxy::ProxyServer::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            Vec::new(),
        );

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut write, _read) = ws.split();

            let policy = serde_json::json!({
                "type": "policy",
                "network": {
                    "allowedRoutes": [],
                    "defaultVerdict": "bogus",
                    "defaultTransport": "upstream"
                }
            });
            write
                .send(Message::Text(policy.to_string().into()))
                .await
                .unwrap();

            write.send(Message::Close(None)).await.ok();
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();
        let proxy_state = Some(state.clone());

        connect_and_run(&ws_url, &token, &last_activity, &proxy_state, session).await;

        assert_eq!(
            *state.default_verdict.read().unwrap(),
            crate::routing::Verdict::Deny
        );
    }

    // Policy with network block but missing defaultVerdict falls back to Deny
    #[tokio::test]
    async fn policy_missing_default_verdict_falls_back_to_deny() {
        let (listener, addr) = bind_server().await;
        let (_proxy_server, state) = crate::proxy::ProxyServer::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            Vec::new(),
        );

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut write, _read) = ws.split();

            let policy = serde_json::json!({
                "type": "policy",
                "network": {
                    "allowedRoutes": []
                }
            });
            write
                .send(Message::Text(policy.to_string().into()))
                .await
                .unwrap();

            write.send(Message::Close(None)).await.ok();
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();
        let proxy_state = Some(state.clone());

        connect_and_run(&ws_url, &token, &last_activity, &proxy_state, session).await;

        assert_eq!(
            *state.default_verdict.read().unwrap(),
            crate::routing::Verdict::Deny
        );
    }

    // Policy with valid forward cert config populates client_certs and ephemeral CA
    #[tokio::test]
    async fn policy_valid_forward_cert_populates_state() {
        let (listener, addr) = bind_server().await;
        let (_proxy_server, state) = crate::proxy::ProxyServer::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            Vec::new(),
        );

        // Generate test cert/key PEM using rcgen
        let cert = rcgen::generate_simple_self_signed(vec!["test".to_string()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut write, _read) = ws.split();

            let policy = serde_json::json!({
                "type": "policy",
                "network": {
                    "allowedRoutes": [
                        {
                            "match": "host.docker.internal:6443",
                            "verdict": "allow",
                            "transport": "direct",
                            "forward": {
                                "dialAddr": "host.docker.internal:6443",
                                "tlsServerName": "127.0.0.1",
                                "upstreamHostHeader": "127.0.0.1:6443",
                                "certPem": cert_pem,
                                "keyPem": key_pem
                            }
                        }
                    ],
                    "defaultVerdict": "deny",
                    "defaultTransport": "upstream"
                }
            });
            write
                .send(Message::Text(policy.to_string().into()))
                .await
                .unwrap();

            write.send(Message::Close(None)).await.ok();
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();
        let proxy_state = Some(state.clone());

        connect_and_run(&ws_url, &token, &last_activity, &proxy_state, session).await;

        // Client certs should be populated
        let certs = state.client_certs.read().unwrap();
        assert_eq!(certs.len(), 1, "expected 1 client cert entry");
        assert!(
            certs.contains_key("host.docker.internal:6443"),
            "expected cert keyed by host.docker.internal:6443, got keys: {:?}",
            certs.keys().collect::<Vec<_>>()
        );

        // Ephemeral CA should be initialized
        assert!(
            state.ephemeral_ca.get().is_some(),
            "ephemeral CA should be initialized when forward certs exist"
        );

        // Route should still be allow-via-direct (not Deny)
        let routes = state.routes.read().unwrap();
        assert_eq!(
            crate::routing::match_route(
                &routes,
                "host.docker.internal:6443",
                crate::routing::Scheme::Https,
                crate::routing::Verdict::Deny,
                crate::routing::Transport::Upstream,
            ),
            crate::routing::MatchedRoute {
                verdict: crate::routing::Verdict::Allow,
                transport: crate::routing::Transport::Direct,
                tls_terminate: false,
            },
            "route should remain allow-via-direct for valid forward cert"
        );
    }

    // apply_local_policy with forward config populates client_certs (standalone path)
    #[tokio::test]
    async fn apply_local_policy_forward_cert_populates_state() {
        let (_proxy_server, state) = crate::proxy::ProxyServer::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            Vec::new(),
        );
        let proxy_state = Some(state.clone());

        let cert = rcgen::generate_simple_self_signed(vec!["test".to_string()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let policy_json = serde_json::json!({
            "network": {
                "allowedRoutes": [
                    {
                        "match": "host.docker.internal:6443",
                        "verdict": "allow",
                        "transport": "direct",
                        "forward": {
                            "dialAddr": "host.docker.internal:6443",
                            "tlsServerName": "127.0.0.1",
                            "certPem": cert_pem,
                            "keyPem": key_pem
                        }
                    }
                ],
                "defaultVerdict": "deny",
                "defaultTransport": "upstream"
            }
        });

        apply_local_policy(&policy_json.to_string(), &proxy_state).await;

        let certs = state.client_certs.read().unwrap();
        assert_eq!(
            certs.len(),
            1,
            "expected 1 client cert entry from apply_local_policy"
        );
        assert!(
            certs.contains_key("host.docker.internal:6443"),
            "expected cert keyed by host.docker.internal:6443, got keys: {:?}",
            certs.keys().collect::<Vec<_>>()
        );
        assert!(
            state.ephemeral_ca.get().is_some(),
            "ephemeral CA should be initialized"
        );
    }

    // Test with the exact JSON the Go CLI produces for a real k3s kubeconfig.
    // Uses RSA PKCS#1 key format ("RSA PRIVATE KEY") which is what k3s generates.
    // This is the end-to-end standalone path test.
    #[tokio::test]
    async fn apply_local_policy_real_kube_json_populates_state() {
        let (_proxy_server, state) = crate::proxy::ProxyServer::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            Vec::new(),
        );
        let proxy_state = Some(state.clone());

        // Generate self-signed cert for testing (EC key — rcgen can't do RSA without extra features)
        let cert = rcgen::generate_simple_self_signed(vec!["test".to_string()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        // Simulate the exact structure the Go CLI writes to the Docker volume
        let policy_json = format!(
            r#"{{"network":{{"allowedRoutes":[{{"match":"host.docker.internal:6443","verdict":"allow","transport":"direct","forward":{{"dialAddr":"host.docker.internal:6443","tlsServerName":"127.0.0.1","upstreamHostHeader":"127.0.0.1:6443","certPem":{},"keyPem":{}}}}}],"defaultVerdict":"deny","defaultTransport":"upstream"}},"env":{{"KUBECONFIG":"/tmp/kubeconfig"}},"files":[{{"path":"/tmp/kubeconfig","content":"apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://host.docker.internal:6443\n  name: sandbox\n","mode":420}}]}}"#,
            serde_json::to_string(&cert_pem).unwrap(),
            serde_json::to_string(&key_pem).unwrap(),
        );

        let env = apply_local_policy(&policy_json, &proxy_state).await;

        // Verify env vars from policy
        assert_eq!(
            env.get("KUBECONFIG").map(String::as_str),
            Some("/tmp/kubeconfig")
        );

        // Verify client certs populated
        let certs = state.client_certs.read().unwrap();
        assert_eq!(certs.len(), 1, "expected 1 client cert entry");
        assert!(
            certs.contains_key("host.docker.internal:6443"),
            "cert should be keyed by host.docker.internal:6443, got: {:?}",
            certs.keys().collect::<Vec<_>>()
        );

        // Verify ephemeral CA initialized
        assert!(
            state.ephemeral_ca.get().is_some(),
            "ephemeral CA should be initialized"
        );

        // Verify route is allow-via-direct (not overridden to Deny)
        let routes = state.routes.read().unwrap();
        assert_eq!(
            crate::routing::match_route(
                &routes,
                "host.docker.internal:6443",
                crate::routing::Scheme::Https,
                crate::routing::Verdict::Deny,
                crate::routing::Transport::Upstream,
            ),
            crate::routing::MatchedRoute {
                verdict: crate::routing::Verdict::Allow,
                transport: crate::routing::Transport::Direct,
                tls_terminate: false,
            }
        );
    }

    // Malformed allowedRoutes forces defaultVerdict to Deny (fail-closed)
    #[tokio::test]
    async fn policy_invalid_routes_forces_deny_default() {
        let (listener, addr) = bind_server().await;
        let (_proxy_server, state) = crate::proxy::ProxyServer::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            Vec::new(),
        );

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut write, _read) = ws.split();

            // allowedRoutes is a string, not an array — malformed
            let policy = serde_json::json!({
                "type": "policy",
                "network": {
                    "allowedRoutes": "not-an-array",
                    "defaultVerdict": "allow",
                    "defaultTransport": "direct"
                }
            });
            write
                .send(Message::Text(policy.to_string().into()))
                .await
                .unwrap();
            write.send(Message::Close(None)).await.ok();
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();
        let proxy_state = Some(state.clone());

        connect_and_run(&ws_url, &token, &last_activity, &proxy_state, session).await;

        // defaultVerdict should be forced to Deny, NOT "allow" from the policy
        assert_eq!(
            *state.default_verdict.read().unwrap(),
            crate::routing::Verdict::Deny,
            "malformed routes should force defaultVerdict to Deny"
        );
    }

    // forward on a non-HostPort route is denied (fail-closed)
    #[tokio::test]
    async fn policy_forward_on_domain_route_is_denied() {
        let (listener, addr) = bind_server().await;
        let (_proxy_server, state) = crate::proxy::ProxyServer::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            Vec::new(),
        );

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut write, _read) = ws.split();

            // forward on a domain (not host:port) route — invalid
            let policy = serde_json::json!({
                "type": "policy",
                "network": {
                    "allowedRoutes": [
                        {
                            "match": "example.com",
                            "verdict": "allow",
                            "transport": "direct",
                            "forward": {
                                "dialAddr": "example.com:443",
                                "tlsServerName": "example.com",
                                "certPem": "not-valid",
                                "keyPem": "not-valid"
                            }
                        }
                    ],
                    "defaultVerdict": "deny",
                    "defaultTransport": "upstream"
                }
            });
            write
                .send(Message::Text(policy.to_string().into()))
                .await
                .unwrap();
            write.send(Message::Close(None)).await.ok();
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();
        let proxy_state = Some(state.clone());

        connect_and_run(&ws_url, &token, &last_activity, &proxy_state, session).await;

        // The domain route with forward should be denied, not allow
        let routes = state.routes.read().unwrap();
        assert_eq!(
            crate::routing::match_route(
                &routes,
                "example.com:443",
                crate::routing::Scheme::Https,
                crate::routing::Verdict::Deny,
                crate::routing::Transport::Upstream,
            ),
            crate::routing::MatchedRoute {
                verdict: crate::routing::Verdict::Deny,
                transport: crate::routing::Transport::Direct,
                tls_terminate: false,
            },
            "forward on non-HostPort route should be denied"
        );
    }

    // Policy with malformed client cert adds Deny route (fail-closed)
    #[tokio::test]
    async fn policy_malformed_client_cert_adds_deny_route() {
        let (listener, addr) = bind_server().await;
        let (_proxy_server, state) = crate::proxy::ProxyServer::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            Vec::new(),
        );

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut write, _read) = ws.split();

            let policy = serde_json::json!({
                "type": "policy",
                "network": {
                    "allowedRoutes": [
                        {
                            "match": "host.docker.internal:6443",
                            "verdict": "allow",
                            "transport": "direct",
                            "forward": {
                                "dialAddr": "host.docker.internal:6443",
                                "tlsServerName": "127.0.0.1",
                                "certPem": "not-valid-pem",
                                "keyPem": "not-valid-pem"
                            }
                        }
                    ],
                    "defaultVerdict": "deny",
                    "defaultTransport": "upstream"
                }
            });
            write
                .send(Message::Text(policy.to_string().into()))
                .await
                .unwrap();

            write.send(Message::Close(None)).await.ok();
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();
        let proxy_state = Some(state.clone());

        connect_and_run(&ws_url, &token, &last_activity, &proxy_state, session).await;

        // The malformed cert should have overridden the route verdict to Deny
        let routes = state.routes.read().unwrap();
        assert!(
            !routes.is_empty(),
            "should have at least the deny override route"
        );
        assert_eq!(
            crate::routing::match_route(
                &routes,
                "host.docker.internal:6443",
                crate::routing::Scheme::Https,
                crate::routing::Verdict::Deny,
                crate::routing::Transport::Upstream,
            ),
            crate::routing::MatchedRoute {
                verdict: crate::routing::Verdict::Deny,
                transport: crate::routing::Transport::Direct,
                tls_terminate: false,
            },
            "malformed client cert route should be denied, not allowed"
        );

        // No client certs should have been stored
        let certs = state.client_certs.read().unwrap();
        assert!(certs.is_empty(), "no valid client certs should be stored");
    }

    // Disconnect while a long-running exec is in flight must not block reconnect.
    #[tokio::test]
    async fn disconnect_during_long_exec_does_not_block_reconnect() {
        let (listener, addr) = bind_server().await;

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut write, _read) = ws.split();

            // Send a 10-second exec then immediately drop the connection.
            let exec_msg = serde_json::json!({
                "type": "exec",
                "id": "slow-1",
                "command": "sleep 10"
            });
            write
                .send(Message::Text(exec_msg.to_string().into()))
                .await
                .unwrap();

            drop(write); // close without a close frame
        });

        let (ws_url, token) = make_config(addr);
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let session = TestDispatcher.new_session();

        // Should return well within 2 seconds, not wait 10 seconds for the exec.
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            connect_and_run(&ws_url, &token, &last_activity, &None, session),
        )
        .await;

        assert!(
            result.is_ok(),
            "connect_and_run blocked waiting for long-running exec to finish"
        );
    }

    // CA cert installation tests moved to ca.rs

    #[tokio::test]
    async fn handle_watch_returns_empty_output_when_no_events() {
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let activity = ActivityStream::new();
        let raw = r#"{"type":"watch","id":"w1","waitMs":50}"#;

        handle_watch(&tx, &activity, raw).await;

        let msg = rx.try_recv().unwrap();
        let v: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(v["type"], "watch_result");
        assert_eq!(v["id"], "w1");
        assert_eq!(v["output"], "");
    }

    #[tokio::test]
    async fn handle_watch_collects_events() {
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let activity = ActivityStream::new();

        // Emit events before subscribing — handle_watch subscribes inside,
        // so we need to emit after the subscribe. Use a task.
        let activity2 = activity.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            activity2.emit("event-one\n".to_string());
            activity2.emit("event-two\n".to_string());
        });

        let raw = r#"{"type":"watch","id":"w2","waitMs":100}"#;
        handle_watch(&tx, &activity, raw).await;

        let msg = rx.try_recv().unwrap();
        let v: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(v["type"], "watch_result");
        assert_eq!(v["id"], "w2");
        let output = v["output"].as_str().unwrap();
        assert!(output.contains("event-one"));
        assert!(output.contains("event-two"));
    }

    #[tokio::test]
    async fn handle_watch_caps_output_size() {
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let activity = ActivityStream::new();

        // Emit enough data to exceed the 256 KB cap
        let activity2 = activity.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let big_line = "x".repeat(64 * 1024) + "\n";
            for _ in 0..5 {
                activity2.emit(big_line.clone());
            }
        });

        let raw = r#"{"type":"watch","id":"w3","waitMs":200}"#;
        handle_watch(&tx, &activity, raw).await;

        let msg = rx.try_recv().unwrap();
        let v: serde_json::Value = serde_json::from_str(&msg).unwrap();
        let output = v["output"].as_str().unwrap();
        assert!(output.contains("[...output truncated...]"));
        // Should not exceed cap + truncation message
        assert!(output.len() < 300 * 1024);
    }

    // handle_policy with matching minProtocolDate returns Ok
    #[tokio::test]
    async fn policy_matching_protocol_date_returns_ok() {
        let raw = serde_json::json!({
            "type": "policy",
            "minProtocolDate": crate::protocol::SANDBOX_PROTOCOL_DATE,
        });
        let result = handle_policy(&raw.to_string(), &None).await;
        assert!(matches!(result, PolicyResult::Ok(_)));
    }

    // handle_policy with older minProtocolDate returns Ok (sandbox is newer)
    #[tokio::test]
    async fn policy_older_protocol_date_returns_ok() {
        let raw = serde_json::json!({
            "type": "policy",
            "minProtocolDate": "2020-01-01",
        });
        let result = handle_policy(&raw.to_string(), &None).await;
        assert!(matches!(result, PolicyResult::Ok(_)));
    }

    // handle_policy with newer minProtocolDate returns VersionMismatch
    #[tokio::test]
    async fn policy_newer_protocol_date_returns_version_mismatch() {
        let raw = serde_json::json!({
            "type": "policy",
            "minProtocolDate": "2099-01-01",
        });
        let result = handle_policy(&raw.to_string(), &None).await;
        match result {
            PolicyResult::VersionMismatch { server_min, client } => {
                assert_eq!(server_min, "2099-01-01");
                assert_eq!(client, crate::protocol::SANDBOX_PROTOCOL_DATE);
            }
            _ => panic!("expected VersionMismatch"),
        }
    }

    // handle_policy without minProtocolDate returns Ok (backwards compat)
    #[tokio::test]
    async fn policy_missing_protocol_date_returns_ok() {
        let raw = serde_json::json!({
            "type": "policy",
            "env": { "FOO": "bar" },
        });
        let result = handle_policy(&raw.to_string(), &None).await;
        match result {
            PolicyResult::Ok(env) => {
                assert_eq!(env.get("FOO").map(|s| s.as_str()), Some("bar"));
            }
            _ => panic!("expected Ok"),
        }
    }

    // A future Lens Sandbox version may send credential shapes (e.g. a new
    // `injectionType`) that this sandbox can't parse. The version gate must
    // fire BEFORE the full typed parse — otherwise serde fails first, the
    // sandbox drops the whole message with a cryptic log, and the operator
    // gets no signal that an upgrade is needed.
    #[tokio::test]
    async fn policy_version_check_runs_before_typed_parse() {
        let raw = serde_json::json!({
            "type": "policy",
            "minProtocolDate": "2099-01-01",
            "credentials": [{
                "id": "future-cred",
                "injections": [{
                    "injectionType": "someFutureVariant",
                    "someField": "someValue"
                }]
            }]
        });
        let result = handle_policy(&raw.to_string(), &None).await;
        match result {
            PolicyResult::VersionMismatch { server_min, client } => {
                assert_eq!(server_min, "2099-01-01");
                assert_eq!(client, crate::protocol::SANDBOX_PROTOCOL_DATE);
            }
            _ => panic!("expected VersionMismatch; got other variant"),
        }
    }

    // handle_policy with invalid date format assumes compatible
    #[tokio::test]
    async fn policy_invalid_protocol_date_format_returns_ok() {
        let raw = serde_json::json!({
            "type": "policy",
            "minProtocolDate": "not-a-date",
        });
        let result = handle_policy(&raw.to_string(), &None).await;
        assert!(matches!(result, PolicyResult::Ok(_)));
    }

    // Server-pushed policy messages (initial + 10-min credential refresh) must NOT
    // count as sandbox activity, otherwise the idle shutdown timer never fires and
    // idle sandboxes never recycle. Only user/Lens Sandbox-orchestrated work (exec, spawn,
    // watch, etc.) should reset the idle clock.
    #[tokio::test]
    async fn policy_message_does_not_update_last_activity() {
        let (listener, addr) = bind_server().await;

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut write, _read) = ws.split();

            let policy = serde_json::json!({
                "type": "policy",
                "env": { "FOO": "bar" },
            });
            write
                .send(Message::Text(policy.to_string().into()))
                .await
                .unwrap();
            write.send(Message::Close(None)).await.ok();
        });

        let (ws_url, token) = make_config(addr);
        // Seed last_activity with an old timestamp so we can detect whether the
        // policy message bumped it back to "now".
        let stale = Instant::now()
            .checked_sub(Duration::from_secs(3600))
            .expect("subtracting one hour from Instant::now() underflowed");
        let last_activity = Arc::new(Mutex::new(stale));
        let session = TestDispatcher.new_session();

        connect_and_run(&ws_url, &token, &last_activity, &None, session).await;

        let observed = *last_activity.lock().await;
        assert_eq!(
            observed,
            stale,
            "policy message must not reset last_activity (got elapsed {:?})",
            observed.elapsed(),
        );
    }

    // --- handle_policy unit tests with real ProxyState ---

    fn test_proxy_state() -> Arc<ProxyState> {
        let (_, state) = crate::proxy::ProxyServer::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            Vec::new(),
        );
        state
    }

    #[tokio::test]
    async fn handle_policy_uri_placeholder_populates_domain_scoped_map() {
        let state = test_proxy_state();
        let policy = serde_json::json!({
            "type": "policy",
            "credentials": [{
                "id": "telegram-bot-token",
                "envVar": "TELEGRAM_BOT_TOKEN",
                "placeholder": "__lens_cred:telegram-bot-token__",
                "injections": [{
                    "injectionType": "uriPlaceholder",
                    "domain": "api.telegram.org",
                    "value": "123456:ABC-DEF"
                }]
            }]
        });
        let result = handle_policy(&policy.to_string(), &Some(state.clone())).await;
        assert!(matches!(result, PolicyResult::Ok(_)));

        // URI placeholder injections should be domain-scoped
        let map = state.uri_placeholder_injections.read().unwrap();
        let entries = map.get("api.telegram.org").expect("expected domain entry");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "__lens_cred:telegram-bot-token__");
        assert_eq!(entries[0].1, "123456:ABC-DEF");

        // Should NOT appear in header credential injections
        let header_map = state.credential_injections.read().unwrap();
        assert!(
            header_map.is_empty(),
            "uriPlaceholder should not create header injections"
        );
    }

    #[tokio::test]
    async fn handle_policy_header_injection_not_in_uri_placeholder_map() {
        let state = test_proxy_state();
        let policy = serde_json::json!({
            "type": "policy",
            "credentials": [{
                "id": "anthropic-api-key",
                "envVar": "ANTHROPIC_API_KEY",
                "placeholder": "__lens_cred:anthropic-api-key__",
                "injections": [{
                    "injectionType": "header",
                    "domain": "api.anthropic.com",
                    "header": "x-api-key",
                    "value": "sk-ant-test"
                }]
            }]
        });
        let result = handle_policy(&policy.to_string(), &Some(state.clone())).await;
        assert!(matches!(result, PolicyResult::Ok(_)));

        // Header injections should be in credential_injections
        let header_map = state.credential_injections.read().unwrap();
        assert!(header_map.contains_key("api.anthropic.com"));

        // Should NOT appear in URI placeholder map
        let uri_map = state.uri_placeholder_injections.read().unwrap();
        assert!(
            uri_map.is_empty(),
            "header injection should not create URI placeholder entry"
        );
    }

    #[tokio::test]
    async fn handle_policy_mixed_injection_types() {
        let state = test_proxy_state();
        let policy = serde_json::json!({
            "type": "policy",
            "credentials": [
                {
                    "id": "anthropic-api-key",
                    "placeholder": "__lens_cred:anthropic-api-key__",
                    "injections": [{
                        "injectionType": "header",
                        "domain": "api.anthropic.com",
                        "header": "x-api-key",
                        "value": "sk-ant-test"
                    }]
                },
                {
                    "id": "telegram-bot-token",
                    "placeholder": "__lens_cred:telegram-bot-token__",
                    "injections": [{
                        "injectionType": "uriPlaceholder",
                        "domain": "api.telegram.org",
                        "value": "123:ABC"
                    }]
                }
            ]
        });
        let result = handle_policy(&policy.to_string(), &Some(state.clone())).await;
        assert!(matches!(result, PolicyResult::Ok(_)));

        let header_map = state.credential_injections.read().unwrap();
        assert!(header_map.contains_key("api.anthropic.com"));
        assert!(!header_map.contains_key("api.telegram.org"));

        let uri_map = state.uri_placeholder_injections.read().unwrap();
        assert!(uri_map.contains_key("api.telegram.org"));
        assert!(!uri_map.contains_key("api.anthropic.com"));
    }

    #[tokio::test]
    async fn handle_policy_parses_ask_as_default_verdict() {
        let state = test_proxy_state();
        let policy = serde_json::json!({
            "type": "policy",
            "network": {
                "allowedRoutes": [],
                "defaultVerdict": "ask",
                "defaultTransport": "upstream",
            },
        });
        handle_policy(&policy.to_string(), &Some(state.clone())).await;
        assert_eq!(
            *state.default_verdict.read().unwrap(),
            crate::routing::Verdict::Ask,
            "defaultVerdict=\"ask\" must enable the gate"
        );
    }

    #[tokio::test]
    async fn handle_policy_ask_without_transport_forces_deny() {
        // Ask requires a transport selection (same as Allow) since the gate
        // resolves to allow-via-transport. Missing transport must fail closed.
        let state = test_proxy_state();
        let policy = serde_json::json!({
            "type": "policy",
            "network": {
                "allowedRoutes": [],
                "defaultVerdict": "ask",
            },
        });
        handle_policy(&policy.to_string(), &Some(state.clone())).await;
        assert_eq!(
            *state.default_verdict.read().unwrap(),
            crate::routing::Verdict::Deny,
            "Ask without transport must fail closed"
        );
    }

    #[tokio::test]
    async fn handle_request_decision_resolves_pending_gate() {
        use crate::protocol::Decision;
        let (state, mut rx) = crate::proxy::tests::test_state();
        // Spawn a gate caller so a pending entry exists for "evil".
        let h = tokio::spawn({
            let state = state.clone();
            async move {
                crate::gate::gate_or_deny(&state, "evil", "CONNECT evil:443", "policy-ambiguous")
                    .await
            }
        });
        let frame = rx.recv().await.expect("request_pending emitted");
        let id = serde_json::from_str::<serde_json::Value>(&frame).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();

        let decision_frame =
            format!(r#"{{"type":"request_decision","id":"{id}","decision":"allow_once"}}"#);
        handle_request_decision(&state, &decision_frame);

        assert_eq!(h.await.unwrap(), Decision::AllowOnce);
    }

    #[tokio::test]
    async fn handle_request_decision_ignores_unknown_id() {
        let (state, _rx) = crate::proxy::tests::test_state();
        // No pending entries; this should just log and return without panic.
        handle_request_decision(
            &state,
            r#"{"type":"request_decision","id":"no-such","decision":"allow_always"}"#,
        );
    }

    #[tokio::test]
    async fn handle_credential_decision_resolves_pending_gate() {
        use crate::protocol::CredentialDecisionKind;
        let (state, mut rx) = crate::proxy::tests::test_state();
        let state_for_task = state.clone();
        let handle = tokio::spawn(async move {
            crate::gate::credential_gate_or_deny(&state_for_task, "github", "use of github").await
        });
        // Drain the credential_pending frame to get the id.
        let frame = rx.recv().await.expect("credential_pending");
        let parsed: serde_json::Value = serde_json::from_str(&frame).unwrap();
        let id = parsed["id"].as_str().unwrap().to_string();

        let decision_frame =
            format!(r#"{{"type":"credential_decision","id":"{id}","decision":"allow"}}"#);
        handle_credential_decision(&state, &decision_frame);

        let decision = handle.await.unwrap();
        assert_eq!(decision, CredentialDecisionKind::Allow);
    }

    #[tokio::test]
    async fn handle_credential_decision_ignores_unknown_id() {
        let (state, _rx) = crate::proxy::tests::test_state();
        handle_credential_decision(
            &state,
            r#"{"type":"credential_decision","id":"no-such","decision":"deny"}"#,
        );
    }

    #[tokio::test]
    async fn handle_credential_decision_ignores_malformed_json() {
        let (state, _rx) = crate::proxy::tests::test_state();
        handle_credential_decision(&state, "not-json");
    }

    #[tokio::test]
    async fn handle_request_decision_ignores_malformed_json() {
        let (state, _rx) = crate::proxy::tests::test_state();
        handle_request_decision(&state, "not-json");
    }
}
