use std::collections::HashSet;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::ServerName;
#[cfg(test)]
use rustls::pki_types::pem::PemObject;
use rustls::server::ClientHello;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::ca::EphemeralCa;
use crate::proxy::CredentialInjection;
use crate::routing::HttpRule;
use crate::sock_mark;

/// How to reach the upstream server after terminating client TLS.
pub enum UpstreamMode {
    /// Direct TCP + TLS to target (used for `action: "direct"` routes).
    DirectTls { host: String, port: u16 },
    /// Pre-established tunnel + TLS (for HTTPS services behind a tunnel).
    /// The inner stream is type-erased so plain TCP and TLS-wrapped tunnels
    /// (when the Lens Sandbox HTTPS port fronts the proxy) share the same path.
    TunnelTls(crate::proxy::BoxedSandboxStream),
}

/// Policy-derived context for a MITM connection.
pub struct MitmContext<'a> {
    pub injections: &'a [CredentialInjection],
    pub http_rules: &'a [HttpRule],
    pub ca: &'a EphemeralCa,
    pub audit_tx: &'a Option<tokio::sync::mpsc::UnboundedSender<String>>,
    pub extra_ca_certs: &'a [rustls::pki_types::CertificateDer<'static>],
    /// Credential placeholder → real value pairs for URI rewriting.
    pub placeholder_map: &'a [(String, String)],
    /// Proxy state for credential-gate dispatch (placeholder index,
    /// pending table, fresh-state reads after `Allow`).
    pub state: &'a std::sync::Arc<crate::proxy::ProxyState>,
    /// Port-bearing CONNECT target (`host:port`) the caller used to
    /// collect `injections` / `placeholder_map`. Distinct from the SNI
    /// hostname (`target_host`) passed to the MITM, which is stripped of
    /// its port for cert generation and the upstream Host header. The
    /// post-Allow credential-gate rebuild re-collects through
    /// `injection_matches`, which honours port-specific patterns, so it
    /// must match against this value — not the port-stripped hostname,
    /// which would never satisfy a `host:port` credential pattern.
    pub match_host: &'a str,
    pub actor: &'a crate::peer_process::ActorContext,
}

/// HTTP/1.1 request body framing, derived from the request method + headers.
/// Used to bound the client→upstream forwarding so a pipelined second request
/// cannot leak through after the first request body ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestBodyMode {
    /// No body — request method or framing implies an empty payload.
    None,
    /// Body is exactly N bytes (Content-Length).
    Fixed(u64),
    /// Body is HTTP/1.1 chunked transfer encoding.
    Chunked,
}

/// Outputs from request-head parsing that the relay needs after
/// `mitm_accept_and_inject` returns.
struct RequestMeta {
    /// True if the original (pre-strip) request advertised an HTTP/1.1 upgrade
    /// (WebSocket, SPDY...). Drives the dispatch to `copy_bidirectional`.
    is_upgrade: bool,
    /// How to bound the client→upstream body forwarding.
    body_mode: RequestBodyMode,
}

/// Handle a MITM connection: terminate TLS from the client,
/// inject credential headers into the first HTTP request,
/// and forward to the upstream using the specified `UpstreamMode`.
pub async fn handle_mitm(
    client: TcpStream,
    target_host: &str,
    upstream_mode: UpstreamMode,
    ctx: &MitmContext<'_>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server_config = build_ephemeral_server_config(ctx.ca, target_host)?;
    let acceptor = TlsAcceptor::from(server_config);
    let tls_client = acceptor.accept(client).await?;
    handle_mitm_pre_accepted(tls_client, target_host, upstream_mode, ctx).await
}

/// MITM variant that skips the initial TLS accept — for callers that have
/// already driven the ClientHello (e.g. the transparent-redirect listener,
/// which peeks SNI via `LazyConfigAcceptor` before committing to a cert).
pub async fn handle_mitm_pre_accepted(
    tls_client: tokio_rustls::server::TlsStream<TcpStream>,
    target_host: &str,
    upstream_mode: UpstreamMode,
    ctx: &MitmContext<'_>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let is_tunnel = !matches!(upstream_mode, UpstreamMode::DirectTls { .. });

    // Read/inject headers BEFORE connecting upstream, so a stalling client
    // doesn't hold open upstream connections.
    let (tls_client, modified, meta) =
        mitm_inject_after_accept(tls_client, target_host, ctx, is_tunnel).await?;

    match upstream_mode {
        UpstreamMode::DirectTls { host, port } => {
            // Through the policy-aware dial, not a bare one: an `egress.tcp`
            // CIDR rule binds by address, so this is the first point at which it
            // can be applied to a target the client named. Skipping it would let
            // a CIDR deny hold on the transparent door and not here.
            let target_stream = crate::proxy::connect_egress_under_policy(
                ctx.state,
                &format!("{host}:{port}"),
                port,
                ctx.actor.process(),
            )
            .await?;
            let mut tls_upstream =
                connect_upstream_tls(target_stream, &host, None, None, ctx.extra_ca_certs).await?;
            tls_upstream.write_all(modified.as_bytes()).await?;
            tls_upstream.write_all(b"\r\n\r\n").await?;
            forward_or_bridge(tls_client, tls_upstream, &meta).await?;
        }
        UpstreamMode::TunnelTls(upstream) => {
            let mut tls_upstream =
                connect_upstream_tls(upstream, target_host, None, None, ctx.extra_ca_certs).await?;
            tls_upstream.write_all(modified.as_bytes()).await?;
            tls_upstream.write_all(b"\r\n\r\n").await?;
            forward_or_bridge(tls_client, tls_upstream, &meta).await?;
        }
    }

    Ok(())
}

/// Build a rustls `ServerConfig` that serves an ephemeral cert for
/// `target_host`. Exposed so the transparent-redirect listener can complete
/// a `LazyConfigAcceptor` handshake after sniffing SNI.
pub fn build_ephemeral_server_config(
    ca: &EphemeralCa,
    target_host: &str,
) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let certified_key = ca
        .certified_key_for_domain(target_host)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertResolver(certified_key)));
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(server_config))
}

/// True if the request advertises an HTTP/1.1 upgrade (WebSocket, SPDY, etc.)
/// via `Connection: upgrade`. Operates on the *original* request bytes, before
/// `inject_headers` rewrites the Connection header.
fn is_upgrade_request(header_block: &str) -> bool {
    for line in header_block.split("\r\n") {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("connection:")
            && rest.contains("upgrade")
        {
            return true;
        }
    }
    false
}

/// Determine HTTP/1.1 request body framing from the original request head.
///
/// HTTP/1.1 framing rules (RFC 9112 §6.3):
/// 1. If `Transfer-Encoding` is present and ends with `chunked` → chunked.
/// 2. Else if `Content-Length` is a non-negative integer → fixed length.
/// 3. Else, request method conventions: HEAD/GET/DELETE/OPTIONS/TRACE have no
///    body; POST/PUT/PATCH/etc. without explicit framing default to no body
///    too (a server is allowed to reject those, but we shouldn't pump bytes
///    of unknown length to upstream where they'd outlive our session).
fn determine_body_mode(header_block: &str, method: &str) -> RequestBodyMode {
    let mut content_length: Option<u64> = None;
    for line in header_block.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("transfer-encoding:") {
            // Per RFC, the last coding listed is the outer one. If chunked is
            // present anywhere we treat it as chunked — a chunked-with-extras
            // request is rare and the safest thing is to switch to chunk
            // parsing rather than blindly forwarding bytes by length.
            if rest.contains("chunked") {
                return RequestBodyMode::Chunked;
            }
        } else if let Some(rest) = lower.strip_prefix("content-length:")
            && let Ok(n) = rest.trim().parse::<u64>()
        {
            content_length = Some(n);
        }
    }
    if let Some(n) = content_length {
        return RequestBodyMode::Fixed(n);
    }
    match method.to_ascii_uppercase().as_str() {
        "GET" | "HEAD" | "DELETE" | "OPTIONS" | "TRACE" | "CONNECT" => RequestBodyMode::None,
        // Methods that conventionally carry a body but were sent without
        // framing — treat as empty rather than forwarding indefinite bytes.
        _ => RequestBodyMode::None,
    }
}

/// Drive the client↔upstream relay. For upgrade requests we keep the legacy
/// `copy_bidirectional` shape so WebSocket/SPDY framing flows through. For
/// regular request/response traffic we use `forward_response_with_close`,
/// which guarantees:
///   1. The response sent to the client carries `Connection: close`, so any
///      pooling HTTP client (reqwest, undici, fetch...) drops the inner TLS
///      connection after one request.
///   2. The inner TLS is explicitly shut down once the response body finishes,
///      so even a client that ignores the response header sees a hard EOF
///      before it can send a second pipelined request through the tunnel.
///
/// Without (1) and (2) the MITM "one request per session" contract was only
/// enforced on the upstream leg; the inner client↔MITM TLS appeared
/// reusable, and a second pooled HTTP/1.1 request would race against the
/// MITM's teardown and surface as spurious 400s. See the regression test in
/// packages/lens-e2e/src/claude-code-lens-mcp.e2e.test.ts.
async fn forward_or_bridge<C, U>(
    mut tls_client: C,
    mut tls_upstream: U,
    meta: &RequestMeta,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    if meta.is_upgrade {
        tokio::io::copy_bidirectional(&mut tls_client, &mut tls_upstream).await?;
        return Ok(());
    }
    forward_response_with_close(&mut tls_client, &mut tls_upstream, meta.body_mode).await
}

async fn forward_response_with_close<C, U>(
    tls_client: &mut C,
    tls_upstream: &mut U,
    body_mode: RequestBodyMode,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(tls_client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(tls_upstream);

    // Bound the client→upstream forwarding by the parsed request body framing.
    // A client that pipelines a second HTTP/1.1 request through the same
    // inner TLS would otherwise have its bytes raw-copied to upstream — and
    // even though Connection: close on request 1 forces upstream to ignore
    // them, the bytes would have bypassed the policy/HTTP-rule/credential
    // injection/audit pipeline, which is wrong.
    //
    // Forwarding stops at the end of the *first* request body; any subsequent
    // bytes from the client sit in `client_read`'s buffer and are discarded
    // when we drop the streams.
    //
    // After the body is forwarded (or immediately, for `None`), the future
    // parks via `pending()` instead of returning — that way the outer
    // `tokio::select!` always completes on the response side, and this future
    // gets cancelled by drop.
    //
    // For `Fixed` and `Chunked`, we shutdown the upstream write half ONLY
    // when the body forwarder finished short (client disconnected mid-body
    // or chunked framing errored out). That edge case otherwise hangs:
    // upstream blocks waiting for the rest of the body, response_forwarder
    // blocks waiting for response headers, the whole MITM session sits
    // there until an external timeout fires.
    //
    // On the *successful* path we deliberately do not shutdown. tokio_rustls'
    // `WriteHalf::shutdown` sends TLS close_notify on the inner connection,
    // and several upstream stacks (notably the Bedrock LLM proxy mock and
    // anything streaming SSE) treat that as "the client is done with this
    // request" and abort the in-flight response — breaking streaming bodies
    // even though the request itself was fully delivered. Upstream already
    // knows the body is complete from Content-Length / the chunked
    // terminator; an explicit shutdown adds nothing and risks tearing the
    // streaming response down.
    let request_forwarder = async {
        match body_mode {
            RequestBodyMode::None => {}
            RequestBodyMode::Fixed(n) => {
                let mut limited = (&mut client_read).take(n);
                let copied = tokio::io::copy(&mut limited, &mut upstream_write).await;
                let incomplete = !matches!(copied, Ok(actual) if actual >= n);
                if incomplete {
                    let _ = upstream_write.shutdown().await;
                }
            }
            RequestBodyMode::Chunked => {
                if forward_chunked_body(&mut client_read, &mut upstream_write)
                    .await
                    .is_err()
                {
                    let _ = upstream_write.shutdown().await;
                }
            }
        }
        std::future::pending::<()>().await;
    };

    let response_forwarder = async {
        // RFC 9110 §15.2: a server MAY send 1xx informational responses (e.g.
        // 100 Continue, 103 Early Hints) before the final response. These
        // each have their own header block but no body. Forward them
        // verbatim — they're not the response we want to rewrite.
        loop {
            let header_bytes = read_until_double_crlf(&mut upstream_read).await?;
            if let Some(code) = parse_status_code(&header_bytes)
                && (100..200).contains(&code)
            {
                client_write.write_all(&header_bytes).await?;
                continue;
            }
            // Final response — rewrite Connection and stream the body.
            let modified = inject_response_connection_close(&header_bytes);
            client_write.write_all(&modified).await?;
            // Stream the body. Returns on upstream EOF (server honored
            // Connection: close) or on a client write error.
            let _ = tokio::io::copy(&mut upstream_read, &mut client_write).await;
            // Eagerly send TLS close_notify + FIN to the client so its
            // connection pool sees the connection as terminated *now*, before
            // it can race a second pipelined request through the tunnel.
            let _ = client_write.shutdown().await;
            return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
        }
    };

    // Run both concurrently, but the response side is what we care about
    // returning a result from. The request body forwarder runs as long as the
    // response forwarder; when the response completes, dropping the future
    // cancels it.
    tokio::select! {
        result = response_forwarder => result?,
        _ = request_forwarder => {}
    }
    Ok(())
}

/// Forward an HTTP/1.1 chunked-encoded request body verbatim from `reader`
/// to `writer`, stopping at the terminating zero-size chunk plus (optional)
/// trailers and the final CRLF. Bytes that arrive after the terminator stay
/// in `reader`'s buffer and are discarded when the caller drops the stream.
///
/// Returns Ok on a clean end-of-body, or Err if framing is invalid.
async fn forward_chunked_body<R, W>(
    reader: &mut R,
    writer: &mut W,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt;
    loop {
        let size_line = read_line_with_crlf(reader).await?;
        writer.write_all(&size_line).await?;

        // Parse hex chunk size, ignoring any chunk extensions after `;`.
        let trimmed = size_line
            .strip_suffix(b"\r\n")
            .ok_or("chunk size line missing CRLF")?;
        let size_part = match trimmed.iter().position(|&b| b == b';') {
            Some(idx) => &trimmed[..idx],
            None => trimmed,
        };
        let size_str =
            std::str::from_utf8(size_part).map_err(|_| "chunk size contained non-UTF-8 bytes")?;
        let size = u64::from_str_radix(size_str.trim(), 16)
            .map_err(|_| format!("invalid chunk size: {size_str:?}"))?;

        if size == 0 {
            // Final chunk. Trailers (or just the empty line) follow until a
            // bare CRLF closes the body.
            loop {
                let line = read_line_with_crlf(reader).await?;
                writer.write_all(&line).await?;
                if line.as_slice() == b"\r\n" {
                    return Ok(());
                }
            }
        }

        // Forward exactly `size` body bytes plus the trailing CRLF.
        let mut limited = reader.take(size);
        tokio::io::copy(&mut limited, writer).await?;
        let mut crlf = [0u8; 2];
        limited.into_inner().read_exact(&mut crlf).await?;
        if crlf != *b"\r\n" {
            return Err("chunk body missing trailing CRLF".into());
        }
        writer.write_all(&crlf).await?;
    }
}

/// Read up to and including the next `\r\n` (or EOF). Returns the bytes
/// including the terminator.
async fn read_line_with_crlf<R>(
    stream: &mut R,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err("stream closed before end of line".into());
        }
        buf.push(byte[0]);
        if buf.len() >= 2 && buf.ends_with(b"\r\n") {
            return Ok(buf);
        }
        if buf.len() > 8192 {
            return Err("chunk header line too large".into());
        }
    }
}

async fn read_until_double_crlf<R>(
    stream: &mut R,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err("upstream closed before end of response headers".into());
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && buf[buf.len() - 4..] == *b"\r\n\r\n" {
            return Ok(buf);
        }
        if buf.len() > 65536 {
            return Err("response headers too large".into());
        }
    }
}

/// Replace any `Connection:` header in the response head with `Connection: close`.
/// Input includes the trailing `\r\n\r\n`; output preserves that boundary so it
/// can be written verbatim to the client.
///
/// Operates on raw bytes (not UTF-8 decoded) so non-UTF-8 header values such as
/// `Set-Cookie` or arbitrary `X-*` byte payloads pass through unmutated. Field
/// names are ASCII per RFC 9110 §5.1, so the case-insensitive `connection:`
/// match is safe to do byte-wise.
fn inject_response_connection_close(header_bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(header_bytes.len() + 32);
    let mut start = 0;

    while start < header_bytes.len() {
        // Find the next CRLF. If none exists in the remainder, treat
        // everything from `start` as a partial line and bail to the
        // defensive tail below.
        let Some(rel) = find_crlf(&header_bytes[start..]) else {
            break;
        };
        let line = &header_bytes[start..start + rel];

        if line.is_empty() {
            // Empty line marks end of headers — append our own Connection:
            // close before the blank line, then re-emit the \r\n\r\n boundary.
            output.extend_from_slice(b"Connection: close\r\n\r\n");
            return output;
        }

        if !line_starts_with_connection_field(line) {
            output.extend_from_slice(line);
            output.extend_from_slice(b"\r\n");
        }
        // Skip any existing Connection: header — we'll add our own at the end.

        start += rel + 2; // step past the CRLF
    }

    // Defensive: malformed input (no terminating blank line). Still emit a
    // syntactically valid header block so the client doesn't hang.
    output.extend_from_slice(b"Connection: close\r\n\r\n");
    output
}

/// Find the index of the next `\r\n` in `bytes`, or `None` if absent.
fn find_crlf(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|w| w == b"\r\n")
}

/// Case-insensitive check for `connection:` field-name prefix on a header line.
/// Field names are ASCII so byte-wise comparison is correct.
fn line_starts_with_connection_field(line: &[u8]) -> bool {
    line.len() >= 11 && line[..11].eq_ignore_ascii_case(b"connection:")
}

/// Parse the numeric status code from an HTTP response header block.
/// Returns `None` if the status line is malformed.
fn parse_status_code(header_bytes: &[u8]) -> Option<u16> {
    let line_end = find_crlf(header_bytes)?;
    let line = &header_bytes[..line_end];
    // Status-line: HTTP-version SP status-code SP reason-phrase
    let mut parts = line.split(|&b| b == b' ');
    let _version = parts.next()?;
    let code = parts.next()?;
    std::str::from_utf8(code).ok()?.parse::<u16>().ok()
}

/// Splice the connection's src_endpoint / actor.process into an audit event and send it.
fn send_audit(
    tx: &tokio::sync::mpsc::UnboundedSender<String>,
    mut event: serde_json::Value,
    actor: &crate::peer_process::ActorContext,
) {
    if let Some(obj) = event.as_object_mut() {
        actor.augment(obj);
    }
    let _ = tx.send(event.to_string());
}

/// Client-side MITM phase (post-TLS-accept): read HTTP request headers,
/// enforce HTTP rules, inject credentials, rewrite URI placeholders, emit
/// audit event. Returns the TLS client stream and the modified header
/// block (ready to send upstream).
async fn mitm_inject_after_accept(
    mut tls_client: tokio_rustls::server::TlsStream<TcpStream>,
    target_host: &str,
    ctx: &MitmContext<'_>,
    is_tunnel: bool,
) -> Result<
    (
        tokio_rustls::server::TlsStream<TcpStream>,
        String,
        RequestMeta,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    // Read HTTP request headers byte-by-byte (up to 64 KB).
    let mut header_buf = Vec::with_capacity(4096);
    let mut byte = [0u8; 1];
    loop {
        let n = tls_client.read(&mut byte).await?;
        if n == 0 {
            return Err("client closed before sending request headers".into());
        }
        header_buf.push(byte[0]);
        if header_buf.len() >= 4 && header_buf[header_buf.len() - 4..] == *b"\r\n\r\n" {
            break;
        }
        if header_buf.len() > 65536 {
            return Err("HTTP request headers too large".into());
        }
    }

    let header_str = String::from_utf8_lossy(&header_buf[..header_buf.len() - 4]);

    // Detect HTTP/1.1 upgrade and request body framing on the *original*
    // headers — `inject_headers` below will strip Connection (for non-upgrade
    // requests) and otherwise normalize the head, so anything we need to know
    // about the client's intent has to be captured here first.
    let is_upgrade = is_upgrade_request(&header_str);

    // Parse request line for HTTP rule enforcement
    let request_line = header_str.lines().next().unwrap_or("UNKNOWN");
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    let method = parts.first().unwrap_or(&"UNKNOWN");
    let body_mode = determine_body_mode(&header_str, method);
    let raw_path = parts.get(1).unwrap_or(&"/");
    // Strip query string and normalize path (collapse //, resolve ..)
    let raw_no_query = raw_path.split('?').next().unwrap_or(raw_path);
    let normalized = crate::routing::normalize_path(raw_no_query);
    let path = normalized.as_str();

    // Enforce HTTP rules — if rules are present and no rule matches, deny the request
    if !ctx.http_rules.is_empty()
        && !crate::routing::http_request_matches_rules(ctx.http_rules, method, path)
    {
        tracing::info!(
            target_host = %target_host,
            method = %method,
            path = %path,
            "HTTP request denied by policy rules"
        );
        if let Some(tx) = ctx.audit_tx {
            let event = serde_json::json!({
                "type": "audit_event",
                "source": "sandbox-proxy",
                "action": format!("{method} {target_host}{path}"),
                "method": method,
                "host": target_host,
                "path": path,
                "result": "failure",
                "status_code": 403,
                "metadata": { "host": target_host, "mitm": true, "tunnel": is_tunnel, "http_rule_denied": true }
            });
            send_audit(tx, event, ctx.actor);
        }
        tls_client
            .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            .await?;
        tls_client.shutdown().await.ok();
        return Err("HTTP request denied by policy rules".into());
    }

    // Two request-head mutations from policy, applied in order:
    //   1. inject_headers     — type=header credential injections
    //   2. rewrite_uri_placeholders — type=uriPlaceholder credential injections
    let mut header_injected = inject_headers(&header_str, ctx.injections);

    // After a credential_gate Allow we may need a fresher URI placeholder
    // map than the one captured in `ctx.placeholder_map`. None = use ctx
    // (the common path, no gate hit). Some(_) = post-Allow refresh.
    let mut refreshed_uri_placeholders: Option<Vec<(String, String)>> = None;

    // Credential gate: every registered placeholder still present in the
    // post-injection header block is a credential the host hasn't armed
    // for `target_host` yet — hold the request, emit one
    // `credential_pending` per distinct credential, and let the host
    // decide on each. After all `Allow`s, the host is expected to have
    // sent follow-up `policy` frames arming every approved credential's
    // `injections`; we refresh header + URI maps and re-scan. If any
    // placeholder still survives the rebuild (host sent
    // `credential_decision` before `policy`, or never armed any injection
    // on this host), fall into the deny path so a contract violation
    // never leaks the placeholder upstream. The first `Deny` / `Timeout`
    // short-circuits — 403 here, never reaching upstream — mirror of the
    // Ask-gate path.
    //
    // Scope reminder: this scan inspects the request head only; bodies
    // are streamed past unchanged. See `scan_for_unarmed_placeholders`.
    //
    // Scan a copy with armed URI placeholders already substituted, mirroring
    // the header substitution `inject_headers` did above. The real URI rewrite
    // only happens at forward time (below), so without this an already-armed
    // `uriPlaceholder` credential still sits in the request line here and
    // re-trips the gate on every call. `ctx.placeholder_map` carries only
    // armed placeholders (`collect_uri_placeholders` skips unarmed ones), so a
    // first, unarmed use still survives and trips the gate.
    let scan_target = rewrite_uri_placeholders(&header_injected, ctx.placeholder_map);
    let matches = scan_for_unarmed_placeholders(ctx.state, &scan_target);
    if !matches.is_empty() {
        let state = ctx.state;
        let action = format!("{method} {target_host}{path}");

        let mut deny_record: Option<(String, &'static str)> = None;
        for m in &matches {
            let decision =
                crate::gate::credential_gate_or_deny(state, &m.credential_id, &action).await;
            if !decision.is_allow() {
                deny_record = Some((m.credential_id.clone(), decision.audit_reason()));
                break;
            }
        }

        if deny_record.is_none() {
            let fresh_headers = crate::proxy::collect_header_injections(state, ctx.match_host);
            let rebuilt = inject_headers(&header_str, &fresh_headers);
            let fresh_uri = crate::proxy::collect_uri_placeholders(state, ctx.match_host);
            // rewrite_uri_placeholders only touches the request line; the
            // scan runs over the whole rebuilt head, so a header-resident
            // placeholder that inject_headers failed to replace is still
            // visible. That's the contract-violation case we want to catch.
            let probe = rewrite_uri_placeholders(&rebuilt, &fresh_uri);
            let still_unarmed = scan_for_unarmed_placeholders(state, &probe);
            if let Some(m) = still_unarmed.first() {
                tracing::warn!(
                    target_host = %target_host,
                    credential_id = %m.credential_id,
                    "credential gate allowed but follow-up policy did not arm credential on this host — failing closed"
                );
                deny_record = Some((m.credential_id.clone(), "policy-frame-missing"));
            } else {
                header_injected = rebuilt;
                refreshed_uri_placeholders = Some(fresh_uri);
            }
        }

        if let Some((credential_id, reason)) = deny_record {
            tracing::info!(
                target_host = %target_host,
                method = %method,
                path = %path,
                credential_id = %credential_id,
                reason,
                "credential gate denied — failing held request closed"
            );
            if let Some(tx) = ctx.audit_tx {
                let event = serde_json::json!({
                    "type": "audit_event",
                    "source": "sandbox-proxy",
                    "action": action,
                    "method": method,
                    "host": target_host,
                    "path": path,
                    "result": "failure",
                    "status_code": 403,
                    "metadata": {
                        "host": target_host,
                        "mitm": true,
                        "tunnel": is_tunnel,
                        "credential_gate_denied": true,
                        "credential_id": credential_id,
                        "reason": reason,
                    }
                });
                send_audit(tx, event, ctx.actor);
            }
            tls_client
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                )
                .await?;
            tls_client.shutdown().await.ok();
            return Err("credential gate denied".into());
        }
    }
    let effective_uri_placeholders: &[(String, String)] = refreshed_uri_placeholders
        .as_deref()
        .unwrap_or(ctx.placeholder_map);
    let modified = rewrite_uri_placeholders(&header_injected, effective_uri_placeholders);
    if modified != header_injected {
        tracing::debug!(
            target_host = %target_host,
            "rewrote credential placeholder(s) in request line"
        );
        // Re-validate: the rewritten path (with the real credential value) must
        // still satisfy HTTP rules. A credential containing `/`, `?`, or `..`
        // could produce a different normalized path than the placeholder version
        // that was checked above, bypassing policy.
        if !ctx.http_rules.is_empty() {
            let rw_line = modified.split("\r\n").next().unwrap_or(&modified);
            let rw_parts: Vec<&str> = rw_line.split_whitespace().collect();
            let rw_method = rw_parts.first().unwrap_or(&"UNKNOWN");
            let rw_raw_path = rw_parts.get(1).unwrap_or(&"/");
            let rw_no_query = rw_raw_path.split('?').next().unwrap_or(rw_raw_path);
            let rw_normalized = crate::routing::normalize_path(rw_no_query);
            if !crate::routing::http_request_matches_rules(
                ctx.http_rules,
                rw_method,
                &rw_normalized,
            ) {
                tracing::warn!(
                    target_host = %target_host,
                    method = %rw_method,
                    placeholder_path = %path,
                    "HTTP request denied: rewritten URI does not match policy rules"
                );
                if let Some(tx) = ctx.audit_tx {
                    let event = serde_json::json!({
                        "type": "audit_event",
                        "source": "sandbox-proxy",
                        "action": format!("{rw_method} {target_host}{path}"),
                        "method": rw_method,
                        "host": target_host,
                        "path": path,
                        "result": "failure",
                        "status_code": 403,
                        "metadata": { "host": target_host, "mitm": true, "tunnel": is_tunnel, "rewritten_path_denied": true }
                    });
                    send_audit(tx, event, ctx.actor);
                }
                tls_client
                    .write_all(
                        b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                    )
                    .await?;
                tls_client.shutdown().await.ok();
                return Err(
                    "HTTP request denied: rewritten URI does not match policy rules".into(),
                );
            }
        }
    }

    if let Some(tx) = ctx.audit_tx {
        let event = serde_json::json!({
            "type": "audit_event",
            "source": "sandbox-proxy",
            "action": format!("{method} {target_host}{path}"),
            "method": method,
            "host": target_host,
            "path": path,
            "result": "success",
            "metadata": { "host": target_host, "mitm": true, "tunnel": is_tunnel }
        });
        send_audit(tx, event, ctx.actor);
    }

    Ok((
        tls_client,
        modified,
        RequestMeta {
            is_upgrade,
            body_mode,
        },
    ))
}

/// Upstream TLS phase: wrap a TCP stream (direct or tunnel) with TLS.
/// `test_root_store` overrides webpki roots — only used in tests.
/// When `client_cert` is provided, adds the CA certs to the root store and
/// uses client certificate authentication for mTLS.
/// `extra_ca_certs` adds additional trusted CAs (e.g. proxy CA for self-signed upstream).
async fn connect_upstream_tls<S>(
    upstream: S,
    target_host: &str,
    test_root_store: Option<rustls::RootCertStore>,
    client_cert: Option<&crate::proxy::ClientCertConfig>,
    extra_ca_certs: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<tokio_rustls::client::TlsStream<S>, Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut root_store = test_root_store.unwrap_or_else(|| {
        let mut store = rustls::RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        store
    });

    // Add custom CA certs from client cert config (e.g. kube API CA)
    if let Some(cc) = client_cert {
        for ca_cert in &cc.ca_certs {
            root_store
                .add(ca_cert.clone())
                .map_err(|e| format!("failed to add CA cert to root store: {e}"))?;
        }
    }

    // Add extra CA certs (e.g. proxy CA for self-signed upstream)
    for cert in extra_ca_certs {
        let _ = root_store.add(cert.clone());
    }

    let client_config = if let Some(cc) = client_cert {
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(cc.cert_chain.clone(), cc.private_key.clone_key())
            .map_err(|e| format!("failed to configure client auth: {e}"))?
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from(target_host.to_string())?;
    Ok(connector.connect(server_name, upstream).await?)
}

/// Handle a TLS bridge connection: terminate TLS from the agent using an ephemeral
/// cert, then connect to the upstream with mTLS (real client certificates).
///
/// Reads the first HTTP/1.1 request headers to rewrite the Host header to the
/// original upstream hostname (for path-based gateways like Rancher). After
/// forwarding the rewritten headers + `Connection: close`, switches to raw
/// bidirectional byte copy for the remainder of the connection. For upgrade
/// requests (WebSocket/SPDY), the connection stays open after the header phase.
#[allow(clippy::too_many_arguments)]
pub async fn handle_tls_bridge(
    client: TcpStream,
    dial_addr: &str,
    tls_server_name: &str,
    client_cert: &crate::proxy::ClientCertConfig,
    ca: &EphemeralCa,
    hostname_for_cert: &str,
    audit_tx: &Option<tokio::sync::mpsc::UnboundedSender<String>>,
    actor: &crate::peer_process::ActorContext,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Generate ephemeral cert for the hostname the agent connects to
    let certified_key = ca
        .certified_key_for_domain(hostname_for_cert)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertResolver(certified_key)));
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    // Accept TLS from agent
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let mut tls_client = acceptor.accept(client).await?;

    // Read the first HTTP/1.1 request headers byte-by-byte (same pattern as
    // mitm_inject_after_accept) so we can rewrite the Host header.
    let mut header_buf = Vec::with_capacity(4096);
    let mut byte = [0u8; 1];
    loop {
        let n = tls_client.read(&mut byte).await?;
        if n == 0 {
            return Err("client closed before sending request headers".into());
        }
        header_buf.push(byte[0]);
        if header_buf.len() >= 4 && header_buf[header_buf.len() - 4..] == *b"\r\n\r\n" {
            break;
        }
        if header_buf.len() > 65536 {
            return Err("HTTP request headers too large".into());
        }
    }

    let header_str = String::from_utf8_lossy(&header_buf[..header_buf.len() - 4]);

    // Rewrite Host header to the original upstream hostname if configured.
    // For direct API servers (no upstream_host_header), leave Host unchanged.
    let modified = if let Some(ref upstream_host) = client_cert.upstream_host_header {
        rewrite_host_header(&header_str, upstream_host)
    } else {
        header_str.to_string()
    };

    // Connect TCP to upstream
    let upstream_stream = sock_mark::connect_tcp_resolve(dial_addr)
        .await
        .map_err(|e| format!("TLS bridge: failed to connect to upstream {dial_addr}: {e}"))?;

    // Wrap upstream in TLS with mTLS client cert
    let mut tls_upstream = connect_upstream_tls(
        upstream_stream,
        tls_server_name,
        None,
        Some(client_cert),
        &[],
    )
    .await?;

    // Send the (possibly rewritten) headers to upstream
    tls_upstream.write_all(modified.as_bytes()).await?;
    tls_upstream.write_all(b"\r\n\r\n").await?;

    if let Some(tx) = audit_tx {
        let event = serde_json::json!({
            "type": "audit_event",
            "source": "sandbox-proxy",
            "action": format!("TLS_BRIDGE {hostname_for_cert} -> {dial_addr}"),
            "host": hostname_for_cert,
            "result": "success",
            "metadata": { "host": hostname_for_cert, "tls_bridge": true }
        });
        send_audit(tx, event, actor);
    }

    // Bidirectional byte copy for the rest of the connection.
    // Supports WebSocket upgrades, SPDY, chunked streaming — all happen
    // after the initial header exchange.
    tokio::io::copy_bidirectional(&mut tls_client, &mut tls_upstream).await?;
    Ok(())
}

/// Rewrite headers for the TLS bridge path: replace Host with the original
/// upstream hostname, strip the dummy Authorization header (real auth is mTLS
/// via client certificates), and manage Connection semantics.
///
/// For non-upgrade requests, forces `Connection: close` so each request on a
/// keep-alive socket gets the correct Host. For upgrade requests
/// (WebSocket/SPDY), leaves Connection alone so the upgrade can proceed.
fn rewrite_host_header(header_block: &str, new_host: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut is_upgrade = false;
    let mut host_found = false;

    for line in header_block.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("host:") {
            lines.push(format!("Host: {new_host}"));
            host_found = true;
        } else if lower.starts_with("authorization:") {
            // Strip the dummy bearer token from the synthetic kubeconfig
            // (e.g. "Bearer lens-sandbox-proxy-auth"). Real auth is mTLS —
            // forwarding this token could confuse gateways or auth proxies.
            continue;
        } else if lower.starts_with("connection:") && lower.contains("upgrade") {
            is_upgrade = true;
            lines.push(line.to_string());
        } else if lower.starts_with("connection:") {
            // Drop existing Connection header — we'll add our own below
            continue;
        } else {
            lines.push(line.to_string());
        }
    }

    if !host_found {
        // Insert Host after the request line
        if lines.len() > 1 {
            lines.insert(1, format!("Host: {new_host}"));
        } else {
            lines.push(format!("Host: {new_host}"));
        }
    }

    // For non-upgrade requests, force Connection: close so keep-alive
    // doesn't cause the second request to have the wrong Host
    if !is_upgrade {
        lines.push("Connection: close".to_string());
    }

    lines.join("\r\n")
}

/// Inject credential headers into an HTTP/1.1 header block.
///
/// For regular (non-upgrade) requests: replaces any existing `Connection`
/// header with `Connection: close`, codifying the MITM's "one client request
/// per inner TLS session" contract end-to-end.
///
/// For HTTP/1.1 upgrade requests (WebSocket, SPDY, ...): preserves the
/// original `Connection: upgrade` (and `Upgrade:`) so the upgrade handshake
/// can complete. Credential injection still applies — the upgrade's initial
/// request is a regular HTTP/1.1 request and may legitimately need an
/// Authorization header etc.
///
/// Only injects headers for credentials whose rules match the request method/path.
/// Result of a placeholder scan against the post-injection request head.
/// One entry per distinct unarmed credential found.
///
/// Scope: the scan only sees the HTTP request **head** (request line +
/// headers). A placeholder embedded in the request **body** is not
/// detected by this scan and will be forwarded upstream untouched —
/// `inject_headers` / `rewrite_uri_placeholders` are likewise head-only,
/// so the substitution machinery couldn't replace a body-resident
/// placeholder even if the gate caught it. Body-resident placeholders
/// are out of scope for the credential gate by design; agents that
/// surface credentials only through request bodies need explicit body
/// support, not just a wider scan.
pub(crate) struct UnarmedPlaceholderMatch {
    pub credential_id: String,
}

/// Walk the registered placeholder set and return every distinct
/// credential whose placeholder is present in the request head. Substring
/// matching is sufficient because placeholders are randomly-shaped value
/// strings (`ghp_LNSPLACE…`, `sk-LNSPLACE…`, etc.) that won't collide
/// with legitimate header content by accident. An empty result means no
/// gating is needed — the common case once the host has armed all
/// credentials, or when the request touches no known provider.
///
/// A request can legitimately carry placeholders for multiple
/// credentials (e.g. one in a header, another in the URI). Returning all
/// of them lets the caller surface a dialog per credential rather than
/// arbitrarily picking one and falsely 403'ing the rest as
/// `policy-frame-missing`.
///
/// The scan is host-agnostic: the `placeholder_index` is keyed by
/// placeholder string only (the policy frame doesn't carry a domain hint
/// for unarmed credentials), so a request that carries a placeholder for
/// a credential intended for a different host will still trip the gate.
/// That's a useful audit signal — the dialog surfaces the mis-targeted
/// credential and the user can deny — rather than silently forwarding
/// the placeholder to the wrong upstream.
pub(crate) fn scan_for_unarmed_placeholders(
    state: &std::sync::Arc<crate::proxy::ProxyState>,
    header_block: &str,
) -> Vec<UnarmedPlaceholderMatch> {
    let index = state.placeholder_index.read().unwrap();
    let mut matches: Vec<UnarmedPlaceholderMatch> = Vec::new();
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for (placeholder, credential_id) in index.iter() {
        if !placeholder.is_empty()
            && header_block.contains(placeholder.as_str())
            && seen.insert(credential_id.as_str())
        {
            matches.push(UnarmedPlaceholderMatch {
                credential_id: credential_id.clone(),
            });
        }
    }
    // Stable order: callers iterate dialogs by credential_id so the user
    // sees a consistent prompt sequence across reruns of the same request.
    matches.sort_by(|a, b| a.credential_id.cmp(&b.credential_id));
    matches
}

pub(crate) fn inject_headers(header_block: &str, injections: &[CredentialInjection]) -> String {
    let lines: Vec<&str> = header_block.split("\r\n").collect();
    let request_line = lines.first().unwrap_or(&"");

    // Parse method and path from request line (e.g. "GET /api/v1/foo HTTP/1.1").
    // Strip query string and normalize the path (collapse `//`, resolve `..`) so rules
    // are evaluated against the same canonical form as upstream HTTP rule enforcement
    // (see line 137). Without this, a rule like `/repos/**` could be bypassed with
    // `/repos/foo?x=y` or `/foo/../repos/bar`.
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    let method = parts.first().unwrap_or(&"");
    let raw_path = parts.get(1).unwrap_or(&"/");
    let raw_no_query = raw_path.split('?').next().unwrap_or(raw_path);
    let normalized_path = crate::routing::normalize_path(raw_no_query);

    // Filter injections by rules - only inject if rules match (or rules are empty)
    let matching_injections: Vec<&CredentialInjection> = injections
        .iter()
        .filter(|inj| {
            crate::routing::http_request_matches_rules(&inj.rules, method, &normalized_path)
        })
        .collect();

    // Build a set of header names we're injecting (lowercased)
    let inject_names: HashSet<String> = matching_injections
        .iter()
        .map(|inj| inj.header.to_lowercase())
        .collect();

    // Detect HTTP/1.1 upgrade. If the client asked to upgrade we preserve the
    // existing Connection: upgrade line and skip the Connection: close
    // injection — otherwise the upgrade handshake on upstream would fail.
    let is_upgrade = is_upgrade_request(header_block);

    let mut result = vec![request_line.to_string()];

    // Keep existing headers that we're not replacing
    for line in lines.iter().skip(1) {
        if line.is_empty() {
            continue;
        }
        let name = line
            .split(':')
            .next()
            .unwrap_or("")
            .to_lowercase()
            .trim()
            .to_string();
        if inject_names.contains(&name) {
            continue;
        }
        if name == "connection" && !is_upgrade {
            continue;
        }
        result.push(line.to_string());
    }

    // Add injected headers (sanitize CRLF to prevent header injection)
    for inj in matching_injections {
        let sanitized_value = inj.value.replace(['\r', '\n'], "");
        result.push(format!("{}: {sanitized_value}", inj.header));
    }
    if !is_upgrade {
        result.push("Connection: close".to_string());
    }

    result.join("\r\n")
}

/// Rewrite `__lens_cred:<name>__` placeholders in the request line only.
///
/// The request line is the first CRLF-terminated line of the HTTP request
/// head (e.g. `GET /bot<TOKEN>/sendMessage HTTP/1.1`). Headers pass through
/// untouched — a placeholder that lands in a header value must NOT be
/// substituted, because silently swapping secrets into arbitrary headers
/// would leak credentials.
///
/// This is the realization of `type=uriPlaceholder` credential injections
/// (see `CredentialInjection` in `policy_schema.rs`): the agent embeds the
/// placeholder in a URL, the MITM proxy swaps it for the real secret just
/// before forwarding upstream.
pub(crate) fn rewrite_uri_placeholders(head: &str, placeholders: &[(String, String)]) -> String {
    if placeholders.is_empty() {
        return head.to_string();
    }
    let Some(line_end) = head.find("\r\n") else {
        return head.to_string();
    };
    let (line, rest) = head.split_at(line_end);
    let mut rewritten = line.to_string();
    for (placeholder, value) in placeholders {
        if rewritten.contains(placeholder.as_str()) {
            rewritten = rewritten.replace(placeholder.as_str(), value);
        }
    }
    format!("{rewritten}{rest}")
}

/// A rustls cert resolver that always returns the same certified key.
#[derive(Debug)]
pub(crate) struct SingleCertResolver(pub(crate) Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for SingleCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// Connect a fresh TLS session to `target_host` over the given TCP stream.
/// Exposes [`connect_upstream_tls`] to sibling modules so the AWS resign path
/// can reuse the same proxy CA trust chain.
pub(crate) async fn connect_upstream_tls_public(
    upstream: TcpStream,
    target_host: &str,
    extra_ca_certs: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    connect_upstream_tls(upstream, target_host, None, None, extra_ca_certs).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::CredentialInjection;
    use std::time::Duration;

    fn make_test_state_with_placeholder(
        credential_id: &str,
        placeholder: &str,
    ) -> std::sync::Arc<crate::proxy::ProxyState> {
        let (state, _rx) = crate::proxy::tests::test_state();
        state
            .placeholder_index
            .write()
            .unwrap()
            .insert(placeholder.to_string(), credential_id.to_string());
        state
    }

    #[test]
    fn scan_for_unarmed_placeholders_returns_match_when_placeholder_present_in_header() {
        // Pin: an outbound request that still carries a registered
        // placeholder after inject_headers (because no injection was
        // armed for this credential on this domain) trips the scan and
        // tells the caller which credential to gate.
        let state =
            make_test_state_with_placeholder("github", "ghp_LNSPLACEHOLDER0000000000000000000000");
        let header_block = "GET /issues HTTP/1.1\r\nHost: api.github.com\r\n\
                            Authorization: Bearer ghp_LNSPLACEHOLDER0000000000000000000000\r\n\r\n";
        let m = scan_for_unarmed_placeholders(&state, header_block);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].credential_id, "github");
    }

    #[test]
    fn scan_for_unarmed_placeholders_returns_empty_when_no_placeholder_in_header() {
        // Headers carry no registered placeholder — the scan returns
        // empty so the caller proceeds with the normal forwarding path.
        let state =
            make_test_state_with_placeholder("github", "ghp_LNSPLACEHOLDER0000000000000000000000");
        let header_block =
            "GET /healthz HTTP/1.1\r\nHost: api.github.com\r\nUser-Agent: probe\r\n\r\n";
        assert!(scan_for_unarmed_placeholders(&state, header_block).is_empty());
    }

    #[test]
    fn scan_for_unarmed_placeholders_returns_empty_when_index_is_empty() {
        // Pre-policy state: the host hasn't sent a credentials array
        // yet, so placeholder_index is empty. Every request bypasses
        // the gate — keeps boot-time traffic snappy.
        let (state, _rx) = crate::proxy::tests::test_state();
        let header_block = "GET / HTTP/1.1\r\nHost: api.github.com\r\n\r\n";
        assert!(scan_for_unarmed_placeholders(&state, header_block).is_empty());
    }

    #[test]
    fn scan_for_unarmed_placeholders_ignores_empty_placeholder_entries() {
        // Defensive: if a (malformed) policy frame ever populated the
        // index with an empty-string placeholder, we must not match it
        // against every request (str::contains("") == true).
        let (state, _rx) = crate::proxy::tests::test_state();
        state
            .placeholder_index
            .write()
            .unwrap()
            .insert(String::new(), "broken".into());
        let header_block = "GET / HTTP/1.1\r\nHost: api.github.com\r\n\r\n";
        assert!(scan_for_unarmed_placeholders(&state, header_block).is_empty());
    }

    #[test]
    fn scan_for_unarmed_placeholders_finds_match_anywhere_in_header_block() {
        // Placeholders can appear in any header — agent libraries vary.
        // GH SDK uses Authorization; some custom CLIs use X-API-Key.
        // Verify the scan isn't limited to a specific header field.
        let state =
            make_test_state_with_placeholder("openai", "sk-LNSPLACEHOLDER000000000000000000000000");
        let header_block = "POST /v1/chat HTTP/1.1\r\nHost: api.openai.com\r\n\
                            X-Custom: sk-LNSPLACEHOLDER000000000000000000000000\r\n\r\n";
        assert!(!scan_for_unarmed_placeholders(&state, header_block).is_empty());
    }

    #[test]
    fn scan_for_unarmed_placeholders_returns_all_distinct_credentials_in_stable_order() {
        // One request that uses two unarmed credentials must surface both
        // so the caller can gate each independently — otherwise the user
        // sees a dialog for one credential, Allows it, and the request
        // gets 403'd as `policy-frame-missing` for the credential they
        // were never asked about.
        let (state, _rx) = crate::proxy::tests::test_state();
        {
            let mut idx = state.placeholder_index.write().unwrap();
            idx.insert(
                "ghp_LNSPLACEHOLDER0000000000000000000000".into(),
                "github".into(),
            );
            idx.insert(
                "sk-LNSPLACEHOLDER000000000000000000000000".into(),
                "openai".into(),
            );
        }
        let header_block = "POST /multi HTTP/1.1\r\nHost: api.example.com\r\n\
                            Authorization: Bearer ghp_LNSPLACEHOLDER0000000000000000000000\r\n\
                            X-OpenAI-Key: sk-LNSPLACEHOLDER000000000000000000000000\r\n\r\n";
        let m = scan_for_unarmed_placeholders(&state, header_block);
        assert_eq!(m.len(), 2);
        // Sorted by credential_id so dialog ordering is reproducible.
        assert_eq!(m[0].credential_id, "github");
        assert_eq!(m[1].credential_id, "openai");
    }

    #[test]
    fn armed_uri_placeholder_is_substituted_before_scan() {
        // Regression: an already-armed `uriPlaceholder` credential must not
        // re-trip the gate. `mitm_inject_after_accept` substitutes header
        // creds (inject_headers) AND uri creds (rewrite_uri_placeholders)
        // before scanning, so an armed placeholder is gone by scan time. If
        // the uri rewrite ran only at forward time (after the scan), the
        // placeholder would still sit in the request line and re-prompt on
        // every call.
        let placeholder = "tg_LNSPLACEHOLDER0000000000000000000000";
        let state = make_test_state_with_placeholder("telegram", placeholder);
        let header_block =
            format!("GET /bot{placeholder}/sendMessage HTTP/1.1\r\nHost: api.telegram.org\r\n\r\n");

        // Armed: `collect_uri_placeholders` would return this pair for the host.
        let armed = [(placeholder.to_string(), "tg_real_secret".to_string())];
        let header_injected = inject_headers(&header_block, &[]);
        let pre_scan = rewrite_uri_placeholders(&header_injected, &armed);
        assert!(
            scan_for_unarmed_placeholders(&state, &pre_scan).is_empty(),
            "armed URI placeholder must be substituted before the scan: {pre_scan}"
        );

        // Unarmed (no armed mapping yet): the placeholder survives the rewrite
        // and the scan still trips, so the first use is gated.
        let unarmed = rewrite_uri_placeholders(&header_injected, &[]);
        assert_eq!(
            scan_for_unarmed_placeholders(&state, &unarmed).len(),
            1,
            "a first, unarmed URI placeholder use must still trip the gate"
        );
    }

    #[test]
    fn inject_headers_replaces_existing() {
        let headers =
            "GET /api HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: old\r\nAccept: */*";
        let injections = vec![CredentialInjection {
            header: "Authorization".to_string(),
            value: "token ghp_new".to_string(),
            rules: vec![],
        }];
        let result = inject_headers(headers, &injections);
        assert!(result.contains("Authorization: token ghp_new"));
        assert!(!result.contains("Authorization: old"));
        assert!(result.contains("Accept: */*"));
        assert!(result.contains("Connection: close"));
    }

    #[test]
    fn inject_headers_adds_new() {
        let headers = "GET /api HTTP/1.1\r\nHost: api.github.com";
        let injections = vec![CredentialInjection {
            header: "Authorization".to_string(),
            value: "Bearer sk-xxx".to_string(),
            rules: vec![],
        }];
        let result = inject_headers(headers, &injections);
        assert!(result.contains("Authorization: Bearer sk-xxx"));
        assert!(result.contains("Host: api.github.com"));
    }

    #[test]
    fn inject_headers_sanitizes_crlf() {
        let headers = "GET / HTTP/1.1\r\nHost: evil.com";
        let injections = vec![CredentialInjection {
            header: "Authorization".to_string(),
            value: "token abc\r\nEvil: injected".to_string(),
            rules: vec![],
        }];
        let result = inject_headers(headers, &injections);
        assert!(result.contains("Authorization: token abcEvil: injected"));
        assert!(!result.lines().any(|l| l.starts_with("Evil:")));
    }

    #[test]
    fn inject_headers_replaces_connection() {
        let headers = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive";
        let injections = vec![];
        let result = inject_headers(headers, &injections);
        assert!(result.contains("Connection: close"));
        assert!(!result.contains("keep-alive"));
    }

    #[test]
    fn inject_headers_multiple_injections() {
        let headers = "POST /v1/chat HTTP/1.1\r\nHost: api.openai.com";
        let injections = vec![
            CredentialInjection {
                header: "Authorization".to_string(),
                value: "Bearer sk-test".to_string(),
                rules: vec![],
            },
            CredentialInjection {
                header: "X-Custom".to_string(),
                value: "custom-value".to_string(),
                rules: vec![],
            },
        ];
        let result = inject_headers(headers, &injections);
        assert!(result.contains("Authorization: Bearer sk-test"));
        assert!(result.contains("X-Custom: custom-value"));
        assert!(result.contains("Host: api.openai.com"));
    }

    #[test]
    fn inject_headers_respects_path_rules() {
        use crate::policy_schema::HttpRule;

        let headers = "GET /v1/clusters/abc/proxy/api HTTP/1.1\r\nHost: lens.example.com\r\nAuthorization: Bearer lnsc_token";
        // This injection only applies to /v1/projects/*/llm/** paths
        let injections = vec![CredentialInjection {
            header: "Authorization".to_string(),
            value: "Bearer sandbox_token".to_string(),
            rules: vec![HttpRule {
                method: None,
                path: Some("/v1/projects/*/llm/**".to_string()),
            }],
        }];
        let result = inject_headers(headers, &injections);
        // Should NOT inject because path doesn't match rules
        assert!(result.contains("Authorization: Bearer lnsc_token"));
        assert!(!result.contains("sandbox_token"));
    }

    #[test]
    fn inject_headers_injects_when_path_matches_rules() {
        use crate::policy_schema::HttpRule;

        let headers =
            "POST /v1/projects/123/llm/bedrock/us-east-1/invoke HTTP/1.1\r\nHost: lens.example.com";
        // This injection only applies to /v1/projects/*/llm/* paths
        let injections = vec![CredentialInjection {
            header: "Authorization".to_string(),
            value: "Bearer sandbox_token".to_string(),
            rules: vec![HttpRule {
                method: None,
                path: Some("/v1/projects/*/llm/**".to_string()),
            }],
        }];
        let result = inject_headers(headers, &injections);
        // Should inject because path matches rules
        assert!(result.contains("Authorization: Bearer sandbox_token"));
    }

    #[test]
    fn inject_headers_injects_for_global_llm_path() {
        use crate::policy_schema::HttpRule;

        // Global LLM endpoint (auto-resolve project)
        let headers = "POST /v1/llm/bedrock/us-east-1/invoke HTTP/1.1\r\nHost: lens.example.com";
        let injections = vec![CredentialInjection {
            header: "Authorization".to_string(),
            value: "Bearer sandbox_token".to_string(),
            rules: vec![
                HttpRule {
                    method: None,
                    path: Some("/v1/projects/*/llm/**".to_string()),
                },
                HttpRule {
                    method: None,
                    path: Some("/v1/llm/**".to_string()),
                },
            ],
        }];
        let result = inject_headers(headers, &injections);
        // Should inject because /v1/llm/** rule matches
        assert!(result.contains("Authorization: Bearer sandbox_token"));
    }

    #[test]
    fn inject_headers_skips_non_llm_paths_with_llm_rules() {
        use crate::policy_schema::HttpRule;

        // Kubernetes proxy endpoint - should NOT get sandbox token
        let headers = "GET /v1/clusters/abc/proxy/api/v1/nodes HTTP/1.1\r\nHost: lens.example.com\r\nAuthorization: Bearer lnsc_cluster_token";
        let injections = vec![CredentialInjection {
            header: "Authorization".to_string(),
            value: "Bearer sandbox_token".to_string(),
            rules: vec![
                HttpRule {
                    method: None,
                    path: Some("/v1/projects/*/llm/**".to_string()),
                },
                HttpRule {
                    method: None,
                    path: Some("/v1/llm/**".to_string()),
                },
            ],
        }];
        let result = inject_headers(headers, &injections);
        // Should NOT inject - cluster proxy path doesn't match LLM rules
        assert!(result.contains("Authorization: Bearer lnsc_cluster_token"));
        assert!(!result.contains("sandbox_token"));
    }

    #[test]
    fn inject_headers_strips_query_string_before_rule_match() {
        use crate::policy_schema::HttpRule;

        // Exact-path rule must still match when the request carries a query string.
        let headers = "GET /repos/foo?admin=true HTTP/1.1\r\nHost: api.github.com";
        let injections = vec![CredentialInjection {
            header: "Authorization".to_string(),
            value: "Bearer ghp_token".to_string(),
            rules: vec![HttpRule {
                method: None,
                path: Some("/repos/foo".to_string()),
            }],
        }];
        let result = inject_headers(headers, &injections);
        assert!(
            result.contains("Authorization: Bearer ghp_token"),
            "query string should not prevent rule match: {result}"
        );
    }

    #[test]
    fn inject_headers_normalizes_path_before_rule_match() {
        use crate::policy_schema::HttpRule;

        // Path traversal must not trick a narrow `/repos/**` rule into injecting
        // credentials on `/admin/secret`. Normalization resolves `..` first.
        let headers = "GET /repos/foo/../../admin/secret HTTP/1.1\r\nHost: api.github.com";
        let injections = vec![CredentialInjection {
            header: "Authorization".to_string(),
            value: "Bearer ghp_token".to_string(),
            rules: vec![HttpRule {
                method: None,
                path: Some("/repos/**".to_string()),
            }],
        }];
        let result = inject_headers(headers, &injections);
        assert!(
            !result.contains("Bearer ghp_token"),
            "path traversal must not bypass rule scoping: {result}"
        );
    }

    #[test]
    fn inject_headers_case_insensitive_replace() {
        let headers = "GET / HTTP/1.1\r\nauthorization: old-value";
        let injections = vec![CredentialInjection {
            header: "Authorization".to_string(),
            value: "Bearer new-value".to_string(),
            rules: vec![],
        }];
        let result = inject_headers(headers, &injections);
        assert!(result.contains("Authorization: Bearer new-value"));
        assert!(!result.contains("old-value"));
    }

    #[test]
    fn inject_headers_preserves_request_line() {
        let headers = "POST /v1/completions HTTP/1.1\r\nHost: api.openai.com";
        let injections = vec![];
        let result = inject_headers(headers, &injections);
        assert!(result.starts_with("POST /v1/completions HTTP/1.1\r\n"));
    }

    #[test]
    fn rewrite_uri_placeholders_replaces_in_request_line() {
        let head = "GET /bot__lens_cred:tg__/sendMessage HTTP/1.1\r\nHost: api.telegram.org";
        let placeholders = vec![("__lens_cred:tg__".to_string(), "123:ABC".to_string())];
        let result = rewrite_uri_placeholders(head, &placeholders);
        assert!(
            result.starts_with("GET /bot123:ABC/sendMessage HTTP/1.1\r\n"),
            "{result}"
        );
        assert!(
            result.contains("Host: api.telegram.org"),
            "headers preserved: {result}"
        );
    }

    #[test]
    fn rewrite_uri_placeholders_does_not_touch_headers() {
        // Placeholder lives only in a header value — must pass through unchanged.
        let head = "GET /api HTTP/1.1\r\nHost: api.example.com\r\nX-Echo: __lens_cred:secret__";
        let placeholders = vec![(
            "__lens_cred:secret__".to_string(),
            "REAL-SECRET".to_string(),
        )];
        let result = rewrite_uri_placeholders(head, &placeholders);
        assert!(
            result.contains("X-Echo: __lens_cred:secret__"),
            "header value must be untouched: {result}"
        );
        assert!(
            !result.contains("REAL-SECRET"),
            "real credential must not leak into headers: {result}"
        );
    }

    #[test]
    fn rewrite_uri_placeholders_only_request_line_when_both_present() {
        let head = "GET /__lens_cred:t__ HTTP/1.1\r\nX-Echo: __lens_cred:t__";
        let placeholders = vec![("__lens_cred:t__".to_string(), "VAL".to_string())];
        let result = rewrite_uri_placeholders(head, &placeholders);
        assert!(
            result.starts_with("GET /VAL HTTP/1.1\r\n"),
            "request line rewritten: {result}"
        );
        assert!(
            result.contains("X-Echo: __lens_cred:t__"),
            "header occurrence preserved: {result}"
        );
    }

    #[test]
    fn rewrite_uri_placeholders_empty_map_is_noop() {
        let head = "GET /__lens_cred:t__ HTTP/1.1\r\nHost: x";
        let result = rewrite_uri_placeholders(head, &[]);
        assert_eq!(result, head);
    }

    #[test]
    fn rewrite_uri_placeholders_no_match_passes_through() {
        let head = "GET /api HTTP/1.1\r\nHost: x";
        let placeholders = vec![("__lens_cred:t__".to_string(), "VAL".to_string())];
        let result = rewrite_uri_placeholders(head, &placeholders);
        assert_eq!(result, head);
    }

    #[test]
    fn rewrite_uri_placeholders_no_crlf_passes_through() {
        // No CRLF means no recognizable request line; do not attempt rewrite.
        let head = "garbage __lens_cred:t__ no-newline";
        let placeholders = vec![("__lens_cred:t__".to_string(), "VAL".to_string())];
        let result = rewrite_uri_placeholders(head, &placeholders);
        assert_eq!(result, head);
    }

    #[test]
    fn rewrite_uri_placeholders_multiple_in_request_line() {
        let head = "GET /__lens_cred:a__/__lens_cred:b__ HTTP/1.1\r\nHost: x";
        let placeholders = vec![
            ("__lens_cred:a__".to_string(), "AAA".to_string()),
            ("__lens_cred:b__".to_string(), "BBB".to_string()),
        ];
        let result = rewrite_uri_placeholders(head, &placeholders);
        assert!(result.starts_with("GET /AAA/BBB HTTP/1.1\r\n"), "{result}");
    }

    #[test]
    fn rewrite_host_header_strips_authorization() {
        let headers = "GET /api/v1/nodes HTTP/1.1\r\nHost: host.docker.internal\r\nAuthorization: Bearer lens-sandbox-proxy-auth\r\nAccept: application/json";
        let result = rewrite_host_header(headers, "rancher.example.com:443");
        assert!(result.contains("Host: rancher.example.com:443"), "{result}");
        assert!(
            !result.contains("Authorization"),
            "dummy bearer token should be stripped: {result}"
        );
        assert!(result.contains("Accept: application/json"), "{result}");
    }

    #[test]
    fn rewrite_host_header_preserves_upgrade_connection() {
        let headers = "GET /api/v1/pods/exec HTTP/1.1\r\nHost: host.docker.internal\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\nAuthorization: Bearer lens-sandbox-proxy-auth";
        let result = rewrite_host_header(headers, "rancher.example.com:443");
        assert!(
            result.contains("Connection: Upgrade"),
            "upgrade Connection should be preserved: {result}"
        );
        assert!(
            !result.contains("Connection: close"),
            "should not add Connection: close for upgrades: {result}"
        );
        assert!(
            !result.contains("Authorization"),
            "dummy bearer token should be stripped even for upgrades: {result}"
        );
    }

    /// Build a TLS server config using a cert from the ephemeral CA for the given hostname.
    fn test_tls_server_config(ca: &EphemeralCa, hostname: &str) -> Arc<rustls::ServerConfig> {
        let certified_key = ca.certified_key_for_domain(hostname).unwrap();
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertResolver(certified_key)));
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }

    /// Build a root store that trusts only the ephemeral CA (for the client side of tests).
    fn ca_root_store(ca: &EphemeralCa) -> rustls::RootCertStore {
        let mut store = rustls::RootCertStore::empty();
        let pem = ca.ca_cert_pem();
        let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_slice_iter(pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        for cert in certs {
            store.add(cert).unwrap();
        }
        store
    }

    /// Shared harness for MITM integration tests.
    /// Spins up: TLS upstream server ← upstream TLS ← MITM ← client TLS.
    /// Returns (upstream_headers, client_response, audit_events).
    async fn run_mitm_harness(
        injections: Vec<CredentialInjection>,
        request: &'static [u8],
        is_tunnel: bool,
    ) -> (String, String, Vec<serde_json::Value>) {
        run_mitm_harness_with_rules(injections, vec![], request, is_tunnel).await
    }

    async fn run_mitm_harness_with_placeholders(
        injections: Vec<CredentialInjection>,
        placeholder_map: Vec<(String, String)>,
        request: &'static [u8],
        is_tunnel: bool,
    ) -> (String, String, Vec<serde_json::Value>) {
        run_mitm_harness_full(injections, vec![], placeholder_map, request, is_tunnel).await
    }

    async fn run_mitm_harness_with_rules(
        injections: Vec<CredentialInjection>,
        http_rules: Vec<HttpRule>,
        request: &'static [u8],
        is_tunnel: bool,
    ) -> (String, String, Vec<serde_json::Value>) {
        run_mitm_harness_full(injections, http_rules, vec![], request, is_tunnel).await
    }

    async fn run_mitm_harness_full(
        injections: Vec<CredentialInjection>,
        http_rules: Vec<HttpRule>,
        placeholder_map: Vec<(String, String)>,
        request: &'static [u8],
        is_tunnel: bool,
    ) -> (String, String, Vec<serde_json::Value>) {
        use tokio::net::TcpListener;

        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        let ca = EphemeralCa::new().unwrap();
        let hostname = "test.example.com";

        // TLS upstream server: reads HTTP request headers, sends 200 response.
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let server_config = test_tls_server_config(&ca, hostname);

        let (state, mut audit_rx) = crate::proxy::tests::test_state();
        let audit_tx_opt = state.audit_tx.lock().unwrap().clone();

        let upstream_handle = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let acceptor = TlsAcceptor::from(server_config);
            let mut tls = acceptor.accept(stream).await.unwrap();

            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                let n = tls.read(&mut byte).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.push(byte[0]);
                if buf.len() >= 4 && buf[buf.len() - 4..] == *b"\r\n\r\n" {
                    break;
                }
            }
            let headers = String::from_utf8(buf).unwrap();

            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            tls.shutdown().await.ok();
            headers
        });

        let upstream_stream = TcpStream::connect(upstream_addr).await.unwrap();

        // Client side
        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let root_store = ca_root_store(&ca);

        let client_handle = tokio::spawn(async move {
            let stream = TcpStream::connect(client_addr).await.unwrap();
            let client_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(client_config));
            let server_name = ServerName::try_from(hostname.to_string()).unwrap();
            let mut tls = connector.connect(server_name, stream).await.unwrap();

            tls.write_all(request).await.unwrap();

            let mut response = Vec::new();
            let _ = tls.read_to_end(&mut response).await;
            String::from_utf8(response).unwrap()
        });

        // Run MITM in the middle: accept client TLS + inject, then connect upstream
        let (client_stream, _) = client_listener.accept().await.unwrap();
        let test_actor =
            crate::peer_process::ActorContext::resolve("10.0.0.5:44000".parse().unwrap());
        let test_ctx = MitmContext {
            injections: &injections,
            http_rules: &http_rules,
            ca: &ca,
            audit_tx: &audit_tx_opt,
            extra_ca_certs: &[],
            placeholder_map: &placeholder_map,
            state: &state,
            match_host: hostname,
            actor: &test_actor,
        };
        let mitm_server_config = build_ephemeral_server_config(&ca, hostname).unwrap();
        let acceptor = TlsAcceptor::from(mitm_server_config);
        let tls_client_stream = acceptor.accept(client_stream).await.unwrap();
        let mitm_result =
            mitm_inject_after_accept(tls_client_stream, hostname, &test_ctx, is_tunnel).await;

        // If MITM denied the request (HTTP rules), collect audit events and return
        let (tls_client, modified, meta) = match mitm_result {
            Ok(v) => v,
            Err(e) => {
                let err_msg = e.to_string();
                // Drain audit events
                let mut audit_events = Vec::new();
                while let Ok(msg) = audit_rx.try_recv() {
                    audit_events.push(serde_json::from_str(&msg).unwrap());
                }
                // Wait for client to receive the 403
                let client_response = client_handle.await.unwrap();
                return (err_msg, client_response, audit_events);
            }
        };

        let ca_root_store = ca_root_store(&ca);
        let mut tls_upstream =
            connect_upstream_tls(upstream_stream, hostname, Some(ca_root_store), None, &[])
                .await
                .unwrap();

        tls_upstream.write_all(modified.as_bytes()).await.unwrap();
        tls_upstream.write_all(b"\r\n\r\n").await.unwrap();
        // Drive the production relay so this integration harness exercises
        // forward_response_with_close (response rewrite + explicit shutdown
        // + bounded request body forwarding), not the legacy
        // `copy_bidirectional` path.
        if let Err(e) = forward_or_bridge(tls_client, tls_upstream, &meta).await {
            let msg = e.to_string();
            assert!(
                msg.contains("close_notify")
                    || msg.contains("closed")
                    || msg.contains("broken pipe"),
                "unexpected forward_or_bridge error: {msg}"
            );
        }

        let upstream_headers = upstream_handle.await.unwrap();
        let client_response = client_handle.await.unwrap();

        let mut audit_events = Vec::new();
        while let Ok(msg) = audit_rx.try_recv() {
            audit_events.push(serde_json::from_str(&msg).unwrap());
        }

        (upstream_headers, client_response, audit_events)
    }

    #[tokio::test]
    async fn mitm_tunnel_injects_and_replaces_header() {
        let (headers, response, audits) = run_mitm_harness(
            vec![CredentialInjection {
                header: "x-api-key".to_string(),
                value: "secret-injected-key".to_string(),
                rules: vec![],
            }],
            b"GET /api/user HTTP/1.1\r\nHost: test.example.com\r\nx-api-key: old-key\r\n\r\n",
            true,
        )
        .await;

        assert!(
            headers.contains("x-api-key: secret-injected-key"),
            "{headers}"
        );
        assert!(!headers.contains("old-key"), "{headers}");
        assert!(headers.contains("Host: test.example.com"), "{headers}");
        assert!(headers.contains("Connection: close"), "{headers}");
        assert!(response.contains("200 OK"), "{response}");
        assert_eq!(audits[0]["metadata"]["tunnel"], true);
    }

    #[tokio::test]
    async fn mitm_direct_sets_tunnel_false_in_audit() {
        let (_headers, _response, audits) = run_mitm_harness(
            vec![CredentialInjection {
                header: "Authorization".to_string(),
                value: "Bearer sk-test".to_string(),
                rules: vec![],
            }],
            b"GET / HTTP/1.1\r\nHost: test.example.com\r\n\r\n",
            false,
        )
        .await;

        assert_eq!(audits[0]["metadata"]["tunnel"], false);
        assert_eq!(audits[0]["metadata"]["mitm"], true);
    }

    #[tokio::test]
    async fn mitm_multiple_injections() {
        let (headers, _response, _audits) = run_mitm_harness(
            vec![
                CredentialInjection {
                    header: "x-api-key".to_string(),
                    value: "key-123".to_string(),
                    rules: vec![],
                },
                CredentialInjection {
                    header: "Authorization".to_string(),
                    value: "Bearer token-456".to_string(),
                    rules: vec![],
                },
            ],
            b"POST /v1/query HTTP/1.1\r\nHost: test.example.com\r\nAuthorization: old\r\n\r\n",
            true,
        )
        .await;

        assert!(headers.contains("x-api-key: key-123"), "{headers}");
        assert!(
            headers.contains("Authorization: Bearer token-456"),
            "{headers}"
        );
        assert!(!headers.contains("Authorization: old"), "{headers}");
        assert!(
            headers.starts_with("POST /v1/query HTTP/1.1\r\n"),
            "{headers}"
        );
    }

    #[tokio::test]
    async fn mitm_http_rules_allow_matching_request() {
        let rules = vec![HttpRule {
            method: Some("GET".to_string()),
            path: Some("/api/v1/*".to_string()),
        }];
        let (_headers, response, audits) = run_mitm_harness_with_rules(
            vec![],
            rules,
            b"GET /api/v1/download HTTP/1.1\r\nHost: test.example.com\r\n\r\n",
            true,
        )
        .await;

        assert!(response.contains("200 OK"), "expected 200, got: {response}");
        assert_eq!(audits[0]["result"], "success");
    }

    #[tokio::test]
    async fn mitm_http_rules_deny_non_matching_request() {
        let rules = vec![HttpRule {
            method: Some("GET".to_string()),
            path: Some("/api/v1/*".to_string()),
        }];
        let (_err, response, audits) = run_mitm_harness_with_rules(
            vec![],
            rules,
            b"POST /api/v1/upload HTTP/1.1\r\nHost: test.example.com\r\n\r\n",
            true,
        )
        .await;

        assert!(
            response.contains("403 Forbidden"),
            "expected 403, got: {response}"
        );
        assert_eq!(audits[0]["result"], "failure");
        assert_eq!(audits[0]["status_code"], 403);
        assert_eq!(audits[0]["metadata"]["http_rule_denied"], true);
        assert_eq!(audits[0]["method"], "POST");
        assert_eq!(audits[0]["host"], "test.example.com");
        assert_eq!(audits[0]["path"], "/api/v1/upload");
    }

    #[tokio::test]
    async fn mitm_http_rules_deny_path_traversal() {
        // Rule allows /api/** only — path traversal via /../ must not escape
        let rules = vec![HttpRule {
            method: None,
            path: Some("/api/**".to_string()),
        }];
        let (_err, response, audits) = run_mitm_harness_with_rules(
            vec![],
            rules,
            b"GET /api/v1/../../admin/secret HTTP/1.1\r\nHost: test.example.com\r\n\r\n",
            true,
        )
        .await;

        assert!(
            response.contains("403 Forbidden"),
            "path traversal should be denied after normalization, got: {response}"
        );
        assert_eq!(audits[0]["result"], "failure");
    }

    #[tokio::test]
    async fn mitm_http_rules_ignore_query_string() {
        let rules = vec![HttpRule {
            method: Some("GET".to_string()),
            path: Some("/api/v1/*".to_string()),
        }];
        let (_headers, response, audits) = run_mitm_harness_with_rules(
            vec![],
            rules,
            b"GET /api/v1/download?format=zip HTTP/1.1\r\nHost: test.example.com\r\n\r\n",
            true,
        )
        .await;

        assert!(
            response.contains("200 OK"),
            "query string should be stripped before matching, got: {response}"
        );
        assert_eq!(audits[0]["result"], "success");
    }

    #[tokio::test]
    async fn mitm_http_rules_with_credentials() {
        let rules = vec![HttpRule {
            method: Some("GET".to_string()),
            path: None,
        }];
        let (headers, response, _audits) = run_mitm_harness_with_rules(
            vec![CredentialInjection {
                header: "Authorization".to_string(),
                value: "Bearer my-token".to_string(),
                rules: vec![],
            }],
            rules,
            b"GET /anything HTTP/1.1\r\nHost: test.example.com\r\n\r\n",
            true,
        )
        .await;

        assert!(response.contains("200 OK"), "expected 200, got: {response}");
        assert!(
            headers.contains("Authorization: Bearer my-token"),
            "credentials should be injected: {headers}"
        );
    }

    #[tokio::test]
    async fn mitm_placeholder_rewrites_uri() {
        let (headers, response, _audits) = run_mitm_harness_with_placeholders(
            vec![],
            vec![(
                "__lens_cred:telegram-bot-token__".to_string(),
                "123456:ABC-DEF".to_string(),
            )],
            b"GET /bot__lens_cred:telegram-bot-token__/sendMessage HTTP/1.1\r\nHost: api.telegram.org\r\n\r\n",
            false,
        )
        .await;

        assert!(
            headers.contains("GET /bot123456:ABC-DEF/sendMessage HTTP/1.1"),
            "placeholder should be rewritten in URI: {headers}"
        );
        assert!(
            !headers.contains("__lens_cred:"),
            "placeholder pattern should not reach upstream: {headers}"
        );
        assert!(response.contains("200 OK"), "expected 200, got: {response}");
    }

    #[tokio::test]
    async fn mitm_placeholder_no_rewrite_when_absent() {
        let (headers, response, _audits) = run_mitm_harness_with_placeholders(
            vec![],
            vec![(
                "__lens_cred:telegram-bot-token__".to_string(),
                "123456:ABC-DEF".to_string(),
            )],
            b"GET /api/v1/chat HTTP/1.1\r\nHost: api.openai.com\r\n\r\n",
            false,
        )
        .await;

        assert!(
            headers.contains("GET /api/v1/chat HTTP/1.1"),
            "URI without placeholder should pass through unchanged: {headers}"
        );
        assert!(
            !headers.contains("123456:ABC-DEF"),
            "real credential should not appear when placeholder is absent: {headers}"
        );
        assert!(response.contains("200 OK"), "expected 200, got: {response}");
    }

    #[tokio::test]
    async fn mitm_placeholder_does_not_rewrite_headers() {
        // Placeholders in header values must pass through untouched.
        // uriPlaceholder is scoped to the request line; rewriting header
        // values would leak real credentials to arbitrary headers the agent
        // happens to set.
        let (headers, response, _audits) = run_mitm_harness_with_placeholders(
            vec![],
            vec![(
                "__lens_cred:telegram-bot-token__".to_string(),
                "123456:ABC-DEF".to_string(),
            )],
            b"GET /api/v1/chat HTTP/1.1\r\nHost: api.example.com\r\nX-Echo: __lens_cred:telegram-bot-token__\r\n\r\n",
            false,
        )
        .await;

        assert!(
            headers.contains("X-Echo: __lens_cred:telegram-bot-token__"),
            "placeholder in header value should NOT be rewritten: {headers}"
        );
        assert!(
            !headers.contains("123456:ABC-DEF"),
            "real credential must not leak into headers: {headers}"
        );
        assert!(response.contains("200 OK"), "expected 200, got: {response}");
    }

    #[tokio::test]
    async fn mitm_placeholder_rewrites_uri_but_not_headers_when_both_present() {
        // When the placeholder appears in both the URI and a header value,
        // only the URI occurrence gets rewritten.
        let (headers, response, _audits) = run_mitm_harness_with_placeholders(
            vec![],
            vec![(
                "__lens_cred:telegram-bot-token__".to_string(),
                "123456:ABC-DEF".to_string(),
            )],
            b"GET /bot__lens_cred:telegram-bot-token__/sendMessage HTTP/1.1\r\nHost: api.telegram.org\r\nX-Echo: __lens_cred:telegram-bot-token__\r\n\r\n",
            false,
        )
        .await;

        assert!(
            headers.contains("GET /bot123456:ABC-DEF/sendMessage HTTP/1.1"),
            "URI placeholder should be rewritten: {headers}"
        );
        assert!(
            headers.contains("X-Echo: __lens_cred:telegram-bot-token__"),
            "header placeholder must NOT be rewritten: {headers}"
        );
        assert!(response.contains("200 OK"), "expected 200, got: {response}");
    }

    #[tokio::test]
    async fn mitm_empty_placeholder_map_no_rewrite() {
        let (headers, response, _audits) = run_mitm_harness_with_placeholders(
            vec![],
            vec![],
            b"GET /bot__lens_cred:fake__/test HTTP/1.1\r\nHost: example.com\r\n\r\n",
            false,
        )
        .await;

        assert!(
            headers.contains("__lens_cred:fake__"),
            "with empty placeholder_map, no rewriting should occur: {headers}"
        );
        assert!(response.contains("200 OK"), "expected 200, got: {response}");
    }

    // --- Post-rewrite HTTP rule re-validation tests ---
    // These prove that if a credential value produces a different normalized
    // path than the placeholder, HTTP rules are re-checked against the
    // rewritten URI to prevent policy bypass.

    #[tokio::test]
    async fn mitm_placeholder_rewrite_passes_revalidation_with_normal_credential() {
        // Rule allows /bot/*/sendMessage. Normal credential stays within the
        // allowed path — should pass both pre- and post-rewrite checks.
        let rules = vec![HttpRule {
            method: Some("GET".into()),
            path: Some("/bot/*/sendMessage".into()),
        }];
        let placeholders = vec![("__lens_cred:tg__".to_string(), "123456:ABC-DEF".to_string())];
        let (headers, response, _audits) = run_mitm_harness_full(
            vec![],
            rules,
            placeholders,
            b"GET /bot/__lens_cred:tg__/sendMessage HTTP/1.1\r\nHost: api.telegram.org\r\n\r\n",
            false,
        )
        .await;

        assert!(
            headers.contains("GET /bot/123456:ABC-DEF/sendMessage HTTP/1.1"),
            "rewritten path should reach upstream: {headers}"
        );
        assert!(response.contains("200 OK"), "expected 200, got: {response}");
    }

    #[tokio::test]
    async fn mitm_placeholder_rewrite_denied_when_credential_causes_path_traversal() {
        // Rule allows /bot/*/sendMessage. Credential value contains /../
        // which, after normalization, produces a path that no longer matches
        // the rule — the post-rewrite re-validation must deny this.
        let rules = vec![HttpRule {
            method: Some("GET".into()),
            path: Some("/bot/*/sendMessage".into()),
        }];
        let placeholders = vec![(
            "__lens_cred:tg__".to_string(),
            "evil/../../admin".to_string(),
        )];
        let (_headers, _response, audits) = run_mitm_harness_full(
            vec![],
            rules,
            placeholders,
            b"GET /bot/__lens_cred:tg__/sendMessage HTTP/1.1\r\nHost: api.telegram.org\r\n\r\n",
            false,
        )
        .await;

        // The request should be denied — check audit trail for a 403
        let denied = audits
            .iter()
            .find(|a| a["status_code"] == 403 && a["metadata"]["rewritten_path_denied"] == true);
        assert!(
            denied.is_some(),
            "rewritten path with traversal should be denied by re-validation: {audits:?}"
        );
        let denied = denied.unwrap();
        assert_eq!(denied["method"], "GET");
        assert_eq!(denied["host"], "test.example.com");
        assert_eq!(denied["path"], "/bot/__lens_cred:tg__/sendMessage");
    }

    #[test]
    fn inject_response_connection_close_replaces_keep_alive() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: keep-alive\r\nContent-Length: 5\r\n\r\n";
        let result = inject_response_connection_close(response);
        let s = String::from_utf8(result).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"), "{s}");
        assert!(s.contains("Connection: close\r\n"), "{s}");
        assert!(!s.to_ascii_lowercase().contains("keep-alive"), "{s}");
        assert!(s.contains("Content-Type: application/json\r\n"), "{s}");
        assert!(s.contains("Content-Length: 5\r\n"), "{s}");
        assert!(s.ends_with("\r\n\r\n"), "{s}");
    }

    #[test]
    fn inject_response_connection_close_adds_when_missing() {
        let response = b"HTTP/1.1 204 No Content\r\nDate: Mon, 01 Jan 2024 00:00:00 GMT\r\n\r\n";
        let result = inject_response_connection_close(response);
        let s = String::from_utf8(result).unwrap();
        assert!(s.starts_with("HTTP/1.1 204 No Content\r\n"), "{s}");
        assert!(s.contains("Connection: close\r\n"), "{s}");
        assert!(s.ends_with("\r\n\r\n"), "{s}");
    }

    #[test]
    fn inject_response_connection_close_case_insensitive_header_match() {
        let response = b"HTTP/1.1 200 OK\r\ncOnNeCtIoN: Keep-Alive\r\n\r\n";
        let result = inject_response_connection_close(response);
        let s = String::from_utf8(result).unwrap();
        assert!(s.contains("Connection: close\r\n"), "{s}");
        // The original mixed-case Connection line must be gone
        assert!(!s.contains("cOnNeCtIoN"), "{s}");
        assert!(!s.to_ascii_lowercase().contains("keep-alive"), "{s}");
    }

    #[test]
    fn inject_response_connection_close_preserves_status_line_with_reason() {
        let response = b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 60\r\n\r\n";
        let result = inject_response_connection_close(response);
        let s = String::from_utf8(result).unwrap();
        assert!(s.starts_with("HTTP/1.1 503 Service Unavailable\r\n"), "{s}");
        assert!(s.contains("Retry-After: 60\r\n"), "{s}");
        assert!(s.contains("Connection: close\r\n"), "{s}");
    }

    #[test]
    fn is_upgrade_request_detects_websocket() {
        let req =
            "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        assert!(is_upgrade_request(req));
    }

    #[test]
    fn is_upgrade_request_case_insensitive() {
        let req = "GET /ws HTTP/1.1\r\nConnection: keep-alive, UPGRADE\r\n\r\n";
        assert!(is_upgrade_request(req));
    }

    #[test]
    fn is_upgrade_request_false_for_normal_request() {
        let req = "GET /api HTTP/1.1\r\nHost: api.example.com\r\nAccept: */*\r\nConnection: close\r\n\r\n";
        assert!(!is_upgrade_request(req));
    }

    #[tokio::test]
    async fn read_until_double_crlf_returns_full_header_block() {
        let bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nbody-after";
        let mut cursor = std::io::Cursor::new(&bytes[..]);
        let result = read_until_double_crlf(&mut cursor).await.unwrap();
        assert_eq!(result, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    }

    #[tokio::test]
    async fn read_until_double_crlf_errors_on_eof_before_terminator() {
        let bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n";
        let mut cursor = std::io::Cursor::new(&bytes[..]);
        let err = read_until_double_crlf(&mut cursor).await.unwrap_err();
        assert!(err.to_string().contains("upstream closed"), "{err}");
    }

    #[test]
    fn parse_status_code_extracts_code() {
        assert_eq!(parse_status_code(b"HTTP/1.1 200 OK\r\n\r\n"), Some(200));
        assert_eq!(
            parse_status_code(b"HTTP/1.1 100 Continue\r\n\r\n"),
            Some(100)
        );
        assert_eq!(
            parse_status_code(b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 60\r\n\r\n"),
            Some(503),
        );
    }

    #[test]
    fn parse_status_code_handles_malformed_input() {
        assert_eq!(parse_status_code(b""), None);
        assert_eq!(parse_status_code(b"garbage"), None);
        assert_eq!(parse_status_code(b"HTTP/1.1\r\n\r\n"), None);
    }

    #[test]
    fn inject_response_connection_close_preserves_non_utf8_bytes() {
        // Construct a Set-Cookie header value with raw 0x80–0xFF bytes that
        // are NOT valid UTF-8. The previous String::from_utf8_lossy path
        // would have replaced these with U+FFFD; the byte-level path must
        // preserve them unchanged.
        let mut response: Vec<u8> = Vec::new();
        response.extend_from_slice(b"HTTP/1.1 200 OK\r\nSet-Cookie: token=");
        response.extend_from_slice(&[0x80, 0xFE, 0xC3, 0x28]); // intentionally invalid UTF-8
        response.extend_from_slice(b"\r\nConnection: keep-alive\r\n\r\n");

        let result = inject_response_connection_close(&response);

        // Connection: close must be present, keep-alive gone.
        assert!(
            result
                .windows(b"Connection: close".len())
                .any(|w| w.eq_ignore_ascii_case(b"Connection: close"))
        );
        assert!(
            !result
                .windows(b"keep-alive".len())
                .any(|w| w.eq_ignore_ascii_case(b"keep-alive"))
        );
        // The raw bytes must round-trip exactly.
        assert!(
            result.windows(4).any(|w| w == [0x80, 0xFE, 0xC3, 0x28]),
            "non-UTF-8 cookie bytes were mutated: {result:?}"
        );
    }

    #[tokio::test]
    async fn forward_response_with_close_rewrites_keep_alive() {
        use tokio::io::AsyncWriteExt;

        let (mut client_outer, mut client_inner) = tokio::io::duplex(8192);
        let (mut upstream_outer, mut upstream_inner) = tokio::io::duplex(8192);

        let task = tokio::spawn(async move {
            forward_response_with_close(
                &mut client_inner,
                &mut upstream_inner,
                RequestBodyMode::None,
            )
            .await
        });

        // Upstream returns a keep-alive response with body.
        upstream_outer
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: keep-alive\r\nContent-Length: 13\r\n\r\n{\"ok\":true}\n",
            )
            .await
            .unwrap();
        // Drop upstream end so the body copy stage sees EOF.
        drop(upstream_outer);

        let mut forwarded = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut client_outer, &mut forwarded)
            .await
            .unwrap();

        let s = String::from_utf8(forwarded).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"), "{s}");
        assert!(s.contains("Connection: close\r\n"), "{s}");
        assert!(!s.to_ascii_lowercase().contains("keep-alive"), "{s}");
        assert!(s.contains("Content-Type: application/json\r\n"), "{s}");
        assert!(s.contains("Content-Length: 13\r\n"), "{s}");
        assert!(s.ends_with("{\"ok\":true}\n"), "{s}");

        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn forward_response_with_close_passes_through_1xx_then_rewrites_final() {
        use tokio::io::AsyncWriteExt;

        let (mut client_outer, mut client_inner) = tokio::io::duplex(8192);
        let (mut upstream_outer, mut upstream_inner) = tokio::io::duplex(8192);

        let task = tokio::spawn(async move {
            forward_response_with_close(
                &mut client_inner,
                &mut upstream_inner,
                RequestBodyMode::None,
            )
            .await
        });

        // Upstream sends 100 Continue, then 103 Early Hints, then the final 200.
        upstream_outer
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .unwrap();
        upstream_outer
            .write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n")
            .await
            .unwrap();
        upstream_outer
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
        drop(upstream_outer);

        let mut forwarded = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut client_outer, &mut forwarded)
            .await
            .unwrap();
        let s = String::from_utf8(forwarded).unwrap();

        // 1xx interim responses are forwarded verbatim — no Connection: close.
        assert!(s.starts_with("HTTP/1.1 100 Continue\r\n\r\n"), "{s}");
        assert!(s.contains("HTTP/1.1 103 Early Hints\r\n"), "{s}");
        assert!(s.contains("Link: </style.css>; rel=preload\r\n"), "{s}");
        // Final 200 response gets Connection: close injected and body forwarded.
        let final_idx = s.find("HTTP/1.1 200 OK").expect("final response");
        let tail = &s[final_idx..];
        assert!(tail.contains("Connection: close\r\n"), "{tail}");
        assert!(tail.ends_with("ok"), "{tail}");

        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn forward_response_with_close_forwards_request_body_to_upstream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut client_outer, mut client_inner) = tokio::io::duplex(8192);
        let (mut upstream_outer, mut upstream_inner) = tokio::io::duplex(8192);

        let body = b"POST body bytes that the upstream should observe verbatim";
        let body_len = body.len() as u64;

        let task = tokio::spawn(async move {
            forward_response_with_close(
                &mut client_inner,
                &mut upstream_inner,
                RequestBodyMode::Fixed(body_len),
            )
            .await
        });

        // Client sends a request body. The MITM is supposed to forward it to
        // the upstream concurrently with response handling.
        client_outer.write_all(body).await.unwrap();

        // Read what the upstream actually got — should be exactly `body`.
        let mut received = vec![0u8; body.len()];
        let mut total = 0;
        while total < body.len() {
            let n = upstream_outer.read(&mut received[total..]).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }
        assert_eq!(&received[..total], body);

        // Once upstream has the body, send the response back.
        upstream_outer
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        drop(upstream_outer);

        let mut forwarded = Vec::new();
        client_outer.read_to_end(&mut forwarded).await.unwrap();
        let s = String::from_utf8(forwarded).unwrap();
        assert!(s.contains("Connection: close\r\n"), "{s}");

        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn forward_response_with_close_shuts_down_client_after_response() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut client_outer, mut client_inner) = tokio::io::duplex(8192);
        let (mut upstream_outer, mut upstream_inner) = tokio::io::duplex(8192);

        let task = tokio::spawn(async move {
            forward_response_with_close(
                &mut client_inner,
                &mut upstream_inner,
                RequestBodyMode::None,
            )
            .await
        });

        upstream_outer
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await
            .unwrap();
        drop(upstream_outer);

        // After the response is forwarded, the MITM must shut down the
        // client side. read_to_end should observe a clean EOF — without the
        // explicit shutdown, this would hang waiting for more data.
        let mut forwarded = Vec::new();
        client_outer.read_to_end(&mut forwarded).await.unwrap();

        let s = String::from_utf8(forwarded).unwrap();
        assert!(s.starts_with("HTTP/1.1 204 No Content\r\n"), "{s}");
        assert!(s.contains("Connection: close\r\n"), "{s}");

        task.await.unwrap().unwrap();
    }

    // ----------------------------------------------------------------------
    // Body-mode parsing
    // ----------------------------------------------------------------------

    #[test]
    fn determine_body_mode_get_with_no_framing_is_none() {
        let req = "GET /api HTTP/1.1\r\nHost: x\r\nAccept: */*\r\n\r\n";
        assert_eq!(determine_body_mode(req, "GET"), RequestBodyMode::None);
    }

    #[test]
    fn determine_body_mode_post_with_content_length() {
        let req = "POST /api HTTP/1.1\r\nHost: x\r\nContent-Length: 42\r\n\r\n";
        assert_eq!(determine_body_mode(req, "POST"), RequestBodyMode::Fixed(42));
    }

    #[test]
    fn determine_body_mode_chunked_takes_precedence_over_content_length() {
        let req = "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 99\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(determine_body_mode(req, "POST"), RequestBodyMode::Chunked);
    }

    #[test]
    fn determine_body_mode_chunked_case_insensitive() {
        let req = "POST /upload HTTP/1.1\r\nTransfer-Encoding: CHUNKED\r\n\r\n";
        assert_eq!(determine_body_mode(req, "POST"), RequestBodyMode::Chunked);
    }

    #[test]
    fn determine_body_mode_post_without_framing_treated_as_no_body() {
        // RFC allows servers to reject; we err on the safe side and don't
        // pump indefinite bytes from the client into upstream.
        let req = "POST /api HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(determine_body_mode(req, "POST"), RequestBodyMode::None);
    }

    // ----------------------------------------------------------------------
    // Bounded request body forwarding
    // ----------------------------------------------------------------------

    #[tokio::test]
    async fn forward_response_with_close_does_not_forward_extra_bytes_after_fixed_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut client_outer, mut client_inner) = tokio::io::duplex(8192);
        let (mut upstream_outer, mut upstream_inner) = tokio::io::duplex(8192);

        let body = b"first request body";
        let body_len = body.len() as u64;

        // The (malicious) client sends the legitimate body PLUS a pipelined
        // second request. The bounded forwarder must stop after the first
        // body — anything after must NOT reach upstream.
        let leaked = b"POST /admin HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut combined = Vec::new();
        combined.extend_from_slice(body);
        combined.extend_from_slice(leaked);

        let task = tokio::spawn(async move {
            forward_response_with_close(
                &mut client_inner,
                &mut upstream_inner,
                RequestBodyMode::Fixed(body_len),
            )
            .await
        });

        client_outer.write_all(&combined).await.unwrap();

        // Drain what upstream actually sees, with a short timeout — we
        // expect exactly `body` to come through and *no* trailing bytes
        // from the pipelined request. After body_len bytes the forwarder
        // parks, so further reads block indefinitely; the timeout is the
        // signal that the bounded forwarder did its job.
        let mut buf = vec![0u8; (body_len as usize) + 64];
        let mut total = 0;
        loop {
            let res = tokio::time::timeout(
                std::time::Duration::from_millis(200),
                upstream_outer.read(&mut buf[total..]),
            )
            .await;
            match res {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    total += n;
                    if total >= buf.len() {
                        break;
                    }
                }
                Ok(Err(_)) | Err(_) => break,
            }
        }

        assert_eq!(
            &buf[..total],
            body,
            "MITM forwarded {total} bytes; expected exactly {body_len} (the bounded body). Extra bytes mean a pipelined second request leaked through."
        );

        // Send a response so the spawned task can complete.
        upstream_outer
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        drop(upstream_outer);
        let mut _client_response = Vec::new();
        client_outer
            .read_to_end(&mut _client_response)
            .await
            .unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn forward_response_with_close_no_body_request_does_not_forward_anything() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut client_outer, mut client_inner) = tokio::io::duplex(8192);
        let (mut upstream_outer, mut upstream_inner) = tokio::io::duplex(8192);

        let task = tokio::spawn(async move {
            forward_response_with_close(
                &mut client_inner,
                &mut upstream_inner,
                RequestBodyMode::None,
            )
            .await
        });

        // Malicious client tries to pipeline a second request through the
        // tunnel. A GET-style "no body" mode must not forward any of it.
        let leaked = b"POST /admin HTTP/1.1\r\nHost: x\r\n\r\n";
        client_outer.write_all(leaked).await.unwrap();

        // Read whatever upstream got. It should be 0 bytes.
        let mut buf = vec![0u8; 256];
        let n = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            upstream_outer.read(&mut buf),
        )
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or(0);
        assert_eq!(
            n,
            0,
            "upstream received {n} bytes from a no-body request: {:?}",
            &buf[..n]
        );

        // Send a response so the task can complete.
        upstream_outer
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await
            .unwrap();
        drop(upstream_outer);
        let mut _resp = Vec::new();
        client_outer.read_to_end(&mut _resp).await.unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn forward_response_with_close_chunked_stops_at_terminator() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut client_outer, mut client_inner) = tokio::io::duplex(8192);
        let (mut upstream_outer, mut upstream_inner) = tokio::io::duplex(8192);

        // Two chunks of 5 bytes each, then the 0-chunk terminator.
        let chunked_body = b"5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n".to_vec();
        // Plus a malicious pipelined second request — chunked parser must
        // stop right after the 0-chunk terminator.
        let leaked = b"POST /admin HTTP/1.1\r\nHost: x\r\n\r\n";

        let task = tokio::spawn(async move {
            forward_response_with_close(
                &mut client_inner,
                &mut upstream_inner,
                RequestBodyMode::Chunked,
            )
            .await
        });

        let mut combined = chunked_body.clone();
        combined.extend_from_slice(leaked);
        client_outer.write_all(&combined).await.unwrap();

        // Drain upstream, with a bounded read so we don't block forever.
        let mut buf = vec![0u8; 1024];
        let mut total = 0;
        loop {
            let res = tokio::time::timeout(
                std::time::Duration::from_millis(300),
                upstream_outer.read(&mut buf[total..]),
            )
            .await;
            match res {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => total += n,
                Ok(Err(_)) => break,
            }
            if total >= buf.len() {
                break;
            }
        }

        assert_eq!(
            &buf[..total],
            chunked_body.as_slice(),
            "chunked forwarder leaked {} extra bytes past the 0-chunk terminator",
            total - chunked_body.len()
        );

        upstream_outer
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        drop(upstream_outer);
        let mut _resp = Vec::new();
        client_outer.read_to_end(&mut _resp).await.unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn forward_response_with_close_signals_eof_to_upstream_on_short_fixed_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Client advertised Content-Length: 100 but disconnects after 30 bytes.
        // Without an explicit shutdown of upstream_write the upstream would
        // block waiting for the remaining 70 bytes, response_forwarder would
        // block waiting for response headers, and the whole MITM session
        // would hang until a system-level timeout fires. With the shutdown
        // upstream sees EOF immediately and can fail fast (or send 4xx).
        let (mut client_outer, mut client_inner) = tokio::io::duplex(8192);
        let (mut upstream_outer, mut upstream_inner) = tokio::io::duplex(8192);

        let task = tokio::spawn(async move {
            forward_response_with_close(
                &mut client_inner,
                &mut upstream_inner,
                RequestBodyMode::Fixed(100),
            )
            .await
        });

        let partial = b"only thirty bytes of one hund\n"; // 30 bytes
        client_outer.write_all(partial).await.unwrap();
        drop(client_outer);

        // First read consumes the partial body.
        let mut buf = vec![0u8; 256];
        let mut received = Vec::new();
        let n = upstream_outer.read(&mut buf).await.unwrap();
        received.extend_from_slice(&buf[..n]);

        // Second read MUST observe EOF promptly — that's what proves the
        // MITM forwarded the shutdown. Without a shutdown this would block
        // until the duplex pipe is dropped externally (or hang in CI).
        let eof = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            upstream_outer.read(&mut buf),
        )
        .await
        .expect("upstream read timed out — MITM did not signal EOF after the short body")
        .unwrap();
        assert_eq!(
            eof, 0,
            "expected EOF after short body, got {eof} more bytes"
        );
        assert_eq!(received.as_slice(), partial);

        // Upstream sends an error response so the spawned task can complete.
        upstream_outer
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        drop(upstream_outer);
        let _ = task.await.unwrap();
    }

    // ----------------------------------------------------------------------
    // Upgrade preservation through inject_headers
    // ----------------------------------------------------------------------

    #[test]
    fn inject_headers_preserves_upgrade_connection() {
        let headers = "GET /ws HTTP/1.1\r\nHost: api.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: abc\r\n";
        let result = inject_headers(headers, &[]);
        assert!(result.contains("Connection: Upgrade"), "{result}");
        assert!(!result.contains("Connection: close"), "{result}");
        assert!(result.contains("Upgrade: websocket"), "{result}");
        assert!(result.contains("Sec-WebSocket-Key: abc"), "{result}");
    }

    #[test]
    fn inject_headers_still_injects_credentials_for_upgrade_request() {
        let headers = "GET /ws HTTP/1.1\r\nHost: api.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n";
        let injections = vec![CredentialInjection {
            header: "Authorization".to_string(),
            value: "Bearer token-xyz".to_string(),
            rules: vec![],
        }];
        let result = inject_headers(headers, &injections);
        assert!(
            result.contains("Authorization: Bearer token-xyz"),
            "{result}"
        );
        assert!(result.contains("Connection: Upgrade"), "{result}");
        assert!(!result.contains("Connection: close"), "{result}");
    }

    // ---------------- credential gate integration ----------------
    //
    // Integration coverage for the gate path through `mitm_inject_after_accept`:
    // these tests drive a full TLS handshake against the MITM and assert how
    // the held request resolves once the simulated host responds. They are
    // the only tests that exercise the state-refresh + defensive-rescan
    // logic — the unit tests above cover the scan in isolation but can't
    // catch staleness in `ctx.placeholder_map` or contract-violation
    // ordering of `credential_decision` vs. `policy` frames.
    //
    // Harness shape:
    //   - real `ProxyState` with `audit_tx` wired so gate-emitted frames
    //     and MITM-emitted audit events land in the same drain
    //   - a "host" task drains `credential_pending`, optionally mutates
    //     state to simulate the follow-up `policy` frame, then resolves
    //     the gate via `gate::resolve_credential_pending`
    //   - the client sees either the upstream response (Allow + armed) or
    //     a 403 (Deny / Allow-but-unarmed)

    /// Outcome a simulated host applies to a `credential_pending` it
    /// receives during a gate test. Mirrors the three contract branches
    /// we want to verify end-to-end.
    enum HostResponse {
        /// Simulate the proper host flow: install header injections for
        /// the target domain into `credential_injections`, then resolve
        /// the gate with Allow. The held request must rebuild headers
        /// against the fresh state and forward to upstream.
        ArmAndAllow {
            domain: String,
            injection: CredentialInjection,
        },
        /// Simulate a contract-violating host: resolve with Allow without
        /// first arming any injection. The defensive re-scan must catch
        /// this and 403 the held request.
        AllowWithoutArming,
        /// Simulate explicit user deny.
        Deny,
    }

    /// Spawn a task that simulates the host: drain audit events,
    /// dispatch `response` on the first `credential_pending`, and forward
    /// every event seen into `sink` so the test can assert after both
    /// sides finish. The task exits when all audit senders are dropped
    /// (the harness coordinates that by clearing `state.audit_tx` and
    /// dropping its own local clone — see `run_gate_harness`).
    fn spawn_host_task(
        state: std::sync::Arc<crate::proxy::ProxyState>,
        mut audit_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
        response: HostResponse,
        sink: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut response = Some(response);
            while let Some(raw) = audit_rx.recv().await {
                let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
                let is_pending = v["type"] == "credential_pending";
                sink.lock().unwrap().push(v.clone());
                if is_pending && let Some(r) = response.take() {
                    let id = v["id"].as_str().unwrap().to_string();
                    match r {
                        HostResponse::ArmAndAllow { domain, injection } => {
                            state
                                .credential_injections
                                .write()
                                .unwrap()
                                .insert(domain, vec![injection]);
                            crate::gate::resolve_credential_pending(
                                &state,
                                &id,
                                crate::protocol::CredentialDecisionKind::Allow,
                            );
                        }
                        HostResponse::AllowWithoutArming => {
                            crate::gate::resolve_credential_pending(
                                &state,
                                &id,
                                crate::protocol::CredentialDecisionKind::Allow,
                            );
                        }
                        HostResponse::Deny => {
                            crate::gate::resolve_credential_pending(
                                &state,
                                &id,
                                crate::protocol::CredentialDecisionKind::Deny,
                            );
                        }
                    }
                }
            }
        })
    }

    /// Full MITM gate harness: TLS client → MITM (driven by ProxyState
    /// with `placeholder_index` populated) → TLS upstream. The host task
    /// applies `response` when `credential_pending` lands. Returns
    /// `(upstream_request_headers, client_response, all_audit_events)`.
    /// On MITM-internal denial (Deny / Allow-but-unarmed) the
    /// `upstream_request_headers` is the empty string — upstream is
    /// never contacted.
    async fn run_gate_harness(
        placeholder: &str,
        credential_id: &str,
        request: Vec<u8>,
        response: HostResponse,
        match_host: &str,
    ) -> (String, String, Vec<serde_json::Value>) {
        use tokio::net::TcpListener;

        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        let ca = EphemeralCa::new().unwrap();
        let hostname = "test.example.com";

        // Real ProxyState — gate flow needs placeholder_index +
        // credential_pending table + audit_tx wired.
        let (state, audit_rx) = crate::proxy::tests::test_state();
        state
            .placeholder_index
            .write()
            .unwrap()
            .insert(placeholder.to_string(), credential_id.to_string());
        // 1s decision timeout keeps deny-path tests snappy.
        state.decision_timeout_override(Duration::from_secs(1));

        // Shared sink: the host task pushes every audit event it sees,
        // and the test reads after both sides finish. The gate emits
        // onto `state.audit_tx` and so does the MITM (via the local
        // clone in `test_ctx`), so the host receives both
        // `credential_pending` and downstream audit_events on the same
        // channel.
        let events_sink: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let host_handle = spawn_host_task(state.clone(), audit_rx, response, events_sink.clone());

        // TLS upstream server.
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let server_config = test_tls_server_config(&ca, hostname);

        let upstream_handle = tokio::spawn(async move {
            let (stream, _) = match upstream_listener.accept().await {
                Ok(v) => v,
                Err(_) => return String::new(),
            };
            let acceptor = TlsAcceptor::from(server_config);
            let mut tls = match acceptor.accept(stream).await {
                Ok(t) => t,
                Err(_) => return String::new(),
            };

            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            while let Ok(n) = tls.read(&mut byte).await {
                if n == 0 {
                    break;
                }
                buf.push(byte[0]);
                if buf.len() >= 4 && buf[buf.len() - 4..] == *b"\r\n\r\n" {
                    break;
                }
            }
            let headers = String::from_utf8_lossy(&buf).to_string();

            let _ = tls
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
            tls.shutdown().await.ok();
            headers
        });

        let upstream_stream = TcpStream::connect(upstream_addr).await.unwrap();

        // Client.
        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let root_store = ca_root_store(&ca);

        let client_handle = tokio::spawn(async move {
            let stream = TcpStream::connect(client_addr).await.unwrap();
            let client_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(client_config));
            let server_name = ServerName::try_from(hostname.to_string()).unwrap();
            let mut tls = connector.connect(server_name, stream).await.unwrap();

            tls.write_all(&request).await.unwrap();

            let mut response = Vec::new();
            let _ = tls.read_to_end(&mut response).await;
            String::from_utf8_lossy(&response).to_string()
        });

        // Drive MITM inside a block so the local `audit_tx` clone (and
        // the `test_ctx` borrow over it) are dropped before we clear
        // `state.audit_tx`. Without that ordering, the host task's
        // `audit_rx.recv()` would never return None and we'd deadlock at
        // `host_handle.await` below.
        let (client_stream, _) = client_listener.accept().await.unwrap();
        let upstream_headers: String = {
            let audit_tx = state.audit_tx.lock().unwrap().clone();
            let test_actor =
                crate::peer_process::ActorContext::resolve("10.0.0.5:44000".parse().unwrap());
            let test_ctx = MitmContext {
                injections: &[],
                http_rules: &[],
                ca: &ca,
                audit_tx: &audit_tx,
                extra_ca_certs: &[],
                placeholder_map: &[],
                state: &state,
                match_host,
                actor: &test_actor,
            };
            let mitm_server_config = build_ephemeral_server_config(&ca, hostname).unwrap();
            let acceptor = TlsAcceptor::from(mitm_server_config);
            let tls_client_stream = acceptor.accept(client_stream).await.unwrap();
            let mitm_result =
                mitm_inject_after_accept(tls_client_stream, hostname, &test_ctx, true).await;
            // test_ctx and audit_tx fall out of scope at the end of this
            // block, which releases the borrow and lets the channel close.

            match mitm_result {
                Ok((tls_client, modified, meta)) => {
                    let ca_root_store = ca_root_store(&ca);
                    let mut tls_upstream = connect_upstream_tls(
                        upstream_stream,
                        hostname,
                        Some(ca_root_store),
                        None,
                        &[],
                    )
                    .await
                    .unwrap();
                    tls_upstream.write_all(modified.as_bytes()).await.unwrap();
                    tls_upstream.write_all(b"\r\n\r\n").await.unwrap();
                    if let Err(e) = forward_or_bridge(tls_client, tls_upstream, &meta).await {
                        let msg = e.to_string();
                        assert!(
                            msg.contains("close_notify")
                                || msg.contains("closed")
                                || msg.contains("broken pipe"),
                            "unexpected forward_or_bridge error: {msg}"
                        );
                    }
                    upstream_handle.await.unwrap_or_default()
                }
                Err(_) => {
                    drop(upstream_stream);
                    upstream_handle.abort();
                    String::new()
                }
            }
            // audit_tx (local) drops here as the block ends.
        };

        let client_response = client_handle.await.unwrap();
        // Now that the only remaining sender lives in `state.audit_tx`,
        // dropping it closes the channel so the host task exits.
        *state.audit_tx.lock().unwrap() = None;
        tokio::time::timeout(Duration::from_secs(2), host_handle)
            .await
            .expect("host task did not exit; an audit sender is still alive")
            .unwrap();

        let events = std::mem::take(&mut *events_sink.lock().unwrap());
        (upstream_headers, client_response, events)
    }

    #[tokio::test]
    async fn mitm_gate_arm_and_allow_re_injects_real_credential() {
        // End-to-end: the request carries a placeholder, the gate holds
        // it, the host arms an Authorization header and allows, and the
        // upstream sees the real Bearer token (placeholder gone).
        let placeholder = "ghp_LNSPLACEHOLDER0000000000000000000000";
        let request = format!(
            "GET /issues HTTP/1.1\r\nHost: test.example.com\r\n\
             Authorization: Bearer {placeholder}\r\n\r\n"
        );
        let (upstream_headers, client_response, events) = run_gate_harness(
            placeholder,
            "github",
            request.into_bytes(),
            HostResponse::ArmAndAllow {
                domain: "test.example.com".to_string(),
                injection: CredentialInjection {
                    header: "Authorization".to_string(),
                    value: "Bearer real-secret".to_string(),
                    rules: vec![],
                },
            },
            "test.example.com",
        )
        .await;

        assert!(
            upstream_headers.contains("Authorization: Bearer real-secret"),
            "upstream should see armed credential: {upstream_headers}"
        );
        assert!(
            !upstream_headers.contains(placeholder),
            "placeholder must not reach upstream: {upstream_headers}"
        );
        assert!(client_response.contains("200 OK"), "{client_response}");

        // Sequence: credential_pending emitted, then success audit_event.
        let kinds: Vec<&str> = events
            .iter()
            .map(|e| e["type"].as_str().unwrap_or(""))
            .collect();
        assert!(
            kinds.contains(&"credential_pending"),
            "credential_pending must be emitted: {kinds:?}"
        );
        let success = events
            .iter()
            .find(|e| e["type"] == "audit_event" && e["result"] == "success");
        assert!(success.is_some(), "expected success audit_event: {kinds:?}");
    }

    #[tokio::test]
    async fn mitm_gate_arm_and_allow_matches_wildcard_domain_injection() {
        // Regression: the post-Allow rebuild must resolve the armed
        // credential through the same pattern matching as the CONNECT path
        // (wildcards, case-insensitive), not an exact host-key lookup. A
        // credential armed under `*.example.com` must satisfy a request to
        // `test.example.com` — otherwise the user Allows, the host arms
        // correctly, and the request is still 403'd as policy-frame-missing.
        let placeholder = "ghp_LNSPLACEHOLDER0000000000000000000000";
        let request = format!(
            "GET /issues HTTP/1.1\r\nHost: test.example.com\r\n\
             Authorization: Bearer {placeholder}\r\n\r\n"
        );
        let (upstream_headers, client_response, _events) = run_gate_harness(
            placeholder,
            "github",
            request.into_bytes(),
            HostResponse::ArmAndAllow {
                domain: "*.example.com".to_string(),
                injection: CredentialInjection {
                    header: "Authorization".to_string(),
                    value: "Bearer real-secret".to_string(),
                    rules: vec![],
                },
            },
            "test.example.com",
        )
        .await;

        assert!(
            upstream_headers.contains("Authorization: Bearer real-secret"),
            "wildcard-domain credential must be armed via pattern match: {upstream_headers}"
        );
        assert!(
            !upstream_headers.contains(placeholder),
            "placeholder must not reach upstream: {upstream_headers}"
        );
        assert!(client_response.contains("200 OK"), "{client_response}");
    }

    #[tokio::test]
    async fn mitm_gate_arm_and_allow_matches_port_specific_domain_injection() {
        // Regression: a credential armed under an explicit `host:port`
        // pattern must satisfy the request whose CONNECT target carries
        // that port. The post-Allow rebuild matches against the
        // port-bearing `match_host`, not the port-stripped SNI hostname —
        // otherwise `injection_matches("test.example.com:8443",
        // "test.example.com")` is false, the placeholder survives the
        // re-scan, and the user's Allow is wrongly 403'd as
        // policy-frame-missing.
        let placeholder = "ghp_LNSPLACEHOLDER0000000000000000000000";
        let request = format!(
            "GET /issues HTTP/1.1\r\nHost: test.example.com:8443\r\n\
             Authorization: Bearer {placeholder}\r\n\r\n"
        );
        let (upstream_headers, client_response, _events) = run_gate_harness(
            placeholder,
            "github",
            request.into_bytes(),
            HostResponse::ArmAndAllow {
                domain: "test.example.com:8443".to_string(),
                injection: CredentialInjection {
                    header: "Authorization".to_string(),
                    value: "Bearer real-secret".to_string(),
                    rules: vec![],
                },
            },
            "test.example.com:8443",
        )
        .await;

        assert!(
            upstream_headers.contains("Authorization: Bearer real-secret"),
            "port-specific credential must be armed via host:port match: {upstream_headers}"
        );
        assert!(
            !upstream_headers.contains(placeholder),
            "placeholder must not reach upstream: {upstream_headers}"
        );
        assert!(client_response.contains("200 OK"), "{client_response}");
    }

    #[tokio::test]
    async fn mitm_gate_deny_fails_held_request_closed() {
        // The user explicitly denies — the held request 403s and never
        // touches upstream.
        let placeholder = "ghp_LNSPLACEHOLDER0000000000000000000000";
        let request = format!(
            "GET /issues HTTP/1.1\r\nHost: test.example.com\r\n\
             Authorization: Bearer {placeholder}\r\n\r\n"
        );
        let (upstream_headers, client_response, events) = run_gate_harness(
            placeholder,
            "github",
            request.into_bytes(),
            HostResponse::Deny,
            "test.example.com",
        )
        .await;

        assert!(
            upstream_headers.is_empty(),
            "upstream must not be contacted on deny: {upstream_headers}"
        );
        assert!(
            client_response.contains("403 Forbidden"),
            "client should see 403: {client_response}"
        );
        let denied = events.iter().find(|e| {
            e["type"] == "audit_event" && e["metadata"]["credential_gate_denied"] == true
        });
        assert!(denied.is_some(), "expected credential_gate_denied audit");
        assert_eq!(denied.unwrap()["metadata"]["reason"], "user-denied");
    }

    #[tokio::test]
    async fn mitm_gate_allow_without_arming_fails_closed_via_rescan() {
        // Contract violation: host resolves Allow without first arming
        // any injection. The defensive re-scan catches the surviving
        // placeholder and 403s the request — placeholder never reaches
        // upstream. Pins the protective behavior added for #3.
        let placeholder = "ghp_LNSPLACEHOLDER0000000000000000000000";
        let request = format!(
            "GET /issues HTTP/1.1\r\nHost: test.example.com\r\n\
             Authorization: Bearer {placeholder}\r\n\r\n"
        );
        let (upstream_headers, client_response, events) = run_gate_harness(
            placeholder,
            "github",
            request.into_bytes(),
            HostResponse::AllowWithoutArming,
            "test.example.com",
        )
        .await;

        assert!(
            upstream_headers.is_empty(),
            "upstream must not be contacted when arming missing: {upstream_headers}"
        );
        assert!(
            client_response.contains("403 Forbidden"),
            "client should see 403: {client_response}"
        );
        let denied = events.iter().find(|e| {
            e["type"] == "audit_event" && e["metadata"]["credential_gate_denied"] == true
        });
        assert!(denied.is_some(), "expected credential_gate_denied audit");
        assert_eq!(
            denied.unwrap()["metadata"]["reason"],
            "policy-frame-missing"
        );
    }

    #[tokio::test]
    async fn mitm_gate_arm_and_allow_refreshes_uri_placeholder_map() {
        // The placeholder lives in the request URI (uriPlaceholder
        // credential), not a header. Before the fix for #1,
        // `ctx.placeholder_map` was captured at CONNECT time and never
        // refreshed — Allow would arm `uri_placeholder_injections` in
        // state, but rewrite_uri_placeholders would keep using the stale
        // ctx map and forward the placeholder upstream verbatim.
        // After the fix, the Allow path re-reads
        // `state.uri_placeholder_injections` so the substitution actually
        // happens.
        let placeholder = "__lens_cred:telegram_bot__";
        let request =
            format!("GET /bot{placeholder}/sendMessage HTTP/1.1\r\nHost: test.example.com\r\n\r\n");
        // Host arms a URI placeholder via state mutation; we can't reuse
        // the HostResponse::ArmAndAllow branch (which writes header
        // injections), so do it inline.
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        let ca = EphemeralCa::new().unwrap();
        let hostname = "test.example.com";

        let (state, mut audit_rx) = crate::proxy::tests::test_state();
        state
            .placeholder_index
            .write()
            .unwrap()
            .insert(placeholder.to_string(), "telegram_bot".to_string());
        state.decision_timeout_override(Duration::from_secs(1));

        let state_for_host = state.clone();
        let host_handle = tokio::spawn(async move {
            while let Some(raw) = audit_rx.recv().await {
                let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
                if v["type"] == "credential_pending" {
                    let id = v["id"].as_str().unwrap().to_string();
                    state_for_host
                        .uri_placeholder_injections
                        .write()
                        .unwrap()
                        .insert(
                            "test.example.com".to_string(),
                            vec![(placeholder.to_string(), "123:REAL-TOKEN".to_string())],
                        );
                    crate::gate::resolve_credential_pending(
                        &state_for_host,
                        &id,
                        crate::protocol::CredentialDecisionKind::Allow,
                    );
                    return;
                }
            }
        });

        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let server_config = test_tls_server_config(&ca, hostname);

        let upstream_handle = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let acceptor = TlsAcceptor::from(server_config);
            let mut tls = acceptor.accept(stream).await.unwrap();
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                let n = tls.read(&mut byte).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.push(byte[0]);
                if buf.len() >= 4 && buf[buf.len() - 4..] == *b"\r\n\r\n" {
                    break;
                }
            }
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .ok();
            tls.shutdown().await.ok();
            String::from_utf8_lossy(&buf).to_string()
        });

        let upstream_stream = TcpStream::connect(upstream_addr).await.unwrap();

        let client_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let root_store = ca_root_store(&ca);

        let req_bytes = request.into_bytes();
        let client_handle = tokio::spawn(async move {
            let stream = TcpStream::connect(client_addr).await.unwrap();
            let client_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(client_config));
            let server_name = ServerName::try_from(hostname.to_string()).unwrap();
            let mut tls = connector.connect(server_name, stream).await.unwrap();
            tls.write_all(&req_bytes).await.unwrap();
            let mut buf = Vec::new();
            let _ = tls.read_to_end(&mut buf).await;
            String::from_utf8_lossy(&buf).to_string()
        });

        let (client_stream, _) = client_listener.accept().await.unwrap();
        let audit_tx = state.audit_tx.lock().unwrap().clone();
        // ctx.placeholder_map intentionally stale (empty) — pinpointing
        // that the Allow path refreshes from state rather than relying
        // on this captured snapshot.
        let test_actor =
            crate::peer_process::ActorContext::resolve("10.0.0.5:44000".parse().unwrap());
        let test_ctx = MitmContext {
            injections: &[],
            http_rules: &[],
            ca: &ca,
            audit_tx: &audit_tx,
            extra_ca_certs: &[],
            placeholder_map: &[],
            state: &state,
            match_host: hostname,
            actor: &test_actor,
        };
        let mitm_server_config = build_ephemeral_server_config(&ca, hostname).unwrap();
        let acceptor = TlsAcceptor::from(mitm_server_config);
        let tls_client_stream = acceptor.accept(client_stream).await.unwrap();
        let (tls_client, modified, meta) =
            mitm_inject_after_accept(tls_client_stream, hostname, &test_ctx, true)
                .await
                .expect("mitm_inject_after_accept should succeed on Allow + armed");

        let ca_root_store = ca_root_store(&ca);
        let mut tls_upstream =
            connect_upstream_tls(upstream_stream, hostname, Some(ca_root_store), None, &[])
                .await
                .unwrap();
        tls_upstream.write_all(modified.as_bytes()).await.unwrap();
        tls_upstream.write_all(b"\r\n\r\n").await.unwrap();
        let _ = forward_or_bridge(tls_client, tls_upstream, &meta).await;

        let upstream_headers = upstream_handle.await.unwrap();
        let client_response = client_handle.await.unwrap();
        host_handle.abort();

        assert!(
            upstream_headers.contains("/bot123:REAL-TOKEN/sendMessage"),
            "URL placeholder must be substituted from refreshed state: {upstream_headers}"
        );
        assert!(
            !upstream_headers.contains(placeholder),
            "stale placeholder leaked: {upstream_headers}"
        );
        assert!(client_response.contains("200 OK"), "{client_response}");
    }

    #[tokio::test]
    async fn mitm_gate_multi_credential_request_arms_each_and_forwards() {
        // One request that carries placeholders for two distinct
        // credentials must trigger a dialog per credential, not a single
        // dialog that arbitrarily 403s the other as `policy-frame-missing`.
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        let ca = EphemeralCa::new().unwrap();
        let hostname = "test.example.com";
        let github_ph = "ghp_LNSPLACEHOLDER0000000000000000000000";
        let openai_ph = "sk-LNSPLACEHOLDER000000000000000000000000";

        let (state, mut audit_rx) = crate::proxy::tests::test_state();
        {
            let mut idx = state.placeholder_index.write().unwrap();
            idx.insert(github_ph.into(), "github".into());
            idx.insert(openai_ph.into(), "openai".into());
        }
        state.decision_timeout_override(Duration::from_secs(1));

        let state_for_host = state.clone();
        let events_sink: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink_for_host = events_sink.clone();
        let host_handle = tokio::spawn(async move {
            // First Allow arms only github; second Allow arms openai. The
            // gate must serialize the dialogs and the rescan must succeed
            // only after both arms land.
            let mut seen = 0;
            while let Some(raw) = audit_rx.recv().await {
                let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
                let is_pending = v["type"] == "credential_pending";
                sink_for_host.lock().unwrap().push(v.clone());
                if is_pending {
                    seen += 1;
                    let id = v["id"].as_str().unwrap().to_string();
                    let cred = v["credentialId"].as_str().unwrap().to_string();
                    let injection = if cred == "github" {
                        CredentialInjection {
                            header: "Authorization".into(),
                            value: "Bearer real-github".into(),
                            rules: vec![],
                        }
                    } else {
                        CredentialInjection {
                            header: "X-OpenAI-Key".into(),
                            value: "real-openai".into(),
                            rules: vec![],
                        }
                    };
                    let mut map = state_for_host.credential_injections.write().unwrap();
                    map.entry("test.example.com".to_string())
                        .or_default()
                        .push(injection);
                    drop(map);
                    crate::gate::resolve_credential_pending(
                        &state_for_host,
                        &id,
                        crate::protocol::CredentialDecisionKind::Allow,
                    );
                    if seen == 2 {
                        return;
                    }
                }
            }
        });

        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let server_config = test_tls_server_config(&ca, hostname);
        let upstream_handle = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let acceptor = TlsAcceptor::from(server_config);
            let mut tls = acceptor.accept(stream).await.unwrap();
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                let n = tls.read(&mut byte).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.push(byte[0]);
                if buf.len() >= 4 && buf[buf.len() - 4..] == *b"\r\n\r\n" {
                    break;
                }
            }
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .ok();
            tls.shutdown().await.ok();
            String::from_utf8_lossy(&buf).to_string()
        });
        let upstream_stream = TcpStream::connect(upstream_addr).await.unwrap();

        let client_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let root_store = ca_root_store(&ca);
        let request = format!(
            "POST /multi HTTP/1.1\r\nHost: test.example.com\r\n\
             Authorization: Bearer {github_ph}\r\nX-OpenAI-Key: {openai_ph}\r\n\r\n"
        );
        let req_bytes = request.into_bytes();
        let client_handle = tokio::spawn(async move {
            let stream = TcpStream::connect(client_addr).await.unwrap();
            let client_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(client_config));
            let server_name = ServerName::try_from(hostname.to_string()).unwrap();
            let mut tls = connector.connect(server_name, stream).await.unwrap();
            tls.write_all(&req_bytes).await.unwrap();
            let mut buf = Vec::new();
            let _ = tls.read_to_end(&mut buf).await;
            String::from_utf8_lossy(&buf).to_string()
        });

        let (client_stream, _) = client_listener.accept().await.unwrap();
        let upstream_headers: String = {
            let audit_tx = state.audit_tx.lock().unwrap().clone();
            let test_actor =
                crate::peer_process::ActorContext::resolve("10.0.0.5:44000".parse().unwrap());
            let test_ctx = MitmContext {
                injections: &[],
                http_rules: &[],
                ca: &ca,
                audit_tx: &audit_tx,
                extra_ca_certs: &[],
                placeholder_map: &[],
                state: &state,
                match_host: hostname,
                actor: &test_actor,
            };
            let mitm_server_config = build_ephemeral_server_config(&ca, hostname).unwrap();
            let acceptor = TlsAcceptor::from(mitm_server_config);
            let tls_client_stream = acceptor.accept(client_stream).await.unwrap();
            let (tls_client, modified, meta) =
                mitm_inject_after_accept(tls_client_stream, hostname, &test_ctx, true)
                    .await
                    .expect("multi-cred allow + arm should succeed");

            let ca_root_store = ca_root_store(&ca);
            let mut tls_upstream =
                connect_upstream_tls(upstream_stream, hostname, Some(ca_root_store), None, &[])
                    .await
                    .unwrap();
            tls_upstream.write_all(modified.as_bytes()).await.unwrap();
            tls_upstream.write_all(b"\r\n\r\n").await.unwrap();
            let _ = forward_or_bridge(tls_client, tls_upstream, &meta).await;
            upstream_handle.await.unwrap_or_default()
        };

        let client_response = client_handle.await.unwrap();
        *state.audit_tx.lock().unwrap() = None;
        let _ = tokio::time::timeout(Duration::from_secs(2), host_handle).await;

        let events = std::mem::take(&mut *events_sink.lock().unwrap());
        let pending: Vec<&serde_json::Value> = events
            .iter()
            .filter(|e| e["type"] == "credential_pending")
            .collect();
        assert_eq!(pending.len(), 2, "expected one dialog per credential");
        let creds: std::collections::BTreeSet<&str> = pending
            .iter()
            .map(|e| e["credentialId"].as_str().unwrap())
            .collect();
        assert!(creds.contains("github") && creds.contains("openai"));

        assert!(
            upstream_headers.contains("Authorization: Bearer real-github"),
            "github arm must reach upstream: {upstream_headers}"
        );
        assert!(
            upstream_headers.contains("X-OpenAI-Key: real-openai"),
            "openai arm must reach upstream: {upstream_headers}"
        );
        assert!(!upstream_headers.contains(github_ph));
        assert!(!upstream_headers.contains(openai_ph));
        assert!(client_response.contains("200 OK"), "{client_response}");
    }

    #[tokio::test]
    async fn a_tcp_cidr_deny_blocks_the_mitm_dial() {
        // An `egress.tcp` CIDR rule binds by address, so a client that named its
        // destination can only be tested against one here, at the dial. Dialling
        // bare would let the same deny hold on the transparent door — which sees
        // an address — and not on this one, and the workload picks the door.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = EphemeralCa::new().unwrap();
        let (state, _rx) = crate::proxy::tests::test_state();
        state.policy.write().unwrap().tcp_egress = crate::routing::parse_tcp_egress(
            &serde_json::json!([{"match": "203.0.113.0/24:443", "verdict": "deny"}]),
        )
        .unwrap();

        let hostname = "db.internal";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let root_store = ca_root_store(&ca);

        let client = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(config));
            let name = ServerName::try_from(hostname.to_string()).unwrap();
            let mut tls = connector.connect(name, stream).await.unwrap();
            tls.write_all(b"GET / HTTP/1.1\r\nHost: db.internal\r\n\r\n")
                .await
                .unwrap();
            let mut buf = Vec::new();
            let _ = tls.read_to_end(&mut buf).await;
        });

        let (client_stream, _) = listener.accept().await.unwrap();
        let actor = crate::peer_process::ActorContext::resolve("10.0.0.5:44000".parse().unwrap());
        let audit_tx = state.audit_tx.lock().unwrap().clone();
        let ctx = MitmContext {
            injections: &[],
            http_rules: &[],
            ca: &ca,
            audit_tx: &audit_tx,
            extra_ca_certs: &[],
            placeholder_map: &[],
            state: &state,
            match_host: hostname,
            actor: &actor,
        };
        let server_config = build_ephemeral_server_config(&ca, hostname).unwrap();
        let tls_client = TlsAcceptor::from(server_config)
            .accept(client_stream)
            .await
            .unwrap();

        // The name resolves into the denied range; the dial must refuse rather
        // than reach the origin.
        let err = handle_mitm_pre_accepted(
            tls_client,
            hostname,
            UpstreamMode::DirectTls {
                host: "203.0.113.9".to_string(),
                port: 443,
            },
            &ctx,
        )
        .await
        .expect_err("a tcp deny covering the resolved address must refuse the dial");
        assert!(
            err.to_string().contains("denied by policy"),
            "expected a policy refusal, got: {err}"
        );
        client.abort();
    }
}
