//! AWS SigV4 re-sign MITM handler.
//!
//! Owned by an [`AwsResignInterceptor`] on
//! [`ProxyState`](crate::proxy::ProxyState). The interceptor holds the
//! placeholder → real-STS-creds map and the set of AWS domain patterns,
//! refreshed in-place on every policy message. The proxy consults it on
//! each `Direct` CONNECT; matching hosts take this MITM path:
//! terminate the agent's TLS with an ephemeral cert, strip the fake SigV4
//! signature, re-sign with the real STS credentials held only in this
//! process's memory, and forward upstream to AWS over fresh TLS.
//!
//! Body handling:
//! - **S3**: always `UNSIGNED-PAYLOAD` → stream the body through unchanged,
//!   no buffering. Lets large uploads pass without memory pressure.
//! - **Non-S3**: buffer up to [`MAX_BUFFERED_BODY_BYTES`], compute SHA-256,
//!   re-sign. Over the cap → `413`. `Transfer-Encoding: chunked` → `411`.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use rustls::ServerConfig;
#[cfg(test)]
use rustls::pki_types::pem::PemObject;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::aws_sigv4::{
    AwsSigv4Config, BodyMode, ResignRequest, is_lens_placeholder, parse_authorization,
    resign_request,
};
use crate::ca::EphemeralCa;

/// Non-S3 body buffer cap. JSON API payloads (DynamoDB, Lambda, SQS, …) are
/// typically KB; 1 MiB is plenty of headroom without risking memory exhaustion.
pub const MAX_BUFFERED_BODY_BYTES: usize = 1_048_576;

/// Cap on header block size, matching the existing MITM path.
const MAX_HEADER_BYTES: usize = 65_536;

/// Context pulled from [`ProxyState`](crate::proxy::ProxyState) for a single resign.
pub struct AwsResignContext<'a> {
    pub configs: &'a HashMap<String, AwsSigv4Config>,
    pub ca: &'a EphemeralCa,
    pub extra_ca_certs: &'a [rustls::pki_types::CertificateDer<'static>],
    pub audit_tx: &'a Option<tokio::sync::mpsc::UnboundedSender<String>>,
    /// Needed to apply `egress.tcp` to the resolved upstream address: a CIDR
    /// rule binds by address, so this dial is the first place it can be tested
    /// against a target the client named.
    pub state: &'a std::sync::Arc<crate::proxy::ProxyState>,
    pub actor: &'a crate::peer_process::ActorContext,
}

/// Owns the mutable state the AWS SigV4 re-sign MITM needs: the placeholder
/// access-key-ID → real-STS-creds map and the set of AWS domain patterns. The
/// proxy holds an `Arc<AwsResignInterceptor>` on [`ProxyState`](crate::proxy::ProxyState)
/// and calls [`matches`](Self::matches) on every `Direct` CONNECT target. When
/// a connection matches, [`handle`](Self::handle) takes over the MITM and
/// forwards a re-signed request upstream to AWS.
pub struct AwsResignInterceptor {
    configs: RwLock<HashMap<String, AwsSigv4Config>>,
    domains: RwLock<Vec<String>>,
}

impl AwsResignInterceptor {
    pub fn new() -> Self {
        Self {
            configs: RwLock::new(HashMap::new()),
            domains: RwLock::new(Vec::new()),
        }
    }

    /// Replace the configs and domains from a fresh policy message.
    pub fn update(&self, configs: HashMap<String, AwsSigv4Config>, domains: Vec<String>) {
        *self.configs.write().unwrap() = configs;
        *self.domains.write().unwrap() = domains;
    }

    /// Does this target host fall under any registered AWS re-sign domain?
    pub fn matches(&self, target_host: &str) -> bool {
        self.domains
            .read()
            .unwrap()
            .iter()
            .any(|pattern| crate::routing::injection_matches(pattern, target_host))
    }

    /// Snapshot of the current configs map — primarily for tests that assert
    /// policy-refresh overwrote the previous configs.
    pub fn configs_snapshot(&self) -> HashMap<String, AwsSigv4Config> {
        self.configs.read().unwrap().clone()
    }

    /// MITM a CONNECT destined for AWS: clone the current configs, build a
    /// context, and delegate to [`handle_aws_resign`]. Cloning the map is
    /// cheap (strings), and snapshotting avoids holding the read lock across
    /// the entire request lifecycle.
    pub async fn handle(
        &self,
        client: TcpStream,
        target_host: &str,
        target_port: u16,
        ca: &EphemeralCa,
        state: &std::sync::Arc<crate::proxy::ProxyState>,
        actor: &crate::peer_process::ActorContext,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let configs = self.configs_snapshot();
        // Snapshotted here rather than passed in: both are plain reads off
        // `state`, which this now takes anyway, and one fewer parameter each is
        // one fewer thing a call site can get wrong.
        let audit_tx = state.audit_tx.lock().unwrap().clone();
        let extra_ca_certs = state.extra_ca_certs.read().unwrap().clone();
        let ctx = AwsResignContext {
            configs: &configs,
            ca,
            extra_ca_certs: &extra_ca_certs,
            audit_tx: &audit_tx,
            state,
            actor,
        };
        handle_aws_resign(client, target_host, target_port, &ctx).await
    }
}

impl Default for AwsResignInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle an MITM connection destined for AWS with SigV4 re-signing.
pub async fn handle_aws_resign(
    client: TcpStream,
    target_host: &str,
    target_port: u16,
    ctx: &AwsResignContext<'_>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (mut tls_client, head_str) = accept_and_read_head(client, target_host, ctx.ca).await?;

    let prepared = match prepare_resigned_request(&mut tls_client, head_str, ctx.configs).await? {
        Some(v) => v,
        None => return Ok(()), // client already saw a 4xx
    };

    // Connect upstream only after we've committed to forwarding.
    let upstream = crate::proxy::connect_egress_under_policy(
        ctx.state,
        &format!("{target_host}:{target_port}"),
        target_port,
        ctx.actor.process(),
    )
    .await?;
    let tls_upstream =
        crate::mitm::connect_upstream_tls_public(upstream, target_host, ctx.extra_ca_certs).await?;

    emit_resign_audit(
        ctx.audit_tx,
        target_host,
        &prepared.method,
        &prepared.path,
        &prepared.service,
    );

    forward_resigned(&mut tls_client, tls_upstream, prepared).await
}

/// Everything that must happen with `tls_client` before we commit to
/// connecting upstream: parse head, look up real credentials, buffer the
/// body (non-S3), re-sign. Returns `None` if we've already written a 4xx
/// response to the client.
async fn prepare_resigned_request(
    tls_client: &mut tokio_rustls::server::TlsStream<TcpStream>,
    head_str: String,
    configs: &HashMap<String, AwsSigv4Config>,
) -> Result<Option<PreparedResign>, Box<dyn std::error::Error + Send + Sync>> {
    let Some(parsed) = parse_request_head(&head_str) else {
        write_client_error(tls_client, 400, "Bad Request").await?;
        return Err("aws resign: could not parse request head".into());
    };

    let Some(auth_value) = parsed.find_header("authorization") else {
        write_client_error(tls_client, 401, "Missing Authorization").await?;
        return Ok(None);
    };

    let Some(auth) = parse_authorization(auth_value) else {
        write_client_error(tls_client, 401, "Unsupported Authorization").await?;
        return Ok(None);
    };

    if !is_lens_placeholder(&auth.access_key_id) {
        write_client_error(tls_client, 401, "Unknown credentials").await?;
        return Ok(None);
    }

    let Some(config) = configs.get(&auth.access_key_id).cloned() else {
        tracing::warn!(
            placeholder = %auth.access_key_id,
            "aws resign: no config for placeholder access key"
        );
        write_client_error(tls_client, 401, "Unknown credentials").await?;
        return Ok(None);
    };

    // Decide body mode BEFORE signing. Non-S3 bodies are fully buffered here
    // so we sign exactly once, with the final SHA-256.
    let outgoing_body = match decide_body(tls_client, &parsed, &auth.service).await {
        Ok(v) => v,
        Err(BodyDecisionError::Reported) => return Ok(None),
        Err(BodyDecisionError::Io(e)) => return Err(e),
    };

    // Reproduce the original signed-headers set so service-specific headers
    // (e.g. DynamoDB's `x-amz-target`) stay inside the signature. The signer
    // re-injects the three infra headers with correct values.
    let signing_headers = collect_signing_headers(&parsed, &auth.signed_headers);

    let body_mode = match &outgoing_body {
        OutgoingBody::Stream => BodyMode::Unsigned,
        OutgoingBody::Buffered { sha256_hex, .. } => BodyMode::Signed {
            sha256_hex: sha256_hex.clone(),
        },
    };

    // Sign for the region the client originally signed with. AWS scopes
    // SigV4 signatures to the target regional endpoint (e.g. a request to
    // `ec2.eu-west-1.amazonaws.com` must carry `/eu-west-1/` in the
    // credential scope). The client SDK already chose that region based on
    // its own configuration — preserving it keeps every regional endpoint
    // working. STS session credentials are not region-bound.
    let req = ResignRequest {
        method: &parsed.method,
        uri: &parsed.uri,
        service: &auth.service,
        region: &auth.region,
        headers: &signing_headers,
        body_mode,
    };
    let resigned = match resign_request(&req, &config, SystemTime::now()) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(err = %e, "aws resign: signing failed");
            write_client_error(tls_client, 500, "Signing failed").await?;
            return Err(format!("aws resign: {e}").into());
        }
    };

    let new_head = apply_resigned_headers(&parsed.head_without_body(), &resigned);
    Ok(Some(PreparedResign {
        new_head,
        outgoing_body,
        method: parsed.method,
        path: parsed.path,
        service: auth.service,
    }))
}

/// A request that has been verified + re-signed and is ready to write upstream.
struct PreparedResign {
    new_head: String,
    outgoing_body: OutgoingBody,
    method: String,
    path: String,
    service: String,
}

async fn forward_resigned(
    tls_client: &mut tokio_rustls::server::TlsStream<TcpStream>,
    mut tls_upstream: tokio_rustls::client::TlsStream<TcpStream>,
    prepared: PreparedResign,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tls_upstream.write_all(prepared.new_head.as_bytes()).await?;
    tls_upstream.write_all(b"\r\n\r\n").await?;

    match prepared.outgoing_body {
        OutgoingBody::Buffered { bytes, .. } => {
            if !bytes.is_empty() {
                tls_upstream.write_all(&bytes).await?;
            }
        }
        OutgoingBody::Stream => {
            // S3 with UNSIGNED-PAYLOAD: client bytes flow through as-is.
        }
    }

    tokio::io::copy_bidirectional(tls_client, &mut tls_upstream).await?;
    Ok(())
}

#[derive(Debug)]
enum OutgoingBody {
    /// S3: stream body with UNSIGNED-PAYLOAD — no buffering.
    Stream,
    /// Non-S3: body fully buffered + hashed before signing.
    Buffered { sha256_hex: String, bytes: Vec<u8> },
}

/// Errors specific to body-decision. `Reported` means we already wrote the
/// appropriate 4xx/5xx to the client; the caller should exit cleanly.
enum BodyDecisionError {
    Reported,
    Io(Box<dyn std::error::Error + Send + Sync>),
}

impl From<std::io::Error> for BodyDecisionError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(Box::new(e))
    }
}

async fn decide_body(
    tls_client: &mut tokio_rustls::server::TlsStream<TcpStream>,
    parsed: &ParsedHead,
    service: &str,
) -> Result<OutgoingBody, BodyDecisionError> {
    if service.eq_ignore_ascii_case("s3") {
        // S3 streaming payload signing (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`,
        // `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`) embeds per-chunk
        // signatures inside the body framing, seeded by the outer signature.
        // Our re-sign replaces the outer Authorization but can't rewrite the
        // chunk framing, so AWS rejects the request. Fail fast with 501 so
        // the caller sees a clear "unsupported" signal instead of a confusing
        // signature mismatch.
        if let Some(sha) = parsed.find_header("x-amz-content-sha256")
            && matches!(
                sha,
                "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" | "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
            )
        {
            write_client_error(tls_client, 501, "Not Implemented")
                .await
                .map_err(BodyDecisionError::Io)?;
            return Err(BodyDecisionError::Reported);
        }
        return Ok(OutgoingBody::Stream);
    }

    if parsed.is_chunked() {
        write_client_error(tls_client, 411, "Length Required")
            .await
            .map_err(BodyDecisionError::Io)?;
        return Err(BodyDecisionError::Reported);
    }

    // Non-S3 bodies must be fully buffered to compute SHA-256 before signing.
    // A missing Content-Length means we'd sign an empty body and let
    // copy_bidirectional forward the real bytes through — AWS then rejects
    // the signature. Fail fast with 411 so the caller sees the misconfig.
    let Some(content_length) = parsed.content_length() else {
        write_client_error(tls_client, 411, "Length Required")
            .await
            .map_err(BodyDecisionError::Io)?;
        return Err(BodyDecisionError::Reported);
    };
    if content_length > MAX_BUFFERED_BODY_BYTES {
        write_client_error(tls_client, 413, "Payload Too Large")
            .await
            .map_err(BodyDecisionError::Io)?;
        return Err(BodyDecisionError::Reported);
    }

    let mut bytes = vec![0u8; content_length];
    if content_length > 0 {
        tls_client.read_exact(&mut bytes).await?;
    }
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha256_hex = hex::encode(hasher.finalize());
    Ok(OutgoingBody::Buffered { sha256_hex, bytes })
}

async fn accept_and_read_head(
    client: TcpStream,
    target_host: &str,
    ca: &EphemeralCa,
) -> Result<
    (tokio_rustls::server::TlsStream<TcpStream>, String),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let certified_key = ca
        .certified_key_for_domain(target_host)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(crate::mitm::SingleCertResolver(certified_key)));
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let mut tls_client = acceptor.accept(client).await?;

    // Read byte-by-byte until CRLFCRLF so we don't consume body bytes.
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut byte = [0u8; 1];
    loop {
        let n = tls_client.read(&mut byte).await?;
        if n == 0 {
            return Err("client closed before request headers".into());
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && buf[buf.len() - 4..] == *b"\r\n\r\n" {
            break;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err("aws resign: headers too large".into());
        }
    }

    let head = String::from_utf8_lossy(&buf[..buf.len() - 4]).to_string();
    Ok((tls_client, head))
}

/// Parsed components of an HTTP/1.1 request head.
#[derive(Debug)]
struct ParsedHead {
    method: String,
    uri: String,
    path: String,
    host: String,
    headers: Vec<(String, String)>,
}

impl ParsedHead {
    fn find_header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn content_length(&self) -> Option<usize> {
        self.find_header("content-length")
            .and_then(|s| s.trim().parse().ok())
    }

    fn is_chunked(&self) -> bool {
        self.find_header("transfer-encoding")
            .map(|s| s.to_ascii_lowercase().contains("chunked"))
            .unwrap_or(false)
    }

    /// Request line + raw headers joined with CRLF, without the trailing
    /// `\r\n\r\n` terminator.
    fn head_without_body(&self) -> String {
        let mut out = format!("{} {} HTTP/1.1", self.method, self.uri);
        for (k, v) in &self.headers {
            out.push_str("\r\n");
            out.push_str(k);
            out.push_str(": ");
            out.push_str(v);
        }
        out
    }
}

fn parse_request_head(head: &str) -> Option<ParsedHead> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }
    let method = parts[0].to_string();
    let uri = parts[1].to_string();
    let path = uri.split('?').next().unwrap_or(&uri).to_string();

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut host: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.find(':') else {
            continue;
        };
        let name = line[..colon].trim().to_string();
        let value = line[colon + 1..].trim().to_string();
        if name.eq_ignore_ascii_case("host") {
            host = Some(value.clone());
        }
        headers.push((name, value));
    }

    Some(ParsedHead {
        method,
        uri,
        path,
        host: host?,
        headers,
    })
}

/// Headers the aws-sigv4 crate re-emits verbatim when we sign — we drop the
/// incoming (fake-signed) versions so they don't duplicate on the wire.
/// Service-specific headers like `x-amz-target` are NOT in this list: they
/// must survive untouched and end up inside the re-signed `SignedHeaders=`.
const SIGV4_INFRA_HEADER_NAMES: &[&str] = &[
    "authorization",
    "x-amz-date",
    "x-amz-content-sha256",
    "x-amz-security-token",
];

fn is_sigv4_infra_header(name: &str) -> bool {
    SIGV4_INFRA_HEADER_NAMES
        .iter()
        .any(|h| h.eq_ignore_ascii_case(name))
}

/// Reproduce the set of headers the original signature covered so the
/// re-signed request lists the same names in `SignedHeaders=`. Infra headers
/// (authorization, x-amz-date, x-amz-security-token, x-amz-content-sha256)
/// are skipped — the signer regenerates them with the real credentials.
fn collect_signing_headers(
    parsed: &ParsedHead,
    signed_header_names: &[String],
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::with_capacity(signed_header_names.len());
    let mut saw_host = false;
    for name in signed_header_names {
        if is_sigv4_infra_header(name) {
            continue;
        }
        if let Some(value) = parsed.find_header(name) {
            if name.eq_ignore_ascii_case("host") {
                saw_host = true;
            }
            out.push((name.clone(), value.to_string()));
        }
    }
    // `host` must always participate — the SDK always signs it even if the
    // parsed list somehow omits it.
    if !saw_host {
        out.push(("host".to_string(), parsed.host.clone()));
    }
    out
}

/// Replace the fake signing-infra headers with the new ones. Service-specific
/// headers (e.g. `x-amz-target`) pass through untouched so the re-signed
/// `SignedHeaders=` list remains internally consistent with the wire. Forces
/// `Connection: close` so keep-alive can't deliver a later request whose
/// Host/Authorization we wouldn't rewrite.
fn apply_resigned_headers(head_without_body: &str, resigned: &[(String, String)]) -> String {
    let mut lines = head_without_body.split("\r\n");
    let request_line = lines.next().unwrap_or("");

    let replaced: std::collections::HashSet<String> = resigned
        .iter()
        .map(|(k, _)| k.to_ascii_lowercase())
        .collect();

    let mut out: Vec<String> = Vec::with_capacity(16);
    out.push(request_line.to_string());

    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.find(':') else {
            continue;
        };
        let name = line[..colon].trim().to_ascii_lowercase();
        if name == "connection" || replaced.contains(&name) || is_sigv4_infra_header(&name) {
            continue;
        }
        // Strip any bare `\r`/`\n` — `split("\r\n")` keeps them in the
        // value, and an upstream HTTP parser that tolerates bare LF would
        // see an injected header. Defense-in-depth against a malicious or
        // buggy SDK inside the sandbox.
        out.push(line.replace(['\r', '\n'], ""));
    }

    for (k, v) in resigned {
        let sanitized = v.replace(['\r', '\n'], "");
        out.push(format!("{k}: {sanitized}"));
    }
    out.push("Connection: close".to_string());

    out.join("\r\n")
}

async fn write_client_error(
    tls: &mut tokio_rustls::server::TlsStream<TcpStream>,
    status: u16,
    reason: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let response =
        format!("HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    tls.write_all(response.as_bytes()).await?;
    tls.shutdown().await.ok();
    Ok(())
}

fn emit_resign_audit(
    audit_tx: &Option<tokio::sync::mpsc::UnboundedSender<String>>,
    target_host: &str,
    method: &str,
    path: &str,
    service: &str,
) {
    if let Some(tx) = audit_tx {
        let event = serde_json::json!({
            "type": "audit_event",
            "source": "sandbox-proxy",
            "action": format!("{method} {target_host}{path}"),
            "result": "success",
            "metadata": {
                "host": target_host,
                "mitm": true,
                "aws_resign": true,
                "service": service,
            }
        });
        let _ = tx.send(event.to_string());
    }
}

#[cfg(test)]
mod tests {

    /// Proxy state + caller for `AwsResignContext`. The resign dial now runs
    /// through the policy-aware connect, which needs both; these tests assert on
    /// what happens before it, and an empty policy claims nothing.
    fn policy_ctx() -> (
        std::sync::Arc<crate::proxy::ProxyState>,
        crate::peer_process::ActorContext,
    ) {
        let (state, rx) = crate::proxy::tests::test_state();
        std::mem::forget(rx);
        let actor = crate::peer_process::ActorContext::resolve("10.0.0.5:54321".parse().unwrap());
        (state, actor)
    }
    use super::*;

    #[test]
    fn parse_request_head_extracts_method_uri_host() {
        let head = "GET /my-bucket?list-type=2 HTTP/1.1\r\n\
                    Host: s3.us-east-1.amazonaws.com\r\n\
                    X-Amz-Date: 20230101T000000Z";
        let parsed = parse_request_head(head).unwrap();
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.uri, "/my-bucket?list-type=2");
        assert_eq!(parsed.path, "/my-bucket");
        assert_eq!(parsed.host, "s3.us-east-1.amazonaws.com");
        assert_eq!(parsed.find_header("x-amz-date"), Some("20230101T000000Z"));
    }

    #[test]
    fn parse_request_head_rejects_missing_host() {
        let head = "GET / HTTP/1.1\r\nX-Amz-Date: 20230101T000000Z";
        assert!(parse_request_head(head).is_none());
    }

    #[test]
    fn parsed_head_detects_chunked() {
        let head = "POST / HTTP/1.1\r\nHost: h.example.com\r\nTransfer-Encoding: chunked";
        let parsed = parse_request_head(head).unwrap();
        assert!(parsed.is_chunked());
    }

    #[test]
    fn parsed_head_reads_content_length() {
        let head = "POST / HTTP/1.1\r\nHost: h.example.com\r\nContent-Length: 42";
        let parsed = parse_request_head(head).unwrap();
        assert_eq!(parsed.content_length(), Some(42));
    }

    #[test]
    fn apply_resigned_headers_strips_infra_keeps_service_headers() {
        let head = "POST / HTTP/1.1\r\n\
                    Host: dynamodb.us-east-1.amazonaws.com\r\n\
                    Authorization: AWS4-HMAC-SHA256 Credential=LENSFAKE...\r\n\
                    X-Amz-Date: 20230101T000000Z\r\n\
                    X-Amz-Content-Sha256: abc\r\n\
                    X-Amz-Security-Token: fake-token\r\n\
                    X-Amz-Target: DynamoDB_20120810.PutItem\r\n\
                    User-Agent: aws-sdk-rust";
        let resigned = vec![
            (
                "authorization".to_string(),
                "AWS4-HMAC-SHA256 Credential=ASIA...".to_string(),
            ),
            ("x-amz-date".to_string(), "20240202T000000Z".to_string()),
            ("x-amz-security-token".to_string(), "real-token".to_string()),
            ("x-amz-content-sha256".to_string(), "deadbeef".to_string()),
        ];
        let out = apply_resigned_headers(head, &resigned);
        assert!(out.contains("POST / HTTP/1.1"));
        assert!(out.contains("Host: dynamodb.us-east-1.amazonaws.com"));
        assert!(out.contains("User-Agent: aws-sdk-rust"));
        assert!(
            out.contains("X-Amz-Target: DynamoDB_20120810.PutItem"),
            "service-specific x-amz-target must be preserved"
        );
        assert!(!out.contains("LENSFAKE"));
        assert!(!out.contains("fake-token"));
        assert!(out.contains("Credential=ASIA..."));
        assert!(out.contains("x-amz-date: 20240202T000000Z"));
        assert!(out.contains("Connection: close"));
    }

    #[test]
    fn collect_signing_headers_replays_original_signed_set_minus_infra() {
        let head = "POST / HTTP/1.1\r\n\
                    Host: dynamodb.us-east-1.amazonaws.com\r\n\
                    X-Amz-Target: DynamoDB_20120810.PutItem\r\n\
                    Content-Type: application/x-amz-json-1.0\r\n\
                    X-Amz-Date: 20230101T000000Z";
        let parsed = parse_request_head(head).unwrap();
        let signed = vec![
            "host".to_string(),
            "x-amz-target".to_string(),
            "x-amz-date".to_string(), // infra — must be skipped
            "content-type".to_string(),
        ];
        let collected = collect_signing_headers(&parsed, &signed);
        let names: Vec<&str> = collected.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"host"));
        assert!(names.contains(&"x-amz-target"));
        assert!(names.contains(&"content-type"));
        assert!(!names.iter().any(|n| n.eq_ignore_ascii_case("x-amz-date")));
    }

    #[test]
    fn collect_signing_headers_adds_host_when_missing_from_signed_list() {
        let head = "GET / HTTP/1.1\r\nHost: s3.us-east-1.amazonaws.com";
        let parsed = parse_request_head(head).unwrap();
        // A pathological signed list without `host` — we still must sign it.
        let collected = collect_signing_headers(&parsed, &[]);
        assert!(collected.iter().any(|(k, _)| k == "host"));
    }

    #[test]
    fn apply_resigned_headers_is_idempotent_against_duplicate_resigned_keys() {
        let head = "GET / HTTP/1.1\r\nHost: h.example.com";
        let resigned = vec![
            (
                "authorization".to_string(),
                "AWS4-HMAC-SHA256 a".to_string(),
            ),
            (
                "authorization".to_string(),
                "AWS4-HMAC-SHA256 b".to_string(),
            ),
        ];
        // Even with duplicates in the resigned list, no pre-existing
        // Authorization leaks through (there was none here anyway).
        let out = apply_resigned_headers(head, &resigned);
        assert!(out.contains("AWS4-HMAC-SHA256 a"));
        assert!(out.contains("AWS4-HMAC-SHA256 b"));
    }

    // ---- end-to-end integration tests ----

    use crate::aws_sigv4::{AwsSigv4Config, BodyMode, ResignRequest, resign_request};
    use rustls::pki_types::ServerName;
    use std::time::UNIX_EPOCH;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsConnector;

    const TEST_HOSTNAME: &str = "s3.us-east-1.amazonaws.com";

    fn real_config() -> AwsSigv4Config {
        AwsSigv4Config {
            access_key_id: "ASIAREALEXAMPLE".to_string(),
            secret_access_key: "real-secret-example".to_string(),
            session_token: "real-session-token".to_string(),
        }
    }

    fn fake_config() -> AwsSigv4Config {
        AwsSigv4Config {
            access_key_id: "LENSFAKE00AABB0000CC".to_string(),
            secret_access_key: "placeholder-secret".to_string(),
            session_token: "placeholder-session-token".to_string(),
        }
    }

    fn test_tls_server_config(ca: &EphemeralCa, hostname: &str) -> Arc<rustls::ServerConfig> {
        let certified_key = ca.certified_key_for_domain(hostname).unwrap();
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(crate::mitm::SingleCertResolver(certified_key)));
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }

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

    /// What the sandbox client pretends to send and which regional endpoint
    /// it's targeting. `extra_signed` simulates service-specific signed
    /// headers like DynamoDB's `x-amz-target`.
    struct HarnessRequest<'a> {
        method: &'a str,
        uri: &'a str,
        body: &'a [u8],
        service: &'a str,
        signed_with_unsigned_payload: bool,
        extra_signed: &'a [(String, String)],
        hostname: &'a str,
        region: &'a str,
    }

    /// Build a sandbox-style pre-signed AWS request: method + path + host
    /// headers + Authorization signed with the FAKE secret. Returns raw bytes
    /// ready to write over a TLS stream.
    fn sandbox_signed_request(spec: &HarnessRequest<'_>) -> Vec<u8> {
        let mut headers = vec![("host".to_string(), spec.hostname.to_string())];
        for (k, v) in spec.extra_signed {
            headers.push((k.clone(), v.clone()));
        }
        let body_mode = if spec.signed_with_unsigned_payload {
            BodyMode::Unsigned
        } else {
            let mut hasher = Sha256::new();
            hasher.update(spec.body);
            BodyMode::Signed {
                sha256_hex: hex::encode(hasher.finalize()),
            }
        };
        let time = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let req = ResignRequest {
            method: spec.method,
            uri: spec.uri,
            service: spec.service,
            region: spec.region,
            headers: &headers,
            body_mode,
        };
        let signed = resign_request(&req, &fake_config(), time).unwrap();

        let hostname = spec.hostname;
        let method = spec.method;
        let uri = spec.uri;
        let mut out = format!("{method} {uri} HTTP/1.1\r\nHost: {hostname}\r\n");
        if !spec.body.is_empty() {
            out.push_str(&format!("Content-Length: {}\r\n", spec.body.len()));
        } else {
            out.push_str("Content-Length: 0\r\n");
        }
        // Any extra signed headers must appear on the wire so the original
        // signature (over fake creds) references real header values.
        for (k, v) in spec.extra_signed {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        for (k, v) in &signed {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str("Connection: close\r\n\r\n");

        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(spec.body);
        bytes
    }

    /// Run the end-to-end flow: sandbox client → MITM resign → TLS upstream.
    /// Returns the headers the upstream observed + the request body.
    async fn run_resign_harness(spec: &HarnessRequest<'_>) -> (String, Vec<u8>) {
        let body = spec.body;
        let hostname = spec.hostname;
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        let ca = EphemeralCa::new().unwrap();

        // Upstream TLS server: reads head + body, replies 200 OK
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_tls_config = test_tls_server_config(&ca, hostname);
        let expected_body_len = body.len();

        let upstream_handle = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let acceptor = TlsAcceptor::from(upstream_tls_config);
            let mut tls = acceptor.accept(stream).await.unwrap();

            // Read head
            let mut head_buf: Vec<u8> = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                let n = tls.read(&mut byte).await.unwrap();
                if n == 0 {
                    break;
                }
                head_buf.push(byte[0]);
                if head_buf.len() >= 4 && head_buf[head_buf.len() - 4..] == *b"\r\n\r\n" {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&head_buf[..head_buf.len() - 4]).to_string();

            // Read body
            let mut body_read = vec![0u8; expected_body_len];
            if expected_body_len > 0 {
                tls.read_exact(&mut body_read).await.ok();
            }

            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            tls.shutdown().await.ok();
            (head, body_read)
        });

        // Sandbox client side
        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let client_root_store = ca_root_store(&ca);

        let request_bytes = sandbox_signed_request(spec);

        let client_hostname = hostname.to_string();
        let client_handle = tokio::spawn(async move {
            let stream = TcpStream::connect(client_addr).await.unwrap();
            let client_cfg = rustls::ClientConfig::builder()
                .with_root_certificates(client_root_store)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(client_cfg));
            let server_name = ServerName::try_from(client_hostname).unwrap();
            let mut tls = connector.connect(server_name, stream).await.unwrap();
            tls.write_all(&request_bytes).await.unwrap();
            tls.flush().await.ok();
            let mut resp = Vec::new();
            let _ = tls.read_to_end(&mut resp).await;
        });

        // Build the MITM handler with a bespoke upstream connector that
        // redirects to our test server (via a `connect_upstream_tls`
        // replacement would be cleaner — we bypass via overriding hostname
        // resolution: connect directly to `upstream_addr` but still validate
        // against the `s3.us-east-1.amazonaws.com` cert because our root
        // store trusts the ephemeral CA for that hostname).
        //
        // We run the handler with a stand-in that routes to 127.0.0.1:port.
        let (client_stream, _) = client_listener.accept().await.unwrap();
        let mut configs = HashMap::new();
        configs.insert(fake_config().access_key_id.clone(), real_config());
        let (policy_state, policy_actor) = policy_ctx();
        let ctx = AwsResignContext {
            configs: &configs,
            ca: &ca,
            extra_ca_certs: &[],
            audit_tx: &None,
            state: &policy_state,
            actor: &policy_actor,
        };

        // Run the resign. The handler connects to `TEST_HOSTNAME:target_port`
        // internally — we need to make TEST_HOSTNAME resolve to our loopback
        // upstream. We do that by passing the loopback addr as target_host
        // to the internal connect — but rustls server cert name still says
        // TEST_HOSTNAME. Trick: use `handle_aws_resign_with_upstream` shim
        // that takes a pre-opened upstream.
        //
        // (Simpler approach below: use a custom connect function.)
        // copy_bidirectional may surface the upstream's close_notify absence
        // as an error at test time — tolerate it like the existing mitm
        // harness does (mitm.rs `run_mitm_harness`).
        if let Err(e) = handle_aws_resign_harness(
            client_stream,
            hostname,
            upstream_addr.port(),
            &ctx,
            ca_root_store(&ca),
        )
        .await
        {
            let msg = e.to_string();
            assert!(
                msg.contains("close_notify")
                    || msg.contains("closed")
                    || msg.contains("broken pipe"),
                "unexpected resign error: {msg}"
            );
        }

        client_handle.await.ok();
        let (head, body_read) = upstream_handle.await.unwrap();
        (head, body_read)
    }

    /// Test-only variant of `handle_aws_resign` that wires a known upstream
    /// root store (so the ephemeral CA is trusted for upstream TLS too).
    /// Reuses the production `prepare_resigned_request` + `forward_resigned`
    /// so the test path can't drift from the real one.
    async fn handle_aws_resign_harness(
        client: TcpStream,
        target_host: &str,
        target_port: u16,
        ctx: &AwsResignContext<'_>,
        upstream_root_store: rustls::RootCertStore,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut tls_client, head_str) = accept_and_read_head(client, target_host, ctx.ca).await?;
        let prepared = prepare_resigned_request(&mut tls_client, head_str, ctx.configs)
            .await?
            .expect("test request must re-sign successfully");

        // Custom upstream TLS: loopback TCP, but keep TEST_HOSTNAME for cert
        // verification via the ephemeral CA's root store.
        let tcp = TcpStream::connect(format!("127.0.0.1:{target_port}")).await?;
        let client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(upstream_root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_cfg));
        let tls_upstream = connector
            .connect(ServerName::try_from(target_host.to_string())?, tcp)
            .await?;

        forward_resigned(&mut tls_client, tls_upstream, prepared).await
    }

    #[tokio::test]
    async fn resign_s3_replaces_fake_signature_with_real() {
        let (head, _body) = run_resign_harness(&HarnessRequest {
            method: "GET",
            uri: "/my-bucket?list-type=2",
            body: b"",
            service: "s3",
            signed_with_unsigned_payload: true, // UNSIGNED-PAYLOAD for S3
            extra_signed: &[],
            hostname: TEST_HOSTNAME,
            region: "us-east-1",
        })
        .await;

        assert!(head.contains("GET /my-bucket?list-type=2 HTTP/1.1"));
        assert!(head.contains("Host: s3.us-east-1.amazonaws.com"));
        assert!(
            !head.contains("LENSFAKE"),
            "no fake access key must reach upstream: {head}"
        );
        assert!(
            head.contains("Credential=ASIAREALEXAMPLE/"),
            "real access key in signature: {head}"
        );
        assert!(
            head.contains("/us-east-1/s3/aws4_request"),
            "region+service in scope: {head}"
        );
        assert!(
            head.to_ascii_lowercase()
                .contains("x-amz-content-sha256: unsigned-payload"),
            "S3 must use UNSIGNED-PAYLOAD: {head}"
        );
        assert!(
            head.to_ascii_lowercase()
                .contains("x-amz-security-token: real-session-token"),
            "real session token included: {head}"
        );
    }

    #[tokio::test]
    async fn resign_non_s3_buffers_and_signs_with_sha256() {
        let body: &[u8] = b"{\"TableName\":\"demo\"}";
        let (head, body_seen) = run_resign_harness(&HarnessRequest {
            method: "POST",
            uri: "/",
            body,
            service: "dynamodb",
            signed_with_unsigned_payload: false, // precomputed SHA for non-S3
            extra_signed: &[],
            hostname: TEST_HOSTNAME,
            region: "us-east-1",
        })
        .await;

        assert!(
            head.contains("/us-east-1/dynamodb/aws4_request"),
            "non-S3 service preserved: {head}"
        );
        assert!(
            !head.to_ascii_lowercase().contains("unsigned-payload"),
            "non-S3 must not use UNSIGNED-PAYLOAD: {head}"
        );
        assert_eq!(body_seen, body, "body must reach upstream unchanged");
    }

    #[tokio::test]
    async fn resign_preserves_service_specific_x_amz_target_in_signed_headers() {
        // DynamoDB selects the operation via `x-amz-target`. If the resign
        // path strips this header (or drops it from the signed-headers list),
        // DynamoDB returns `UnknownOperationException`. The SDK signs with
        // `x-amz-target` in `SignedHeaders=` — the re-sign must do the same.
        let body: &[u8] = b"{\"TableName\":\"demo\"}";
        let extra_signed = vec![(
            "x-amz-target".to_string(),
            "DynamoDB_20120810.PutItem".to_string(),
        )];
        let (head, _body) = run_resign_harness(&HarnessRequest {
            method: "POST",
            uri: "/",
            body,
            service: "dynamodb",
            signed_with_unsigned_payload: false,
            extra_signed: &extra_signed,
            hostname: TEST_HOSTNAME,
            region: "us-east-1",
        })
        .await;

        assert!(
            head.contains("X-Amz-Target: DynamoDB_20120810.PutItem")
                || head.contains("x-amz-target: DynamoDB_20120810.PutItem"),
            "x-amz-target must reach upstream: {head}"
        );
        let auth_line = head
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
            .expect("authorization line");
        assert!(
            auth_line.to_ascii_lowercase().contains("x-amz-target"),
            "x-amz-target must be in the re-signed SignedHeaders list: {auth_line}"
        );
    }

    #[tokio::test]
    async fn resign_non_s3_rejects_oversize_body() {
        // The handler rejects requests with Content-Length > MAX. We don't
        // need the TLS upstream for this — the handler should answer 413
        // before connecting upstream. Verify via a minimal client-side test.
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        let ca = EphemeralCa::new().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let root_store = ca_root_store(&ca);

        // Build a fake-signed request that claims a 2 MB body.
        let huge_len = MAX_BUFFERED_BODY_BYTES + 1;
        let method = "POST";
        let uri = "/";
        let signed = {
            let headers = vec![("host".to_string(), TEST_HOSTNAME.to_string())];
            let time = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
            let req = ResignRequest {
                method,
                uri,
                service: "dynamodb",
                region: "us-east-1",
                headers: &headers,
                // Any hash — handler rejects before verifying.
                body_mode: BodyMode::Signed {
                    sha256_hex: "0".repeat(64),
                },
            };
            resign_request(&req, &fake_config(), time).unwrap()
        };
        let mut req = format!(
            "{method} {uri} HTTP/1.1\r\nHost: {TEST_HOSTNAME}\r\nContent-Length: {huge_len}\r\n"
        );
        for (k, v) in &signed {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("Connection: close\r\n\r\n");

        let client_handle = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let cfg = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(cfg));
            let server_name = ServerName::try_from(TEST_HOSTNAME).unwrap();
            let mut tls = connector.connect(server_name, stream).await.unwrap();
            tls.write_all(req.as_bytes()).await.unwrap();
            // Client doesn't send the body — handler should have already
            // rejected based on Content-Length.
            let mut resp = Vec::new();
            let _ = tls.read_to_end(&mut resp).await;
            String::from_utf8_lossy(&resp).to_string()
        });

        let (client_stream, _) = listener.accept().await.unwrap();
        let mut configs = HashMap::new();
        configs.insert(fake_config().access_key_id.clone(), real_config());
        let (policy_state, policy_actor) = policy_ctx();
        let ctx = AwsResignContext {
            configs: &configs,
            ca: &ca,
            extra_ca_certs: &[],
            audit_tx: &None,
            state: &policy_state,
            actor: &policy_actor,
        };

        let _ = handle_aws_resign(client_stream, TEST_HOSTNAME, 1, &ctx).await;
        let response = client_handle.await.unwrap();
        assert!(
            response.contains("413"),
            "expected 413 Payload Too Large, got: {response}"
        );
    }

    #[tokio::test]
    async fn resign_non_s3_rejects_chunked_transfer() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let ca = EphemeralCa::new().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let root_store = ca_root_store(&ca);

        let signed = {
            let headers = vec![("host".to_string(), TEST_HOSTNAME.to_string())];
            let time = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
            let req = ResignRequest {
                method: "POST",
                uri: "/",
                service: "dynamodb",
                region: "us-east-1",
                headers: &headers,
                body_mode: BodyMode::Signed {
                    sha256_hex: "0".repeat(64),
                },
            };
            resign_request(&req, &fake_config(), time).unwrap()
        };
        let mut req =
            format!("POST / HTTP/1.1\r\nHost: {TEST_HOSTNAME}\r\nTransfer-Encoding: chunked\r\n");
        for (k, v) in &signed {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("Connection: close\r\n\r\n0\r\n\r\n");

        let client_handle = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let cfg = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(cfg));
            let server_name = ServerName::try_from(TEST_HOSTNAME).unwrap();
            let mut tls = connector.connect(server_name, stream).await.unwrap();
            tls.write_all(req.as_bytes()).await.unwrap();
            let mut resp = Vec::new();
            let _ = tls.read_to_end(&mut resp).await;
            String::from_utf8_lossy(&resp).to_string()
        });

        let (client_stream, _) = listener.accept().await.unwrap();
        let mut configs = HashMap::new();
        configs.insert(fake_config().access_key_id.clone(), real_config());
        let (policy_state, policy_actor) = policy_ctx();
        let ctx = AwsResignContext {
            configs: &configs,
            ca: &ca,
            extra_ca_certs: &[],
            audit_tx: &None,
            state: &policy_state,
            actor: &policy_actor,
        };
        let _ = handle_aws_resign(client_stream, TEST_HOSTNAME, 1, &ctx).await;
        let response = client_handle.await.unwrap();
        assert!(
            response.contains("411"),
            "expected 411 Length Required, got: {response}"
        );
    }

    #[tokio::test]
    async fn resign_s3_rejects_streaming_payload_signing() {
        // S3 `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` embeds per-chunk signatures
        // inside the body framing, seeded by the outer signature. Our
        // re-sign replaces the outer Authorization but can't rewrite the
        // per-chunk framing, so AWS rejects. Reject up-front with 501.
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let ca = EphemeralCa::new().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let root_store = ca_root_store(&ca);

        // Hand-craft the auth header using the fake key — handler must
        // detect STREAMING before it re-signs, so exact signature bytes
        // don't matter here.
        let req = format!(
            "PUT /my-bucket/my-object HTTP/1.1\r\n\
             Host: {TEST_HOSTNAME}\r\n\
             Content-Length: 100\r\n\
             Authorization: AWS4-HMAC-SHA256 \
             Credential=LENSFAKE00AABB0000CC/20230101/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=00\r\n\
             X-Amz-Date: 20230101T000000Z\r\n\
             X-Amz-Content-Sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD\r\n\
             Connection: close\r\n\r\n"
        );

        let client_handle = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let cfg = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(cfg));
            let server_name = ServerName::try_from(TEST_HOSTNAME).unwrap();
            let mut tls = connector.connect(server_name, stream).await.unwrap();
            tls.write_all(req.as_bytes()).await.unwrap();
            let mut resp = Vec::new();
            let _ = tls.read_to_end(&mut resp).await;
            String::from_utf8_lossy(&resp).to_string()
        });

        let (client_stream, _) = listener.accept().await.unwrap();
        let mut configs = HashMap::new();
        configs.insert(fake_config().access_key_id.clone(), real_config());
        let (policy_state, policy_actor) = policy_ctx();
        let ctx = AwsResignContext {
            configs: &configs,
            ca: &ca,
            extra_ca_certs: &[],
            audit_tx: &None,
            state: &policy_state,
            actor: &policy_actor,
        };
        let _ = handle_aws_resign(client_stream, TEST_HOSTNAME, 1, &ctx).await;
        let response = client_handle.await.unwrap();
        assert!(
            response.contains("501"),
            "expected 501 for S3 STREAMING-AWS4-HMAC-SHA256-PAYLOAD, got: {response}"
        );
    }

    #[tokio::test]
    async fn resign_non_s3_rejects_missing_content_length() {
        // Non-S3 bodies must be fully buffered to compute SHA-256 before
        // signing. A missing Content-Length and no Transfer-Encoding means
        // we can't know the body length, so signing an empty body here and
        // letting copy_bidirectional forward the real bytes would produce
        // a signature AWS rejects. Better to fail fast with 411.
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let ca = EphemeralCa::new().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let root_store = ca_root_store(&ca);

        let signed = {
            let headers = vec![("host".to_string(), TEST_HOSTNAME.to_string())];
            let time = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
            let req = ResignRequest {
                method: "POST",
                uri: "/",
                service: "dynamodb",
                region: "us-east-1",
                headers: &headers,
                body_mode: BodyMode::Signed {
                    sha256_hex: "0".repeat(64),
                },
            };
            resign_request(&req, &fake_config(), time).unwrap()
        };
        // Deliberately NO Content-Length, NO Transfer-Encoding.
        let mut req = format!("POST / HTTP/1.1\r\nHost: {TEST_HOSTNAME}\r\n");
        for (k, v) in &signed {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("Connection: close\r\n\r\n");

        let client_handle = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let cfg = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(cfg));
            let server_name = ServerName::try_from(TEST_HOSTNAME).unwrap();
            let mut tls = connector.connect(server_name, stream).await.unwrap();
            tls.write_all(req.as_bytes()).await.unwrap();
            let mut resp = Vec::new();
            let _ = tls.read_to_end(&mut resp).await;
            String::from_utf8_lossy(&resp).to_string()
        });

        let (client_stream, _) = listener.accept().await.unwrap();
        let mut configs = HashMap::new();
        configs.insert(fake_config().access_key_id.clone(), real_config());
        let (policy_state, policy_actor) = policy_ctx();
        let ctx = AwsResignContext {
            configs: &configs,
            ca: &ca,
            extra_ca_certs: &[],
            audit_tx: &None,
            state: &policy_state,
            actor: &policy_actor,
        };
        let _ = handle_aws_resign(client_stream, TEST_HOSTNAME, 1, &ctx).await;
        let response = client_handle.await.unwrap();
        assert!(
            response.contains("411"),
            "expected 411 for non-S3 without Content-Length, got: {response}"
        );
    }

    #[tokio::test]
    async fn resign_rejects_unknown_fake_access_key() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let ca = EphemeralCa::new().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let root_store = ca_root_store(&ca);

        // Sign with a fake key that's not in the configs map.
        let unknown_fake = AwsSigv4Config {
            access_key_id: "LENSFAKEUNKNOWN00001".to_string(),
            secret_access_key: "x".to_string(),
            session_token: "x".to_string(),
        };
        let signed = {
            let headers = vec![("host".to_string(), TEST_HOSTNAME.to_string())];
            let time = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
            let req = ResignRequest {
                method: "GET",
                uri: "/",
                service: "s3",
                region: "us-east-1",
                headers: &headers,
                body_mode: BodyMode::Unsigned,
            };
            resign_request(&req, &unknown_fake, time).unwrap()
        };
        let mut req = format!("GET / HTTP/1.1\r\nHost: {TEST_HOSTNAME}\r\nContent-Length: 0\r\n");
        for (k, v) in &signed {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("Connection: close\r\n\r\n");

        let client_handle = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let cfg = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(cfg));
            let server_name = ServerName::try_from(TEST_HOSTNAME).unwrap();
            let mut tls = connector.connect(server_name, stream).await.unwrap();
            tls.write_all(req.as_bytes()).await.unwrap();
            let mut resp = Vec::new();
            let _ = tls.read_to_end(&mut resp).await;
            String::from_utf8_lossy(&resp).to_string()
        });

        let (client_stream, _) = listener.accept().await.unwrap();
        let configs: HashMap<String, AwsSigv4Config> = HashMap::new();
        let (policy_state, policy_actor) = policy_ctx();
        let ctx = AwsResignContext {
            configs: &configs,
            ca: &ca,
            extra_ca_certs: &[],
            audit_tx: &None,
            state: &policy_state,
            actor: &policy_actor,
        };
        let _ = handle_aws_resign(client_stream, TEST_HOSTNAME, 1, &ctx).await;
        let response = client_handle.await.unwrap();
        assert!(
            response.contains("401"),
            "expected 401 for unknown fake key, got: {response}"
        );
    }

    // ---- mock-AWS cryptographic verification ----
    //
    // The tests above prove the re-signed request *looks* valid. They don't
    // prove a real AWS service would accept the signature — a subtle bug in
    // canonical-request construction (wrong header ordering, wrong body hash,
    // wrong service scope) would go undetected.
    //
    // `verify_resigned_signature` below acts as a mock AWS endpoint: it
    // parses the received Authorization header, reconstructs the canonical
    // request from what actually arrived on the wire, re-signs with the real
    // credentials, and asserts the signatures match byte-for-byte.
    //
    // This is circular in the sense that both sides use `aws-sigv4`. But it
    // *does* catch any request-tampering bug (MITM drops a header, rewrites
    // the URI, changes the body) because the canonical reconstruction
    // depends on the wire state.

    /// Parse `x-amz-date` in ISO 8601 basic format (`YYYYMMDDTHHMMSSZ`) into
    /// a `SystemTime`. Required so the verifier re-signs using the exact
    /// timestamp the MITM embedded in its `Authorization` canonical request.
    fn parse_amz_date(s: &str) -> Result<std::time::SystemTime, String> {
        if s.len() != 16 || s.as_bytes().get(8).is_none_or(|b| *b != b'T') {
            return Err(format!("invalid x-amz-date: {s}"));
        }
        let year: i64 = s[0..4].parse().map_err(|_| "bad year".to_string())?;
        let month: i64 = s[4..6].parse().map_err(|_| "bad month".to_string())?;
        let day: i64 = s[6..8].parse().map_err(|_| "bad day".to_string())?;
        let hour: i64 = s[9..11].parse().map_err(|_| "bad hour".to_string())?;
        let minute: i64 = s[11..13].parse().map_err(|_| "bad minute".to_string())?;
        let second: i64 = s[13..15].parse().map_err(|_| "bad second".to_string())?;

        // Howard Hinnant's days_from_civil — Gregorian to serial day count
        // relative to 1970-01-01. Shift Jan/Feb to the previous year so the
        // leap-day offset math works out to a single formula.
        let y = if month <= 2 { year - 1 } else { year };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let m_shift = if month > 2 { month - 3 } else { month + 9 };
        let doy = (153 * m_shift + 2) / 5 + day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days_since_epoch = era * 146_097 + doe - 719_468;

        let secs = days_since_epoch * 86_400 + hour * 3600 + minute * 60 + second;
        let secs: u64 = secs
            .try_into()
            .map_err(|_| "date before 1970".to_string())?;
        Ok(UNIX_EPOCH + std::time::Duration::from_secs(secs))
    }

    /// Verify that a re-signed request produces the signature the real AWS
    /// service would compute for the same canonical request. Mirrors what an
    /// AWS endpoint does on signature validation: parses the signing time
    /// from `x-amz-date`, reconstructs the canonical request from the
    /// received headers/body, re-signs with the expected real credentials,
    /// and compares the resulting signature byte-for-byte.
    fn verify_resigned_signature(
        method: &str,
        head: &str,
        body: &[u8],
        expected: &AwsSigv4Config,
    ) -> Result<(), String> {
        let parsed = parse_request_head(head).ok_or("cannot parse head")?;

        let received_auth = parsed
            .find_header("authorization")
            .ok_or("no authorization header")?;
        let sig_auth = crate::aws_sigv4::parse_authorization(received_auth)
            .ok_or("authorization is not SigV4")?;

        // Re-signing must use the exact timestamp the MITM embedded — a
        // 1-second drift changes the signature entirely.
        let amz_date = parsed
            .find_header("x-amz-date")
            .ok_or("no x-amz-date header")?;
        let signing_time = parse_amz_date(amz_date)?;

        let received_signature = received_auth
            .split(", ")
            .find_map(|p| p.trim().strip_prefix("Signature="))
            .ok_or("no Signature= in auth")?;

        let body_mode = match parsed.find_header("x-amz-content-sha256") {
            Some("UNSIGNED-PAYLOAD") => BodyMode::Unsigned,
            Some(hex_digest) => BodyMode::Signed {
                sha256_hex: hex_digest.to_string(),
            },
            None => {
                // Non-S3 without the content-sha256 header: compute from body.
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(body);
                BodyMode::Signed {
                    sha256_hex: hex::encode(hasher.finalize()),
                }
            }
        };

        // Reconstruct the signed-headers set from what actually arrived.
        // Any mutation after signing (e.g. a header dropped by the proxy)
        // would surface here as "missing signed header" or as a canonical
        // request that differs from what the sender signed.
        let mut headers = Vec::new();
        for name in &sig_auth.signed_headers {
            let value = parsed
                .find_header(name)
                .ok_or_else(|| format!("signed header `{name}` missing from request"))?;
            headers.push((name.clone(), value.to_string()));
        }

        let req = ResignRequest {
            method,
            uri: &parsed.uri,
            service: &sig_auth.service,
            region: &sig_auth.region,
            headers: &headers,
            body_mode,
        };
        let expected_headers = resign_request(&req, expected, signing_time)
            .map_err(|e| format!("re-signing failed: {e}"))?;

        let expected_auth = expected_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.as_str())
            .ok_or("re-sign produced no authorization header")?;
        let expected_signature = expected_auth
            .split(", ")
            .find_map(|p| p.trim().strip_prefix("Signature="))
            .ok_or("no Signature= in expected auth")?;

        if expected_signature == received_signature {
            Ok(())
        } else {
            Err(format!(
                "signature mismatch:\n  received: {received_signature}\n  expected: {expected_signature}"
            ))
        }
    }

    #[tokio::test]
    async fn mock_aws_validates_resigned_s3_signature() {
        let (head, body) = run_resign_harness(&HarnessRequest {
            method: "GET",
            uri: "/my-bucket?list-type=2",
            body: b"",
            service: "s3",
            signed_with_unsigned_payload: true,
            extra_signed: &[],
            hostname: TEST_HOSTNAME,
            region: "us-east-1",
        })
        .await;

        verify_resigned_signature("GET", &head, &body, &real_config())
            .expect("mock AWS must accept the re-signed S3 request");
    }

    #[tokio::test]
    async fn mock_aws_validates_resigned_dynamodb_signature() {
        let body: &[u8] = b"{\"TableName\":\"demo\"}";
        let extra_signed = vec![(
            "x-amz-target".to_string(),
            "DynamoDB_20120810.PutItem".to_string(),
        )];
        let (head, body_seen) = run_resign_harness(&HarnessRequest {
            method: "POST",
            uri: "/",
            body,
            service: "dynamodb",
            signed_with_unsigned_payload: false,
            extra_signed: &extra_signed,
            hostname: TEST_HOSTNAME,
            region: "us-east-1",
        })
        .await;

        verify_resigned_signature("POST", &head, &body_seen, &real_config())
            .expect("mock AWS must accept the re-signed DynamoDB request with x-amz-target");
    }

    #[tokio::test]
    async fn mock_aws_rejects_signature_computed_with_wrong_secret() {
        let (head, body) = run_resign_harness(&HarnessRequest {
            method: "GET",
            uri: "/my-bucket?list-type=2",
            body: b"",
            service: "s3",
            signed_with_unsigned_payload: true,
            extra_signed: &[],
            hostname: TEST_HOSTNAME,
            region: "us-east-1",
        })
        .await;

        let wrong = AwsSigv4Config {
            secret_access_key: "a-different-secret-key".to_string(),
            ..real_config()
        };
        assert!(
            verify_resigned_signature("GET", &head, &body, &wrong).is_err(),
            "verifier must reject a signature that doesn't match the expected secret"
        );
    }

    #[tokio::test]
    async fn resign_end_to_end_preserves_non_default_region_scope() {
        // Regression guard for the cross-region re-sign bug: when the client
        // inside the sandbox signs for a region other than the connection's
        // default (e.g. `--region eu-west-1`), the upstream request must
        // carry that same region in the credential scope. Otherwise AWS
        // rejects with "Credential should be scoped to a valid region" on
        // STS/CloudWatch or "AuthFailure" on EC2.
        //
        // `signed_with_unsigned_payload: false` because EC2 (like every
        // non-S3 service) requires the empty-body SHA in the signature;
        // UNSIGNED-PAYLOAD is an S3-only affordance.
        let (head, body) = run_resign_harness(&HarnessRequest {
            method: "GET",
            uri: "/",
            body: b"",
            service: "ec2",
            signed_with_unsigned_payload: false,
            extra_signed: &[],
            hostname: "ec2.eu-west-1.amazonaws.com",
            region: "eu-west-1",
        })
        .await;

        assert!(
            head.contains("/eu-west-1/ec2/aws4_request"),
            "upstream Authorization must be scoped to eu-west-1, got: {head}"
        );
        assert!(
            !head.contains("/us-east-1/"),
            "no us-east-1 scope must leak into the upstream request: {head}"
        );

        // Mock-AWS validation: rebuild the canonical request from what
        // arrived upstream and confirm the signature is cryptographically
        // correct for the eu-west-1 credential scope. This is what a real
        // eu-west-1 EC2 endpoint does on signature validation.
        verify_resigned_signature("GET", &head, &body, &real_config())
            .expect("mock AWS at eu-west-1 must accept the re-signed request");
    }

    #[tokio::test]
    async fn mock_aws_rejects_tampered_signed_header_value() {
        // Swap x-amz-target's value AFTER the MITM has signed the request —
        // the verifier must rebuild the canonical request from what actually
        // arrived and notice the signature no longer matches. This is
        // exactly what a real DynamoDB endpoint does on signature validation.
        let body: &[u8] = b"{\"TableName\":\"demo\"}";
        let extra_signed = vec![(
            "x-amz-target".to_string(),
            "DynamoDB_20120810.PutItem".to_string(),
        )];
        let (head, body_seen) = run_resign_harness(&HarnessRequest {
            method: "POST",
            uri: "/",
            body,
            service: "dynamodb",
            signed_with_unsigned_payload: false,
            extra_signed: &extra_signed,
            hostname: TEST_HOSTNAME,
            region: "us-east-1",
        })
        .await;

        let tampered = head.replace("DynamoDB_20120810.PutItem", "DynamoDB_20120810.DeleteItem");
        assert_ne!(
            tampered, head,
            "test precondition: tamper must change the head"
        );
        assert!(
            verify_resigned_signature("POST", &tampered, &body_seen, &real_config()).is_err(),
            "verifier must reject a request whose signed-header value was altered after signing"
        );
    }
}
