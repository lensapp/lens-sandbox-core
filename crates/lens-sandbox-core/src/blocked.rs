//! The response a client gets when sandbox policy refuses its request.
//!
//! A bare `403` reads to an agent as the destination refusing it, so every
//! policy refusal on every door sends this one response instead: a reason
//! phrase, an `X-Sandbox-Blocked` header carrying a fixed reason code, an
//! RFC 9209 `Proxy-Status`, and a one-line plain-text body whose first line is
//! stable enough to match on.
//!
//! The library does not know which product embeds it, so the wording is
//! neutral unless the embedder names its product with
//! [`crate::proxy::ProxyState::set_block_label`].
//!
//! The body names the request and nothing else. It carries no query string, no
//! credential placeholder, no rule or policy name, and none of the free-text
//! detail the log records: whoever reads it is the workload the policy is
//! keeping things from.
//!
//! Most clients never show the answer to a `CONNECT`, so a refused tunnel is
//! accepted and the refusal is given inside it (see [`answer_in_tunnel`]): the
//! sandbox CA is already trusted, and the request the client then sends is
//! answered with this response. The destination is never dialled.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Why policy refused a request. The set is fixed: a consumer matches on
/// [`BlockReason::code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockReason {
    /// A rule, or the default verdict, denies the request.
    PolicyDeny,
    /// A rule names the destination, but not for the binary that asked.
    BinaryNotAllowed,
    /// The developer was asked and did not allow it.
    AskDeclined,
    /// The request carries a credential the developer did not release.
    CredentialGate,
    /// The upstream proxy refused the destination by its own policy.
    UpstreamPolicy,
}

impl BlockReason {
    /// The value of `X-Sandbox-Blocked`, and the one the body names.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::PolicyDeny => "policy-deny",
            Self::BinaryNotAllowed => "binary-not-allowed",
            Self::AskDeclined => "ask-declined",
            Self::CredentialGate => "credential-gate",
            Self::UpstreamPolicy => "upstream-policy",
        }
    }
}

/// The field that carries the reason code. It is the sandbox's, so an
/// intercepted response loses one the origin sent (see `crate::mitm`).
pub(crate) const BLOCKED_FIELD: &str = "X-Sandbox-Blocked";

/// Longest method, host or path the body repeats. A real one is far shorter,
/// and the client sent it, so the body never has to carry more of it than this.
const MAX_FIELD_BYTES: usize = 256;

/// Longest product label an embedder may set. It is a product name, and it goes
/// into the status line.
const MAX_LABEL_BYTES: usize = 64;

/// Check a product label for [`response`]: printable ASCII and spaces, not
/// blank, no surrounding spaces, at most [`MAX_LABEL_BYTES`]. Anything else
/// could break the response head it is written into.
pub(crate) fn check_label(label: &str) -> Result<(), String> {
    if label.is_empty() || label.len() > MAX_LABEL_BYTES {
        return Err(format!(
            "a block label must be 1 to {MAX_LABEL_BYTES} bytes long"
        ));
    }
    if label.trim() != label || !label.bytes().all(|b| b == b' ' || b.is_ascii_graphic()) {
        return Err(
            "a block label must be printable ASCII, with no surrounding spaces".to_string(),
        );
    }
    Ok(())
}

/// The response for a refused request: `method` to `host` at `path`, as the
/// client sent them. `path` may carry a query string; it is dropped. A refused
/// `CONNECT` passes its `host:port` target and an empty path. `label` names the
/// embedding product in the status line and the body; it has passed
/// [`check_label`] on its way in (see `ProxyState::set_block_label`), so it is
/// written verbatim.
pub(crate) fn response(
    label: Option<&str>,
    reason: BlockReason,
    method: &str,
    host: &str,
    path: &str,
) -> Vec<u8> {
    let method = printable(method);
    let host = printable(host);
    let hostname = crate::proxy::extract_hostname(&host);
    // A request line names the host it was sent to; only a `CONNECT` is about
    // a port.
    let shown = if method == "CONNECT" {
        host.clone()
    } else {
        format!(
            "{hostname}{}",
            printable(&redact_placeholders(without_query(path)))
        )
    };
    let code = reason.code();
    let by = label.map_or_else(String::new, |label| format!("{label} "));
    let body = format!(
        "Blocked by {by}sandbox egress policy: {method} {shown} (reason: {code}). \
         This is not a response from {hostname}.\n"
    );
    // The `Proxy-Status` member names the intermediary with a token, which a
    // product label is not, so it stays the same whatever the label.
    let mut out = format!(
        "HTTP/1.1 403 Forbidden by {by}sandbox policy\r\n\
         {BLOCKED_FIELD}: {code}\r\n\
         Proxy-Status: sandbox; error=http_request_denied; details=\"{code}\"\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    // A response to `HEAD` describes the body it would have had, and has none.
    if method != "HEAD" {
        out.extend_from_slice(body.as_bytes());
    }
    out
}

/// Whether an upstream proxy's answer to a `CONNECT` is a refusal by its own
/// policy: a `403` that carries `X-Sandbox-Blocked: upstream-policy`. Any
/// other refusal it makes is a failure of the upstream, not a block.
pub(crate) fn upstream_blocked(head: &str) -> bool {
    let mut lines = head.lines();
    let status = lines.next().unwrap_or_default();
    status.split_whitespace().nth(1) == Some("403")
        && lines.any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.trim().eq_ignore_ascii_case(BLOCKED_FIELD)
                    && value.trim() == BlockReason::UpstreamPolicy.code()
            })
        })
}

/// The error an upstream tunnel fails with when the upstream proxy refused the
/// destination by its policy, so the door can say so.
#[derive(Debug)]
pub(crate) struct UpstreamBlocked;

impl std::fmt::Display for UpstreamBlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Lens Sandbox upstream refused the destination by its policy")
    }
}

impl std::error::Error for UpstreamBlocked {}

/// How long a refused tunnel waits for the client's first byte. A TLS client
/// sends its ClientHello as soon as the tunnel opens; a protocol whose server
/// speaks first never sends one, and is not kept waiting for long.
const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a refused TLS session may take, from the ClientHello to the answer.
pub(crate) const DENIED_TUNNEL_TIMEOUT: Duration = Duration::from_secs(10);

/// Answer the first request on an accepted TLS session to `host` with the
/// refusal, then end the session. The request is read only to name it; nothing
/// of it is logged.
pub(crate) async fn answer_tls<S>(mut tls: S, label: Option<&str>, host: &str, reason: BlockReason)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Ok(head) = crate::http_body::read_head(&mut tls).await else {
        return;
    };
    let head = String::from_utf8_lossy(&head);
    tls.write_all(&crate::proxy::refusal_for_head(label, reason, host, &head))
        .await
        .ok();
    tls.shutdown().await.ok();
}

/// Refuse a `CONNECT` to `target_host` inside the tunnel: open it, and if the
/// client speaks TLS, complete the handshake with `config`, which serves a
/// certificate for the host, and answer the request it sends (see [`answer_tls`]). A client that does not
/// speak TLS is disconnected.
pub(crate) async fn answer_in_tunnel(
    mut client: TcpStream,
    config: std::sync::Arc<rustls::ServerConfig>,
    label: Option<&str>,
    target_host: &str,
    reason: BlockReason,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let hostname = crate::proxy::extract_hostname(target_host);
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    // A TLS record starts with its content type, and a ClientHello is a
    // handshake record: 0x16.
    let mut first = [0u8; 1];
    match tokio::time::timeout(FIRST_BYTE_TIMEOUT, client.peek(&mut first)).await {
        Ok(Ok(1)) if first[0] == 0x16 => {}
        _ => return Ok(()),
    }
    let _ = tokio::time::timeout(DENIED_TUNNEL_TIMEOUT, async {
        if let Ok(tls) = tokio_rustls::TlsAcceptor::from(config).accept(client).await {
            answer_tls(tls, label, &hostname, reason).await;
        }
    })
    .await;
    Ok(())
}

fn without_query(path: &str) -> &str {
    path.split(['?', '#']).next().unwrap_or_default()
}

/// Replace every `__lens_cred:<id>__` with `__lens_cred__`. A path may carry a
/// credential's placeholder, and its id names the credential.
fn redact_placeholders(path: &str) -> String {
    const OPEN: &str = "__lens_cred:";
    let mut out = String::with_capacity(path.len());
    let mut rest = path;
    while let Some(start) = rest.find(OPEN) {
        out.push_str(&rest[..start]);
        out.push_str("__lens_cred__");
        let after = &rest[start + OPEN.len()..];
        rest = after.find("__").map_or("", |end| &after[end + 2..]);
    }
    out.push_str(rest);
    out
}

/// Keep visible ASCII and cap the length, so nothing the client sent can break
/// the line or stretch it.
fn printable(field: &str) -> String {
    field
        .chars()
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .take(MAX_FIELD_BYTES)
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The status line, the reason header, and the first body line of a
    /// response, for the tests of every door to assert on.
    pub(crate) fn parse(response: &str) -> (&str, Option<&str>, &str) {
        let (head, body) = response.split_once("\r\n\r\n").unwrap_or((response, ""));
        let status = head.lines().next().unwrap_or_default();
        let reason = head
            .lines()
            .find_map(|line| line.strip_prefix("X-Sandbox-Blocked: "));
        (status, reason, body.lines().next().unwrap_or_default())
    }

    /// Assert `response` is the block response for `reason` with this body line.
    pub(crate) fn assert_blocked(response: &str, reason: BlockReason, first_line: &str) {
        let (status, header, line) = parse(response);
        assert_eq!(
            status, "HTTP/1.1 403 Forbidden by sandbox policy",
            "{response}"
        );
        assert_eq!(header, Some(reason.code()), "{response}");
        assert_eq!(line, first_line, "{response}");
    }

    #[test]
    fn a_refused_request_names_itself_and_its_reason() {
        let response = response(
            None,
            BlockReason::PolicyDeny,
            "GET",
            "api.example.com:443",
            "/v1/foo?token=secret#frag",
        );
        let text = String::from_utf8(response).unwrap();
        assert_blocked(
            &text,
            BlockReason::PolicyDeny,
            "Blocked by sandbox egress policy: GET api.example.com/v1/foo \
             (reason: policy-deny). This is not a response from api.example.com.",
        );
        assert!(!text.contains("secret"), "{text}");
        assert!(text.contains(
            "Proxy-Status: sandbox; error=http_request_denied; details=\"policy-deny\"\r\n"
        ));
        assert!(text.contains("Content-Type: text/plain; charset=utf-8\r\n"));
        assert!(text.contains("Cache-Control: no-store\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        assert!(head.contains(&format!("Content-Length: {}\r\n", body.len())));
    }

    #[test]
    fn a_refused_connect_names_its_target() {
        let text = String::from_utf8(response(
            None,
            BlockReason::AskDeclined,
            "CONNECT",
            "db.example.com:5432",
            "",
        ))
        .unwrap();
        assert_blocked(
            &text,
            BlockReason::AskDeclined,
            "Blocked by sandbox egress policy: CONNECT db.example.com:5432 \
             (reason: ask-declined). This is not a response from db.example.com.",
        );
    }

    #[test]
    fn every_reason_has_its_code() {
        for (reason, code) in [
            (BlockReason::PolicyDeny, "policy-deny"),
            (BlockReason::BinaryNotAllowed, "binary-not-allowed"),
            (BlockReason::AskDeclined, "ask-declined"),
            (BlockReason::CredentialGate, "credential-gate"),
            (BlockReason::UpstreamPolicy, "upstream-policy"),
        ] {
            let text = String::from_utf8(response(None, reason, "GET", "h.example", "/")).unwrap();
            assert_eq!(parse(&text).1, Some(code));
            assert!(text.contains(&format!("(reason: {code})")));
        }
    }

    #[test]
    fn a_placeholder_in_the_path_is_not_repeated() {
        let text = String::from_utf8(response(
            None,
            BlockReason::CredentialGate,
            "POST",
            "api.telegram.org",
            "/bot__lens_cred:telegram-bot-token__/sendMessage",
        ))
        .unwrap();
        assert!(!text.contains("telegram-bot-token"), "{text}");
        assert!(text.contains("POST api.telegram.org/bot__lens_cred__/sendMessage "));
    }

    #[test]
    fn what_the_client_sent_cannot_break_the_line() {
        let text = String::from_utf8(response(
            None,
            BlockReason::PolicyDeny,
            "GET",
            "evil.example\r\nX-Injected: 1",
            &format!("/a b\r\n{}", "x".repeat(1000)),
        ))
        .unwrap();
        assert!(!text.contains("\r\nX-Injected"), "{text}");
        let (_, body) = text.split_once("\r\n\r\n").unwrap();
        assert_eq!(body.lines().count(), 1, "{body}");
        assert!(body.len() < 1000, "{body}");
    }

    #[test]
    fn only_a_marked_403_is_an_upstream_block() {
        assert!(upstream_blocked(
            "HTTP/1.1 403 Forbidden\r\nx-sandbox-blocked:  upstream-policy\r\n\r\n"
        ));
        assert!(!upstream_blocked("HTTP/1.1 403 Forbidden\r\n\r\n"));
        assert!(!upstream_blocked(
            "HTTP/1.1 502 Bad Gateway\r\nX-Sandbox-Blocked: upstream-policy\r\n\r\n"
        ));
        assert!(!upstream_blocked(
            "HTTP/1.1 403 Forbidden\r\nX-Sandbox-Blocked: policy-deny\r\n\r\n"
        ));
    }

    #[test]
    fn an_embedder_label_names_its_product() {
        let text = String::from_utf8(response(
            Some("Lens Agents"),
            BlockReason::PolicyDeny,
            "GET",
            "api.example.com",
            "/v1/foo",
        ))
        .unwrap();
        let (status, reason, line) = parse(&text);
        assert_eq!(
            status,
            "HTTP/1.1 403 Forbidden by Lens Agents sandbox policy"
        );
        assert_eq!(reason, Some("policy-deny"));
        assert_eq!(
            line,
            "Blocked by Lens Agents sandbox egress policy: GET api.example.com/v1/foo \
             (reason: policy-deny). This is not a response from api.example.com."
        );
        assert!(text.contains("Proxy-Status: sandbox; error=http_request_denied;"));
    }

    #[test]
    fn a_label_that_could_break_the_head_is_refused() {
        assert!(check_label("Lens Agents").is_ok());
        for bad in [
            "",
            " Lens",
            "Lens ",
            "Lens\r\nX-Injected: 1",
            "Lens\tAgents",
            "Lëns",
            &"x".repeat(MAX_LABEL_BYTES + 1),
        ] {
            assert!(check_label(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_refused_head_request_has_no_body() {
        let text = String::from_utf8(response(
            None,
            BlockReason::PolicyDeny,
            "HEAD",
            "h.example",
            "/",
        ))
        .unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        assert!(body.is_empty(), "{text}");
        assert!(!head.contains("Content-Length: 0\r\n"), "{head}");
    }
}
