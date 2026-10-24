//! The response a client gets when sandbox policy refuses its request.
//!
//! A bare `403` reads to an agent as the destination refusing it, so every
//! policy refusal on every door sends this one response instead: a reason
//! phrase, an `X-Lens-Agents-Blocked` header carrying a fixed reason code, an
//! RFC 9209 `Proxy-Status`, and a one-line plain-text body whose first line is
//! stable enough to match on.
//!
//! The body names the request and nothing else. It carries no query string, no
//! credential placeholder, no rule or policy name, and none of the free-text
//! detail the log records: whoever reads it is the workload the policy is
//! keeping things from.

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
}

impl BlockReason {
    /// The value of `X-Lens-Agents-Blocked`, and the one the body names.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::PolicyDeny => "policy-deny",
            Self::BinaryNotAllowed => "binary-not-allowed",
            Self::AskDeclined => "ask-declined",
            Self::CredentialGate => "credential-gate",
        }
    }
}

/// Longest method, host or path the body repeats. A real one is far shorter,
/// and the client sent it, so the body never has to carry more of it than this.
const MAX_FIELD_BYTES: usize = 256;

/// The response for a refused request: `method` to `host` at `path`, as the
/// client sent them. `path` may carry a query string; it is dropped. A refused
/// `CONNECT` passes its `host:port` target and an empty path.
pub(crate) fn response(reason: BlockReason, method: &str, host: &str, path: &str) -> Vec<u8> {
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
    let body = format!(
        "Blocked by Lens Agents sandbox egress policy: {method} {shown} (reason: {code}). \
         This is not a response from {hostname}.\n"
    );
    let mut out = format!(
        "HTTP/1.1 403 Forbidden by Lens Agents sandbox policy\r\n\
         X-Lens-Agents-Blocked: {code}\r\n\
         Proxy-Status: lens-agents-sandbox; error=http_request_denied; details=\"{code}\"\r\n\
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
            .find_map(|line| line.strip_prefix("X-Lens-Agents-Blocked: "));
        (status, reason, body.lines().next().unwrap_or_default())
    }

    /// Assert `response` is the block response for `reason` with this body line.
    pub(crate) fn assert_blocked(response: &str, reason: BlockReason, first_line: &str) {
        let (status, header, line) = parse(response);
        assert_eq!(
            status, "HTTP/1.1 403 Forbidden by Lens Agents sandbox policy",
            "{response}"
        );
        assert_eq!(header, Some(reason.code()), "{response}");
        assert_eq!(line, first_line, "{response}");
    }

    #[test]
    fn a_refused_request_names_itself_and_its_reason() {
        let response = response(
            BlockReason::PolicyDeny,
            "GET",
            "api.example.com:443",
            "/v1/foo?token=secret#frag",
        );
        let text = String::from_utf8(response).unwrap();
        assert_blocked(
            &text,
            BlockReason::PolicyDeny,
            "Blocked by Lens Agents sandbox egress policy: GET api.example.com/v1/foo \
             (reason: policy-deny). This is not a response from api.example.com.",
        );
        assert!(!text.contains("secret"), "{text}");
        assert!(text.contains(
            "Proxy-Status: lens-agents-sandbox; error=http_request_denied; details=\"policy-deny\"\r\n"
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
            BlockReason::AskDeclined,
            "CONNECT",
            "db.example.com:5432",
            "",
        ))
        .unwrap();
        assert_blocked(
            &text,
            BlockReason::AskDeclined,
            "Blocked by Lens Agents sandbox egress policy: CONNECT db.example.com:5432 \
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
        ] {
            let text = String::from_utf8(response(reason, "GET", "h.example", "/")).unwrap();
            assert_eq!(parse(&text).1, Some(code));
            assert!(text.contains(&format!("(reason: {code})")));
        }
    }

    #[test]
    fn a_placeholder_in_the_path_is_not_repeated() {
        let text = String::from_utf8(response(
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
    fn a_refused_head_request_has_no_body() {
        let text =
            String::from_utf8(response(BlockReason::PolicyDeny, "HEAD", "h.example", "/")).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        assert!(body.is_empty(), "{text}");
        assert!(!head.contains("Content-Length: 0\r\n"), "{head}");
    }
}
