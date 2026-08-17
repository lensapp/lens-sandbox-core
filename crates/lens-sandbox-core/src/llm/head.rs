//! Rewriting the request head for a backend.
//!
//! The body is translated elsewhere; this is the envelope. It has to say the
//! backend's name and the backend's path, and it has to say nothing about the
//! API the sandbox thought it was calling — least of all that API's key.
//!
//! Dropping the credential is the point. The sandbox holds a key for the host
//! its policy named, and the request carries it. That host is not where this
//! request is going. So every header that could carry it goes, and the backend
//! is sent only what the `credentials` block binds to the backend itself.

use super::Redirect;

/// Request headers a redirect never carries to the backend.
///
/// Four groups, and each is dropped for its own reason:
///
/// - `host` is restated, because the request is going somewhere else.
/// - The credential headers name the API the sandbox thought it was calling.
///   Every well-known spelling is listed, because one that is missed is a key
///   sent to a host that was never meant to have it. `cookie` is in the list
///   for the same reason, even though the proxy injects no cookies itself.
/// - `anthropic-version` and `anthropic-beta` describe that same API, and mean
///   nothing to the backend.
/// - `accept-encoding` would let the backend compress an answer this proxy has
///   to read, and the framing headers describe a body that no longer exists.
const DROPPED: &[&str] = &[
    "host",
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "cookie",
    "anthropic-version",
    "anthropic-beta",
    "accept-encoding",
    "content-length",
    "transfer-encoding",
    "trailer",
    "expect",
];

/// Restate a request head so it addresses `redirect`'s backend.
///
/// `head` is CRLF-joined and carries no trailing blank line, as every other
/// head-rewriting step in this crate expects. The framing headers are dropped
/// here and restored by
/// [`crate::http_body::reframe_head_as_content_length`], which is what states
/// the length of the translated body.
pub fn rewrite_for_backend(head: &str, redirect: &Redirect) -> String {
    let head = head.trim_end_matches("\r\n");
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();

    let mut out = String::with_capacity(head.len() + 64);
    out.push_str(&rewrite_request_line(request_line, &redirect.path));
    for line in lines {
        let name = line
            .split_once(':')
            .map(|(name, _)| name.trim().to_ascii_lowercase());
        if name.as_deref().is_some_and(|name| DROPPED.contains(&name)) {
            continue;
        }
        out.push_str("\r\n");
        out.push_str(line);
    }
    out.push_str("\r\nHost: ");
    out.push_str(&host_header(redirect));
    out
}

/// Point the request line at the backend's path, keeping the method and the
/// HTTP version the sandbox used.
fn rewrite_request_line(request_line: &str, path: &str) -> String {
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("POST");
    let version = parts.nth(1).unwrap_or("HTTP/1.1");
    format!("{method} {path} {version}")
}

/// The `Host` value: bare hostname on the default port, `host:port` otherwise.
fn host_header(redirect: &Redirect) -> String {
    if redirect.port == 443 {
        redirect.host.clone()
    } else {
        redirect.authority()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_schema::LlmTranslation;

    fn redirect(host: &str, port: u16, path: &str) -> Redirect {
        Redirect {
            host: host.to_string(),
            port,
            path: path.to_string(),
            body: Vec::new(),
            streaming: false,
            translation: LlmTranslation::AnthropicMessagesToOpenaiChat,
            model: "qwen3".to_string(),
        }
    }

    #[test]
    fn the_request_line_and_host_name_the_backend() {
        let head = "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAccept: */*";
        let out = rewrite_for_backend(
            head,
            &redirect("vllm.internal", 443, "/v1/chat/completions"),
        );
        assert_eq!(
            out,
            "POST /v1/chat/completions HTTP/1.1\r\nAccept: */*\r\nHost: vllm.internal"
        );
    }

    #[test]
    fn a_non_default_port_is_stated_in_the_host_header() {
        let head = "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com";
        let out = rewrite_for_backend(head, &redirect("vllm.internal", 8443, "/v1/chat"));
        assert!(out.ends_with("\r\nHost: vllm.internal:8443"), "{out}");
    }

    #[test]
    fn every_credential_header_is_left_behind() {
        let head = "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\
                    x-api-key: sk-ant-real\r\nAuthorization: Bearer sk-ant-real\r\n\
                    Api-Key: sk-ant-real\r\nProxy-Authorization: Basic x\r\n\
                    X-Goog-Api-Key: g\r\nCookie: session=sk-ant-real\r\n\
                    User-Agent: agent/1";
        let out = rewrite_for_backend(head, &redirect("vllm.internal", 443, "/v1/chat"));
        assert!(
            !out.to_ascii_lowercase().contains("sk-ant-real"),
            "the key for the API we left must not reach the backend: {out}"
        );
        assert!(!out.to_ascii_lowercase().contains("proxy-authorization"));
        assert!(!out.to_ascii_lowercase().contains("x-goog-api-key"));
        assert!(!out.to_ascii_lowercase().contains("cookie"));
        assert!(out.contains("User-Agent: agent/1"));
    }

    #[test]
    fn the_headers_naming_the_old_api_are_left_behind() {
        let head = "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\
                    anthropic-version: 2023-06-01\r\nanthropic-beta: tools-2024-04-04";
        let out = rewrite_for_backend(head, &redirect("vllm.internal", 443, "/v1/chat"));
        assert!(!out.to_ascii_lowercase().contains("anthropic-"), "{out}");
    }

    #[test]
    fn the_answer_is_not_offered_as_compressed() {
        // The proxy has to read the answer to translate it.
        let head = "POST /v1/messages HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip, br";
        let out = rewrite_for_backend(head, &redirect("vllm.internal", 443, "/v1/chat"));
        assert!(
            !out.to_ascii_lowercase().contains("accept-encoding"),
            "{out}"
        );
    }

    #[test]
    fn the_old_framing_is_left_for_the_caller_to_restate() {
        let head = "POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Length: 900\r\n\
                    Transfer-Encoding: chunked\r\nTrailer: X-Sig\r\nExpect: 100-continue";
        let out = rewrite_for_backend(head, &redirect("vllm.internal", 443, "/v1/chat"));
        let lower = out.to_ascii_lowercase();
        assert!(!lower.contains("content-length"));
        assert!(!lower.contains("transfer-encoding"));
        assert!(!lower.contains("trailer"));
        assert!(!lower.contains("expect"));
    }

    #[test]
    fn header_names_are_matched_whatever_their_case() {
        let head = "POST /v1/messages HTTP/1.1\r\nHOST: api.anthropic.com\r\nX-API-KEY: sk";
        let out = rewrite_for_backend(head, &redirect("vllm.internal", 443, "/v1/chat"));
        assert_eq!(
            out, "POST /v1/chat HTTP/1.1\r\nHost: vllm.internal",
            "a differently-cased header must not survive"
        );
    }

    #[test]
    fn a_head_with_a_trailing_crlf_is_tolerated() {
        let head = "POST /v1/messages HTTP/1.1\r\nHost: x\r\n";
        let out = rewrite_for_backend(head, &redirect("vllm.internal", 443, "/v1/chat"));
        assert_eq!(out, "POST /v1/chat HTTP/1.1\r\nHost: vllm.internal");
    }
}
