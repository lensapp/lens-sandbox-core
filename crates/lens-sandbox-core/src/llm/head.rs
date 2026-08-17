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

use super::{Redirect, translate};
use crate::policy_schema::LlmFormat;

/// Request headers a redirect never carries to the backend.
///
/// Four groups, and each is dropped for its own reason:
///
/// - `host` is restated, because the request is going somewhere else.
/// - The credential headers name the API the sandbox thought it was calling.
///   Every well-known spelling is listed, because one that is missed is a key
///   sent to a host that was never meant to have it. `cookie` is in the list
///   for the same reason, even though the proxy injects no cookies itself.
/// - `openai-organization` and `openai-project` name the account the sandbox was
///   billing at that API. The backend has no such account, and neither one is
///   the proxy's to quote.
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
    "openai-organization",
    "openai-project",
    "accept-encoding",
    "content-length",
    "transfer-encoding",
    "trailer",
    "expect",
];

/// Headers that describe the API rather than the request.
///
/// They cross only when the backend speaks the very API they describe, which is
/// what a route naming one format twice means. There they say what the sandbox
/// asked for — a beta the answer depends on, the version its shape is written
/// against — and dropping them would change the answer the sandbox gets. A route
/// that translates leaves them behind: the backend speaks another API and knows
/// none of these names.
const API_HEADERS: &[&str] = &["anthropic-version", "anthropic-beta", "openai-beta"];

/// The Anthropic Messages version this proxy writes against.
///
/// The API refuses a request that names no version, and a translating route has
/// none to carry: the sandbox spoke another API and never sent one. So the proxy
/// names the version its own translation is written against, which is the only
/// one it can honestly name.
const ANTHROPIC_VERSION: &str = "2023-06-01";

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
    let translating = !translate::is_passthrough(redirect.translation);

    let mut out = String::with_capacity(head.len() + 64);
    out.push_str(&rewrite_request_line(request_line, &redirect.path));
    for line in lines {
        // A line with no colon names nothing, matches no list, and survives.
        let name = line
            .split_once(':')
            .map(|(name, _)| name.trim().to_ascii_lowercase())
            .unwrap_or_default();
        if DROPPED.contains(&name.as_str()) || (translating && API_HEADERS.contains(&name.as_str()))
        {
            continue;
        }
        out.push_str("\r\n");
        out.push_str(line);
    }
    // Only a translating route has no version to carry. A passthrough sandbox
    // that named none wrote a request the API refuses, and that refusal is the
    // answer it earned; inventing a version here would hide it.
    if translating && redirect.translation.to == LlmFormat::AnthropicMessages {
        out.push_str("\r\nanthropic-version: ");
        out.push_str(ANTHROPIC_VERSION);
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
    use crate::policy_schema::{LlmFormat, LlmTranslation};

    fn redirect(host: &str, port: u16, path: &str) -> Redirect {
        translating(
            host,
            port,
            path,
            LlmFormat::AnthropicMessages,
            LlmFormat::OpenaiChat,
        )
    }

    fn translating(host: &str, port: u16, path: &str, from: LlmFormat, to: LlmFormat) -> Redirect {
        Redirect {
            host: host.to_string(),
            port,
            path: path.to_string(),
            body: Vec::new(),
            streaming: false,
            translation: LlmTranslation { from, to },
            model: "qwen3".to_string(),
        }
    }

    fn passthrough(host: &str, path: &str, format: LlmFormat) -> Redirect {
        Redirect {
            host: host.to_string(),
            port: 443,
            path: path.to_string(),
            body: Vec::new(),
            streaming: false,
            translation: LlmTranslation {
                from: format,
                to: format,
            },
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
    fn a_translating_route_leaves_the_old_api_s_own_headers_behind() {
        // This backend speaks Chat. Neither name means anything to it.
        let head = "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\
                    anthropic-version: 2023-06-01\r\nanthropic-beta: tools-2024-04-04";
        let out = rewrite_for_backend(head, &redirect("vllm.internal", 443, "/v1/chat"));
        assert!(!out.to_ascii_lowercase().contains("anthropic-"), "{out}");
    }

    #[test]
    fn an_anthropic_backend_is_told_which_version_it_is_being_asked_for() {
        // The Messages API refuses a request that names no version, and a
        // sandbox speaking another API never sent one.
        let head = "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com";
        let out = rewrite_for_backend(
            head,
            &translating(
                "claude.internal",
                443,
                "/v1/messages",
                LlmFormat::OpenaiChat,
                LlmFormat::AnthropicMessages,
            ),
        );
        assert!(out.contains("\r\nanthropic-version: 2023-06-01"), "{out}");
    }

    #[test]
    fn a_backend_speaking_the_same_api_is_told_what_the_sandbox_asked_of_it() {
        // The betas name features the answer depends on, and this backend serves
        // the very API that defines them.
        let head = "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\
                    anthropic-version: 2023-01-01\r\nanthropic-beta: context-1m-2025-08-07";
        let out = rewrite_for_backend(
            head,
            &passthrough(
                "claude.internal",
                "/v1/messages",
                LlmFormat::AnthropicMessages,
            ),
        );
        assert!(
            out.contains("anthropic-beta: context-1m-2025-08-07"),
            "{out}"
        );
        assert!(out.contains("anthropic-version: 2023-01-01"), "{out}");
        assert!(
            !out.contains("2023-06-01"),
            "the version the sandbox named is not restated: {out}"
        );
    }

    #[test]
    fn a_passthrough_route_names_no_version_the_sandbox_did_not_name() {
        // The request is one the Messages API refuses, and that refusal is the
        // answer the sandbox earned. Inventing a version would hide it.
        let head = "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com";
        let out = rewrite_for_backend(
            head,
            &passthrough(
                "claude.internal",
                "/v1/messages",
                LlmFormat::AnthropicMessages,
            ),
        );
        assert!(!out.to_ascii_lowercase().contains("anthropic-"), "{out}");
    }

    #[test]
    fn an_openai_beta_survives_only_where_it_is_understood() {
        let head = "POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\n\
                    openai-beta: responses=v1\r\nOpenAI-Organization: org-1\r\n\
                    OpenAI-Project: proj-1";
        let kept = rewrite_for_backend(
            head,
            &passthrough("vllm.internal", "/v1/responses", LlmFormat::OpenaiResponses),
        );
        assert!(kept.contains("openai-beta: responses=v1"), "{kept}");
        // The account is still not the proxy's to quote.
        let lower = kept.to_ascii_lowercase();
        assert!(!lower.contains("openai-organization"), "{kept}");
        assert!(!lower.contains("openai-project"), "{kept}");

        let dropped = rewrite_for_backend(head, &redirect("vllm.internal", 443, "/v1/chat"));
        assert!(
            !dropped.to_ascii_lowercase().contains("openai-beta"),
            "{dropped}"
        );
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
