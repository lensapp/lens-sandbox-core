//! A backend's refusal, written in the format the sandbox reads.
//!
//! `switchyard-translation` translates answers, not error bodies, so this is the
//! one part of the crossing the proxy still writes itself. It has to: an error
//! body in the wrong shape reads to the sandbox as a malformed answer, which is
//! the one thing a failing request should never look like.

use serde_json::{Value, json};

use crate::policy_schema::LlmFormat;

/// Write what the backend said, and the status it said it with, as an error the
/// sandbox knows how to read.
pub fn write(format: LlmFormat, response: &Value, status: u16) -> Value {
    let message = response
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("llm backend returned status {status}"));

    match format {
        LlmFormat::AnthropicMessages => json!({
            "type": "error",
            "error": { "type": anthropic_type(status), "message": message },
        }),
        // Both OpenAI APIs report a failure the same way.
        LlmFormat::OpenaiChat | LlmFormat::OpenaiResponses => json!({
            "error": {
                "type": openai_type(status),
                "message": message,
                "param": Value::Null,
                "code": Value::Null,
            },
        }),
    }
}

/// The Anthropic error type for an HTTP status.
fn anthropic_type(status: u16) -> &'static str {
    match status {
        400 => "invalid_request_error",
        401 => "authentication_error",
        403 => "permission_error",
        404 => "not_found_error",
        413 => "request_too_large",
        429 => "rate_limit_error",
        529 => "overloaded_error",
        _ => "api_error",
    }
}

/// The OpenAI error type for an HTTP status.
///
/// OpenAI names fewer of these than Anthropic does, so several statuses share a
/// name. The status itself is what a client reads; the name is how it reads.
fn openai_type(status: u16) -> &'static str {
    match status {
        400 | 404 | 413 | 422 => "invalid_request_error",
        401 => "authentication_error",
        403 => "permission_error",
        429 => "rate_limit_error",
        _ => "server_error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Value {
        serde_json::from_str(json).expect("fixture parses")
    }

    #[test]
    fn an_anthropic_sandbox_reads_an_anthropic_error() {
        let out = write(
            LlmFormat::AnthropicMessages,
            &parse(r#"{ "error": { "message": "no such model" } }"#),
            400,
        );
        assert_eq!(out["type"], "error");
        assert_eq!(out["error"]["type"], "invalid_request_error");
        assert_eq!(out["error"]["message"], "no such model");
    }

    #[test]
    fn an_openai_sandbox_reads_an_openai_error() {
        for format in [LlmFormat::OpenaiChat, LlmFormat::OpenaiResponses] {
            let out = write(
                format,
                &parse(r#"{ "error": { "message": "no such model" } }"#),
                400,
            );
            // OpenAI states no envelope type, only the error itself.
            assert!(out.get("type").is_none(), "{format:?}");
            assert_eq!(out["error"]["type"], "invalid_request_error", "{format:?}");
            assert_eq!(out["error"]["message"], "no such model", "{format:?}");
            assert!(out["error"]["code"].is_null(), "{format:?}");
        }
    }

    #[test]
    fn a_refusal_with_no_body_still_says_something() {
        for format in [
            LlmFormat::AnthropicMessages,
            LlmFormat::OpenaiChat,
            LlmFormat::OpenaiResponses,
        ] {
            let out = write(format, &parse("{}"), 503);
            assert!(
                out["error"]["message"]
                    .as_str()
                    .expect("message")
                    .contains("503"),
                "{format:?}"
            );
        }
    }

    #[test]
    fn each_status_keeps_its_own_name() {
        for (status, anthropic, openai) in [
            (401, "authentication_error", "authentication_error"),
            (403, "permission_error", "permission_error"),
            (404, "not_found_error", "invalid_request_error"),
            (429, "rate_limit_error", "rate_limit_error"),
            (500, "api_error", "server_error"),
        ] {
            let body = parse("{}");
            assert_eq!(
                write(LlmFormat::AnthropicMessages, &body, status)["error"]["type"],
                anthropic,
                "status {status}"
            );
            assert_eq!(
                write(LlmFormat::OpenaiChat, &body, status)["error"]["type"],
                openai,
                "status {status}"
            );
        }
    }
}
