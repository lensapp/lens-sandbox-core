//! The OpenAI Chat Completions answer, read and rewritten as an Anthropic
//! Messages answer.
//!
//! This is the whole-body direction: the sandbox did not ask for a stream, so
//! the backend sends one JSON object and the sandbox is given one back.
//! [`crate::llm::openai_stream`] does the same job event by event.
//!
//! A backend that refuses is translated too. An OpenAI error body reaching a
//! sandbox that speaks Anthropic reads as a malformed answer, which is the one
//! thing a failing request should never look like.

use serde_json::{Map, Value, json};

/// Translate an answer the backend returned with `status`.
///
/// Only a 2xx carries a completion. Every other status is turned into the
/// Anthropic error the sandbox knows how to read — a refusal, and equally a
/// redirect the backend URL earned from a stray slash, which carries no answer
/// and must not be read as an empty one.
pub fn translate(response: &Value, status: u16) -> Result<Value, String> {
    if !(200..300).contains(&status) {
        return Ok(translate_error(response, status));
    }

    let choice = response
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .ok_or("openai answer has no choices")?;
    let message = choice
        .get("message")
        .ok_or("openai choice has no message")?;

    let mut content = Vec::new();
    if let Some(text) = message.get("content").and_then(Value::as_str)
        && !text.is_empty()
    {
        content.push(json!({ "type": "text", "text": text }));
    }
    for call in message
        .get("tool_calls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        content.push(tool_use_block(call)?);
    }

    let usage = response.get("usage");
    Ok(json!({
        "id": response.get("id").cloned().unwrap_or(json!("msg_translated")),
        "type": "message",
        "role": "assistant",
        "model": response.get("model").cloned().unwrap_or(Value::Null),
        "content": content,
        "stop_reason": stop_reason(choice.get("finish_reason").and_then(Value::as_str)),
        "stop_sequence": Value::Null,
        "usage": {
            "input_tokens": token_count(usage, "prompt_tokens"),
            "output_tokens": token_count(usage, "completion_tokens"),
        },
    }))
}

/// One OpenAI tool call as the Anthropic block that means the same thing.
pub(crate) fn tool_use_block(call: &Value) -> Result<Value, String> {
    let function = call
        .get("function")
        .ok_or("openai tool call has no function")?;
    let arguments = function
        .get("arguments")
        .and_then(Value::as_str)
        .unwrap_or("{}");
    // Anthropic carries the arguments as an object, OpenAI as a string holding
    // one. A string that is not an object is the backend breaking its own
    // contract, and guessing an empty object here would show the sandbox a tool
    // call with no arguments as though the model had made one.
    let input: Value = serde_json::from_str(if arguments.is_empty() {
        "{}"
    } else {
        arguments
    })
    .map_err(|e| format!("openai tool call arguments are not JSON: {e}"))?;

    Ok(json!({
        "type": "tool_use",
        "id": call.get("id").cloned().unwrap_or(Value::Null),
        "name": function.get("name").cloned().unwrap_or(Value::Null),
        "input": input,
    }))
}

/// The Anthropic name for why the model stopped.
pub(crate) fn stop_reason(finish_reason: Option<&str>) -> Value {
    match finish_reason {
        None => Value::Null,
        Some("length") => json!("max_tokens"),
        Some("tool_calls" | "function_call") => json!("tool_use"),
        // `stop`, `content_filter`, and anything a backend invents: the turn is
        // over, and Anthropic has one name for that.
        Some(_) => json!("end_turn"),
    }
}

/// A token count, defaulting to zero rather than to absent — the sandbox reads
/// these as numbers.
pub(crate) fn token_count(usage: Option<&Value>, field: &str) -> u64 {
    usage
        .and_then(|usage| usage.get(field))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

/// An OpenAI error body as the Anthropic error the sandbox knows how to read.
fn translate_error(response: &Value, status: u16) -> Value {
    let error = response.get("error");
    let message = error
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("llm backend returned status {status}"));

    let mut body = Map::new();
    body.insert("type".into(), json!("error"));
    body.insert(
        "error".into(),
        json!({ "type": error_type(status), "message": message }),
    );
    Value::Object(body)
}

/// The Anthropic error type for an HTTP status.
fn error_type(status: u16) -> &'static str {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn openai(json: &str) -> Value {
        serde_json::from_str(json).expect("fixture parses")
    }

    #[test]
    fn a_text_answer_becomes_a_message() {
        let out = translate(
            &openai(
                r#"{
                    "id": "chatcmpl-1",
                    "model": "qwen3-coder-30b",
                    "choices": [{ "index": 0, "finish_reason": "stop",
                        "message": { "role": "assistant", "content": "hello" } }],
                    "usage": { "prompt_tokens": 12, "completion_tokens": 3 }
                }"#,
            ),
            200,
        )
        .expect("answer translates");

        assert_eq!(out["id"], "chatcmpl-1");
        assert_eq!(out["type"], "message");
        assert_eq!(out["role"], "assistant");
        assert_eq!(out["model"], "qwen3-coder-30b");
        assert_eq!(out["content"][0]["type"], "text");
        assert_eq!(out["content"][0]["text"], "hello");
        assert_eq!(out["stop_reason"], "end_turn");
        assert_eq!(out["usage"]["input_tokens"], 12);
        assert_eq!(out["usage"]["output_tokens"], 3);
    }

    #[test]
    fn a_tool_call_becomes_a_tool_use_block() {
        let out = translate(
            &openai(
                r#"{
                    "id": "chatcmpl-2",
                    "choices": [{ "finish_reason": "tool_calls", "message": {
                        "role": "assistant", "content": null,
                        "tool_calls": [{ "id": "call_1", "type": "function",
                            "function": { "name": "get_weather",
                                          "arguments": "{\"city\":\"Helsinki\"}" } }] } }]
                }"#,
            ),
            200,
        )
        .expect("answer translates");

        assert_eq!(out["content"][0]["type"], "tool_use");
        assert_eq!(out["content"][0]["id"], "call_1");
        assert_eq!(out["content"][0]["name"], "get_weather");
        assert_eq!(out["content"][0]["input"]["city"], "Helsinki");
        assert_eq!(out["stop_reason"], "tool_use");
    }

    #[test]
    fn text_and_tool_calls_keep_their_order() {
        let out = translate(
            &openai(
                r#"{ "choices": [{ "finish_reason": "tool_calls", "message": {
                    "content": "checking",
                    "tool_calls": [{ "id": "call_1", "function": { "name": "w", "arguments": "{}" } }]
                } }] }"#,
            ),
            200,
        )
        .expect("answer translates");
        assert_eq!(out["content"][0]["type"], "text");
        assert_eq!(out["content"][1]["type"], "tool_use");
    }

    #[test]
    fn a_length_stop_becomes_max_tokens() {
        let out = translate(
            &openai(
                r#"{ "choices": [{ "finish_reason": "length", "message": { "content": "x" } }] }"#,
            ),
            200,
        )
        .expect("answer translates");
        assert_eq!(out["stop_reason"], "max_tokens");
    }

    #[test]
    fn empty_tool_arguments_read_as_no_arguments() {
        let out = translate(
            &openai(
                r#"{ "choices": [{ "finish_reason": "tool_calls", "message": {
                    "tool_calls": [{ "id": "c", "function": { "name": "w", "arguments": "" } }] } }] }"#,
            ),
            200,
        )
        .expect("answer translates");
        assert_eq!(out["content"][0]["input"], json!({}));
    }

    #[test]
    fn tool_arguments_that_are_not_json_refuse_the_answer() {
        let err = translate(
            &openai(
                r#"{ "choices": [{ "finish_reason": "tool_calls", "message": {
                    "tool_calls": [{ "id": "c", "function": { "name": "w",
                        "arguments": "not json" } }] } }] }"#,
            ),
            200,
        )
        .expect_err("a tool call with no readable arguments is not one to show the sandbox");
        assert!(err.contains("not JSON"), "{err}");
    }

    #[test]
    fn an_answer_without_choices_is_refused() {
        assert!(translate(&openai(r#"{ "id": "x" }"#), 200).is_err());
    }

    #[test]
    fn missing_usage_reads_as_zero() {
        let out = translate(
            &openai(
                r#"{ "choices": [{ "finish_reason": "stop", "message": { "content": "x" } }] }"#,
            ),
            200,
        )
        .expect("answer translates");
        assert_eq!(out["usage"]["input_tokens"], 0);
        assert_eq!(out["usage"]["output_tokens"], 0);
    }

    #[test]
    fn a_refusal_becomes_an_anthropic_error() {
        let out = translate(
            &openai(
                r#"{ "error": { "message": "no such model", "type": "invalid_request_error" } }"#,
            ),
            400,
        )
        .expect("error translates");
        assert_eq!(out["type"], "error");
        assert_eq!(out["error"]["type"], "invalid_request_error");
        assert_eq!(out["error"]["message"], "no such model");
    }

    #[test]
    fn a_refusal_with_no_body_still_says_something() {
        let out = translate(&openai("{}"), 503).expect("error translates");
        assert_eq!(out["error"]["type"], "api_error");
        assert!(
            out["error"]["message"]
                .as_str()
                .expect("message")
                .contains("503")
        );
    }

    #[test]
    fn a_status_that_carries_no_completion_becomes_an_error() {
        // A 301 has no answer in it. Reading one as an empty completion would
        // show the sandbox a successful call that never happened.
        let out = translate(&openai("{}"), 301).expect("redirect translates");
        assert_eq!(out["type"], "error");
        assert_eq!(out["error"]["type"], "api_error");
        assert!(
            out["error"]["message"]
                .as_str()
                .expect("message")
                .contains("301")
        );
    }

    #[test]
    fn each_refusal_status_keeps_its_own_name() {
        for (status, expected) in [
            (401, "authentication_error"),
            (403, "permission_error"),
            (404, "not_found_error"),
            (429, "rate_limit_error"),
            (500, "api_error"),
        ] {
            let out = translate(&openai("{}"), status).expect("error translates");
            assert_eq!(out["error"]["type"], expected, "status {status}");
        }
    }
}
