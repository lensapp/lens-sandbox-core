//! Turning one LLM wire format into another.
//!
//! The formats themselves are `switchyard-translation`'s work: it decodes a
//! provider's JSON into a neutral conversation, then encodes that conversation
//! for the provider on the other side. This file owns the four things that crate
//! leaves to its caller.
//!
//! - Which pair of formats a route's [`LlmTranslation`] names, and which way
//!   round each direction runs. A request goes sandbox → backend; the answer
//!   comes back backend → sandbox.
//! - The [`policy`] every translation runs under.
//! - The model. The sandbox asked for one name and the backend serves another,
//!   so the name the table resolved replaces whatever came out of the encoder.
//! - A refusal. `switchyard-translation` translates answers, not error bodies,
//!   so a backend that says no is dressed here in the error shape the sandbox
//!   knows how to read.

use serde_json::{Map, Value, json};
use switchyard_translation::{
    DeterministicIdPolicy, LossyConversionPolicy, PreservationPolicy, TargetCapabilities,
    TranslationDiagnostic, TranslationEngine, TranslationPolicy, UnknownFieldPolicy, WireFormat,
};

use crate::policy_schema::LlmTranslation;

/// The formats a route joins: what the sandbox speaks, and what the backend
/// speaks.
fn formats(translation: LlmTranslation) -> (WireFormat, WireFormat) {
    match translation {
        LlmTranslation::AnthropicMessagesToOpenaiChat => {
            (WireFormat::AnthropicMessages, WireFormat::OpenAiChat)
        }
    }
}

/// The policy every translation in this proxy runs under.
///
/// - Unknown fields are dropped. The backend is sent what this proxy understands
///   and nothing more, which is the same allow-list posture the rest of the MITM
///   takes with a head it rewrites.
/// - A lossy conversion is a warning rather than a refusal, so a turn carrying
///   Anthropic `thinking` blocks still reaches an OpenAI backend that has
///   nowhere to put them. A capability the backend genuinely cannot serve is
///   refused earlier, in [`super::decide`], where the message can name it.
/// - Preservation is off. It exists to carry an exact source body through
///   several formats and back; this proxy translates once in each direction.
///   `Embed` would write Switchyard metadata into the body the backend receives,
///   which is not this proxy's to add.
fn policy() -> TranslationPolicy {
    TranslationPolicy {
        unknown_field_policy: UnknownFieldPolicy::DropWithWarning,
        lossy_conversion_policy: LossyConversionPolicy::AllowWithDiagnostics,
        deterministic_ids: DeterministicIdPolicy::GenerateStable {
            prefix: "lens".to_string(),
        },
        preservation: PreservationPolicy::Disabled,
        target_capabilities: TargetCapabilities::default(),
    }
}

/// Record what a translation had to drop or approximate.
///
/// The policy above lets both happen, so nothing here fails a request. But a
/// backend that was sent something the sandbox would not recognise is worth
/// being able to look at afterwards.
fn report(diagnostics: &[TranslationDiagnostic]) {
    for diagnostic in diagnostics {
        tracing::debug!(
            code = %diagnostic.code,
            message = %diagnostic.message,
            path = ?diagnostic.path,
            "llm translation was not exact"
        );
    }
}

/// The formats one streamed answer is translated between: backend first, because
/// that is the direction an answer travels.
pub fn answer_formats(translation: LlmTranslation) -> (WireFormat, WireFormat) {
    let (sandbox, backend) = formats(translation);
    (backend, sandbox)
}

/// Translate the sandbox's request into the one the backend is sent, asking it
/// for `model`.
pub fn request(translation: LlmTranslation, request: &Value, model: &str) -> Result<Value, String> {
    let (sandbox, backend) = formats(translation);
    let translated = TranslationEngine::default()
        .translate_request(sandbox, backend, request, &policy())
        .map_err(|e| format!("this request does not translate to the backend's format: {e}"))?;
    report(&translated.diagnostics);
    let mut body = translated.body;
    let object = body
        .as_object_mut()
        .ok_or("the translated request is not a JSON object")?;

    // Whatever the sandbox asked for, the backend serves the model the table
    // resolved for it.
    object.insert("model".to_string(), json!(model));

    // The sandbox asked Anthropic, which reports usage on every stream. OpenAI
    // reports it only when asked, and the answer has to carry what the sandbox
    // is waiting for.
    if backend == WireFormat::OpenAiChat
        && object.get("stream").and_then(Value::as_bool) == Some(true)
    {
        object.insert(
            "stream_options".to_string(),
            json!({ "include_usage": true }),
        );
    }
    Ok(body)
}

/// Translate a whole answer the backend returned with `status`.
///
/// Only a 2xx carries a completion. Every other status becomes the error the
/// sandbox knows how to read — a refusal, and equally a redirect the backend URL
/// earned from a stray slash, which carries no answer and must not be read as an
/// empty one.
pub fn response(
    translation: LlmTranslation,
    response: &Value,
    status: u16,
) -> Result<Value, String> {
    if !(200..300).contains(&status) {
        return Ok(match translation {
            LlmTranslation::AnthropicMessagesToOpenaiChat => anthropic_refusal(response, status),
        });
    }
    let (backend, sandbox) = answer_formats(translation);
    let translated = TranslationEngine::default()
        .translate_response(backend, sandbox, response, &policy())
        .map_err(|e| format!("the backend's answer does not translate: {e}"))?;
    report(&translated.diagnostics);
    Ok(translated.body)
}

/// A backend's refusal as the Anthropic error the sandbox knows how to read.
///
/// An OpenAI error body reaching a sandbox that speaks Anthropic reads as a
/// malformed answer, which is the one thing a failing request should never look
/// like.
fn anthropic_refusal(response: &Value, status: u16) -> Value {
    let message = response
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("llm backend returned status {status}"));

    let mut body = Map::new();
    body.insert("type".to_string(), json!("error"));
    body.insert(
        "error".to_string(),
        json!({ "type": anthropic_error_type(status), "message": message }),
    );
    Value::Object(body)
}

/// The Anthropic error type for an HTTP status.
fn anthropic_error_type(status: u16) -> &'static str {
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

    const ANTHROPIC_TO_OPENAI: LlmTranslation = LlmTranslation::AnthropicMessagesToOpenaiChat;

    fn parse(json: &str) -> Value {
        serde_json::from_str(json).expect("fixture parses")
    }

    fn translated(json: &str) -> Value {
        request(ANTHROPIC_TO_OPENAI, &parse(json), "qwen3-coder-30b").expect("request translates")
    }

    fn answered(json: &str, status: u16) -> Value {
        response(ANTHROPIC_TO_OPENAI, &parse(json), status).expect("answer translates")
    }

    // ----------------------------------------------------------------------
    // Request: sandbox -> backend
    // ----------------------------------------------------------------------

    #[test]
    fn a_plain_turn_becomes_a_chat_request() {
        let out = translated(
            r#"{
                "model": "claude-sonnet-5",
                "max_tokens": 1024,
                "temperature": 0.2,
                "messages": [{ "role": "user", "content": "hello" }]
            }"#,
        );
        assert_eq!(out["model"], "qwen3-coder-30b");
        // OpenAI renamed the cap, and the translation writes the current name.
        assert_eq!(out["max_completion_tokens"], 1024);
        assert_eq!(out["temperature"], 0.2);
        assert_eq!(out["messages"][0]["role"], "user");
    }

    #[test]
    fn the_model_the_table_resolved_replaces_the_one_the_sandbox_asked_for() {
        let out = translated(r#"{ "model": "claude-opus-5", "messages": [] }"#);
        assert_eq!(out["model"], "qwen3-coder-30b");
    }

    #[test]
    fn the_system_prompt_leads_the_conversation() {
        let out = translated(
            r#"{
                "system": "be brief",
                "messages": [{ "role": "user", "content": "hello" }]
            }"#,
        );
        assert_eq!(out["messages"][0]["role"], "system");
        assert_eq!(out["messages"][1]["role"], "user");
    }

    #[test]
    fn stop_sequences_become_stop() {
        let out = translated(
            r#"{ "stop_sequences": ["END"], "messages": [{ "role": "user", "content": "x" }] }"#,
        );
        assert_eq!(out["stop"][0], "END");
        assert!(out.get("stop_sequences").is_none());
    }

    #[test]
    fn a_streamed_request_asks_for_usage_too() {
        // Anthropic reports usage on every stream; OpenAI reports it only when
        // asked, and the answer has to carry what the sandbox is waiting for.
        let out =
            translated(r#"{ "stream": true, "messages": [{ "role": "user", "content": "x" }] }"#);
        assert_eq!(out["stream"], true);
        assert_eq!(out["stream_options"]["include_usage"], true);
    }

    #[test]
    fn an_unstreamed_request_asks_for_no_stream_options() {
        let out = translated(r#"{ "messages": [{ "role": "user", "content": "x" }] }"#);
        assert!(out.get("stream_options").is_none());
    }

    #[test]
    fn an_image_crosses_as_an_image() {
        let out = translated(
            r#"{ "messages": [{ "role": "user", "content": [
                { "type": "text", "text": "what is this" },
                { "type": "image", "source": {
                    "type": "base64", "media_type": "image/png", "data": "AAAA" } }
            ] }] }"#,
        );
        let content = &out["messages"][0]["content"];
        assert_eq!(content[0]["type"], "text");
        assert_eq!(content[1]["type"], "image_url");
        assert_eq!(content[1]["image_url"]["url"], "data:image/png;base64,AAAA");
    }

    #[test]
    fn tools_become_function_declarations() {
        let out = translated(
            r#"{
                "messages": [{ "role": "user", "content": "x" }],
                "tools": [{
                    "name": "get_weather",
                    "description": "look up the weather",
                    "input_schema": { "type": "object",
                        "properties": { "city": { "type": "string" } } }
                }],
                "tool_choice": { "type": "any" }
            }"#,
        );
        assert_eq!(out["tools"][0]["type"], "function");
        assert_eq!(out["tools"][0]["function"]["name"], "get_weather");
        assert_eq!(
            out["tools"][0]["function"]["parameters"]["properties"]["city"]["type"],
            "string"
        );
        assert_eq!(out["tool_choice"], "required");
    }

    #[test]
    fn a_named_tool_choice_names_a_function() {
        let out = translated(
            r#"{ "messages": [{ "role": "user", "content": "x" }],
                 "tools": [{ "name": "get_weather",
                     "input_schema": { "type": "object" } }],
                 "tool_choice": { "type": "tool", "name": "get_weather" } }"#,
        );
        assert_eq!(out["tool_choice"]["type"], "function");
        assert_eq!(out["tool_choice"]["function"]["name"], "get_weather");
    }

    #[test]
    fn an_assistant_tool_call_becomes_a_tool_call() {
        let out = translated(
            r#"{ "messages": [
                { "role": "user", "content": "weather?" },
                { "role": "assistant", "content": [
                    { "type": "text", "text": "checking" },
                    { "type": "tool_use", "id": "toolu_1", "name": "get_weather",
                      "input": { "city": "Helsinki" } }
                ] }
            ] }"#,
        );
        let assistant = &out["messages"][1];
        assert_eq!(assistant["tool_calls"][0]["type"], "function");
        assert_eq!(
            assistant["tool_calls"][0]["function"]["name"],
            "get_weather"
        );
        assert_eq!(
            assistant["tool_calls"][0]["function"]["arguments"],
            r#"{"city":"Helsinki"}"#
        );
    }

    #[test]
    fn a_tool_result_becomes_its_own_tool_message_first() {
        // Anthropic carries the result inside the user turn; OpenAI wants it as
        // its own message, before whatever else the user said.
        let out = translated(
            r#"{ "messages": [
                { "role": "user", "content": [
                    { "type": "tool_result", "tool_use_id": "toolu_1", "content": "5 degrees" },
                    { "type": "text", "text": "and tomorrow?" }
                ] }
            ] }"#,
        );
        assert_eq!(out["messages"][0]["role"], "tool");
        assert_eq!(out["messages"][0]["tool_call_id"], "toolu_1");
        assert_eq!(out["messages"][1]["role"], "user");
    }

    #[test]
    fn a_thinking_block_does_not_stop_the_request() {
        // An OpenAI backend has nowhere to put Anthropic's record of a previous
        // turn, and the turn still has to reach it.
        let out = translated(
            r#"{ "messages": [
                { "role": "assistant", "content": [
                    { "type": "thinking", "thinking": "hmm", "signature": "sig" },
                    { "type": "text", "text": "the answer" } ] }
            ] }"#,
        );
        assert!(
            serde_json::to_string(&out)
                .expect("request serializes")
                .contains("the answer")
        );
    }

    #[test]
    fn a_redacted_thinking_block_reaches_no_backend() {
        // Anthropic's own encrypted record of a previous turn. It carries no
        // instruction, and writing it into the prompt would show the backend
        // this proxy's plumbing as something the sandbox said.
        let out = translated(
            r#"{ "messages": [
                { "role": "assistant", "content": [
                    { "type": "redacted_thinking", "data": "EroBCkYIAxgCKkBmw" },
                    { "type": "text", "text": "the answer" } ] }
            ] }"#,
        );
        let wire = serde_json::to_string(&out).expect("request serializes");
        assert!(wire.contains("the answer"), "{wire}");
        assert!(
            !wire.contains("EroBCkYIAxgCKkBmw"),
            "the redacted record must not become part of the prompt: {wire}"
        );
    }

    // ----------------------------------------------------------------------
    // Answer: backend -> sandbox
    // ----------------------------------------------------------------------

    #[test]
    fn a_text_answer_becomes_a_message() {
        let out = answered(
            r#"{
                "id": "chatcmpl-1",
                "model": "qwen3-coder-30b",
                "choices": [{ "index": 0, "finish_reason": "stop",
                    "message": { "role": "assistant", "content": "hello" } }],
                "usage": { "prompt_tokens": 12, "completion_tokens": 3 }
            }"#,
            200,
        );
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
        let out = answered(
            r#"{
                "id": "chatcmpl-2",
                "choices": [{ "finish_reason": "tool_calls", "message": {
                    "role": "assistant", "content": null,
                    "tool_calls": [{ "id": "call_1", "type": "function",
                        "function": { "name": "get_weather",
                                      "arguments": "{\"city\":\"Helsinki\"}" } }] } }]
            }"#,
            200,
        );
        let call = out["content"]
            .as_array()
            .expect("content")
            .iter()
            .find(|block| block["type"] == "tool_use")
            .expect("the call reaches the sandbox");
        assert_eq!(call["id"], "call_1");
        assert_eq!(call["name"], "get_weather");
        assert_eq!(call["input"]["city"], "Helsinki");
        assert_eq!(out["stop_reason"], "tool_use");
    }

    #[test]
    fn text_and_tool_calls_keep_their_order() {
        let out = answered(
            r#"{ "choices": [{ "finish_reason": "tool_calls", "message": {
                "content": "checking",
                "tool_calls": [{ "id": "call_1",
                    "function": { "name": "w", "arguments": "{}" } }]
            } }] }"#,
            200,
        );
        assert_eq!(out["content"][0]["type"], "text");
        assert_eq!(out["content"][1]["type"], "tool_use");
    }

    #[test]
    fn a_length_stop_becomes_max_tokens() {
        let out = answered(
            r#"{ "choices": [{ "finish_reason": "length",
                "message": { "content": "x" } }] }"#,
            200,
        );
        assert_eq!(out["stop_reason"], "max_tokens");
    }

    #[test]
    fn missing_usage_reads_as_zero() {
        let out = answered(
            r#"{ "choices": [{ "finish_reason": "stop", "message": { "content": "x" } }] }"#,
            200,
        );
        assert_eq!(out["usage"]["input_tokens"], 0);
        assert_eq!(out["usage"]["output_tokens"], 0);
    }

    #[test]
    fn a_refusal_becomes_an_anthropic_error() {
        let out = answered(
            r#"{ "error": { "message": "no such model",
                "type": "invalid_request_error" } }"#,
            400,
        );
        assert_eq!(out["type"], "error");
        assert_eq!(out["error"]["type"], "invalid_request_error");
        assert_eq!(out["error"]["message"], "no such model");
    }

    #[test]
    fn a_refusal_with_no_body_still_says_something() {
        let out = answered("{}", 503);
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
        let out = answered("{}", 301);
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
            let out = answered("{}", status);
            assert_eq!(out["error"]["type"], expected, "status {status}");
        }
    }
}
