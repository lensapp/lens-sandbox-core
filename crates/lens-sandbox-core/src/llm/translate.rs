//! Turning one LLM wire format into another.
//!
//! The formats themselves are `switchyard-translation`'s work: it decodes a
//! provider's JSON into a neutral conversation, then encodes that conversation
//! for the provider on the other side. This file owns what that crate leaves to
//! its caller.
//!
//! - Which way round each direction runs. A request goes sandbox → backend; the
//!   answer comes back backend → sandbox.
//! - The [`policy`] every translation runs under.
//! - The model. The sandbox asked for one name and the backend serves another,
//!   so the name the table resolved replaces whatever came out of the encoder.
//! - A route that names one format twice, which translates nothing at all: no
//!   field is added, dropped or renamed, and apart from the model the body says
//!   what the sandbox wrote it to say.
//!
//! A refusal is written by [`super::refusal`], because the crate translates
//! answers and not error bodies.

use serde_json::{Value, json};
use switchyard_translation::{
    DeterministicIdPolicy, LossyConversionPolicy, PreservationPolicy, TargetCapabilities,
    TranslationDiagnostic, TranslationEngine, TranslationPolicy, UnknownFieldPolicy, WireFormat,
};

use super::refusal;
use crate::policy_schema::{LlmFormat, LlmTranslation};

/// The name `switchyard-translation` knows a format by.
pub fn wire(format: LlmFormat) -> WireFormat {
    match format {
        LlmFormat::AnthropicMessages => WireFormat::AnthropicMessages,
        LlmFormat::OpenaiChat => WireFormat::OpenAiChat,
        LlmFormat::OpenaiResponses => WireFormat::OpenAiResponses,
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

/// Whether a route changes the wire format at all.
pub fn is_passthrough(translation: LlmTranslation) -> bool {
    translation.from == translation.to
}

/// Translate the sandbox's request into the one the backend is sent, asking it
/// for `model`.
pub fn request(translation: LlmTranslation, request: &Value, model: &str) -> Result<Value, String> {
    let mut body = if is_passthrough(translation) {
        request.clone()
    } else {
        let translated = TranslationEngine::default()
            .translate_request(
                wire(translation.from),
                wire(translation.to),
                request,
                &policy(),
            )
            .map_err(|e| format!("this request does not translate to the backend's format: {e}"))?;
        report(&translated.diagnostics);
        translated.body
    };
    let object = body
        .as_object_mut()
        .ok_or("the translated request is not a JSON object")?;

    // Whatever the sandbox asked for, the backend serves the model the table
    // resolved for it. This is the one edit a passthrough route also makes.
    object.insert("model".to_string(), json!(model));

    // Anthropic and Responses report usage on every stream; Chat reports it only
    // when asked, and the answer has to carry what the sandbox is waiting for. A
    // sandbox already speaking Chat asked for what it wanted, so this adds
    // nothing to a request it wrote itself.
    if translation.to == LlmFormat::OpenaiChat
        && !is_passthrough(translation)
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
    // A body that could not be read is [`Value::Null`] by the time it gets here.
    // On a status that promised no completion it is the refusal that matters, so
    // the status alone writes it. On a status that promised one, there is no
    // answer to hand back and saying so is the only honest reading.
    if response.is_null() {
        if (200..300).contains(&status) {
            return Err(format!(
                "the backend answered {status} with a body that is not an answer"
            ));
        }
        return Ok(refusal::write(translation.from, response, status));
    }
    if is_passthrough(translation) {
        // The answer is already in the format the sandbox reads, a refusal as
        // much as a completion, so it is handed back as it came. Rewriting it
        // would drop what only the backend knows — an OpenAI `code` that clients
        // branch on, a `param`, a request id.
        return Ok(response.clone());
    }
    if !(200..300).contains(&status) {
        return Ok(refusal::write(translation.from, response, status));
    }
    let translated = TranslationEngine::default()
        .translate_response(
            wire(translation.to),
            wire(translation.from),
            response,
            &policy(),
        )
        .map_err(|e| format!("the backend's answer does not translate: {e}"))?;
    report(&translated.diagnostics);
    Ok(translated.body)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANTHROPIC_TO_OPENAI: LlmTranslation = LlmTranslation {
        from: LlmFormat::AnthropicMessages,
        to: LlmFormat::OpenaiChat,
    };

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
    // Every pair a policy can name
    // ----------------------------------------------------------------------

    const FORMATS: [LlmFormat; 3] = [
        LlmFormat::AnthropicMessages,
        LlmFormat::OpenaiChat,
        LlmFormat::OpenaiResponses,
    ];

    /// The same one-turn conversation, written the way each format writes it.
    fn one_turn(format: LlmFormat) -> Value {
        match format {
            LlmFormat::AnthropicMessages => parse(
                r#"{ "model": "m", "max_tokens": 64,
                     "messages": [{ "role": "user", "content": "weather?" }] }"#,
            ),
            LlmFormat::OpenaiChat => parse(
                r#"{ "model": "m", "max_completion_tokens": 64,
                     "messages": [{ "role": "user", "content": "weather?" }] }"#,
            ),
            LlmFormat::OpenaiResponses => {
                parse(r#"{ "model": "m", "max_output_tokens": 64, "input": "weather?" }"#)
            }
        }
    }

    #[test]
    fn every_pair_of_formats_carries_one_turn() {
        for from in FORMATS {
            for to in FORMATS {
                let translation = LlmTranslation { from, to };
                let out = request(translation, &one_turn(from), "served-by")
                    .unwrap_or_else(|e| panic!("{from:?} -> {to:?}: {e}"));
                assert_eq!(out["model"], "served-by", "{from:?} -> {to:?}");
                assert!(
                    serde_json::to_string(&out)
                        .expect("request serializes")
                        .contains("weather?"),
                    "{from:?} -> {to:?} lost the turn: {out}"
                );
            }
        }
    }

    #[test]
    fn an_openai_sandbox_reaches_an_anthropic_backend() {
        let out = request(
            LlmTranslation {
                from: LlmFormat::OpenaiChat,
                to: LlmFormat::AnthropicMessages,
            },
            &parse(
                r#"{ "model": "gpt-4o", "max_completion_tokens": 64,
                     "messages": [
                        { "role": "system", "content": "be brief" },
                        { "role": "user", "content": "weather?" }] }"#,
            ),
            "claude-opus-5",
        )
        .expect("request translates");

        assert_eq!(out["model"], "claude-opus-5");
        // Anthropic lifts the system turn out of the conversation.
        assert_eq!(out["system"], "be brief");
        assert_eq!(out["max_tokens"], 64);
        assert_eq!(out["messages"][0]["role"], "user");
    }

    #[test]
    fn a_route_that_names_one_format_twice_changes_only_the_model() {
        let sent = parse(
            r#"{ "model": "claude-opus-5", "max_tokens": 64, "metadata": { "user_id": "u1" },
                 "messages": [{ "role": "user", "content": "hi" }] }"#,
        );
        let out = request(
            LlmTranslation {
                from: LlmFormat::AnthropicMessages,
                to: LlmFormat::AnthropicMessages,
            },
            &sent,
            "claude-opus-5-eu",
        )
        .expect("request crosses");

        let mut expected = sent.clone();
        expected["model"] = json!("claude-opus-5-eu");
        assert_eq!(out, expected, "a passthrough route rewrites nothing else");
    }

    #[test]
    fn only_a_translated_chat_request_is_asked_for_usage() {
        // A sandbox already speaking Chat asked for what it wanted.
        let streamed = parse(r#"{ "model": "m", "stream": true, "messages": [] }"#);
        let passthrough = request(
            LlmTranslation {
                from: LlmFormat::OpenaiChat,
                to: LlmFormat::OpenaiChat,
            },
            &streamed,
            "m",
        )
        .expect("request crosses");
        assert!(passthrough.get("stream_options").is_none(), "{passthrough}");
    }

    #[test]
    fn a_passthrough_answer_crosses_untouched() {
        let answered = parse(r#"{ "id": "msg_1", "type": "message", "vendor_extra": true }"#);
        let out = response(
            LlmTranslation {
                from: LlmFormat::AnthropicMessages,
                to: LlmFormat::AnthropicMessages,
            },
            &answered,
            200,
        )
        .expect("answer crosses");
        assert_eq!(out, answered);
    }

    #[test]
    fn a_passthrough_refusal_keeps_what_only_the_backend_knows() {
        // An OpenAI client branches on `code`, and the translated shape has none
        // to give it.
        let refused = parse(
            r#"{ "error": { "message": "you ran out", "type": "insufficient_quota",
                 "code": "insufficient_quota", "param": null } }"#,
        );
        let out = response(
            LlmTranslation {
                from: LlmFormat::OpenaiChat,
                to: LlmFormat::OpenaiChat,
            },
            &refused,
            429,
        )
        .expect("refusal crosses");
        assert_eq!(out, refused);
    }

    #[test]
    fn a_passthrough_backend_that_said_nothing_readable_still_says_something() {
        let out = response(
            LlmTranslation {
                from: LlmFormat::OpenaiChat,
                to: LlmFormat::OpenaiChat,
            },
            &Value::Null,
            502,
        )
        .expect("refusal is written");
        assert!(
            out["error"]["message"]
                .as_str()
                .expect("message")
                .contains("502"),
            "{out}"
        );
    }

    #[test]
    fn a_success_carrying_no_answer_is_not_reported_as_one() {
        // Handing back an error body under a 200 would tell the sandbox the call
        // succeeded and the model refused, and neither happened.
        for translation in [
            ANTHROPIC_TO_OPENAI,
            LlmTranslation {
                from: LlmFormat::OpenaiChat,
                to: LlmFormat::OpenaiChat,
            },
        ] {
            let out = response(translation, &Value::Null, 200);
            assert!(out.is_err(), "{translation:?}: {out:?}");
        }
    }

    #[test]
    fn an_anthropic_answer_reaches_an_openai_sandbox() {
        let out = response(
            LlmTranslation {
                from: LlmFormat::OpenaiChat,
                to: LlmFormat::AnthropicMessages,
            },
            &parse(
                r#"{ "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-opus-5",
                     "content": [{ "type": "text", "text": "5 degrees" }],
                     "stop_reason": "end_turn",
                     "usage": { "input_tokens": 9, "output_tokens": 3 } }"#,
            ),
            200,
        )
        .expect("answer translates");

        assert_eq!(out["object"], "chat.completion");
        assert_eq!(out["choices"][0]["message"]["content"], "5 degrees");
        assert_eq!(out["choices"][0]["finish_reason"], "stop");
        assert_eq!(out["usage"]["prompt_tokens"], 9);
        assert_eq!(out["usage"]["completion_tokens"], 3);
    }

    #[test]
    fn a_refusal_is_written_in_the_format_the_sandbox_reads() {
        let body = parse(r#"{ "error": { "message": "no such model" } }"#);
        let anthropic = response(
            LlmTranslation {
                from: LlmFormat::AnthropicMessages,
                to: LlmFormat::OpenaiChat,
            },
            &body,
            400,
        )
        .expect("error translates");
        assert_eq!(anthropic["type"], "error");

        let openai = response(
            LlmTranslation {
                from: LlmFormat::OpenaiChat,
                to: LlmFormat::AnthropicMessages,
            },
            &body,
            400,
        )
        .expect("error translates");
        assert!(openai.get("type").is_none());
        assert_eq!(openai["error"]["message"], "no such model");
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
