//! The Anthropic Messages request, read and rewritten as an OpenAI Chat
//! Completions request.
//!
//! This file owns what the proxy knows about the shape of an Anthropic request:
//! how to translate one ([`translate`]), and what one asks of the backend that
//! will serve it ([`requirements`]).
//!
//! Two shapes do not survive the crossing, and both are refusals rather than
//! quiet losses:
//!
//! - A content block this translation does not know is an error. Dropping it
//!   would send the backend a different request from the one the sandbox wrote,
//!   and the answer would look like the model's judgement rather than ours.
//! - Assistant `thinking` blocks are the one exception: they are Anthropic's
//!   own record of a previous turn, an OpenAI backend has nowhere to put them,
//!   and they carry no instruction the message text does not already carry.

use serde_json::{Map, Value, json};

/// What a request asks of the backend that will serve it, checked against
/// [`crate::policy_schema::LlmCapabilities`] before anything is translated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Requirements {
    /// The request offers tools, so the backend must be able to call them.
    pub tools: bool,
    /// The request carries an image.
    pub images: bool,
}

/// What this request needs from a backend.
pub fn requirements(request: &Value) -> Requirements {
    Requirements {
        tools: request
            .get("tools")
            .and_then(Value::as_array)
            .is_some_and(|tools| !tools.is_empty()),
        images: request
            .get("messages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|message| message.get("content")?.as_array())
            .flatten()
            .any(|block| block_type(block) == "image"),
    }
}

/// Whether the sandbox asked for the answer to be streamed.
pub fn is_streaming(request: &Value) -> bool {
    request.get("stream").and_then(Value::as_bool) == Some(true)
}

/// The model the sandbox asked for, or `""` when it named none.
pub fn model_of(request: &Value) -> &str {
    request.get("model").and_then(Value::as_str).unwrap_or("")
}

/// Translate an Anthropic Messages request into an OpenAI Chat request asking
/// for `model`.
pub fn translate(request: &Value, model: &str) -> Result<Value, String> {
    let mut messages = Vec::new();
    if let Some(system) = request.get("system") {
        let text = flatten_text(system)?;
        if !text.is_empty() {
            messages.push(json!({ "role": "system", "content": text }));
        }
    }
    for message in request
        .get("messages")
        .and_then(Value::as_array)
        .ok_or("anthropic request has no messages array")?
    {
        translate_message(message, &mut messages)?;
    }

    let mut out = Map::new();
    out.insert("model".into(), json!(model));
    out.insert("messages".into(), Value::Array(messages));

    for (from, to) in [
        ("max_tokens", "max_tokens"),
        ("temperature", "temperature"),
        ("top_p", "top_p"),
        ("stream", "stream"),
        ("stop_sequences", "stop"),
    ] {
        if let Some(value) = request.get(from) {
            out.insert(to.into(), value.clone());
        }
    }

    if let Some(tools) = request.get("tools").and_then(Value::as_array)
        && !tools.is_empty()
    {
        out.insert(
            "tools".into(),
            Value::Array(tools.iter().map(translate_tool).collect::<Result<_, _>>()?),
        );
    }
    if let Some(choice) = request.get("tool_choice") {
        out.insert("tool_choice".into(), translate_tool_choice(choice)?);
    }
    // The sandbox asked for usage on a streamed answer by asking Anthropic,
    // which always reports it. OpenAI reports it on a stream only when asked.
    if is_streaming(request) {
        out.insert("stream_options".into(), json!({ "include_usage": true }));
    }

    Ok(Value::Object(out))
}

/// Translate one Anthropic message, appending the OpenAI messages it becomes.
///
/// One message can become several. Anthropic carries tool results inside the
/// user turn that follows the call; OpenAI wants each of them as its own `tool`
/// message, and wants them before whatever else the user said.
fn translate_message(message: &Value, out: &mut Vec<Value>) -> Result<(), String> {
    let role = message
        .get("role")
        .and_then(Value::as_str)
        .ok_or("anthropic message has no role")?;
    let content = message
        .get("content")
        .ok_or("anthropic message has no content")?;

    if let Some(text) = content.as_str() {
        out.push(json!({ "role": role, "content": text }));
        return Ok(());
    }
    let blocks = content
        .as_array()
        .ok_or("anthropic message content must be a string or an array of blocks")?;

    match role {
        "assistant" => out.push(assistant_message(blocks)?),
        "user" => user_messages(blocks, out)?,
        other => return Err(format!("unknown anthropic message role {other:?}")),
    }
    Ok(())
}

/// One assistant turn: its prose, and the tool calls it made.
fn assistant_message(blocks: &[Value]) -> Result<Value, String> {
    let mut text = String::new();
    let mut tool_calls = Vec::new();
    for block in blocks {
        match block_type(block) {
            "text" => push_text(&mut text, block_text(block)),
            "tool_use" => tool_calls.push(json!({
                "id": block.get("id").cloned().unwrap_or(Value::Null),
                "type": "function",
                "function": {
                    "name": block.get("name").cloned().unwrap_or(Value::Null),
                    "arguments": serde_json::to_string(
                        block.get("input").unwrap_or(&json!({})),
                    ).map_err(|e| format!("tool_use input is not JSON: {e}"))?,
                }
            })),
            // Anthropic's own record of an earlier turn. See the module note.
            "thinking" | "redacted_thinking" => {}
            other => return Err(unknown_block(other)),
        }
    }

    let mut message = Map::new();
    message.insert("role".into(), json!("assistant"));
    // OpenAI wants the key present even when the turn was tool calls alone.
    message.insert(
        "content".into(),
        if text.is_empty() {
            Value::Null
        } else {
            json!(text)
        },
    );
    if !tool_calls.is_empty() {
        message.insert("tool_calls".into(), Value::Array(tool_calls));
    }
    Ok(Value::Object(message))
}

/// One user turn: the tool results it answers with, then what the user said.
fn user_messages(blocks: &[Value], out: &mut Vec<Value>) -> Result<(), String> {
    let mut parts = Vec::new();
    for block in blocks {
        match block_type(block) {
            "tool_result" => out.push(json!({
                "role": "tool",
                "tool_call_id": block.get("tool_use_id").cloned().unwrap_or(Value::Null),
                "content": flatten_text(block.get("content").unwrap_or(&json!("")))?,
            })),
            "text" => parts.push(json!({ "type": "text", "text": block_text(block) })),
            "image" => parts.push(json!({
                "type": "image_url",
                "image_url": { "url": image_url(block)? },
            })),
            other => return Err(unknown_block(other)),
        }
    }
    if !parts.is_empty() {
        out.push(json!({ "role": "user", "content": parts }));
    }
    Ok(())
}

/// An Anthropic image source as the `image_url` OpenAI reads.
fn image_url(block: &Value) -> Result<String, String> {
    let source = block
        .get("source")
        .ok_or("anthropic image block has no source")?;
    match source.get("type").and_then(Value::as_str) {
        Some("base64") => {
            let media = source
                .get("media_type")
                .and_then(Value::as_str)
                .ok_or("anthropic base64 image has no media_type")?;
            let data = source
                .get("data")
                .and_then(Value::as_str)
                .ok_or("anthropic base64 image has no data")?;
            Ok(format!("data:{media};base64,{data}"))
        }
        Some("url") => source
            .get("url")
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .ok_or_else(|| "anthropic url image has no url".to_string()),
        other => Err(format!("unknown anthropic image source type {other:?}")),
    }
}

/// An Anthropic tool declaration as an OpenAI function declaration.
fn translate_tool(tool: &Value) -> Result<Value, String> {
    let name = tool
        .get("name")
        .and_then(Value::as_str)
        .ok_or("anthropic tool has no name")?;
    let mut function = Map::new();
    function.insert("name".into(), json!(name));
    if let Some(description) = tool.get("description") {
        function.insert("description".into(), description.clone());
    }
    function.insert(
        "parameters".into(),
        tool.get("input_schema").cloned().unwrap_or(json!({
            "type": "object", "properties": {}
        })),
    );
    Ok(json!({ "type": "function", "function": Value::Object(function) }))
}

/// An Anthropic `tool_choice` as the OpenAI spelling of the same instruction.
fn translate_tool_choice(choice: &Value) -> Result<Value, String> {
    match choice.get("type").and_then(Value::as_str) {
        Some("auto") => Ok(json!("auto")),
        Some("any") => Ok(json!("required")),
        Some("none") => Ok(json!("none")),
        Some("tool") => {
            let name = choice
                .get("name")
                .and_then(Value::as_str)
                .ok_or("anthropic tool_choice of type tool has no name")?;
            Ok(json!({ "type": "function", "function": { "name": name } }))
        }
        other => Err(format!("unknown anthropic tool_choice type {other:?}")),
    }
}

/// Every text block of a string-or-blocks field, joined into one string.
fn flatten_text(value: &Value) -> Result<String, String> {
    if let Some(text) = value.as_str() {
        return Ok(text.to_string());
    }
    let blocks = value
        .as_array()
        .ok_or("expected a string or an array of content blocks")?;
    let mut out = String::new();
    for block in blocks {
        match block_type(block) {
            "text" => push_text(&mut out, block_text(block)),
            other => return Err(unknown_block(other)),
        }
    }
    Ok(out)
}

/// The `type` of a content block, or `""` when it declares none.
fn block_type(block: &Value) -> &str {
    block.get("type").and_then(Value::as_str).unwrap_or("")
}

/// The `text` of a text block.
fn block_text(block: &Value) -> &str {
    block.get("text").and_then(Value::as_str).unwrap_or("")
}

/// Append a paragraph, keeping the blocks apart.
fn push_text(out: &mut String, text: &str) {
    if !out.is_empty() && !text.is_empty() {
        out.push_str("\n\n");
    }
    out.push_str(text);
}

fn unknown_block(kind: &str) -> String {
    format!(
        "anthropic content block {kind:?} has no translation, and dropping it would send the \
         backend a different request from the one the sandbox wrote"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anthropic(json: &str) -> Value {
        serde_json::from_str(json).expect("fixture parses")
    }

    fn translated(json: &str) -> Value {
        translate(&anthropic(json), "qwen3-coder-30b").expect("request translates")
    }

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
        assert_eq!(out["max_tokens"], 1024);
        assert_eq!(out["temperature"], 0.2);
        assert_eq!(out["messages"][0]["role"], "user");
        assert_eq!(out["messages"][0]["content"], "hello");
    }

    #[test]
    fn the_system_prompt_becomes_the_first_message() {
        let out = translated(
            r#"{
                "system": "be brief",
                "messages": [{ "role": "user", "content": "hello" }]
            }"#,
        );
        assert_eq!(out["messages"][0]["role"], "system");
        assert_eq!(out["messages"][0]["content"], "be brief");
        assert_eq!(out["messages"][1]["role"], "user");
    }

    #[test]
    fn a_block_form_system_prompt_joins_into_one_message() {
        let out = translated(
            r#"{
                "system": [
                    { "type": "text", "text": "be brief" },
                    { "type": "text", "text": "answer in english" }
                ],
                "messages": [{ "role": "user", "content": "hello" }]
            }"#,
        );
        assert_eq!(
            out["messages"][0]["content"],
            "be brief\n\nanswer in english"
        );
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
    fn an_image_becomes_a_data_url() {
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
                    "input_schema": { "type": "object", "properties": { "city": { "type": "string" } } }
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
        assert_eq!(assistant["content"], "checking");
        assert_eq!(assistant["tool_calls"][0]["id"], "toolu_1");
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
    fn a_tool_only_assistant_turn_still_carries_a_content_key() {
        let out = translated(
            r#"{ "messages": [
                { "role": "user", "content": "weather?" },
                { "role": "assistant", "content": [
                    { "type": "tool_use", "id": "toolu_1", "name": "w", "input": {} } ] }
            ] }"#,
        );
        assert!(out["messages"][1]["content"].is_null());
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
        assert_eq!(out["messages"][0]["content"], "5 degrees");
        assert_eq!(out["messages"][1]["role"], "user");
        assert_eq!(out["messages"][1]["content"][0]["text"], "and tomorrow?");
    }

    #[test]
    fn a_tool_result_alone_adds_no_empty_user_turn() {
        let out = translated(
            r#"{ "messages": [
                { "role": "user", "content": [
                    { "type": "tool_result", "tool_use_id": "toolu_1",
                      "content": [{ "type": "text", "text": "5 degrees" }] } ] }
            ] }"#,
        );
        assert_eq!(out["messages"].as_array().expect("messages").len(), 1);
        assert_eq!(out["messages"][0]["content"], "5 degrees");
    }

    #[test]
    fn a_thinking_block_is_left_behind() {
        let out = translated(
            r#"{ "messages": [
                { "role": "assistant", "content": [
                    { "type": "thinking", "thinking": "hmm", "signature": "sig" },
                    { "type": "text", "text": "the answer" } ] }
            ] }"#,
        );
        assert_eq!(out["messages"][0]["content"], "the answer");
    }

    #[test]
    fn an_unknown_block_refuses_the_request() {
        let err = translate(
            &anthropic(
                r#"{ "messages": [{ "role": "user", "content": [
                    { "type": "document", "source": {} } ] }] }"#,
            ),
            "m",
        )
        .expect_err("a block we cannot carry must not be dropped");
        assert!(err.contains("document"), "{err}");
    }

    #[test]
    fn a_request_without_messages_is_refused() {
        assert!(translate(&anthropic(r#"{ "model": "x" }"#), "m").is_err());
    }

    // ----------------------------------------------------------------------
    // Requirements
    // ----------------------------------------------------------------------

    #[test]
    fn a_plain_request_needs_nothing_special() {
        let needs = requirements(&anthropic(
            r#"{ "messages": [{ "role": "user", "content": "hi" }] }"#,
        ));
        assert_eq!(needs, Requirements::default());
    }

    #[test]
    fn offered_tools_need_a_backend_that_calls_them() {
        let needs = requirements(&anthropic(
            r#"{ "messages": [], "tools": [{ "name": "w", "input_schema": {} }] }"#,
        ));
        assert!(needs.tools);
    }

    #[test]
    fn an_empty_tool_list_asks_for_nothing() {
        let needs = requirements(&anthropic(r#"{ "messages": [], "tools": [] }"#));
        assert!(!needs.tools);
    }

    #[test]
    fn an_image_needs_a_backend_that_sees() {
        let needs = requirements(&anthropic(
            r#"{ "messages": [{ "role": "user", "content": [
                { "type": "image", "source": { "type": "url", "url": "https://x/y.png" } } ] }] }"#,
        ));
        assert!(needs.images);
    }
}
