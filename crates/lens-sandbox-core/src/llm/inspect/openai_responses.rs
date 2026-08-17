//! Reading an OpenAI Responses request.
//!
//! The conversation is `input`, either a plain string or an array of items. An
//! item is not a content block: a turn, a tool call, a tool result and a
//! reasoning record are all items. Two of them hold content parts of their own —
//! a `message` under `content`, a `function_call_output` under `output`.

use serde_json::Value;

use super::{Reader, Requirements, kind, offers_tools};

/// The OpenAI Responses reader.
pub struct Responses;

/// Input item types this format defines and the translation understands.
///
/// A `function_call_output` is understood only where it states its output as a
/// string; see [`stringified_output`].
///
/// An item with no `type` is refused, and that is not pedantry. The Responses
/// API accepts a bare `{"role": ..., "content": ...}` as shorthand for a message
/// item, but the translation does not: it writes the whole item into the prompt
/// as raw JSON, so the backend is told the sandbox said `{"content":"hi",
/// "role":"user"}`. Refusing is the only reading of that which is not a lie.
const CARRIED_ITEMS: &[&str] = &[
    "message",
    "reasoning",
    "function_call",
    "function_call_output",
];

/// Content part types a `message` item may hold.
const CARRIED_PARTS: &[&str] = &[
    "input_text",
    "output_text",
    "refusal",
    "input_image",
    "input_file",
];

impl Reader for Responses {
    fn requirements(&self, request: &Value) -> Requirements {
        Requirements {
            tools: offers_tools(request),
            images: parts(request).any(|kind| kind == "input_image"),
        }
    }

    fn unsupported_part<'a>(&self, request: &'a Value) -> Option<&'a str> {
        items(request)
            .find(|kind| !CARRIED_ITEMS.contains(kind))
            .or_else(|| stringified_output(request))
            .or_else(|| parts(request).find(|kind| !CARRIED_PARTS.contains(kind)))
    }
}

/// Every input item, in order. A plain string `input` holds none.
fn input(request: &Value) -> impl Iterator<Item = &Value> {
    request
        .get("input")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

/// The `type` of every input item, in order.
fn items(request: &Value) -> impl Iterator<Item = &str> {
    input(request).map(kind)
}

/// The `type` of every content part in the conversation, in order, wherever it
/// sits: in a `message` item's content, or in a tool result's array output.
///
/// Both positions count for [`Requirements`], because on a route that translates
/// nothing an image reaches the backend from either one.
fn parts(request: &Value) -> impl Iterator<Item = &str> {
    input(request)
        .filter_map(|item| match kind(item) {
            "message" => item.get("content")?.as_array(),
            "function_call_output" => item.get("output")?.as_array(),
            _ => None,
        })
        .flatten()
        .map(kind)
}

/// A tool result whose output the translation would hand on as raw JSON.
///
/// The Responses API lets a `function_call_output` state its output either as a
/// string or as an array of parts. The translation reads only the string: an
/// array is serialized whole and becomes the *text* of the tool result, so a
/// model on the other side is shown `[{"type":"input_image",...}]` where the
/// sandbox put an image. Every array is refused, whatever it holds.
fn stringified_output(request: &Value) -> Option<&str> {
    input(request)
        .filter(|item| kind(item) == "function_call_output")
        .find(|item| item.get("output").is_some_and(Value::is_array))
        .map(kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn responses(json: &str) -> Value {
        serde_json::from_str(json).expect("fixture parses")
    }

    fn needs(json: &str) -> Requirements {
        Responses.requirements(&responses(json))
    }

    fn refused(json: &str) -> Option<String> {
        Responses
            .unsupported_part(&responses(json))
            .map(ToString::to_string)
    }

    #[test]
    fn a_plain_string_input_needs_nothing_special() {
        const PLAIN: &str = r#"{ "model": "m", "input": "hi" }"#;
        assert_eq!(needs(PLAIN), Requirements::default());
        assert_eq!(refused(PLAIN).as_deref(), None);
    }

    #[test]
    fn a_conversation_of_known_items_carries() {
        assert_eq!(
            refused(
                r#"{ "input": [
                    { "type": "message", "role": "user", "content": [
                        { "type": "input_text", "text": "weather?" } ] },
                    { "type": "reasoning", "summary": [] },
                    { "type": "function_call", "call_id": "t1", "name": "w", "arguments": "{}" },
                    { "type": "function_call_output", "call_id": "t1", "output": "5 degrees" }
                ] }"#,
            )
            .as_deref(),
            None
        );
    }

    #[test]
    fn a_bare_role_and_content_item_is_refused() {
        // Legal Responses shorthand that the translation writes into the prompt
        // as its own raw JSON.
        assert_eq!(
            refused(r#"{ "input": [{ "role": "user", "content": "hi" }] }"#).as_deref(),
            Some("")
        );
    }

    #[test]
    fn an_item_no_translation_carries_is_named() {
        assert_eq!(
            refused(r#"{ "input": [{ "type": "web_search_call", "id": "ws_1" }] }"#).as_deref(),
            Some("web_search_call")
        );
    }

    #[test]
    fn an_image_needs_a_backend_that_sees() {
        assert!(
            needs(
                r#"{ "input": [{ "type": "message", "role": "user", "content": [
                    { "type": "input_image", "image_url": "https://x/y.png" } ] }] }"#,
            )
            .images
        );
    }

    #[test]
    fn a_file_crosses_but_an_unknown_part_does_not() {
        assert_eq!(
            refused(
                r#"{ "input": [{ "type": "message", "role": "user", "content": [
                    { "type": "input_file", "file_id": "f_1" } ] }] }"#,
            )
            .as_deref(),
            None
        );
        assert_eq!(
            refused(
                r#"{ "input": [{ "type": "message", "role": "user", "content": [
                    { "type": "input_audio", "data": "AAAA" } ] }] }"#,
            )
            .as_deref(),
            Some("input_audio")
        );
    }

    #[test]
    fn a_tool_result_stated_as_parts_is_refused() {
        // The translation reads only a string here and serializes anything else
        // into the text of the result.
        assert_eq!(
            refused(
                r#"{ "input": [{ "type": "function_call_output", "call_id": "t1",
                    "output": [{ "type": "input_text", "text": "here it is" }] }] }"#,
            )
            .as_deref(),
            Some("function_call_output")
        );
        assert_eq!(
            refused(
                r#"{ "input": [{ "type": "function_call_output", "call_id": "t1",
                    "output": "5 degrees" }] }"#,
            )
            .as_deref(),
            None
        );
    }

    #[test]
    fn an_image_in_a_tool_result_is_still_an_image() {
        // A route that translates nothing never asks what carries, so the gate
        // is the only thing standing between this and a blind backend.
        assert!(
            needs(
                r#"{ "input": [{ "type": "function_call_output", "call_id": "t1", "output": [
                    { "type": "input_image", "image_url": "data:image/png;base64,AAAA" } ] }] }"#,
            )
            .images
        );
    }

    #[test]
    fn the_item_is_named_before_the_part_inside_it() {
        assert_eq!(
            refused(
                r#"{ "input": [{ "type": "computer_call", "content": [
                    { "type": "input_audio" } ] }] }"#,
            )
            .as_deref(),
            Some("computer_call")
        );
    }
}
