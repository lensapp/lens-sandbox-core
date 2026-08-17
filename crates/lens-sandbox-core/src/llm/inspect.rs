//! What the proxy reads from the request the sandbox sent.
//!
//! Turning one wire format into another is [`super::translate`]'s job, and it is
//! delegated. This file answers the three questions that have to be answered
//! *before* anything is translated: which model was asked for, whether the
//! answer is to be streamed, and what the request needs from the backend that
//! will serve it.
//!
//! The shapes read here are Anthropic Messages, because that is the format every
//! [`crate::policy_schema::LlmTranslation`] currently starts from. A translation
//! that starts somewhere else needs its own reader beside this one.

use serde_json::Value;

/// What a request asks of the backend that will serve it, checked against
/// [`crate::policy_schema::LlmCapabilities`] before anything is translated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Requirements {
    /// The request offers tools, so the backend must be able to call them.
    pub tools: bool,
    /// The request carries an image.
    pub images: bool,
}

/// Content block types a translation carries across.
///
/// This is the Anthropic Messages contract, and nothing wider. Two reasons to
/// keep it narrow:
///
/// - `switchyard-translation` decodes several other providers' spellings of the
///   same thing — `input_image`, `image_url`, `file` — out of an Anthropic body
///   as well. [`requirements`] counts what an Anthropic request can legally
///   carry, so a foreign spelling would reach the backend without ever meeting
///   the capability gate.
/// - A block outside the list is not dropped by the translation. In a user turn
///   it is written into the prompt as its own raw JSON, which is worse than
///   dropping it: the backend reads this proxy's plumbing as something the
///   sandbox said.
///
/// `redacted_thinking` is on the list although the translation has no decoding
/// for it either. Anthropic writes one only into an assistant turn, and there an
/// undecoded block is dropped rather than written out.
const CARRIED_BLOCKS: &[&str] = &[
    "text",
    "thinking",
    "redacted_thinking",
    "tool_use",
    "tool_result",
    "image",
];

/// What this request needs from a backend.
pub fn requirements(request: &Value) -> Requirements {
    Requirements {
        tools: request
            .get("tools")
            .and_then(Value::as_array)
            .is_some_and(|tools| !tools.is_empty()),
        images: blocks(request).any(|(kind, _)| kind == "image"),
    }
}

/// The first content block this request carries and a translation cannot.
///
/// Dropping one would send the backend a different request from the one the
/// sandbox wrote, and the answer would then read as the model's judgement
/// rather than as ours. So a block nothing can carry refuses the request.
///
/// Inside a `tool_result` only text is carried. Anthropic allows an image
/// there, but the translation has no OpenAI shape for one and writes it into
/// the tool output as its own raw JSON, base64 and all.
pub fn unsupported_block(request: &Value) -> Option<&str> {
    blocks(request).find_map(|(kind, nested)| {
        let carried = if nested {
            kind == "text"
        } else {
            CARRIED_BLOCKS.contains(&kind)
        };
        (!carried).then_some(kind)
    })
}

/// The `type` of every content block in the conversation, in order, and whether
/// it sits inside another block rather than directly in a turn.
fn blocks(request: &Value) -> impl Iterator<Item = (&str, bool)> {
    request
        .get("messages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|message| message.get("content")?.as_array())
        .flatten()
        .flat_map(|block| {
            let nested = block
                .get("content")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|inner| (kind(inner), true));
            std::iter::once((kind(block), false)).chain(nested)
        })
}

/// The `type` a content block declares, or `""` when it declares none.
fn kind(block: &Value) -> &str {
    block.get("type").and_then(Value::as_str).unwrap_or("")
}

/// Whether the sandbox asked for the answer to be streamed.
pub fn is_streaming(request: &Value) -> bool {
    request.get("stream").and_then(Value::as_bool) == Some(true)
}

/// The model the sandbox asked for, or `""` when it named none.
pub fn model_of(request: &Value) -> &str {
    request.get("model").and_then(Value::as_str).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anthropic(json: &str) -> Value {
        serde_json::from_str(json).expect("fixture parses")
    }

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

    #[test]
    fn a_conversation_of_known_blocks_carries() {
        assert_eq!(
            unsupported_block(&anthropic(
                r#"{ "messages": [
                    { "role": "user", "content": [{ "type": "text", "text": "hi" }] },
                    { "role": "assistant", "content": [
                        { "type": "thinking", "thinking": "hmm", "signature": "s" },
                        { "type": "tool_use", "id": "t1", "name": "w", "input": {} } ] }
                ] }"#,
            )),
            None
        );
    }

    #[test]
    fn a_block_no_translation_carries_is_named() {
        assert_eq!(
            unsupported_block(&anthropic(
                r#"{ "messages": [{ "role": "user", "content": [
                    { "type": "text", "text": "read this" },
                    { "type": "document", "source": {} } ] }] }"#,
            )),
            Some("document")
        );
    }

    #[test]
    fn another_providers_spelling_of_an_image_does_not_slip_past_the_gate() {
        // The translation would read this as an image, but `requirements` counts
        // Anthropic's spelling, so it would reach a backend that declared it
        // cannot see.
        for kind in ["input_image", "image_url", "file", "input_file"] {
            let request = anthropic(&format!(
                r#"{{ "messages": [{{ "role": "user", "content": [
                    {{ "type": "{kind}", "image_url": "https://x/y.png" }} ] }}] }}"#,
            ));
            assert_eq!(unsupported_block(&request), Some(kind));
        }
    }

    #[test]
    fn a_block_that_declares_no_type_carries_nothing() {
        assert_eq!(
            unsupported_block(&anthropic(
                r#"{ "messages": [{ "role": "user", "content": [{ "text": "hi" }] }] }"#,
            )),
            Some("")
        );
    }

    #[test]
    fn a_tool_result_of_text_carries() {
        assert_eq!(
            unsupported_block(&anthropic(
                r#"{ "messages": [{ "role": "user", "content": [
                    { "type": "tool_result", "tool_use_id": "t1", "content": [
                        { "type": "text", "text": "5 degrees" } ] } ] }] }"#,
            )),
            None
        );
    }

    #[test]
    fn a_tool_result_of_plain_text_carries() {
        assert_eq!(
            unsupported_block(&anthropic(
                r#"{ "messages": [{ "role": "user", "content": [
                    { "type": "tool_result", "tool_use_id": "t1",
                      "content": "5 degrees" } ] }] }"#,
            )),
            None
        );
    }

    #[test]
    fn an_image_inside_a_tool_result_is_refused() {
        // Legal Anthropic, and the translation has nowhere to put it: it would
        // write the base64 into the tool output as raw JSON.
        assert_eq!(
            unsupported_block(&anthropic(
                r#"{ "messages": [{ "role": "user", "content": [
                    { "type": "tool_result", "tool_use_id": "t1", "content": [
                        { "type": "text", "text": "here" },
                        { "type": "image", "source": { "type": "base64",
                            "media_type": "image/png", "data": "AAAA" } } ] } ] }] }"#,
            )),
            Some("image")
        );
    }

    #[test]
    fn an_image_inside_a_tool_result_still_asks_for_a_backend_that_sees() {
        let needs = requirements(&anthropic(
            r#"{ "messages": [{ "role": "user", "content": [
                { "type": "tool_result", "tool_use_id": "t1", "content": [
                    { "type": "image", "source": { "type": "base64",
                        "media_type": "image/png", "data": "AAAA" } } ] } ] }] }"#,
        ));
        assert!(needs.images);
    }

    #[test]
    fn a_streamed_request_says_so() {
        assert!(is_streaming(&anthropic(r#"{ "stream": true }"#)));
        assert!(!is_streaming(&anthropic(r#"{ "stream": false }"#)));
        assert!(!is_streaming(&anthropic("{}")));
    }

    #[test]
    fn a_request_that_names_no_model_names_nothing() {
        assert_eq!(
            model_of(&anthropic(r#"{ "model": "claude-opus-5" }"#)),
            "claude-opus-5"
        );
        assert_eq!(model_of(&anthropic("{}")), "");
    }
}
