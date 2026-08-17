//! Reading an Anthropic Messages request.
//!
//! The conversation is `messages[]`, each turn holding a string or an array of
//! content blocks. A `tool_result` block holds a conversation of its own, and
//! the system prompt beside the conversation may be an array of blocks too.

use serde_json::Value;

use super::{Reader, Requirements, kind, offers_tools};

/// The Anthropic Messages reader.
pub struct Messages;

/// Content block types this format defines and the translation understands.
///
/// Narrow on purpose. The translation also decodes several other formats'
/// spellings of the same thing out of an Anthropic body — `input_image`,
/// `image_url`, `input_file` — and [`Messages::requirements`] counts only what
/// an Anthropic request can legally carry, so a foreign spelling would reach the
/// backend without ever meeting the capability gate.
///
/// `redacted_thinking` is listed although the translation has no decoding for it
/// either. Anthropic writes one only into an assistant turn, and there an
/// undecoded block is dropped rather than written out.
const CARRIED: &[&str] = &[
    "text",
    "thinking",
    "redacted_thinking",
    "tool_use",
    "tool_result",
    "image",
];

impl Reader for Messages {
    fn requirements(&self, request: &Value) -> Requirements {
        Requirements {
            tools: offers_tools(request),
            images: blocks(request).any(|(kind, _)| kind == "image"),
        }
    }

    fn unsupported_part<'a>(&self, request: &'a Value) -> Option<&'a str> {
        blocks(request).find_map(|(kind, text_only)| {
            let carried = if text_only {
                kind == "text"
            } else {
                CARRIED.contains(&kind)
            };
            (!carried).then_some(kind)
        })
    }
}

/// The `type` of every content block in the request, in order, and whether it
/// sits where the translation carries nothing but text.
///
/// Two positions do. Inside a `tool_result` an image is allowed by Anthropic and
/// written into the tool output as its own raw JSON, base64 and all, because the
/// translation has no shape for one there. Inside a `system` stated as an array
/// anything but text is deleted outright, without so much as a diagnostic.
fn blocks(request: &Value) -> impl Iterator<Item = (&str, bool)> {
    let system = request
        .get("system")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|block| (kind(block), true));

    let turns = request
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
        });

    system.chain(turns)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anthropic(json: &str) -> Value {
        serde_json::from_str(json).expect("fixture parses")
    }

    fn needs(json: &str) -> Requirements {
        Messages.requirements(&anthropic(json))
    }

    fn refused(json: &str) -> Option<String> {
        Messages
            .unsupported_part(&anthropic(json))
            .map(ToString::to_string)
    }

    #[test]
    fn a_plain_request_needs_nothing_special() {
        assert_eq!(
            needs(r#"{ "messages": [{ "role": "user", "content": "hi" }] }"#),
            Requirements::default()
        );
    }

    #[test]
    fn an_image_needs_a_backend_that_sees() {
        assert!(
            needs(
                r#"{ "messages": [{ "role": "user", "content": [
                    { "type": "image", "source": { "type": "url", "url": "https://x/y.png" } } ] }] }"#,
            )
            .images
        );
    }

    #[test]
    fn a_conversation_of_known_blocks_carries() {
        assert_eq!(
            refused(
                r#"{ "messages": [
                    { "role": "user", "content": [{ "type": "text", "text": "hi" }] },
                    { "role": "assistant", "content": [
                        { "type": "thinking", "thinking": "hmm", "signature": "s" },
                        { "type": "tool_use", "id": "t1", "name": "w", "input": {} } ] }
                ] }"#,
            )
            .as_deref(),
            None
        );
    }

    #[test]
    fn a_block_no_translation_carries_is_named() {
        assert_eq!(
            refused(
                r#"{ "messages": [{ "role": "user", "content": [
                    { "type": "text", "text": "read this" },
                    { "type": "document", "source": {} } ] }] }"#,
            )
            .as_deref(),
            Some("document")
        );
    }

    #[test]
    fn another_formats_spelling_of_an_image_does_not_slip_past_the_gate() {
        // The translation would read these as an image or a file, but
        // `requirements` counts Anthropic's spelling, so they would reach a
        // backend that declared it cannot see.
        for kind in ["input_image", "image_url", "file", "input_file"] {
            let request = anthropic(&format!(
                r#"{{ "messages": [{{ "role": "user", "content": [
                    {{ "type": "{kind}", "image_url": "https://x/y.png" }} ] }}] }}"#,
            ));
            assert_eq!(Messages.unsupported_part(&request), Some(kind));
        }
    }

    #[test]
    fn a_block_that_declares_no_type_carries_nothing() {
        assert_eq!(
            refused(r#"{ "messages": [{ "role": "user", "content": [{ "text": "hi" }] }] }"#)
                .as_deref(),
            Some("")
        );
    }

    #[test]
    fn a_tool_result_of_text_carries() {
        assert_eq!(
            refused(
                r#"{ "messages": [{ "role": "user", "content": [
                    { "type": "tool_result", "tool_use_id": "t1", "content": [
                        { "type": "text", "text": "5 degrees" } ] } ] }] }"#,
            )
            .as_deref(),
            None
        );
    }

    #[test]
    fn a_tool_result_of_plain_text_carries() {
        assert_eq!(
            refused(
                r#"{ "messages": [{ "role": "user", "content": [
                    { "type": "tool_result", "tool_use_id": "t1",
                      "content": "5 degrees" } ] }] }"#,
            )
            .as_deref(),
            None
        );
    }

    #[test]
    fn an_image_inside_a_tool_result_is_refused() {
        // Legal Anthropic, and the translation has nowhere to put it: it would
        // write the base64 into the tool output as raw JSON.
        assert_eq!(
            refused(
                r#"{ "messages": [{ "role": "user", "content": [
                    { "type": "tool_result", "tool_use_id": "t1", "content": [
                        { "type": "text", "text": "here" },
                        { "type": "image", "source": { "type": "base64",
                            "media_type": "image/png", "data": "AAAA" } } ] } ] }] }"#,
            )
            .as_deref(),
            Some("image")
        );
    }

    #[test]
    fn a_system_prompt_of_text_carries_whichever_way_it_is_written() {
        for system in [
            r#""be brief""#,
            r#"[{ "type": "text", "text": "be brief" }]"#,
        ] {
            let request = anthropic(&format!(
                r#"{{ "system": {system}, "messages": [{{ "role": "user", "content": "hi" }}] }}"#,
            ));
            assert_eq!(Messages.unsupported_part(&request), None, "{system}");
        }
    }

    #[test]
    fn anything_but_text_in_a_system_prompt_is_refused() {
        // The translation deletes it and says nothing, so the backend would be
        // instructed by less than the sandbox wrote.
        assert_eq!(
            refused(
                r#"{ "system": [
                    { "type": "text", "text": "be brief" },
                    { "type": "image", "source": { "type": "base64",
                        "media_type": "image/png", "data": "AAAA" } } ],
                    "messages": [{ "role": "user", "content": "hi" }] }"#,
            )
            .as_deref(),
            Some("image")
        );
    }

    #[test]
    fn an_image_inside_a_tool_result_still_asks_for_a_backend_that_sees() {
        assert!(
            needs(
                r#"{ "messages": [{ "role": "user", "content": [
                    { "type": "tool_result", "tool_use_id": "t1", "content": [
                        { "type": "image", "source": { "type": "base64",
                            "media_type": "image/png", "data": "AAAA" } } ] } ] }] }"#,
            )
            .images
        );
    }
}
