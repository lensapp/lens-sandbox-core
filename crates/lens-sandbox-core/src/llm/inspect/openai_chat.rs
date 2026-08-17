//! Reading an OpenAI Chat Completions request.
//!
//! The conversation is `messages[]`, each turn holding a string or an array of
//! content parts. Tool calls hang off the assistant turn rather than sitting in
//! its content, so they are no part of one and are not read here. A tool result
//! is a turn of its own, and its content is parts like any other turn's — but
//! the translation carries less out of it, so what a part may be depends on the
//! role of the turn it sits in.

use serde_json::Value;

use super::{Reader, Requirements, kind, offers_tools};

/// The OpenAI Chat Completions reader.
pub struct Chat;

/// Content part types this format defines and the translation understands.
///
/// Narrow on purpose, for the reason given in [`super`]. The translation also
/// accepts the Responses spellings — `input_text`, `input_image`, `input_file` —
/// out of a Chat body, and [`Chat::requirements`] counts only what a Chat
/// request can legally carry, so those would reach the backend without meeting
/// the capability gate.
///
/// `input_audio` is a legal Chat part and is absent: the translation has no
/// decoding for it, so it would be written into the prompt as raw JSON.
const CARRIED: &[&str] = &["text", "refusal", "image_url", "file"];

impl Reader for Chat {
    fn requirements(&self, request: &Value) -> Requirements {
        Requirements {
            tools: offers_tools(request),
            images: parts(request).any(|(_, kind)| kind == "image_url"),
        }
    }

    fn unsupported_part<'a>(&self, request: &'a Value) -> Option<&'a str> {
        parts(request).find_map(|(role, kind)| (!carried(role, kind)).then_some(kind))
    }
}

/// Whether the translation carries a part of this type in a turn of this role.
///
/// The list above answers for an ordinary turn. Two roles carry less, and
/// neither says so: out of a `tool` turn the translation keeps the text and
/// makes it the whole result, and out of an instruction it keeps the text and a
/// refusal. Anything else in those turns is deleted, with no diagnostic to read
/// afterwards, so it is refused here instead.
fn carried(role: &str, kind: &str) -> bool {
    match role {
        "tool" => kind == "text",
        "system" | "developer" => kind == "text" || kind == "refusal",
        _ => CARRIED.contains(&kind),
    }
}

/// The role of every content part's turn and the part's own `type`, in order.
///
/// A turn whose content is a plain string has no parts, and nothing in it can be
/// anything but text.
fn parts(request: &Value) -> impl Iterator<Item = (&str, &str)> {
    request
        .get("messages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|message| {
            let role = message.get("role").and_then(Value::as_str).unwrap_or("");
            message
                .get("content")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(move |part| (role, kind(part)))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chat(json: &str) -> Value {
        serde_json::from_str(json).expect("fixture parses")
    }

    fn needs(json: &str) -> Requirements {
        Chat.requirements(&chat(json))
    }

    fn refused(json: &str) -> Option<String> {
        Chat.unsupported_part(&chat(json)).map(ToString::to_string)
    }

    #[test]
    fn a_plain_turn_needs_nothing_special() {
        assert_eq!(
            needs(r#"{ "messages": [{ "role": "user", "content": "hi" }] }"#),
            Requirements::default()
        );
    }

    #[test]
    fn a_conversation_of_known_parts_carries() {
        assert_eq!(
            refused(
                r#"{ "messages": [
                    { "role": "system", "content": "be brief" },
                    { "role": "user", "content": [
                        { "type": "text", "text": "what is this" },
                        { "type": "image_url", "image_url": { "url": "https://x/y.png" } } ] },
                    { "role": "assistant", "content": [
                        { "type": "refusal", "refusal": "no" } ] }
                ] }"#,
            )
            .as_deref(),
            None
        );
    }

    #[test]
    fn a_tool_call_and_its_result_are_not_content_parts() {
        assert_eq!(
            refused(
                r#"{ "messages": [
                    { "role": "assistant", "tool_calls": [{ "id": "t1", "type": "function",
                        "function": { "name": "w", "arguments": "{}" } }] },
                    { "role": "tool", "tool_call_id": "t1", "content": "5 degrees" }
                ] }"#,
            )
            .as_deref(),
            None
        );
    }

    #[test]
    fn a_tool_result_carries_nothing_but_its_text() {
        // The translation keeps the text and makes it the whole result. An image
        // beside it is deleted, and not even a diagnostic says so.
        assert_eq!(
            refused(
                r#"{ "messages": [{ "role": "tool", "tool_call_id": "t1", "content": [
                    { "type": "text", "text": "here it is" },
                    { "type": "image_url", "image_url": { "url": "https://x/y.png" } } ] }] }"#,
            )
            .as_deref(),
            Some("image_url")
        );
    }

    #[test]
    fn an_instruction_carries_nothing_but_its_words() {
        for role in ["system", "developer"] {
            let request = chat(&format!(
                r#"{{ "messages": [{{ "role": "{role}", "content": [
                    {{ "type": "text", "text": "be brief" }},
                    {{ "type": "image_url", "image_url": {{ "url": "https://x/y.png" }} }}
                ] }}] }}"#,
            ));
            assert_eq!(Chat.unsupported_part(&request), Some("image_url"), "{role}");
        }
    }

    #[test]
    fn an_image_needs_a_backend_that_sees() {
        assert!(
            needs(
                r#"{ "messages": [{ "role": "user", "content": [
                    { "type": "image_url", "image_url": { "url": "https://x/y.png" } } ] }] }"#,
            )
            .images
        );
    }

    #[test]
    fn another_formats_spelling_of_an_image_does_not_slip_past_the_gate() {
        for kind in ["input_image", "input_text", "input_file"] {
            let request = chat(&format!(
                r#"{{ "messages": [{{ "role": "user", "content": [
                    {{ "type": "{kind}", "image_url": "https://x/y.png" }} ] }}] }}"#,
            ));
            assert_eq!(Chat.unsupported_part(&request), Some(kind));
        }
    }

    #[test]
    fn a_part_no_translation_carries_is_named() {
        assert_eq!(
            refused(
                r#"{ "messages": [{ "role": "user", "content": [
                    { "type": "input_audio", "input_audio": { "data": "AAAA" } } ] }] }"#,
            )
            .as_deref(),
            Some("input_audio")
        );
    }

    #[test]
    fn a_part_that_declares_no_type_carries_nothing() {
        assert_eq!(
            refused(r#"{ "messages": [{ "role": "user", "content": [{ "text": "hi" }] }] }"#)
                .as_deref(),
            Some("")
        );
    }
}
