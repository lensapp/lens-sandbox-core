//! What the proxy reads from the request the sandbox sent.
//!
//! Turning one wire format into another is [`super::translate`]'s job, and it is
//! delegated. This module answers what has to be answered *before* anything is
//! translated: which model was asked for, whether the answer is to be streamed,
//! and whether the request can be carried at all.
//!
//! The first two questions have one answer for every format — all three spell
//! the model `model` and the stream `stream` — so they are free functions. The
//! rest depends on the shape of the request, so there is one [`Reader`] per
//! format the sandbox may speak.
//!
//! Every reader follows the same rule: **carry what the format legally defines
//! and the translation understands, and refuse the rest.** The two halves both
//! matter. A block the translation cannot decode is not dropped — it is written
//! into the prompt as its own raw JSON, so the backend reads this proxy's
//! plumbing as something the sandbox said. And a block from another format's
//! vocabulary may decode into an image without ever being counted as one, which
//! would carry it past the capability gate in [`super::decide`].

mod anthropic;
mod openai_chat;
mod openai_responses;

use serde_json::Value;

use crate::policy_schema::LlmFormat;

/// What a request asks of the backend that will serve it, checked against
/// [`crate::policy_schema::LlmCapabilities`] before anything is translated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Requirements {
    /// The request offers tools, so the backend must be able to call them.
    pub tools: bool,
    /// The request carries an image.
    pub images: bool,
}

/// What one wire format's requests look like to this proxy.
pub trait Reader: Sync {
    /// What this request needs from a backend.
    fn requirements(&self, request: &Value) -> Requirements;

    /// The first part of this request that no translation carries, named as the
    /// request spelled it.
    ///
    /// Refusing is the point. Dropping the part would send the backend a
    /// different request from the one the sandbox wrote, and the answer would
    /// then read as the model's judgement rather than as ours.
    fn unsupported_part<'a>(&self, request: &'a Value) -> Option<&'a str>;
}

/// The reader for the format a sandbox speaks.
pub fn reader(format: LlmFormat) -> &'static dyn Reader {
    match format {
        LlmFormat::AnthropicMessages => &anthropic::Messages,
        LlmFormat::OpenaiChat => &openai_chat::Chat,
        LlmFormat::OpenaiResponses => &openai_responses::Responses,
    }
}

/// Whether the sandbox asked for the answer to be streamed.
///
/// Read before the route is known, so it cannot depend on a format: all three
/// name the field `stream`, and all three mean the same thing by it.
pub fn is_streaming(request: &Value) -> bool {
    request.get("stream").and_then(Value::as_bool) == Some(true)
}

/// The model the sandbox asked for, or `""` when it named none.
///
/// Read before the route is known, because a route may be scoped to one model.
/// All three formats name the field `model`.
pub fn model_of(request: &Value) -> &str {
    request.get("model").and_then(Value::as_str).unwrap_or("")
}

/// Whether a request offers tools. All three formats carry them under `tools`.
fn offers_tools(request: &Value) -> bool {
    request
        .get("tools")
        .and_then(Value::as_array)
        .is_some_and(|tools| !tools.is_empty())
}

/// The `type` a block declares, or `""` when it declares none.
///
/// A block with no type is a block the translation cannot recognise, and `""`
/// matches no carried name, so it is refused like any other.
fn kind(block: &Value) -> &str {
    block.get("type").and_then(Value::as_str).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Value {
        serde_json::from_str(json).expect("fixture parses")
    }

    #[test]
    fn every_format_spells_the_stream_the_same() {
        assert!(is_streaming(&parse(r#"{ "stream": true }"#)));
        assert!(!is_streaming(&parse(r#"{ "stream": false }"#)));
        assert!(!is_streaming(&parse("{}")));
    }

    #[test]
    fn every_format_spells_the_model_the_same() {
        assert_eq!(
            model_of(&parse(r#"{ "model": "claude-opus-5" }"#)),
            "claude-opus-5"
        );
        assert_eq!(model_of(&parse("{}")), "");
    }

    #[test]
    fn a_request_that_offers_no_tools_needs_none() {
        for format in [
            LlmFormat::AnthropicMessages,
            LlmFormat::OpenaiChat,
            LlmFormat::OpenaiResponses,
        ] {
            let needs = reader(format).requirements(&parse(r#"{ "tools": [] }"#));
            assert!(!needs.tools, "{format:?}");
        }
    }

    #[test]
    fn every_reader_counts_the_tools_it_is_offered() {
        for format in [
            LlmFormat::AnthropicMessages,
            LlmFormat::OpenaiChat,
            LlmFormat::OpenaiResponses,
        ] {
            let needs = reader(format).requirements(&parse(r#"{ "tools": [{ "name": "w" }] }"#));
            assert!(needs.tools, "{format:?}");
        }
    }
}
