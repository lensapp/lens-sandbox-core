//! The backend's streamed answer, translated frame by frame.
//!
//! `switchyard-translation` translates one parsed event at a time and remembers,
//! between calls, which content block is open. The SSE framing around those
//! events is this file's work: [`StreamTranslator`] takes the backend's bytes as
//! they arrive and gives back the bytes to send on. It buffers a partial line,
//! because an SSE frame split across two TCP reads is ordinary, and it never
//! holds a completed event.
//!
//! Reading a stream needs no format knowledge. All three formats put one JSON
//! object on a `data:` line, and only Chat marks the end with a sentinel, so a
//! parser that reads `data:` lines and stops at `[DONE]` reads all three.
//! Writing one does need it, and [`frame`] is where that lives.

use serde_json::Value;
use switchyard_translation::{StreamTranslationState, TranslationEngine};

use super::translate::{is_passthrough, wire};
use crate::policy_schema::{LlmFormat, LlmTranslation};

/// Cap on one SSE line held while waiting for its newline. Frames are one JSON
/// object each; the cap stops a backend that never sends a newline from growing
/// the buffer without bound.
const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

/// What a Chat stream sends instead of an end-of-message event.
const DONE: &[u8] = b"data: [DONE]\n\n";

/// Turns the backend's event stream into the one the sandbox is waiting for.
pub struct StreamTranslator {
    /// Bytes of a line whose newline has not arrived yet.
    line: Vec<u8>,
    engine: TranslationEngine,
    state: StreamTranslationState,
    translation: LlmTranslation,
    /// Whether any event has gone out, so an answer that never began is not
    /// given an ending. Counted here rather than read off the translation state,
    /// because only some of the encoders record having started.
    started: bool,
    /// Whether the message has been closed, so a second end is not written.
    ended: bool,
}

impl StreamTranslator {
    /// A translator for the answer to a request `translation` sent out.
    pub fn new(translation: LlmTranslation) -> Self {
        Self {
            line: Vec::new(),
            engine: TranslationEngine::default(),
            state: StreamTranslationState::new(wire(translation.to), wire(translation.from)),
            translation,
            started: false,
            ended: false,
        }
    }

    /// Translate the bytes the backend just sent.
    ///
    /// A partial trailing line is kept for the next call, so the caller can pass
    /// on whatever a socket read happened to give it. A route that translates
    /// nothing hands the bytes straight back, which is both cheaper and exact:
    /// no event is reframed, so none can be lost on the way.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        if is_passthrough(self.translation) {
            return Ok(bytes.to_vec());
        }
        let mut out = Vec::new();
        for &byte in bytes {
            if byte != b'\n' {
                self.line.push(byte);
                if self.line.len() > MAX_LINE_BYTES {
                    return Err("llm backend sent an SSE line with no end".to_string());
                }
                continue;
            }
            let line = std::mem::take(&mut self.line);
            let line = String::from_utf8(line)
                .map_err(|_| "llm backend sent a non-UTF-8 SSE line".to_string())?;
            self.translate_line(line.trim_end_matches('\r'), &mut out)?;
        }
        Ok(out)
    }

    /// Close whatever is still open, because the backend has nothing more to
    /// send. Writing an unterminated message would leave the sandbox waiting for
    /// an end that is never coming.
    pub fn finish(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        self.end(&mut out);
        out
    }

    /// Translate one SSE line.
    fn translate_line(&mut self, line: &str, out: &mut Vec<u8>) -> Result<(), String> {
        // Blank lines separate frames, a line starting with `:` is a comment
        // (heartbeats are sent as one), and an `event:` line only repeats the
        // `type` the data carries. None of them holds an event.
        let Some(data) = line.strip_prefix("data:") else {
            return Ok(());
        };
        let data = data.trim();
        if data == "[DONE]" {
            self.end(out);
            return Ok(());
        }
        let chunk: Value = serde_json::from_str(data)
            .map_err(|e| format!("llm backend sent an SSE frame that is not JSON: {e}"))?;
        let events = self
            .engine
            .translate_event(
                &mut self.state,
                wire(self.translation.to),
                wire(self.translation.from),
                &chunk,
            )
            .map_err(|e| format!("llm backend sent a frame that does not translate: {e}"))?;
        self.started |= !events.is_empty();
        for event in &events {
            frame(self.translation.from, event, out);
        }
        Ok(())
    }

    /// Write the events that end the message, once.
    ///
    /// A stream that never started ends silently. Asked to finish one,
    /// `switchyard-translation` synthesises a whole well-formed empty message,
    /// which would show the sandbox an answer the model never gave; a backend
    /// that opened a stream and then said nothing gave no answer at all.
    ///
    /// A translation that fails here writes nothing, which leaves the sandbox
    /// with a truncated message — the same thing it sees when a backend dies
    /// mid-answer, and the caller terminates the body either way.
    fn end(&mut self, out: &mut Vec<u8>) {
        if self.ended || is_passthrough(self.translation) || !self.started {
            return;
        }
        self.ended = true;
        let sandbox = self.translation.from;
        if let Ok(events) = self.engine.finish_stream(&mut self.state, wire(sandbox)) {
            for event in &events {
                frame(sandbox, event, out);
            }
            // Inside the branch: the sentinel says the answer completed, and an
            // answer whose ending could not be written did not.
            if sandbox == LlmFormat::OpenaiChat {
                out.extend_from_slice(DONE);
            }
        }
    }
}

/// Write one translated event as the sandbox's format frames it.
///
/// Anthropic and Responses both name every event, and both name it with the
/// `type` the event already carries. A Chat stream names nothing, and marks its
/// end with [`DONE`] instead of with a final event.
fn frame(sandbox: LlmFormat, event: &Value, out: &mut Vec<u8>) {
    match sandbox {
        LlmFormat::AnthropicMessages | LlmFormat::OpenaiResponses => {
            let name = event
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("message");
            out.extend_from_slice(format!("event: {name}\ndata: {event}\n\n").as_bytes());
        }
        LlmFormat::OpenaiChat => {
            out.extend_from_slice(format!("data: {event}\n\n").as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ANTHROPIC_TO_OPENAI: LlmTranslation = LlmTranslation {
        from: LlmFormat::AnthropicMessages,
        to: LlmFormat::OpenaiChat,
    };

    /// Feed a whole OpenAI stream and read back the Anthropic events.
    fn stream(input: &str) -> Vec<(String, Value)> {
        parse_events(&bytes_out(ANTHROPIC_TO_OPENAI, input))
    }

    /// Feed a whole backend stream through `translation` and keep the raw bytes.
    fn bytes_out(translation: LlmTranslation, input: &str) -> Vec<u8> {
        let mut translator = StreamTranslator::new(translation);
        let mut out = translator
            .push(input.as_bytes())
            .expect("stream translates");
        out.extend(translator.finish());
        out
    }

    fn parse_events(bytes: &[u8]) -> Vec<(String, Value)> {
        let text = String::from_utf8(bytes.to_vec()).expect("events are UTF-8");
        text.split("\n\n")
            .filter(|frame| !frame.trim().is_empty())
            .map(|frame| {
                let mut name = String::new();
                let mut data = Value::Null;
                for line in frame.lines() {
                    if let Some(rest) = line.strip_prefix("event: ") {
                        name = rest.to_string();
                    } else if let Some(rest) = line.strip_prefix("data: ") {
                        data = serde_json::from_str(rest).expect("event data is JSON");
                    }
                }
                (name, data)
            })
            .collect()
    }

    fn names(events: &[(String, Value)]) -> Vec<&str> {
        events.iter().map(|(name, _)| name.as_str()).collect()
    }

    fn deltas(events: &[(String, Value)], field: &str) -> String {
        events
            .iter()
            .filter(|(name, _)| name == "content_block_delta")
            .map(|(_, data)| data["delta"][field].as_str().unwrap_or("").to_string())
            .collect()
    }

    const TEXT_STREAM: &str = concat!(
        r#"data: {"id":"chatcmpl-1","model":"qwen3","choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}"#,
        "\n\n",
        r#"data: {"id":"chatcmpl-1","choices":[{"index":0,"delta":{"content":"Hel"}}]}"#,
        "\n\n",
        r#"data: {"id":"chatcmpl-1","choices":[{"index":0,"delta":{"content":"lo"}}]}"#,
        "\n\n",
        r#"data: {"id":"chatcmpl-1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
        "\n\n",
        r#"data: {"id":"chatcmpl-1","choices":[],"usage":{"prompt_tokens":9,"completion_tokens":2}}"#,
        "\n\n",
        "data: [DONE]\n\n",
    );

    #[test]
    fn a_text_stream_becomes_one_anthropic_message() {
        let events = stream(TEXT_STREAM);
        assert_eq!(
            names(&events),
            [
                "message_start",
                "content_block_start",
                "content_block_delta",
                "content_block_delta",
                "content_block_stop",
                "message_delta",
                "message_stop",
            ]
        );
        // An Anthropic message id carries the `msg_` prefix, so the answer reads
        // like one from the API the sandbox thinks it called.
        assert_eq!(events[0].1["message"]["id"], "msg_chatcmpl-1");
        assert_eq!(events[0].1["message"]["model"], "qwen3");
        assert_eq!(events[1].1["content_block"]["type"], "text");
        assert_eq!(deltas(&events, "text"), "Hello");
        assert_eq!(events[5].1["delta"]["stop_reason"], "end_turn");
        assert_eq!(events[5].1["usage"]["output_tokens"], 2);
    }

    #[test]
    fn an_empty_first_delta_writes_an_empty_block() {
        // OpenAI announces the role with an empty content string, and the answer
        // carries no text at all. An Anthropic message always holds at least one
        // content block, so the empty one is written rather than left out.
        let events = stream(concat!(
            r#"data: {"id":"c","choices":[{"delta":{"role":"assistant","content":""}}]}"#,
            "\n\ndata: [DONE]\n\n",
        ));
        assert_eq!(
            names(&events),
            [
                "message_start",
                "content_block_start",
                "content_block_stop",
                "message_delta",
                "message_stop",
            ]
        );
        assert_eq!(events[1].1["content_block"]["text"], "");
    }

    #[test]
    fn a_stream_split_across_reads_is_translated_whole() {
        let mut translator = StreamTranslator::new(ANTHROPIC_TO_OPENAI);
        let mut out = Vec::new();
        // Cut every frame at an awkward point.
        for part in TEXT_STREAM.as_bytes().chunks(7) {
            out.extend(translator.push(part).expect("stream translates"));
        }
        out.extend(translator.finish());
        assert_eq!(deltas(&parse_events(&out), "text"), "Hello");
    }

    #[test]
    fn crlf_line_endings_are_read_the_same() {
        let events = stream(concat!(
            "data: {\"id\":\"c\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\r\n\r\n",
            "data: [DONE]\r\n\r\n",
        ));
        assert_eq!(deltas(&events, "text"), "hi");
    }

    #[test]
    fn a_tool_call_stream_becomes_a_tool_use_block() {
        let events = stream(concat!(
            r#"data: {"id":"c","model":"m","choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}]}}]}"#,
            "\n\n",
            r#"data: {"id":"c","choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\":"}}]}}]}"#,
            "\n\n",
            r#"data: {"id":"c","choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"Oulu\"}"}}]}}]}"#,
            "\n\n",
            r#"data: {"id":"c","choices":[{"delta":{},"finish_reason":"tool_calls"}]}"#,
            "\n\ndata: [DONE]\n\n",
        ));
        let start = events
            .iter()
            .find(|(name, _)| name == "content_block_start")
            .expect("a tool block opens");
        assert_eq!(start.1["content_block"]["type"], "tool_use");
        assert_eq!(start.1["content_block"]["id"], "call_1");
        assert_eq!(start.1["content_block"]["name"], "get_weather");
        assert_eq!(start.1["content_block"]["input"], json!({}));
        assert_eq!(deltas(&events, "partial_json"), r#"{"city":"Oulu"}"#);
        assert_eq!(names(&events).last(), Some(&"message_stop"));
        let message_delta = events
            .iter()
            .find(|(name, _)| name == "message_delta")
            .expect("the message ends");
        assert_eq!(message_delta.1["delta"]["stop_reason"], "tool_use");
    }

    #[test]
    fn text_before_a_tool_call_closes_first() {
        let events = stream(concat!(
            r#"data: {"id":"c","choices":[{"delta":{"content":"checking"}}]}"#,
            "\n\n",
            r#"data: {"id":"c","choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"w","arguments":"{}"}}]}}]}"#,
            "\n\ndata: [DONE]\n\n",
        ));
        let starts: Vec<&Value> = events
            .iter()
            .filter(|(name, _)| name == "content_block_start")
            .map(|(_, data)| data)
            .collect();
        assert_eq!(starts.len(), 2);
        assert_eq!(starts[0]["content_block"]["type"], "text");
        assert_eq!(starts[0]["index"], 0);
        assert_eq!(starts[1]["content_block"]["type"], "tool_use");
        assert_eq!(starts[1]["index"], 1);
        assert_eq!(
            events
                .iter()
                .filter(|(name, _)| name == "content_block_stop")
                .count(),
            2
        );
    }

    #[test]
    fn two_tool_calls_take_two_blocks() {
        let events = stream(concat!(
            r#"data: {"id":"c","choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"a","arguments":"{}"}}]}}]}"#,
            "\n\n",
            r#"data: {"id":"c","choices":[{"delta":{"tool_calls":[{"index":1,"id":"c2","function":{"name":"b","arguments":"{}"}}]}}]}"#,
            "\n\ndata: [DONE]\n\n",
        ));
        let starts: Vec<&Value> = events
            .iter()
            .filter(|(name, _)| name == "content_block_start")
            .map(|(_, data)| data)
            .collect();
        assert_eq!(starts.len(), 2);
        assert_eq!(starts[0]["content_block"]["name"], "a");
        assert_eq!(starts[0]["index"], 0);
        assert_eq!(starts[1]["content_block"]["name"], "b");
        assert_eq!(starts[1]["index"], 1);
    }

    #[test]
    fn a_stream_that_just_stops_is_still_closed() {
        // No `[DONE]`, no finish_reason — the backend went away. The sandbox
        // still has to be told the message ended.
        let events = stream(concat!(
            r#"data: {"id":"c","choices":[{"delta":{"content":"half"}}]}"#,
            "\n\n",
        ));
        assert_eq!(
            names(&events),
            [
                "message_start",
                "content_block_start",
                "content_block_delta",
                "content_block_stop",
                "message_delta",
                "message_stop",
            ]
        );
    }

    #[test]
    fn a_stream_that_sent_nothing_ends_without_an_empty_message() {
        let mut translator = StreamTranslator::new(ANTHROPIC_TO_OPENAI);
        assert!(translator.finish().is_empty());
    }

    #[test]
    fn the_end_is_written_once() {
        let events = stream(concat!(
            r#"data: {"id":"c","choices":[{"delta":{"content":"hi"}}]}"#,
            "\n\ndata: [DONE]\n\n",
        ));
        assert_eq!(
            events
                .iter()
                .filter(|(name, _)| name == "message_stop")
                .count(),
            1
        );
    }

    #[test]
    fn a_backend_error_mid_stream_becomes_an_error_event() {
        let events = stream(concat!(
            r#"data: {"error":{"message":"backend fell over","type":"server_error"}}"#,
            "\n\n",
        ));
        let error = events
            .iter()
            .find(|(name, _)| name == "error")
            .expect("the failure reaches the sandbox");
        assert_eq!(error.1["error"]["message"], "backend fell over");
    }

    #[test]
    fn a_frame_that_is_not_json_refuses_the_stream() {
        let mut translator = StreamTranslator::new(ANTHROPIC_TO_OPENAI);
        let err = translator
            .push(b"data: {not json}\n\n")
            .expect_err("an unreadable frame is not one to pass on");
        assert!(err.contains("not JSON"), "{err}");
    }

    #[test]
    fn a_line_that_never_ends_is_refused() {
        let mut translator = StreamTranslator::new(ANTHROPIC_TO_OPENAI);
        let err = translator
            .push(&vec![b'x'; MAX_LINE_BYTES + 1])
            .expect_err("a line with no end must not grow the buffer without bound");
        assert!(err.contains("no end"), "{err}");
    }

    /// One Anthropic backend stream, for the sandboxes that do not speak it.
    const ANTHROPIC_STREAM: &str = concat!(
        r#"data: {"type":"message_start","message":{"id":"msg_1","model":"claude-opus-5"}}"#,
        "\n\n",
        r#"data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
        "\n\n",
        r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}"#,
        "\n\n",
    );

    #[test]
    fn a_chat_sandbox_reads_unnamed_frames_and_a_done_sentinel() {
        let out = bytes_out(
            LlmTranslation {
                from: LlmFormat::OpenaiChat,
                to: LlmFormat::AnthropicMessages,
            },
            ANTHROPIC_STREAM,
        );
        let text = String::from_utf8(out).expect("events are UTF-8");
        assert!(
            !text.contains("event: "),
            "a Chat stream names no event: {text}"
        );
        assert!(text.contains(r#""content":"Hi""#), "{text}");
        assert!(
            text.trim_end().ends_with("data: [DONE]"),
            "a Chat stream ends with the sentinel: {text}"
        );
    }

    #[test]
    fn a_responses_sandbox_reads_named_frames_and_no_sentinel() {
        let out = bytes_out(
            LlmTranslation {
                from: LlmFormat::OpenaiResponses,
                to: LlmFormat::AnthropicMessages,
            },
            ANTHROPIC_STREAM,
        );
        let text = String::from_utf8(out).expect("events are UTF-8");
        assert!(text.contains("event: response.created"), "{text}");
        assert!(text.contains("event: response.output_text.delta"), "{text}");
        assert!(text.contains("event: response.completed"), "{text}");
        assert!(
            !text.contains("[DONE]"),
            "only a Chat stream carries the sentinel: {text}"
        );
    }

    #[test]
    fn a_route_that_translates_nothing_hands_the_bytes_straight_back() {
        // Byte for byte, `event:` lines and all. Reframing could only lose
        // something the sandbox already knows how to read.
        for format in [
            LlmFormat::AnthropicMessages,
            LlmFormat::OpenaiChat,
            LlmFormat::OpenaiResponses,
        ] {
            let out = bytes_out(
                LlmTranslation {
                    from: format,
                    to: format,
                },
                ANTHROPIC_STREAM,
            );
            assert_eq!(
                String::from_utf8(out).expect("events are UTF-8"),
                ANTHROPIC_STREAM,
                "{format:?}"
            );
        }
    }

    #[test]
    fn comments_and_blank_lines_carry_no_event() {
        let events = stream(": heartbeat\n\n\ndata: [DONE]\n\n");
        assert!(events.is_empty());
    }
}
