//! The backend's streamed answer, translated frame by frame.
//!
//! `switchyard-translation` translates one parsed event at a time and remembers,
//! between calls, which content block is open. The SSE framing around those
//! events is this file's work: [`StreamTranslator`] takes the backend's bytes as
//! they arrive and gives back the bytes to send on. It buffers a partial line,
//! because an SSE frame split across two TCP reads is ordinary, and it never
//! holds a completed event.
//!
//! Every event is framed with the `type` the target format gave it, which is
//! where an Anthropic client reads the event name from. That is the only wire
//! format a route can address a sandbox in today; a route that answers a sandbox
//! speaking something else needs its own framing beside this one.

use serde_json::Value;
use switchyard_translation::{StreamTranslationState, TranslationEngine, WireFormat};

use crate::policy_schema::LlmTranslation;

/// Cap on one SSE line held while waiting for its newline. Frames are one JSON
/// object each; the cap stops a backend that never sends a newline from growing
/// the buffer without bound.
const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

/// Turns the backend's event stream into the one the sandbox is waiting for.
pub struct StreamTranslator {
    /// Bytes of a line whose newline has not arrived yet.
    line: Vec<u8>,
    engine: TranslationEngine,
    state: StreamTranslationState,
    /// The format the backend streams in.
    backend: WireFormat,
    /// The format the sandbox reads.
    sandbox: WireFormat,
    /// Whether the message has been closed, so a second end is not written.
    ended: bool,
}

impl StreamTranslator {
    /// A translator for the answer to a request `translation` sent out.
    pub fn new(translation: LlmTranslation) -> Self {
        let (backend, sandbox) = super::translate::answer_formats(translation);
        Self {
            line: Vec::new(),
            engine: TranslationEngine::default(),
            state: StreamTranslationState::new(backend, sandbox),
            backend,
            sandbox,
            ended: false,
        }
    }

    /// Translate the bytes the backend just sent.
    ///
    /// A partial trailing line is kept for the next call, so the caller can pass
    /// on whatever a socket read happened to give it.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
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
        // Blank lines separate frames, and a line starting with `:` is a comment
        // (heartbeats are sent as one). Neither carries an event.
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
            .translate_event(&mut self.state, self.backend, self.sandbox, &chunk)
            .map_err(|e| format!("llm backend sent a frame that does not translate: {e}"))?;
        push_events(out, &events);
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
        if self.ended || !self.state.emitted_message_start {
            return;
        }
        self.ended = true;
        if let Ok(events) = self.engine.finish_stream(&mut self.state, self.sandbox) {
            push_events(out, &events);
        }
    }
}

/// Frame translated events as SSE, naming each by its `type`.
fn push_events(out: &mut Vec<u8>, events: &[Value]) {
    for event in events {
        let name = event
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("message");
        out.extend_from_slice(format!("event: {name}\ndata: {event}\n\n").as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ANTHROPIC_TO_OPENAI: LlmTranslation = LlmTranslation::AnthropicMessagesToOpenaiChat;

    /// Feed a whole OpenAI stream and read back the Anthropic events.
    fn stream(input: &str) -> Vec<(String, Value)> {
        let mut translator = StreamTranslator::new(ANTHROPIC_TO_OPENAI);
        let mut out = translator
            .push(input.as_bytes())
            .expect("stream translates");
        out.extend(translator.finish());
        parse_events(&out)
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

    #[test]
    fn comments_and_blank_lines_carry_no_event() {
        let events = stream(": heartbeat\n\n\ndata: [DONE]\n\n");
        assert!(events.is_empty());
    }
}
