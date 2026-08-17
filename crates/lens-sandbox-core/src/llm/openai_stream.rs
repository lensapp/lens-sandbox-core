//! The OpenAI Chat Completions stream, read and rewritten as an Anthropic
//! Messages stream.
//!
//! The two protocols carry the same answer in opposite shapes. OpenAI sends one
//! flat chunk per token, each repeating where it belongs; Anthropic sends a
//! structure — a message opens, content blocks open and close inside it, and
//! the message closes. So this translation cannot be a function over one chunk:
//! it is a state machine that remembers which block is open, and closes it when
//! the backend moves on.
//!
//! [`StreamTranslator`] takes the backend's bytes as they arrive and gives back
//! the bytes to send on. It buffers a partial line, because an SSE frame split
//! across two TCP reads is ordinary, and never holds a completed event.

use serde_json::{Value, json};

use super::openai_response::{stop_reason, token_count, tool_use_block};

/// Cap on one SSE line held while waiting for its newline. Frames are one JSON
/// object each; the cap stops a backend that never sends a newline from growing
/// the buffer without bound.
const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

/// Which Anthropic content block is open, and what it is carrying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenBlock {
    /// The model's prose.
    Text,
    /// One tool call, named by the index OpenAI gives it.
    Tool(u64),
}

/// Turns an OpenAI Chat stream into an Anthropic Messages stream.
#[derive(Debug, Default)]
pub struct StreamTranslator {
    /// Bytes of a line whose newline has not arrived yet.
    line: Vec<u8>,
    /// Whether `message_start` has gone out.
    started: bool,
    /// Whether `message_stop` has gone out, so a second end is not written.
    stopped: bool,
    /// The block currently open, if any.
    open: Option<OpenBlock>,
    /// The Anthropic index the next block opens at.
    next_index: usize,
    /// OpenAI tool-call index → the Anthropic block index it opened.
    tool_blocks: Vec<(u64, usize)>,
    id: Option<String>,
    model: Option<String>,
    stop: Value,
    input_tokens: u64,
    output_tokens: u64,
}

impl StreamTranslator {
    pub fn new() -> Self {
        Self {
            stop: Value::Null,
            ..Self::default()
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
        self.end_message(&mut out);
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
            self.end_message(out);
            return Ok(());
        }
        let chunk: Value = serde_json::from_str(data)
            .map_err(|e| format!("llm backend sent an SSE frame that is not JSON: {e}"))?;
        self.translate_chunk(&chunk, out)
    }

    /// Translate one OpenAI chunk.
    fn translate_chunk(&mut self, chunk: &Value, out: &mut Vec<u8>) -> Result<(), String> {
        if let Some(error) = chunk.get("error") {
            push_event(
                out,
                "error",
                json!({
                    "type": "error",
                    "error": {
                        "type": "api_error",
                        "message": error.get("message").cloned().unwrap_or(Value::Null),
                    }
                }),
            );
            return Ok(());
        }

        if let Some(id) = chunk.get("id").and_then(Value::as_str)
            && self.id.is_none()
        {
            self.id = Some(id.to_string());
        }
        if let Some(model) = chunk.get("model").and_then(Value::as_str)
            && self.model.is_none()
        {
            self.model = Some(model.to_string());
        }
        if let Some(usage) = chunk.get("usage").filter(|usage| !usage.is_null()) {
            self.input_tokens = token_count(Some(usage), "prompt_tokens");
            self.output_tokens = token_count(Some(usage), "completion_tokens");
        }

        self.start_message(out);

        let Some(choice) = chunk
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|choices| choices.first())
        else {
            // A usage-only chunk carries no choices. OpenAI sends one last.
            return Ok(());
        };

        if let Some(delta) = choice.get("delta") {
            if let Some(text) = delta.get("content").and_then(Value::as_str)
                && !text.is_empty()
            {
                self.open_text(out);
                push_event(
                    out,
                    "content_block_delta",
                    json!({
                        "type": "content_block_delta",
                        "index": self.next_index - 1,
                        "delta": { "type": "text_delta", "text": text },
                    }),
                );
            }
            for call in delta
                .get("tool_calls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                self.translate_tool_call(call, out)?;
            }
        }

        if let Some(finish) = choice.get("finish_reason").and_then(Value::as_str) {
            self.stop = stop_reason(Some(finish));
        }
        Ok(())
    }

    /// Translate one entry of a chunk's `tool_calls` array.
    fn translate_tool_call(&mut self, call: &Value, out: &mut Vec<u8>) -> Result<(), String> {
        let slot = call.get("index").and_then(Value::as_u64).unwrap_or(0);
        let index = match self.tool_blocks.iter().find(|(s, _)| *s == slot) {
            Some((_, index)) => *index,
            None => {
                self.close_block(out);
                let index = self.next_index;
                self.next_index += 1;
                self.tool_blocks.push((slot, index));
                self.open = Some(OpenBlock::Tool(slot));
                // The opening chunk names the call; the ones that follow only
                // add to its arguments. Anthropic wants the name up front, so
                // an empty `input` opens the block and the deltas fill it.
                let mut block = tool_use_block(call)?;
                block["input"] = json!({});
                push_event(
                    out,
                    "content_block_start",
                    json!({
                        "type": "content_block_start",
                        "index": index,
                        "content_block": block,
                    }),
                );
                index
            }
        };

        if let Some(arguments) = call
            .get("function")
            .and_then(|function| function.get("arguments"))
            .and_then(Value::as_str)
            && !arguments.is_empty()
        {
            push_event(
                out,
                "content_block_delta",
                json!({
                    "type": "content_block_delta",
                    "index": index,
                    "delta": { "type": "input_json_delta", "partial_json": arguments },
                }),
            );
        }
        Ok(())
    }

    /// Open the message, once.
    fn start_message(&mut self, out: &mut Vec<u8>) {
        if self.started {
            return;
        }
        self.started = true;
        push_event(
            out,
            "message_start",
            json!({
                "type": "message_start",
                "message": {
                    "id": self.id.clone().unwrap_or_else(|| "msg_translated".to_string()),
                    "type": "message",
                    "role": "assistant",
                    "model": self.model.clone().map_or(Value::Null, Value::from),
                    "content": [],
                    "stop_reason": Value::Null,
                    "stop_sequence": Value::Null,
                    // The backend reports its token counts at the end of the
                    // stream, and this frame has to go first. The real counts
                    // arrive in `message_delta`.
                    "usage": { "input_tokens": 0, "output_tokens": 0 },
                }
            }),
        );
    }

    /// Make sure a text block is the one open.
    fn open_text(&mut self, out: &mut Vec<u8>) {
        if self.open == Some(OpenBlock::Text) {
            return;
        }
        self.close_block(out);
        let index = self.next_index;
        self.next_index += 1;
        self.open = Some(OpenBlock::Text);
        push_event(
            out,
            "content_block_start",
            json!({
                "type": "content_block_start",
                "index": index,
                "content_block": { "type": "text", "text": "" },
            }),
        );
    }

    /// Close the open block, if there is one.
    fn close_block(&mut self, out: &mut Vec<u8>) {
        if self.open.take().is_some() {
            push_event(
                out,
                "content_block_stop",
                json!({ "type": "content_block_stop", "index": self.next_index - 1 }),
            );
        }
    }

    /// Close the message, once.
    fn end_message(&mut self, out: &mut Vec<u8>) {
        if self.stopped {
            return;
        }
        // A backend that fails before its first chunk leaves nothing to close,
        // and an empty message the sandbox would have to interpret is worse
        // than the connection ending.
        if !self.started {
            self.stopped = true;
            return;
        }
        self.stopped = true;
        self.close_block(out);
        push_event(
            out,
            "message_delta",
            json!({
                "type": "message_delta",
                "delta": { "stop_reason": self.stop.clone(), "stop_sequence": Value::Null },
                "usage": {
                    "input_tokens": self.input_tokens,
                    "output_tokens": self.output_tokens,
                },
            }),
        );
        push_event(out, "message_stop", json!({ "type": "message_stop" }));
    }
}

/// Append one Anthropic SSE frame.
fn push_event(out: &mut Vec<u8>, name: &str, data: Value) {
    out.extend_from_slice(format!("event: {name}\ndata: {data}\n\n").as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed a whole OpenAI stream and read back the Anthropic events.
    fn stream(input: &str) -> Vec<(String, Value)> {
        let mut translator = StreamTranslator::new();
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
        assert_eq!(events[0].1["message"]["id"], "chatcmpl-1");
        assert_eq!(events[0].1["message"]["model"], "qwen3");
        assert_eq!(events[1].1["content_block"]["type"], "text");
        assert_eq!(events[2].1["delta"]["text"], "Hel");
        assert_eq!(events[3].1["delta"]["text"], "lo");
        assert_eq!(events[5].1["delta"]["stop_reason"], "end_turn");
        assert_eq!(events[5].1["usage"]["input_tokens"], 9);
        assert_eq!(events[5].1["usage"]["output_tokens"], 2);
    }

    #[test]
    fn an_empty_first_delta_opens_no_block() {
        // OpenAI announces the role with an empty content string. A block opened
        // for it would be a block the model never wrote in.
        let events = stream(concat!(
            r#"data: {"id":"c","choices":[{"delta":{"role":"assistant","content":""}}]}"#,
            "\n\ndata: [DONE]\n\n",
        ));
        assert_eq!(
            names(&events),
            ["message_start", "message_delta", "message_stop"]
        );
    }

    #[test]
    fn a_stream_split_across_reads_is_translated_whole() {
        let mut translator = StreamTranslator::new();
        let mut out = Vec::new();
        // Cut every frame in half at an awkward point.
        let bytes = TEXT_STREAM.as_bytes();
        for pair in bytes.chunks(7) {
            out.extend(translator.push(pair).expect("stream translates"));
        }
        out.extend(translator.finish());
        let events = parse_events(&out);
        let text: String = events
            .iter()
            .filter(|(name, _)| name == "content_block_delta")
            .map(|(_, data)| data["delta"]["text"].as_str().unwrap_or("").to_string())
            .collect();
        assert_eq!(text, "Hello");
    }

    #[test]
    fn crlf_line_endings_are_read_the_same() {
        let events = stream(concat!(
            "data: {\"id\":\"c\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\r\n\r\n",
            "data: [DONE]\r\n\r\n",
        ));
        assert_eq!(events[2].1["delta"]["text"], "hi");
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
        assert_eq!(events[1].1["content_block"]["type"], "tool_use");
        assert_eq!(events[1].1["content_block"]["id"], "call_1");
        assert_eq!(events[1].1["content_block"]["name"], "get_weather");
        assert_eq!(events[1].1["content_block"]["input"], json!({}));
        assert_eq!(events[2].1["delta"]["type"], "input_json_delta");
        let arguments: String = events[2..4]
            .iter()
            .map(|(_, data)| {
                data["delta"]["partial_json"]
                    .as_str()
                    .unwrap_or("")
                    .to_string()
            })
            .collect();
        assert_eq!(arguments, r#"{"city":"Oulu"}"#);
        assert_eq!(events[5].1["delta"]["stop_reason"], "tool_use");
    }

    #[test]
    fn text_before_a_tool_call_closes_first() {
        let events = stream(concat!(
            r#"data: {"id":"c","choices":[{"delta":{"content":"checking"}}]}"#,
            "\n\n",
            r#"data: {"id":"c","choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"w","arguments":"{}"}}]}}]}"#,
            "\n\ndata: [DONE]\n\n",
        ));
        assert_eq!(
            names(&events),
            [
                "message_start",
                "content_block_start",
                "content_block_delta",
                "content_block_stop",
                "content_block_start",
                "content_block_delta",
                "content_block_stop",
                "message_delta",
                "message_stop",
            ]
        );
        assert_eq!(events[1].1["index"], 0);
        assert_eq!(events[4].1["index"], 1);
        assert_eq!(events[6].1["index"], 1);
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
        assert_eq!(events[4].1["delta"]["stop_reason"], Value::Null);
    }

    #[test]
    fn a_stream_that_sent_nothing_ends_without_an_empty_message() {
        let mut translator = StreamTranslator::new();
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
        assert_eq!(events[0].0, "error");
        assert_eq!(events[0].1["error"]["message"], "backend fell over");
    }

    #[test]
    fn a_frame_that_is_not_json_refuses_the_stream() {
        let mut translator = StreamTranslator::new();
        let err = translator
            .push(b"data: {not json}\n\n")
            .expect_err("an unreadable frame is not one to pass on");
        assert!(err.contains("not JSON"), "{err}");
    }

    #[test]
    fn comments_and_blank_lines_carry_no_event() {
        let events = stream(": heartbeat\n\n\ndata: [DONE]\n\n");
        assert!(events.is_empty());
    }
}
