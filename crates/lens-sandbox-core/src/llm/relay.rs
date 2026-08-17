//! Carrying the backend's answer back to the sandbox.
//!
//! The ordinary MITM path splices a response through as bytes. This one cannot:
//! the answer is in the backend's format and the sandbox is waiting for its own.
//! So the answer is read, translated, and re-framed, and the head the sandbox
//! sees is written here rather than forwarded.
//!
//! Two shapes, decided by what the sandbox asked for:
//!
//! - A whole answer is buffered, translated once, and sent with its length.
//! - A streamed answer is translated event by event and sent as it arrives, so
//!   the sandbox sees the first token as early as it would have from the API it
//!   thought it was calling.
//!
//! A backend that refuses takes the buffered path either way. An error is not a
//! stream, whatever the request asked for.

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::{MAX_LLM_BODY_BYTES, Redirect, stream::StreamTranslator, translate};
use crate::http_body::{ResponseBody, determine_response_framing, read_head};

type Failure = Box<dyn std::error::Error + Send + Sync>;

/// The one status that carries an event stream. Anything else — a redirect the
/// backend URL earned by a stray slash, a refusal, a retry-after — is an answer,
/// not a stream, and is translated as a whole body whatever the request asked
/// for. Dressing a 301 up as `200 OK` with an empty stream would show the
/// sandbox a successful call that never happened.
const STREAMING_STATUS: u16 = 200;

/// Read the backend's answer, translate it, and write it to the sandbox.
pub async fn forward_translated<C, U>(
    client: &mut C,
    upstream: &mut U,
    redirect: &Redirect,
) -> Result<(), Failure>
where
    C: AsyncWrite + Unpin,
    U: AsyncRead + Unpin,
{
    let head_bytes = read_head(upstream).await?;
    let head = String::from_utf8_lossy(&head_bytes).into_owned();
    let status = parse_status(&head).ok_or("llm backend sent a malformed status line")?;
    let mut body = ResponseBody::new(determine_response_framing(&head));

    if redirect.streaming && status == STREAMING_STATUS {
        stream_answer(client, upstream, &mut body, redirect).await?;
    } else {
        whole_answer(client, upstream, &mut body, status, redirect).await?;
    }
    client.shutdown().await.ok();
    Ok(())
}

/// Translate a whole answer and send it with its length.
async fn whole_answer<C, U>(
    client: &mut C,
    upstream: &mut U,
    body: &mut ResponseBody,
    status: u16,
    redirect: &Redirect,
) -> Result<(), Failure>
where
    C: AsyncWrite + Unpin,
    U: AsyncRead + Unpin,
{
    let mut raw = Vec::new();
    while let Some(part) = body.next(upstream).await? {
        if raw.len() + part.len() > MAX_LLM_BODY_BYTES {
            return Err("llm backend answer exceeds the translation limit".into());
        }
        raw.extend_from_slice(&part);
    }

    // An empty or unreadable body is null, and [`translate::response`] decides
    // what to make of it: a refusal the status alone writes, or — where the
    // status promised a completion — no answer at all.
    let parsed = serde_json::from_slice(&raw).unwrap_or(serde_json::Value::Null);
    let translated = translate::response(redirect.translation, &parsed, status)?;
    let payload = serde_json::to_vec(&translated)?;

    client
        .write_all(
            format!(
                "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n",
                reason_phrase(status),
                payload.len(),
            )
            .as_bytes(),
        )
        .await?;
    client.write_all(&payload).await?;
    Ok(())
}

/// Translate a streamed answer event by event, sending each as it arrives.
async fn stream_answer<C, U>(
    client: &mut C,
    upstream: &mut U,
    body: &mut ResponseBody,
    redirect: &Redirect,
) -> Result<(), Failure>
where
    C: AsyncWrite + Unpin,
    U: AsyncRead + Unpin,
{
    client
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n\
              Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        )
        .await?;

    // Once the head has gone out the sandbox is reading a message, and it is owed
    // the end of one. So neither a backend that dies mid-stream nor a frame this
    // proxy cannot read aborts here: both stop the loop, and the message is
    // closed and the body terminated on the way out.
    let mut translator = StreamTranslator::new(redirect.translation);
    loop {
        let Ok(Some(part)) = body.next(upstream).await else {
            break;
        };
        let Ok(events) = translator.push(&part) else {
            break;
        };
        write_chunk(client, &events).await?;
    }
    let tail = translator.finish();
    write_chunk(client, &tail).await?;
    client.write_all(b"0\r\n\r\n").await?;
    Ok(())
}

/// Write one chunked-encoding chunk, or nothing when there is nothing to say.
///
/// A zero-length chunk is the end-of-body marker, so an empty translation must
/// never be written as one.
async fn write_chunk<C>(client: &mut C, payload: &[u8]) -> Result<(), Failure>
where
    C: AsyncWrite + Unpin,
{
    if payload.is_empty() {
        return Ok(());
    }
    client
        .write_all(format!("{:x}\r\n", payload.len()).as_bytes())
        .await?;
    client.write_all(payload).await?;
    client.write_all(b"\r\n").await?;
    Ok(())
}

/// The status code of a response head.
fn parse_status(head: &str) -> Option<u16> {
    head.split_whitespace().nth(1)?.parse().ok()
}

/// A reason phrase for the statuses a backend realistically answers with. The
/// phrase is decoration — clients read the code — so anything else is named for
/// its class.
fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ if status < 300 => "OK",
        _ if status < 400 => "Redirect",
        _ if status < 500 => "Client Error",
        _ => "Server Error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_schema::{LlmFormat, LlmTranslation};

    fn redirect(streaming: bool) -> Redirect {
        Redirect {
            host: "vllm.internal".to_string(),
            port: 443,
            path: "/v1/chat/completions".to_string(),
            body: Vec::new(),
            streaming,
            translation: LlmTranslation {
                from: LlmFormat::AnthropicMessages,
                to: LlmFormat::OpenaiChat,
            },
            model: "qwen3".to_string(),
        }
    }

    /// Run one backend answer through the relay and read back what the sandbox
    /// would see.
    async fn relayed(answer: &str, streaming: bool) -> String {
        let mut upstream = std::io::Cursor::new(answer.as_bytes().to_vec());
        let mut client = Vec::new();
        forward_translated(&mut client, &mut upstream, &redirect(streaming))
            .await
            .expect("answer relays");
        String::from_utf8(client).expect("answer is UTF-8")
    }

    /// Split a written response into its head and its body.
    fn split(response: &str) -> (&str, &str) {
        response.split_once("\r\n\r\n").expect("head ends")
    }

    /// A backend answer framed by its length.
    fn fixed_answer(status_line: &str, content_type: &str, body: &str) -> String {
        format!(
            "{status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    /// A backend answer framed in chunks, one chunk per part.
    fn chunked_answer(content_type: &str, parts: &[&str]) -> String {
        let mut out = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nTransfer-Encoding: chunked\r\n\r\n"
        );
        for part in parts {
            out.push_str(&format!("{:x}\r\n{part}\r\n", part.len()));
        }
        out.push_str("0\r\n\r\n");
        out
    }

    #[tokio::test]
    async fn a_whole_answer_is_translated_and_measured() {
        let answer = fixed_answer(
            "HTTP/1.1 200 OK",
            "application/json",
            r#"{"id":"chatcmpl-1","model":"qwen3","choices":[{"finish_reason":"stop","message":{"content":"hello"}}]}"#,
        );
        let out = relayed(&answer, false).await;
        let (head, body) = split(&out);
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        assert!(head.contains("Content-Type: application/json"));
        assert!(head.contains(&format!("Content-Length: {}", body.len())));
        assert!(head.contains("Connection: close"));

        let parsed: serde_json::Value = serde_json::from_str(body).expect("body is JSON");
        assert_eq!(parsed["type"], "message");
        assert_eq!(parsed["content"][0]["text"], "hello");
    }

    #[tokio::test]
    async fn a_chunked_answer_is_read_through_its_framing() {
        let answer = chunked_answer(
            "application/json",
            &[
                r#"{"choices":[{"message":{"cont"#,
                r#"ent":"hi"},"finish_reason":"#,
                r#""stop"}]}"#,
            ],
        );
        let out = relayed(&answer, false).await;
        let (_, body) = split(&out);
        let parsed: serde_json::Value = serde_json::from_str(body).expect("body is JSON");
        assert_eq!(parsed["content"][0]["text"], "hi");
    }

    #[tokio::test]
    async fn an_answer_that_ends_with_the_connection_is_read_whole() {
        let answer = concat!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n",
            r#"{"choices":[{"message":{"content":"hi"},"finish_reason":"stop"}]}"#,
        );
        let out = relayed(answer, false).await;
        let (_, body) = split(&out);
        let parsed: serde_json::Value = serde_json::from_str(body).expect("body is JSON");
        assert_eq!(parsed["content"][0]["text"], "hi");
    }

    #[tokio::test]
    async fn a_refusal_reaches_the_sandbox_in_its_own_language() {
        let answer = fixed_answer(
            "HTTP/1.1 429 Too Many Requests",
            "application/json",
            r#"{"error":{"message":"slow down"}}"#,
        );
        let out = relayed(&answer, false).await;
        let (head, body) = split(&out);
        assert!(
            head.starts_with("HTTP/1.1 429 Too Many Requests\r\n"),
            "{head}"
        );
        let parsed: serde_json::Value = serde_json::from_str(body).expect("body is JSON");
        assert_eq!(parsed["type"], "error");
        assert_eq!(parsed["error"]["type"], "rate_limit_error");
        assert_eq!(parsed["error"]["message"], "slow down");
    }

    #[tokio::test]
    async fn a_refusal_takes_the_whole_answer_path_even_on_a_streamed_request() {
        // An error is not a stream, whatever the request asked for.
        let answer = fixed_answer(
            "HTTP/1.1 401 Unauthorized",
            "application/json",
            r#"{"error":{"message":"no key"}}"#,
        );
        let out = relayed(&answer, true).await;
        let (head, body) = split(&out);
        assert!(head.starts_with("HTTP/1.1 401 Unauthorized\r\n"), "{head}");
        assert!(head.contains("Content-Type: application/json"), "{head}");
        assert!(!head.contains("text/event-stream"), "{head}");
        let parsed: serde_json::Value = serde_json::from_str(body).expect("body is JSON");
        assert_eq!(parsed["error"]["type"], "authentication_error");
    }

    #[tokio::test]
    async fn a_refusal_with_an_unreadable_body_still_answers() {
        let answer = fixed_answer("HTTP/1.1 502 Bad Gateway", "text/html", "<html>nope</html>");
        let out = relayed(&answer, false).await;
        let (head, body) = split(&out);
        assert!(head.starts_with("HTTP/1.1 502 Bad Gateway\r\n"), "{head}");
        let parsed: serde_json::Value = serde_json::from_str(body).expect("body is JSON");
        assert_eq!(parsed["type"], "error");
        assert_eq!(parsed["error"]["type"], "api_error");
    }

    #[tokio::test]
    async fn a_streamed_answer_arrives_as_chunked_anthropic_events() {
        let answer = chunked_answer(
            "text/event-stream",
            &[
                concat!(
                    r#"data: {"id":"c","model":"qwen3","choices":[{"delta":{"content":"hi"}}]}"#,
                    "\n\n"
                ),
                "data: [DONE]\n\n",
            ],
        );
        let out = relayed(&answer, true).await;
        let (head, body) = split(&out);
        assert!(head.contains("Content-Type: text/event-stream"), "{head}");
        assert!(head.contains("Transfer-Encoding: chunked"), "{head}");
        assert!(body.ends_with("0\r\n\r\n"), "the body must be terminated");

        let events = dechunk(body);
        assert!(events.contains("event: message_start"), "{events}");
        assert!(events.contains("event: content_block_delta"), "{events}");
        assert!(events.contains(r#""text":"hi""#), "{events}");
        assert!(events.contains("event: message_stop"), "{events}");
    }

    #[tokio::test]
    async fn a_stream_the_backend_abandons_is_still_ended() {
        // The head promises a stream and the body stops mid-event. The sandbox
        // is owed the end of the message it was reading.
        let answer = concat!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n",
            r#"data: {"id":"c","choices":[{"delta":{"content":"half"}}]}"#,
            "\n\n",
        );
        let out = relayed(answer, true).await;
        let (_, body) = split(&out);
        let events = dechunk(body);
        assert!(events.contains("event: message_stop"), "{events}");
        assert!(body.ends_with("0\r\n\r\n"));
    }

    #[tokio::test]
    async fn a_redirect_on_a_streamed_request_is_not_dressed_up_as_a_stream() {
        // A backend URL that earned a 301 from a stray slash would otherwise
        // reach the sandbox as `200 OK` with an empty event stream — a call that
        // never happened, reported as a success.
        let answer = fixed_answer("HTTP/1.1 301 Moved Permanently", "text/html", "");
        let out = relayed(&answer, true).await;
        let (head, body) = split(&out);
        assert!(head.starts_with("HTTP/1.1 301 "), "{head}");
        assert!(!head.contains("text/event-stream"), "{head}");
        let parsed: serde_json::Value = serde_json::from_str(body).expect("body is JSON");
        assert_eq!(parsed["type"], "error");
    }

    #[tokio::test]
    async fn a_stream_carrying_a_frame_the_proxy_cannot_read_is_still_ended() {
        let answer = concat!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n",
            r#"data: {"id":"c","choices":[{"delta":{"content":"half"}}]}"#,
            "\n\ndata: {not json}\n\n",
        );
        let out = relayed(answer, true).await;
        let (_, body) = split(&out);
        assert!(body.ends_with("0\r\n\r\n"), "the body must be terminated");
        let events = dechunk(body);
        assert!(events.contains("event: message_stop"), "{events}");
    }

    #[tokio::test]
    async fn a_malformed_status_line_refuses_the_answer() {
        let mut upstream = std::io::Cursor::new(b"not-http\r\n\r\n".to_vec());
        let mut client = Vec::new();
        assert!(
            forward_translated(&mut client, &mut upstream, &redirect(false))
                .await
                .is_err()
        );
    }

    /// Decode a chunked body back into the bytes it carries.
    fn dechunk(body: &str) -> String {
        let mut out = String::new();
        let mut rest = body;
        loop {
            let (size_line, tail) = rest.split_once("\r\n").expect("chunk size line");
            let size = usize::from_str_radix(size_line.trim(), 16).expect("chunk size");
            if size == 0 {
                return out;
            }
            out.push_str(&tail[..size]);
            rest = &tail[size + 2..];
        }
    }
}
