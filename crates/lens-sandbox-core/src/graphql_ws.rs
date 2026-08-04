//! GraphQL over WebSocket: judge every operation a client sends on an upgraded
//! connection.
//!
//! A GraphQL rule on a plain request reads the body once and decides once. An
//! upgraded connection has no second request head: the client sends operations
//! as WebSocket frames for as long as the socket lives. So the same rules judge
//! each frame here, and a frame is forwarded only after it has passed.
//!
//! What cannot be read is refused, in keeping with the rest of the policy:
//! a compressed frame (the handshake strips the offer, so a compressed frame
//! means upstream ignored it), a binary frame, a text message above
//! [`MAX_TEXT_MESSAGE_BYTES`], a message that is not the graphql-ws envelope,
//! and any framing the protocol does not allow.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::policy_schema::GraphqlMatcher;

/// The largest client text message the proxy will hold to read an operation.
/// A GraphQL document above this is refused, not passed unread.
pub(crate) const MAX_TEXT_MESSAGE_BYTES: usize = 64 * 1024;

/// Frames one message may be split across. This bounds what is held for a
/// message that is still arriving, which the byte limit above cannot: an empty
/// fragment carries no payload but still carries its framing. A client that
/// needs more than this to state one operation is not one the proxy can read.
const MAX_MESSAGE_FRAMES: usize = 64;

const OPCODE_CONTINUATION: u8 = 0x0;
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xA;

/// A server-side close frame carrying 1008 Policy Violation (RFC 6455 §7.4.1).
const POLICY_CLOSE_FRAME: &[u8] = &[0x88, 0x02, 0x03, 0xF0];

/// One client frame, as received and as read.
struct Frame {
    fin: bool,
    rsv: u8,
    opcode: u8,
    masked: bool,
    /// The frame exactly as it arrived, ready to forward unchanged.
    raw: Vec<u8>,
    /// The payload with the client's mask removed.
    payload: Vec<u8>,
}

/// Relay an upgraded connection, judging every operation the client sends.
///
/// Returns the reason a client message was refused, or `None` when a side simply
/// closed the connection. Server frames are relayed unread: policy binds what
/// the sandbox asks for, and the answer is the origin's to give.
pub(crate) async fn relay<C, U>(
    client: &mut C,
    upstream: &mut U,
    matchers: &[&GraphqlMatcher],
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

    let client_to_upstream = police_client_frames(&mut client_read, &mut upstream_write, matchers);
    let upstream_to_client = async {
        tokio::io::copy(&mut upstream_read, &mut client_write).await?;
        Ok::<Option<String>, Box<dyn std::error::Error + Send + Sync>>(None)
    };

    let denial = tokio::select! {
        end = client_to_upstream => end?,
        end = upstream_to_client => end?,
    };

    // A denied frame gets the client a reason it can read, then the socket goes.
    if denial.is_some() {
        let _ = client_write.write_all(POLICY_CLOSE_FRAME).await;
    }
    let _ = client_write.shutdown().await;
    let _ = upstream_write.shutdown().await;
    Ok(denial)
}

/// Read client frames, judge each complete text message, and forward what
/// passes.
///
/// A fragmented message is held until its last frame arrives, because half an
/// operation cannot be judged.
async fn police_client_frames<R, W>(
    reader: &mut R,
    writer: &mut W,
    matchers: &[&GraphqlMatcher],
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut fragmenting = false;
    let mut held_raw: Vec<u8> = Vec::new();
    let mut held_text: Vec<u8> = Vec::new();
    let mut held_frames = 0usize;
    let mut close_seen = false;

    loop {
        let Some(frame) = read_frame(reader).await? else {
            return Ok(None);
        };
        if close_seen {
            return Ok(Some(
                "client sent a WebSocket frame after its close frame".to_string(),
            ));
        }
        if let Err(reason) = validate(&frame, fragmenting) {
            return Ok(Some(reason));
        }

        match frame.opcode {
            OPCODE_TEXT | OPCODE_CONTINUATION => {
                if held_text.len() + frame.payload.len() > MAX_TEXT_MESSAGE_BYTES {
                    return Ok(Some(format!(
                        "a client WebSocket message above {MAX_TEXT_MESSAGE_BYTES} bytes cannot be read"
                    )));
                }
                // The payload bound alone does not bound what is held: an empty
                // fragment adds no payload but still adds its framing, so a
                // stream of them would grow `held_raw` without end.
                held_frames += 1;
                if held_frames > MAX_MESSAGE_FRAMES {
                    return Ok(Some(format!(
                        "a client WebSocket message split across more than {MAX_MESSAGE_FRAMES} frames cannot be read"
                    )));
                }
                held_text.extend_from_slice(&frame.payload);
                held_raw.extend_from_slice(&frame.raw);
                if !frame.fin {
                    fragmenting = true;
                    continue;
                }
                fragmenting = false;
                held_frames = 0;

                let judged = match std::str::from_utf8(&held_text) {
                    Ok(text) => judge_message(text, matchers),
                    Err(_) => Err("a client WebSocket text message is not valid UTF-8".to_string()),
                };
                if let Err(reason) = judged {
                    return Ok(Some(reason));
                }
                writer.write_all(&held_raw).await?;
                writer.flush().await?;
                held_raw.clear();
                held_text.clear();
            }
            // A control frame carries no operation, so it goes on unjudged.
            _ => {
                close_seen = frame.opcode == OPCODE_CLOSE;
                writer.write_all(&frame.raw).await?;
                writer.flush().await?;
            }
        }
    }
}

/// Judge one graphql-ws message.
///
/// Both protocol revisions are covered: `subscribe` of graphql-transport-ws and
/// `start` of the older graphql-ws carry an operation. A message this does not
/// recognise is refused rather than forwarded, because an unknown type may
/// carry an operation in a shape the rules cannot read.
fn judge_message(text: &str, matchers: &[&GraphqlMatcher]) -> Result<(), String> {
    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|err| format!("a client WebSocket message is not valid JSON: {err}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "a client WebSocket message must be a JSON object".to_string())?;
    let message_type = object
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "a client WebSocket message carries no type".to_string())?;

    match message_type {
        "subscribe" | "start" => {
            let payload = object
                .get("payload")
                .filter(|payload| payload.is_object())
                .ok_or_else(|| {
                    format!("a GraphQL {message_type} message carries no operation payload")
                })?;
            crate::graphql::check_envelope(payload, matchers)
        }
        "connection_init" | "connection_terminate" | "ping" | "pong" | "complete" | "stop" => {
            Ok(())
        }
        other => Err(format!(
            "a client WebSocket message of type {other:?} is not a GraphQL operation this proxy can read"
        )),
    }
}

/// Read one frame, or `None` when the client has gone.
///
/// A client that stops mid-frame reads as gone rather than as an error: nothing
/// of a half-read frame is ever forwarded, so there is nothing to report.
async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Frame>, Box<dyn std::error::Error + Send + Sync>> {
    let mut head = [0u8; 2];
    if !read_exact_or_eof(reader, &mut head).await? {
        return Ok(None);
    }

    let mut raw = head.to_vec();
    let payload_len = match head[1] & 0x7F {
        len @ 0..=125 => u64::from(len),
        126 => {
            let mut bytes = [0u8; 2];
            if !read_exact_or_eof(reader, &mut bytes).await? {
                return Ok(None);
            }
            raw.extend_from_slice(&bytes);
            u64::from(u16::from_be_bytes(bytes))
        }
        _ => {
            let mut bytes = [0u8; 8];
            if !read_exact_or_eof(reader, &mut bytes).await? {
                return Ok(None);
            }
            raw.extend_from_slice(&bytes);
            u64::from_be_bytes(bytes)
        }
    };

    let masked = head[1] & 0x80 != 0;
    let mut mask = [0u8; 4];
    if masked {
        if !read_exact_or_eof(reader, &mut mask).await? {
            return Ok(None);
        }
        raw.extend_from_slice(&mask);
    }

    // Read no further than the proxy can hold, and stop one byte over the limit
    // so the frame reads as oversized. Every arm of `validate` then refuses it —
    // a control frame on its 125-byte bound, a text or continuation frame on the
    // length check, a binary frame and a reserved opcode outright — so a frame
    // this leaves half-read is never followed by another read of this stream.
    let payload_len = usize::try_from(payload_len).unwrap_or(usize::MAX);
    let mut payload = vec![0u8; payload_len.min(MAX_TEXT_MESSAGE_BYTES + 1)];
    if !read_exact_or_eof(reader, &mut payload).await? {
        return Ok(None);
    }
    raw.extend_from_slice(&payload);
    if masked {
        unmask(&mut payload, mask);
    }

    Ok(Some(Frame {
        fin: head[0] & 0x80 != 0,
        rsv: head[0] & 0x70,
        opcode: head[0] & 0x0F,
        masked,
        raw,
        payload,
    }))
}

/// Fill `buf`, or report `false` when the client closed instead.
async fn read_exact_or_eof<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    match reader.read_exact(buf).await {
        Ok(_) => Ok(true),
        Err(e) if is_disconnect(&e) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Whether a frame is one this proxy may relay at this point in the stream.
fn validate(frame: &Frame, fragmenting: bool) -> Result<(), String> {
    if !frame.masked {
        return Err("a client WebSocket frame must be masked".to_string());
    }
    if frame.rsv != 0 {
        return Err("a client WebSocket frame uses an extension the proxy cannot read".to_string());
    }
    match frame.opcode {
        OPCODE_CLOSE | OPCODE_PING | OPCODE_PONG => {
            if !frame.fin || frame.payload.len() > 125 {
                return Err("a client WebSocket control frame breaks its framing".to_string());
            }
        }
        OPCODE_TEXT => {
            if fragmenting {
                return Err(
                    "a client WebSocket message began before the last one finished".to_string(),
                );
            }
        }
        OPCODE_CONTINUATION => {
            if !fragmenting {
                return Err("a client WebSocket continuation frame continues nothing".to_string());
            }
        }
        OPCODE_BINARY => {
            return Err(
                "a GraphQL WebSocket carries text messages, so a binary frame cannot be read"
                    .to_string(),
            );
        }
        other => {
            return Err(format!(
                "a client WebSocket frame uses reserved opcode {other:#x}"
            ));
        }
    }
    if frame.payload.len() > MAX_TEXT_MESSAGE_BYTES {
        return Err(format!(
            "a client WebSocket frame above {MAX_TEXT_MESSAGE_BYTES} bytes cannot be read"
        ));
    }
    Ok(())
}

fn unmask(payload: &mut [u8], mask: [u8; 4]) {
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
}

fn is_disconnect(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
    )
}

/// Drop the client's extension offer from an upgrade request.
///
/// A compressed frame hides the operation, so the offer never reaches upstream
/// and the frames stay readable. Extensions are optional to a WebSocket client
/// (RFC 6455 §9.1), so removing the offer costs the client nothing but
/// compression.
///
/// An obsolete folded line (RFC 9110 §5.2) below the offer goes with it, or it
/// would fold onto the header above and carry the offer through anyway.
pub(crate) fn strip_extension_offer(head: &str) -> String {
    let mut dropping = false;
    head.split("\r\n")
        .filter(|line| {
            if line.starts_with(' ') || line.starts_with('\t') {
                return !dropping;
            }
            dropping = line
                .to_ascii_lowercase()
                .starts_with("sec-websocket-extensions:");
            !dropping
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// Whether a `101` answer negotiated an extension, which after
/// [`strip_extension_offer`] means upstream answered an offer nobody made.
pub(crate) fn answer_negotiates_extension(head: &[u8]) -> bool {
    String::from_utf8_lossy(head).split("\r\n").any(|line| {
        line.to_ascii_lowercase()
            .strip_prefix("sec-websocket-extensions:")
            .is_some_and(|value| !value.trim().is_empty())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_schema::{GraphqlMatcher, GraphqlOperationTypeMatcher};

    fn subscription_rule() -> GraphqlMatcher {
        GraphqlMatcher {
            operation_type: GraphqlOperationTypeMatcher::Subscription,
            operation_name: None,
            fields: vec!["messageAdded".to_string()],
        }
    }

    fn judge(text: &str) -> Result<(), String> {
        let rule = subscription_rule();
        judge_message(text, &[&rule])
    }

    /// One masked client frame carrying `text`.
    fn client_text_frame(text: &str) -> Vec<u8> {
        masked_frame(OPCODE_TEXT, true, text.as_bytes())
    }

    fn masked_frame(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
        let mask = [0xA1, 0xB2, 0xC3, 0xD4];
        let mut frame = vec![if fin { 0x80 | opcode } else { opcode }];
        assert!(payload.len() < 126, "test frames stay in the short form");
        frame.push(0x80 | payload.len() as u8);
        frame.extend_from_slice(&mask);
        let mut masked = payload.to_vec();
        unmask(&mut masked, mask);
        frame.extend_from_slice(&masked);
        frame
    }

    #[test]
    fn a_permitted_subscription_passes() {
        let message = r#"{"id":"1","type":"subscribe","payload":{"query":"subscription S { messageAdded { id } }"}}"#;
        assert_eq!(judge(message), Ok(()));
    }

    #[test]
    fn the_older_start_message_carries_an_operation_too() {
        let message = r#"{"id":"1","type":"start","payload":{"query":"subscription S { messageAdded { id } }"}}"#;
        assert_eq!(judge(message), Ok(()));
    }

    #[test]
    fn a_field_no_rule_names_is_refused() {
        let message = r#"{"id":"1","type":"subscribe","payload":{"query":"subscription S { auditLog { id } }"}}"#;
        let reason = judge(message).expect_err("auditLog is not permitted");
        assert!(reason.contains("no rule permits"), "{reason}");
    }

    #[test]
    fn a_mutation_smuggled_through_the_socket_is_refused() {
        // The rule covers subscriptions. The same socket carries queries and
        // mutations in graphql-ws, so the type has to be judged here too.
        let message = r#"{"id":"1","type":"subscribe","payload":{"query":"mutation M { messageAdded { id } }"}}"#;
        let reason = judge(message).expect_err("a mutation is not a subscription");
        assert!(reason.contains("no rule permits"), "{reason}");
    }

    #[test]
    fn control_messages_pass_unjudged() {
        for message_type in [
            "connection_init",
            "connection_terminate",
            "ping",
            "pong",
            "complete",
            "stop",
        ] {
            let message = format!(r#"{{"type":"{message_type}"}}"#);
            assert_eq!(judge(&message), Ok(()), "{message_type} must pass");
        }
    }

    #[test]
    fn an_unknown_message_type_is_refused() {
        let reason = judge(r#"{"type":"execute","payload":{}}"#)
            .expect_err("an unknown type may hide an operation");
        assert!(reason.contains("execute"), "{reason}");
    }

    #[test]
    fn a_subscribe_without_a_payload_is_refused() {
        let reason =
            judge(r#"{"id":"1","type":"subscribe"}"#).expect_err("there is no operation to judge");
        assert!(reason.contains("no operation payload"), "{reason}");
    }

    #[test]
    fn a_message_that_is_not_json_is_refused() {
        assert!(judge("not json").is_err());
        assert!(judge("[]").is_err());
    }

    #[tokio::test]
    async fn a_permitted_frame_reaches_upstream_unchanged() {
        let (mut client, client_near) = tokio::io::duplex(4096);
        let (mut upstream, upstream_near) = tokio::io::duplex(4096);
        let frame = client_text_frame(
            r#"{"id":"1","type":"subscribe","payload":{"query":"subscription S { messageAdded { id } }"}}"#,
        );

        let expected = frame.clone();
        let task = tokio::spawn(async move {
            let mut client_near = client_near;
            let mut upstream_near = upstream_near;
            let rule = subscription_rule();
            relay(&mut client_near, &mut upstream_near, &[&rule]).await
        });

        client.write_all(&frame).await.unwrap();
        let mut seen = vec![0u8; expected.len()];
        upstream.read_exact(&mut seen).await.unwrap();
        assert_eq!(seen, expected, "the frame must arrive byte for byte");

        drop(client);
        assert_eq!(task.await.unwrap().unwrap(), None);
    }

    #[tokio::test]
    async fn a_refused_frame_never_reaches_upstream() {
        let (mut client, client_near) = tokio::io::duplex(4096);
        let (mut upstream, upstream_near) = tokio::io::duplex(4096);
        let frame = client_text_frame(
            r#"{"id":"1","type":"subscribe","payload":{"query":"subscription S { auditLog { id } }"}}"#,
        );

        let task = tokio::spawn(async move {
            let mut client_near = client_near;
            let mut upstream_near = upstream_near;
            let rule = subscription_rule();
            relay(&mut client_near, &mut upstream_near, &[&rule]).await
        });

        client.write_all(&frame).await.unwrap();

        let reason = task.await.unwrap().unwrap().expect("expected a denial");
        assert!(reason.contains("no rule permits"), "{reason}");

        // Upstream saw nothing, and the client was told why.
        let mut seen = Vec::new();
        upstream.read_to_end(&mut seen).await.unwrap();
        assert!(
            seen.is_empty(),
            "upstream must see no denied frame: {seen:?}"
        );
        let mut close = Vec::new();
        client.read_to_end(&mut close).await.unwrap();
        assert_eq!(close, POLICY_CLOSE_FRAME);
    }

    #[tokio::test]
    async fn a_fragmented_message_is_judged_whole() {
        let (mut client, client_near) = tokio::io::duplex(4096);
        let (mut upstream, upstream_near) = tokio::io::duplex(4096);
        // Split so that neither half is a readable operation on its own.
        let first = masked_frame(
            OPCODE_TEXT,
            false,
            br#"{"id":"1","type":"subscribe","payload":{"query":"#,
        );
        let second = masked_frame(
            OPCODE_CONTINUATION,
            true,
            br#""subscription S { auditLog { id } }"}}"#,
        );

        let task = tokio::spawn(async move {
            let mut client_near = client_near;
            let mut upstream_near = upstream_near;
            let rule = subscription_rule();
            relay(&mut client_near, &mut upstream_near, &[&rule]).await
        });

        client.write_all(&first).await.unwrap();
        client.write_all(&second).await.unwrap();

        let reason = task.await.unwrap().unwrap().expect("expected a denial");
        assert!(reason.contains("no rule permits"), "{reason}");
        let mut seen = Vec::new();
        upstream.read_to_end(&mut seen).await.unwrap();
        assert!(
            seen.is_empty(),
            "no fragment may go on before the message is judged: {seen:?}"
        );
    }

    #[tokio::test]
    async fn a_binary_frame_is_refused() {
        let (mut client, client_near) = tokio::io::duplex(4096);
        let (_upstream, upstream_near) = tokio::io::duplex(4096);
        let frame = masked_frame(OPCODE_BINARY, true, b"\x00\x01\x02");

        let task = tokio::spawn(async move {
            let mut client_near = client_near;
            let mut upstream_near = upstream_near;
            let rule = subscription_rule();
            relay(&mut client_near, &mut upstream_near, &[&rule]).await
        });

        client.write_all(&frame).await.unwrap();
        let reason = task.await.unwrap().unwrap().expect("expected a denial");
        assert!(reason.contains("binary frame"), "{reason}");
    }

    #[tokio::test]
    async fn a_frame_above_the_limit_is_refused_and_nothing_after_it_is_read() {
        let (mut client, client_near) = tokio::io::duplex(MAX_TEXT_MESSAGE_BYTES * 2);
        let (mut upstream, upstream_near) = tokio::io::duplex(4096);

        // A text frame one byte over what the proxy will hold. The payload is
        // never fully read, so the stream stays out of step from here — the
        // refusal has to end the connection, not resynchronise.
        let payload_len = MAX_TEXT_MESSAGE_BYTES + 1;
        // The 64-bit length form: this length does not fit the 16-bit one.
        let mut frame = vec![0x81, 0xFF];
        frame.extend_from_slice(&(payload_len as u64).to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 0]);
        frame.extend_from_slice(&vec![b'x'; payload_len]);

        let task = tokio::spawn(async move {
            let mut client_near = client_near;
            let mut upstream_near = upstream_near;
            let rule = subscription_rule();
            relay(&mut client_near, &mut upstream_near, &[&rule]).await
        });

        client.write_all(&frame).await.unwrap();
        let reason = task.await.unwrap().unwrap().expect("expected a denial");
        assert!(reason.contains("cannot be read"), "{reason}");
        let mut seen = Vec::new();
        upstream.read_to_end(&mut seen).await.unwrap();
        assert!(
            seen.is_empty(),
            "no part of it may go on: {} bytes",
            seen.len()
        );
    }

    #[tokio::test]
    async fn a_message_split_across_too_many_frames_is_refused() {
        // Empty fragments add no payload, so the byte limit never fires on them.
        // Without a frame limit the proxy would hold their framing for as long as
        // the client cared to send them.
        let (mut client, client_near) = tokio::io::duplex(64 * 1024);
        let (mut upstream, upstream_near) = tokio::io::duplex(4096);

        let task = tokio::spawn(async move {
            let mut client_near = client_near;
            let mut upstream_near = upstream_near;
            let rule = subscription_rule();
            relay(&mut client_near, &mut upstream_near, &[&rule]).await
        });

        client
            .write_all(&masked_frame(OPCODE_TEXT, false, b""))
            .await
            .unwrap();
        for _ in 0..MAX_MESSAGE_FRAMES {
            client
                .write_all(&masked_frame(OPCODE_CONTINUATION, false, b""))
                .await
                .unwrap();
        }

        let reason = task.await.unwrap().unwrap().expect("expected a denial");
        assert!(reason.contains("more than"), "{reason}");
        let mut seen = Vec::new();
        upstream.read_to_end(&mut seen).await.unwrap();
        assert!(seen.is_empty(), "nothing may go on: {} bytes", seen.len());
    }

    #[tokio::test]
    async fn a_message_may_still_arrive_in_several_frames() {
        let (mut client, client_near) = tokio::io::duplex(4096);
        let (mut upstream, upstream_near) = tokio::io::duplex(4096);
        let first = masked_frame(
            OPCODE_TEXT,
            false,
            br#"{"id":"1","type":"subscribe","payload":{"query":"#,
        );
        let second = masked_frame(
            OPCODE_CONTINUATION,
            true,
            br#""subscription S { messageAdded } "}}"#,
        );

        let task = tokio::spawn(async move {
            let mut client_near = client_near;
            let mut upstream_near = upstream_near;
            let rule = subscription_rule();
            relay(&mut client_near, &mut upstream_near, &[&rule]).await
        });

        client.write_all(&first).await.unwrap();
        client.write_all(&second).await.unwrap();

        let mut seen = vec![0u8; first.len() + second.len()];
        upstream.read_exact(&mut seen).await.unwrap();
        assert_eq!(
            seen,
            [first, second].concat(),
            "both fragments go on, once the whole message has passed"
        );
        drop(client);
        assert_eq!(task.await.unwrap().unwrap(), None);
    }

    #[tokio::test]
    async fn a_frame_with_a_reserved_bit_is_refused() {
        let (mut client, client_near) = tokio::io::duplex(4096);
        let (_upstream, upstream_near) = tokio::io::duplex(4096);
        // RSV1 set: what a permessage-deflate frame looks like. The handshake
        // strips the offer, so a client that compresses anyway is refused.
        let mut frame = masked_frame(OPCODE_TEXT, true, b"{}");
        frame[0] |= 0x40;

        let task = tokio::spawn(async move {
            let mut client_near = client_near;
            let mut upstream_near = upstream_near;
            let rule = subscription_rule();
            relay(&mut client_near, &mut upstream_near, &[&rule]).await
        });

        client.write_all(&frame).await.unwrap();
        let reason = task.await.unwrap().unwrap().expect("expected a denial");
        assert!(reason.contains("extension"), "{reason}");
    }

    #[tokio::test]
    async fn an_unmasked_client_frame_is_refused() {
        let (mut client, client_near) = tokio::io::duplex(4096);
        let (_upstream, upstream_near) = tokio::io::duplex(4096);
        // Server framing from a client: no mask bit, no mask key.
        let frame = vec![0x81, 0x02, b'h', b'i'];

        let task = tokio::spawn(async move {
            let mut client_near = client_near;
            let mut upstream_near = upstream_near;
            let rule = subscription_rule();
            relay(&mut client_near, &mut upstream_near, &[&rule]).await
        });

        client.write_all(&frame).await.unwrap();
        let reason = task.await.unwrap().unwrap().expect("expected a denial");
        assert!(reason.contains("masked"), "{reason}");
    }

    #[tokio::test]
    async fn a_server_frame_reaches_the_client_unread() {
        let (mut client, client_near) = tokio::io::duplex(4096);
        let (mut upstream, upstream_near) = tokio::io::duplex(4096);
        // Unmasked, as a server sends, and not a graphql-ws message at all.
        let server_frame = vec![0x81, 0x03, b'a', b'b', b'c'];

        let expected = server_frame.clone();
        let task = tokio::spawn(async move {
            let mut client_near = client_near;
            let mut upstream_near = upstream_near;
            let rule = subscription_rule();
            relay(&mut client_near, &mut upstream_near, &[&rule]).await
        });

        upstream.write_all(&server_frame).await.unwrap();
        let mut seen = vec![0u8; expected.len()];
        client.read_exact(&mut seen).await.unwrap();
        assert_eq!(seen, expected);
        drop(upstream);
        let _ = task.await.unwrap();
    }

    #[test]
    fn the_extension_offer_leaves_the_handshake() {
        let head = "GET /graphql HTTP/1.1\r\nHost: x\r\nSec-WebSocket-Extensions: permessage-deflate\r\nUpgrade: websocket";
        let stripped = strip_extension_offer(head);
        assert!(!stripped.to_ascii_lowercase().contains("permessage-deflate"));
        assert!(stripped.contains("Upgrade: websocket"));
        assert!(stripped.contains("Host: x"));
    }

    #[test]
    fn a_folded_offer_leaves_whole() {
        // The obsolete fold would otherwise join the header above it and carry
        // the offer through.
        let head = "GET /graphql HTTP/1.1\r\nHost: x\r\n\
            Sec-WebSocket-Extensions: permessage-deflate;\r\n client_max_window_bits\r\n\
            Upgrade: websocket";
        let stripped = strip_extension_offer(head);
        assert!(!stripped.contains("client_max_window_bits"), "{stripped}");
        assert!(!stripped.contains("permessage-deflate"), "{stripped}");
        assert!(stripped.contains("Upgrade: websocket"), "{stripped}");
        assert!(stripped.contains("Host: x"), "{stripped}");
    }

    #[test]
    fn an_extension_in_the_answer_is_seen() {
        assert!(answer_negotiates_extension(
            b"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
        ));
        assert!(!answer_negotiates_extension(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
        ));
        // An empty value negotiates nothing.
        assert!(!answer_negotiates_extension(
            b"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Extensions: \r\n\r\n"
        ));
    }
}
