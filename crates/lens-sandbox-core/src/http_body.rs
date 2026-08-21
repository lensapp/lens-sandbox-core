//! HTTP/1.1 body framing: how much of the stream belongs to this message, and
//! how to buffer and re-frame it. Requests are the main subject; a response is
//! framed by [`determine_response_framing`] and read by [`ResponseBody`], for
//! the caller that has to see an answer rather than splice it.
//!
//! Both proxy doors read a request head one byte at a time up to the
//! terminating `\r\n\r\n`, so when policy runs the body is always still on the
//! socket. [`BodyFraming`] says how much of it this request owns, which serves
//! two callers: the relay bounds client→upstream forwarding so a pipelined
//! second request cannot slip past policy, and a rule that matches on the body
//! buffers it with [`read_body`] before deciding.
//!
//! Nothing here reads past the end of the body it was asked for. Framing lines
//! are read a byte at a time and payloads with `read_exact`, so bytes a client
//! pipelined behind the request stay on the socket rather than being swallowed
//! into a buffer this module would later drop.

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest request body buffered for policy inspection.
///
/// A body over the cap is refused rather than truncated: a rule that matches on
/// the body cannot be evaluated against bytes we declined to read, and
/// forwarding an uninspected payload past a rule that asked to see it would
/// fail open.
pub const MAX_INSPECT_BYTES: usize = 64 * 1024;

/// Largest request body buffered to judge an MCP rule.
///
/// Larger than [`MAX_INSPECT_BYTES`] because the bodies differ in kind, not in
/// degree: a GraphQL document is a query, while an MCP request can carry a whole
/// model completion back to the server, sampling results included.
///
/// One kind of body outgrows this cap: a Base64 image is often a megabyte on its
/// own. Such a request is denied, and the denial names the limit. Raise this
/// constant when a real fleet needs the room. It is not a policy field on
/// purpose: how much a door reads before it decides is the door's budget, and an
/// operator who could widen it could make every request cost what they liked.
pub const MAX_JUDGED_BODY_BYTES: usize = 1024 * 1024;

/// Largest message head [`read_head`] will read. A head is metadata; one that
/// keeps growing is a stream that will never reach its blank line.
pub const MAX_HEAD_BYTES: usize = 64 * 1024;

/// Cap on a single chunked framing line (chunk size, or one trailer field).
/// Framing lines are short by construction; the cap stops a stream that never
/// sends its CRLF from growing the buffer without bound.
const MAX_FRAMING_LINE_BYTES: usize = 8192;

/// Cap on trailer fields after the zero-size chunk, so a stream that emits
/// them endlessly cannot hold the connection open.
const MAX_TRAILER_LINES: usize = 64;

/// HTTP/1.1 request body framing, derived from the request method + headers.
/// Used to bound the client→upstream forwarding so a pipelined second request
/// cannot leak through after the first request body ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    /// No body — request method or framing implies an empty payload.
    None,
    /// Body is exactly N bytes (`Content-Length`).
    Fixed(u64),
    /// Body is HTTP/1.1 chunked transfer encoding.
    Chunked,
}

/// HTTP/1.1 *response* body framing. Same three shapes a request has, plus the
/// one only a response can take: a body whose end is the end of the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseFraming {
    /// Body is exactly N bytes (`Content-Length`).
    Fixed(u64),
    /// Body is HTTP/1.1 chunked transfer encoding.
    Chunked,
    /// Body runs until the connection closes.
    UntilClose,
}

/// Reads a response body a piece at a time, whatever its framing.
///
/// Exists for the caller that has to *see* a body rather than splice it, and
/// cannot wait for the end of it to start: a streamed answer is read, rewritten,
/// and passed on while the origin is still sending. Each [`next`](Self::next)
/// call returns the next run of decoded body bytes, and `None` once the body is
/// over. Chunk framing is consumed, never returned.
pub struct ResponseBody {
    framing: ResponseFraming,
    /// Bytes of a `Fixed` body still to come.
    remaining: u64,
    done: bool,
}

/// How much of an unframed or fixed-length body one read asks for.
const READ_CHUNK_BYTES: usize = 16 * 1024;

impl ResponseBody {
    pub fn new(framing: ResponseFraming) -> Self {
        Self {
            framing,
            remaining: match framing {
                ResponseFraming::Fixed(n) => n,
                _ => 0,
            },
            done: false,
        }
    }

    /// The next run of body bytes, or `None` at the end of the body.
    pub async fn next<R>(&mut self, reader: &mut R) -> Result<Option<Vec<u8>>, BodyReadError>
    where
        R: AsyncRead + Unpin,
    {
        if self.done {
            return Ok(None);
        }
        match self.framing {
            ResponseFraming::Fixed(_) => self.next_fixed(reader).await,
            ResponseFraming::Chunked => self.next_chunk(reader).await,
            ResponseFraming::UntilClose => self.next_until_close(reader).await,
        }
    }

    async fn next_fixed<R>(&mut self, reader: &mut R) -> Result<Option<Vec<u8>>, BodyReadError>
    where
        R: AsyncRead + Unpin,
    {
        if self.remaining == 0 {
            self.done = true;
            return Ok(None);
        }
        let want = self.remaining.min(READ_CHUNK_BYTES as u64) as usize;
        let mut buf = vec![0u8; want];
        let read = reader
            .read(&mut buf)
            .await
            .map_err(|_| BodyReadError::Malformed("body ended before Content-Length"))?;
        if read == 0 {
            return Err(BodyReadError::Malformed("body ended before Content-Length"));
        }
        buf.truncate(read);
        self.remaining -= read as u64;
        Ok(Some(buf))
    }

    async fn next_chunk<R>(&mut self, reader: &mut R) -> Result<Option<Vec<u8>>, BodyReadError>
    where
        R: AsyncRead + Unpin,
    {
        let size_line = read_framing_line(reader).await?;
        let size_token = size_line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_token, 16)
            .map_err(|_| BodyReadError::Malformed("invalid chunked body chunk size"))?;

        if size == 0 {
            for _ in 0..MAX_TRAILER_LINES {
                if read_framing_line(reader).await?.is_empty() {
                    self.done = true;
                    return Ok(None);
                }
            }
            return Err(BodyReadError::Malformed("too many chunked body trailers"));
        }

        let mut buf = vec![0u8; size];
        reader
            .read_exact(&mut buf)
            .await
            .map_err(|_| BodyReadError::Malformed("chunked body ended mid-chunk"))?;
        if !read_framing_line(reader).await?.is_empty() {
            return Err(BodyReadError::Malformed(
                "chunked body chunk missing terminating CRLF",
            ));
        }
        Ok(Some(buf))
    }

    async fn next_until_close<R>(
        &mut self,
        reader: &mut R,
    ) -> Result<Option<Vec<u8>>, BodyReadError>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = vec![0u8; READ_CHUNK_BYTES];
        let read = reader
            .read(&mut buf)
            .await
            .map_err(|_| BodyReadError::Malformed("body ended before the connection did"))?;
        if read == 0 {
            self.done = true;
            return Ok(None);
        }
        buf.truncate(read);
        Ok(Some(buf))
    }
}

/// Why a request body could not be buffered for inspection.
///
/// Both variants are policy denials at the call site: a rule asked to see the
/// body and we cannot show it one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyReadError {
    /// The body is larger than the caller's inspection budget, which it carries:
    /// an operator reading a denial needs the number to compare against.
    TooLarge { limit: usize },
    /// The stream ended early, or its chunked framing was malformed.
    Malformed(&'static str),
}

impl BodyReadError {
    /// Stable token for audit metadata.
    pub fn audit_reason(&self) -> &'static str {
        match self {
            Self::TooLarge { .. } => "body-too-large",
            Self::Malformed(_) => "body-malformed",
        }
    }
}

impl std::fmt::Display for BodyReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { limit } => {
                write!(f, "payload exceeds the {limit}-byte read limit")
            }
            Self::Malformed(detail) => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for BodyReadError {}

/// Determine HTTP/1.1 request body framing from the original request head.
///
/// HTTP/1.1 framing rules (RFC 9112 §6.3):
/// 1. If `Transfer-Encoding` is present and ends with `chunked` → chunked.
/// 2. Else if `Content-Length` is a non-negative integer → fixed length.
/// 3. Else there is no body, whatever the method. A server is allowed to reject
///    a `POST` sent that way, but we must not pump bytes of unknown length to
///    upstream where they would outlive our session — so the method is not
///    consulted, and this function does not take one.
pub fn determine_body_framing(header_block: &str) -> BodyFraming {
    match declared_framing(header_block) {
        DeclaredFraming::Chunked => BodyFraming::Chunked,
        DeclaredFraming::Fixed(n) => BodyFraming::Fixed(n),
        DeclaredFraming::Absent => BodyFraming::None,
    }
}

/// Determine HTTP/1.1 *response* body framing from a response head.
///
/// Reads the same two headers as [`determine_body_framing`] and differs in one
/// thing, which is the whole difference between the two directions: a response
/// that declares no framing does not have an empty body, it has a body that
/// ends when the connection does (RFC 9112 §6.3, item 8).
pub fn determine_response_framing(header_block: &str) -> ResponseFraming {
    match declared_framing(header_block) {
        DeclaredFraming::Chunked => ResponseFraming::Chunked,
        DeclaredFraming::Fixed(n) => ResponseFraming::Fixed(n),
        DeclaredFraming::Absent => ResponseFraming::UntilClose,
    }
}

/// What a head's framing headers declare, before either direction's
/// no-framing convention is applied.
enum DeclaredFraming {
    Chunked,
    Fixed(u64),
    Absent,
}

fn declared_framing(header_block: &str) -> DeclaredFraming {
    let mut content_length: Option<u64> = None;
    for line in header_block.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("transfer-encoding:") {
            // Per RFC, the last coding listed is the outer one. If chunked is
            // present anywhere we treat it as chunked — a chunked-with-extras
            // message is rare and the safest thing is to switch to chunk
            // parsing rather than blindly moving bytes by length.
            if rest.contains("chunked") {
                return DeclaredFraming::Chunked;
            }
        } else if let Some(rest) = lower.strip_prefix("content-length:")
            && let Ok(n) = rest.trim().parse::<u64>()
        {
            content_length = Some(n);
        }
    }
    content_length.map_or(DeclaredFraming::Absent, DeclaredFraming::Fixed)
}

/// Read this request's body in full so a policy rule can match on it.
///
/// A chunked body is returned decoded, with its chunk framing and trailers
/// consumed; the caller replays it as one fixed-length unit and restates the
/// head with [`reframe_head_as_content_length`].
pub async fn read_body<R>(
    reader: &mut R,
    framing: BodyFraming,
    max_bytes: usize,
) -> Result<Vec<u8>, BodyReadError>
where
    R: AsyncRead + Unpin,
{
    match framing {
        BodyFraming::None => Ok(Vec::new()),
        BodyFraming::Fixed(len) => {
            // A length that doesn't fit this platform's usize is past any cap
            // we would accept anyway.
            let len =
                usize::try_from(len).map_err(|_| BodyReadError::TooLarge { limit: max_bytes })?;
            if len > max_bytes {
                return Err(BodyReadError::TooLarge { limit: max_bytes });
            }
            let mut body = vec![0u8; len];
            reader
                .read_exact(&mut body)
                .await
                .map_err(|_| BodyReadError::Malformed("body ended before Content-Length"))?;
            Ok(body)
        }
        BodyFraming::Chunked => read_chunked_body(reader, max_bytes).await,
    }
}

/// Decode a chunked body, stopping after the zero-size chunk and its trailers.
async fn read_chunked_body<R>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>, BodyReadError>
where
    R: AsyncRead + Unpin,
{
    let mut decoded: Vec<u8> = Vec::new();
    loop {
        let size_line = read_framing_line(reader).await?;
        // Chunk extensions (`;name=value`) are framing metadata, not payload.
        let size_token = size_line.split(';').next().unwrap_or_default().trim();
        let chunk_size = usize::from_str_radix(size_token, 16)
            .map_err(|_| BodyReadError::Malformed("invalid chunked body chunk size"))?;

        if chunk_size == 0 {
            // Trailers run until a blank line. They describe a framing we are
            // about to discard, so read past them without collecting.
            for _ in 0..MAX_TRAILER_LINES {
                if read_framing_line(reader).await?.is_empty() {
                    return Ok(decoded);
                }
            }
            return Err(BodyReadError::Malformed("too many chunked body trailers"));
        }

        if decoded.len().saturating_add(chunk_size) > max_bytes {
            return Err(BodyReadError::TooLarge { limit: max_bytes });
        }
        let start = decoded.len();
        decoded.resize(start + chunk_size, 0);
        reader
            .read_exact(&mut decoded[start..])
            .await
            .map_err(|_| BodyReadError::Malformed("chunked body ended mid-chunk"))?;

        if !read_framing_line(reader).await?.is_empty() {
            return Err(BodyReadError::Malformed(
                "chunked body chunk missing terminating CRLF",
            ));
        }
    }
}

/// Read one CRLF-terminated framing line, returning it without the CRLF.
async fn read_framing_line<R>(reader: &mut R) -> Result<String, BodyReadError>
where
    R: AsyncRead + Unpin,
{
    let mut line = read_crlf_line(reader).await?;
    line.truncate(line.len() - 2);
    String::from_utf8(line)
        .map_err(|_| BodyReadError::Malformed("invalid UTF-8 in chunked body framing"))
}

/// Read one CRLF-terminated line, returning it *with* the terminator, so a
/// caller relaying framing verbatim can write back exactly what it read.
///
/// Reads a byte at a time so that neither a payload nor a pipelined second
/// request is consumed along with the line.
pub async fn read_crlf_line<R>(reader: &mut R) -> Result<Vec<u8>, BodyReadError>
where
    R: AsyncRead + Unpin,
{
    let mut line: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = reader
            .read(&mut byte)
            .await
            .map_err(|_| BodyReadError::Malformed("stream ended before the end of a line"))?;
        if read == 0 {
            return Err(BodyReadError::Malformed(
                "stream ended before the end of a line",
            ));
        }
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
        if line.len() > MAX_FRAMING_LINE_BYTES {
            return Err(BodyReadError::TooLarge {
                limit: MAX_FRAMING_LINE_BYTES,
            });
        }
    }
}

/// Tell a client that said `Expect: 100-continue` to send its body.
///
/// Every door that reads a request body itself has to do this, and only those
/// do. A door that forwards the body leaves the answer to the origin server; a
/// door that reads the body has taken the origin's place, and until it replies
/// the client holds the body back while the door waits for one that never comes.
///
/// Clients must accept more than one 1xx, so a later `100 Continue` forwarded
/// from upstream does no harm.
pub async fn answer_continue_if_expected<W>(
    client: &mut W,
    header_block: &str,
) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    if !expects_continue(header_block) {
        return Ok(());
    }
    client
        .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
        .await
        .map_err(|err| format!("could not answer Expect: 100-continue: {err}"))
}

/// Whether a request head asks the proxy to confirm before the body is sent.
fn expects_continue(header_block: &str) -> bool {
    header_block.split("\r\n").skip(1).any(|line| {
        let lower = line.to_ascii_lowercase();
        lower
            .strip_prefix("expect:")
            .is_some_and(|value| value.trim() == "100-continue")
    })
}

/// Read a message head, up to and including the blank line that ends it.
///
/// Reads a byte at a time for the same reason every other reader here does: the
/// body must still be on the socket when policy runs.
pub async fn read_head<R>(reader: &mut R) -> Result<Vec<u8>, BodyReadError>
where
    R: AsyncRead + Unpin,
{
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        let read = reader
            .read(&mut byte)
            .await
            .map_err(|_| BodyReadError::Malformed("stream ended before the end of the head"))?;
        if read == 0 {
            return Err(BodyReadError::Malformed(
                "stream ended before the end of the head",
            ));
        }
        head.push(byte[0]);
        if head.len() >= 4 && head[head.len() - 4..] == *b"\r\n\r\n" {
            return Ok(head);
        }
        if head.len() > MAX_HEAD_BYTES {
            return Err(BodyReadError::TooLarge {
                limit: MAX_HEAD_BYTES,
            });
        }
    }
}

/// Restate a request head so its framing describes a body replayed as one
/// fixed-length unit.
///
/// Drops `Transfer-Encoding`, `Content-Length`, and `Trailer`, then appends a
/// single `Content-Length`. Leaving the original framing in place beside the
/// new one is what request smuggling is made of, so all three go.
///
/// `Expect` goes with them. The body is in hand, which means the proxy already
/// answered the client's `100-continue`; carrying the ask upstream would earn a
/// second answer for a body that is on its way.
///
/// `head` is CRLF-joined and carries no trailing blank line, matching what both
/// doors hand to upstream.
pub fn reframe_head_as_content_length(head: &str, body_len: usize) -> String {
    let head = head.trim_end_matches("\r\n");
    let mut out = String::with_capacity(head.len() + 32);
    for (idx, line) in head.split("\r\n").enumerate() {
        // The request line has no field name to inspect.
        if idx > 0 {
            let name = line
                .split_once(':')
                .map(|(name, _)| name.trim().to_ascii_lowercase());
            if matches!(
                name.as_deref(),
                Some("transfer-encoding" | "content-length" | "trailer" | "expect")
            ) {
                continue;
            }
            out.push_str("\r\n");
        }
        out.push_str(line);
    }
    out.push_str("\r\nContent-Length: ");
    out.push_str(&body_len.to_string());
    out
}

/// Confirm that a request head does not hide its body from inspection.
///
/// A body the proxy cannot read is a body a rule cannot judge, so a coding it
/// does not undo and a format it does not split are refused rather than passed
/// on unread.
pub fn ensure_body_is_readable(header_block: &str) -> Result<(), String> {
    for line in header_block.split("\r\n").skip(1) {
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("content-encoding:") {
            let coding = value.trim();
            if !coding.is_empty() && coding != "identity" {
                return Err(format!(
                    "request body uses content-encoding {coding}, which the proxy does not decode"
                ));
            }
        }
        if let Some(value) = lower.strip_prefix("content-type:")
            && value.trim_start().starts_with("multipart/")
        {
            return Err("a multipart request body is not inspected".to_string());
        }
    }
    Ok(())
}

/// Parse a JSON body, refusing a duplicate object key at any depth.
///
/// `serde_json` keeps the last of two same-named keys without complaint, and a
/// server may keep the first. That difference is the proxy-reads-one,
/// server-runs-the-other gap that every body rule exists to close, so a repeated
/// key fails the request instead. Trailing content after the value is refused
/// for the same reason: two documents in one body are two accounts of the
/// request.
pub fn parse_json_strict(body: &[u8]) -> Result<serde_json::Value, String> {
    let mut de = serde_json::Deserializer::from_slice(body);
    let value = StrictValue::deserialize_from(&mut de).map_err(|err| err.to_string())?;
    de.end().map_err(|err| err.to_string())?;
    Ok(value)
}

/// The visitor behind [`parse_json_strict`].
struct StrictValue;

impl StrictValue {
    fn deserialize_from<'de, D: Deserializer<'de>>(de: D) -> Result<Value, D::Error> {
        de.deserialize_any(StrictValue)
    }
}

impl<'de> Visitor<'de> for StrictValue {
    type Value = Value;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("any JSON value with no repeated object key")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, de: D) -> Result<Value, D::Error> {
        Self::deserialize_from(de)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Ok(serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_string()))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(StrictSeed)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value_seed(StrictSeed)?;
            if object.insert(key.clone(), value).is_some() {
                return Err(de::Error::custom(format!("duplicate key \"{key}\"")));
            }
        }
        Ok(Value::Object(object))
    }
}

/// Carries the duplicate-key refusal into every nested value.
struct StrictSeed;

impl<'de> de::DeserializeSeed<'de> for StrictSeed {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<Value, D::Error> {
        StrictValue::deserialize_from(de)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_with_no_framing_has_no_body() {
        let req = "GET / HTTP/1.1\r\nHost: x\r\n";
        assert_eq!(determine_body_framing(req), BodyFraming::None);
    }

    #[test]
    fn content_length_gives_fixed_framing() {
        let req = "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 42\r\n";
        assert_eq!(determine_body_framing(req), BodyFraming::Fixed(42));
    }

    #[test]
    fn chunked_takes_precedence_over_content_length() {
        let req =
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 42\r\nTransfer-Encoding: chunked\r\n";
        assert_eq!(determine_body_framing(req), BodyFraming::Chunked);
    }

    #[test]
    fn chunked_detection_is_case_insensitive() {
        let req = "POST / HTTP/1.1\r\nHost: x\r\nTRANSFER-ENCODING: Chunked\r\n";
        assert_eq!(determine_body_framing(req), BodyFraming::Chunked);
    }

    #[test]
    fn post_without_framing_is_treated_as_no_body() {
        let req = "POST / HTTP/1.1\r\nHost: x\r\n";
        assert_eq!(determine_body_framing(req), BodyFraming::None);
    }

    #[tokio::test]
    async fn fixed_body_reads_exactly_its_length() {
        let mut stream = std::io::Cursor::new(b"hello, worldPIPELINED".to_vec());
        let body = read_body(&mut stream, BodyFraming::Fixed(12), MAX_INSPECT_BYTES)
            .await
            .expect("fixed body reads");
        assert_eq!(body, b"hello, world");
    }

    #[tokio::test]
    async fn fixed_body_over_the_cap_is_refused_before_reading() {
        let mut stream = std::io::Cursor::new(vec![b'x'; 64]);
        let err = read_body(&mut stream, BodyFraming::Fixed(64), 32)
            .await
            .expect_err("cap should refuse");
        assert!(matches!(err, BodyReadError::TooLarge { .. }), "{err:?}");
        // Refused before consuming, so the cap costs nothing to enforce.
        assert_eq!(stream.position(), 0);
    }

    #[tokio::test]
    async fn fixed_body_cut_short_is_malformed() {
        let mut stream = std::io::Cursor::new(b"short".to_vec());
        let err = read_body(&mut stream, BodyFraming::Fixed(64), MAX_INSPECT_BYTES)
            .await
            .expect_err("truncated body should fail");
        assert!(matches!(err, BodyReadError::Malformed(_)));
    }

    #[tokio::test]
    async fn no_body_framing_reads_nothing() {
        let mut stream = std::io::Cursor::new(b"PIPELINED".to_vec());
        let body = read_body(&mut stream, BodyFraming::None, MAX_INSPECT_BYTES)
            .await
            .expect("empty body reads");
        assert!(body.is_empty());
        assert_eq!(stream.position(), 0);
    }

    #[tokio::test]
    async fn chunked_body_is_decoded_and_trailers_consumed() {
        let raw = "5\r\nhello\r\n7\r\n, world\r\n0\r\nX-Sig: ignored\r\n\r\n";
        let mut stream = std::io::Cursor::new(raw.as_bytes().to_vec());
        let body = read_body(&mut stream, BodyFraming::Chunked, MAX_INSPECT_BYTES)
            .await
            .expect("chunked body decodes");
        assert_eq!(body, b"hello, world");
        // Everything through the trailer terminator is consumed, and nothing more.
        assert_eq!(stream.position() as usize, raw.len());
    }

    #[tokio::test]
    async fn chunked_body_leaves_a_pipelined_request_on_the_stream() {
        let raw = "5\r\nhello\r\n0\r\n\r\nGET /next HTTP/1.1\r\n\r\n";
        let mut stream = std::io::Cursor::new(raw.as_bytes().to_vec());
        let body = read_body(&mut stream, BodyFraming::Chunked, MAX_INSPECT_BYTES)
            .await
            .expect("chunked body decodes");
        assert_eq!(body, b"hello");
        let consumed = stream.position() as usize;
        assert_eq!(&raw.as_bytes()[consumed..], b"GET /next HTTP/1.1\r\n\r\n");
    }

    #[tokio::test]
    async fn chunk_extensions_are_ignored() {
        let raw = "5;name=value\r\nhello\r\n0\r\n\r\n";
        let mut stream = std::io::Cursor::new(raw.as_bytes().to_vec());
        let body = read_body(&mut stream, BodyFraming::Chunked, MAX_INSPECT_BYTES)
            .await
            .expect("chunk extensions are framing, not payload");
        assert_eq!(body, b"hello");
    }

    #[tokio::test]
    async fn chunked_body_over_the_cap_is_refused() {
        let raw = "20\r\n................................\r\n0\r\n\r\n";
        let mut stream = std::io::Cursor::new(raw.as_bytes().to_vec());
        let err = read_body(&mut stream, BodyFraming::Chunked, 16)
            .await
            .expect_err("cap should refuse");
        assert!(matches!(err, BodyReadError::TooLarge { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn chunked_body_accumulates_toward_the_cap_across_chunks() {
        let raw = "8\r\n........\r\n8\r\n........\r\n0\r\n\r\n";
        let mut stream = std::io::Cursor::new(raw.as_bytes().to_vec());
        let err = read_body(&mut stream, BodyFraming::Chunked, 12)
            .await
            .expect_err("the cap bounds the whole body, not one chunk");
        assert!(matches!(err, BodyReadError::TooLarge { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn chunked_body_without_a_terminator_is_malformed() {
        let mut stream = std::io::Cursor::new(b"5\r\nhello\r\n".to_vec());
        let err = read_body(&mut stream, BodyFraming::Chunked, MAX_INSPECT_BYTES)
            .await
            .expect_err("missing terminator should fail");
        assert!(matches!(err, BodyReadError::Malformed(_)));
    }

    #[tokio::test]
    async fn chunk_with_a_bad_size_token_is_malformed() {
        let mut stream = std::io::Cursor::new(b"zz\r\nhello\r\n0\r\n\r\n".to_vec());
        let err = read_body(&mut stream, BodyFraming::Chunked, MAX_INSPECT_BYTES)
            .await
            .expect_err("non-hex chunk size should fail");
        assert!(matches!(err, BodyReadError::Malformed(_)));
    }

    #[tokio::test]
    async fn a_head_is_read_up_to_its_blank_line_and_no_further() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nbody-after";
        let mut stream = std::io::Cursor::new(&raw[..]);
        let head = read_head(&mut stream).await.expect("head reads");
        assert_eq!(head, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        // The body stays on the stream for whoever frames it.
        assert_eq!(&raw[stream.position() as usize..], b"body-after");
    }

    #[tokio::test]
    async fn a_head_that_never_ends_is_malformed() {
        let mut stream = std::io::Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n".to_vec());
        let err = read_head(&mut stream)
            .await
            .expect_err("an unterminated head should fail");
        assert!(matches!(err, BodyReadError::Malformed(_)));
    }

    #[tokio::test]
    async fn a_head_over_the_cap_is_refused() {
        let mut oversized = vec![b'x'; MAX_HEAD_BYTES + 1];
        oversized.extend_from_slice(b"\r\n\r\n");
        let mut stream = std::io::Cursor::new(oversized);
        let err = read_head(&mut stream).await.expect_err("cap should refuse");
        assert!(matches!(err, BodyReadError::TooLarge { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn a_line_is_returned_with_its_terminator() {
        let raw = b"1a;ext=1\r\npayload";
        let mut stream = std::io::Cursor::new(&raw[..]);
        let line = read_crlf_line(&mut stream).await.expect("line reads");
        assert_eq!(line, b"1a;ext=1\r\n");
        assert_eq!(&raw[stream.position() as usize..], b"payload");
    }

    #[test]
    fn reframing_replaces_chunked_framing_with_a_content_length() {
        let head = "POST /graphql HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\
                    Trailer: X-Sig\r\nX-Keep: yes";
        let out = reframe_head_as_content_length(head, 42);
        assert_eq!(
            out,
            "POST /graphql HTTP/1.1\r\nHost: x\r\nX-Keep: yes\r\nContent-Length: 42"
        );
    }

    #[test]
    fn reframing_replaces_an_existing_content_length() {
        let head = "POST /graphql HTTP/1.1\r\nContent-Length: 999";
        let out = reframe_head_as_content_length(head, 7);
        assert_eq!(out, "POST /graphql HTTP/1.1\r\nContent-Length: 7");
    }

    #[test]
    fn reframing_matches_field_names_case_insensitively() {
        let head = "POST / HTTP/1.1\r\ntransfer-encoding: chunked\r\nCONTENT-LENGTH: 5";
        let out = reframe_head_as_content_length(head, 0);
        assert_eq!(out, "POST / HTTP/1.1\r\nContent-Length: 0");
    }

    #[test]
    fn reframing_tolerates_a_trailing_crlf_on_the_head() {
        let head = "POST / HTTP/1.1\r\nHost: x\r\n";
        let out = reframe_head_as_content_length(head, 3);
        assert_eq!(out, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3");
    }

    #[test]
    fn a_plain_head_is_readable() {
        let head = "POST /graphql HTTP/1.1\r\nHost: x\r\nContent-Type: application/json";
        assert!(ensure_body_is_readable(head).is_ok());
    }

    #[test]
    fn an_identity_encoding_is_readable() {
        let head = "POST /graphql HTTP/1.1\r\nContent-Encoding: identity";
        assert!(ensure_body_is_readable(head).is_ok());
    }

    #[test]
    fn a_compressed_body_is_refused() {
        for coding in ["gzip", "deflate", "br", "zstd"] {
            let head = format!("POST /graphql HTTP/1.1\r\nContent-Encoding: {coding}");
            let err = ensure_body_is_readable(&head)
                .expect_err("a coding the proxy cannot undo must be refused");
            assert!(err.contains(coding), "{err}");
        }
    }

    #[test]
    fn a_multipart_body_is_refused() {
        let head = "POST /graphql HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=xyz";
        assert!(ensure_body_is_readable(head).is_err());
    }

    #[test]
    fn a_header_name_is_read_without_regard_to_case() {
        let head = "POST /graphql HTTP/1.1\r\nCONTENT-ENCODING: GZIP";
        assert!(ensure_body_is_readable(head).is_err());
    }

    #[test]
    fn a_request_line_that_looks_like_a_header_is_not_read_as_one() {
        // The first line is the request line, never a field.
        let head = "POST /content-encoding:gzip HTTP/1.1\r\nHost: x";
        assert!(ensure_body_is_readable(head).is_ok());
    }
}
