//! HTTP/1.1 request body framing: how much of the stream belongs to this
//! request, and how to buffer and re-frame it.
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

use tokio::io::{AsyncRead, AsyncReadExt};

/// Largest request body buffered for policy inspection.
///
/// A body over the cap is refused rather than truncated: a rule that matches on
/// the body cannot be evaluated against bytes we declined to read, and
/// forwarding an uninspected payload past a rule that asked to see it would
/// fail open.
pub const MAX_INSPECT_BYTES: usize = 64 * 1024;

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

/// Why a request body could not be buffered for inspection.
///
/// Both variants are policy denials at the call site: a rule asked to see the
/// body and we cannot show it one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyReadError {
    /// The body is larger than the caller's inspection budget.
    TooLarge,
    /// The stream ended early, or its chunked framing was malformed.
    Malformed(&'static str),
}

impl BodyReadError {
    /// Stable token for audit metadata.
    pub fn audit_reason(&self) -> &'static str {
        match self {
            Self::TooLarge => "body-too-large",
            Self::Malformed(_) => "body-malformed",
        }
    }
}

impl std::fmt::Display for BodyReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => write!(f, "request body exceeds the inspection limit"),
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
/// 3. Else, request method conventions: HEAD/GET/DELETE/OPTIONS/TRACE have no
///    body; POST/PUT/PATCH/etc. without explicit framing default to no body
///    too (a server is allowed to reject those, but we shouldn't pump bytes
///    of unknown length to upstream where they'd outlive our session).
pub fn determine_body_framing(header_block: &str, method: &str) -> BodyFraming {
    let mut content_length: Option<u64> = None;
    for line in header_block.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("transfer-encoding:") {
            // Per RFC, the last coding listed is the outer one. If chunked is
            // present anywhere we treat it as chunked — a chunked-with-extras
            // request is rare and the safest thing is to switch to chunk
            // parsing rather than blindly forwarding bytes by length.
            if rest.contains("chunked") {
                return BodyFraming::Chunked;
            }
        } else if let Some(rest) = lower.strip_prefix("content-length:")
            && let Ok(n) = rest.trim().parse::<u64>()
        {
            content_length = Some(n);
        }
    }
    if let Some(n) = content_length {
        return BodyFraming::Fixed(n);
    }
    match method.to_ascii_uppercase().as_str() {
        "GET" | "HEAD" | "DELETE" | "OPTIONS" | "TRACE" | "CONNECT" => BodyFraming::None,
        // Methods that conventionally carry a body but were sent without
        // framing — treat as empty rather than forwarding indefinite bytes.
        _ => BodyFraming::None,
    }
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
            let len = usize::try_from(len).map_err(|_| BodyReadError::TooLarge)?;
            if len > max_bytes {
                return Err(BodyReadError::TooLarge);
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
            return Err(BodyReadError::TooLarge);
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
///
/// Reads a byte at a time so that neither chunk payload nor a pipelined second
/// request is consumed along with the line.
async fn read_framing_line<R>(reader: &mut R) -> Result<String, BodyReadError>
where
    R: AsyncRead + Unpin,
{
    let mut line: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = reader
            .read(&mut byte)
            .await
            .map_err(|_| BodyReadError::Malformed("chunked body ended before its terminator"))?;
        if read == 0 {
            return Err(BodyReadError::Malformed(
                "chunked body ended before its terminator",
            ));
        }
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return String::from_utf8(line)
                .map_err(|_| BodyReadError::Malformed("invalid UTF-8 in chunked body framing"));
        }
        if line.len() > MAX_FRAMING_LINE_BYTES {
            return Err(BodyReadError::TooLarge);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_with_no_framing_has_no_body() {
        let req = "GET / HTTP/1.1\r\nHost: x\r\n";
        assert_eq!(determine_body_framing(req, "GET"), BodyFraming::None);
    }

    #[test]
    fn content_length_gives_fixed_framing() {
        let req = "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 42\r\n";
        assert_eq!(determine_body_framing(req, "POST"), BodyFraming::Fixed(42));
    }

    #[test]
    fn chunked_takes_precedence_over_content_length() {
        let req =
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 42\r\nTransfer-Encoding: chunked\r\n";
        assert_eq!(determine_body_framing(req, "POST"), BodyFraming::Chunked);
    }

    #[test]
    fn chunked_detection_is_case_insensitive() {
        let req = "POST / HTTP/1.1\r\nHost: x\r\nTRANSFER-ENCODING: Chunked\r\n";
        assert_eq!(determine_body_framing(req, "POST"), BodyFraming::Chunked);
    }

    #[test]
    fn post_without_framing_is_treated_as_no_body() {
        let req = "POST / HTTP/1.1\r\nHost: x\r\n";
        assert_eq!(determine_body_framing(req, "POST"), BodyFraming::None);
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
        assert_eq!(err, BodyReadError::TooLarge);
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
        assert_eq!(err, BodyReadError::TooLarge);
    }

    #[tokio::test]
    async fn chunked_body_accumulates_toward_the_cap_across_chunks() {
        let raw = "8\r\n........\r\n8\r\n........\r\n0\r\n\r\n";
        let mut stream = std::io::Cursor::new(raw.as_bytes().to_vec());
        let err = read_body(&mut stream, BodyFraming::Chunked, 12)
            .await
            .expect_err("the cap bounds the whole body, not one chunk");
        assert_eq!(err, BodyReadError::TooLarge);
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
}
