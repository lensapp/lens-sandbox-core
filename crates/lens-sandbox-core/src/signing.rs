//! Request signing for a host whose credential is a signing key.
//!
//! Most credentials are a value the proxy swaps into the request. AWS SigV4 is
//! not: the SDK in the sandbox signs the request with a placeholder key, and a
//! signature cannot be swapped, only computed again. [`AwsSigner`] holds the
//! placeholder access-key-ID → real-STS-creds map and the AWS domain patterns,
//! refreshed in place on every policy message. The MITM pipeline
//! (`crate::mitm`) asks it to sign a request it has already decided to forward,
//! as the last change to the head.
//!
//! Body handling:
//! - **S3**: always `UNSIGNED-PAYLOAD` → the body streams through unread, so
//!   large uploads pass without memory pressure.
//! - **Non-S3**: the body is buffered up to [`MAX_SIGNED_BODY_BYTES`] and its
//!   SHA-256 signed. Over the cap → `413`. `Transfer-Encoding: chunked` → `411`.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::SystemTime;

use sha2::{Digest, Sha256};

use crate::aws_sigv4::{
    AwsSigv4Config, BodyMode, ResignRequest, SigV4AuthHeader, is_lens_placeholder,
    parse_authorization, resign_request,
};
use crate::http_body::BodyFraming;

/// Non-S3 body buffer cap. JSON API payloads (DynamoDB, Lambda, SQS, …) are
/// typically KB; 1 MiB is plenty of headroom without risking memory exhaustion.
pub const MAX_SIGNED_BODY_BYTES: usize = 1_048_576;

/// Owns the real keys the placeholder signatures stand for, and the domains
/// whose requests are re-signed with them.
pub struct AwsSigner {
    configs: RwLock<HashMap<String, AwsSigv4Config>>,
    domains: RwLock<Vec<String>>,
}

impl AwsSigner {
    pub fn new() -> Self {
        Self {
            configs: RwLock::new(HashMap::new()),
            domains: RwLock::new(Vec::new()),
        }
    }

    /// Replace the configs and domains from a fresh policy message.
    pub fn update(&self, configs: HashMap<String, AwsSigv4Config>, domains: Vec<String>) {
        *self.configs.write().unwrap() = configs;
        *self.domains.write().unwrap() = domains;
    }

    /// Does this target host fall under any registered AWS re-sign domain?
    pub fn matches(&self, target_host: &str) -> bool {
        self.domains
            .read()
            .unwrap()
            .iter()
            .any(|pattern| crate::routing::injection_matches(pattern, target_host))
    }

    /// Snapshot of the current configs map — primarily for tests that assert
    /// policy-refresh overwrote the previous configs.
    pub fn configs_snapshot(&self) -> HashMap<String, AwsSigv4Config> {
        self.configs.read().unwrap().clone()
    }

    /// Read the placeholder signature on `head` and find the real key it
    /// stands for. Nothing is signed yet: the body may still have to be read.
    pub(crate) fn signature_for(&self, head: &str) -> Result<PendingSignature, Refusal> {
        let parsed = parse_request_head(head).ok_or(Refusal::BAD_REQUEST)?;
        let auth_value = parsed
            .find_header("authorization")
            .ok_or(Refusal::new(401, "Missing Authorization"))?;
        let auth = parse_authorization(auth_value)
            .ok_or(Refusal::new(401, "Unsupported Authorization"))?;
        if !is_lens_placeholder(&auth.access_key_id) {
            return Err(Refusal::UNKNOWN_CREDENTIALS);
        }
        let Some(config) = self
            .configs
            .read()
            .unwrap()
            .get(&auth.access_key_id)
            .cloned()
        else {
            tracing::warn!(
                placeholder = %auth.access_key_id,
                "aws resign: no config for placeholder access key"
            );
            return Err(Refusal::UNKNOWN_CREDENTIALS);
        };
        // S3 streaming payload signing (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`,
        // `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`) embeds per-chunk
        // signatures inside the body framing, seeded by the outer signature.
        // Re-signing replaces the outer Authorization but can't rewrite the
        // chunk framing, so AWS would reject the request with a confusing
        // signature mismatch. Say "unsupported" instead.
        if auth.service.eq_ignore_ascii_case("s3")
            && matches!(
                parsed.find_header("x-amz-content-sha256"),
                Some(
                    "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
                        | "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
                )
            )
        {
            return Err(Refusal::new(501, "Not Implemented"));
        }
        Ok(PendingSignature { auth, config })
    }
}

impl Default for AwsSigner {
    fn default() -> Self {
        Self::new()
    }
}

/// Why a request was not signed, as the status the client is answered with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub status: u16,
    pub reason: &'static str,
}

impl Refusal {
    const BAD_REQUEST: Self = Self::new(400, "Bad Request");
    const UNKNOWN_CREDENTIALS: Self = Self::new(401, "Unknown credentials");

    const fn new(status: u16, reason: &'static str) -> Self {
        Self { status, reason }
    }
}

/// A placeholder signature matched to the real key that replaces it.
pub(crate) struct PendingSignature {
    auth: SigV4AuthHeader,
    config: AwsSigv4Config,
}

impl PendingSignature {
    pub(crate) fn service(&self) -> &str {
        &self.auth.service
    }

    /// S3 accepts `UNSIGNED-PAYLOAD`; every other service needs the body hash.
    pub(crate) fn signs_the_body(&self) -> bool {
        !self.auth.service.eq_ignore_ascii_case("s3")
    }

    /// Sign `head` with the real key. `body` is the whole request body when
    /// [`signs_the_body`](Self::signs_the_body), and ignored otherwise.
    pub(crate) fn sign(&self, head: &str, body: &[u8]) -> Result<String, Refusal> {
        let parsed = parse_request_head(head).ok_or(Refusal::BAD_REQUEST)?;
        let body_mode = if self.signs_the_body() {
            BodyMode::Signed {
                sha256_hex: hex::encode(Sha256::digest(body)),
            }
        } else {
            BodyMode::Unsigned
        };
        // Reproduce the original signed-headers set so service-specific headers
        // (e.g. DynamoDB's `x-amz-target`) stay inside the signature. The signer
        // re-injects the infra headers with correct values.
        let signing_headers = collect_signing_headers(&parsed, &self.auth.signed_headers);
        // Sign for the region the client originally signed with. AWS scopes
        // SigV4 signatures to the target regional endpoint (e.g. a request to
        // `ec2.eu-west-1.amazonaws.com` must carry `/eu-west-1/` in the
        // credential scope). The client SDK already chose that region based on
        // its own configuration — preserving it keeps every regional endpoint
        // working. STS session credentials are not region-bound.
        let req = ResignRequest {
            method: &parsed.method,
            uri: &parsed.uri,
            service: &self.auth.service,
            region: &self.auth.region,
            headers: &signing_headers,
            body_mode,
        };
        let resigned = resign_request(&req, &self.config, SystemTime::now()).map_err(|e| {
            tracing::error!(err = %e, "aws resign: signing failed");
            Refusal::new(500, "Signing failed")
        })?;
        Ok(apply_resigned_headers(
            &parsed.head_without_body(),
            &resigned,
        ))
    }
}

/// How many body bytes a request whose body is signed has to be read for.
pub(crate) fn signed_body_length(framing: BodyFraming) -> Result<usize, Refusal> {
    match framing {
        BodyFraming::None => Ok(0),
        BodyFraming::Fixed(len) => usize::try_from(len)
            .ok()
            .filter(|len| *len <= MAX_SIGNED_BODY_BYTES)
            .ok_or(Refusal::new(413, "Payload Too Large")),
        BodyFraming::Chunked => Err(Refusal::new(411, "Length Required")),
    }
}

/// `head` without the headers a signature replaces. A placeholder in them is
/// the signer's to consume, so it never leaves and asks nobody about itself.
pub(crate) fn without_signature_headers(head: &str) -> String {
    head.split("\r\n")
        .filter(|line| {
            !line
                .split_once(':')
                .is_some_and(|(name, _)| is_sigv4_infra_header(name.trim()))
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// Parsed components of an HTTP/1.1 request head.
#[derive(Debug)]
struct ParsedHead {
    method: String,
    uri: String,
    host: String,
    headers: Vec<(String, String)>,
}

impl ParsedHead {
    fn find_header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Request line + raw headers joined with CRLF, without the trailing
    /// `\r\n\r\n` terminator.
    fn head_without_body(&self) -> String {
        let mut out = format!("{} {} HTTP/1.1", self.method, self.uri);
        for (k, v) in &self.headers {
            out.push_str("\r\n");
            out.push_str(k);
            out.push_str(": ");
            out.push_str(v);
        }
        out
    }
}

fn parse_request_head(head: &str) -> Option<ParsedHead> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }
    let method = parts[0].to_string();
    let uri = parts[1].to_string();

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut host: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.find(':') else {
            continue;
        };
        let name = line[..colon].trim().to_string();
        let value = line[colon + 1..].trim().to_string();
        if name.eq_ignore_ascii_case("host") {
            host = Some(value.clone());
        }
        headers.push((name, value));
    }

    Some(ParsedHead {
        method,
        uri,
        host: host?,
        headers,
    })
}

/// Headers the aws-sigv4 crate re-emits verbatim when we sign — we drop the
/// incoming (fake-signed) versions so they don't duplicate on the wire.
/// Service-specific headers like `x-amz-target` are NOT in this list: they
/// must survive untouched and end up inside the re-signed `SignedHeaders=`.
const SIGV4_INFRA_HEADER_NAMES: &[&str] = &[
    "authorization",
    "x-amz-date",
    "x-amz-content-sha256",
    "x-amz-security-token",
];

fn is_sigv4_infra_header(name: &str) -> bool {
    SIGV4_INFRA_HEADER_NAMES
        .iter()
        .any(|h| h.eq_ignore_ascii_case(name))
}

/// Reproduce the set of headers the original signature covered so the
/// re-signed request lists the same names in `SignedHeaders=`. Infra headers
/// (authorization, x-amz-date, x-amz-security-token, x-amz-content-sha256)
/// are skipped — the signer regenerates them with the real credentials.
fn collect_signing_headers(
    parsed: &ParsedHead,
    signed_header_names: &[String],
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::with_capacity(signed_header_names.len());
    let mut saw_host = false;
    for name in signed_header_names {
        if is_sigv4_infra_header(name) {
            continue;
        }
        if let Some(value) = parsed.find_header(name) {
            if name.eq_ignore_ascii_case("host") {
                saw_host = true;
            }
            out.push((name.clone(), value.to_string()));
        }
    }
    // `host` must always participate — the SDK always signs it even if the
    // parsed list somehow omits it.
    if !saw_host {
        out.push(("host".to_string(), parsed.host.clone()));
    }
    out
}

/// Replace the fake signing-infra headers with the new ones. Service-specific
/// headers (e.g. `x-amz-target`) pass through untouched so the re-signed
/// `SignedHeaders=` list remains internally consistent with the wire. Forces
/// `Connection: close` so keep-alive can't deliver a later request whose
/// Host/Authorization we wouldn't rewrite.
fn apply_resigned_headers(head_without_body: &str, resigned: &[(String, String)]) -> String {
    let mut lines = head_without_body.split("\r\n");
    let request_line = lines.next().unwrap_or("");

    let replaced: std::collections::HashSet<String> = resigned
        .iter()
        .map(|(k, _)| k.to_ascii_lowercase())
        .collect();

    let mut out: Vec<String> = Vec::with_capacity(16);
    out.push(request_line.to_string());

    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.find(':') else {
            continue;
        };
        let name = line[..colon].trim().to_ascii_lowercase();
        if name == "connection" || replaced.contains(&name) || is_sigv4_infra_header(&name) {
            continue;
        }
        // Strip any bare `\r`/`\n` — `split("\r\n")` keeps them in the
        // value, and an upstream HTTP parser that tolerates bare LF would
        // see an injected header. Defense-in-depth against a malicious or
        // buggy SDK inside the sandbox.
        out.push(line.replace(['\r', '\n'], ""));
    }

    for (k, v) in resigned {
        let sanitized = v.replace(['\r', '\n'], "");
        out.push(format!("{k}: {sanitized}"));
    }
    out.push("Connection: close".to_string());

    out.join("\r\n")
}

/// Verify that a re-signed request carries the signature the real AWS service
/// would compute for it. Mirrors what an AWS endpoint does on signature
/// validation: parses the signing time from `x-amz-date`, reconstructs the
/// canonical request from the received headers/body, re-signs with the
/// expected real credentials, and compares the signatures byte-for-byte.
///
/// This is circular in the sense that both sides use `aws-sigv4`. But it
/// *does* catch any request-tampering bug (the pipeline drops a header,
/// rewrites the URI, changes the body) because the canonical reconstruction
/// depends on the wire state.
#[cfg(test)]
pub(crate) fn verify_signature(
    head: &str,
    body: &[u8],
    expected: &AwsSigv4Config,
) -> Result<(), String> {
    let parsed = parse_request_head(head).ok_or("cannot parse head")?;

    let received_auth = parsed
        .find_header("authorization")
        .ok_or("no authorization header")?;
    let sig_auth = parse_authorization(received_auth).ok_or("authorization is not SigV4")?;

    // Re-signing must use the exact timestamp the pipeline embedded — a
    // 1-second drift changes the signature entirely.
    let amz_date = parsed
        .find_header("x-amz-date")
        .ok_or("no x-amz-date header")?;
    let signing_time = parse_amz_date(amz_date)?;

    let received_signature = received_auth
        .split(", ")
        .find_map(|p| p.trim().strip_prefix("Signature="))
        .ok_or("no Signature= in auth")?;

    let body_mode = match parsed.find_header("x-amz-content-sha256") {
        Some("UNSIGNED-PAYLOAD") => BodyMode::Unsigned,
        Some(hex_digest) => BodyMode::Signed {
            sha256_hex: hex_digest.to_string(),
        },
        None => BodyMode::Signed {
            sha256_hex: hex::encode(Sha256::digest(body)),
        },
    };

    // Reconstruct the signed-headers set from what actually arrived. Any
    // mutation after signing (e.g. a header dropped by the proxy) surfaces
    // here as "missing signed header" or as a canonical request that differs
    // from what the sender signed.
    let mut headers = Vec::new();
    for name in &sig_auth.signed_headers {
        let value = parsed
            .find_header(name)
            .ok_or_else(|| format!("signed header `{name}` missing from request"))?;
        headers.push((name.clone(), value.to_string()));
    }

    let req = ResignRequest {
        method: &parsed.method,
        uri: &parsed.uri,
        service: &sig_auth.service,
        region: &sig_auth.region,
        headers: &headers,
        body_mode,
    };
    let expected_headers = resign_request(&req, expected, signing_time)
        .map_err(|e| format!("re-signing failed: {e}"))?;

    let expected_auth = expected_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.as_str())
        .ok_or("re-sign produced no authorization header")?;
    let expected_signature = expected_auth
        .split(", ")
        .find_map(|p| p.trim().strip_prefix("Signature="))
        .ok_or("no Signature= in expected auth")?;

    if expected_signature == received_signature {
        Ok(())
    } else {
        Err(format!(
            "signature mismatch:\n  received: {received_signature}\n  expected: {expected_signature}"
        ))
    }
}

/// Parse `x-amz-date` in ISO 8601 basic format (`YYYYMMDDTHHMMSSZ`) into a
/// `SystemTime`, so the verifier re-signs at the exact time the pipeline did.
#[cfg(test)]
fn parse_amz_date(s: &str) -> Result<SystemTime, String> {
    if s.len() != 16 || s.as_bytes().get(8).is_none_or(|b| *b != b'T') {
        return Err(format!("invalid x-amz-date: {s}"));
    }
    let year: i64 = s[0..4].parse().map_err(|_| "bad year".to_string())?;
    let month: i64 = s[4..6].parse().map_err(|_| "bad month".to_string())?;
    let day: i64 = s[6..8].parse().map_err(|_| "bad day".to_string())?;
    let hour: i64 = s[9..11].parse().map_err(|_| "bad hour".to_string())?;
    let minute: i64 = s[11..13].parse().map_err(|_| "bad minute".to_string())?;
    let second: i64 = s[13..15].parse().map_err(|_| "bad second".to_string())?;

    // Howard Hinnant's days_from_civil — Gregorian to serial day count
    // relative to 1970-01-01. Shift Jan/Feb to the previous year so the
    // leap-day offset math works out to a single formula.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m_shift = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * m_shift + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days_since_epoch = era * 146_097 + doe - 719_468;

    let secs = days_since_epoch * 86_400 + hour * 3600 + minute * 60 + second;
    let secs: u64 = secs
        .try_into()
        .map_err(|_| "date before 1970".to_string())?;
    Ok(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_head_extracts_method_uri_host() {
        let head = "GET /my-bucket?list-type=2 HTTP/1.1\r\n\
                    Host: s3.us-east-1.amazonaws.com\r\n\
                    X-Amz-Date: 20230101T000000Z";
        let parsed = parse_request_head(head).unwrap();
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.uri, "/my-bucket?list-type=2");
        assert_eq!(parsed.host, "s3.us-east-1.amazonaws.com");
        assert_eq!(parsed.find_header("x-amz-date"), Some("20230101T000000Z"));
    }

    #[test]
    fn parse_request_head_rejects_missing_host() {
        let head = "GET / HTTP/1.1\r\nX-Amz-Date: 20230101T000000Z";
        assert!(parse_request_head(head).is_none());
    }

    #[test]
    fn apply_resigned_headers_strips_infra_keeps_service_headers() {
        let head = "POST / HTTP/1.1\r\n\
                    Host: dynamodb.us-east-1.amazonaws.com\r\n\
                    Authorization: AWS4-HMAC-SHA256 Credential=LENSFAKE...\r\n\
                    X-Amz-Date: 20230101T000000Z\r\n\
                    X-Amz-Content-Sha256: abc\r\n\
                    X-Amz-Security-Token: fake-token\r\n\
                    X-Amz-Target: DynamoDB_20120810.PutItem\r\n\
                    User-Agent: aws-sdk-rust";
        let resigned = vec![
            (
                "authorization".to_string(),
                "AWS4-HMAC-SHA256 Credential=ASIA...".to_string(),
            ),
            ("x-amz-date".to_string(), "20240202T000000Z".to_string()),
            ("x-amz-security-token".to_string(), "real-token".to_string()),
            ("x-amz-content-sha256".to_string(), "deadbeef".to_string()),
        ];
        let out = apply_resigned_headers(head, &resigned);
        assert!(out.contains("POST / HTTP/1.1"));
        assert!(out.contains("Host: dynamodb.us-east-1.amazonaws.com"));
        assert!(out.contains("User-Agent: aws-sdk-rust"));
        assert!(
            out.contains("X-Amz-Target: DynamoDB_20120810.PutItem"),
            "service-specific x-amz-target must be preserved"
        );
        assert!(!out.contains("LENSFAKE"));
        assert!(!out.contains("fake-token"));
        assert!(out.contains("Credential=ASIA..."));
        assert!(out.contains("x-amz-date: 20240202T000000Z"));
        assert!(out.contains("Connection: close"));
    }

    #[test]
    fn collect_signing_headers_replays_original_signed_set_minus_infra() {
        let head = "POST / HTTP/1.1\r\n\
                    Host: dynamodb.us-east-1.amazonaws.com\r\n\
                    X-Amz-Target: DynamoDB_20120810.PutItem\r\n\
                    Content-Type: application/x-amz-json-1.0\r\n\
                    X-Amz-Date: 20230101T000000Z";
        let parsed = parse_request_head(head).unwrap();
        let signed = vec![
            "host".to_string(),
            "x-amz-target".to_string(),
            "x-amz-date".to_string(), // infra — must be skipped
            "content-type".to_string(),
        ];
        let collected = collect_signing_headers(&parsed, &signed);
        let names: Vec<&str> = collected.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"host"));
        assert!(names.contains(&"x-amz-target"));
        assert!(names.contains(&"content-type"));
        assert!(!names.iter().any(|n| n.eq_ignore_ascii_case("x-amz-date")));
    }

    #[test]
    fn collect_signing_headers_adds_host_when_missing_from_signed_list() {
        let head = "GET / HTTP/1.1\r\nHost: s3.us-east-1.amazonaws.com";
        let parsed = parse_request_head(head).unwrap();
        // A pathological signed list without `host` — we still must sign it.
        let collected = collect_signing_headers(&parsed, &[]);
        assert!(collected.iter().any(|(k, _)| k == "host"));
    }

    #[test]
    fn apply_resigned_headers_is_idempotent_against_duplicate_resigned_keys() {
        let head = "GET / HTTP/1.1\r\nHost: h.example.com";
        let resigned = vec![
            (
                "authorization".to_string(),
                "AWS4-HMAC-SHA256 a".to_string(),
            ),
            (
                "authorization".to_string(),
                "AWS4-HMAC-SHA256 b".to_string(),
            ),
        ];
        // Even with duplicates in the resigned list, no pre-existing
        // Authorization leaks through (there was none here anyway).
        let out = apply_resigned_headers(head, &resigned);
        assert!(out.contains("AWS4-HMAC-SHA256 a"));
        assert!(out.contains("AWS4-HMAC-SHA256 b"));
    }

    #[test]
    fn the_signature_headers_are_left_out_of_the_head_the_gate_scans() {
        let head = "GET / HTTP/1.1\r\n\
                    Host: s3.us-east-1.amazonaws.com\r\n\
                    authorization: AWS4-HMAC-SHA256 Credential=LENSFAKE00AABB0000CC/x\r\n\
                    X-Amz-Security-Token: placeholder-session-token\r\n\
                    X-Custom: LENSFAKE00AABB0000CC";
        assert_eq!(
            without_signature_headers(head),
            "GET / HTTP/1.1\r\n\
             Host: s3.us-east-1.amazonaws.com\r\n\
             X-Custom: LENSFAKE00AABB0000CC",
            "a placeholder outside the signature is still the gate's to see"
        );
    }

    #[test]
    fn a_body_is_read_for_its_signature_only_when_its_length_is_known_and_small() {
        assert_eq!(signed_body_length(BodyFraming::None), Ok(0));
        assert_eq!(signed_body_length(BodyFraming::Fixed(20)), Ok(20));
        assert_eq!(
            signed_body_length(BodyFraming::Fixed(MAX_SIGNED_BODY_BYTES as u64 + 1))
                .map_err(|refusal| refusal.status),
            Err(413)
        );
        assert_eq!(
            signed_body_length(BodyFraming::Chunked).map_err(|refusal| refusal.status),
            Err(411)
        );
    }
}
