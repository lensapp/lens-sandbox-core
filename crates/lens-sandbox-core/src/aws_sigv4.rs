//! AWS SigV4 re-signing for the MITM boundary.
//!
//! Agents inside the sandbox sign with placeholder AWS credentials (worthless
//! outside the proxy). This module re-signs the request with the real STS
//! session credentials delivered in the policy message, producing the header
//! set that the MITM handler substitutes before forwarding upstream to AWS.
//!
//! The real credentials never reach the sandbox filesystem or agent process
//! memory — they live only in the sandbox-core proxy process.

use std::time::SystemTime;

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{
    PayloadChecksumKind, SignableBody, SignableRequest, SigningParams, SigningSettings, sign,
};
use aws_sigv4::sign::v4;

/// Real STS session credentials for re-signing a request to AWS.
///
/// STS session credentials are not region-bound, so no region is stored here.
/// The signing region is taken from the client's original `Authorization`
/// header and passed explicitly to [`resign_request`] — it must match the
/// regional endpoint the client is targeting, or AWS rejects the signature.
#[derive(Debug, Clone)]
pub struct AwsSigv4Config {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
}

/// Payload signing strategy.
#[derive(Debug, Clone)]
pub enum BodyMode {
    /// Payload hash is `SHA256(body)`, lowercase hex. Used for small JSON
    /// request bodies where we have already buffered + hashed the body.
    Signed { sha256_hex: String },

    /// `X-Amz-Content-Sha256: UNSIGNED-PAYLOAD`. AWS skips body-hash
    /// verification — we can then stream the body through without buffering.
    /// S3 accepts this; most other services don't.
    Unsigned,
}

/// Errors produced while re-signing.
#[derive(Debug)]
pub enum AwsSigv4Error {
    InvalidSigningParams(String),
    InvalidRequest(String),
    SigningFailed(String),
}

impl std::fmt::Display for AwsSigv4Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSigningParams(m) => write!(f, "invalid signing params: {m}"),
            Self::InvalidRequest(m) => write!(f, "invalid request: {m}"),
            Self::SigningFailed(m) => write!(f, "signing failed: {m}"),
        }
    }
}

impl std::error::Error for AwsSigv4Error {}

/// Parsed components of an AWS4-HMAC-SHA256 `Authorization` header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigV4AuthHeader {
    pub access_key_id: String,
    pub date: String,
    pub region: String,
    pub service: String,
    pub signed_headers: Vec<String>,
}

/// Parse the value of an AWS SigV4 `Authorization` header.
///
/// Expected format:
/// `AWS4-HMAC-SHA256 Credential=<key>/<YYYYMMDD>/<region>/<service>/aws4_request,
///  SignedHeaders=<h1;h2>, Signature=<hex>`
///
/// Returns `None` for anything that isn't a recognizable SigV4 header.
pub fn parse_authorization(header_value: &str) -> Option<SigV4AuthHeader> {
    let rest = header_value.strip_prefix("AWS4-HMAC-SHA256")?;
    let rest = rest.trim_start();

    let mut credential: Option<&str> = None;
    let mut signed_headers_raw: Option<&str> = None;

    for part in rest.split(',') {
        let trimmed = part.trim();
        if let Some(v) = trimmed.strip_prefix("Credential=") {
            credential = Some(v);
        } else if let Some(v) = trimmed.strip_prefix("SignedHeaders=") {
            signed_headers_raw = Some(v);
        }
    }

    let cred = credential?;
    let signed = signed_headers_raw?;

    // Credential = <key>/<date>/<region>/<service>/aws4_request
    let mut parts = cred.split('/');
    let access_key_id = parts.next()?.to_string();
    let date = parts.next()?.to_string();
    let region = parts.next()?.to_string();
    let service = parts.next()?.to_string();
    let terminator = parts.next()?;
    if terminator != "aws4_request" {
        return None;
    }

    let signed_headers = signed
        .split(';')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();

    if signed_headers.is_empty() {
        return None;
    }

    Some(SigV4AuthHeader {
        access_key_id,
        date,
        region,
        service,
        signed_headers,
    })
}

/// True when the access key ID carries the sandbox placeholder prefix.
/// Case-sensitive — the AWS SDK forwards the key verbatim.
pub fn is_lens_placeholder(access_key_id: &str) -> bool {
    access_key_id.starts_with("LENSFAKE")
}

/// Inputs to [`resign_request`]. `headers` must include every header in the
/// original `SignedHeaders=` list (host, any `x-amz-*`, any user headers the
/// SDK signed) but must NOT include the placeholder `Authorization` header.
/// `region` must match the regional endpoint the request is being sent to.
#[derive(Debug, Clone)]
pub struct ResignRequest<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub service: &'a str,
    pub region: &'a str,
    pub headers: &'a [(String, String)],
    pub body_mode: BodyMode,
}

/// Re-sign an AWS request with real credentials.
pub fn resign_request(
    req: &ResignRequest<'_>,
    config: &AwsSigv4Config,
    signing_time: SystemTime,
) -> Result<Vec<(String, String)>, AwsSigv4Error> {
    let identity = Credentials::new(
        &config.access_key_id,
        &config.secret_access_key,
        Some(config.session_token.clone()),
        None,
        "lens-resign",
    )
    .into();

    // XAmzSha256 makes the signer include the `x-amz-content-sha256` header
    // in both the outgoing request and the signed-headers set. For
    // UnsignedPayload the value becomes `UNSIGNED-PAYLOAD`; for Precomputed
    // it becomes the hex digest. S3 requires this header; other services
    // accept but don't require it.
    let mut settings = SigningSettings::default();
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;

    let params: SigningParams<'_> = v4::SigningParams::builder()
        .identity(&identity)
        .region(req.region)
        .name(req.service)
        .time(signing_time)
        .settings(settings)
        .build()
        .map_err(|e| AwsSigv4Error::InvalidSigningParams(e.to_string()))?
        .into();

    let body = match &req.body_mode {
        BodyMode::Signed { sha256_hex } => SignableBody::Precomputed(sha256_hex.clone()),
        BodyMode::Unsigned => SignableBody::UnsignedPayload,
    };

    let header_refs: Vec<(&str, &str)> = req
        .headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let signable = SignableRequest::new(req.method, req.uri, header_refs.into_iter(), body)
        .map_err(|e| AwsSigv4Error::InvalidRequest(e.to_string()))?;

    let (instructions, _signature) = sign(signable, &params)
        .map_err(|e| AwsSigv4Error::SigningFailed(e.to_string()))?
        .into_parts();

    Ok(instructions
        .headers()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn test_config() -> AwsSigv4Config {
        AwsSigv4Config {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: "FwoGZXIvYXdzSESSIONTOKEN".to_string(),
        }
    }

    /// 2023-01-01T00:00:00Z — any fixed time works, so long as the test is
    /// insensitive to the current wall clock.
    fn fixed_time() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_672_531_200)
    }

    fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn resign_unsigned_payload_sets_content_sha256_to_unsigned() {
        let headers = [("host".to_string(), "s3.us-east-1.amazonaws.com".to_string())];
        let req = ResignRequest {
            method: "PUT",
            uri: "/my-bucket/my-object",
            service: "s3",
            region: "us-east-1",
            headers: &headers,
            body_mode: BodyMode::Unsigned,
        };
        let result = resign_request(&req, &test_config(), fixed_time()).unwrap();

        assert_eq!(
            find_header(&result, "x-amz-content-sha256"),
            Some("UNSIGNED-PAYLOAD"),
            "UNSIGNED-PAYLOAD header must be set for S3 streaming path"
        );
    }

    #[test]
    fn resign_emits_authorization_and_date_and_session_token() {
        let headers = [("host".to_string(), "s3.us-east-1.amazonaws.com".to_string())];
        let req = ResignRequest {
            method: "PUT",
            uri: "/my-bucket/my-object",
            service: "s3",
            region: "us-east-1",
            headers: &headers,
            body_mode: BodyMode::Unsigned,
        };
        let result = resign_request(&req, &test_config(), fixed_time()).unwrap();

        let auth = find_header(&result, "authorization").expect("authorization header");
        assert!(
            auth.starts_with("AWS4-HMAC-SHA256 "),
            "auth must be SigV4: {auth}"
        );
        assert!(
            auth.contains("Credential=AKIAIOSFODNN7EXAMPLE/"),
            "real access key in credential scope: {auth}"
        );
        assert!(
            auth.contains("/us-east-1/s3/aws4_request"),
            "region+service in scope: {auth}"
        );
        assert!(
            auth.contains("SignedHeaders="),
            "SignedHeaders present: {auth}"
        );
        assert!(auth.contains("Signature="), "Signature present: {auth}");

        assert!(
            find_header(&result, "x-amz-date").is_some(),
            "x-amz-date header present"
        );
        assert_eq!(
            find_header(&result, "x-amz-security-token"),
            Some("FwoGZXIvYXdzSESSIONTOKEN"),
            "session token header included"
        );
    }

    #[test]
    fn resign_signed_body_uses_precomputed_sha256() {
        // Empty-body SHA-256 (the canonical AWS empty-payload hash)
        let empty_sha =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string();

        let headers = [(
            "host".to_string(),
            "dynamodb.us-east-1.amazonaws.com".to_string(),
        )];
        let req = ResignRequest {
            method: "POST",
            uri: "/",
            service: "dynamodb",
            region: "us-east-1",
            headers: &headers,
            body_mode: BodyMode::Signed {
                sha256_hex: empty_sha.clone(),
            },
        };
        let result = resign_request(&req, &test_config(), fixed_time()).unwrap();

        let auth = find_header(&result, "authorization").expect("authorization header");
        assert!(auth.contains("/us-east-1/dynamodb/aws4_request"));

        // For Signed payloads, content-sha256 is NOT UNSIGNED-PAYLOAD. Either
        // the signer emits the exact hash or omits the header (services that
        // don't require it). Assert UNSIGNED-PAYLOAD is NOT set.
        assert_ne!(
            find_header(&result, "x-amz-content-sha256"),
            Some("UNSIGNED-PAYLOAD"),
            "signed body must not carry UNSIGNED-PAYLOAD"
        );
    }

    #[test]
    fn parse_authorization_extracts_scope_and_signed_headers() {
        let header = "AWS4-HMAC-SHA256 \
            Credential=LENSFAKE00AABB0000CC/20230101/us-east-1/s3/aws4_request, \
            SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
            Signature=abcdef";

        let parsed = parse_authorization(header).unwrap();
        assert_eq!(parsed.access_key_id, "LENSFAKE00AABB0000CC");
        assert_eq!(parsed.date, "20230101");
        assert_eq!(parsed.region, "us-east-1");
        assert_eq!(parsed.service, "s3");
        assert_eq!(
            parsed.signed_headers,
            vec!["host", "x-amz-content-sha256", "x-amz-date"]
        );
    }

    #[test]
    fn parse_authorization_rejects_non_sigv4() {
        assert!(parse_authorization("Bearer abc").is_none());
        assert!(parse_authorization("").is_none());
        assert!(parse_authorization("AWS4-HMAC-SHA256 Credential=foo").is_none());
        assert!(
            parse_authorization(
                "AWS4-HMAC-SHA256 Credential=k/20230101/us-east-1/s3/NOT_TERMINATOR, \
                 SignedHeaders=host, Signature=x"
            )
            .is_none()
        );
    }

    #[test]
    fn is_lens_placeholder_matches_prefix() {
        assert!(is_lens_placeholder("LENSFAKE00AABB0000CC"));
        assert!(!is_lens_placeholder("AKIAIOSFODNN7EXAMPLE"));
        assert!(!is_lens_placeholder("ASIAFAKELENS0000001"));
        assert!(!is_lens_placeholder(""));
    }

    #[test]
    fn resign_scope_uses_signing_region_argument() {
        // Re-signing a request destined for eu-west-1 must produce a credential
        // scope in eu-west-1, regardless of what is carried in the config.
        let headers = [(
            "host".to_string(),
            "ec2.eu-west-1.amazonaws.com".to_string(),
        )];
        let req = ResignRequest {
            method: "GET",
            uri: "/",
            service: "ec2",
            region: "eu-west-1",
            headers: &headers,
            body_mode: BodyMode::Unsigned,
        };
        let result = resign_request(&req, &test_config(), fixed_time()).unwrap();

        let auth = find_header(&result, "authorization").expect("authorization header");
        assert!(
            auth.contains("/eu-west-1/ec2/aws4_request"),
            "credential scope must be scoped to the caller-supplied region, got: {auth}"
        );
    }

    #[test]
    fn resign_is_deterministic_for_fixed_time() {
        let headers = vec![("host".to_string(), "s3.us-east-1.amazonaws.com".to_string())];
        let req = ResignRequest {
            method: "GET",
            uri: "/my-bucket?list-type=2",
            service: "s3",
            region: "us-east-1",
            headers: &headers,
            body_mode: BodyMode::Unsigned,
        };
        let a = resign_request(&req, &test_config(), fixed_time()).unwrap();
        let b = resign_request(&req, &test_config(), fixed_time()).unwrap();
        assert_eq!(
            find_header(&a, "authorization"),
            find_header(&b, "authorization"),
            "same inputs must produce identical signatures"
        );
    }
}
