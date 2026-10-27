//! Re-signing, driven end to end through the MITM.
//!
//! The sandbox signs with a placeholder key. These tests prove that a request
//! to a host whose requests are re-signed leaves the proxy signed with the real
//! key, after every other step of the pipeline has had its say.

use super::*;
use crate::aws_sigv4::{AwsSigv4Config, BodyMode, ResignRequest, resign_request};
use sha2::{Digest, Sha256};

const TEST_HOSTNAME: &str = "s3.us-east-1.amazonaws.com";
const PLACEHOLDER: &str = "LENSFAKE00AABB0000CC";

fn real_config() -> AwsSigv4Config {
    AwsSigv4Config {
        access_key_id: "ASIAREALEXAMPLE".to_string(),
        secret_access_key: "real-secret-example".to_string(),
        session_token: "real-session-token".to_string(),
    }
}

fn fake_config() -> AwsSigv4Config {
    AwsSigv4Config {
        access_key_id: PLACEHOLDER.to_string(),
        secret_access_key: "placeholder-secret".to_string(),
        session_token: "placeholder-session-token".to_string(),
    }
}

/// What the sandbox client pretends to send and which regional endpoint it's
/// targeting. `extra_signed` simulates service-specific signed headers like
/// DynamoDB's `x-amz-target`.
struct HarnessRequest<'a> {
    method: &'a str,
    uri: &'a str,
    body: &'a [u8],
    service: &'a str,
    signed_with_unsigned_payload: bool,
    extra_signed: &'a [(String, String)],
    hostname: &'static str,
    region: &'a str,
}

impl Default for HarnessRequest<'_> {
    fn default() -> Self {
        Self {
            method: "GET",
            uri: "/my-bucket?list-type=2",
            body: b"",
            service: "s3",
            signed_with_unsigned_payload: true,
            extra_signed: &[],
            hostname: TEST_HOSTNAME,
            region: "us-east-1",
        }
    }
}

/// A sandbox-style pre-signed AWS request: method + path + host headers +
/// Authorization signed with the FAKE secret, as raw bytes.
fn sandbox_signed_request(spec: &HarnessRequest<'_>) -> Vec<u8> {
    let mut headers = vec![("host".to_string(), spec.hostname.to_string())];
    headers.extend(spec.extra_signed.iter().cloned());
    let body_mode = if spec.signed_with_unsigned_payload {
        BodyMode::Unsigned
    } else {
        BodyMode::Signed {
            sha256_hex: hex::encode(Sha256::digest(spec.body)),
        }
    };
    let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    let req = ResignRequest {
        method: spec.method,
        uri: spec.uri,
        service: spec.service,
        region: spec.region,
        headers: &headers,
        body_mode,
    };
    let signed = resign_request(&req, &fake_config(), time).unwrap();

    let mut out = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n",
        spec.method,
        spec.uri,
        spec.hostname,
        spec.body.len()
    );
    // Any extra signed headers must appear on the wire so the original
    // signature (over fake creds) references real header values.
    for (k, v) in spec.extra_signed.iter().chain(&signed) {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("Connection: close\r\n\r\n");

    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(spec.body);
    bytes
}

/// A proxy that re-signs `hostname` for the placeholder key, which the
/// credential gate also knows as the placeholder of an AWS connection.
fn signing_state(
    hostname: &str,
) -> (
    Arc<crate::proxy::ProxyState>,
    tokio::sync::mpsc::UnboundedReceiver<String>,
) {
    let (state, audit_rx) = crate::proxy::tests::test_state();
    state.aws_signer.update(
        std::collections::HashMap::from([(PLACEHOLDER.to_string(), real_config())]),
        vec![hostname.to_string()],
    );
    state
        .placeholder_index
        .write()
        .unwrap()
        .insert(PLACEHOLDER.to_string(), "aws:connection-1".to_string());
    (state, audit_rx)
}

/// Send `request` to `hostname` through the MITM. A request the pipeline holds
/// for a question fails the test rather than hanging it.
async fn run_signed(
    state: Arc<crate::proxy::ProxyState>,
    audit_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
    hostname: &'static str,
    http_rules: Vec<HttpRule>,
    request: Vec<u8>,
) -> (String, String, Vec<serde_json::Value>) {
    let policy = HarnessPolicy {
        http_rules,
        ..Default::default()
    };
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        run_mitm_harness_in(state, audit_rx, hostname, policy, request, false),
    )
    .await
    .expect("the request is never held for a question")
}

/// Send a sandbox-signed request and return the head and body the origin saw.
async fn upstream_of(spec: &HarnessRequest<'_>, http_rules: Vec<HttpRule>) -> (String, Vec<u8>) {
    let (state, audit_rx) = signing_state(spec.hostname);
    let (upstream, _, _) = run_signed(
        state,
        audit_rx,
        spec.hostname,
        http_rules,
        sandbox_signed_request(spec),
    )
    .await;
    let (head, body) = upstream
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("the request must reach the origin: {upstream}"));
    (head.to_string(), body.as_bytes().to_vec())
}

/// Send `request` and return what the client was answered, when the pipeline
/// refuses it before anything is forwarded.
///
/// The credential gate does not see the signature headers on a signed host, so
/// the refusal is the only thing that keeps the placeholder signature from
/// leaving.
async fn refusal_of(request: Vec<u8>) -> (String, Vec<serde_json::Value>) {
    let (state, audit_rx) = signing_state(TEST_HOSTNAME);
    let (outcome, client, audits) =
        run_signed(state, audit_rx, TEST_HOSTNAME, vec![], request).await;
    assert!(
        outcome.starts_with("aws resign: "),
        "the refused request must not reach the origin: {outcome}"
    );
    (client, audits)
}

/// A head signed with the placeholder key and no matching body, for the
/// refusals that answer before any body is read.
fn placeholder_signed_head(method: &str, service: &str, extra: &str) -> String {
    let headers = vec![("host".to_string(), TEST_HOSTNAME.to_string())];
    let req = ResignRequest {
        method,
        uri: "/",
        service,
        region: "us-east-1",
        headers: &headers,
        body_mode: BodyMode::Signed {
            sha256_hex: "0".repeat(64),
        },
    };
    let signed = resign_request(&req, &fake_config(), std::time::SystemTime::now()).unwrap();
    let mut head = format!("{method} / HTTP/1.1\r\nHost: {TEST_HOSTNAME}\r\n{extra}");
    for (k, v) in &signed {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("Connection: close\r\n\r\n");
    head
}

#[tokio::test]
async fn s3_has_its_placeholder_signature_replaced_with_a_real_one() {
    let (head, _) = upstream_of(&HarnessRequest::default(), vec![]).await;

    assert!(head.contains("GET /my-bucket?list-type=2 HTTP/1.1"));
    assert!(head.contains("Host: s3.us-east-1.amazonaws.com"));
    assert!(
        !head.contains("LENSFAKE"),
        "no fake access key must reach upstream: {head}"
    );
    assert!(
        head.contains("Credential=ASIAREALEXAMPLE/"),
        "real access key in signature: {head}"
    );
    assert!(
        head.contains("/us-east-1/s3/aws4_request"),
        "region+service in scope: {head}"
    );
    let lower = head.to_ascii_lowercase();
    assert!(
        lower.contains("x-amz-content-sha256: unsigned-payload"),
        "S3 must use UNSIGNED-PAYLOAD: {head}"
    );
    assert!(
        lower.contains("x-amz-security-token: real-session-token"),
        "real session token included: {head}"
    );
}

#[tokio::test]
async fn a_non_s3_body_is_buffered_and_signed_with_its_sha256() {
    let body: &[u8] = b"{\"TableName\":\"demo\"}";
    let (head, body_seen) = upstream_of(
        &HarnessRequest {
            method: "POST",
            uri: "/",
            body,
            service: "dynamodb",
            signed_with_unsigned_payload: false,
            ..Default::default()
        },
        vec![],
    )
    .await;

    assert!(
        head.contains("/us-east-1/dynamodb/aws4_request"),
        "non-S3 service preserved: {head}"
    );
    assert!(
        !head.to_ascii_lowercase().contains("unsigned-payload"),
        "non-S3 must not use UNSIGNED-PAYLOAD: {head}"
    );
    assert_eq!(body_seen, body, "body must reach upstream unchanged");
}

#[tokio::test]
async fn a_service_specific_header_stays_inside_the_signature() {
    // DynamoDB selects the operation via `x-amz-target`. If re-signing strips
    // this header (or drops it from the signed-headers list), DynamoDB returns
    // `UnknownOperationException`.
    let extra_signed = vec![(
        "x-amz-target".to_string(),
        "DynamoDB_20120810.PutItem".to_string(),
    )];
    let (head, _) = upstream_of(
        &HarnessRequest {
            method: "POST",
            uri: "/",
            body: b"{\"TableName\":\"demo\"}",
            service: "dynamodb",
            signed_with_unsigned_payload: false,
            extra_signed: &extra_signed,
            ..Default::default()
        },
        vec![],
    )
    .await;

    assert!(
        head.contains("x-amz-target: DynamoDB_20120810.PutItem"),
        "x-amz-target must reach upstream: {head}"
    );
    let auth_line = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
        .expect("authorization line");
    assert!(
        auth_line.contains("x-amz-target"),
        "x-amz-target must be in the re-signed SignedHeaders list: {auth_line}"
    );
}

#[tokio::test]
async fn the_credential_gate_does_not_ask_about_the_placeholder_the_signer_replaces() {
    // `signing_state` indexes the placeholder as a credential's, as the policy
    // does for an AWS connection. It sits in the Authorization header the
    // signer replaces, so it never leaves and the gate has nothing to ask.
    let (state, audit_rx) = signing_state(TEST_HOSTNAME);
    let (upstream, _, audits) = run_signed(
        state,
        audit_rx,
        TEST_HOSTNAME,
        vec![],
        sandbox_signed_request(&HarnessRequest::default()),
    )
    .await;
    assert!(
        upstream.contains("Credential=ASIAREALEXAMPLE/"),
        "{upstream}"
    );
    assert_eq!(audits.len(), 1, "{audits:?}");
    assert_eq!(audits[0]["result"], "success");
    assert_eq!(audits[0]["metadata"]["aws_resign"], true);
    assert_eq!(audits[0]["metadata"]["service"], "s3");
}

#[tokio::test]
async fn a_token_request_to_a_host_whose_requests_are_re_signed_is_answered() {
    let (state, audit_rx) = signing_state(TEST_HOSTNAME);
    state
        .token_answers
        .write()
        .unwrap()
        .insert(TEST_HOSTNAME.to_string(), vec![token_answer("api.default")]);
    let body = "grant_type=client_credentials&client_id=client-1&scope=api.default";
    let request = format!(
        "POST /oauth2/token HTTP/1.1\r\nHost: {TEST_HOSTNAME}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let (outcome, client, audits) =
        run_signed(state, audit_rx, TEST_HOSTNAME, vec![], request.into_bytes()).await;

    assert!(outcome.contains("answered by the proxy"), "{outcome}");
    assert!(client.starts_with("HTTP/1.1 200 OK\r\n"), "{client}");
    assert!(client.contains("placeholder-token"), "{client}");
    assert_eq!(audits[0]["metadata"]["token_answered"], true);
}

#[tokio::test]
async fn a_non_s3_body_over_the_cap_is_refused_with_413() {
    let len = crate::signing::MAX_SIGNED_BODY_BYTES + 1;
    let head = placeholder_signed_head("POST", "dynamodb", &format!("Content-Length: {len}\r\n"));
    // The body is never sent: the pipeline answers from the declared length.
    let (client, audits) = refusal_of(head.into_bytes()).await;
    assert!(client.starts_with("HTTP/1.1 413 "), "{client}");
    assert_eq!(audits[0]["status_code"], 413);
    assert_eq!(audits[0]["metadata"]["signing_refused"], true);
}

#[tokio::test]
async fn a_chunked_non_s3_body_is_refused_with_411() {
    let mut request = placeholder_signed_head("POST", "dynamodb", "Transfer-Encoding: chunked\r\n");
    request.push_str("0\r\n\r\n");
    let (client, _) = refusal_of(request.into_bytes()).await;
    assert!(client.starts_with("HTTP/1.1 411 "), "{client}");
}

#[tokio::test]
async fn s3_streaming_payload_signing_is_refused_with_501() {
    // `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` embeds per-chunk signatures inside
    // the body framing, seeded by the outer signature, which re-signing cannot
    // rewrite. The signature bytes do not matter: it is refused before signing.
    let request = format!(
        "PUT /my-bucket/my-object HTTP/1.1\r\n\
         Host: {TEST_HOSTNAME}\r\n\
         Content-Length: 100\r\n\
         Authorization: AWS4-HMAC-SHA256 \
         Credential={PLACEHOLDER}/20230101/us-east-1/s3/aws4_request, \
         SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
         Signature=00\r\n\
         X-Amz-Date: 20230101T000000Z\r\n\
         X-Amz-Content-Sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD\r\n\
         Connection: close\r\n\r\n"
    );
    let (client, _) = refusal_of(request.into_bytes()).await;
    assert!(client.starts_with("HTTP/1.1 501 "), "{client}");
}

#[tokio::test]
async fn an_unknown_placeholder_key_is_refused_with_401() {
    let unknown = AwsSigv4Config {
        access_key_id: "LENSFAKEUNKNOWN00001".to_string(),
        ..fake_config()
    };
    let headers = vec![("host".to_string(), TEST_HOSTNAME.to_string())];
    let req = ResignRequest {
        method: "GET",
        uri: "/",
        service: "s3",
        region: "us-east-1",
        headers: &headers,
        body_mode: BodyMode::Unsigned,
    };
    let signed = resign_request(&req, &unknown, std::time::SystemTime::now()).unwrap();
    let mut request = format!("GET / HTTP/1.1\r\nHost: {TEST_HOSTNAME}\r\n");
    for (k, v) in &signed {
        request.push_str(&format!("{k}: {v}\r\n"));
    }
    request.push_str("\r\n");
    let (client, _) = refusal_of(request.into_bytes()).await;
    assert!(client.starts_with("HTTP/1.1 401 "), "{client}");
}

#[tokio::test]
async fn a_request_signed_with_a_real_key_is_refused_with_401() {
    // Only a placeholder is the proxy's to replace. A real key in the sandbox
    // is not something to sign over.
    let real = AwsSigv4Config {
        access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
        ..fake_config()
    };
    let headers = vec![("host".to_string(), TEST_HOSTNAME.to_string())];
    let req = ResignRequest {
        method: "GET",
        uri: "/",
        service: "s3",
        region: "us-east-1",
        headers: &headers,
        body_mode: BodyMode::Unsigned,
    };
    let signed = resign_request(&req, &real, std::time::SystemTime::now()).unwrap();
    let mut request = format!("GET / HTTP/1.1\r\nHost: {TEST_HOSTNAME}\r\n");
    for (k, v) in &signed {
        request.push_str(&format!("{k}: {v}\r\n"));
    }
    request.push_str("\r\n");
    let (client, _) = refusal_of(request.into_bytes()).await;
    assert!(client.starts_with("HTTP/1.1 401 "), "{client}");
}

#[tokio::test]
async fn a_request_that_declares_no_length_is_signed_for_an_empty_body() {
    // A request with neither Content-Length nor Transfer-Encoding has no body
    // (RFC 9112 §6.3). The relay forwards nothing after the head, so an empty
    // body is exactly what the origin receives and what the signature covers.
    let spec = HarnessRequest {
        method: "GET",
        uri: "/",
        service: "ec2",
        signed_with_unsigned_payload: false,
        ..Default::default()
    };
    let request = String::from_utf8(sandbox_signed_request(&spec))
        .unwrap()
        .replace("Content-Length: 0\r\n", "");
    let (state, audit_rx) = signing_state(TEST_HOSTNAME);
    let (upstream, _, _) =
        run_signed(state, audit_rx, TEST_HOSTNAME, vec![], request.into_bytes()).await;
    let (head, body) = upstream.split_once("\r\n\r\n").unwrap();
    assert!(body.is_empty(), "{body}");
    assert!(
        !head.to_ascii_lowercase().contains("content-length"),
        "the head is left as the client wrote it: {head}"
    );
    crate::signing::verify_signature(head, b"", &real_config())
        .expect("mock AWS must accept a request signed for an empty body");
}

#[tokio::test]
async fn a_body_a_rule_already_read_is_the_body_that_is_signed() {
    let (head, body) = upstream_of(
        &HarnessRequest {
            method: "POST",
            uri: "/graphql",
            body: QUERY.as_bytes(),
            service: "appsync",
            signed_with_unsigned_payload: false,
            ..Default::default()
        },
        appsync_query_rule(),
    )
    .await;

    assert!(head.contains("POST /graphql HTTP/1.1"), "head: {head}");
    assert_eq!(String::from_utf8_lossy(&body), QUERY);
    crate::signing::verify_signature(&head, &body, &real_config())
        .expect("mock AWS must accept the re-signed AppSync request");
}

#[tokio::test]
async fn a_request_its_rules_refuse_is_never_signed_or_sent() {
    let request = sandbox_signed_request(&HarnessRequest {
        method: "POST",
        uri: "/graphql",
        body: MUTATION.as_bytes(),
        service: "appsync",
        signed_with_unsigned_payload: false,
        ..Default::default()
    });
    let (state, audit_rx) = signing_state(TEST_HOSTNAME);
    let (_, client, audits) = run_signed(
        state,
        audit_rx,
        TEST_HOSTNAME,
        appsync_query_rule(),
        request,
    )
    .await;
    crate::blocked::tests::assert_blocked(
        &client,
        crate::blocked::BlockReason::PolicyDeny,
        &format!(
            "Blocked by sandbox egress policy: POST {TEST_HOSTNAME}/graphql \
             (reason: policy-deny). This is not a response from {TEST_HOSTNAME}."
        ),
    );
    assert_eq!(audits[0]["metadata"]["graphql_denied"], true);
}

#[tokio::test]
async fn a_re_signed_request_cannot_open_a_connection_upgrade() {
    let request = format!(
        "GET /realtime HTTP/1.1\r\nHost: {TEST_HOSTNAME}\r\n\
         Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
    );
    let (state, audit_rx) = signing_state(TEST_HOSTNAME);
    let (reason, _, _) =
        run_signed(state, audit_rx, TEST_HOSTNAME, vec![], request.into_bytes()).await;
    assert!(reason.contains("connection upgrade"), "{reason}");
}

/// A rule permitting read-only GraphQL on `/graphql`, as an AppSync policy
/// would write it.
fn appsync_query_rule() -> Vec<HttpRule> {
    use crate::policy_schema::{GraphqlMatcher, GraphqlOperationTypeMatcher};
    vec![HttpRule {
        method: Some("POST".to_string()),
        path: Some("/graphql".to_string()),
        graphql: Some(GraphqlMatcher {
            operation_type: GraphqlOperationTypeMatcher::Query,
            operation_name: None,
            fields: vec![],
            arguments: vec![],
        }),
        mcp: None,
    }]
}

const QUERY: &str = r#"{"query":"query Q { listThings { id } }"}"#;
const MUTATION: &str = r#"{"query":"mutation M { deleteThing(id: 1) }"}"#;

// ---- mock-AWS cryptographic verification ----
//
// The tests above prove the re-signed request *looks* valid.
// `verify_signature` acts as a mock AWS endpoint: it rebuilds the canonical
// request from what actually arrived on the wire and checks the signature.

#[tokio::test]
async fn mock_aws_validates_a_re_signed_s3_signature() {
    let (head, body) = upstream_of(&HarnessRequest::default(), vec![]).await;
    crate::signing::verify_signature(&head, &body, &real_config())
        .expect("mock AWS must accept the re-signed S3 request");
}

#[tokio::test]
async fn mock_aws_validates_a_re_signed_dynamodb_signature() {
    let extra_signed = vec![(
        "x-amz-target".to_string(),
        "DynamoDB_20120810.PutItem".to_string(),
    )];
    let (head, body) = upstream_of(
        &HarnessRequest {
            method: "POST",
            uri: "/",
            body: b"{\"TableName\":\"demo\"}",
            service: "dynamodb",
            signed_with_unsigned_payload: false,
            extra_signed: &extra_signed,
            ..Default::default()
        },
        vec![],
    )
    .await;
    crate::signing::verify_signature(&head, &body, &real_config())
        .expect("mock AWS must accept the re-signed DynamoDB request with x-amz-target");

    // Swap x-amz-target's value after signing: the verifier must notice, as
    // a real DynamoDB endpoint would.
    let tampered = head.replace("DynamoDB_20120810.PutItem", "DynamoDB_20120810.DeleteItem");
    assert_ne!(tampered, head);
    assert!(crate::signing::verify_signature(&tampered, &body, &real_config()).is_err());
}

#[tokio::test]
async fn mock_aws_rejects_a_signature_computed_with_another_secret() {
    let (head, body) = upstream_of(&HarnessRequest::default(), vec![]).await;
    let wrong = AwsSigv4Config {
        secret_access_key: "a-different-secret-key".to_string(),
        ..real_config()
    };
    assert!(crate::signing::verify_signature(&head, &body, &wrong).is_err());
}

#[tokio::test]
async fn a_request_keeps_the_region_its_client_signed_for() {
    // When the client signs for a region other than the connection's default
    // (e.g. `--region eu-west-1`), the upstream request must carry that same
    // region in the credential scope. Otherwise AWS rejects with "Credential
    // should be scoped to a valid region" on STS/CloudWatch or "AuthFailure"
    // on EC2.
    let (head, body) = upstream_of(
        &HarnessRequest {
            method: "GET",
            uri: "/",
            service: "ec2",
            signed_with_unsigned_payload: false,
            hostname: "ec2.eu-west-1.amazonaws.com",
            region: "eu-west-1",
            ..Default::default()
        },
        vec![],
    )
    .await;

    assert!(
        head.contains("/eu-west-1/ec2/aws4_request"),
        "upstream Authorization must be scoped to eu-west-1, got: {head}"
    );
    assert!(!head.contains("/us-east-1/"), "{head}");
    crate::signing::verify_signature(&head, &body, &real_config())
        .expect("mock AWS at eu-west-1 must accept the re-signed request");
}
