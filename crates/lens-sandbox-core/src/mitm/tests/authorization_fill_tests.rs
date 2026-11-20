//! An `authorizationPlaceholder` injection fills its placeholder where the
//! request's `Authorization` header carries it, and changes no other request.

use super::*;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

const PLACEHOLDER: &str = "lnshub_LNSPLACEHOLDER0000000000";
const LOGIN: &str = "lnshub_pat_some-login";

fn fill(username: &str) -> Vec<CredentialInjection> {
    vec![CredentialInjection {
        header: "Authorization".to_string(),
        value: LOGIN.to_string(),
        body: None,
        rules: vec![],
        fills: Some(crate::proxy::AuthorizationFill {
            placeholder: PLACEHOLDER.to_string(),
            username: username.to_string(),
        }),
    }]
}

fn basic(user: &str, password: &str) -> String {
    format!("Basic {}", BASE64.encode(format!("{user}:{password}")))
}

fn request(path: &str, authorization: Option<&str>) -> String {
    let mut head = format!("GET {path} HTTP/1.1\r\nHost: hub.some-hub.example");
    if let Some(value) = authorization {
        head.push_str(&format!("\r\nAuthorization: {value}"));
    }
    head.push_str("\r\nAccept: */*");
    head
}

fn authorizations(head: &str) -> Vec<&str> {
    head.split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.trim())
        .collect()
}

#[test]
fn given_a_bearer_placeholder_when_the_request_passes_then_it_carries_the_login() {
    let head = request("/api/v1/me", Some(&format!("Bearer {PLACEHOLDER}")));

    let sent = inject_headers(&head, &fill("some-user"));

    assert_eq!(authorizations(&sent), [format!("Bearer {LOGIN}")]);
}

#[test]
fn given_a_basic_placeholder_password_when_the_request_passes_then_it_carries_the_stored_user_and_the_login()
 {
    let head = request("/token?service=hub", Some(&basic("x", PLACEHOLDER)));

    let sent = inject_headers(&head, &fill("some-fleet/some-sub"));

    assert_eq!(authorizations(&sent), [basic("some-fleet/some-sub", LOGIN)]);
}

#[test]
fn given_a_lowercase_scheme_and_header_name_when_the_request_passes_then_the_placeholder_is_filled()
{
    let head = format!(
        "GET /token HTTP/1.1\r\nHost: hub.some-hub.example\r\nauthorization: basic {}",
        BASE64.encode(format!("x:{PLACEHOLDER}"))
    );

    let sent = inject_headers(&head, &fill("some-user"));

    assert_eq!(authorizations(&sent), [basic("some-user", LOGIN)]);
}

#[test]
fn given_a_real_bearer_token_when_the_request_passes_then_it_is_unchanged() {
    let head = request("/api/v1/me", Some("Bearer lnshub_pat_the-workloads-own"));

    let sent = inject_headers(&head, &fill("some-user"));

    assert_eq!(
        authorizations(&sent),
        ["Bearer lnshub_pat_the-workloads-own"]
    );
}

#[test]
fn given_a_real_basic_password_when_the_request_passes_then_it_is_unchanged() {
    let head = request("/token", Some(&basic("x", "lnshub_pat_the-workloads-own")));

    let sent = inject_headers(&head, &fill("some-user"));

    assert_eq!(
        authorizations(&sent),
        [basic("x", "lnshub_pat_the-workloads-own")]
    );
}

#[test]
fn given_the_registry_jwt_on_v2_when_the_request_passes_then_it_is_unchanged() {
    let head = request(
        "/v2/some-ns/some-repo/manifests/latest",
        Some("Bearer eyJhbGciOiJIUzI1NiJ9.e30.c2lnbmF0dXJl"),
    );

    let sent = inject_headers(&head, &fill("some-user"));

    assert_eq!(
        authorizations(&sent),
        ["Bearer eyJhbGciOiJIUzI1NiJ9.e30.c2lnbmF0dXJl"]
    );
}

#[test]
fn given_no_authorization_header_when_the_request_passes_then_none_is_added() {
    let head = request("/v2/", None);

    let sent = inject_headers(&head, &fill("some-user"));

    assert!(authorizations(&sent).is_empty(), "{sent}");
}

#[test]
fn given_the_placeholder_in_the_request_line_when_the_request_passes_then_it_is_not_filled() {
    let head = request(&format!("/token?account={PLACEHOLDER}"), None);

    let sent = inject_headers(&head, &fill("some-user"));

    assert!(
        sent.starts_with(&format!("GET /token?account={PLACEHOLDER} ")),
        "{sent}"
    );
    assert!(!sent.contains(LOGIN), "{sent}");
}

#[test]
fn given_the_placeholder_in_another_header_when_the_request_passes_then_it_is_not_filled() {
    let head = format!("{}\r\nX-Token: {PLACEHOLDER}", request("/api", None));

    let sent = inject_headers(&head, &fill("some-user"));

    assert!(sent.contains(&format!("X-Token: {PLACEHOLDER}")), "{sent}");
    assert!(!sent.contains(LOGIN), "{sent}");
}

#[test]
fn given_a_bearer_placeholder_with_more_after_it_when_the_request_passes_then_it_is_unchanged() {
    let carried = format!("Bearer {PLACEHOLDER}extra");
    let head = request("/api", Some(&carried));

    let sent = inject_headers(&head, &fill("some-user"));

    assert_eq!(authorizations(&sent), [carried.as_str()]);
}

#[test]
fn given_two_authorization_headers_when_the_request_passes_then_only_the_one_with_the_placeholder_is_filled()
 {
    let head = format!(
        "{}\r\nAuthorization: Bearer {PLACEHOLDER}",
        request("/api", Some("Bearer some-other-token"))
    );

    let sent = inject_headers(&head, &fill("some-user"));

    assert_eq!(
        authorizations(&sent),
        [
            "Bearer some-other-token".to_string(),
            format!("Bearer {LOGIN}")
        ]
    );
}

#[test]
fn given_a_basic_token_that_is_not_base64_when_the_request_passes_then_it_is_unchanged() {
    let head = request("/token", Some("Basic !!!not-base64!!!"));

    let sent = inject_headers(&head, &fill("some-user"));

    assert_eq!(authorizations(&sent), ["Basic !!!not-base64!!!"]);
}

#[test]
fn given_an_unarmed_placeholder_as_a_basic_password_when_the_request_is_scanned_then_its_credential_is_gated()
 {
    let state = make_test_state_with_placeholder("hub", PLACEHOLDER);
    let head = request("/token", Some(&basic("x", PLACEHOLDER)));

    let gated = scan_for_unarmed_placeholders(&state, &head);

    assert_eq!(gated.len(), 1);
    assert_eq!(gated[0].credential_id, "hub");
}

fn with_the_fill(login: &str) -> std::sync::Arc<crate::proxy::ProxyState> {
    let (state, _rx) = crate::proxy::tests::test_state();
    let mut fills = fill("some-user");
    fills[0].value = login.to_string();
    state
        .credential_injections
        .write()
        .unwrap()
        .insert("hub.some-hub.example".to_string(), fills);
    state
}

fn resend(head: String) -> Resend {
    Resend {
        head,
        sent: fill("some-user"),
        match_host: "hub.some-hub.example".to_string(),
        placeholders: vec![],
        mcp: None,
        body_len: None,
    }
}

#[test]
fn given_a_renewed_login_when_a_request_carried_the_placeholder_then_it_is_sent_again_with_the_new_login()
 {
    let state = with_the_fill("lnshub_pat_renewed");
    let carried = resend(request("/token", Some(&basic("x", PLACEHOLDER))));

    let again = carried.renewed_head(&state).expect("sent again");

    assert_eq!(
        authorizations(&again),
        [basic("some-user", "lnshub_pat_renewed")]
    );
}

#[test]
fn given_a_renewed_login_when_a_request_carried_the_registry_jwt_then_it_is_not_sent_again() {
    let state = with_the_fill("lnshub_pat_renewed");
    let carried = resend(request(
        "/v2/",
        Some("Bearer eyJhbGciOiJIUzI1NiJ9.e30.c2ln"),
    ));

    assert!(carried.renewed_head(&state).is_none());
}
