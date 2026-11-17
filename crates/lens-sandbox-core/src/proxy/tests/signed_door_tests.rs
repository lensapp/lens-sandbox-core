//! A host whose requests are re-signed, reached through the doors that do not
//! open a `CONNECT` tunnel: transparent TLS and absolute-form `https://`.

use super::*;
use crate::aws_sigv4::{AwsSigv4Config, BodyMode, ResignRequest, resign_request};
use rustls::pki_types::pem::PemObject;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HOST: &str = "s3.us-east-1.amazonaws.com";
const TARGET: &str = "s3.us-east-1.amazonaws.com:443";
const PLACEHOLDER: &str = "LENSFAKE00AABB0000CC";
const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

fn real_keys() -> AwsSigv4Config {
    AwsSigv4Config {
        access_key_id: "ASIAREALEXAMPLE".to_string(),
        secret_access_key: "real-secret-example".to_string(),
        session_token: "real-session-token".to_string(),
    }
}

/// A proxy that re-signs `HOST`, whose dials reach an origin that answers one
/// request with `OK`. The handle gives the head the origin was sent.
async fn signing_origin() -> (Arc<ProxyState>, tokio::task::JoinHandle<String>) {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (state, _rx) = test_state_on(TestNetwork::Serving {
        name: HOST,
        target: "203.0.113.9:443".parse().unwrap(),
        origin: origin.local_addr().unwrap(),
    });
    install_catch_all_allow(&state);
    state.aws_signer.update(
        std::collections::HashMap::from([(PLACEHOLDER.to_string(), real_keys())]),
        vec![HOST.to_string()],
    );
    let ca = get_or_init_ca(&state).unwrap();
    *state.extra_ca_certs.write().unwrap() =
        rustls::pki_types::CertificateDer::pem_slice_iter(ca.ca_cert_pem().as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
    let origin_tls = crate::mitm::build_ephemeral_server_config(ca, HOST).unwrap();
    let served = tokio::spawn(async move {
        let (tcp, _) = origin.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(origin_tls)
            .accept(tcp)
            .await
            .unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(tls.read_u8().await.unwrap());
        }
        tls.write_all(OK).await.unwrap();
        tls.shutdown().await.ok();
        String::from_utf8(head).unwrap()
    });
    (state, served)
}

/// A `GET` to `HOST` that the sandbox signed with the placeholder key, as
/// `request_line` names it.
fn placeholder_signed(request_line: &str) -> Vec<u8> {
    let placeholder = AwsSigv4Config {
        access_key_id: PLACEHOLDER.to_string(),
        secret_access_key: "placeholder-secret".to_string(),
        session_token: "placeholder-session-token".to_string(),
    };
    let signed = resign_request(
        &ResignRequest {
            method: "GET",
            uri: "/my-bucket",
            service: "s3",
            region: "us-east-1",
            headers: &[("host".to_string(), HOST.to_string())],
            body_mode: BodyMode::Unsigned,
        },
        &placeholder,
        std::time::SystemTime::now(),
    )
    .unwrap();
    let mut request = format!("{request_line}\r\nHost: {HOST}\r\n");
    for (name, value) in &signed {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.into_bytes()
}

fn assert_signed_with_the_real_key(head: &str) {
    assert!(head.contains("Credential=ASIAREALEXAMPLE/"), "{head}");
    assert!(!head.contains(PLACEHOLDER), "{head}");
    crate::signing::verify_signature(head.trim_end_matches("\r\n"), b"", &real_keys())
        .expect("the origin gets a head signed with the real key");
}

#[tokio::test]
async fn a_transparent_tls_request_to_a_signed_host_is_re_signed() {
    let (state, served) = signing_origin().await;
    let (stream, _handler) = transparent_tls_connection(&state).await;
    let mut tls = sandbox_tls_client(&state, stream, HOST).await;
    tls.write_all(&placeholder_signed("GET /my-bucket HTTP/1.1"))
        .await
        .unwrap();
    let mut answer = Vec::new();
    let _ = tls.read_to_end(&mut answer).await;

    assert_signed_with_the_real_key(&served.await.unwrap());
    assert!(String::from_utf8_lossy(&answer).ends_with("ok"));
}

#[tokio::test]
async fn an_absolute_https_request_to_a_signed_host_is_re_signed() {
    let (state, served) = signing_origin().await;
    let (mut client, server) = socket_pair().await;
    let head = placeholder_signed(&format!("GET https://{HOST}/my-bucket HTTP/1.1"));
    tokio::spawn(
        async move { handle_https_forward(server, TARGET, head, &state, &test_actor()).await },
    );
    let mut answer = Vec::new();
    let _ = client.read_to_end(&mut answer).await;

    assert_signed_with_the_real_key(&served.await.unwrap());
    assert!(String::from_utf8_lossy(&answer).ends_with("ok"));
}
