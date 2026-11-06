//! A `forward` route: the MITM judges the request as for any host, then sends it
//! to the address the route names, with the route's client certificate.

use super::*;
use crate::routing::HttpRule;
use rustls::pki_types::PrivateKeyDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const HOST: &str = "api.example.test";
const TARGET: &str = "api.example.test:443";
const SERVER_NAME: &str = "kube-api.internal";
const GATEWAY_HOST: &str = "rancher.example.test";
const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
const SWITCHING: &[u8] =
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n";

/// An origin that completes TLS only with a client that presents the
/// certificate of the returned forward route. It answers one request with
/// `answer`, and after a `101` it echoes four bytes. The handle gives the head
/// it was sent, or `None` when the client presented no certificate.
async fn origin(
    answer: &'static [u8],
) -> (ClientCertConfig, tokio::task::JoinHandle<Option<String>>) {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issue = |name: &str| {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec![name.to_string()])
            .unwrap()
            .signed_by(&key, &ca, &ca_key)
            .unwrap();
        (
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
    };
    let (server_chain, server_key) = issue(SERVER_NAME);
    let (client_chain, client_key) = issue("sandbox");

    let mut client_roots = rustls::RootCertStore::empty();
    client_roots.add(ca.der().clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .unwrap();
    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_chain, server_key)
        .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let forward = ClientCertConfig {
        cert_chain: client_chain,
        private_key: client_key,
        ca_certs: vec![ca.der().clone()],
        dial_addr: listener.local_addr().unwrap().to_string(),
        tls_server_name: SERVER_NAME.to_string(),
        upstream_host_header: Some(GATEWAY_HOST.to_string()),
    };
    let served = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(tcp)
            .await
            .ok()?;
        let head = read_head(&mut tls).await;
        tls.write_all(answer).await.unwrap();
        if answer == SWITCHING {
            let mut frame = [0u8; 4];
            tls.read_exact(&mut frame).await.unwrap();
            tls.write_all(&frame).await.unwrap();
        }
        tls.shutdown().await.ok();
        Some(head)
    });
    (forward, served)
}

async fn read_head<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.unwrap());
    }
    String::from_utf8(head).unwrap()
}

/// Send what `sandbox` writes through the MITM to a forwarded `HOST`, and
/// return what `sandbox` read back.
async fn through_the_mitm<F>(
    http_rules: Vec<HttpRule>,
    forward: ClientCertConfig,
    sandbox: impl FnOnce(DuplexStream) -> F,
) -> String
where
    F: std::future::Future<Output = String>,
{
    let (state, _rx) = test_state();
    let ca = get_or_init_ca(&state).unwrap();
    let audit_tx = state.audit_tx.lock().unwrap().clone();
    let actor = test_actor();
    let ctx = crate::mitm::MitmContext {
        injections: &[],
        http_rules: &http_rules,
        ca,
        audit_tx: &audit_tx,
        extra_ca_certs: &[],
        placeholder_map: &[],
        state: &state,
        match_host: TARGET,
        actor: &actor,
        gate_deferred: false,
    };
    let (sandbox_end, proxy_end) = tokio::io::duplex(64 * 1024);
    let mode = crate::mitm::UpstreamMode::DirectTls {
        host: HOST.to_string(),
        port: 443,
        forward: Some(forward),
    };
    let (_, answer) = tokio::join!(
        crate::mitm::handle_mitm_pre_accepted(proxy_end, HOST, mode, &ctx),
        sandbox(sandbox_end),
    );
    answer
}

async fn request(mut sandbox: DuplexStream, head: &'static str) -> String {
    sandbox.write_all(head.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let _ = sandbox.read_to_end(&mut answer).await;
    String::from_utf8(answer).unwrap()
}

const KUBECONFIG_GET: &str = "GET /api/v1/pods HTTP/1.1\r\nHost: api.example.test\r\n\
                              Authorization: Bearer lens-sandbox-proxy-auth\r\n\r\n";

#[tokio::test]
async fn a_forwarded_request_reaches_the_route_address_with_its_client_certificate() {
    let (forward, served) = origin(OK).await;
    let answer = through_the_mitm(vec![], forward, |s| request(s, KUBECONFIG_GET)).await;

    let head = served
        .await
        .unwrap()
        .expect("the origin must see the client certificate");
    assert!(head.starts_with("GET /api/v1/pods HTTP/1.1\r\n"), "{head}");
    assert!(
        head.contains(&format!("Host: {GATEWAY_HOST}\r\n")),
        "{head}"
    );
    assert!(
        !head.to_ascii_lowercase().contains("authorization"),
        "the kubeconfig's dummy token stays behind: {head}"
    );
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
    assert!(answer.ends_with("ok"), "{answer}");
}

#[tokio::test]
async fn the_route_rules_judge_a_forwarded_request_before_it_is_sent() {
    let (forward, served) = origin(OK).await;
    let reads_only = vec![HttpRule {
        method: Some("GET".to_string()),
        path: None,
        graphql: None,
        mcp: None,
    }];
    let answer = through_the_mitm(reads_only, forward, |s| {
        request(
            s,
            "DELETE /api/v1/pods/x HTTP/1.1\r\nHost: api.example.test\r\n\r\n",
        )
    })
    .await;

    assert!(answer.starts_with("HTTP/1.1 403 "), "{answer}");
    assert!(
        tokio::time::timeout(Duration::from_millis(200), served)
            .await
            .is_err(),
        "a refused request must not reach the origin"
    );
}

#[tokio::test]
async fn an_upgrade_on_a_forwarded_host_is_relayed_both_ways() {
    // `kubectl exec` and `port-forward` upgrade the connection.
    let (forward, served) = origin(SWITCHING).await;
    let answer = through_the_mitm(vec![], forward, |mut sandbox| async move {
        sandbox
            .write_all(
                b"POST /api/v1/namespaces/default/pods/p/exec HTTP/1.1\r\n\
                  Host: api.example.test\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n",
            )
            .await
            .unwrap();
        let head = read_head(&mut sandbox).await;
        sandbox.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        sandbox.read_exact(&mut echo).await.unwrap();
        format!("{head}{}", String::from_utf8_lossy(&echo))
    })
    .await;

    let head = served.await.unwrap().expect("client certificate");
    assert!(head.contains("Upgrade: SPDY/3.1"), "{head}");
    assert!(answer.starts_with("HTTP/1.1 101 "), "{answer}");
    assert!(answer.ends_with("ping"), "{answer}");
}

/// A policy that sends `HOST` direct, through `forward`.
fn forwarding_state(forward: ClientCertConfig) -> Arc<ProxyState> {
    let (state, _rx) = test_state();
    install_catch_all_allow(&state);
    state
        .client_certs
        .write()
        .unwrap()
        .insert(TARGET.to_string(), forward);
    get_or_init_ca(&state).unwrap();
    state
}

#[tokio::test]
async fn a_connect_to_a_forwarded_host_gets_its_credentials_and_its_client_certificate() {
    // The injected credential replaces the kubeconfig's dummy token, and the
    // client certificate goes on the same connection.
    let (forward, served) = origin(OK).await;
    let state = forwarding_state(forward);
    state.credential_injections.write().unwrap().insert(
        HOST.to_string(),
        vec![CredentialInjection {
            header: "Authorization".to_string(),
            value: "Bearer real-token".to_string(),
            body: None,
            rules: vec![],
        }],
    );
    let (mut client, server) = socket_pair().await;
    let handler_state = state.clone();
    tokio::spawn(
        async move { handle_connect(server, TARGET, &test_actor(), &handler_state).await },
    );

    let established = read_head(&mut client).await;
    assert!(established.starts_with("HTTP/1.1 200"), "{established}");
    let mut tls = sandbox_tls_client(&state, client, HOST).await;
    tls.write_all(KUBECONFIG_GET.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let _ = tls.read_to_end(&mut answer).await;

    let head = served.await.unwrap().expect("client certificate");
    assert!(head.contains("Authorization: Bearer real-token"), "{head}");
    assert!(!head.contains("lens-sandbox-proxy-auth"), "{head}");
    assert!(
        head.contains(&format!("Host: {GATEWAY_HOST}\r\n")),
        "{head}"
    );
    assert!(String::from_utf8_lossy(&answer).ends_with("ok"));
}

#[tokio::test]
async fn an_absolute_https_request_to_a_forwarded_host_is_forwarded() {
    let (forward, served) = origin(OK).await;
    let state = forwarding_state(forward);
    let (mut client, server) = socket_pair().await;
    let head =
        b"GET https://api.example.test/api/v1/pods HTTP/1.1\r\nHost: api.example.test\r\n\r\n";
    tokio::spawn(async move {
        handle_https_forward(server, TARGET, head.to_vec(), &state, &test_actor()).await
    });

    let mut answer = Vec::new();
    let _ = client.read_to_end(&mut answer).await;
    let head = served.await.unwrap().expect("client certificate");
    assert!(head.starts_with("GET /api/v1/pods HTTP/1.1\r\n"), "{head}");
    assert!(String::from_utf8_lossy(&answer).ends_with("ok"));
}

#[tokio::test]
async fn a_transparent_tls_connection_to_a_forwarded_host_is_forwarded() {
    let (forward, served) = origin(OK).await;
    let state = forwarding_state(forward);
    let (stream, _handler) = transparent_tls_connection(&state).await;
    let mut tls = sandbox_tls_client(&state, stream, HOST).await;
    tls.write_all(KUBECONFIG_GET.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let _ = tls.read_to_end(&mut answer).await;

    let head = served.await.unwrap().expect("client certificate");
    assert!(
        head.contains(&format!("Host: {GATEWAY_HOST}\r\n")),
        "{head}"
    );
    assert!(String::from_utf8_lossy(&answer).ends_with("ok"));
}
