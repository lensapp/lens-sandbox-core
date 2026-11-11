//! A `forward` route: the MITM judges the request as for any host, then sends it
//! to the address the route names, with the route's client certificate.

use super::*;
use crate::routing::HttpRule;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::pem::PemObject;
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
    let (forward, served) = origin_answering(vec![answer], || {}).await;
    let first = tokio::spawn(async move { served.await.unwrap().into_iter().next() });
    (forward, first)
}

/// [`origin`], answering its `n`th connection with `answers[n]`, and calling
/// `on_request` once it has read each request. The handle gives the heads it
/// was sent, up to the first client that presented no certificate.
async fn origin_answering(
    answers: Vec<&'static [u8]>,
    on_request: impl Fn() + Send + 'static,
) -> (ClientCertConfig, tokio::task::JoinHandle<Vec<String>>) {
    let (forward, listener, acceptor) = mtls_origin().await;
    let served = tokio::spawn(async move {
        let mut heads = Vec::new();
        for answer in answers {
            let (tcp, _) = listener.accept().await.unwrap();
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                break;
            };
            heads.push(read_head(&mut tls).await);
            on_request();
            tls.write_all(answer).await.unwrap();
            if answer == SWITCHING {
                let mut frame = [0u8; 4];
                tls.read_exact(&mut frame).await.unwrap();
                tls.write_all(&frame).await.unwrap();
            }
            tls.shutdown().await.ok();
        }
        heads
    });
    (forward, served)
}

/// A forward route, and the listener and TLS acceptor of an origin that
/// accepts only the route's client certificate.
async fn mtls_origin() -> (
    ClientCertConfig,
    tokio::net::TcpListener,
    tokio_rustls::TlsAcceptor,
) {
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
    (
        forward,
        listener,
        tokio_rustls::TlsAcceptor::from(Arc::new(config)),
    )
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
    state: &Arc<ProxyState>,
    injections: &[CredentialInjection],
    http_rules: Vec<HttpRule>,
    forward: ClientCertConfig,
    sandbox: impl FnOnce(DuplexStream) -> F,
) -> String
where
    F: std::future::Future<Output = String>,
{
    let ca = get_or_init_ca(state).unwrap();
    // An `llm` backend in these tests serves a certificate from the proxy's CA.
    let trusted: Vec<_> =
        rustls::pki_types::CertificateDer::pem_slice_iter(ca.ca_cert_pem().as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
    let audit_tx = state.audit_tx.lock().unwrap().clone();
    let actor = test_actor();
    let ctx = crate::mitm::MitmContext {
        injections,
        http_rules: &http_rules,
        ca,
        audit_tx: &audit_tx,
        extra_ca_certs: &trusted,
        placeholder_map: &[],
        state,
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

async fn request(mut sandbox: DuplexStream, request: impl Into<Vec<u8>>) -> String {
    sandbox.write_all(&request.into()).await.unwrap();
    let mut answer = Vec::new();
    let _ = sandbox.read_to_end(&mut answer).await;
    String::from_utf8(answer).unwrap()
}

const KUBECONFIG_GET: &str = "GET /api/v1/pods HTTP/1.1\r\nHost: api.example.test\r\n\
                              Authorization: Bearer lens-sandbox-proxy-auth\r\n\r\n";

#[tokio::test]
async fn a_forwarded_request_reaches_the_route_address_with_its_client_certificate() {
    let (forward, served) = origin(OK).await;
    let (state, mut audits) = test_state();
    let answer =
        through_the_mitm(&state, &[], vec![], forward, |s| request(s, KUBECONFIG_GET)).await;

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

    // Recorded as any intercepted request is, with what the origin answered.
    let audits = drain_audit_lines(&mut audits);
    let forwarded: Vec<_> = audits.iter().filter(|e| e["result"] == "success").collect();
    assert_eq!(forwarded.len(), 1, "{audits:?}");
    let event = forwarded[0];
    assert!(
        event["action"].as_str().unwrap().starts_with("GET "),
        "{event}"
    );
    assert_eq!(event["metadata"]["mitm"], true, "{event}");
    assert_eq!(event["metadata"]["tls_bridge"], true, "{event}");
    assert_eq!(event["upstream_status_code"], 200, "{event}");
}

fn bearer(token: &str) -> Vec<CredentialInjection> {
    vec![CredentialInjection {
        header: "Authorization".to_string(),
        value: format!("Bearer {token}"),
        body: None,
        rules: vec![],
    }]
}

#[tokio::test]
async fn a_401_to_a_renewed_credential_is_sent_again_through_the_forward() {
    const UNAUTHORIZED: &[u8] =
        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let (state, mut audits) = test_state();
    let injections = bearer("old-token");
    state
        .credential_injections
        .write()
        .unwrap()
        .insert(HOST.to_string(), injections.clone());
    // The credential is renewed while the origin holds the first request.
    let renewing = state.clone();
    let (forward, served) = origin_answering(vec![UNAUTHORIZED, OK], move || {
        renewing
            .credential_injections
            .write()
            .unwrap()
            .insert(HOST.to_string(), bearer("new-token"));
    })
    .await;
    let answer = through_the_mitm(&state, &injections, vec![], forward, |s| {
        request(s, KUBECONFIG_GET)
    })
    .await;

    // A missing resend relays the 401, and the origin waits for a second
    // connection that never comes, so the answer is checked first.
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
    let heads = served.await.unwrap();
    assert_eq!(heads.len(), 2, "{heads:?}");
    assert!(
        heads[0].contains("Authorization: Bearer old-token"),
        "{}",
        heads[0]
    );
    assert!(
        heads[1].contains("Authorization: Bearer new-token"),
        "{}",
        heads[1]
    );
    assert!(
        heads[1].contains(&format!("Host: {GATEWAY_HOST}\r\n")),
        "{}",
        heads[1]
    );
    let audits = drain_audit_lines(&mut audits);
    assert!(
        audits
            .iter()
            .any(|e| e["metadata"]["resent_after_renewal"] == true),
        "{audits:?}"
    );
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
    let (state, _audits) = test_state();
    let answer = through_the_mitm(&state, &[], reads_only, forward, |s| {
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
    let (state, _audits) = test_state();
    let answer = through_the_mitm(&state, &[], vec![], forward, |mut sandbox| async move {
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
fn forwarding_state(
    forward: ClientCertConfig,
) -> (Arc<ProxyState>, mpsc::UnboundedReceiver<String>) {
    let (state, audits) = test_state();
    install_catch_all_allow(&state);
    state
        .client_certs
        .write()
        .unwrap()
        .insert(TARGET.to_string(), forward);
    get_or_init_ca(&state).unwrap();
    (state, audits)
}

#[tokio::test]
async fn a_connect_to_a_forwarded_host_gets_its_credentials_and_its_client_certificate() {
    // The injected credential replaces the kubeconfig's dummy token, and the
    // client certificate goes on the same connection.
    let (forward, served) = origin(OK).await;
    let (state, _audits) = forwarding_state(forward);
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
    let (state, _audits) = forwarding_state(forward);
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

/// What the client of an absolute-form `https://` request to a forwarded host
/// reads while `verdict` covers the route address in the `egress.tcp` table,
/// the audit, and whether the origin was dialled.
async fn forward_under_tcp(verdict: &str) -> (String, Vec<serde_json::Value>, bool) {
    let (forward, listener, _) = mtls_origin().await;
    let (state, mut audits) = forwarding_state(forward);
    let rule = format!(
        r#"[{{"match": "127.0.0.0/8:{}", "verdict": "{verdict}"}}]"#,
        listener.local_addr().unwrap().port()
    );
    install_tcp_rules(&state, &rule);
    let (mut client, server) = socket_pair().await;
    let head =
        b"GET https://api.example.test/api/v1/pods HTTP/1.1\r\nHost: api.example.test\r\n\r\n";
    let _ = handle_https_forward(server, TARGET, head.to_vec(), &state, &test_actor()).await;

    let mut answer = Vec::new();
    let _ = client.read_to_end(&mut answer).await;
    let dialled = tokio::time::timeout(Duration::from_millis(200), listener.accept())
        .await
        .is_ok();
    (
        String::from_utf8(answer).unwrap(),
        drain_audit_lines(&mut audits),
        dialled,
    )
}

#[tokio::test]
async fn a_tcp_deny_on_the_route_address_refuses_the_forward() {
    let (answer, audits, dialled) = forward_under_tcp("deny").await;
    assert!(answer.starts_with("HTTP/1.1 403 "), "{answer}");
    assert!(
        audits
            .iter()
            .any(|e| e["metadata"]["reason"] == "policy-deny"),
        "{audits:?}"
    );
    assert!(!dialled);
}

#[tokio::test]
async fn a_tcp_ask_on_the_route_address_refuses_the_forward() {
    // No gate can run inside the dial, as on every other MITM upstream.
    let (answer, _, dialled) = forward_under_tcp("ask").await;
    assert!(answer.starts_with("HTTP/1.1 403 "), "{answer}");
    assert!(!dialled);
}

#[tokio::test]
async fn a_transparent_tls_connection_to_a_forwarded_host_is_forwarded() {
    let (forward, served) = origin(OK).await;
    let (state, _audits) = forwarding_state(forward);
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

#[tokio::test]
async fn a_signed_request_on_a_forwarded_host_is_signed_for_the_gateway_host() {
    use crate::aws_sigv4::{AwsSigv4Config, BodyMode, ResignRequest, resign_request};
    const PLACEHOLDER: &str = "LENSFAKE00AABB0000CC";
    let real = AwsSigv4Config {
        access_key_id: "ASIAREALEXAMPLE".to_string(),
        secret_access_key: "real-secret-example".to_string(),
        session_token: "real-session-token".to_string(),
    };
    let (state, _audits) = test_state();
    state.aws_signer.update(
        std::collections::HashMap::from([(PLACEHOLDER.to_string(), real.clone())]),
        vec![HOST.to_string()],
    );
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
    let mut sandbox_request = format!("GET /my-bucket HTTP/1.1\r\nHost: {HOST}\r\n");
    for (name, value) in &signed {
        sandbox_request.push_str(&format!("{name}: {value}\r\n"));
    }
    sandbox_request.push_str("\r\n");

    let (forward, served) = origin(OK).await;
    let answer = through_the_mitm(&state, &[], vec![], forward, |s| {
        request(s, sandbox_request)
    })
    .await;

    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
    let head = served.await.unwrap().expect("client certificate");
    assert!(
        head.contains(&format!("Host: {GATEWAY_HOST}\r\n")),
        "{head}"
    );
    assert!(head.contains("Credential=ASIAREALEXAMPLE/"), "{head}");
    crate::signing::verify_signature(head.trim_end_matches("\r\n"), b"", &real)
        .expect("the signature covers the head the gateway gets");
}

#[tokio::test]
async fn an_llm_redirect_from_a_forwarded_host_leaves_the_forward_behind() {
    const BACKEND: &str = "203.0.113.10";
    const BODY: &str =
        r#"{"model":"claude-sonnet-5","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#;
    const ANSWER: &str = r#"{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-5","content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}"#;

    let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (state, _audits) = test_state_on(TestNetwork::Reaching {
        target: format!("{BACKEND}:443").parse().unwrap(),
        origin: backend.local_addr().unwrap(),
    });
    let routes = crate::routing::parse_proxy_routes(&serde_json::json!([
        { "match": HOST, "verdict": "allow", "transport": "direct", "tlsTerminate": true },
        { "match": BACKEND, "verdict": "allow", "transport": "direct", "tlsTerminate": true }
    ]))
    .unwrap()
    .into_iter()
    .map(|parsed| parsed.rule)
    .collect();
    let llm = crate::llm::LlmRouting::from_policy(
        &serde_json::from_value(serde_json::json!({
            "backends": [{ "id": "mirror", "url": format!("https://{BACKEND}/v1/messages") }],
            "routes": [{
                "match": { "domain": HOST, "path": "/v1/messages" },
                "translate": { "from": "anthropicMessages", "to": "anthropicMessages" },
                "backend": "mirror"
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    apply_network_policy(
        &state,
        NetworkPolicy {
            routes,
            default_verdict: Verdict::Deny,
            default_transport: Transport::Direct,
            llm: Arc::new(llm),
            ..Default::default()
        },
    );
    let backend_tls =
        crate::mitm::build_ephemeral_server_config(get_or_init_ca(&state).unwrap(), BACKEND)
            .unwrap();
    let backend_saw = tokio::spawn(async move {
        let (tcp, _) = backend.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(backend_tls)
            .accept(tcp)
            .await
            .unwrap();
        let head = read_head(&mut tls).await;
        let framing = crate::http_body::determine_body_framing(&head);
        crate::http_body::read_body(&mut tls, framing, 1 << 20)
            .await
            .unwrap();
        let answer = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{ANSWER}",
            ANSWER.len()
        );
        tls.write_all(answer.as_bytes()).await.unwrap();
        tls.shutdown().await.ok();
        head
    });

    let (forward, served) = origin(OK).await;
    let sandbox_request = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/json\r\n\
         anthropic-version: 2023-06-01\r\nContent-Length: {}\r\n\r\n{BODY}",
        BODY.len()
    );
    let answer = through_the_mitm(&state, &[], vec![], forward, |s| {
        request(s, sandbox_request)
    })
    .await;

    assert!(answer.starts_with("HTTP/1.1 200 "), "{answer}");
    assert!(
        tokio::time::timeout(Duration::from_millis(200), served)
            .await
            .is_err(),
        "the forward's origin must not be dialled for a redirected request"
    );
    let head = backend_saw.await.unwrap();
    assert!(head.contains(&format!("Host: {BACKEND}\r\n")), "{head}");
    assert!(!head.contains(GATEWAY_HOST), "{head}");
}

#[tokio::test]
async fn a_watch_streams_each_event_before_the_origin_ends_the_answer() {
    // `kubectl get -w` and `logs -f` read events from an answer that stays open.
    let (forward, listener, acceptor) = mtls_origin().await;
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    let origin = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        read_head(&mut tls).await;
        tls.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nADDED\n\r\n")
            .await
            .unwrap();
        tls.flush().await.unwrap();
        released.await.unwrap();
        tls.write_all(b"0\r\n\r\n").await.unwrap();
        tls.shutdown().await.ok();
    });

    let (state, _audits) = test_state();
    let answer = through_the_mitm(&state, &[], vec![], forward, |mut sandbox| async move {
        sandbox
            .write_all(b"GET /api/v1/pods?watch=true HTTP/1.1\r\nHost: api.example.test\r\n\r\n")
            .await
            .unwrap();
        let mut seen = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !seen.windows(6).any(|w| w == b"ADDED\n") {
                seen.push(sandbox.read_u8().await.unwrap());
            }
        })
        .await
        .expect("the first event must arrive while the origin holds the answer open");
        release.send(()).unwrap();
        sandbox.read_to_end(&mut seen).await.unwrap();
        String::from_utf8(seen).unwrap()
    })
    .await;

    origin.await.unwrap();
    assert!(answer.ends_with("0\r\n\r\n"), "{answer}");
}
