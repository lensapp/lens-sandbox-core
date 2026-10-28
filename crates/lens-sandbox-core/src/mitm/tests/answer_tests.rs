//! What the origin answered a request the proxy terminated and forwarded, and
//! the request sent once more when the credential it carried was renewed while
//! it was in flight.

use super::*;

const HOST: &str = "inference.lns.run";

fn bearer(value: &str) -> Vec<CredentialInjection> {
    vec![CredentialInjection {
        header: "Authorization".to_string(),
        value: format!("Bearer {value}"),
        body: None,
        rules: vec![],
    }]
}

fn answer(status_line: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: {content_type}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn json_answer(status_line: &str, body: &str) -> String {
    answer(status_line, "application/json", body)
}

const UNAUTHORIZED: &str = "401 Unauthorized";
const KEY_REJECTED: &str = r#"{"error":{"code":"invalid_key","message":"no such key"}}"#;

fn ok() -> String {
    json_answer("200 OK", r#"{"id":"chat-1"}"#)
}

/// What one request did.
struct Run {
    /// Each request that reached the origin, head and body, in order.
    upstream: Vec<String>,
    /// What the workload received.
    client: String,
    audit: Vec<serde_json::Value>,
}

impl Run {
    /// The record of the forwarded request: the one with no refusal in it.
    fn forwarded(&self) -> &serde_json::Value {
        let forwarded: Vec<_> = self
            .audit
            .iter()
            .filter(|event| event["result"] == "success")
            .collect();
        assert_eq!(forwarded.len(), 1, "{:?}", self.audit);
        forwarded[0]
    }
}

/// Send `request` for [`HOST`], which holds the injected credential
/// `Bearer old-key`, through the MITM to an origin that answers its `n`th
/// connection with `answers[n]`. When `renew_to` is set, the credential is
/// renewed to it while the first request is with the origin, as a policy frame
/// would renew it.
async fn run(request: Vec<u8>, answers: Vec<String>, renew_to: Option<&'static str>) -> Run {
    run_under(vec![], request, answers, renew_to).await
}

/// [`run`], with HTTP rules on the route.
async fn run_under(
    http_rules: Vec<HttpRule>,
    request: Vec<u8>,
    answers: Vec<String>,
    renew_to: Option<&'static str>,
) -> Run {
    use tokio::net::TcpListener;

    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let ca = EphemeralCa::new().unwrap();
    let (state, mut audit_rx) = crate::proxy::tests::test_state();
    state
        .credential_injections
        .write()
        .unwrap()
        .insert(HOST.to_string(), bearer("old-key"));
    let audit_tx = state.audit_tx.lock().unwrap().clone();

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let server_config = test_tls_server_config(&ca, HOST);
    let received = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let origin = {
        let received = received.clone();
        let state = state.clone();
        tokio::spawn(async move {
            for answer in answers {
                let (stream, _) = upstream_listener.accept().await.unwrap();
                let mut tls = TlsAcceptor::from(server_config.clone())
                    .accept(stream)
                    .await
                    .unwrap();
                let head = crate::http_body::read_head(&mut tls).await.unwrap();
                let head = String::from_utf8(head).unwrap();
                let framing = crate::http_body::determine_body_framing(&head);
                let body = crate::http_body::read_body(&mut tls, framing, 1 << 20)
                    .await
                    .unwrap();
                received
                    .lock()
                    .unwrap()
                    .push(format!("{head}{}", String::from_utf8_lossy(&body)));
                if let Some(value) = renew_to {
                    state
                        .credential_injections
                        .write()
                        .unwrap()
                        .insert(HOST.to_string(), bearer(value));
                }
                tls.write_all(answer.as_bytes()).await.unwrap();
                tls.shutdown().await.ok();
            }
        })
    };

    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let root_store = ca_root_store(&ca);
    let client = tokio::spawn(async move {
        let stream = TcpStream::connect(client_addr).await.unwrap();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let name = ServerName::try_from(HOST.to_string()).unwrap();
        let mut tls = TlsConnector::from(Arc::new(config))
            .connect(name, stream)
            .await
            .unwrap();
        tls.write_all(&request).await.unwrap();
        let mut response = Vec::new();
        let _ = tls.read_to_end(&mut response).await;
        String::from_utf8(response).unwrap()
    });

    let (client_stream, _) = client_listener.accept().await.unwrap();
    let actor = crate::peer_process::ActorContext::resolve("10.0.0.5:44000".parse().unwrap());
    let injections = bearer("old-key");
    let ctx = MitmContext {
        injections: &injections,
        http_rules: &http_rules,
        ca: &ca,
        audit_tx: &audit_tx,
        extra_ca_certs: &[],
        placeholder_map: &[],
        state: &state,
        match_host: HOST,
        actor: &actor,
        gate_deferred: false,
    };
    let acceptor = TlsAcceptor::from(build_ephemeral_server_config(&ca, HOST).unwrap());
    let tls_client = acceptor.accept(client_stream).await.unwrap();
    let (tls_client, head, meta) = mitm_inject_after_accept(tls_client, HOST, &ctx, false)
        .await
        .unwrap();

    // The dial the proxy makes, pointed at the test origin.
    let dial = async || {
        let stream = TcpStream::connect(upstream_addr).await?;
        connect_upstream_tls(stream, HOST, Some(ca_root_store(&ca)), None, &[]).await
    };
    let mut tls_upstream = dial().await.unwrap();
    write_request_head_and_body(&mut tls_upstream, &head, &meta)
        .await
        .unwrap();
    let _ = forward_renewing(tls_client, tls_upstream, &meta, &state, dial).await;
    drop(meta);

    let client = client.await.unwrap();
    origin.abort();
    let upstream = received.lock().unwrap().clone();
    let mut audit = Vec::new();
    while let Ok(message) = audit_rx.try_recv() {
        audit.push(serde_json::from_str(&message).unwrap());
    }
    Run {
        upstream,
        client,
        audit,
    }
}

fn get() -> Vec<u8> {
    format!(
        "GET /api/v1/models HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer placeholder\r\n\r\n"
    )
    .into_bytes()
}

fn post(body: &str) -> Vec<u8> {
    format!(
        "POST /api/v1/chat/completions HTTP/1.1\r\nHost: {HOST}\r\n\
         Authorization: Bearer placeholder\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

// What the origin answered.

#[tokio::test]
async fn the_record_of_a_forwarded_request_carries_what_the_origin_answered() {
    let run = run(get(), vec![ok()], None).await;
    let event = run.forwarded();
    assert_eq!(event["upstream_status_code"], 200, "{event}");
    assert!(event.get("upstream_error_code").is_none(), "{event}");
}

#[tokio::test]
async fn the_proxy_s_own_status_stays_apart_from_the_origin_s() {
    let run = run(get(), vec![json_answer("402 Payment Required", "{}")], None).await;
    let event = run.forwarded();
    // `status_code` is what the proxy decided; it let the request through.
    assert!(event.get("status_code").is_none(), "{event}");
    assert_eq!(event["result"], "success");
    assert_eq!(event["upstream_status_code"], 402, "{event}");
}

#[tokio::test]
async fn an_openai_refusal_names_its_error_code() {
    let body =
        r#"{"error":{"code":"insufficient_credit","message":"out of credit","request_id":"r1"}}"#;
    let refusal = json_answer("402 Payment Required", body);
    let run = run(get(), vec![refusal.clone()], None).await;
    let event = run.forwarded();
    assert_eq!(event["upstream_status_code"], 402, "{event}");
    assert_eq!(
        event["upstream_error_code"], "insufficient_credit",
        "{event}"
    );
    // Reading the code changes nothing the workload receives.
    assert!(run.client.ends_with(body), "{}", run.client);
    assert!(run.client.starts_with("HTTP/1.1 402 Payment Required\r\n"));
}

#[tokio::test]
async fn an_anthropic_refusal_names_its_error_type() {
    let body = r#"{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}"#;
    let run = run(
        get(),
        vec![json_answer("429 Too Many Requests", body)],
        None,
    )
    .await;
    let event = run.forwarded();
    assert_eq!(event["upstream_status_code"], 429, "{event}");
    assert_eq!(event["upstream_error_code"], "rate_limit_error", "{event}");
}

#[tokio::test]
async fn a_chunked_refusal_is_read_through_its_framing() {
    let first = r#"{"error":{"code":"limit_"#;
    let second = r#"exceeded"}}"#;
    let refusal = format!(
        "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\n\
         Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
         {:x}\r\n{first}\r\n{:x}\r\n{second}\r\n0\r\n\r\n",
        first.len(),
        second.len()
    );
    let run = run(get(), vec![refusal], None).await;
    let event = run.forwarded();
    assert_eq!(event["upstream_error_code"], "limit_exceeded", "{event}");
    assert!(run.client.contains(first), "{}", run.client);
}

#[tokio::test]
async fn a_refusal_body_over_the_bound_is_relayed_whole_and_not_read() {
    let padding = "x".repeat(crate::upstream_answer::MAX_ERROR_BODY_BYTES);
    let body = format!(r#"{{"error":{{"code":"insufficient_credit","pad":"{padding}"}}}}"#);
    let run = run(
        get(),
        vec![json_answer("402 Payment Required", &body)],
        None,
    )
    .await;
    let event = run.forwarded();
    assert_eq!(event["upstream_status_code"], 402, "{event}");
    assert!(event.get("upstream_error_code").is_none(), "{event}");
    assert!(run.client.ends_with(&body));
}

#[tokio::test]
async fn a_refusal_that_is_not_json_has_no_error_code() {
    let body = r#"{"error":{"code":"insufficient_credit"}}"#;
    let run = run(
        get(),
        vec![answer("402 Payment Required", "text/plain", body)],
        None,
    )
    .await;
    let event = run.forwarded();
    assert_eq!(event["upstream_status_code"], 402, "{event}");
    assert!(event.get("upstream_error_code").is_none(), "{event}");
}

#[tokio::test]
async fn a_success_body_is_never_read_for_a_code() {
    let body = r#"{"error":{"code":"insufficient_credit"}}"#;
    let run = run(get(), vec![json_answer("200 OK", body)], None).await;
    let event = run.forwarded();
    assert_eq!(event["upstream_status_code"], 200, "{event}");
    assert!(event.get("upstream_error_code").is_none(), "{event}");
}

// The request sent once more after a renewal.

#[tokio::test]
async fn a_401_after_the_credential_was_renewed_is_sent_once_more_with_the_new_value() {
    let refusal = json_answer(UNAUTHORIZED, KEY_REJECTED);
    let run = run(get(), vec![refusal, ok()], Some("new-key")).await;

    assert_eq!(run.upstream.len(), 2, "{:?}", run.upstream);
    assert!(run.upstream[0].contains("Authorization: Bearer old-key"));
    assert!(
        run.upstream[1].contains("Authorization: Bearer new-key"),
        "{}",
        run.upstream[1]
    );
    // The workload sees only the answer to the request sent again.
    assert!(
        run.client.starts_with("HTTP/1.1 200 OK\r\n"),
        "{}",
        run.client
    );
    assert!(!run.client.contains("invalid_key"), "{}", run.client);
    let event = run.forwarded();
    assert_eq!(event["upstream_status_code"], 200, "{event}");
    assert_eq!(event["metadata"]["resent_after_renewal"], true, "{event}");
}

#[tokio::test]
async fn a_body_the_proxy_read_is_sent_again_with_the_request() {
    let refusal = json_answer(UNAUTHORIZED, KEY_REJECTED);
    let body = r#"{"query":"query Viewer { viewer { login } }"}"#;
    let request = format!(
        "POST /graphql HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let run = run_under(
        super::graphql_read_rule(),
        request.into_bytes(),
        vec![refusal, ok()],
        Some("new-key"),
    )
    .await;
    assert_eq!(run.upstream.len(), 2, "{:?}", run.upstream);
    assert!(run.upstream[1].contains("Authorization: Bearer new-key"));
    assert!(run.upstream[1].ends_with(body), "{}", run.upstream[1]);
    assert!(
        run.client.starts_with("HTTP/1.1 200 OK\r\n"),
        "{}",
        run.client
    );
}

#[tokio::test]
async fn a_body_still_on_the_client_socket_is_not_sent_again() {
    let refusal = json_answer(UNAUTHORIZED, KEY_REJECTED);
    let body = r#"{"model":"m","messages":[]}"#;
    let run = run(post(body), vec![refusal, ok()], Some("new-key")).await;
    // The proxy relayed this body as it arrived and kept none of it, so it has
    // nothing to send a second time.
    assert_eq!(run.upstream.len(), 1, "{:?}", run.upstream);
    assert!(run.client.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
}

#[tokio::test]
async fn a_401_with_the_credential_unchanged_reaches_the_workload() {
    let refusal = json_answer(UNAUTHORIZED, KEY_REJECTED);
    let run = run(get(), vec![refusal, ok()], None).await;
    assert_eq!(run.upstream.len(), 1, "{:?}", run.upstream);
    assert!(run.client.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
    assert!(run.client.ends_with(KEY_REJECTED), "{}", run.client);
    let event = run.forwarded();
    assert_eq!(event["upstream_status_code"], 401, "{event}");
    assert!(event["metadata"].get("resent_after_renewal").is_none());
}

#[tokio::test]
async fn a_request_is_sent_again_at_most_once() {
    let refusal = json_answer(UNAUTHORIZED, KEY_REJECTED);
    let run = run(
        get(),
        vec![refusal.clone(), refusal, ok()],
        // The origin renews the credential on every request it refuses.
        Some("new-key"),
    )
    .await;
    assert_eq!(run.upstream.len(), 2, "{:?}", run.upstream);
    assert!(run.client.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
    let event = run.forwarded();
    assert_eq!(event["upstream_status_code"], 401, "{event}");
    assert_eq!(event["metadata"]["resent_after_renewal"], true, "{event}");
}

#[tokio::test]
async fn another_refusal_after_a_renewal_is_not_sent_again() {
    let refusal = json_answer("403 Forbidden", r#"{"error":{"code":"forbidden"}}"#);
    let run = run(get(), vec![refusal, ok()], Some("new-key")).await;
    assert_eq!(run.upstream.len(), 1, "{:?}", run.upstream);
    assert!(run.client.starts_with("HTTP/1.1 403 Forbidden\r\n"));
}

#[tokio::test]
async fn a_401_after_an_interim_answer_reaches_the_workload() {
    let refusal = format!(
        "HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n{}",
        json_answer(UNAUTHORIZED, KEY_REJECTED)
    );
    let run = run(get(), vec![refusal, ok()], Some("new-key")).await;
    // The workload is already reading this answer, so it is not swapped.
    assert_eq!(run.upstream.len(), 1, "{:?}", run.upstream);
    assert!(run.client.contains("401 Unauthorized"), "{}", run.client);
    assert_eq!(run.forwarded()["upstream_status_code"], 401);
}
