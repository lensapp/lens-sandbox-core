//! The `llm` redirect, driven end to end through the MITM.
//!
//! The unit tests under `crate::llm` prove each translation on its own. These
//! prove the thing they cannot: that one request really leaves the proxy
//! addressed to the backend, carrying the backend's credential and not the
//! sandbox's, and that the answer really comes back in the format the sandbox
//! is waiting for.

use super::*;

/// What one request through the MITM produced.
enum Outcome {
    /// The request reached a backend.
    Served {
        /// The head and body the backend received.
        upstream: String,
        /// The response the sandbox received.
        client: String,
        audit: Vec<serde_json::Value>,
    },
    /// Policy refused the request.
    Denied {
        reason: String,
        client: String,
        audit: Vec<serde_json::Value>,
    },
}

impl Outcome {
    fn served(self) -> (String, String, Vec<serde_json::Value>) {
        match self {
            Outcome::Served {
                upstream,
                client,
                audit,
            } => (upstream, client, audit),
            Outcome::Denied { reason, .. } => panic!("expected the request to be served: {reason}"),
        }
    }

    fn denied(self) -> (String, String) {
        match self {
            Outcome::Denied { reason, client, .. } => (reason, client),
            Outcome::Served { upstream, .. } => {
                panic!("expected the request to be refused, but it reached:\n{upstream}")
            }
        }
    }

    fn audit(&self) -> &[serde_json::Value] {
        match self {
            Outcome::Served { audit, .. } | Outcome::Denied { audit, .. } => audit,
        }
    }
}

/// The host the sandbox believes it is calling.
const FRONT_HOST: &str = "api.anthropic.com";
/// The host the policy sends the request to instead.
const BACKEND_HOST: &str = "vllm.internal";

/// The `egress.http` table these tests run under: both hosts allowed, the
/// backend narrowed to the one endpoint it serves.
const ROUTES: &str = r#"[
    { "match": "api.anthropic.com", "verdict": "allow", "transport": "direct",
      "tlsTerminate": true, "rules": [{ "method": "POST", "path": "/v1/messages" }] },
    { "match": "vllm.internal", "verdict": "allow", "transport": "direct",
      "tlsTerminate": true, "rules": [{ "method": "POST", "path": "/v1/chat/completions" }] }
]"#;

/// The `llm` block these tests run under.
const LLM: &str = r#"{
    "backends": [{
        "id": "local",
        "url": "https://vllm.internal/v1/chat/completions",
        "modelMap": [{ "match": "claude-*", "model": "qwen3-coder-30b" }]
    }],
    "routes": [{
        "match": { "domain": "api.anthropic.com", "path": "/v1/messages" },
        "translate": { "from": "anthropicMessages", "to": "openaiChat" },
        "backend": "local"
    }]
}"#;

/// An ordinary Anthropic request body, as an agent would write it.
const ANTHROPIC_BODY: &str =
    r#"{"model":"claude-sonnet-5","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}"#;

/// What an OpenAI-compatible backend answers with.
const OPENAI_BODY: &str = r#"{"id":"chatcmpl-1","model":"qwen3-coder-30b","choices":[{"finish_reason":"stop","message":{"content":"hello"}}]}"#;

/// An Anthropic request carrying `body`, framed by its real length. Written
/// here rather than spelled out so a fixture can never claim a length it does
/// not have — a reader would wait for the rest of it forever.
fn anthropic_request(body: &str) -> Vec<u8> {
    format!(
        "POST /v1/messages HTTP/1.1\r\n\
         Host: api.anthropic.com\r\n\
         x-api-key: sk-ant-sandbox-key\r\n\
         anthropic-version: 2023-06-01\r\n\
         Accept-Encoding: gzip\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// A backend answer carrying `body`, framed by its real length.
fn openai_answer(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Publish an egress table and an `llm` block as one policy.
fn install_policy(state: &Arc<crate::proxy::ProxyState>, routes: &str, llm: &str) {
    let routes = crate::routing::parse_proxy_routes(&serde_json::from_str(routes).unwrap())
        .unwrap()
        .into_iter()
        .map(|parsed| parsed.rule)
        .collect();
    let llm = crate::llm::LlmRouting::from_policy(&serde_json::from_str(llm).unwrap()).unwrap();
    crate::proxy::apply_network_policy(
        state,
        crate::proxy::NetworkPolicy {
            routes,
            default_verdict: crate::routing::Verdict::Deny,
            default_transport: crate::routing::Transport::Direct,
            llm: Arc::new(llm),
            ..Default::default()
        },
    );
}

/// Drive one request through the MITM and let the backend answer.
///
/// The dial is made here rather than by the proxy, so these tests need no
/// resolvable backend; what they exercise is everything the proxy decides about
/// the request and the answer.
async fn run(
    routes: &str,
    llm: &str,
    request: Vec<u8>,
    answer: String,
    is_tunnel: bool,
) -> Outcome {
    use tokio::net::TcpListener;

    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let ca = EphemeralCa::new().unwrap();

    // The backend, answering on its own name.
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let server_config = test_tls_server_config(&ca, BACKEND_HOST);

    let (state, mut audit_rx) = crate::proxy::tests::test_state();
    install_policy(&state, routes, llm);
    // The backend's own credential, bound to the backend.
    state.credential_injections.write().unwrap().insert(
        BACKEND_HOST.to_string(),
        vec![CredentialInjection {
            header: "Authorization".to_string(),
            value: "Bearer real-vllm-key".to_string(),
            rules: vec![],
        }],
    );
    let audit_tx_opt = state.audit_tx.lock().unwrap().clone();

    let upstream_handle = tokio::spawn(async move {
        let (stream, _) = upstream_listener.accept().await.unwrap();
        let acceptor = TlsAcceptor::from(server_config);
        let mut tls = acceptor.accept(stream).await.unwrap();
        let head = crate::http_body::read_head(&mut tls).await.unwrap();
        let head = String::from_utf8(head).unwrap();
        let framing = crate::http_body::determine_body_framing(&head);
        let body = crate::http_body::read_body(&mut tls, framing, 1 << 20)
            .await
            .unwrap();
        tls.write_all(answer.as_bytes()).await.unwrap();
        tls.shutdown().await.ok();
        format!("{head}{}", String::from_utf8_lossy(&body))
    });

    let upstream_stream = TcpStream::connect(upstream_addr).await.unwrap();

    // The sandbox, calling the API its policy named.
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let root_store = ca_root_store(&ca);
    let client_handle = tokio::spawn(async move {
        let stream = TcpStream::connect(client_addr).await.unwrap();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::try_from(FRONT_HOST.to_string()).unwrap();
        let mut tls = connector.connect(server_name, stream).await.unwrap();
        tls.write_all(&request).await.unwrap();
        let mut response = Vec::new();
        let _ = tls.read_to_end(&mut response).await;
        String::from_utf8(response).unwrap()
    });

    let (client_stream, _) = client_listener.accept().await.unwrap();
    let test_actor = crate::peer_process::ActorContext::resolve("10.0.0.5:44000".parse().unwrap());
    // The credential the sandbox holds for the API it thinks it is calling.
    let front_injections = vec![CredentialInjection {
        header: "x-api-key".to_string(),
        value: "sk-ant-sandbox-key".to_string(),
        rules: vec![],
    }];
    let http_rules = vec![HttpRule {
        method: Some("POST".to_string()),
        path: Some("/v1/messages".to_string()),
        graphql: None,
    }];
    let ctx = MitmContext {
        injections: &front_injections,
        http_rules: &http_rules,
        ca: &ca,
        audit_tx: &audit_tx_opt,
        extra_ca_certs: &[],
        placeholder_map: &[],
        state: &state,
        match_host: FRONT_HOST,
        actor: &test_actor,
    };

    let acceptor = TlsAcceptor::from(build_ephemeral_server_config(&ca, FRONT_HOST).unwrap());
    let tls_client_stream = acceptor.accept(client_stream).await.unwrap();
    let result = mitm_inject_after_accept(tls_client_stream, FRONT_HOST, &ctx, is_tunnel).await;

    let drain = |rx: &mut tokio::sync::mpsc::UnboundedReceiver<String>| {
        let mut events = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            events.push(serde_json::from_str(&msg).unwrap());
        }
        events
    };

    let (mut tls_client, modified, meta) = match result {
        Ok(value) => value,
        Err(e) => {
            let reason = e.to_string();
            let audit = drain(&mut audit_rx);
            upstream_handle.abort();
            return Outcome::Denied {
                reason,
                client: client_handle.await.unwrap(),
                audit,
            };
        }
    };

    let mut tls_upstream = connect_upstream_tls(
        upstream_stream,
        BACKEND_HOST,
        Some(ca_root_store(&ca)),
        None,
        &[],
    )
    .await
    .unwrap();
    write_request_head_and_body(&mut tls_upstream, &modified, &meta)
        .await
        .unwrap();

    let redirect = meta.redirect.as_ref().expect("the route redirected");
    crate::llm::relay::forward_translated(&mut tls_client, &mut tls_upstream, redirect)
        .await
        .unwrap();

    let upstream = upstream_handle.await.unwrap();
    let client = client_handle.await.unwrap();
    let audit = drain(&mut audit_rx);
    Outcome::Served {
        upstream,
        client,
        audit,
    }
}

/// The default run: a plain request, a plain answer, a direct route.
async fn redirected() -> Outcome {
    run(
        ROUTES,
        LLM,
        anthropic_request(ANTHROPIC_BODY),
        openai_answer(OPENAI_BODY),
        false,
    )
    .await
}

/// The JSON body of an HTTP message.
fn body_of(message: &str) -> serde_json::Value {
    let (_, body) = message.split_once("\r\n\r\n").expect("head ends");
    serde_json::from_str(body).expect("body is JSON")
}

#[tokio::test]
async fn the_backend_receives_the_request_addressed_to_itself() {
    let (upstream, _, _) = redirected().await.served();
    assert!(
        upstream.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"),
        "{upstream}"
    );
    assert!(upstream.contains("Host: vllm.internal\r\n"), "{upstream}");
}

#[tokio::test]
async fn the_backend_receives_the_request_in_its_own_format() {
    let (upstream, _, _) = redirected().await.served();
    let body = body_of(&upstream);
    assert_eq!(body["model"], "qwen3-coder-30b");
    assert_eq!(body["max_completion_tokens"], 64);
    assert_eq!(body["messages"][0]["role"], "user");
    assert_eq!(body["messages"][0]["content"], "hi");
}

#[tokio::test]
async fn the_backend_never_sees_the_credential_the_sandbox_holds() {
    let (upstream, _, _) = redirected().await.served();
    assert!(
        !upstream.contains("sk-ant-sandbox-key"),
        "the key for the API the sandbox named must not reach the backend:\n{upstream}"
    );
    assert!(
        !upstream.to_ascii_lowercase().contains("anthropic-version"),
        "{upstream}"
    );
    assert!(
        upstream.contains("Authorization: Bearer real-vllm-key"),
        "the backend's own credential must be injected:\n{upstream}"
    );
}

#[tokio::test]
async fn the_request_head_states_the_length_of_the_translated_body() {
    let (upstream, _, _) = redirected().await.served();
    let (head, body) = upstream.split_once("\r\n\r\n").expect("head ends");
    assert!(
        head.contains(&format!("Content-Length: {}", body.len())),
        "{upstream}"
    );
    assert!(
        !head.to_ascii_lowercase().contains("accept-encoding"),
        "a compressed answer is one the proxy cannot translate:\n{upstream}"
    );
}

#[tokio::test]
async fn the_sandbox_receives_the_answer_in_the_format_it_expects() {
    let (_, client, _) = redirected().await.served();
    assert!(client.starts_with("HTTP/1.1 200 OK\r\n"), "{client}");
    let body = body_of(&client);
    assert_eq!(body["type"], "message");
    assert_eq!(body["role"], "assistant");
    assert_eq!(body["content"][0]["type"], "text");
    assert_eq!(body["content"][0]["text"], "hello");
    assert_eq!(body["stop_reason"], "end_turn");
}

#[tokio::test]
async fn the_audit_record_says_where_the_request_went() {
    let outcome = redirected().await;
    let event = outcome
        .audit()
        .iter()
        .find(|event| event["result"] == "success")
        .expect("a success is recorded");
    assert_eq!(event["host"], FRONT_HOST);
    assert_eq!(event["metadata"]["llm_backend"], "vllm.internal:443");
    assert_eq!(event["metadata"]["llm_model"], "qwen3-coder-30b");
}

#[tokio::test]
async fn a_backend_no_egress_rule_allows_is_refused() {
    // The `llm` block redirects; it does not grant. Without a rule for the
    // backend the request must not leave.
    let routes = r#"[
        { "match": "api.anthropic.com", "verdict": "allow", "transport": "direct",
          "tlsTerminate": true, "rules": [{ "method": "POST", "path": "/v1/messages" }] }
    ]"#;
    let (reason, client) = run(
        routes,
        LLM,
        anthropic_request(ANTHROPIC_BODY),
        openai_answer(OPENAI_BODY),
        false,
    )
    .await
    .denied();
    assert!(reason.contains("no egress.http rule allows"), "{reason}");
    assert!(client.starts_with("HTTP/1.1 403"), "{client}");
}

#[tokio::test]
async fn a_backend_whose_rules_refuse_the_translated_path_is_refused() {
    let routes = r#"[
        { "match": "api.anthropic.com", "verdict": "allow", "transport": "direct",
          "tlsTerminate": true, "rules": [{ "method": "POST", "path": "/v1/messages" }] },
        { "match": "vllm.internal", "verdict": "allow", "transport": "direct",
          "tlsTerminate": true, "rules": [{ "method": "GET", "path": "/health" }] }
    ]"#;
    let (reason, client) = run(
        routes,
        LLM,
        anthropic_request(ANTHROPIC_BODY),
        openai_answer(OPENAI_BODY),
        false,
    )
    .await
    .denied();
    assert!(reason.contains("no HTTP rule"), "{reason}");
    assert!(client.starts_with("HTTP/1.1 403"), "{client}");
}

#[tokio::test]
async fn a_tunnelled_session_refuses_the_redirect_rather_than_ignoring_it() {
    // The tunnel is already connected to the host the sandbox named, so there
    // is no dial left to point elsewhere. Passing the request on would send the
    // sandbox's key to the API the redirect exists to withhold it from.
    let (reason, client) = run(
        ROUTES,
        LLM,
        anthropic_request(ANTHROPIC_BODY),
        openai_answer(OPENAI_BODY),
        true,
    )
    .await
    .denied();
    assert!(reason.contains("tunnelled"), "{reason}");
    assert!(client.starts_with("HTTP/1.1 403"), "{client}");
}

#[tokio::test]
async fn a_request_the_backend_cannot_serve_is_refused() {
    let llm = r#"{
        "backends": [{
            "id": "local",
            "url": "https://vllm.internal/v1/chat/completions",
            "capabilities": { "tools": false }
        }],
        "routes": [{
            "match": { "domain": "api.anthropic.com", "path": "/v1/messages" },
            "translate": { "from": "anthropicMessages", "to": "openaiChat" },
            "backend": "local"
        }]
    }"#;
    const WITH_TOOLS: &str = r#"{"model":"claude-opus-5","messages":[],"tools":[{"name":"w","input_schema":{"type":"object"}}]}"#;
    let (reason, client) = run(
        ROUTES,
        llm,
        anthropic_request(WITH_TOOLS),
        openai_answer(OPENAI_BODY),
        false,
    )
    .await
    .denied();
    assert!(reason.contains("tools"), "{reason}");
    assert!(client.starts_with("HTTP/1.1 403"), "{client}");
}

#[tokio::test]
async fn a_streamed_request_comes_back_as_anthropic_events() {
    const STREAMED: &str =
        r#"{"model":"claude-opus-5","stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
    // No length: an event stream ends when the connection does.
    const SSE: &str = concat!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
        r#"data: {"id":"c","model":"qwen3-coder-30b","choices":[{"delta":{"content":"hel"}}]}"#,
        "\n\n",
        r#"data: {"id":"c","choices":[{"delta":{"content":"lo"},"finish_reason":"stop"}]}"#,
        "\n\ndata: [DONE]\n\n",
    );

    let (upstream, client, _) = run(
        ROUTES,
        LLM,
        anthropic_request(STREAMED),
        SSE.to_string(),
        false,
    )
    .await
    .served();
    assert_eq!(body_of(&upstream)["stream"], true);
    assert_eq!(body_of(&upstream)["stream_options"]["include_usage"], true);

    assert!(
        client.contains("Content-Type: text/event-stream"),
        "{client}"
    );
    assert!(client.contains("event: message_start"), "{client}");
    assert!(client.contains(r#""text":"hel""#), "{client}");
    assert!(client.contains(r#""text":"lo""#), "{client}");
    assert!(client.contains("event: message_stop"), "{client}");
}

#[tokio::test]
async fn a_route_that_translates_nothing_still_swaps_the_backend_and_the_key() {
    // The most ordinary use of the block: keep the protocol, change who serves
    // it. Nothing about the body may move.
    const PASSTHROUGH_ROUTES: &str = r#"[
        { "match": "api.anthropic.com", "verdict": "allow", "transport": "direct",
          "tlsTerminate": true, "rules": [{ "method": "POST", "path": "/v1/messages" }] },
        { "match": "vllm.internal", "verdict": "allow", "transport": "direct",
          "tlsTerminate": true, "rules": [{ "method": "POST", "path": "/v1/messages" }] }
    ]"#;
    const PASSTHROUGH_LLM: &str = r#"{
        "backends": [{ "id": "mirror", "url": "https://vllm.internal/v1/messages" }],
        "routes": [{
            "match": { "domain": "api.anthropic.com", "path": "/v1/messages" },
            "translate": { "from": "anthropicMessages", "to": "anthropicMessages" },
            "backend": "mirror"
        }]
    }"#;
    const ANSWER: &str = r#"{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5","content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}"#;

    let (upstream, client, _) = run(
        PASSTHROUGH_ROUTES,
        PASSTHROUGH_LLM,
        anthropic_request(ANTHROPIC_BODY),
        openai_answer(ANSWER),
        false,
    )
    .await
    .served();

    // The request reached the backend, addressed to it and holding its key.
    assert!(
        upstream.starts_with("POST /v1/messages HTTP/1.1\r\n"),
        "{upstream}"
    );
    assert!(upstream.contains("Host: vllm.internal\r\n"), "{upstream}");
    assert!(
        upstream.contains("Authorization: Bearer real-vllm-key"),
        "{upstream}"
    );
    assert!(!upstream.contains("sk-ant-sandbox-key"), "{upstream}");
    // This backend serves the very API the sandbox addressed, so the version it
    // named describes the backend just as well and travels with the request.
    assert!(
        upstream.contains("anthropic-version: 2023-06-01"),
        "{upstream}"
    );

    // And it reached it word for word, because no model map renamed anything.
    assert_eq!(
        body_of(&upstream),
        serde_json::from_str::<serde_json::Value>(ANTHROPIC_BODY).expect("body is JSON")
    );

    // The answer came back the same way.
    assert_eq!(
        body_of(&client),
        serde_json::from_str::<serde_json::Value>(ANSWER).expect("answer is JSON")
    );
}
