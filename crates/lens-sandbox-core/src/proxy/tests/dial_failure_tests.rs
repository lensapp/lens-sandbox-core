//! A host embedder's own [`crate::egress::Egress`], and what every door does
//! when the dial to an admitted destination fails.
//!
//! A host judge that cannot reach a destination answers `502 Bad Gateway` with
//! an RFC 9209 `Proxy-Status` that says why, inside the intercepted TLS session
//! when there is one, and audits the request as an error with the reason. It
//! never leaves the client with an empty reply, and never audits the request as
//! a success.

use super::*;
use crate::egress::Egress;
use std::sync::Mutex as StdMutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HOST: &str = "api.example.test";

/// What the fake resolver answers for a name. An address literal always
/// resolves to itself, as it does with the real resolver.
#[derive(Clone, Copy, Debug)]
enum Lookup {
    Fails,
    Hangs,
    Answers(IpAddr),
}

/// An embedder's own egress: it records every name it is asked to resolve,
/// and refuses every dial.
struct FakeEgress {
    lookup: Lookup,
    resolved: StdMutex<Vec<String>>,
}

impl FakeEgress {
    fn resolved(&self) -> Vec<String> {
        self.resolved.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl Egress for FakeEgress {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<SocketAddr> {
        self.resolved.lock().unwrap().push(host.to_string());
        if let Ok(ip) = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
        {
            return Ok(SocketAddr::new(ip, port));
        }
        match self.lookup {
            Lookup::Fails => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                crate::resolver::ResolveFailed(format!("resolve {host}: no record")),
            )),
            Lookup::Hangs => std::future::pending().await,
            Lookup::Answers(ip) => Ok(SocketAddr::new(ip, port)),
        }
    }

    async fn connect(&self, _addr: SocketAddr) -> std::io::Result<TcpStream> {
        Err(std::io::ErrorKind::ConnectionRefused.into())
    }

    async fn bind_udp(&self, _local: SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
        Err(std::io::ErrorKind::NetworkUnreachable.into())
    }
}

/// A host state built the way an embedder builds it, with `lookup` as its
/// resolver, that allows every destination on a direct route.
fn host_state(
    lookup: Lookup,
) -> (
    Arc<ProxyState>,
    Arc<FakeEgress>,
    mpsc::UnboundedReceiver<String>,
) {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let egress = Arc::new(FakeEgress {
        lookup,
        resolved: StdMutex::new(Vec::new()),
    });
    let ca = Arc::new(crate::ca::EphemeralCa::new().unwrap());
    let state = ProxyState::for_host_with_egress(ca, Vec::new(), egress.clone());
    let (tx, rx) = mpsc::unbounded_channel();
    state.connect_audit(tx);
    {
        let mut policy = state.policy.write().unwrap();
        policy.default_verdict = Verdict::Allow;
        policy.default_transport = Transport::Direct;
    }
    (state, egress, rx)
}

/// A route whose HTTP rules make the proxy intercept the host's traffic.
fn intercept(state: &Arc<ProxyState>) {
    state
        .policy
        .write()
        .unwrap()
        .routes
        .push(crate::routing::RouteRule {
            matcher: crate::routing::RouteMatcher::Domain(HOST.to_string()),
            verdict: Verdict::Allow,
            transport: Transport::Direct,
            tls_terminate: false,
            http_rules: vec![crate::policy_schema::HttpRule {
                method: None,
                path: Some("/**".to_string()),
                graphql: None,
                mcp: None,
            }],
            scheme: None,
            binaries: None,
        });
}

/// Each way a request reaches the proxy.
#[derive(Clone, Copy, Debug)]
enum Door {
    /// `CONNECT` with no interception: the proxy dials before the `200`.
    ConnectRelay,
    /// `CONNECT` with interception: the proxy dials after the client's TLS
    /// handshake, once it has read the request.
    ConnectIntercepted,
    /// `GET http://…` through the explicit proxy.
    PlainHttp,
    /// `GET https://…` through the explicit proxy.
    HttpsForward,
    /// A redirected plain HTTP connection.
    TransparentHttp,
    /// A redirected TLS connection, always intercepted.
    TransparentTls,
}

const DOORS: [Door; 6] = [
    Door::ConnectRelay,
    Door::ConnectIntercepted,
    Door::PlainHttp,
    Door::HttpsForward,
    Door::TransparentHttp,
    Door::TransparentTls,
];

/// How long a test waits for an answer. A door that leaves the client to its
/// own timeout fails here.
const ANSWER_WITHIN: Duration = Duration::from_secs(3);

/// Read what `stream` is told until it closes.
async fn read_all<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match tokio::time::timeout(ANSWER_WITHIN, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(n)) => response.extend_from_slice(&chunk[..n]),
            Err(_) => panic!(
                "no answer within {ANSWER_WITHIN:?}; so far: {:?}",
                String::from_utf8_lossy(&response)
            ),
        }
    }
    String::from_utf8_lossy(&response).to_string()
}

/// Send one request for `/v1/x` on `HOST` through `door`, and return what the
/// client was told, once the handler is done.
async fn answer(state: &Arc<ProxyState>, door: Door) -> String {
    if matches!(door, Door::ConnectIntercepted) {
        intercept(state);
    }
    let (mut client, server) = socket_pair().await;
    let actor = test_actor();
    let handler_state = state.clone();
    let handler = tokio::spawn(async move {
        match door {
            Door::TransparentHttp => {
                serve_egress(
                    server,
                    "203.0.113.9:80".parse().unwrap(),
                    actor,
                    handler_state,
                )
                .await
            }
            Door::TransparentTls => {
                serve_egress(
                    server,
                    "203.0.113.9:443".parse().unwrap(),
                    actor,
                    handler_state,
                )
                .await
            }
            _ => serve_explicit(server, actor, handler_state).await,
        }
    });

    let response = match door {
        Door::ConnectRelay => {
            client
                .write_all(
                    format!("CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
            read_all(&mut client).await
        }
        Door::ConnectIntercepted => {
            client
                .write_all(
                    format!("CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
            read_established(&mut client).await;
            let mut tls = sandbox_tls_client(state, client, HOST).await;
            tls.write_all(format!("GET /v1/x HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes())
                .await
                .unwrap();
            read_all(&mut tls).await
        }
        Door::PlainHttp => {
            client
                .write_all(
                    format!("GET http://{HOST}/v1/x HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
            read_all(&mut client).await
        }
        Door::HttpsForward => {
            client
                .write_all(
                    format!("GET https://{HOST}/v1/x HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
            read_all(&mut client).await
        }
        Door::TransparentHttp => {
            client
                .write_all(format!("GET /v1/x HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes())
                .await
                .unwrap();
            read_all(&mut client).await
        }
        Door::TransparentTls => {
            let mut tls = sandbox_tls_client(state, client, HOST).await;
            tls.write_all(format!("GET /v1/x HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes())
                .await
                .unwrap();
            read_all(&mut tls).await
        }
    };
    let _ = tokio::time::timeout(ANSWER_WITHIN, handler)
        .await
        .unwrap_or_else(|_| panic!("{door:?}: the handler ends once it has answered"));
    response
}

/// The client was told `502` and why, in `Proxy-Status`.
fn assert_bad_gateway(door: Door, response: &str, error: &str) {
    assert!(
        response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
        "{door:?}: {response:?}"
    );
    assert!(
        response.contains(&format!("\r\nProxy-Status: sandbox; error={error}\r\n")),
        "{door:?}: {response:?}"
    );
}

/// The request was audited once, as a dial that failed for `error`, and never
/// as a success or a policy refusal.
fn assert_audited_as_failed(door: Door, rx: &mut mpsc::UnboundedReceiver<String>, error: &str) {
    let events = drain_audit_lines(rx);
    assert!(
        !events.iter().any(|e| e["result"] == "success"),
        "{door:?}: a request that reached nothing is no success: {events:?}"
    );
    assert!(
        !events.iter().any(|e| e["result"] == "failure"),
        "{door:?}: a failed dial is not a policy refusal: {events:?}"
    );
    let failed: Vec<_> = events.iter().filter(|e| e["result"] == "error").collect();
    assert_eq!(failed.len(), 1, "{door:?}: {events:?}");
    let event = failed[0];
    assert_eq!(event["status_code"], 502, "{door:?}: {event}");
    assert_eq!(
        event["metadata"]["reason"], "dial-failed",
        "{door:?}: {event}"
    );
    assert_eq!(
        event["metadata"]["proxy_status"], error,
        "{door:?}: {event}"
    );
    assert!(
        event["metadata"]["error"]
            .as_str()
            .is_some_and(|detail| !detail.is_empty()),
        "{door:?}: the event says what failed: {event}"
    );
}

#[tokio::test]
async fn the_embedders_own_resolver_is_asked_on_every_door() {
    for door in DOORS {
        let (state, egress, _rx) = host_state(Lookup::Fails);
        answer(&state, door).await;
        assert_eq!(
            egress.resolved(),
            [HOST],
            "{door:?}: the upstream dial resolves through the embedder's egress"
        );
    }
}

#[tokio::test]
async fn a_name_that_does_not_resolve_is_answered_502_dns_error_on_every_door() {
    for door in DOORS {
        let (state, _egress, mut rx) = host_state(Lookup::Fails);
        let response = answer(&state, door).await;
        assert_bad_gateway(door, &response, "dns_error");
        assert_audited_as_failed(door, &mut rx, "dns_error");
    }
}

#[tokio::test]
async fn a_refused_connect_is_answered_502_connection_refused_on_every_door() {
    for door in DOORS {
        let (state, egress, mut rx) = host_state(Lookup::Answers("203.0.113.7".parse().unwrap()));
        let response = answer(&state, door).await;
        assert_eq!(egress.resolved(), [HOST], "{door:?}");
        assert_bad_gateway(door, &response, "connection_refused");
        assert_audited_as_failed(door, &mut rx, "connection_refused");
    }
}

/// A resolver that never answers (the host's DNS servers went away with a VPN)
/// is cut off at the resolve deadline and told as a DNS failure.
#[tokio::test]
async fn a_resolve_that_never_returns_ends_at_the_deadline_as_502_dns_error_on_every_door() {
    for door in DOORS {
        let (state, egress, mut rx) = host_state(Lookup::Hangs);
        *state.resolve_timeout.write().unwrap() = Duration::from_millis(200);
        let started = tokio::time::Instant::now();
        let response = answer(&state, door).await;
        assert!(
            started.elapsed() < ANSWER_WITHIN,
            "{door:?}: answered at the deadline, not the client's"
        );
        assert_eq!(egress.resolved(), [HOST], "{door:?}");
        assert_bad_gateway(door, &response, "dns_error");
        assert_audited_as_failed(door, &mut rx, "dns_error");
    }
}

#[test]
fn the_resolve_deadline_is_the_documented_default() {
    let (state, _egress, _rx) = host_state(Lookup::Fails);
    assert_eq!(
        *state.resolve_timeout.read().unwrap(),
        crate::egress::RESOLVE_TIMEOUT
    );
}

/// A raw TCP flow has no HTTP to answer in, so a failed dial closes it at once
/// and is audited as failed.
#[tokio::test]
async fn a_raw_flow_whose_dial_fails_is_closed_at_once_and_audited_as_failed() {
    let (state, _egress, mut rx) = host_state(Lookup::Fails);
    install_tcp_rules(
        &state,
        r#"[{"match": "203.0.113.0/24:5432", "verdict": "allow"}]"#,
    );
    let (mut client, server) = socket_pair().await;
    let handler_state = state.clone();
    let handler = tokio::spawn(async move {
        serve_egress(
            server,
            "203.0.113.7:5432".parse().unwrap(),
            test_actor(),
            handler_state,
        )
        .await
    });
    let said = read_all(&mut client).await;
    assert_eq!(said, "", "nothing is said on a raw flow");
    handler.await.unwrap().expect_err("the dial was refused");
    let events = drain_audit_lines(&mut rx);
    let failed: Vec<_> = events.iter().filter(|e| e["result"] == "error").collect();
    assert_eq!(failed.len(), 1, "{events:?}");
    assert_eq!(failed[0]["metadata"]["reason"], "dial-failed", "{events:?}");
    assert_eq!(
        failed[0]["metadata"]["proxy_status"], "connection_refused",
        "{events:?}"
    );
    assert!(
        !events.iter().any(|e| e["result"] == "success"),
        "{events:?}"
    );
}

/// A policy refusal at the dial stays a refusal on the plain HTTP door, as it
/// is on the `CONNECT` door: a `403`, audited as `policy-deny`, never a `502`.
#[tokio::test]
async fn a_tcp_rule_that_refuses_the_resolved_address_stays_a_refusal_on_the_plain_http_door() {
    let (state, _egress, mut rx) = host_state(Lookup::Answers("10.1.2.3".parse().unwrap()));
    install_tcp_rules(&state, r#"[{"match": "10.0.0.0/8:80", "verdict": "deny"}]"#);
    let response = answer(&state, Door::PlainHttp).await;
    assert!(response.starts_with("HTTP/1.1 403 "), "{response:?}");
    let events = drain_audit_lines(&mut rx);
    assert!(
        events
            .iter()
            .any(|e| e["result"] == "failure" && e["metadata"]["reason"] == "policy-deny"),
        "{events:?}"
    );
    assert!(!events.iter().any(|e| e["result"] == "error"), "{events:?}");
}
