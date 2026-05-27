//! Integration tests for the DNS stub resolver over real UDP sockets.
//!
//! Runs on any platform — no nftables required. The tests stand up three
//! actors on loopback:
//!
//! 1. A **mock upstream** UDP socket that echoes canned responses.
//! 2. The **stub** bound on a free port, fed an `Arc<ProxyState>` whose
//!    routes we control.
//! 3. A **client** socket that sends a query and awaits the reply.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::domain::Name;
use hickory_proto::rr::{DNSClass, RecordType};
use lens_sandbox_core::proxy::{ProxyServer, ProxyState};
use lens_sandbox_core::routing::{RouteMatcher, RouteRule, Transport, Verdict};
use tokio::net::UdpSocket;

fn build_query(qname: &str, qtype: RecordType, id: u16) -> Vec<u8> {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let mut q = Query::new();
    q.set_name(Name::from_str(qname).unwrap());
    q.set_query_type(qtype);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);
    msg.to_vec().unwrap()
}

/// Spawn a mock upstream resolver on a random loopback port. Echoes a
/// NOERROR response carrying the query's id and question back to the peer.
async fn spawn_mock_upstream() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
            let msg = Message::from_vec(&buf[..n]).unwrap();
            let mut resp =
                Message::new(msg.metadata.id, MessageType::Response, msg.metadata.op_code);
            resp.metadata.recursion_available = true;
            resp.metadata.response_code = ResponseCode::NoError;
            for q in msg.queries {
                resp.add_query(q);
            }
            let bytes = resp.to_vec().unwrap();
            sock.send_to(&bytes, peer).await.unwrap();
        }
    });
    addr
}

/// Fresh `ProxyState` seeded with the given domain patterns. The proxy's
/// public constructor (`ProxyServer::new`) is the only way to build a
/// state from outside the crate — we never run its listeners.
fn state_with_allow(patterns: &[&str]) -> Arc<ProxyState> {
    let (_srv, state) = ProxyServer::new(
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        None,
        Vec::new(),
    );
    let rules: Vec<RouteRule> = patterns
        .iter()
        .map(|p| RouteRule {
            matcher: RouteMatcher::Domain(p.to_string()),
            verdict: Verdict::Allow,
            transport: Transport::Direct,
            tls_terminate: false,
            http_rules: Vec::new(),
            scheme: None,
        })
        .collect();
    *state.routes.write().unwrap() = rules;
    state
}

/// Bind a stub on a free port, wired to the given upstream. Returns the
/// stub's listen address. The spawned task loops forever; tokio drops it
/// when the runtime shuts down at end-of-test.
async fn spawn_stub_with_upstream(state: Arc<ProxyState>, upstream: SocketAddr) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let socket = Arc::new(sock);
    tokio::spawn(async move {
        lens_sandbox_core::dns::serve(socket, state, upstream).await;
    });
    addr
}

#[tokio::test]
async fn allowed_query_is_forwarded_to_upstream() {
    let upstream = spawn_mock_upstream().await;
    let state = state_with_allow(&["example.com"]);
    let stub_addr = spawn_stub_with_upstream(state, upstream).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(stub_addr).await.unwrap();
    client
        .send(&build_query("example.com", RecordType::A, 0xAAAA))
        .await
        .unwrap();

    let mut buf = [0u8; 1500];
    let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("reply before timeout")
        .expect("recv ok");
    let resp = Message::from_vec(&buf[..n]).unwrap();
    assert_eq!(resp.metadata.id, 0xAAAA);
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
}

#[tokio::test]
async fn denied_query_returns_nxdomain_without_hitting_upstream() {
    // Point the "upstream" at an unreachable loopback port — if the stub
    // ever forwards a denied query, the test would hang on recv() and the
    // 2s timeout would fire. NXDOMAIN from the stub itself gets here fast.
    let unreachable: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let state = state_with_allow(&["example.com"]);
    let stub_addr = spawn_stub_with_upstream(state, unreachable).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(stub_addr).await.unwrap();
    client
        .send(&build_query("evil.com", RecordType::A, 0xBBBB))
        .await
        .unwrap();

    let mut buf = [0u8; 1500];
    let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("NXDOMAIN before timeout")
        .expect("recv ok");
    let resp = Message::from_vec(&buf[..n]).unwrap();
    assert_eq!(resp.metadata.id, 0xBBBB);
    assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
}

#[tokio::test]
async fn wildcard_allow_lets_subdomain_through() {
    let upstream = spawn_mock_upstream().await;
    let state = state_with_allow(&["*.amazonaws.com"]);
    let stub_addr = spawn_stub_with_upstream(state, upstream).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(stub_addr).await.unwrap();
    client
        .send(&build_query(
            "sts.us-east-1.amazonaws.com",
            RecordType::A,
            0xCCCC,
        ))
        .await
        .unwrap();

    let mut buf = [0u8; 1500];
    let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("reply before timeout")
        .expect("recv ok");
    let resp = Message::from_vec(&buf[..n]).unwrap();
    assert_eq!(resp.metadata.id, 0xCCCC);
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
}
