//! The supervisor's own name lookups, against a real cage.
//!
//! A binary-scoped route makes the DNS stub judge the process behind every
//! query it receives. The supervisor is never the process such a rule names —
//! it resolves on the workload's behalf — so a lookup of its own must not reach
//! the stub at all. Whether one does is a kernel question: an unmarked UDP/53
//! query is carried into the stub by an nftables redirect, and only a real chain
//! can say whether a query carried the mark. So this needs Linux and
//! `CAP_NET_ADMIN`, and it is `#[ignore]`d like the other cage tests. CI runs it
//! with `cargo test -- --ignored`.
//!
//! # Why two names
//!
//! The audit path deduplicates by name, so one name could only ever report
//! once. The control phase and the phase under test therefore use different
//! names, and one wildcard rule fences both.

#![cfg(target_os = "linux")]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use lens_sandbox_core::config::DEFAULT_DNS_STUB_PORT;
use lens_sandbox_core::network;
use lens_sandbox_core::proxy::{ProxyServer, ProxyState};
use lens_sandbox_core::routing::{RouteMatcher, RouteRule, Transport, Verdict};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// The one binary the fence admits. Never the test binary, so every query the
/// stub judges is refused.
const FENCED_BINARY: &str = "/usr/bin/curl";

/// RFC 2606 reserves `.invalid`, so nothing real is disturbed and no answer can
/// arrive. The control phase asks for one name, the phase under test the other.
const CONTROL_NAME: &str = "control.invalid";
const PROBE_NAME: &str = "probe.invalid";

/// Long enough for a stub denial to reach the audit channel, short enough not
/// to stall the suite.
const SETTLE: Duration = Duration::from_secs(1);

/// The cage, removed however the test leaves — an assertion that fires mid-test
/// would otherwise strand the table and break every run after it.
struct Cage;

impl Cage {
    fn install() -> Self {
        network::install_network_lockdown().expect("lockdown needs Linux and CAP_NET_ADMIN");
        Cage
    }
}

impl Drop for Cage {
    fn drop(&mut self) {
        network::cleanup_network_lockdown();
    }
}

/// A state whose only route admits `*.invalid` for [`FENCED_BINARY`] alone.
fn fenced_state() -> Arc<ProxyState> {
    let (_server, state) = ProxyServer::new(
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        None,
        Vec::new(),
    );
    state.policy.write().unwrap().routes = vec![RouteRule {
        matcher: RouteMatcher::Domain("*.invalid".to_string()),
        verdict: Verdict::Allow,
        transport: Transport::Direct,
        tls_terminate: false,
        http_rules: Vec::new(),
        scheme: None,
        binaries: Some(vec![PathBuf::from(FENCED_BINARY)]),
    }];
    state
}

/// Bind the stub where the cage's redirect points, so a query that is carried
/// into it arrives. The upstream address is never used: every query this stub
/// judges is refused.
async fn spawn_stub(state: Arc<ProxyState>) -> SocketAddr {
    let listen = SocketAddr::from(([127, 0, 0, 1], DEFAULT_DNS_STUB_PORT));
    let socket = UdpSocket::bind(listen)
        .await
        .expect("the stub port is free");
    let unreachable: SocketAddr = "127.0.0.1:1".parse().unwrap();
    tokio::spawn(async move {
        lens_sandbox_core::dns::serve(Arc::new(socket), state, unreachable).await;
    });
    listen
}

#[tokio::test]
#[ignore]
async fn the_supervisors_own_lookup_never_reaches_the_stub() {
    let state = fenced_state();
    let (audit_tx, mut audit) = mpsc::unbounded_channel();
    *state.audit_tx.lock().unwrap() = Some(audit_tx);
    let stub = spawn_stub(state).await;
    let _cage = Cage::install();

    // Control: a query the stub does receive. This is the failure the report
    // describes — the fence names one binary, the caller is another, and the
    // name is refused. It proves the fence is live and that a refusal reaches
    // the audit channel this test then reads for silence.
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(stub).await.unwrap();
    client
        .send(&query_for(CONTROL_NAME))
        .await
        .expect("the stub is listening");
    tokio::time::sleep(SETTLE).await;
    let refusal = audit
        .try_recv()
        .expect("the stub refuses a query from an unlisted binary");
    assert!(
        refusal.contains("dns-binary-not-allowed"),
        "expected a binary-fence refusal, got {refusal}"
    );

    // The supervisor's own lookup. It leaves on a marked socket, so the cage
    // sends it to the upstream resolver instead of into the stub. The name does
    // not exist, so the answer is an error either way — what matters is that no
    // refusal follows, because the stub never judged it.
    let _ = lens_sandbox_core::resolver::resolve_first(PROBE_NAME, 443).await;
    tokio::time::sleep(SETTLE).await;
    assert!(
        audit.try_recv().is_err(),
        "the supervisor's own lookup was judged by the stub"
    );
}

/// One A query for `qname`, as a client would send it.
fn query_for(qname: &str) -> Vec<u8> {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::domain::Name;
    use hickory_proto::rr::{DNSClass, RecordType};
    use std::str::FromStr;

    let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let mut query = Query::new();
    query.set_name(Name::from_str(qname).unwrap());
    query.set_query_type(RecordType::A);
    query.set_query_class(DNSClass::IN);
    msg.add_query(query);
    msg.to_vec().unwrap()
}
