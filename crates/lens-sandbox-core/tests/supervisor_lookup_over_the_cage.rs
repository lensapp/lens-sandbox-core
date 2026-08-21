//! The supervisor's own name lookups, against a real cage.
//!
//! A binary-scoped route makes the DNS stub judge the process behind every
//! query it receives. The supervisor is never the process such a rule names —
//! it resolves on the workload's behalf — so a lookup of its own must not reach
//! the stub at all. Whether one does is a kernel question: an unmarked UDP/53
//! query is carried into the stub by an nftables redirect, and only a real chain
//! can say whether a query carried the mark. So this needs Linux and
//! `CAP_NET_ADMIN`, and it is `#[ignore]`d like the other cage tests.
//!
//! # Why a network namespace of its own
//!
//! It needs one, and `lo` as the only way out:
//!
//! ```sh
//! sudo unshare -n -- sh -c 'ip link set lo up && ip route add default dev lo &&
//!     cargo test -p lens-sandbox-core --test supervisor_lookup_over_the_cage -- --ignored'
//! ```
//!
//! A sandbox owns its namespace. A developer's machine does not: `resolv.conf`
//! there usually names a forwarding daemon on loopback, and that daemon's own
//! upstream query carries no mark. In a shared namespace the cage catches that
//! query and the stub refuses it, so a refusal no longer says whose lookup it
//! judged and the test cannot tell a marked query from an unmarked one.
//!
//! Alone in a namespace nothing can forward on the supervisor's behalf, and the
//! redirect becomes the only thing that can carry a query to the stub. The
//! default route over `lo` is what gives a query somewhere to go: without any
//! route the send fails before netfilter sees the packet, and a query that lost
//! its mark would never be redirected for the test to catch. A marked query
//! reaches nothing instead, which is the point, and the test needs no network.
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

/// Where the control phase aims its query. `TEST-NET-1` is documented as
/// unreachable, so nothing but the cage's own redirect can answer for it.
const OFF_BOX_RESOLVER: &str = "192.0.2.1:53";

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
async fn spawn_stub(state: Arc<ProxyState>) {
    let listen = SocketAddr::from(([127, 0, 0, 1], DEFAULT_DNS_STUB_PORT));
    let socket = UdpSocket::bind(listen)
        .await
        .expect("the stub port is free");
    let unreachable: SocketAddr = "127.0.0.1:1".parse().unwrap();
    tokio::spawn(async move {
        lens_sandbox_core::dns::serve(Arc::new(socket), state, unreachable).await;
    });
}

#[tokio::test]
#[ignore]
async fn the_supervisors_own_lookup_never_reaches_the_stub() {
    let state = fenced_state();
    let (audit_tx, mut audit) = mpsc::unbounded_channel();
    *state.audit_tx.lock().unwrap() = Some(audit_tx);
    spawn_stub(state).await;
    let _cage = Cage::install();

    // Control: an unmarked query, aimed away from the stub. The redirect is
    // what carries it there, the fence names another binary, and the refusal
    // reaches the audit channel. So this walks the whole delivery path whose
    // silence the next phase reads — redirect live, stub judging, audit
    // flowing — and a phase that cannot fail is not left proving anything.
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(OFF_BOX_RESOLVER).await.unwrap();
    client
        .send(&query_for(CONTROL_NAME))
        .await
        .expect("the default route over lo gives the query somewhere to go");
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
    // not exist, so an error is the expected answer — what matters is that no
    // refusal follows, because the stub never judged it.
    //
    // A resolver that failed to build never opens a socket, and the silence
    // below would then prove nothing. So the failure has to be the lookup's:
    // every lookup-side error names the host it was asked for, and the two
    // configuration failures name no host at all.
    if let Err(error) = lens_sandbox_core::resolver::resolve_first(PROBE_NAME, 443).await {
        assert!(
            error.to_string().contains(PROBE_NAME),
            "no query was ever sent: {error}"
        );
    }
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
