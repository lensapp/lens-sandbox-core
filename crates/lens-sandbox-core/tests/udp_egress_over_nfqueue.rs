//! Raw UDP egress, end to end through the kernel.
//!
//! The relay's parser and its decisions are unit-tested from a byte buffer.
//! What no unit test can answer is whether the kernel and the relay agree: that
//! the filter chain really hands a datagram to the queue, that an accept really
//! releases it, and that a refusal really comes back as an ICMP error rather
//! than as silence. That needs a real chain, so it needs Linux and
//! `CAP_NET_ADMIN`, and it is `#[ignore]`d like the other cage tests: a default
//! `cargo test` on a developer's mac must not try it. CI runs it with
//! `cargo test -- --ignored`.
//!
//! The test installs the crate's own lockdown script, so it judges the rules as
//! shipped rather than a copy written to pass.
//!
//! # Why one test with two phases
//!
//! A queue number takes one reader, and the table has one name. Two test
//! functions would race for both. One function keeps a single relay and a
//! single cage, and changes the policy between the phases — which also shows
//! that the answer follows the policy, not the first datagram.
//!
//! # What the destination has to be
//!
//! Not loopback: the filter chain accepts loopback before the queue rule, so a
//! local echo server would never reach the relay. The probe therefore goes to
//! `TEST-NET-1`, which routes out of the default route and answers nothing. So
//! an accepted datagram is silence too, and silence alone proves little — the
//! accept phase reads the relay's audit record for the proof.

#![cfg(target_os = "linux")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use lens_sandbox_core::network;
use lens_sandbox_core::proxy::{NetworkPolicy, ProxyServer, ProxyState, apply_network_policy};
use lens_sandbox_core::routing::parse_udp_egress;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Documented as unreachable, so nothing answers and nothing is disturbed.
const DESTINATION: &str = "192.0.2.1:9999";

/// Long enough for a locally generated ICMP error to arrive, short enough that
/// a phase expecting silence does not stall the suite.
const SETTLE: Duration = Duration::from_secs(1);

/// Probes the accept phase may spend waiting for the relay to start reading its
/// queue. See the phase for why one probe is not enough.
const PROBE_ATTEMPTS: usize = 3;

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

/// Publish udp rules through the real parser and the real reload path, so the
/// test can only install a shape a policy could carry, and installs it the way a
/// policy frame would — generation bump included, so no decision remembered
/// under the old rules stands.
fn install_udp_rules(state: &Arc<ProxyState>, json: &str) {
    let rules = parse_udp_egress(&serde_json::from_str(json).expect("rules parse as json"))
        .expect("rules are a shape the policy accepts");
    apply_network_policy(
        state,
        NetworkPolicy {
            udp_egress: rules,
            ..NetworkPolicy::default()
        },
    );
}

/// Send one datagram to [`DESTINATION`] and report what came back within
/// `SETTLE`. A connected UDP socket surfaces an ICMP error on its next call, so
/// `Some` is a refusal and `None` is silence.
async fn probe() -> Option<std::io::Error> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.expect("a free port");
    let destination: SocketAddr = DESTINATION.parse().expect("a literal address");
    socket.connect(destination).await.expect("no dial happens");
    if let Err(error) = socket.send(b"probe").await {
        return Some(error);
    }
    let mut buf = [0u8; 64];
    match tokio::time::timeout(SETTLE, socket.recv(&mut buf)).await {
        Ok(Err(error)) => Some(error),
        Ok(Ok(_)) => panic!("{DESTINATION} answered; the test needs a destination that cannot"),
        Err(_) => None,
    }
}

#[tokio::test]
#[ignore]
async fn the_kernel_and_the_relay_agree_on_accept_and_on_refusal() {
    let (_server, state) = ProxyServer::new(
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        None,
        Vec::new(),
    );
    let (audit_tx, mut audit) = mpsc::unbounded_channel();
    *state.audit_tx.lock().unwrap() = Some(audit_tx);

    install_udp_rules(
        &state,
        &format!(r#"[{{"match": "{DESTINATION}", "verdict": "allow"}}]"#),
    );
    lens_sandbox_core::udp_egress::spawn(state.clone());
    let _cage = Cage::install();

    // Phase one: a rule names the destination, so the datagram leaves. Nothing
    // is out there to answer it, and — the point — nothing refuses it either.
    //
    // The relay binds its queue on its own thread, and the chain drops rather
    // than admits while nobody is reading, so a datagram sent into that startup
    // window vanishes. Probe until the relay speaks. A refusal is a real
    // failure at any attempt and stops the test there.
    let mut audited = None;
    for _ in 0..PROBE_ATTEMPTS {
        assert!(
            probe().await.is_none(),
            "an allowed datagram must not be refused"
        );
        if let Ok(record) = audit.try_recv() {
            audited = Some(record);
            break;
        }
    }
    let record = audited.expect("the relay must audit the datagram it allowed");
    assert!(
        record.contains(DESTINATION) && record.contains("success"),
        "audit record does not report the allowed datagram: {record}"
    );

    // Phase two: the rule is gone, so the same destination is now refused —
    // and the sender learns at once, which is what the mark-and-repeat path
    // exists for. A silent drop would leave it waiting out its own timeout.
    install_udp_rules(&state, "[]");
    let refusal = probe()
        .await
        .expect("a datagram no rule names must not leave");
    assert_eq!(
        refusal.kind(),
        std::io::ErrorKind::ConnectionRefused,
        "the refusal must arrive as ICMP port-unreachable: {refusal}"
    );
}
