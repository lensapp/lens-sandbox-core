//! Raw UDP egress: every datagram the sandbox sends is judged against the
//! `egress.udp` table before it leaves.
//!
//! # How a datagram gets here
//!
//! There is no connection to intercept and no `SO_ORIGINAL_DST` to ask —
//! the kernel offers that option to TCP and SCTP only — so the transparent
//! listener's method does not carry over. Instead the `output_filter` chain
//! hands the packet to this process whole, on an NFQUEUE, and the kernel holds
//! it until a verdict comes back. Nothing is rewritten: an accepted datagram
//! goes to the destination the workload chose, from the address it chose, and
//! the reply arrives normally because the cage filters output only.
//!
//! The packet is the evidence. Its header is what the kernel built, not what
//! the sender claims, so the destination read here is the real one.
//!
//! # The three answers
//!
//! - **Accept** — it continues, untouched.
//! - **Reject** — it is marked with [`sock_mark::REJECT_MARK`] and judged again,
//!   so the chain's reject rule answers the sender with ICMP port-unreachable.
//!   A verdict cannot send ICMP itself; this is how a refusal stays the
//!   immediate error it was before UDP was policed at all.
//! - **Drop** — silence. Only for a datagram whose rule says `ask`: the dialog
//!   outlives the datagram, and an ICMP refusal usually surfaces as a hard error
//!   that stops the client retrying into the answer.
//!
//! # What a datagram cannot promise
//!
//! **A live flow outlives a policy.** The queue rule sits after the chain's
//! `ct state established` accept, so once a reply is seen the flow stops coming
//! here and a reload cannot reach it. A live raw TCP splice behaves the same:
//! the generation stamped on a decision voids *pending consent*, never traffic
//! already flowing. A flow that never gets a reply — statsd, syslog — stays new
//! and is judged for every datagram.
//!
//! **A flow is not a kernel object.** Its name is five numbers, and the kernel
//! hands a source port out again once it is free, so a decision remembered
//! against one is only as trustworthy as it is short-lived. See
//! [`FLOW_VERDICT_TTL`].
//!
//! **A sender that does not wait cannot be identified.** Caller identity comes
//! from the socket, and a program that sends one datagram and exits may leave
//! nothing to read. A `binaries` rule then fails closed. Fire-and-forget
//! protocols and that filter do not combine.

// Everything below is reached through the queue loop, which only Linux has. The
// alternative — compiling the module for Linux alone — would take the packet
// parser and the decision logic out of the test run on the machines this crate
// is written on, and those are the parts worth testing anywhere.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::peer_process::ActorContext;
use crate::protocol::Treatment;
use crate::proxy::{ProxyState, RawDecision};
use crate::routing::Verdict;
use crate::sock_mark;

/// UDP's protocol number in an IPv4 `protocol` or IPv6 `next header` field.
const IPPROTO_UDP: u8 = 17;

/// How long one flow's verdict is reused before the flow is judged again.
///
/// A fixed life, not an idle timer: a source port is a name the kernel reissues
/// once it is free, so an entry kept alive by traffic would let whoever inherits
/// the port inherit the verdict too. Ten seconds spares a one-way sender a
/// `/proc` walk per datagram while keeping that window too short to aim at.
const FLOW_VERDICT_TTL: Duration = Duration::from_secs(10);

/// How long a developer's answer to a datagram dialog stands.
///
/// The datagram that raised the card is gone, so the answer can only serve what
/// the workload sends next. It has to outlive the click and the client's retry
/// cadence — a second or two for most, longer for a command the developer
/// re-runs — without becoming policy by the back door. An `allow always` does
/// not depend on this: the relay answers it with a rule, and the rule arrives as
/// its own policy.
const GRANT_TTL: Duration = Duration::from_secs(30);

/// Cap on remembered flows, and on standing answers. Both are keyed by something
/// a workload can mint at will — a source port, a destination — so both are
/// pruned and then refused rather than grown without bound. Refusing to grow
/// costs a `/proc` walk per datagram, never a permission.
const MAX_REMEMBERED: usize = 4096;

/// Bytes of each packet copied to userspace. An IPv4 header is at most 60 and an
/// IPv6 one 40, and the ports are the first 4 bytes after it — so this covers
/// the largest header pair. The kernel keeps the whole packet; only the copy is
/// bounded, and nothing here reads the payload.
const COPY_RANGE: u16 = 68;

/// Packets the kernel will hold for this queue before it starts discarding.
/// Paired with fail-open turned off, so a flood is dropped rather than let
/// through — see [`run`].
const MAX_QUEUED_PACKETS: u32 = 1024;

/// A datagram's two endpoints, read from the packet itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Datagram {
    pub(crate) src: SocketAddr,
    pub(crate) dst: SocketAddr,
}

/// What the relay tells the kernel to do with a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    Accept,
    Reject,
    Drop,
}

/// Read the endpoints out of a queued packet, or `None` for a packet this layer
/// will not judge.
///
/// Everything unreadable is refused rather than guessed at: a truncated header,
/// a protocol that is not UDP, an IPv6 extension header, an IPv4 fragment. The
/// caller drops what this refuses, so each of those shapes fails closed.
///
/// Fragments deserve their own note. A fragment after the first carries no
/// ports, so it could not be matched against a port-scoped rule at all — and
/// judging only the first would let the rest through on its verdict. The kernel
/// fragments after this hook, so a fragment arriving here is already irregular.
pub(crate) fn parse_datagram(packet: &[u8]) -> Option<Datagram> {
    let (src_ip, dst_ip, after_header) = match packet.first()? >> 4 {
        4 => {
            if packet.len() < 20 || packet[9] != IPPROTO_UDP {
                return None;
            }
            // The low 13 bits are the fragment offset and the bit above them is
            // "more fragments"; either set means this packet is a piece.
            if u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0 {
                return None;
            }
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            if header_len < 20 {
                return None;
            }
            let src = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?);
            let dst = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?);
            (IpAddr::V4(src), IpAddr::V4(dst), packet.get(header_len..)?)
        }
        6 => {
            if packet.len() < 40 || packet[6] != IPPROTO_UDP {
                return None;
            }
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
            (IpAddr::V6(src), IpAddr::V6(dst), packet.get(40..)?)
        }
        _ => return None,
    };
    let ports = after_header.get(..4)?;
    Some(Datagram {
        src: SocketAddr::new(src_ip, u16::from_be_bytes([ports[0], ports[1]])),
        dst: SocketAddr::new(dst_ip, u16::from_be_bytes([ports[2], ports[3]])),
    })
}

/// Verdicts already reached, so a flow's second datagram costs no `/proc` walk
/// and raises no second audit event. Owned by the relay thread alone.
///
/// An `ask` is never remembered here. Its answer arrives later and lands in
/// [`Grants`]; a cached refusal would hide that answer for as long as it lived,
/// which is precisely the retry the dialog exists to serve.
#[derive(Default)]
struct FlowCache {
    entries: HashMap<Datagram, Remembered>,
}

/// A decision and the two things that limit how long it may be reused: the
/// policy that reached it, and the clock.
struct Remembered {
    disposition: Disposition,
    generation: u64,
    expiry: Instant,
}

impl FlowCache {
    /// The remembered disposition, if one was reached under `generation` and has
    /// not expired. A reload therefore voids every entry at once, because a
    /// decision belongs to the policy that made it.
    fn get(&self, flow: &Datagram, generation: u64) -> Option<Disposition> {
        let entry = self.entries.get(flow)?;
        (entry.generation == generation && entry.expiry > Instant::now())
            .then_some(entry.disposition)
    }

    fn insert(&mut self, flow: Datagram, disposition: Disposition, generation: u64) {
        if self.entries.len() >= MAX_REMEMBERED {
            let now = Instant::now();
            self.entries.retain(|_, entry| entry.expiry > now);
            if self.entries.len() >= MAX_REMEMBERED {
                return;
            }
        }
        self.entries.insert(
            flow,
            Remembered {
                disposition,
                generation,
                expiry: Instant::now() + FLOW_VERDICT_TTL,
            },
        );
    }
}

/// Answers to datagram dialogs, waiting for the retry they were given for.
///
/// Keyed by destination, which is what the card named. Keying by flow would miss
/// the common retry, because a client that gave up and tried again usually does
/// so from a fresh source port.
#[derive(Clone, Default)]
struct Grants(Arc<Mutex<HashMap<SocketAddr, Granted>>>);

/// An answer, and the policy it was given under. Consent belongs to the policy
/// that raised the question: a reload may have deleted the rule, narrowed it, or
/// turned it into a deny.
struct Granted {
    generation: u64,
    expiry: Instant,
}

impl Grants {
    /// Whether an answer given under `generation` still stands for `dst`.
    fn admits(&self, dst: SocketAddr, generation: u64) -> bool {
        let grants = self.0.lock().unwrap();
        grants
            .get(&dst)
            .is_some_and(|g| g.generation == generation && g.expiry > Instant::now())
    }

    fn record(&self, dst: SocketAddr, generation: u64) {
        let mut grants = self.0.lock().unwrap();
        if grants.len() >= MAX_REMEMBERED {
            let now = Instant::now();
            grants.retain(|_, g| g.expiry > now);
            if grants.len() >= MAX_REMEMBERED {
                // Failing closed here means a developer clicked allow and
                // nothing happened. Say so: silence after a click is the one
                // outcome nobody can diagnose.
                tracing::warn!(%dst, "grant table full; a developer's approval was not recorded");
                return;
            }
        }
        grants.insert(
            dst,
            Granted {
                generation,
                expiry: Instant::now() + GRANT_TTL,
            },
        );
    }
}

/// Judge one datagram.
///
/// Runs on the relay's own thread, so the `/proc` walk here blocks nothing else
/// — and the dialog an `ask` raises is spawned rather than awaited, because
/// waiting for a human with a datagram in hand is what this design refuses to
/// do.
fn decide(
    state: &Arc<ProxyState>,
    datagram: Datagram,
    cache: &mut FlowCache,
    grants: &Grants,
    runtime: &tokio::runtime::Handle,
) -> Disposition {
    let target = datagram.dst.to_string();

    // The floor every egress path shares, and not a policy question: an
    // accepted datagram leaves directly, so a link-local destination would
    // reach the host's own metadata surface. A rule cannot grant this.
    if sock_mark::is_disallowed_egress_ip(datagram.dst.ip()) {
        let actor = ActorContext::resolve_udp(datagram.src);
        crate::proxy::emit_policy_deny_connect(state, &target, "blocked-destination", &actor);
        return Disposition::Reject;
    }

    let generation = state.policy.read().unwrap().generation;
    if let Some(remembered) = cache.get(&datagram, generation) {
        return remembered;
    }

    let actor = ActorContext::resolve_udp(datagram.src);
    let decision = crate::proxy::udp_egress_verdict(state, datagram.dst, actor.process());
    match decision.verdict {
        Verdict::Allow => {
            crate::proxy::emit_audit(state, &target, "success", 200, &actor);
            cache.insert(datagram, Disposition::Accept, decision.generation);
            Disposition::Accept
        }
        Verdict::Deny => {
            // One reason string for a matched deny and for a table that named
            // nothing: both are the policy refusing, and the relay surfaces a
            // failure to the developer by matching on this exact value.
            crate::proxy::emit_policy_deny_connect(state, &target, "policy-deny", &actor);
            cache.insert(datagram, Disposition::Reject, decision.generation);
            Disposition::Reject
        }
        Verdict::Ask if grants.admits(datagram.dst, decision.generation) => {
            crate::proxy::emit_audit(state, &target, "success", 200, &actor);
            Disposition::Accept
        }
        Verdict::Ask => {
            ask(state, &decision, datagram.dst, grants, runtime);
            crate::proxy::emit_audit(state, &target, "failure", 403, &actor);
            Disposition::Drop
        }
    }
}

/// Put a destination to the developer, and record the answer for the datagrams
/// that follow. Returns at once: the card outlives this datagram by design.
///
/// The gate deduplicates on the action, so a client retrying into a refusal
/// joins the open dialog instead of raising a second card.
fn ask(
    state: &Arc<ProxyState>,
    decision: &RawDecision,
    dst: SocketAddr,
    grants: &Grants,
    runtime: &tokio::runtime::Handle,
) {
    // Named the way the policy author wrote it, when a pin let a hostname rule
    // bind — a developer cannot answer for an address they never typed.
    let shown = decision
        .matched_target
        .clone()
        .unwrap_or_else(|| dst.to_string());
    let generation = decision.generation;
    let reason = decision.reason;
    let state = state.clone();
    let grants = grants.clone();
    runtime.spawn(async move {
        let action = format!("UDP {shown}");
        let answer = crate::gate::gate_or_deny(
            &state,
            &crate::proxy::gate_key(&shown),
            &action,
            reason,
            Treatment::Datagram,
        )
        .await;
        if !answer.is_allow() {
            crate::proxy::emit_gate_denied(&state, &action, answer);
            return;
        }
        // The answer belongs to the policy that raised the question. A reload
        // while the card was open may have deleted the rule, narrowed it, or
        // turned it into a deny, and the generation carried here is what stops
        // consent surviving that.
        crate::proxy::emit_gate_resolved(&state, &action, answer);
        grants.record(dst, generation);
        tracing::info!(target = %shown, reason = answer.audit_reason(), "udp egress ALLOWED (gated)");
    });
}

/// Start the relay on its own thread. A datagram is judged synchronously there,
/// so nothing it does can occupy a tokio worker.
///
/// The thread ending is not fatal to the proxy, and not a way through either:
/// with no reader the queue fills and the kernel discards, so UDP simply stays
/// denied. It is logged at error level because that is a real loss of function.
#[cfg(target_os = "linux")]
pub(crate) fn spawn(state: Arc<ProxyState>) {
    let runtime = tokio::runtime::Handle::current();
    let thread = std::thread::Builder::new()
        .name("udp-egress".to_string())
        .spawn(move || match run(&state, &runtime) {
            Ok(()) => tracing::error!("udp egress relay ended; udp stays denied"),
            Err(e) => tracing::error!("udp egress relay failed: {e}; udp stays denied"),
        });
    if let Err(e) = thread {
        tracing::error!("could not start the udp egress relay: {e}; udp stays denied");
    }
}

/// Bind the queue and judge what arrives, forever.
#[cfg(target_os = "linux")]
fn run(state: &Arc<ProxyState>, runtime: &tokio::runtime::Handle) -> std::io::Result<()> {
    let queue_num = crate::config::DEFAULT_UDP_QUEUE_NUM;
    let mut queue = nfq::Queue::open()?;
    queue.bind(queue_num)?;
    queue.set_copy_range(queue_num, COPY_RANGE)?;
    queue.set_queue_max_len(queue_num, MAX_QUEUED_PACKETS)?;
    // The setting that decides which way a full queue fails. Left on, the kernel
    // would accept what it could not show us — every datagram past the cap
    // leaving unjudged, exactly when something is flooding.
    queue.set_fail_open(queue_num, false)?;
    tracing::info!(queue = queue_num, "udp egress relay judging datagrams");

    let mut cache = FlowCache::default();
    let grants = Grants::default();
    loop {
        let mut msg = queue.recv()?;
        let disposition = match parse_datagram(msg.get_payload()) {
            Some(datagram) => decide(state, datagram, &mut cache, &grants, runtime),
            None => Disposition::Drop,
        };
        match disposition {
            Disposition::Accept => msg.set_verdict(nfq::Verdict::Accept),
            Disposition::Drop => msg.set_verdict(nfq::Verdict::Drop),
            Disposition::Reject => {
                // Not a drop wearing a different name: the mark sends the packet
                // back through the chain, where the reject rule answers the
                // sender. See `sock_mark::REJECT_MARK`.
                msg.set_nfmark(sock_mark::REJECT_MARK);
                msg.set_verdict(nfq::Verdict::Repeat);
            }
        }
        queue.verdict(msg)?;
    }
}

/// NFQUEUE is a Linux facility, and so is the cage it belongs to. Elsewhere the
/// crate still builds and the rest of the proxy still runs; UDP is simply not
/// policed, because on those platforms nothing is confining it either.
#[cfg(not(target_os = "linux"))]
pub(crate) fn spawn(_state: Arc<ProxyState>) {
    tracing::info!("udp egress relay not started: NFQUEUE requires Linux");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{NetworkPolicy, apply_network_policy};
    use crate::routing::parse_udp_egress;

    /// An IPv4 UDP packet with the given endpoints.
    fn ipv4_packet(src: &str, src_port: u16, dst: &str, dst_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45; // version 4, 5 words of header
        packet[9] = IPPROTO_UDP;
        packet[12..16].copy_from_slice(&src.parse::<Ipv4Addr>().unwrap().octets());
        packet[16..20].copy_from_slice(&dst.parse::<Ipv4Addr>().unwrap().octets());
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        packet
    }

    fn ipv6_packet(src: &str, src_port: u16, dst: &str, dst_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 48];
        packet[0] = 0x60; // version 6
        packet[6] = IPPROTO_UDP;
        packet[8..24].copy_from_slice(&src.parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&dst.parse::<Ipv6Addr>().unwrap().octets());
        packet[40..42].copy_from_slice(&src_port.to_be_bytes());
        packet[42..44].copy_from_slice(&dst_port.to_be_bytes());
        packet
    }

    #[test]
    fn parses_an_ipv4_datagram() {
        let packet = ipv4_packet("10.0.0.5", 41234, "10.20.0.9", 123);
        assert_eq!(
            parse_datagram(&packet),
            Some(Datagram {
                src: "10.0.0.5:41234".parse().unwrap(),
                dst: "10.20.0.9:123".parse().unwrap(),
            })
        );
    }

    #[test]
    fn parses_an_ipv6_datagram() {
        let packet = ipv6_packet("2001:db8::5", 41234, "2001:db8::9", 123);
        assert_eq!(
            parse_datagram(&packet),
            Some(Datagram {
                src: "[2001:db8::5]:41234".parse().unwrap(),
                dst: "[2001:db8::9]:123".parse().unwrap(),
            })
        );
    }

    #[test]
    fn reads_the_ports_past_ipv4_options() {
        // A header longer than the minimum moves the ports. Reading them at a
        // fixed offset would judge two bytes of an option as the destination
        // port, and match the wrong rule.
        let mut packet = ipv4_packet("10.0.0.5", 41234, "10.20.0.9", 123);
        packet[0] = 0x46; // 6 words: one 4-byte option
        packet.splice(20..20, [0u8; 4]);
        packet[24..26].copy_from_slice(&41234u16.to_be_bytes());
        packet[26..28].copy_from_slice(&123u16.to_be_bytes());
        assert_eq!(
            parse_datagram(&packet).map(|d| d.dst),
            Some("10.20.0.9:123".parse().unwrap())
        );
    }

    #[test]
    fn refuses_what_it_cannot_read() {
        let full = ipv4_packet("10.0.0.5", 41234, "10.20.0.9", 123);

        // Not UDP.
        let mut other_protocol = full.clone();
        other_protocol[9] = 6;
        assert_eq!(parse_datagram(&other_protocol), None);

        // A fragment, by offset or by the more-fragments bit. Neither can be
        // matched against a port-scoped rule.
        for flags in [0x0020u16, 0x2000] {
            let mut fragment = full.clone();
            fragment[6..8].copy_from_slice(&flags.to_be_bytes());
            assert_eq!(parse_datagram(&fragment), None, "flags {flags:#06x}");
        }

        // A header claiming fewer than the five words it must have.
        let mut short_header = full.clone();
        short_header[0] = 0x44;
        assert_eq!(parse_datagram(&short_header), None);

        // Truncated before the ports, and an IP version that is neither.
        assert_eq!(parse_datagram(&full[..22]), None);
        assert_eq!(parse_datagram(&[]), None);
        let mut bad_version = full.clone();
        bad_version[0] = 0x55;
        assert_eq!(parse_datagram(&bad_version), None);
    }

    #[test]
    fn an_ipv6_extension_header_is_refused() {
        // Hop-by-hop options sit between the header and the ports. Reading the
        // ports at a fixed offset would take two option bytes for a port.
        let mut packet = ipv6_packet("2001:db8::5", 41234, "2001:db8::9", 123);
        packet[6] = 0; // hop-by-hop, not UDP
        assert_eq!(parse_datagram(&packet), None);
    }

    fn state_with_udp_rules(json: &str) -> Arc<ProxyState> {
        let (state, _rx) = crate::proxy::tests::test_state();
        let rules = parse_udp_egress(&serde_json::from_str(json).unwrap()).unwrap();
        apply_network_policy(
            &state,
            NetworkPolicy {
                udp_egress: rules,
                ..Default::default()
            },
        );
        state
    }

    /// The relay's answer for a datagram to `dst`, with a fresh cache.
    async fn disposition_for(state: &Arc<ProxyState>, dst: &str) -> Disposition {
        let datagram = Datagram {
            src: "10.0.0.5:41234".parse().unwrap(),
            dst: dst.parse().unwrap(),
        };
        decide(
            state,
            datagram,
            &mut FlowCache::default(),
            &Grants::default(),
            &tokio::runtime::Handle::current(),
        )
    }

    #[tokio::test]
    async fn a_rule_allows_its_own_destination_only() {
        let state = state_with_udp_rules(r#"[{"match": "10.20.0.0/24:123", "verdict": "allow"}]"#);
        assert_eq!(
            disposition_for(&state, "10.20.0.9:123").await,
            Disposition::Accept
        );
        // The same host on another port, and another host on the same port, are
        // both destinations no rule names.
        assert_eq!(
            disposition_for(&state, "10.20.0.9:124").await,
            Disposition::Reject
        );
        assert_eq!(
            disposition_for(&state, "10.30.0.9:123").await,
            Disposition::Reject
        );
    }

    #[tokio::test]
    async fn a_destination_no_rule_names_is_refused() {
        // There is no second table for a datagram to fall through to, so an
        // empty udp table denies everything — whatever the default verdict for
        // the connection tables says.
        let (state, _rx) = crate::proxy::tests::test_state();
        apply_network_policy(
            &state,
            NetworkPolicy {
                default_verdict: Verdict::Allow,
                ..Default::default()
            },
        );
        assert_eq!(
            disposition_for(&state, "10.20.0.9:123").await,
            Disposition::Reject
        );
    }

    #[tokio::test]
    async fn the_floor_refuses_link_local_whatever_the_rule_says() {
        // Cloud metadata. An accepted datagram leaves directly, so no rule may
        // grant this.
        let state =
            state_with_udp_rules(r#"[{"match": "169.254.0.0/16:123", "verdict": "allow"}]"#);
        assert_eq!(
            disposition_for(&state, "169.254.169.254:123").await,
            Disposition::Reject
        );
    }

    #[tokio::test]
    async fn an_ask_drops_the_datagram_that_raised_it() {
        // Silence, not a refusal: the client must keep retrying to meet the
        // answer, and an ICMP error usually stops it.
        let state = state_with_udp_rules(r#"[{"match": "10.20.0.0/24:123", "verdict": "ask"}]"#);
        assert_eq!(
            disposition_for(&state, "10.20.0.9:123").await,
            Disposition::Drop
        );
    }

    #[tokio::test]
    async fn an_answered_ask_admits_the_retry_until_the_policy_moves() {
        let state = state_with_udp_rules(r#"[{"match": "10.20.0.0/24:123", "verdict": "ask"}]"#);
        let dst: SocketAddr = "10.20.0.9:123".parse().unwrap();
        let datagram = Datagram {
            src: "10.0.0.5:41234".parse().unwrap(),
            dst,
        };
        let grants = Grants::default();
        let generation = state.policy.read().unwrap().generation;
        grants.record(dst, generation);

        let judge = |grants: &Grants| {
            decide(
                &state,
                datagram,
                &mut FlowCache::default(),
                grants,
                &tokio::runtime::Handle::current(),
            )
        };
        assert_eq!(judge(&grants), Disposition::Accept);

        // A reload is a new question. Consent belongs to the policy that asked
        // it, so the answer must not carry over.
        apply_network_policy(
            &state,
            NetworkPolicy {
                udp_egress: parse_udp_egress(
                    &serde_json::from_str(r#"[{"match": "10.20.0.0/24:123", "verdict": "ask"}]"#)
                        .unwrap(),
                )
                .unwrap(),
                default_verdict: Verdict::Deny,
                ..Default::default()
            },
        );
        assert_eq!(judge(&grants), Disposition::Drop);
    }

    #[tokio::test]
    async fn a_remembered_verdict_is_dropped_when_the_policy_moves() {
        let state = state_with_udp_rules(r#"[{"match": "10.20.0.0/24:123", "verdict": "allow"}]"#);
        let datagram = Datagram {
            src: "10.0.0.5:41234".parse().unwrap(),
            dst: "10.20.0.9:123".parse().unwrap(),
        };
        let mut cache = FlowCache::default();
        let runtime = tokio::runtime::Handle::current();
        let grants = Grants::default();
        assert_eq!(
            decide(&state, datagram, &mut cache, &grants, &runtime),
            Disposition::Accept
        );

        // Same flow, revoked policy. The cache must not answer for it.
        apply_network_policy(
            &state,
            NetworkPolicy {
                udp_egress: Vec::new(),
                ..Default::default()
            },
        );
        assert_eq!(
            decide(&state, datagram, &mut cache, &grants, &runtime),
            Disposition::Reject
        );
    }

    #[test]
    fn the_flow_cache_forgets_a_superseded_generation() {
        let flow = Datagram {
            src: "10.0.0.5:41234".parse().unwrap(),
            dst: "10.20.0.9:123".parse().unwrap(),
        };
        let mut cache = FlowCache::default();
        cache.insert(flow, Disposition::Accept, 7);
        assert_eq!(cache.get(&flow, 7), Some(Disposition::Accept));
        assert_eq!(cache.get(&flow, 8), None);
    }

    #[test]
    fn a_grant_stands_only_for_its_own_destination_and_generation() {
        let grants = Grants::default();
        let dst: SocketAddr = "10.20.0.9:123".parse().unwrap();
        grants.record(dst, 3);
        assert!(grants.admits(dst, 3));
        assert!(!grants.admits(dst, 4));
        assert!(!grants.admits("10.20.0.9:124".parse().unwrap(), 3));
    }
}
