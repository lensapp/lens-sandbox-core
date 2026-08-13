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
//! # What this costs, and what a datagram cannot promise
//!
//! **Every datagram comes here.** The chain's conntrack accept excludes UDP, so
//! an established flow is not waved through: a flow is five numbers, and the
//! kernel hands a source port back out once it is free, so the kernel cannot
//! tell one program's flow from its successor's. The price is a round trip to
//! userspace per packet — nothing at a media stream's rate, and a ceiling worth
//! knowing about for bulk UDP. [`FlowCache`] is what keeps the decision itself a
//! hash lookup rather than a `/proc` walk.
//!
//! **A flow is not a kernel object.** For the same reason, a decision remembered
//! against one is only as trustworthy as it is short-lived, and one a `binaries`
//! rule reached is not remembered at all. See [`FLOW_VERDICT_TTL`] and
//! [`FlowCache`].
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

/// Cap on remembered flows, on standing answers, and on open dialogs. All three
/// are keyed by something a workload can mint at will — a source port, a
/// destination — so all three are pruned and then refused rather than grown
/// without bound. Refusing to grow costs a `/proc` walk per datagram or an
/// unasked question, never a permission.
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

/// How long a claimed dialog stands without an answer. Twice the gate's own
/// timeout, so it can only ever free a claim whose task did not live to release
/// it — a dialog that is merely slow is never taken away from the developer.
const CLAIM_TTL: Duration = crate::gate::DECISION_TIMEOUT.saturating_mul(2);

/// Recoverable errors the queue socket may report in a row before the relay
/// treats them as its end rather than as lost datagrams. A bound, not a budget:
/// it stops a socket that fails every call from spinning a core forever.
const MAX_CONSECUTIVE_RECV_ERRORS: u32 = 64;

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
/// Two verdicts are never remembered here.
///
/// A dropped `ask`, because its answer arrives later and lands in [`Grants`]: a
/// cached refusal would hide that answer for as long as it lived, which is
/// precisely the retry the dialog exists to serve.
///
/// A verdict a `binaries` rule decided, because the key is a flow and a flow is
/// not a program — the reason this module's docs open with. See
/// `RawDecision::caller_scoped`.
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
/// Keyed by the target the card named — the hostname when a pin let a hostname
/// rule bind, else the address. A developer answers for what they were shown, so
/// a name whose next A record differs still lands on the answer they gave.
/// Keying by flow would miss the common retry, because a client that gave up and
/// tried again usually does so from a fresh source port.
///
/// A grant carries no generation. It is consulted from one place only — the arm
/// where the *current* table has just said `ask` about this destination — so the
/// question the developer answered is still the question being asked. A reload
/// that deleted the rule, narrowed it, or turned it into a deny never reaches
/// that arm, and a reload that changed nothing relevant must not throw the
/// answer away: an unrelated policy frame arriving while a card is open is
/// routine, and a generation check would turn a click into silence.
#[derive(Clone, Default)]
struct Grants(Arc<Mutex<HashMap<String, Instant>>>);

impl Grants {
    /// Whether an answer still stands for the target the card named.
    fn admits(&self, shown: &str) -> bool {
        let grants = self.0.lock().unwrap();
        grants
            .get(shown)
            .is_some_and(|expiry| *expiry > Instant::now())
    }

    fn record(&self, shown: String) {
        let mut grants = self.0.lock().unwrap();
        if grants.len() >= MAX_REMEMBERED {
            let now = Instant::now();
            grants.retain(|_, expiry| *expiry > now);
            if grants.len() >= MAX_REMEMBERED {
                // Failing closed here means a developer clicked allow and
                // nothing happened. Say so: silence after a click is the one
                // outcome nobody can diagnose.
                tracing::warn!(
                    target = %shown,
                    "grant table full; a developer's approval was not recorded"
                );
                return;
            }
        }
        grants.insert(shown, Instant::now() + GRANT_TTL);
    }
}

/// Dialogs already open, so a client retrying into a dropped `ask` joins the
/// card it already raised instead of spawning a task per datagram.
///
/// The gate deduplicates the *card*, not the waiting: without this, a client
/// retrying at any rate would pile up one task per datagram, each holding a
/// subscription for up to the gate's decision timeout, and a denial would then
/// emit one audit event per task — a refusal event is not pooled, by design.
///
/// A claim carries an expiry only as a backstop. It is released when the dialog
/// answers; the expiry is what frees a destination whose task never got that
/// far, because a claim nothing releases would drop every later datagram to it
/// in silence — with no card, and nothing in the log to say why.
#[derive(Clone, Default)]
struct Pending(Arc<Mutex<HashMap<String, Instant>>>);

impl Pending {
    /// Claim the dialog for `shown`, or `false` if one is already open. Bounded
    /// like every other table here: at the cap nothing is claimed, so no card is
    /// raised and the datagram is dropped — the answer a card would have needed.
    fn claim(&self, shown: &str) -> bool {
        let mut pending = self.0.lock().unwrap();
        let now = Instant::now();
        if pending.len() >= MAX_REMEMBERED {
            pending.retain(|_, expiry| *expiry > now);
            if pending.len() >= MAX_REMEMBERED {
                tracing::warn!(
                    target = %shown,
                    "too many open udp dialogs; not asking about this one"
                );
                return false;
            }
        }
        if pending.get(shown).is_some_and(|expiry| *expiry > now) {
            return false;
        }
        pending.insert(shown.to_string(), now + CLAIM_TTL);
        true
    }

    fn release(&self, shown: &str) {
        self.0.lock().unwrap().remove(shown);
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
    pending: &Pending,
    runtime: &tokio::runtime::Handle,
) -> Disposition {
    // The cache comes first, ahead of the floor below and the table alike: every
    // answer this function can reach costs a `/proc` walk, and a flow that is
    // still sending is asking a question already answered.
    let generation = state.policy.read().unwrap().generation;
    if let Some(remembered) = cache.get(&datagram, generation) {
        return remembered;
    }

    let target = datagram.dst.to_string();

    // The floor every egress path shares, and not a policy question: an
    // accepted datagram leaves directly, so a link-local destination would
    // reach the host's own metadata surface. A rule cannot grant this.
    if sock_mark::is_disallowed_egress_ip(datagram.dst.ip()) {
        let actor = ActorContext::resolve_udp(datagram.src);
        crate::proxy::emit_policy_deny_connect(state, &target, "blocked-destination", &actor);
        cache.insert(datagram, Disposition::Reject, generation);
        return Disposition::Reject;
    }

    let actor = ActorContext::resolve_udp(datagram.src);
    let decision = crate::proxy::udp_egress_verdict(state, datagram.dst, actor.process());
    let disposition = match decision.verdict {
        Verdict::Allow => {
            crate::proxy::emit_audit(state, &target, "success", 200, &actor);
            Disposition::Accept
        }
        Verdict::Deny => {
            // One reason string for a matched deny and for a table that named
            // nothing: both are the policy refusing, and the relay surfaces a
            // failure to the developer by matching on this exact value.
            crate::proxy::emit_policy_deny_connect(state, &target, "policy-deny", &actor);
            Disposition::Reject
        }
        Verdict::Ask => {
            // Named the way the policy author wrote it, when a pin let a
            // hostname rule bind — a developer cannot answer for an address they
            // never typed, so that name is also what the answer is filed under.
            let shown = decision.matched_target.clone().unwrap_or(target);
            if grants.admits(&shown) {
                crate::proxy::emit_audit(state, &shown, "success", 200, &actor);
                // Remembered like any other accept, if the rule allows it to
                // be. The flow is then admitted for its own, shorter life, so
                // one still sending when the grant lapses finishes on the answer
                // it was given rather than being cut off mid-burst.
                Disposition::Accept
            } else {
                crate::proxy::emit_audit(state, &shown, "failure", 403, &actor);
                ask(state, &decision, shown, grants, pending, runtime);
                // Returned rather than remembered: the answer the dialog is
                // about to produce must reach the retry. See [`FlowCache`].
                return Disposition::Drop;
            }
        }
    };
    if !decision.caller_scoped {
        cache.insert(datagram, disposition, decision.generation);
    }
    disposition
}

/// Put a destination to the developer, and record the answer for the datagrams
/// that follow. Returns at once: the card outlives this datagram by design.
fn ask(
    state: &Arc<ProxyState>,
    decision: &RawDecision,
    shown: String,
    grants: &Grants,
    pending: &Pending,
    runtime: &tokio::runtime::Handle,
) {
    if !pending.claim(&shown) {
        return;
    }
    let reason = decision.reason;
    let state = state.clone();
    let grants = grants.clone();
    let pending = pending.clone();
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
        if answer.is_allow() {
            crate::proxy::emit_gate_resolved(&state, &action, answer);
            grants.record(shown.clone());
            tracing::info!(target = %shown, reason = answer.audit_reason(), "udp egress ALLOWED (gated)");
        } else {
            crate::proxy::emit_gate_denied(&state, &action, answer);
        }
        // Released last, and on both answers: until it is, the destination
        // raises no second card, which is the whole point of claiming it.
        pending.release(&shown);
    });
}

/// Start the relay on its own thread. A datagram is judged synchronously there,
/// so nothing it does can occupy a tokio worker.
///
/// The thread ending is not fatal to the proxy, and not a way through either:
/// with no reader the queue fills and the kernel discards, so UDP simply stays
/// denied. It is logged at error level because that is a real loss of function.
#[cfg(target_os = "linux")]
pub fn spawn(state: Arc<ProxyState>) {
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
    let pending = Pending::default();
    let mut failures = 0u32;
    loop {
        let mut msg = match queue.recv() {
            Ok(msg) => {
                failures = 0;
                msg
            }
            // A signal or a socket that momentarily could not keep up is not a
            // reason to stop policing UDP for the life of the process. Giving up
            // here would leave the cage dropping every datagram in silence — no
            // ICMP, because the rule that sends it is only reached by a verdict.
            Err(e) if is_transient(&e) => {
                failures += 1;
                if failures >= MAX_CONSECUTIVE_RECV_ERRORS {
                    return Err(e);
                }
                // Debug, not warn: `ENOBUFS` is the kernel reporting a flood it
                // could not hold, so this arrives at whatever rate the flood
                // does. The bound above is what makes a real fault loud.
                tracing::debug!("udp egress relay retrying after a queue error: {e}");
                continue;
            }
            Err(e) => return Err(e),
        };
        let disposition = match parse_datagram(msg.get_payload()) {
            Some(datagram) => decide(state, datagram, &mut cache, &grants, &pending, runtime),
            // A shape this layer will not read: a fragment, an IPv6 extension
            // header, a truncated header. Logged at debug and not above, because
            // whatever is producing them is producing them at line rate.
            None => {
                tracing::debug!(
                    bytes = msg.get_payload().len(),
                    "udp egress relay dropped a datagram it could not read"
                );
                Disposition::Drop
            }
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
        // One unanswered packet, which the kernel discards when the queue
        // overflows. The loop outlives it.
        if let Err(e) = queue.verdict(msg) {
            tracing::warn!("udp egress relay could not answer for a datagram: {e}");
        }
    }
}

/// Whether an error on the queue socket is one more datagram lost rather than
/// the relay's end. `ENOBUFS` is the kernel saying it discarded some; `nfq`
/// reports an interrupted dump as `EINTR`.
#[cfg(target_os = "linux")]
fn is_transient(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
    ) || e.raw_os_error() == Some(libc::ENOBUFS)
}

/// NFQUEUE is a Linux facility, and so is the cage it belongs to. Elsewhere the
/// crate still builds and the rest of the proxy still runs; UDP is simply not
/// policed, because on those platforms nothing is confining it either.
#[cfg(not(target_os = "linux"))]
pub fn spawn(_state: Arc<ProxyState>) {
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
            &Pending::default(),
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
    async fn an_answer_stands_while_the_table_still_asks_the_same_question() {
        let ask_rule = r#"[{"match": "10.20.0.0/24:123", "verdict": "ask"}]"#;
        let state = state_with_udp_rules(ask_rule);
        let datagram = Datagram {
            src: "10.0.0.5:41234".parse().unwrap(),
            dst: "10.20.0.9:123".parse().unwrap(),
        };
        let grants = Grants::default();
        grants.record("10.20.0.9:123".to_string());

        let judge = |grants: &Grants| {
            decide(
                &state,
                datagram,
                &mut FlowCache::default(),
                grants,
                &Pending::default(),
                &tokio::runtime::Handle::current(),
            )
        };
        assert_eq!(judge(&grants), Disposition::Accept);

        // An unrelated reload. A policy frame arrives whenever a credential is
        // refreshed, and a developer who has just clicked allow must not have
        // the click quietly discarded by one.
        apply_network_policy(
            &state,
            NetworkPolicy {
                udp_egress: parse_udp_egress(&serde_json::from_str(ask_rule).unwrap()).unwrap(),
                default_verdict: Verdict::Deny,
                ..Default::default()
            },
        );
        assert_eq!(judge(&grants), Disposition::Accept);

        // The rule itself is gone, so nothing asks about this destination any
        // more, and the answer to a question no longer put cannot admit it.
        apply_network_policy(&state, NetworkPolicy::default());
        assert_eq!(judge(&grants), Disposition::Reject);
    }

    #[tokio::test]
    async fn an_admitted_flow_is_remembered_like_any_other_accept() {
        // Otherwise every datagram of an approved flow re-walks `/proc` and
        // raises its own audit event, for as long as the answer stands.
        let state = state_with_udp_rules(r#"[{"match": "10.20.0.0/24:123", "verdict": "ask"}]"#);
        let datagram = Datagram {
            src: "10.0.0.5:41234".parse().unwrap(),
            dst: "10.20.0.9:123".parse().unwrap(),
        };
        let mut cache = FlowCache::default();
        let grants = Grants::default();
        grants.record("10.20.0.9:123".to_string());
        let runtime = tokio::runtime::Handle::current();
        assert_eq!(
            decide(
                &state,
                datagram,
                &mut cache,
                &grants,
                &Pending::default(),
                &runtime
            ),
            Disposition::Accept
        );

        // The same flow, judged with no grant at all. Only the cache can answer.
        assert_eq!(
            decide(
                &state,
                datagram,
                &mut cache,
                &Grants::default(),
                &Pending::default(),
                &runtime
            ),
            Disposition::Accept
        );
    }

    #[tokio::test]
    async fn a_verdict_a_binaries_rule_decided_is_not_remembered() {
        // The cache key is the flow, and a flow is not a process: the kernel
        // reissues a source port as soon as it is free. Remembering this would
        // answer for whichever program binds that port next.
        let allow_ntpd =
            r#"{"match": "10.20.0.0/24:123", "verdict": "allow", "binaries": ["/usr/bin/ntpd"]}"#;
        let deny_all = r#"{"match": "10.20.0.0/24:123", "verdict": "deny"}"#;
        // Both shapes an excluded caller can end on: the rule that named it, and
        // an unrestricted rule further down that it falls through to.
        for table in [
            format!("[{allow_ntpd}]"),
            format!("[{allow_ntpd},{deny_all}]"),
        ] {
            let state = state_with_udp_rules(&table);
            let datagram = Datagram {
                src: "10.0.0.5:41234".parse().unwrap(),
                dst: "10.20.0.9:123".parse().unwrap(),
            };
            let mut cache = FlowCache::default();
            let generation = state.policy.read().unwrap().generation;
            // No process owns this socket here, so the filter fails closed —
            // which is a refusal about a caller, not about a destination.
            assert_eq!(
                decide(
                    &state,
                    datagram,
                    &mut cache,
                    &Grants::default(),
                    &Pending::default(),
                    &tokio::runtime::Handle::current()
                ),
                Disposition::Reject
            );
            assert_eq!(
                cache.get(&datagram, generation),
                None,
                "a caller's verdict must not be left for the next caller to find: {table}"
            );
        }
    }

    #[tokio::test]
    async fn one_open_dialog_per_destination() {
        let state = state_with_udp_rules(r#"[{"match": "10.20.0.0/24:123", "verdict": "ask"}]"#);
        let pending = Pending::default();
        let judge = |src_port: u16| {
            decide(
                &state,
                Datagram {
                    src: SocketAddr::new("10.0.0.5".parse().unwrap(), src_port),
                    dst: "10.20.0.9:123".parse().unwrap(),
                },
                &mut FlowCache::default(),
                &Grants::default(),
                &pending,
                &tokio::runtime::Handle::current(),
            )
        };
        // A client retrying from a fresh source port each time, which is what a
        // client that gave up on a dropped datagram does.
        assert_eq!(judge(41234), Disposition::Drop);
        assert_eq!(judge(41235), Disposition::Drop);
        assert!(
            !pending.claim("10.20.0.9:123"),
            "the retries must join the open card, not raise one each"
        );
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
        let pending = Pending::default();
        assert_eq!(
            decide(&state, datagram, &mut cache, &grants, &pending, &runtime),
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
            decide(&state, datagram, &mut cache, &grants, &pending, &runtime),
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
    fn a_grant_stands_only_for_the_target_the_card_named() {
        let grants = Grants::default();
        grants.record("ntp.internal:123".to_string());
        assert!(grants.admits("ntp.internal:123"));
        assert!(!grants.admits("ntp.internal:124"));
        assert!(!grants.admits("10.20.0.9:123"));
    }
}
