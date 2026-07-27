//! DNS stub resolver: filters unmarked UDP/53 queries against the route
//! allowlist before forwarding them to the host resolver.
//!
//! nftables REDIRECTs `meta mark != MARK_VALUE` UDP/53 traffic to this listener
//! (`127.0.0.1:5355` by default). For each query we parse the first question,
//! match its QNAME against `ProxyState.routes` via
//! `routing::hostname_match_for_caller` (Domain and HostPort matchers;
//! wildcards supported; CIDR matchers are intentionally excluded — a bare IP
//! literal is not a legitimate QNAME and allowing it would leak CIDR policy to
//! the upstream resolver. IP-based access is still enforced at the TCP layer).
//! Explicit `Deny` rules take first-match precedence, same as
//! `find_matching_route`. When a route carries a `binaries` filter we resolve
//! the querying process (best-effort, via `/proc`) so a name reachable only by
//! other binaries fails closed here, exactly as it would at the TCP layer. The
//! stub then either forwards allowed queries upstream or responds with
//! NXDOMAIN + a deny audit event.
//!
//! Without this filter, an allow-UDP/53 rule opens a ~50 B/s covert channel
//! through the upstream resolver (QNAME-encoded exfil, TXT-encoded ingress).
//! Gating queries by the same allowlist that already protects TCP closes
//! that door without adding any new policy surface.
//!
//! Allowed `AAAA`, `HTTPS` (type 65), and `SVCB` (type 64) queries are
//! answered with NODATA (NOERROR + empty answer) rather than forwarded: the
//! transparent interceptor binds IPv4 loopback only, and all three record
//! types can hand the workload an address that routes around it — AAAA a real
//! IPv6 address, HTTPS/SVCB an `ipv4hint`/`ipv6hint`. NODATA is the standard
//! "nothing of this type here" signal, so the client falls back to the A
//! record and the v4 redirect catches it, keeping all egress on the
//! interceptable IPv4 path. Denied names keep their NXDOMAIN path.
//!
//! Not handled (intentional, v1 scope):
//! - TCP/53 fallback (rare for A/AAAA responses; the NAT chain REDIRECTs
//!   TCP/53 into the transparent listener, which classifies DNS as Unknown
//!   and drops — same user-visible behaviour as blocking).
//! - Caching — the upstream (Docker's `127.0.0.11` or Colima's
//!   `192.168.5.1`) already caches.
//! - DNSSEC validation — out of scope; we forward DNSSEC records opaquely.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::peer_process::{PeerProcess, resolve_udp_offloaded};
use crate::proxy::{ProxyState, emit_deny_event, pin_dns_answers};
use crate::routing::{FqdnPin, HostnameMatch, hostname_match_for_caller, matching_fqdn_pin};
use crate::sock_mark;

/// Receive buffer for incoming DNS *queries*. 1232 is the EDNS0-recommended
/// payload that fits in the smallest common path MTU (1280 for IPv6, less
/// fragmentation overhead) — queries themselves fit in 512 bytes trivially,
/// so this is generous.
const QUERY_BUF_SIZE: usize = 1232;

/// Receive buffer for upstream *responses*. Has to be larger than the query
/// buffer: well-behaved EDNS0 clients advertise 4096 in their OPT record,
/// and the upstream resolver will use the full size for DNSSEC RRSIGs,
/// long TXT/MX, and fat CNAME chains. Sizing this at 1232 (the query
/// recommendation) silently truncates real-world responses without setting
/// the TC bit, and the client sees a malformed message.
const RESPONSE_BUF_SIZE: usize = 4096;

/// Upstream query timeout. Two seconds matches glibc's default per-server
/// timeout — if the upstream is slower than that, let the client's own
/// resolver retry.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);

/// Cap on concurrent in-flight DNS queries. A malicious sandbox user can
/// blast 127.0.0.1:53 (post-REDIRECT) at line rate; without a bound each
/// datagram would spawn a task and an ephemeral upstream socket, letting
/// the sandbox exhaust the proxy's fd/memory budget. 64 is generous for
/// real workloads (glibc's default is ~3 concurrent outstanding queries
/// per resolver) and cheap to keep warm.
const MAX_INFLIGHT_QUERIES: usize = 64;

/// Run the UDP DNS stub. One bound socket, one receive loop, one spawned task
/// per query so a slow upstream doesn't block the accept path.
pub async fn run(listen_addr: SocketAddr, state: Arc<ProxyState>) -> Result<(), String> {
    let upstream = discover_upstream()
        .ok_or_else(|| "no upstream nameserver found (check /etc/resolv.conf)".to_string())?;
    let socket = UdpSocket::bind(listen_addr)
        .await
        .map_err(|e| format!("dns stub bind {listen_addr}: {e}"))?;
    tracing::info!(listen = %listen_addr, upstream = %upstream, "dns stub listening");
    serve(Arc::new(socket), state, upstream).await;
    Ok(())
}

/// Core receive loop, factored out so integration tests can drive it with a
/// pre-bound socket and an explicit upstream (avoids depending on
/// `/etc/resolv.conf`). Runs until the socket errors or the task is
/// cancelled.
pub async fn serve(socket: Arc<UdpSocket>, state: Arc<ProxyState>, upstream: SocketAddr) {
    let semaphore = Arc::new(Semaphore::new(MAX_INFLIGHT_QUERIES));
    let mut buf = [0u8; QUERY_BUF_SIZE];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("dns stub recv error: {e}");
                continue;
            }
        };
        // `try_acquire_owned` — non-blocking. If the stub is saturated we
        // drop the datagram rather than let the queue grow; the client's
        // resolver will retry. The warn log isn't rate-limited here — rely
        // on the tracing layer's own filtering if a saturated stub becomes
        // a noise problem.
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(
                    peer = %peer,
                    "dns stub at capacity ({MAX_INFLIGHT_QUERIES}), dropping query"
                );
                continue;
            }
        };
        let packet = buf[..n].to_vec();
        let socket = socket.clone();
        let state = state.clone();
        // `permit` is moved into the task; dropping it at task end releases
        // the semaphore slot.
        tokio::spawn(async move {
            let _permit = permit;
            handle_query(packet, peer, &socket, &state, upstream).await;
        });
    }
}

/// Handle one received datagram. Decides allow/deny against the route
/// allowlist, then either forwards upstream or synthesises NXDOMAIN.
async fn handle_query(
    packet: Vec<u8>,
    peer: SocketAddr,
    socket: &UdpSocket,
    state: &Arc<ProxyState>,
    upstream: SocketAddr,
) {
    let decision = resolve_decision(&packet, peer, state).await;

    match decision {
        Decision::Allow {
            qname,
            pin,
            generation,
        } => {
            tracing::debug!(qname = %qname, "dns stub forwarding");
            if let Err(e) = forward_upstream(
                &packet,
                upstream,
                socket,
                peer,
                state,
                pin.as_ref(),
                generation,
            )
            .await
            {
                tracing::warn!(qname = %qname, "dns stub upstream error: {e}");
            }
        }
        Decision::Deny { qname, reason } => {
            emit_deny(state, &qname, reason);
            if let Some(resp) = empty_response(&packet, ResponseCode::NXDomain) {
                let _ = socket.send_to(&resp, peer).await;
            }
        }
        Decision::SuppressNodata { qname } => {
            tracing::debug!(qname = %qname, "dns stub answering AAAA/HTTPS/SVCB with NODATA to force IPv4");
            if let Some(resp) = empty_response(&packet, ResponseCode::NoError) {
                let _ = socket.send_to(&resp, peer).await;
            }
        }
        Decision::Malformed => {
            // Silently drop — replying FORMERR would leak that the stub
            // exists. The client's own retry logic handles timeouts.
            tracing::debug!("dns stub dropping malformed query");
        }
    }
}

enum Decision {
    /// Resolve the name. `pin` is the `tcp_fqdn` pin spec its A answers should
    /// be recorded against (`None` for names with no fqdn tcp rule).
    /// `generation` is the policy generation this decision was made under, so a
    /// pin from an answer that lands after a policy change can be dropped.
    Allow {
        qname: String,
        pin: Option<FqdnPin>,
        generation: u64,
    },
    Deny {
        qname: String,
        reason: &'static str,
    },
    SuppressNodata {
        qname: String,
    },
    Malformed,
}

/// Audit reason for a name blocked because no route allows it (or an explicit
/// `Deny` matched).
const DENY_REASON: &str = "dns-denied";
/// Audit reason for a name whose only matching route is scoped to binaries
/// other than the caller's — the DNS analogue of a `binary_filtered` TCP miss.
const BINARY_DENY_REASON: &str = "dns-binary-not-allowed";

/// Classify a query, resolving the querying process only when the policy has a
/// binary-scoped rule — the one thing a caller can change. A no-`binaries`
/// policy never walks `/proc`; otherwise we resolve once (offloaded) and
/// classify with the real caller, so DNS and the TCP layer stay in lockstep.
/// An unresolvable caller fails a binary-scoped name closed.
///
/// We deliberately do NOT narrow this to "resolve only when the caller-less
/// classification is `BinaryDenied`": once a binary rule excludes a missing
/// caller, a *later* unrestricted `deny` produces a plain `Denied` that is
/// indistinguishable from a caller-independent deny, so a listed binary that
/// the TCP layer would allow (allow-for-binary, then deny-the-broader-domain)
/// would be wrongly NXDOMAIN'd. The walk under a binary policy is bounded by
/// the inflight semaphore.
async fn resolve_decision(packet: &[u8], peer: SocketAddr, state: &ProxyState) -> Decision {
    // Scoped so the policy read guard drops before the `.await` below — a
    // std RwLock guard must never be held across an await point.
    let has_binary_rule = {
        let policy = state.policy.read().unwrap();
        policy.routes.iter().any(|r| r.binaries.is_some())
            || policy.tcp_fqdn.iter().any(|r| r.binaries.is_some())
    };
    let caller = if has_binary_rule {
        resolve_udp_offloaded(peer).await
    } else {
        None
    };
    classify_query(packet, state, caller.as_ref())
}

/// Parse the request and match its first question against the allowlist.
/// `caller` is the resolved querying process (see [`resolve_decision`]), used
/// to apply a route's `binaries` filter. Split out for direct unit testing —
/// no I/O, no async.
fn classify_query(packet: &[u8], state: &ProxyState, caller: Option<&PeerProcess>) -> Decision {
    let Ok(msg) = Message::from_vec(packet) else {
        return Decision::Malformed;
    };
    let Some(query) = msg.queries.first() else {
        return Decision::Malformed;
    };
    // `to_utf8` yields a trailing dot for absolute names (e.g.
    // "example.com.") — strip it so `find_matching_route`'s host-level
    // comparisons line up with domain patterns from policy. Also lower
    // the name: DNS is case-insensitive per RFC 1035 §2.3.3, and if we
    // used the raw qname in the dedup key a caller could bypass the
    // audit dedup (and spam events) by varying case —
    // `EVIL.example.com`, `Evil.example.com`, etc.
    let qname = query.name().to_utf8();
    let stripped = qname.strip_suffix('.').unwrap_or(&qname);
    let normalized = stripped.to_ascii_lowercase();

    // AAAA answers point the workload at an IPv6 address the IPv4-only
    // transparent interceptor can't catch; HTTPS (65) and SVCB (64) records
    // carry ipv4hint/ipv6hint/ALPN that route around the proxy the same way;
    // and an ANY (255) query would let the upstream reply carry any of those
    // record types in one response. So an allowed name resolves its A record
    // (forward) and all of these to NODATA, keeping egress on the interceptable
    // IPv4 path. NOTE: this gates on the *query* type, not the response — the
    // additional section of a forwarded non-suppressed reply could still carry
    // hints; scrubbing those records out of the response would be the more
    // complete fix. Denial is unaffected: a denied name gets NXDOMAIN
    // regardless of record type.
    let should_suppress = matches!(
        query.query_type(),
        RecordType::AAAA | RecordType::HTTPS | RecordType::SVCB | RecordType::ANY
    );
    // Read the L7 routes, the FQDN rules, and the generation under ONE policy
    // snapshot. The DNS verdict pairs an L7-route match with an FQDN-derived
    // pin stamped with the generation, so all three must come from the same
    // policy — reading them separately would let a reload pair one policy's L7
    // allow with another policy's FQDN pin (and stamp it with a generation the
    // pin doesn't belong to). A reload swaps the whole snapshot and bumps the
    // generation atomically, so an equal generation at pin-insertion time still
    // proves the pin matches the policy in force. `pin` is `None` for names
    // with no fqdn tcp rule; it is attached to any allow so the stub records
    // the answer IPs for the TCP layer.
    let policy = state.policy.read().unwrap();
    let generation = policy.generation;
    let pin = matching_fqdn_pin(&policy.tcp_fqdn, &normalized, caller);
    let fqdn_match = hostname_match_for_caller(&policy.tcp_fqdn, &normalized, caller);

    let allow = |qname, pin| {
        if should_suppress {
            Decision::SuppressNodata { qname }
        } else {
            Decision::Allow {
                qname,
                pin,
                generation,
            }
        }
    };

    // Supervisor bootstrap hosts (set once at startup, never updated) need
    // to resolve before any policy has arrived — otherwise the supervisor
    // can't even connect to Lens Sandbox to fetch the first policy.
    if state
        .bootstrap_dns_allowlist
        .iter()
        .any(|h| h == &normalized)
    {
        return allow(normalized, pin);
    }

    // DNS matches on hostname only (no scheme/port); port- and scheme-aware
    // enforcement still applies at the subsequent TCP step. `caller` applies
    // any `binaries` filter, so a name reachable only by other binaries fails
    // closed here just as it would at the TCP layer.
    let matched = hostname_match_for_caller(&policy.routes, &normalized, caller);
    drop(policy);
    match matched {
        HostnameMatch::Allowed => return allow(normalized, pin),
        HostnameMatch::Denied => {
            return Decision::Deny {
                qname: normalized,
                reason: DENY_REASON,
            };
        }
        // A binary-scoped rule matched the name but excluded the caller. Fail
        // closed with its own reason, and — unlike an unmatched name — do not
        // consult the JIT-approved set: that set is host-keyed, so honouring it
        // would let any binary re-open a host once any binary got it approved.
        HostnameMatch::BinaryDenied => {
            return Decision::Deny {
                qname: normalized,
                reason: BINARY_DENY_REASON,
            };
        }
        HostnameMatch::Unmatched => {}
    }

    // No l7 route matched — a raw-TCP fqdn rule may still permit the lookup so
    // its answer IPs can be pinned for the TCP layer. Same first-match / deny /
    // binary-scoping semantics as the l7 gate above.
    match fqdn_match {
        HostnameMatch::Allowed => return allow(normalized, pin),
        HostnameMatch::Denied => {
            return Decision::Deny {
                qname: normalized,
                reason: DENY_REASON,
            };
        }
        HostnameMatch::BinaryDenied => {
            return Decision::Deny {
                qname: normalized,
                reason: BINARY_DENY_REASON,
            };
        }
        HostnameMatch::Unmatched => {}
    }

    // No route matched. A host the JIT approval gate allowed this session
    // still resolves: this lets an interactive "allow once" connect (it
    // persists no route) and closes the "allow always" race where the proxy
    // resolves before the host's follow-up `policy` frame lands. An explicit
    // `Deny` is handled above, so a denied name never reaches here; entries
    // appear only via a developer's gate click.
    if state
        .gate_resolved_hosts
        .read()
        .unwrap()
        .contains(&normalized)
    {
        return allow(normalized, pin);
    }

    Decision::Deny {
        qname: normalized,
        reason: DENY_REASON,
    }
}

/// Synthesise an answer-less response with the given code, echoing the
/// request's header (id, flags) and question section. `NXDomain` is the deny
/// reply; `NoError` (NODATA) is the AAAA-suppression reply. Returns `None` if
/// the packet can't be parsed; callers should then stay silent.
fn empty_response(packet: &[u8], code: ResponseCode) -> Option<Vec<u8>> {
    let msg = Message::from_vec(packet).ok()?;
    let mut resp = Message::new(msg.metadata.id, MessageType::Response, msg.metadata.op_code);
    resp.metadata.recursion_desired = msg.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = code;
    for q in msg.queries {
        resp.add_query(q);
    }
    resp.to_vec().ok()
}

/// Forward the raw datagram to the upstream resolver and relay its response
/// back to the client. One-shot UDP socket per query — simple, no
/// connection tracking, upstream's own conntrack handles reply routing.
async fn forward_upstream(
    packet: &[u8],
    upstream: SocketAddr,
    client_socket: &UdpSocket,
    client_peer: SocketAddr,
    state: &Arc<ProxyState>,
    pin: Option<&FqdnPin>,
    generation: u64,
) -> Result<(), String> {
    // SO_MARK on the upstream socket so the nftables NAT chain doesn't
    // redirect the stub's own query packet back at itself. The listening
    // stub socket (bound in `run`) is sandbox-facing and stays unmarked
    // on purpose.
    let local: SocketAddr = if upstream.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let up = sock_mark::bind_udp(local)
        .await
        .map_err(|e| format!("upstream bind: {e}"))?;
    up.connect(upstream)
        .await
        .map_err(|e| format!("upstream connect {upstream}: {e}"))?;
    up.send(packet)
        .await
        .map_err(|e| format!("upstream send: {e}"))?;

    let mut resp_buf = [0u8; RESPONSE_BUF_SIZE];
    let n = timeout(UPSTREAM_TIMEOUT, up.recv(&mut resp_buf))
        .await
        .map_err(|_| "upstream timeout".to_string())?
        .map_err(|e| format!("upstream recv: {e}"))?;

    // Pin the answer's A-record IPs for the fqdn tcp rule this name matched, so
    // the raw TCP layer admits the follow-up connection to a resolved IP. Only
    // A records (IPv4) are pinned — the transparent interceptor is IPv4-only and
    // AAAA is already suppressed to NODATA upstream of here.
    if let Some(pin) = pin {
        pin_answer_ips(&resp_buf[..n], state, pin, generation);
    }

    client_socket
        .send_to(&resp_buf[..n], client_peer)
        .await
        .map_err(|e| format!("client reply: {e}"))?;
    Ok(())
}

/// Parse an upstream response and pin its A-record IPs against `pin`, using the
/// smallest TTL across every answer-section record. A malformed response is
/// ignored (the bytes are still relayed to the client by the caller).
fn pin_answer_ips(response: &[u8], state: &Arc<ProxyState>, pin: &FqdnPin, generation: u64) {
    let Ok(msg) = Message::from_vec(response) else {
        return;
    };
    let mut ips = Vec::new();
    let mut min_ttl = u32::MAX;
    for record in &msg.answers {
        // Honor the shortest TTL over every answer record, not just the A
        // records: a 30s CNAME in front of a 3600s A record means the
        // name→address mapping is only valid for 30s, so the pin must expire
        // with the CNAME, not the A. Min can only shorten — the fail-safe way.
        min_ttl = min_ttl.min(record.ttl);
        if let RData::A(a) = &record.data {
            let ip = IpAddr::V4(a.0);
            // Defence in depth: never pin a loopback/link-local/unspecified
            // answer, so a poisoned DNS response can't even enter the store (the
            // egress connect guard rejects these too, but keep the store clean).
            if crate::sock_mark::is_disallowed_egress_ip(ip) {
                continue;
            }
            ips.push(ip);
        }
    }
    if ips.is_empty() {
        return;
    }
    // `min_ttl` is set from at least the A record(s) above, so it is never `MAX`
    // once `ips` is non-empty; `pin_dns_answers` clamps a 0 up to the floor.
    let ttl = min_ttl;
    pin_dns_answers(state, &ips, pin, ttl, generation);
}

/// Parse `/etc/resolv.conf` for the first `nameserver` line. In Docker this
/// is typically `127.0.0.11` (embedded resolver) or `192.168.5.1` (Colima).
///
/// Tolerant of the formats real systems produce: leading whitespace,
/// `#` / `;` comments (line-start or inline), tab-separated tokens,
/// trailing whitespace. Only the first token after `nameserver` is
/// parsed — anything else on the line is ignored.
///
/// Called once at stub startup. `/etc/resolv.conf` inside a container is
/// fixed at container start, so there's no re-read path.
fn discover_upstream() -> Option<SocketAddr> {
    let content = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    parse_resolv_conf(&content)
}

fn parse_resolv_conf(content: &str) -> Option<SocketAddr> {
    for line in content.lines() {
        let trimmed = line.trim_start();
        // Skip blank lines and comments.
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        let mut tokens = trimmed.split_ascii_whitespace();
        if tokens.next() != Some("nameserver") {
            continue;
        }
        // First token after `nameserver` is the address; subsequent tokens
        // (inline comments, Linux zone-id suffixes, etc.) are ignored.
        let addr = tokens.next()?;
        // Also strip a `%zone` suffix if present (link-local v6 form); we
        // don't support it but shouldn't panic on it either.
        let addr = addr.split('%').next().unwrap_or(addr);
        if let Ok(ip) = addr.parse::<std::net::IpAddr>() {
            return Some(SocketAddr::new(ip, 53));
        }
    }
    None
}

fn emit_deny(state: &Arc<ProxyState>, qname: &str, reason: &str) {
    tracing::info!(qname, reason, "dns stub denied query");
    // `"d:"` key prefix keeps DNS denies separate from the transparent-TCP
    // (`"t:"`) and hostname-keyed CONNECT paths in the shared dedup map. The
    // reason distinguishes an allowlist miss (`dns-denied`) from a
    // binary-scoping exclusion (`dns-binary-not-allowed`).
    emit_deny_event(
        state,
        format!("d:{qname}"),
        format!("DNS {qname}"),
        serde_json::json!({ "dns": true, "reason": reason, "qname": qname }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::ProxyServer;
    use crate::routing::{RouteMatcher, RouteRule, Transport, Verdict};
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::domain::Name;
    use hickory_proto::rr::{DNSClass, RecordType};
    use std::path::PathBuf;
    use std::str::FromStr;

    fn make_query(qname: &str, rtype: RecordType) -> Vec<u8> {
        let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        let mut q = Query::new();
        q.set_name(Name::from_str(qname).unwrap());
        q.set_query_type(rtype);
        q.set_query_class(DNSClass::IN);
        msg.add_query(q);
        msg.to_vec().unwrap()
    }

    /// Build a state via the public constructor, then overwrite `routes`.
    /// Using `ProxyServer::new` here (rather than hand-rolling every field)
    /// keeps the unit tests in lockstep with production — adding a field
    /// to `ProxyState` doesn't break this block.
    fn state_with_routes(routes: Vec<RouteRule>) -> Arc<ProxyState> {
        let (_srv, state) = ProxyServer::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            Vec::new(),
        );
        state.policy.write().unwrap().routes = routes;
        state
    }

    fn rule(pattern: &str) -> RouteRule {
        RouteRule {
            matcher: RouteMatcher::Domain(pattern.to_string()),
            verdict: Verdict::Allow,
            transport: Transport::Direct,
            tls_terminate: false,
            http_rules: Vec::new(),
            scheme: None,
            binaries: None,
        }
    }

    /// An allow rule for `pattern` scoped to the given absolute exe paths.
    fn binary_rule(pattern: &str, bins: &[&str]) -> RouteRule {
        RouteRule {
            binaries: Some(bins.iter().map(|b| PathBuf::from(*b)).collect()),
            ..rule(pattern)
        }
    }

    /// A resolved caller whose connecting exe is `exe` (no ancestors).
    fn caller(exe: &str) -> PeerProcess {
        PeerProcess {
            pid: 100,
            name: "proc".into(),
            exe: Some(PathBuf::from(exe)),
            ancestors: Vec::new(),
        }
    }

    #[test]
    fn pin_ttl_honors_a_short_cname_ttl() {
        use hickory_proto::rr::Record;
        use hickory_proto::rr::rdata::{A, CNAME};
        use std::net::Ipv4Addr;

        // Response: a 60s CNAME in front of a 3600s A record. The pin must
        // expire with the CNAME (60s), not the A (3600s) — the name→address
        // mapping is only valid as long as the shortest link in the chain.
        let a_ip = Ipv4Addr::new(203, 0, 113, 5);
        let mut resp = Message::new(0x1, MessageType::Response, OpCode::Query);
        let name = Name::from_str("db.example.com.").unwrap();
        let target = Name::from_str("real.example.com.").unwrap();
        resp.add_answer(Record::from_rdata(
            name,
            60,
            RData::CNAME(CNAME(target.clone())),
        ));
        resp.add_answer(Record::from_rdata(target, 3600, RData::A(A(a_ip))));
        let bytes = resp.to_vec().unwrap();

        let state = state_with_routes(Vec::new());
        let pin = FqdnPin {
            port: Some(5432),
            verdict: Verdict::Allow,
            binaries: None,
        };
        let generation = state.policy.read().unwrap().generation;
        pin_answer_ips(&bytes, &state, &pin, generation);

        let policy = state.policy.read().unwrap();
        let entry = policy.pins.get(&IpAddr::V4(a_ip)).expect("A record pinned");
        // 60s CNAME TTL (> the 30s floor) bounds the pin. Without honoring the
        // CNAME the A's 3600s would apply, pushing expiry ~an hour out.
        assert!(
            entry[0].expiry <= std::time::Instant::now() + Duration::from_secs(120),
            "the 60s CNAME TTL must bound the pin, not the 3600s A TTL"
        );
    }

    #[test]
    fn bootstrap_allowlist_resolves_before_policy_arrives() {
        // Empty routes, but bootstrap allowlist has the Lens Sandbox host — the
        // supervisor's first DNS lookup at startup has to succeed.
        let (_srv, state) = ProxyServer::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            vec!["host.docker.internal".to_string()],
        );
        let packet = make_query("host.docker.internal", RecordType::A);
        match classify_query(&packet, &state, None) {
            Decision::Allow { qname, .. } => assert_eq!(qname, "host.docker.internal"),
            other => panic!("bootstrap host should resolve, got: {}", describe(&other)),
        }

        // Non-bootstrap host with empty routes still denied.
        let packet = make_query("evil.example.com", RecordType::A);
        match classify_query(&packet, &state, None) {
            Decision::Deny { .. } => {}
            other => panic!("non-bootstrap should deny, got: {}", describe(&other)),
        }
    }

    #[test]
    fn classify_captures_generation_and_fqdn_from_one_snapshot() {
        // The pin's generation must come from the same snapshot as the fqdn
        // rule that produced it. A reload bumps the generation and swaps the
        // fqdn rules atomically under one lock, so classify can never pair a new
        // generation with a stale fqdn rule — the race that would let a revoked
        // allow-pin survive under the new policy.
        let fqdn_allow = |host: &str| RouteRule {
            matcher: RouteMatcher::Domain(host.to_string()),
            verdict: Verdict::Allow,
            transport: Transport::Direct,
            tls_terminate: false,
            http_rules: Vec::new(),
            scheme: None,
            binaries: None,
        };
        let state = state_with_routes(Vec::new());
        state.policy.write().unwrap().tcp_fqdn = vec![fqdn_allow("db.internal")];

        let packet = make_query("db.internal", RecordType::A);
        let (pin, generation) = match classify_query(&packet, &state, None) {
            Decision::Allow {
                pin, generation, ..
            } => (pin, generation),
            other => panic!("expected Allow, got: {}", describe(&other)),
        };
        let current = state.policy.read().unwrap().generation;
        assert_eq!(
            generation, current,
            "captured generation must match the snapshot the fqdn was read from"
        );
        assert!(pin.is_some(), "the fqdn allow rule must yield a pin");

        // A reload bumps the generation and re-publishes the fqdn rules in one
        // atomic swap; the next classify captures the new generation together
        // with the fqdn read.
        crate::proxy::apply_network_policy(
            &state,
            crate::proxy::NetworkPolicy {
                tcp_fqdn: vec![fqdn_allow("db.internal")],
                ..Default::default()
            },
        );
        let generation2 = match classify_query(&packet, &state, None) {
            Decision::Allow { generation, .. } => generation,
            other => panic!("expected Allow after reload, got: {}", describe(&other)),
        };
        assert_eq!(
            generation2,
            current + 1,
            "generation must advance with the reload"
        );
    }

    #[test]
    fn classify_pairs_routes_and_fqdn_from_one_snapshot() {
        // The DNS verdict pairs an L7-route match with an FQDN-derived pin, so
        // both must come from the same policy snapshot. The race this guards
        // against was a reload publishing new L7 routes before the tcp policy,
        // letting classify see policy B's L7 allow with policy A's FQDN pin and
        // pin an IP neither complete policy would. `apply_network_policy` swaps
        // routes and fqdn rules together, so a routes-allow only ever carries a
        // pin from the same snapshot's fqdn rules.
        let route = |host: &str, verdict| RouteRule {
            matcher: RouteMatcher::Domain(host.to_string()),
            verdict,
            transport: Transport::Direct,
            tls_terminate: false,
            http_rules: Vec::new(),
            scheme: None,
            binaries: None,
        };
        let state = state_with_routes(Vec::new());
        let packet = make_query("h.internal", RecordType::A);

        // Policy A: L7 denies H, but a tcp_fqdn rule allows it. The L7 deny
        // wins, so the lookup is denied and no pin is produced.
        crate::proxy::apply_network_policy(
            &state,
            crate::proxy::NetworkPolicy {
                routes: vec![route("h.internal", Verdict::Deny)],
                default_verdict: Verdict::Deny,
                tcp_fqdn: vec![route("h.internal", Verdict::Allow)],
                ..Default::default()
            },
        );
        match classify_query(&packet, &state, None) {
            Decision::Deny { .. } => {}
            other => panic!("policy A must deny H at DNS, got: {}", describe(&other)),
        }

        // Policy B: L7 allows H, no tcp_fqdn rule. The lookup is allowed but
        // carries no pin — a routes-allow never pairs with a stale fqdn pin.
        crate::proxy::apply_network_policy(
            &state,
            crate::proxy::NetworkPolicy {
                routes: vec![route("h.internal", Verdict::Allow)],
                default_verdict: Verdict::Deny,
                ..Default::default()
            },
        );
        match classify_query(&packet, &state, None) {
            Decision::Allow { pin, .. } => assert!(
                pin.is_none(),
                "a routes-allow must not carry an fqdn pin from another snapshot"
            ),
            other => panic!("policy B must allow H at DNS, got: {}", describe(&other)),
        }
    }

    #[test]
    fn allow_hostport_pattern_by_hostname_only() {
        // DNS queries carry no port, but policy may list a host:port rule
        // (e.g. "127.0.0.1.nip.io:37421"). The DNS gate must allow the
        // lookup anyway; port enforcement happens on the subsequent TCP.
        let state = state_with_routes(vec![RouteRule {
            matcher: RouteMatcher::HostPort("127.0.0.1.nip.io".to_string(), 37421),
            verdict: Verdict::Allow,
            transport: Transport::Direct,
            tls_terminate: false,
            http_rules: Vec::new(),
            scheme: None,
            binaries: None,
        }]);
        let packet = make_query("127.0.0.1.nip.io", RecordType::A);
        match classify_query(&packet, &state, None) {
            Decision::Allow { .. } => {}
            other => panic!(
                "expected Allow for HostPort pattern, got: {}",
                describe(&other)
            ),
        }
    }

    #[test]
    fn allow_exact_match() {
        let state = state_with_routes(vec![rule("example.com")]);
        let packet = make_query("example.com", RecordType::A);
        match classify_query(&packet, &state, None) {
            Decision::Allow { qname, .. } => assert_eq!(qname, "example.com"),
            other => panic!("expected Allow, got: {}", describe(&other)),
        }
    }

    #[test]
    fn allow_wildcard_match() {
        let state = state_with_routes(vec![rule("*.amazonaws.com")]);
        let packet = make_query("sts.us-east-1.amazonaws.com", RecordType::A);
        match classify_query(&packet, &state, None) {
            Decision::Allow { .. } => {}
            other => panic!("wildcard should match, got: {}", describe(&other)),
        }
    }

    #[test]
    fn deny_unlisted_host() {
        let state = state_with_routes(vec![rule("example.com")]);
        let packet = make_query("evil.com", RecordType::A);
        match classify_query(&packet, &state, None) {
            Decision::Deny { qname, .. } => assert_eq!(qname, "evil.com"),
            other => panic!("expected Deny, got: {}", describe(&other)),
        }
    }

    #[test]
    fn binary_scoped_name_resolves_for_the_listed_caller() {
        let state = state_with_routes(vec![binary_rule("api.example.com", &["/usr/bin/curl"])]);
        let packet = make_query("api.example.com", RecordType::A);
        let curl = caller("/usr/bin/curl");
        match classify_query(&packet, &state, Some(&curl)) {
            Decision::Allow { qname, .. } => assert_eq!(qname, "api.example.com"),
            other => panic!("listed caller should resolve, got: {}", describe(&other)),
        }
    }

    #[test]
    fn binary_scoped_name_is_denied_for_an_excluded_caller() {
        let state = state_with_routes(vec![binary_rule("api.example.com", &["/usr/bin/curl"])]);
        let packet = make_query("api.example.com", RecordType::A);
        let wget = caller("/usr/bin/wget");
        match classify_query(&packet, &state, Some(&wget)) {
            Decision::Deny { qname, reason } => {
                assert_eq!(qname, "api.example.com");
                assert_eq!(reason, BINARY_DENY_REASON);
            }
            other => panic!(
                "excluded caller should be denied, got: {}",
                describe(&other)
            ),
        }
    }

    #[test]
    fn binary_scoped_name_is_denied_when_the_caller_is_unresolved() {
        // No caller info (non-Linux, closed socket, `/proc` failure) fails a
        // binary-scoped name closed, exactly as it does at the TCP layer.
        let state = state_with_routes(vec![binary_rule("api.example.com", &["/usr/bin/curl"])]);
        let packet = make_query("api.example.com", RecordType::A);
        match classify_query(&packet, &state, None) {
            Decision::Deny { reason, .. } => assert_eq!(reason, BINARY_DENY_REASON),
            other => panic!(
                "unresolved caller should be denied, got: {}",
                describe(&other)
            ),
        }
    }

    #[test]
    fn a_gate_approved_host_cannot_reopen_a_binary_scoped_name() {
        // The JIT-approved set is host-keyed, not caller-keyed. An excluded
        // caller must not ride a prior approval of the same host back in.
        let state = state_with_routes(vec![binary_rule("api.example.com", &["/usr/bin/curl"])]);
        state
            .gate_resolved_hosts
            .write()
            .unwrap()
            .insert("api.example.com".into());
        let packet = make_query("api.example.com", RecordType::A);
        let wget = caller("/usr/bin/wget");
        match classify_query(&packet, &state, Some(&wget)) {
            Decision::Deny { reason, .. } => assert_eq!(reason, BINARY_DENY_REASON),
            other => panic!(
                "gate must not reopen a scoped name, got: {}",
                describe(&other)
            ),
        }
    }

    #[test]
    fn an_aaaa_query_for_an_excluded_caller_is_denied_not_suppressed() {
        // An excluded caller has no access at all, so AAAA gets NXDOMAIN
        // (Deny), not the NODATA suppression an allowed caller would see.
        let state = state_with_routes(vec![binary_rule("api.example.com", &["/usr/bin/curl"])]);
        let packet = make_query("api.example.com", RecordType::AAAA);
        let wget = caller("/usr/bin/wget");
        match classify_query(&packet, &state, Some(&wget)) {
            Decision::Deny { reason, .. } => assert_eq!(reason, BINARY_DENY_REASON),
            other => panic!("excluded AAAA should deny, got: {}", describe(&other)),
        }
    }

    #[test]
    fn an_unrestricted_name_ignores_the_caller() {
        // A rule with no `binaries` filter resolves for any caller, and the
        // presence of a binary rule for a *different* host doesn't affect it.
        let state = state_with_routes(vec![
            binary_rule("api.example.com", &["/usr/bin/curl"]),
            rule("cdn.example.com"),
        ]);
        let packet = make_query("cdn.example.com", RecordType::A);
        let wget = caller("/usr/bin/wget");
        match classify_query(&packet, &state, Some(&wget)) {
            Decision::Allow { .. } => {}
            other => panic!(
                "unrestricted name should resolve, got: {}",
                describe(&other)
            ),
        }
    }

    #[test]
    fn deny_empty_policy() {
        // Zero routes: no name can ever resolve. Correct fail-closed behaviour.
        let state = state_with_routes(vec![]);
        let packet = make_query("example.com", RecordType::A);
        assert!(matches!(
            classify_query(&packet, &state, None),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn gate_resolved_host_resolves_without_a_route() {
        // A gate-approved host must resolve even under empty policy, or an
        // "allow once" (which persists no route) could never connect.
        let state = state_with_routes(vec![]);
        state
            .gate_resolved_hosts
            .write()
            .unwrap()
            .insert("example.com".to_string());

        let a = make_query("example.com", RecordType::A);
        assert!(matches!(
            classify_query(&a, &state, None),
            Decision::Allow { .. }
        ));

        // AAAA stays suppressed to NODATA so egress remains on the
        // interceptable IPv4 path, exactly as for a route-allowed name.
        let aaaa = make_query("example.com", RecordType::AAAA);
        assert!(matches!(
            classify_query(&aaaa, &state, None),
            Decision::SuppressNodata { .. }
        ));

        // A name the gate has not approved still fails closed.
        let other = make_query("not-approved.example", RecordType::A);
        assert!(matches!(
            classify_query(&other, &state, None),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn explicit_deny_beats_gate_approval() {
        // A Deny rule must NXDOMAIN even a gate-approved host, so the resolve
        // fallback can't sidestep a Deny added after approval.
        let state = state_with_routes(vec![RouteRule {
            matcher: RouteMatcher::Domain("evil.example".to_string()),
            verdict: Verdict::Deny,
            transport: Transport::Direct,
            tls_terminate: false,
            http_rules: Vec::new(),
            scheme: None,
            binaries: None,
        }]);
        state
            .gate_resolved_hosts
            .write()
            .unwrap()
            .insert("evil.example".to_string());
        let a = make_query("evil.example", RecordType::A);
        assert!(matches!(
            classify_query(&a, &state, None),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn allowed_name_resolves_a_but_suppresses_aaaa() {
        // The allowlist is keyed by hostname, but the record type still
        // matters at the response: an allowed name returns its A record
        // (forward) while its AAAA is downgraded to NODATA. Handing back a
        // real IPv6 address would let the workload open a direct v6
        // connection the IPv4-only transparent interceptor can't catch.
        let state = state_with_routes(vec![rule("example.com")]);
        let a = make_query("example.com", RecordType::A);
        let aaaa = make_query("example.com", RecordType::AAAA);
        assert!(matches!(
            classify_query(&a, &state, None),
            Decision::Allow { .. }
        ));
        match classify_query(&aaaa, &state, None) {
            Decision::SuppressNodata { qname } => assert_eq!(qname, "example.com"),
            other => panic!(
                "AAAA for an allowed name must be suppressed, got: {}",
                describe(&other)
            ),
        }
    }

    #[test]
    fn allowed_name_https_record_is_suppressed() {
        // An HTTPS (type 65) record can carry ipv4hint/ipv6hint and ALPN that
        // would let the workload connect outside the interceptable IPv4 proxy
        // path. Suppress it to NODATA exactly like AAAA so the client falls
        // back to the plain A record the v4 redirect catches.
        let state = state_with_routes(vec![rule("example.com")]);
        let https = make_query("example.com", RecordType::HTTPS);
        match classify_query(&https, &state, None) {
            Decision::SuppressNodata { qname } => assert_eq!(qname, "example.com"),
            other => panic!(
                "HTTPS for an allowed name must be suppressed, got: {}",
                describe(&other)
            ),
        }
    }

    #[test]
    fn allowed_name_svcb_record_is_suppressed() {
        // SVCB (type 64) is the generic sibling of HTTPS and carries the same
        // address hints; suppress it to NODATA the same way.
        let state = state_with_routes(vec![rule("example.com")]);
        let svcb = make_query("example.com", RecordType::SVCB);
        match classify_query(&svcb, &state, None) {
            Decision::SuppressNodata { qname } => assert_eq!(qname, "example.com"),
            other => panic!(
                "SVCB for an allowed name must be suppressed, got: {}",
                describe(&other)
            ),
        }
    }

    #[test]
    fn allowed_name_any_query_is_suppressed() {
        // An ANY (qtype 255) query for an allowed name would otherwise be
        // forwarded verbatim, letting the upstream reply carry AAAA/HTTPS/SVCB
        // answers — the exact address hints the suppression exists to block.
        // Force it to NODATA so the client falls back to a typed A query.
        let state = state_with_routes(vec![rule("example.com")]);
        let any = make_query("example.com", RecordType::ANY);
        match classify_query(&any, &state, None) {
            Decision::SuppressNodata { qname } => assert_eq!(qname, "example.com"),
            other => panic!(
                "ANY for an allowed name must be suppressed, got: {}",
                describe(&other)
            ),
        }
    }

    #[test]
    fn denied_name_aaaa_still_nxdomains_not_suppressed() {
        // Suppression is a downgrade for *allowed* names only. A denied name
        // must keep its NXDOMAIN (Deny) path for every record type so the
        // covert-channel defence isn't weakened — NODATA would still confirm
        // the name's existence to the sandbox.
        let state = state_with_routes(vec![rule("example.com")]);
        let aaaa = make_query("evil.com", RecordType::AAAA);
        match classify_query(&aaaa, &state, None) {
            Decision::Deny { qname, .. } => assert_eq!(qname, "evil.com"),
            other => panic!(
                "AAAA for a denied name must Deny, got: {}",
                describe(&other)
            ),
        }
    }

    #[test]
    fn bootstrap_host_aaaa_is_suppressed() {
        // Bootstrap hosts resolve before policy, but they're reached over the
        // proxy's marked sockets just like everything else — so their AAAA is
        // downgraded too, keeping all egress on the interceptable IPv4 path.
        let (_srv, state) = ProxyServer::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            vec!["host.docker.internal".to_string()],
        );
        let aaaa = make_query("host.docker.internal", RecordType::AAAA);
        assert!(matches!(
            classify_query(&aaaa, &state, None),
            Decision::SuppressNodata { .. }
        ));
    }

    #[test]
    fn deny_rule_before_wildcard_allow_denies_dns() {
        // First-match semantics: a Deny rule listed before a broader
        // wildcard Allow must take precedence. Otherwise the wildcard
        // leaks the denied name upstream, defeating the covert-channel
        // defence.
        let state = state_with_routes(vec![
            RouteRule {
                matcher: RouteMatcher::Domain("evil.example.com".to_string()),
                verdict: Verdict::Deny,
                transport: Transport::Upstream,
                tls_terminate: false,
                http_rules: Vec::new(),
                scheme: None,
                binaries: None,
            },
            RouteRule {
                matcher: RouteMatcher::Domain("*.example.com".to_string()),
                verdict: Verdict::Allow,
                transport: Transport::Direct,
                tls_terminate: false,
                http_rules: Vec::new(),
                scheme: None,
                binaries: None,
            },
        ]);
        let packet = make_query("evil.example.com", RecordType::A);
        assert!(matches!(
            classify_query(&packet, &state, None),
            Decision::Deny { .. }
        ));
        // Sanity: non-denied subdomain still allowed by the wildcard.
        let packet = make_query("good.example.com", RecordType::A);
        assert!(matches!(
            classify_query(&packet, &state, None),
            Decision::Allow { .. }
        ));
    }

    #[test]
    fn qname_case_is_normalized_for_audit_dedup() {
        // DNS is case-insensitive. The decision's `qname` must be
        // lowercased so the dedup key (`format!("d:{qname}")` in
        // `emit_deny`) collapses `EVIL.com`, `Evil.com`, and `evil.com`
        // into a single audit event.
        let state = state_with_routes(vec![rule("example.com")]);
        let packet = make_query("EVIL.example", RecordType::A);
        match classify_query(&packet, &state, None) {
            Decision::Deny { qname, .. } => assert_eq!(qname, "evil.example"),
            other => panic!("expected Deny, got {}", describe(&other)),
        }
    }

    #[test]
    fn explicit_deny_rule_blocks_dns_lookup() {
        // A `verdict: deny` rule for a hostname must not cause that name
        // to be forwarded upstream. Forwarding would leak the name to any
        // observer at the upstream resolver and let an adversary
        // enumerate the deny list via timing (stub NXDOMAIN is fast,
        // upstream NXDOMAIN is slow).
        let state = state_with_routes(vec![RouteRule {
            matcher: RouteMatcher::Domain("evil.example".to_string()),
            verdict: Verdict::Deny,
            transport: Transport::Upstream,
            tls_terminate: false,
            http_rules: Vec::new(),
            scheme: None,
            binaries: None,
        }]);
        let packet = make_query("evil.example", RecordType::A);
        assert!(matches!(
            classify_query(&packet, &state, None),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn ask_verdict_allows_dns_lookup() {
        // `Verdict::Ask` resolves at the DNS layer the same as Allow: the
        // approval gate fires on the subsequent TCP attempt, so denying DNS
        // here would NXDOMAIN before the developer ever saw a dialog. This
        // test pins the trade-off — DNS QNAME leak to the upstream resolver
        // is accepted as the cost of an interactive gate.
        let state = state_with_routes(vec![RouteRule {
            matcher: RouteMatcher::Domain("ask.example".to_string()),
            verdict: Verdict::Ask,
            transport: Transport::Upstream,
            tls_terminate: false,
            http_rules: Vec::new(),
            scheme: None,
            binaries: None,
        }]);
        let packet = make_query("ask.example", RecordType::A);
        assert!(matches!(
            classify_query(&packet, &state, None),
            Decision::Allow { .. }
        ));
    }

    #[test]
    fn cidr_rule_does_not_allow_bare_ip_qname() {
        // CIDR rules control IP-based TCP access, not DNS. A query whose
        // QNAME is a bare IP literal (e.g. "10.1.2.3") should be denied at
        // the DNS layer even if a CIDR rule covers that address, both
        // because bare-IP qnames aren't legitimate hostnames and because
        // allowing them would leak policy to the upstream resolver.
        let state = state_with_routes(vec![RouteRule {
            matcher: RouteMatcher::Cidr("10.0.0.0/8".parse().unwrap()),
            verdict: Verdict::Allow,
            transport: Transport::Direct,
            tls_terminate: false,
            http_rules: Vec::new(),
            scheme: None,
            binaries: None,
        }]);
        let packet = make_query("10.1.2.3", RecordType::A);
        assert!(matches!(
            classify_query(&packet, &state, None),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn malformed_packet_classified_as_malformed() {
        let state = state_with_routes(vec![rule("example.com")]);
        let garbage = vec![0u8; 3];
        assert!(matches!(
            classify_query(&garbage, &state, None),
            Decision::Malformed
        ));
    }

    #[test]
    fn no_questions_classified_as_malformed() {
        let state = state_with_routes(vec![rule("example.com")]);
        // Well-formed header with zero questions — some probe tools do this.
        let msg = Message::new(1, MessageType::Query, OpCode::Query);
        let packet = msg.to_vec().unwrap();
        assert!(matches!(
            classify_query(&packet, &state, None),
            Decision::Malformed
        ));
    }

    #[test]
    fn nxdomain_response_preserves_id_and_question() {
        let packet = make_query("denied.example", RecordType::A);
        let resp = empty_response(&packet, ResponseCode::NXDomain).expect("response built");
        let msg = Message::from_vec(&resp).expect("parseable");
        assert_eq!(msg.metadata.id, 0x1234);
        assert_eq!(msg.metadata.message_type, MessageType::Response);
        assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(msg.queries.len(), 1);
        assert_eq!(msg.queries[0].name().to_utf8(), "denied.example.");
    }

    #[test]
    fn nodata_response_is_noerror_with_no_answers() {
        // AAAA suppression must echo the question under NOERROR with an empty
        // answer section — the NODATA shape clients read as "no IPv6 here, use
        // A". NXDOMAIN here would instead tell the client the name doesn't
        // exist and kill the IPv4 fallback.
        let packet = make_query("api.anthropic.com", RecordType::AAAA);
        let resp = empty_response(&packet, ResponseCode::NoError).expect("response built");
        let msg = Message::from_vec(&resp).expect("parseable");
        assert_eq!(msg.metadata.id, 0x1234);
        assert_eq!(msg.metadata.message_type, MessageType::Response);
        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        assert_eq!(msg.answers.len(), 0, "NODATA carries no address records");
        assert_eq!(msg.queries.len(), 1);
        assert_eq!(msg.queries[0].name().to_utf8(), "api.anthropic.com.");
    }

    /// Helper for panic messages.
    fn describe(d: &Decision) -> &'static str {
        match d {
            Decision::Allow { .. } => "Allow",
            Decision::Deny { .. } => "Deny",
            Decision::SuppressNodata { .. } => "SuppressNodata",
            Decision::Malformed => "Malformed",
        }
    }

    #[test]
    fn resolv_conf_parses_docker_style() {
        let content = "\
# Generated by Docker Engine.
nameserver 127.0.0.11
options ndots:0
";
        assert_eq!(
            parse_resolv_conf(content).unwrap(),
            "127.0.0.11:53".parse().unwrap()
        );
    }

    #[test]
    fn resolv_conf_tolerates_inline_comment() {
        let content = "nameserver 127.0.0.11 # docker embedded resolver\n";
        assert_eq!(
            parse_resolv_conf(content).unwrap(),
            "127.0.0.11:53".parse().unwrap()
        );
    }

    #[test]
    fn resolv_conf_tolerates_leading_whitespace_and_tabs() {
        let content = "\t nameserver\t1.2.3.4\n";
        assert_eq!(
            parse_resolv_conf(content).unwrap(),
            "1.2.3.4:53".parse().unwrap()
        );
    }

    #[test]
    fn resolv_conf_skips_commented_nameserver_line() {
        let content = "\
# nameserver 8.8.8.8
nameserver 1.1.1.1
";
        assert_eq!(
            parse_resolv_conf(content).unwrap(),
            "1.1.1.1:53".parse().unwrap()
        );
    }

    #[test]
    fn resolv_conf_returns_first_nameserver_only() {
        let content = "nameserver 1.1.1.1\nnameserver 8.8.8.8\n";
        assert_eq!(
            parse_resolv_conf(content).unwrap(),
            "1.1.1.1:53".parse().unwrap()
        );
    }

    #[test]
    fn resolv_conf_returns_none_when_no_nameserver() {
        assert!(parse_resolv_conf("options ndots:0\n").is_none());
        assert!(parse_resolv_conf("").is_none());
    }
}
