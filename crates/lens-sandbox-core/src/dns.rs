//! DNS stub resolver: filters unmarked UDP/53 queries against the route
//! allowlist before forwarding them to the host resolver.
//!
//! nftables REDIRECTs `meta mark != MARK_VALUE` UDP/53 traffic to this listener
//! (`127.0.0.1:5355` by default). For each query we parse the first question,
//! match its QNAME against `ProxyState.routes` via `routing::hostname_allowed`
//! (Domain and HostPort matchers; wildcards supported; CIDR matchers are
//! intentionally excluded — a bare IP literal is not a legitimate QNAME and
//! allowing it would leak CIDR policy to the upstream resolver. IP-based
//! access is still enforced at the TCP layer). Explicit `Deny` rules take
//! first-match precedence, same as `find_matching_route`. The stub then
//! either forwards allowed queries upstream or responds with NXDOMAIN +
//! a deny audit event.
//!
//! Without this filter, an allow-UDP/53 rule opens a ~50 B/s covert channel
//! through the upstream resolver (QNAME-encoded exfil, TXT-encoded ingress).
//! Gating queries by the same allowlist that already protects TCP closes
//! that door without adding any new policy surface.
//!
//! Allowed `AAAA` queries are answered with NODATA (NOERROR + empty answer)
//! rather than forwarded: the transparent interceptor binds IPv4 loopback
//! only, so handing back a real IPv6 address would let the workload open a
//! direct v6 connection that bypasses the proxy entirely. NODATA is the
//! standard "no IPv6 here" signal, so the client falls back to the A record
//! and the v4 redirect catches it. Denied names keep their NXDOMAIN path.
//!
//! Not handled (intentional, v1 scope):
//! - TCP/53 fallback (rare for A/AAAA responses; the NAT chain REDIRECTs
//!   TCP/53 into the transparent listener, which classifies DNS as Unknown
//!   and drops — same user-visible behaviour as blocking).
//! - Caching — the upstream (Docker's `127.0.0.11` or Colima's
//!   `192.168.5.1`) already caches.
//! - DNSSEC validation — out of scope; we forward DNSSEC records opaquely.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::RecordType;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::proxy::{ProxyState, emit_deny_event};
use crate::routing::hostname_allowed;
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
    let decision = classify_query(&packet, state);

    match decision {
        Decision::Allow { qname } => {
            tracing::debug!(qname = %qname, "dns stub forwarding");
            if let Err(e) = forward_upstream(&packet, upstream, socket, peer).await {
                tracing::warn!(qname = %qname, "dns stub upstream error: {e}");
            }
        }
        Decision::Deny { qname } => {
            emit_deny(state, &qname);
            if let Some(resp) = empty_response(&packet, ResponseCode::NXDomain) {
                let _ = socket.send_to(&resp, peer).await;
            }
        }
        Decision::SuppressAaaa { qname } => {
            tracing::debug!(qname = %qname, "dns stub answering AAAA with NODATA to force IPv4");
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
    Allow { qname: String },
    Deny { qname: String },
    SuppressAaaa { qname: String },
    Malformed,
}

/// Parse the request and match its first question against the allowlist.
/// Split out for direct unit testing — no I/O, no async.
fn classify_query(packet: &[u8], state: &ProxyState) -> Decision {
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
    // transparent interceptor can't catch, so an allowed name resolves to A
    // (forward) and AAAA (NODATA). Denial is unaffected: a denied name gets
    // NXDOMAIN regardless of record type.
    let is_aaaa = query.query_type() == RecordType::AAAA;
    let allow = |qname| {
        if is_aaaa {
            Decision::SuppressAaaa { qname }
        } else {
            Decision::Allow { qname }
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
        return allow(normalized);
    }

    let routes = state.routes.read().unwrap();
    // DNS has no notion of scheme or port, so we run the lenient
    // `hostname_allowed` check. Port- and scheme-aware enforcement still
    // applies at the subsequent TCP step via `find_matching_route`; the
    // DNS gate just prevents covert exfil via unlisted names.
    if hostname_allowed(&routes, &normalized) {
        allow(normalized)
    } else {
        Decision::Deny { qname: normalized }
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

    client_socket
        .send_to(&resp_buf[..n], client_peer)
        .await
        .map_err(|e| format!("client reply: {e}"))?;
    Ok(())
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

fn emit_deny(state: &Arc<ProxyState>, qname: &str) {
    tracing::info!(qname, "dns stub denied query (not in allowlist)");
    // `"d:"` key prefix + `"dns-denied"` reason keep DNS denies separate
    // from the transparent-TCP (`"t:"`) and hostname-keyed CONNECT paths
    // in the shared dedup map.
    emit_deny_event(
        state,
        format!("d:{qname}"),
        format!("DNS {qname}"),
        serde_json::json!({ "dns": true, "reason": "dns-denied", "qname": qname }),
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
        *state.routes.write().unwrap() = routes;
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
        }
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
        match classify_query(&packet, &state) {
            Decision::Allow { qname } => assert_eq!(qname, "host.docker.internal"),
            other => panic!("bootstrap host should resolve, got: {}", describe(&other)),
        }

        // Non-bootstrap host with empty routes still denied.
        let packet = make_query("evil.example.com", RecordType::A);
        match classify_query(&packet, &state) {
            Decision::Deny { .. } => {}
            other => panic!("non-bootstrap should deny, got: {}", describe(&other)),
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
        }]);
        let packet = make_query("127.0.0.1.nip.io", RecordType::A);
        match classify_query(&packet, &state) {
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
        match classify_query(&packet, &state) {
            Decision::Allow { qname } => assert_eq!(qname, "example.com"),
            other => panic!("expected Allow, got: {}", describe(&other)),
        }
    }

    #[test]
    fn allow_wildcard_match() {
        let state = state_with_routes(vec![rule("*.amazonaws.com")]);
        let packet = make_query("sts.us-east-1.amazonaws.com", RecordType::A);
        match classify_query(&packet, &state) {
            Decision::Allow { .. } => {}
            other => panic!("wildcard should match, got: {}", describe(&other)),
        }
    }

    #[test]
    fn deny_unlisted_host() {
        let state = state_with_routes(vec![rule("example.com")]);
        let packet = make_query("evil.com", RecordType::A);
        match classify_query(&packet, &state) {
            Decision::Deny { qname } => assert_eq!(qname, "evil.com"),
            other => panic!("expected Deny, got: {}", describe(&other)),
        }
    }

    #[test]
    fn deny_empty_policy() {
        // Zero routes: no name can ever resolve. Correct fail-closed behaviour.
        let state = state_with_routes(vec![]);
        let packet = make_query("example.com", RecordType::A);
        assert!(matches!(
            classify_query(&packet, &state),
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
        assert!(matches!(classify_query(&a, &state), Decision::Allow { .. }));
        match classify_query(&aaaa, &state) {
            Decision::SuppressAaaa { qname } => assert_eq!(qname, "example.com"),
            other => panic!(
                "AAAA for an allowed name must be suppressed, got: {}",
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
        match classify_query(&aaaa, &state) {
            Decision::Deny { qname } => assert_eq!(qname, "evil.com"),
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
            classify_query(&aaaa, &state),
            Decision::SuppressAaaa { .. }
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
            },
            RouteRule {
                matcher: RouteMatcher::Domain("*.example.com".to_string()),
                verdict: Verdict::Allow,
                transport: Transport::Direct,
                tls_terminate: false,
                http_rules: Vec::new(),
                scheme: None,
            },
        ]);
        let packet = make_query("evil.example.com", RecordType::A);
        assert!(matches!(
            classify_query(&packet, &state),
            Decision::Deny { .. }
        ));
        // Sanity: non-denied subdomain still allowed by the wildcard.
        let packet = make_query("good.example.com", RecordType::A);
        assert!(matches!(
            classify_query(&packet, &state),
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
        match classify_query(&packet, &state) {
            Decision::Deny { qname } => assert_eq!(qname, "evil.example"),
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
        }]);
        let packet = make_query("evil.example", RecordType::A);
        assert!(matches!(
            classify_query(&packet, &state),
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
        }]);
        let packet = make_query("ask.example", RecordType::A);
        assert!(matches!(
            classify_query(&packet, &state),
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
        }]);
        let packet = make_query("10.1.2.3", RecordType::A);
        assert!(matches!(
            classify_query(&packet, &state),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn malformed_packet_classified_as_malformed() {
        let state = state_with_routes(vec![rule("example.com")]);
        let garbage = vec![0u8; 3];
        assert!(matches!(
            classify_query(&garbage, &state),
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
            classify_query(&packet, &state),
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
            Decision::SuppressAaaa { .. } => "SuppressAaaa",
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
