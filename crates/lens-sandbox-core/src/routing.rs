//! Route rules, hostname/path matching, and HTTP rule evaluation for the
//! sandbox proxy. Parses the policy JSON into `RouteRule`s and resolves a
//! CONNECT target (plus optional HTTP method/path) to an action.

use std::path::PathBuf;

use ipnet::IpNet;

pub use crate::policy_schema::{
    GraphqlMatcher, HttpRequestMatch, HttpRule, Scheme, Transport, Verdict,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRule {
    pub matcher: RouteMatcher,
    /// Policy decision for matched traffic.
    pub verdict: Verdict,
    /// Transport applied when the verdict is `Allow`. Ignored when the verdict
    /// is `Deny`.
    pub transport: Transport,
    /// When true and `transport` is `LensSandbox`, the proxy terminates client TLS
    /// and forwards through the upstream tunnel. Ignored for `Direct`.
    pub tls_terminate: bool,
    pub http_rules: Vec<HttpRule>,
    /// Restrict this rule to a specific scheme; `None` means the rule matches
    /// both `http` and `https` requests.
    pub scheme: Option<Scheme>,
    /// Restrict this rule to callers whose exe (or an ancestor) is one of these
    /// absolute paths, matched against the kernel-resolved `/proc/<pid>/exe`
    /// target (a canonical path, not a symlink or shim). `None` matches any
    /// caller; see [`find_matching_route`] for the fail-closed semantics of a
    /// host match that the filter excludes.
    pub binaries: Option<Vec<PathBuf>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteMatcher {
    Domain(String),
    Cidr(IpNet),
    /// A CIDR (or single-IP `/32`,`/128`) scoped to a specific port, e.g.
    /// `10.0.0.0/24:5432`. Unlike [`RouteMatcher::Cidr`], which matches any
    /// port, this matches only the given port.
    CidrPort(IpNet, u16),
    HostPort(String, u16),
}

/// A route rule paired with its optional raw forwarding config.
/// Returned by `parse_proxy_routes` — the forward config carries raw PEM strings
/// that `handle_policy` parses into `ClientCertConfig` for the proxy state.
pub struct ParsedRoute {
    pub rule: RouteRule,
    pub forward: Option<crate::policy_schema::ForwardConfig>,
}

/// Parse a JSON array of route rules (used by the `policy` message handler).
pub fn parse_proxy_routes(json: &serde_json::Value) -> Result<Vec<ParsedRoute>, String> {
    let arr = json.as_array().ok_or("proxyRoutes must be an array")?;
    arr.iter()
        .map(|v| {
            let raw: crate::policy_schema::RouteRule =
                serde_json::from_value(v.clone()).map_err(|e| format!("invalid route: {e}"))?;
            let forward = raw.forward.clone();
            let rule: RouteRule = raw.try_into()?;
            Ok(ParsedRoute { rule, forward })
        })
        .collect()
}

impl TryFrom<crate::policy_schema::RouteRule> for RouteRule {
    type Error = String;

    fn try_from(raw: crate::policy_schema::RouteRule) -> Result<Self, String> {
        let verdict = raw.verdict;
        let transport = raw.transport;

        let matcher = parse_matcher(&raw.match_pattern)?;

        let http_rules: Vec<HttpRule> = raw
            .rules
            .into_iter()
            .filter_map(|r| {
                // Filter out empty rules — every field absent is a match-all that
                // would silently bypass deny-by-default semantics. A rule that
                // carries only a `graphql` block is not empty: it constrains the
                // operation on every method and path.
                if r.method.is_none() && r.path.is_none() && r.graphql.is_none() {
                    return None;
                }
                Some(HttpRule {
                    method: r.method,
                    path: r.path,
                    graphql: r.graphql,
                })
            })
            .collect();

        // A GraphQL rule governs the requests its head covers, so a bodiless
        // rule beside it does not admit them. That is worth saying out loud at
        // load: the operator sees which shape wins before a request is denied
        // by it. Mirrors how an egress `tcp`/`http` overlap is logged, not
        // rejected — deciding glob subsumption between rules is its own
        // problem, and the runtime precedence already removes the ambiguity.
        if http_rules.iter().any(|r| r.graphql.is_some())
            && http_rules.iter().any(|r| r.graphql.is_none())
        {
            tracing::info!(
                pattern = %raw.match_pattern,
                "route mixes GraphQL and non-GraphQL HTTP rules: a request matching a GraphQL rule's method and path is decided by the GraphQL rules alone"
            );
        }

        let binaries = raw.binaries.map(parse_binaries).transpose()?;

        Ok(RouteRule {
            matcher,
            verdict,
            transport,
            tls_terminate: raw.tls_terminate,
            http_rules,
            scheme: raw.scheme,
            binaries,
        })
    }
}

/// Parse a `match` pattern into a [`RouteMatcher`]. Shared by application-layer
/// (`allowedRoutes` / `egress.http`) and raw-TCP (`egress.tcp`) parsing so the
/// two never diverge on how a pattern is interpreted. Accepts a bare IP/CIDR,
/// `ip:port`/`host:port`, `cidr:port` (`10.0.0.0/24:5432`), bracketed IPv6
/// (`[::1]:6443`, `[2001:db8::/32]:5432`), or a domain / wildcard.
pub fn parse_matcher(pattern: &str) -> Result<RouteMatcher, String> {
    if let Ok(cidr) = pattern.parse::<IpNet>() {
        // CIDR check first — avoids false match on IPv6 like "2001:db8::/32"
        Ok(RouteMatcher::Cidr(cidr))
    } else if pattern.starts_with('[') {
        // Bracketed IPv6 with port: [::1]:6443, or bracketed IPv6 CIDR with
        // port: [2001:db8::/32]:5432.
        let Some((bracket_part, port_str)) = pattern.rsplit_once("]:") else {
            return Err(format!("invalid bracketed address: {pattern}"));
        };
        let host = bracket_part.trim_start_matches('[');
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("invalid port in {pattern}"))?;
        // A `/` inside the brackets means a prefix length — treat it as a
        // CIDR scoped to the port. A bare literal stays HostPort so existing
        // `[::1]:6443` rules are unchanged.
        if host.contains('/') {
            let net = host
                .parse::<IpNet>()
                .map_err(|_| format!("invalid CIDR in {pattern}"))?;
            Ok(RouteMatcher::CidrPort(net, port))
        } else {
            Ok(RouteMatcher::HostPort(host.to_ascii_lowercase(), port))
        }
    } else if pattern.matches(':').count() == 1
        && let Some((net, port)) = parse_cidr_port(pattern)
    {
        // Unbracketed IPv4 CIDR with port: 10.0.0.0/24:5432. IPv6 CIDRs must
        // use bracket notation (handled above) — the single-colon guard keeps
        // a raw IPv6 CIDR:port from being mis-split here.
        Ok(RouteMatcher::CidrPort(net, port))
    } else if pattern.matches(':').count() > 1 {
        // Raw unbracketed IPv6 (multiple colons without brackets) — reject
        Err(format!(
            "ambiguous IPv6 address without brackets: {pattern}; use [addr]:port notation"
        ))
    } else if let Some((host, port_str)) = pattern.rsplit_once(':') {
        // Single colon — could be host:port
        if let Ok(port) = port_str.parse::<u16>() {
            Ok(RouteMatcher::HostPort(host.to_ascii_lowercase(), port))
        } else {
            // Port doesn't parse — treat as domain
            Ok(RouteMatcher::Domain(pattern.to_string()))
        }
    } else {
        Ok(RouteMatcher::Domain(pattern.to_string()))
    }
}

/// Split `cidr:port` (`10.0.0.0/24:5432`), or `None` if either half is not what
/// it claims. Returning `None` rather than an error matters: a parse failure is
/// answered with `force_deny()` over the entire policy, so a URL- or path-shaped
/// pattern must fall through to the domain arms and stay one inert rule instead
/// of taking every working rule down with it.
fn parse_cidr_port(pattern: &str) -> Option<(IpNet, u16)> {
    let (net_str, port_str) = pattern.rsplit_once(':')?;
    Some((net_str.parse().ok()?, port_str.parse().ok()?))
}

/// Whether two host patterns can name the same host, either one possibly a
/// wildcard. Two disjoint wildcards that nonetheless share hosts (`*.a.com` vs
/// `b.*.com`) are not detected: this backs a warning, so a miss costs a log
/// line, not enforcement.
fn patterns_overlap(a: &str, b: &str) -> bool {
    domain_matches(a, b) || domain_matches(b, a)
}

/// Every `(raw rule, http rule)` pair where a non-deny rule from a raw table
/// covers a host and port an `egress.http` rule also covers. Both rules are
/// valid and the policy still loads; what the overlap *means* differs by table,
/// so the caller says it. Silence is the failure mode either way.
///
/// Only hostname (`HostPort`) raw rules are comparable; whether a CIDR covers a
/// name is knowable only after resolving.
pub(crate) fn overlapping_http_rules<'a>(
    raw_egress: &'a [RouteRule],
    routes: &'a [RouteRule],
) -> Vec<(&'a RouteMatcher, &'a RouteMatcher)> {
    let mut overlaps = Vec::new();
    for raw in raw_egress.iter().filter(|r| r.verdict != Verdict::Deny) {
        let RouteMatcher::HostPort(host, port) = &raw.matcher else {
            continue;
        };
        for route in routes {
            let covers = match &route.matcher {
                RouteMatcher::Domain(pattern) => patterns_overlap(pattern, host),
                RouteMatcher::HostPort(pattern, p) => p == port && patterns_overlap(pattern, host),
                RouteMatcher::Cidr(_) | RouteMatcher::CidrPort(_, _) => false,
            };
            if covers {
                overlaps.push((&raw.matcher, &route.matcher));
            }
        }
    }
    overlaps
}

/// Parse the `egress.tcp` list into ONE ordered `Vec<RouteRule>`, preserving the
/// original rule order. Connect resolution ([`find_matching_tcp_egress`]) walks
/// this single list in policy order so a static IP rule and a hostname (pinned)
/// rule compete by their real position — an earlier rule always wins, whichever
/// kind it is. The matcher kind is the connect-vs-pin discriminator:
/// `CidrPort` matches the resolved dst IP directly; `HostPort` matches only a
/// dst IP that a live DNS pin bound to a name the rule covers.
///
/// Every rule MUST carry a port, so only the port-scoped matchers survive here.
/// A raw connection is spliced opaquely, so a portless "any port to this
/// host/subnet" grant is a broad hole. Rejecting one fails the whole policy
/// closed, which is the point: a rule that can never match is worse than no rule
/// at all, because a dead *deny* fails open. That is the standard every shape
/// below is held to.
///
/// An IP-literal `HostPort` (`10.0.0.5:5432`) is normalized to `CidrPort` so it
/// stays a direct IP match rather than a hostname rule: the discriminator is
/// then purely the matcher kind, and the DNS gate (which skips `CidrPort`,
/// never `HostPort`) can share this list without an IP literal leaking in as a
/// QNAME. Normalization is scoped to the raw tables — the L7 `parse_matcher`
/// path keeps its string semantics untouched.
pub fn parse_tcp_egress(json: &serde_json::Value) -> Result<Vec<RouteRule>, String> {
    parse_port_scoped_egress(json, PortScopedTable::Tcp)
}

/// Parse the `egress.udp` list, under the rules [`parse_tcp_egress`] documents —
/// one ordered list, a mandatory port, IP literals normalized to `CidrPort`. Port
/// 53 is refused here and accepted there; see
/// [`UdpEgressRule::match_pattern`](crate::policy_schema::UdpEgressRule::match_pattern).
pub fn parse_udp_egress(json: &serde_json::Value) -> Result<Vec<RouteRule>, String> {
    parse_port_scoped_egress(json, PortScopedTable::Udp)
}

/// The two raw egress tables. Both are parsed by the same code so they can never
/// drift on how a pattern is read; this names what still differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PortScopedTable {
    Tcp,
    Udp,
}

impl PortScopedTable {
    fn label(self) -> &'static str {
        match self {
            PortScopedTable::Tcp => "egress.tcp",
            PortScopedTable::Udp => "egress.udp",
        }
    }
}

/// The fields both tables carry, and the one shape the parser reads.
/// [`TcpEgressRule`](crate::policy_schema::TcpEgressRule) and
/// [`UdpEgressRule`](crate::policy_schema::UdpEgressRule) stay separate types so
/// the published JSON Schema can document what each table promises.
#[derive(serde::Deserialize)]
struct PortScopedRule {
    #[serde(rename = "match")]
    match_pattern: String,
    verdict: Verdict,
    #[serde(default)]
    binaries: Option<Vec<String>>,
}

/// Well-known DNS port.
const DNS_PORT: u16 = 53;

fn parse_port_scoped_egress(
    json: &serde_json::Value,
    table: PortScopedTable,
) -> Result<Vec<RouteRule>, String> {
    let arr = json
        .as_array()
        .ok_or_else(|| format!("{} must be an array", table.label()))?;
    let mut out = Vec::with_capacity(arr.len());
    for v in arr {
        let raw: PortScopedRule = serde_json::from_value(v.clone())
            .map_err(|e| format!("invalid {} rule: {e}", table.label()))?;
        let matcher = normalize_ip_literal(parse_matcher(&raw.match_pattern)?);
        // Port 0 joins the portless patterns in being rejected: no connection
        // can target it, so the rule would resolve and pin at DNS yet never
        // match a real connect.
        let port = match matcher {
            RouteMatcher::CidrPort(_, 0) | RouteMatcher::HostPort(_, 0) => {
                return Err(format!(
                    "{} rule \"{}\": port 0 is not a valid destination port",
                    table.label(),
                    raw.match_pattern
                ));
            }
            RouteMatcher::CidrPort(_, port) | RouteMatcher::HostPort(_, port) => port,
            RouteMatcher::Cidr(_) | RouteMatcher::Domain(_) => {
                return Err(format!(
                    "{} rule \"{}\" must specify a port, e.g. \"host:443\" or \"10.0.0.0/24:443\"",
                    table.label(),
                    raw.match_pattern
                ));
            }
        };
        if table == PortScopedTable::Udp && port == DNS_PORT {
            return Err(format!(
                "{} rule \"{}\": port {port} is served by the sandbox DNS stub, so this rule \
                 could never match",
                table.label(),
                raw.match_pattern
            ));
        }
        let binaries = raw.binaries.map(parse_binaries).transpose()?;
        out.push(RouteRule {
            matcher,
            verdict: raw.verdict,
            // Raw egress always leaves directly; the shared `RouteRule` still
            // carries a transport, so pin it to `Direct` for the raw path.
            transport: Transport::Direct,
            tls_terminate: false,
            http_rules: Vec::new(),
            scheme: None,
            binaries,
        });
    }
    Ok(out)
}

/// Fold an IP-literal `HostPort` into the equivalent single-address `CidrPort`
/// so the raw-TCP layer treats it as a direct IP match. A hostname `HostPort`
/// (and every other matcher) is returned unchanged. This also gives IPv6
/// literals canonical numeric matching instead of string comparison.
///
/// The literal is canonicalized first, so a mapped form (`[::ffff:10.0.0.5]`)
/// folds to the IPv4 `/32` it actually addresses rather than a `/128` V6 net
/// that the always-V4 `SO_ORIGINAL_DST` could never match.
fn normalize_ip_literal(matcher: RouteMatcher) -> RouteMatcher {
    match matcher {
        RouteMatcher::HostPort(host, port) => match host.parse::<std::net::IpAddr>() {
            Ok(ip) => RouteMatcher::CidrPort(IpNet::from(ip.to_canonical()), port),
            Err(_) => RouteMatcher::HostPort(host, port),
        },
        other => other,
    }
}

/// Validate a rule's `binaries` filter. Entries are matched against the
/// kernel-resolved `/proc/<pid>/exe` (always an absolute, canonical path), so
/// both failure modes below can *never* match and are almost certainly
/// misconfigurations — reject them at parse time rather than fail closed
/// silently at request time:
///
/// - An empty list matches no caller, turning an `allow` into an unconditional
///   deny for the host. Omit `binaries` to allow any caller.
/// - A relative path can never equal an absolute `/proc/<pid>/exe` target.
fn parse_binaries(paths: Vec<String>) -> Result<Vec<PathBuf>, String> {
    if paths.is_empty() {
        return Err(
            "binaries filter is empty: it matches no caller and would deny the host for \
             everyone; omit `binaries` to allow any caller"
                .to_string(),
        );
    }
    for path in &paths {
        if !std::path::Path::new(path).is_absolute() {
            return Err(format!(
                "binaries entry {path:?} is not an absolute path; entries are matched against \
                 the kernel-resolved /proc/<pid>/exe, so a relative path can never match"
            ));
        }
    }
    Ok(paths.into_iter().map(PathBuf::from).collect())
}

/// Match result from `match_route`.
#[derive(Debug, Clone, PartialEq)]
pub struct MatchedRoute {
    pub verdict: Verdict,
    pub transport: Transport,
    pub tls_terminate: bool,
}

/// First-match outcome of matching a DNS QNAME against one route table,
/// distinguished so a caller can tell an explicit `Deny`, and a
/// binary-scoped exclusion, apart from "no rule matched" — the DNS stub
/// falls back to its JIT-approved set only on the latter. Matching semantics
/// are as documented on [`hostname_match_for_caller`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostnameMatch {
    /// First admitting rule permits the lookup (its verdict is not `Deny`).
    ///
    /// `Ask` counts as allowed here: the approval gate fires on the TCP attempt
    /// (see `gate::gate_or_deny`), so a NXDOMAIN would preempt the dialog and
    /// the developer would never get to approve. The QNAME reaching the upstream
    /// resolver before the click is the cost of having an interactive gate.
    Allowed,
    /// First admitting rule is an explicit `Deny`.
    Denied,
    /// No rule matched the hostname.
    Unmatched,
    /// A binary-scoped rule matched the hostname but excluded the caller, and
    /// no later rule admitted it. Fails closed (NXDOMAIN) rather than falling
    /// back to the JIT-approved set — the DNS analogue of `find_matching_route`
    /// reporting `binary_filtered`.
    BinaryDenied,
}

impl HostnameMatch {
    /// Combine two tables' answers for one name: it resolves iff some table
    /// holds a live allow for it. DNS carries no port and no protocol, while the
    /// tables govern different ports — and, for `egress.udp`, a different
    /// protocol — of the same host, so a deny in one cannot speak for another's.
    /// Port-, protocol-, and caller-aware enforcement still runs when the
    /// connection or the datagram is judged, which is where the tables are
    /// actually separated.
    ///
    /// With no allow anywhere the name is refused either way; `self` only picks
    /// which reason is reported, following connect-time order.
    pub(crate) fn union(self, other: HostnameMatch) -> HostnameMatch {
        match (self, other) {
            (HostnameMatch::Allowed, _) | (_, HostnameMatch::Allowed) => HostnameMatch::Allowed,
            (HostnameMatch::Unmatched, fallback) => fallback,
            (first, _) => first,
        }
    }
}

/// How the DNS gate treats a *port-scoped* deny. DNS carries no destination
/// port, so the http table and the raw tables need different answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortScope {
    /// `egress.http` routes: ordered first-match, exactly like
    /// [`find_matching_route`]. Any matched deny denies the name for this table;
    /// whether it still resolves depends on the other tables — see
    /// [`HostnameMatch::union`].
    FirstMatch,
    /// Raw-table (`egress.tcp`, `egress.udp`) rules: *port-existential*. One
    /// answer serves every port, so the name resolves when some port survives to
    /// an allow. A deny rules out only its own port (and kills a later allow on
    /// it). Safe because the per-port decision is re-made against the real
    /// `host:port` when the connection or the datagram is judged, and a name
    /// left with only denies still reports `Denied`.
    PerPort,
}

/// [`hostname_match`] with the caller's identity, applying each rule's
/// `binaries` filter through the shared [`caller_admits_rule`] helper so the
/// DNS gate and `find_matching_route` never diverge on binary-scoping (the
/// no-reopen guard included). Passing `None` fails a binary-scoped host closed,
/// exactly as an unresolved caller does at the TCP layer.
///
/// `scope` picks how a *port-scoped* deny is treated — see [`PortScope`].
pub(crate) fn hostname_match_for_caller(
    routes: &[RouteRule],
    hostname: &str,
    caller: Option<&crate::peer_process::PeerProcess>,
    scope: PortScope,
) -> HostnameMatch {
    let lower = hostname.to_ascii_lowercase();
    let mut binary_filtered = false;
    let mut denied_ports: Vec<u16> = Vec::new();
    for rule in routes {
        if !qname_matches_rule(rule, &lower) {
            continue;
        }
        if !caller_admits_rule(rule, caller, binary_filtered) {
            // A binary-scoped rule matched the hostname but excluded the caller
            // (or a later unrestricted rule was suppressed). Remember it so the
            // tail fails closed instead of falling back to the JIT-approved set.
            binary_filtered = true;
            continue;
        }
        let port = match &rule.matcher {
            RouteMatcher::HostPort(_, p) => Some(*p),
            _ => None,
        };
        match (rule.verdict, port, scope) {
            // PerPort: a port-scoped deny rules out only its own port.
            (Verdict::Deny, Some(p), PortScope::PerPort) => denied_ports.push(p),
            (Verdict::Deny, _, _) => return HostnameMatch::Denied,
            // Dead if an earlier deny shadowed this port; keep scanning.
            (_, Some(p), PortScope::PerPort) => {
                if !denied_ports.contains(&p) {
                    return HostnameMatch::Allowed;
                }
            }
            (_, _, _) => return HostnameMatch::Allowed,
        }
    }
    // No live allow survived. An admitted deny (even a port-scoped one that
    // shadowed the only allow) denies the name outright; otherwise fail closed
    // on any binary exclusion, else report no match.
    if !denied_ports.is_empty() {
        HostnameMatch::Denied
    } else if binary_filtered {
        HostnameMatch::BinaryDenied
    } else {
        HostnameMatch::Unmatched
    }
}

/// Whether `rule`'s matcher covers a bare DNS QNAME. `Domain` and `HostPort`
/// (host part, port ignored) match; `Cidr` never does — a QNAME is a name, not
/// an IP literal, and admitting one would leak CIDR policy to the upstream
/// resolver. Address-based access is enforced at the TCP layer instead.
fn qname_matches_rule(rule: &RouteRule, lower: &str) -> bool {
    match &rule.matcher {
        RouteMatcher::Domain(pattern) => domain_matches(pattern, lower),
        RouteMatcher::HostPort(pattern_host, _) => domain_matches(pattern_host, lower),
        RouteMatcher::Cidr(_) | RouteMatcher::CidrPort(_, _) => false,
    }
}

/// Outcome of resolving a connection's destination against the route table.
/// Distinguishes a plain host miss from a host match that a rule's `binaries`
/// filter excluded, so the proxy can fail that case closed instead of leaking
/// it through the default action.
#[derive(Debug)]
pub enum RouteOutcome<'a> {
    /// A rule matched host, scheme, and (if present) its binary filter.
    Matched(&'a RouteRule),
    /// No rule matched. `binary_filtered` is true when at least one rule matched
    /// host and scheme but its `binaries` filter excluded the caller.
    NoMatch { binary_filtered: bool },
}

/// Match a host:port target against the route rules. Rules with a `scheme`
/// filter only match requests with the same scheme as `request_scheme`; rules
/// without one match both `http` and `https`.
///
/// When a rule carries a `binaries` filter, `caller` (the connecting exe plus
/// its ancestor chain) must include one of the listed paths. Without caller
/// info — non-Linux, an already-closed socket, or a `/proc` read failure — a
/// binary-filtered rule never matches, and the miss is reported as
/// `binary_filtered` so the proxy fails closed.
///
/// Once a binary-scoped rule matches the host but excludes the caller, a later
/// *unrestricted* `allow`/`ask` rule for the same host is skipped so it cannot
/// re-open the restriction; a later `deny`, or a later binary-scoped rule that
/// lists the caller, still applies. First-match order otherwise stands — put an
/// unrestricted rule *before* a binary-scoped one if you want it to win.
pub fn find_matching_route<'a>(
    routes: &'a [RouteRule],
    host: &str,
    request_scheme: Scheme,
    caller: Option<&crate::peer_process::PeerProcess>,
) -> RouteOutcome<'a> {
    let hostname = if host.starts_with('[') {
        host.split(']')
            .next()
            .unwrap_or(host)
            .trim_start_matches('[')
    } else {
        host.split(':').next().unwrap_or(host)
    };

    let mut binary_filtered = false;
    for rule in routes {
        if let Some(required) = rule.scheme
            && required != request_scheme
        {
            continue;
        }
        let matched = match &rule.matcher {
            RouteMatcher::Domain(pattern) => domain_matches(pattern, hostname),
            RouteMatcher::Cidr(cidr) => hostname
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| cidr.contains(&ip.to_canonical())),
            RouteMatcher::CidrPort(cidr, pattern_port) => {
                hostname
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| cidr.contains(&ip.to_canonical()))
                    && extract_port(host, 443) == *pattern_port
            }
            RouteMatcher::HostPort(pattern_host, pattern_port) => {
                let target_hostname = extract_hostname(host).to_ascii_lowercase();
                let target_port = extract_port(host, 443);
                domain_matches(pattern_host, &target_hostname) && *pattern_port == target_port
            }
        };
        if !matched {
            continue;
        }
        if caller_admits_rule(rule, caller, binary_filtered) {
            return RouteOutcome::Matched(rule);
        }
        // Host+scheme matched but the binary filter excluded the caller (or a
        // later unrestricted rule was suppressed). Keep scanning for a later
        // rule that admits it, but remember the exclusion so the proxy fails
        // closed instead of leaking through the default action or a broad
        // unrestricted rule.
        binary_filtered = true;
    }
    RouteOutcome::NoMatch { binary_filtered }
}

/// A raw-TCP destination as one egress door knows it. The doors differ only in
/// what they can supply: the transparent listener has the destination IP but
/// lost the name to `SO_ORIGINAL_DST`, while the explicit proxy is handed a name
/// that may or may not be an IP literal. Live DNS pins supply the names neither
/// door was given, so a hostname rule binds the same way on both.
#[derive(Debug, Clone, Copy)]
pub struct TcpTarget<'t> {
    ip: Option<std::net::IpAddr>,
    host: Option<&'t str>,
    pinned_qnames: &'t [&'t str],
}

impl<'t> TcpTarget<'t> {
    /// A destination in whichever form the door had it: an IP literal (the
    /// transparent door's `SO_ORIGINAL_DST`, or a client that dialed an address)
    /// or a hostname (a `CONNECT` target, an absolute-form URL).
    ///
    /// An IP literal is not a name, so it is never offered to `Domain`/`HostPort`
    /// rules; those reach it only through `pinned_qnames`. That is what stops a
    /// client resolving a name itself and reconnecting to the bare address to
    /// shake a hostname rule.
    pub fn at(host: &'t str, pinned_qnames: &'t [&'t str]) -> Self {
        match host.parse() {
            Ok(ip) => Self {
                ip: Some(ip),
                host: None,
                pinned_qnames,
            },
            Err(_) => Self {
                ip: None,
                host: Some(host),
                pinned_qnames,
            },
        }
    }

    /// The first name this destination is known by that satisfies `pred`.
    fn matching_name(&self, pred: impl Fn(&str) -> bool) -> Option<&'t str> {
        self.host
            .filter(|h| pred(h))
            .or_else(|| self.pinned_qnames.iter().copied().find(|q| pred(q)))
    }
}

/// What the `egress.tcp` table said, and the name it said it about.
///
/// `matched_name` is the name the matching rule bound through — the door's own
/// target, or the DNS pin the transparent door had to reach the rule through —
/// and is `None` when the rule matched by address. It exists so the approval
/// dialog can name the destination the way the policy author wrote it: the
/// transparent door holds only an address, and asking a developer about a bare
/// IP for a rule they wrote as a hostname is unanswerable.
#[derive(Debug)]
pub struct TcpMatch<'a> {
    pub outcome: RouteOutcome<'a>,
    pub matched_name: Option<&'a str>,
}

/// Match a raw-TCP destination against the ordered `egress.tcp` rules in one
/// pass, so IP rules and hostname rules compete by their real policy position.
///
/// Only the port-scoped matchers occur here — [`parse_tcp_egress`] rejects the
/// portless ones, so an any-port raw grant cannot exist. `CidrPort` matches the
/// destination IP, canonicalized so an IPv4-mapped IPv6 literal cannot slip past
/// a v4 CIDR; `HostPort` matches any name the destination is known by.
/// `egress.tcp` rules carry no scheme, so there is no scheme filter here. Binary
/// scoping and the no-reopen guard run through the same [`caller_admits_rule`]
/// helper as [`find_matching_route`], so first-match / deny / binary semantics
/// are identical across every door.
pub fn find_matching_tcp_egress<'a>(
    rules: &'a [RouteRule],
    target: TcpTarget<'a>,
    port: u16,
    caller: Option<&crate::peer_process::PeerProcess>,
) -> TcpMatch<'a> {
    let mut binary_filtered = false;
    for rule in rules {
        let mut matched_name = None;
        let matched = match &rule.matcher {
            RouteMatcher::CidrPort(cidr, pattern_port) => {
                *pattern_port == port
                    && target
                        .ip
                        .is_some_and(|ip| cidr.contains(&ip.to_canonical()))
            }
            RouteMatcher::HostPort(pattern_host, pattern_port) => {
                matched_name = (*pattern_port == port)
                    .then(|| target.matching_name(|n| domain_matches(pattern_host, n)))
                    .flatten();
                matched_name.is_some()
            }
            // Rejected at parse time: a portless raw grant is exactly what the
            // port requirement exists to forbid, so there is nothing to match.
            RouteMatcher::Cidr(_) | RouteMatcher::Domain(_) => false,
        };
        if !matched {
            continue;
        }
        if caller_admits_rule(rule, caller, binary_filtered) {
            return TcpMatch {
                outcome: RouteOutcome::Matched(rule),
                matched_name,
            };
        }
        // Matched the target but the binary filter excluded the caller (or a
        // later unrestricted rule was suppressed). Keep scanning, but remember
        // the exclusion so the proxy fails closed rather than falling through.
        binary_filtered = true;
    }
    TcpMatch {
        outcome: RouteOutcome::NoMatch { binary_filtered },
        matched_name: None,
    }
}

/// Whether a rule that already matched the target admits `caller`, applying the
/// `binaries` filter and the no-reopen guard. Shared by `find_matching_route`
/// (TCP) and `hostname_match_for_caller` (DNS) so the two never diverge on
/// binary-scoping. When it returns `false`, the caller records the exclusion
/// (`binary_filtered`) and scans on.
///
/// `binary_filtered` is the caller's running "an earlier binary-scoped rule
/// already claimed this target but excluded me" flag; it drives the guard that
/// stops a later *unrestricted* `allow`/`ask` from re-opening the target.
fn caller_admits_rule(
    rule: &RouteRule,
    caller: Option<&crate::peer_process::PeerProcess>,
    binary_filtered: bool,
) -> bool {
    if !binary_filter_matches(rule, caller) {
        return false;
    }
    // No-reopen: once an earlier binary-scoped rule claimed this target but
    // excluded the caller, a later *unrestricted* `allow`/`ask` must not let it
    // back in. An explicit `deny` is never suppressed — it reinforces the
    // block — and a later binary-scoped rule that lists the caller (its
    // `binaries` is `Some`) still matches.
    !(binary_filtered && rule.binaries.is_none() && rule.verdict != Verdict::Deny)
}

/// Whether `rule`'s `binaries` filter admits `caller`. A rule with no filter
/// admits everyone; a filtered rule requires the caller's exe or one of its
/// ancestors to be in the list, so an unresolved caller (`None`) fails closed.
/// Private on purpose — all binary scoping goes through [`caller_admits_rule`],
/// which layers the no-reopen guard on top.
fn binary_filter_matches(
    rule: &RouteRule,
    caller: Option<&crate::peer_process::PeerProcess>,
) -> bool {
    let Some(allowed) = rule.binaries.as_deref() else {
        return true;
    };
    let Some(caller) = caller else {
        return false;
    };
    caller
        .binary_paths()
        .any(|candidate| allowed.iter().any(|p| p.as_path() == candidate))
}

/// Match a host:port target against the route rules. Binary-filtered rules
/// never match here — there is no caller to check — so they fall through to the
/// supplied defaults, exactly as a plain host miss does. A binary-scoped rule
/// also suppresses any later unrestricted rule for the same host, so this
/// caller-agnostic path returns the defaults rather than that later rule.
/// Returns the matched route config for the first matching rule, or the
/// defaults otherwise. This is a caller-agnostic convenience: the live proxy
/// calls [`find_matching_route`] with the resolved caller so the binary filter
/// applies. Prefer that path when caller identity is available; reach for this
/// only when it is not, or does not matter.
pub fn match_route(
    routes: &[RouteRule],
    host: &str,
    request_scheme: Scheme,
    default_verdict: Verdict,
    default_transport: Transport,
) -> MatchedRoute {
    match find_matching_route(routes, host, request_scheme, None) {
        RouteOutcome::Matched(rule) => MatchedRoute {
            verdict: rule.verdict,
            transport: rule.transport,
            tls_terminate: rule.tls_terminate,
        },
        RouteOutcome::NoMatch { .. } => MatchedRoute {
            verdict: default_verdict,
            transport: default_transport,
            tls_terminate: false,
        },
    }
}

/// Extract hostname from a target like "host:port" or "[::1]:port".
fn extract_hostname(target: &str) -> String {
    if target.starts_with('[') {
        target
            .split(']')
            .next()
            .unwrap_or(target)
            .trim_start_matches('[')
            .to_string()
    } else {
        target.split(':').next().unwrap_or(target).to_string()
    }
}

/// Extract port from a target like "host:port" or "[::1]:port", defaulting to `default`.
fn extract_port(target: &str, default: u16) -> u16 {
    if target.starts_with('[') {
        target
            .rsplit_once("]:")
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or(default)
    } else {
        target
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or(default)
    }
}

pub fn domain_matches(pattern: &str, hostname: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let hostname = hostname.to_ascii_lowercase();
    if pattern == "*" {
        // Catch-all: any non-empty hostname or IP literal. Empty (e.g. a
        // malformed ":443" CONNECT target) fails closed like every other arm.
        !hostname.is_empty()
    } else if let Some(suffix) = pattern.strip_prefix("*.") {
        // Leading wildcard: *.example.com matches foo.example.com and example.com
        hostname == suffix || hostname.ends_with(&format!(".{suffix}"))
    } else if pattern.contains("*.") {
        // Mid-segment wildcard: prefix.*.suffix matches prefix.anything.suffix
        // Split on "*" (not "*.") so the dot stays in the suffix, preventing
        // over-matching like "us-east-1amazonaws.com" for "*.amazonaws.com".
        let (prefix, suffix) = pattern.split_once('*').unwrap();
        hostname.starts_with(prefix)
            && hostname[prefix.len()..].ends_with(suffix)
            && hostname.len() > prefix.len() + suffix.len()
    } else {
        hostname == pattern
    }
}

/// Match a credential-injection pattern against a CONNECT target (e.g. "host:port").
///
/// Patterns may specify an explicit port (e.g. "lens.example.com:8443"). In that
/// case we match the full host:port to prevent leaking credentials to other
/// services on the same host. Patterns without a port (including wildcards like
/// "bedrock-runtime.*.amazonaws.com") match by hostname only.
pub fn injection_matches(pattern: &str, target_host: &str) -> bool {
    // Wildcard patterns: hostname-only match (port agnostic)
    if pattern.contains('*') {
        let hostname = extract_hostname(target_host);
        return domain_matches(pattern, &hostname);
    }
    // Non-wildcard: if pattern has port, compare host:port; else hostname only.
    // Detect port via last ':' after any IPv6 ']' (IPv6 literals aren't expected here).
    let pattern_has_port = pattern
        .rsplit_once(':')
        .is_some_and(|(_, p)| p.parse::<u16>().is_ok());
    if pattern_has_port {
        pattern.eq_ignore_ascii_case(target_host)
    } else {
        let hostname = extract_hostname(target_host);
        domain_matches(pattern, &hostname)
    }
}

const MAX_SEPARATOR_DECODE_PASSES: usize = 8;

/// Decode percent-encoded path separators so a request can't smuggle a `..` or
/// `/` past the allowlist that the origin would then decode and act on.
/// Only the security-relevant separators are decoded (case-insensitively):
/// `%2e` → `.`, and `%2f` / `%5c` → `/` (any literal backslash is folded to `/`
/// up front), plus `%25` → `%` so the loop can unwrap a multiply-encoded
/// separator. Other percent sequences (e.g. `%20`) are left intact so a
/// legitimately-encoded segment byte still matches by its encoded form.
/// Decoding repeats to a bounded fixed point so forms like `%252e` collapse
/// too; malformed sequences (`%zz`, a bare `%`) pass through unchanged.
///
/// Scope: only ASCII separator encodings are canonicalized. Overlong/non-ASCII
/// encodings that some legacy origins decode to a separator (e.g. overlong-UTF-8
/// `%c0%af` / `%e0%80%af` → `/`) are deliberately NOT decoded here — the
/// realistic origins reachable through this proxy (modern HTTPS APIs) reject
/// overlong UTF-8, so closing them is left to the origin's own hardening.
fn decode_path_separators(path: &str) -> String {
    let mut current = path.replace('\\', "/");
    for _ in 0..MAX_SEPARATOR_DECODE_PASSES {
        let decoded = decode_separators_once(&current);
        if decoded == current {
            return current;
        }
        current = decoded;
    }
    current
}

fn decode_separators_once(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut result = String::with_capacity(input.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        // Only treat `%` as the start of an encoded byte when it is followed by
        // two hex digits. Consuming the next two chars unconditionally would let
        // a bare or malformed `%` (e.g. `%g`, a trailing `%`, or the first `%`
        // of `%%2f`) swallow the `%` of a following encoded separator, desyncing
        // our canonical view from the path the origin decodes. A non-hex `%` is
        // emitted literally and we advance by one.
        if c == '%'
            && i + 2 < chars.len()
            && chars[i + 1].is_ascii_hexdigit()
            && chars[i + 2].is_ascii_hexdigit()
        {
            let hex: String = [chars[i + 1], chars[i + 2]].iter().collect();
            if let Some(sep) = decode_separator_byte(&hex) {
                result.push(sep);
                i += 3;
                continue;
            }
        }
        result.push(c);
        i += 1;
    }
    result
}

fn decode_separator_byte(hex: &str) -> Option<char> {
    match hex.to_ascii_lowercase().as_str() {
        "2e" => Some('.'),
        "2f" | "5c" => Some('/'),
        "25" => Some('%'),
        _ => None,
    }
}

/// Normalize a URL path for safe matching: decode percent-encoded separators,
/// collapse `//`, resolve `..`, strip trailing `/`.
/// Percent-encoded path separators (`%2e`, `%2f`, `%5c`, incl. multiply-encoded
/// forms) ARE decoded so matching happens on the canonical path the origin sees;
/// other percent sequences are left encoded.
pub fn normalize_path(path: &str) -> String {
    let decoded = decode_path_separators(path);
    let mut segments: Vec<&str> = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }
    format!("/{}", segments.join("/"))
}

/// Match a URL path against a glob pattern.
/// Supports: exact match, `*` (single segment or empty with trailing slash), and `**` (any depth).
/// Examples:
/// - `/api/v1/*` matches `/api/v1/foo`, `/api/v1/` but not `/api/v1/foo/bar` or `/api/v1`
/// - `/api/**` matches `/api`, `/api/`, `/api/v1/users`
/// - `/v1/projects/*/llm/*` matches `/v1/projects/123/llm/anthropic`
pub fn path_glob_matches(pattern: &str, path: &str) -> bool {
    if pattern == "*" || pattern == "**" {
        return true;
    }

    // Include empty segments to preserve trailing slash info
    let pattern_segs: Vec<&str> = pattern.split('/').collect();
    let path_segs: Vec<&str> = path.split('/').collect();

    glob_match_segments(&pattern_segs, &path_segs)
}

fn glob_match_segments(pattern: &[&str], path: &[&str]) -> bool {
    let mut pi = 0; // pattern index
    let mut si = 0; // path segment index

    while pi < pattern.len() {
        let pat = pattern[pi];

        if pat == "**" {
            // ** at the end matches everything remaining
            if pi == pattern.len() - 1 {
                return true;
            }
            // Try matching ** against 0, 1, 2, ... segments
            for skip in 0..=(path.len() - si) {
                if glob_match_segments(&pattern[pi + 1..], &path[si + skip..]) {
                    return true;
                }
            }
            return false;
        }

        // Need at least one more path segment
        if si >= path.len() {
            return false;
        }

        if pat == "*" {
            // Single wildcard matches exactly one segment (can be empty for trailing slash)
            pi += 1;
            si += 1;
        } else if pat == path[si] {
            // Exact match (including empty segments)
            pi += 1;
            si += 1;
        } else {
            return false;
        }
    }

    // Pattern exhausted - path must also be exhausted
    si == path.len()
}

/// What a route's HTTP rules make of a request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpRuleOutcome<'a> {
    /// No rule covers this method and path. The caller denies the request.
    NoMatch,
    /// A rule with no GraphQL condition covers it. The caller allows it, and
    /// no body is read.
    Allow,
    /// GraphQL rules cover it, and they decide it once the body is read. Each
    /// matcher listed is a candidate; one of them must cover the operation
    /// whole.
    Graphql(Vec<&'a GraphqlMatcher>),
}

/// Decide what a route's HTTP rules make of a request head.
///
/// An empty rule list puts no restriction on the route, which is the
/// deny-by-default contract on [`crate::policy_schema::RouteRule::rules`].
///
/// Where both kinds of rule cover the same head, the GraphQL rules win and the
/// body decides. [`crate::policy_schema::HttpRule::graphql`] says why.
pub fn classify_http_request<'a>(
    rules: &'a [HttpRule],
    method: &str,
    path: &str,
) -> HttpRuleOutcome<'a> {
    if rules.is_empty() {
        return HttpRuleOutcome::Allow;
    }

    let mut graphql = Vec::new();
    let mut covered_by_head_alone = false;
    for rule in rules
        .iter()
        .filter(|rule| head_matches(rule.method.as_deref(), rule.path.as_deref(), method, path))
    {
        match &rule.graphql {
            Some(matcher) => graphql.push(matcher),
            None => covered_by_head_alone = true,
        }
    }

    if !graphql.is_empty() {
        HttpRuleOutcome::Graphql(graphql)
    } else if covered_by_head_alone {
        HttpRuleOutcome::Allow
    } else {
        HttpRuleOutcome::NoMatch
    }
}

/// Whether a credential injection's rules cover a request.
///
/// Head-only by construction — see [`crate::policy_schema::HttpRequestMatch`].
/// An empty list covers every request to the domain.
pub fn injection_covers_request(rules: &[HttpRequestMatch], method: &str, path: &str) -> bool {
    rules.is_empty()
        || rules
            .iter()
            .any(|rule| head_matches(rule.method.as_deref(), rule.path.as_deref(), method, path))
}

/// Whether a request's method and path satisfy a rule's head conditions. An
/// absent condition places no restriction.
fn head_matches(
    rule_method: Option<&str>,
    rule_path: Option<&str>,
    method: &str,
    path: &str,
) -> bool {
    let method_ok = match rule_method {
        None | Some("*") => true,
        Some(wanted) => wanted.eq_ignore_ascii_case(method),
    };
    let path_ok = match rule_path {
        None => true,
        Some(pattern) => path_glob_matches(pattern, path),
    };
    method_ok && path_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether the rules permit a request on its head alone.
    fn allows(rules: &[HttpRule], method: &str, path: &str) -> bool {
        matches!(
            classify_http_request(rules, method, path),
            HttpRuleOutcome::Allow
        )
    }

    fn head_rule(method: &str, path: &str) -> HttpRule {
        HttpRule {
            method: Some(method.to_string()),
            path: Some(path.to_string()),
            graphql: None,
        }
    }

    fn graphql_rule(method: &str, path: &str, fields: &[&str]) -> HttpRule {
        HttpRule {
            method: Some(method.to_string()),
            path: Some(path.to_string()),
            graphql: Some(crate::policy_schema::GraphqlMatcher {
                operation_type: crate::policy_schema::GraphqlOperationTypeMatcher::Query,
                operation_name: None,
                fields: fields.iter().map(ToString::to_string).collect(),
            }),
        }
    }

    // ----------------------------------------------------------------------
    // GraphQL rule precedence
    // ----------------------------------------------------------------------

    #[test]
    fn a_graphql_rule_claims_the_head_it_covers() {
        let rules = vec![graphql_rule("POST", "/graphql", &["viewer"])];
        assert!(matches!(
            classify_http_request(&rules, "POST", "/graphql"),
            HttpRuleOutcome::Graphql(matchers) if matchers.len() == 1
        ));
    }

    #[test]
    fn a_graphql_rule_wins_over_a_bodiless_rule_on_the_same_head() {
        // The whole point: a broad allow beside a GraphQL rule must not let a
        // request past unread, or the GraphQL rule would do nothing at all.
        let rules = vec![
            head_rule("POST", "/**"),
            graphql_rule("POST", "/graphql", &["viewer"]),
        ];
        assert!(matches!(
            classify_http_request(&rules, "POST", "/graphql"),
            HttpRuleOutcome::Graphql(_)
        ));
    }

    #[test]
    fn rule_order_does_not_change_which_kind_wins() {
        let graphql_first = vec![
            graphql_rule("POST", "/graphql", &["viewer"]),
            head_rule("POST", "/**"),
        ];
        assert!(matches!(
            classify_http_request(&graphql_first, "POST", "/graphql"),
            HttpRuleOutcome::Graphql(_)
        ));
    }

    #[test]
    fn a_bodiless_rule_still_covers_a_head_no_graphql_rule_claims() {
        let rules = vec![
            head_rule("POST", "/**"),
            graphql_rule("POST", "/graphql", &["viewer"]),
        ];
        assert!(allows(&rules, "POST", "/rest/things"));
    }

    #[test]
    fn every_graphql_rule_covering_the_head_becomes_a_candidate() {
        let rules = vec![
            graphql_rule("POST", "/graphql", &["viewer"]),
            graphql_rule("POST", "/**", &["rateLimit"]),
            head_rule("GET", "/health"),
        ];
        match classify_http_request(&rules, "POST", "/graphql") {
            HttpRuleOutcome::Graphql(matchers) => assert_eq!(matchers.len(), 2),
            other => panic!("expected two candidates, got {other:?}"),
        }
    }

    #[test]
    fn a_head_no_rule_covers_matches_nothing() {
        let rules = vec![graphql_rule("POST", "/graphql", &["viewer"])];
        assert!(matches!(
            classify_http_request(&rules, "DELETE", "/graphql"),
            HttpRuleOutcome::NoMatch
        ));
    }

    #[test]
    fn an_empty_rule_list_places_no_restriction() {
        assert!(matches!(
            classify_http_request(&[], "POST", "/graphql"),
            HttpRuleOutcome::Allow
        ));
    }

    #[test]
    fn a_rule_of_only_a_graphql_block_survives_parsing_and_covers_any_head() {
        let json = r#"[{
            "match": "api.github.com",
            "verdict": "allow",
            "transport": "direct",
            "rules": [{ "graphql": { "operationType": "query" } }]
        }]"#;
        let routes = parse_routes(json).unwrap();
        assert_eq!(
            routes[0].http_rules.len(),
            1,
            "the rule must not be dropped"
        );
        assert!(matches!(
            classify_http_request(&routes[0].http_rules, "POST", "/anything"),
            HttpRuleOutcome::Graphql(_)
        ));
    }

    #[test]
    fn a_rule_with_no_condition_at_all_is_still_dropped() {
        let json = r#"[{
            "match": "api.github.com",
            "verdict": "allow",
            "transport": "direct",
            "rules": [{}]
        }]"#;
        let routes = parse_routes(json).unwrap();
        assert!(
            routes[0].http_rules.is_empty(),
            "a match-all rule would bypass deny-by-default"
        );
    }

    #[test]
    fn a_graphql_rule_parses_its_matcher() {
        let json = r#"[{
            "match": "api.github.com",
            "verdict": "allow",
            "transport": "direct",
            "rules": [{
                "method": "POST",
                "path": "/graphql",
                "graphql": {
                    "operationType": "mutation",
                    "operationName": "Create*",
                    "fields": ["createIssue"]
                }
            }]
        }]"#;
        let routes = parse_routes(json).unwrap();
        let matcher = routes[0].http_rules[0]
            .graphql
            .as_ref()
            .expect("matcher parsed");
        assert_eq!(
            matcher.operation_type,
            crate::policy_schema::GraphqlOperationTypeMatcher::Mutation
        );
        assert_eq!(matcher.operation_name.as_deref(), Some("Create*"));
        assert_eq!(matcher.fields, ["createIssue"]);
    }

    #[test]
    fn a_graphql_matcher_rejects_an_unknown_key() {
        let json = r#"[{
            "match": "api.github.com",
            "verdict": "allow",
            "transport": "direct",
            "rules": [{ "graphql": { "operationType": "query", "opration_nmae": "typo" } }]
        }]"#;
        let err = parse_routes(json).expect_err("a misspelled key must fail the policy");
        assert!(err.contains("opration_nmae"), "{err}");
    }

    #[test]
    fn an_unknown_key_on_an_http_rule_fails_the_policy() {
        // A misspelt `graphql` would otherwise leave the bare method and path
        // behind as an unconditional allow — the narrowing would go missing
        // without a sound.
        let json = r#"[{
            "match": "api.github.com",
            "verdict": "allow",
            "transport": "direct",
            "rules": [{
                "method": "POST",
                "path": "/graphql",
                "grapql": { "operationType": "query" }
            }]
        }]"#;
        let err = parse_routes(json).expect_err("a misspelt narrowing key must fail the policy");
        assert!(err.contains("grapql"), "{err}");
    }

    #[test]
    fn a_graphql_matcher_requires_an_operation_type() {
        let json = r#"[{
            "match": "api.github.com",
            "verdict": "allow",
            "transport": "direct",
            "rules": [{ "graphql": { "fields": ["viewer"] } }]
        }]"#;
        let err = parse_routes(json).expect_err("an absent operation type must fail the policy");
        assert!(err.contains("operationType"), "{err}");
    }

    fn parse_routes(json: &str) -> Result<Vec<RouteRule>, String> {
        let val: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
        parse_proxy_routes(&val).map(|parsed| parsed.into_iter().map(|p| p.rule).collect())
    }

    #[test]
    fn parse_routes_basic() {
        let json = r#"[
            {"match": "10.0.0.0/8", "verdict": "allow", "transport": "direct"},
            {"match": "*.internal.company.com", "verdict": "allow", "transport": "direct"},
            {"match": "*.sketchy.com", "verdict": "deny", "transport": "upstream"}
        ]"#;
        let routes = parse_routes(json).unwrap();
        assert_eq!(routes.len(), 3);
        assert_eq!(routes[0].verdict, Verdict::Allow);
        assert_eq!(routes[0].transport, Transport::Direct);
        assert_eq!(routes[2].verdict, Verdict::Deny);
        assert!(matches!(routes[0].matcher, RouteMatcher::Cidr(_)));
        assert!(matches!(routes[1].matcher, RouteMatcher::Domain(_)));
    }

    #[test]
    fn parse_routes_empty() {
        let routes = parse_routes("[]").unwrap();
        assert!(routes.is_empty());
    }

    #[test]
    fn parse_routes_invalid_verdict() {
        let json = r#"[{"match": "foo.com", "verdict": "unknown", "transport": "direct"}]"#;
        assert!(parse_routes(json).is_err());
    }

    #[test]
    fn parse_routes_missing_transport() {
        let json = r#"[{"match": "foo.com", "verdict": "allow"}]"#;
        assert!(parse_routes(json).is_err());
    }

    #[test]
    fn parse_routes_missing_verdict() {
        let json = r#"[{"match": "foo.com", "transport": "direct"}]"#;
        assert!(parse_routes(json).is_err());
    }

    #[test]
    fn match_route_cidr() {
        let routes =
            parse_routes(r#"[{"match": "10.0.0.0/8", "verdict": "allow", "transport": "direct"}]"#)
                .unwrap();
        assert_eq!(
            match_route(
                &routes,
                "10.1.2.3:443",
                Scheme::Https,
                Verdict::Allow,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Allow,
                transport: Transport::Direct,
                tls_terminate: false,
            }
        );
        assert_eq!(
            match_route(
                &routes,
                "8.8.8.8:443",
                Scheme::Https,
                Verdict::Allow,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Allow,
                transport: Transport::Upstream,
                tls_terminate: false,
            }
        );
    }

    #[test]
    fn cidr_deny_matches_an_ipv4_mapped_ipv6_literal() {
        // `::ffff:10.0.0.5` is the same host on the wire as `10.0.0.5` — the
        // kernel emits real IPv4 packets for it. The SSRF floor canonicalizes
        // (sock_mark::is_disallowed_egress_ip), so if the policy layer does not,
        // a CIDR deny is evaded while the dial still succeeds.
        let routes = parse_routes(
            r#"[{"match": "10.0.0.0/8", "verdict": "deny", "transport": "direct"},
                {"match": "*", "verdict": "allow", "transport": "direct"}]"#,
        )
        .unwrap();
        match find_matching_route(&routes, "[::ffff:10.0.0.5]:443", Scheme::Https, None) {
            RouteOutcome::Matched(rule) => assert_eq!(rule.verdict, Verdict::Deny),
            other => panic!("mapped form must hit the CIDR deny; got {other:?}"),
        }
    }

    #[test]
    fn cidr_port_deny_matches_an_ipv4_mapped_ipv6_literal() {
        let routes = parse_routes(
            r#"[{"match": "10.0.0.0/8:443", "verdict": "deny", "transport": "direct"},
                {"match": "*", "verdict": "allow", "transport": "direct"}]"#,
        )
        .unwrap();
        match find_matching_route(&routes, "[::ffff:10.0.0.5]:443", Scheme::Https, None) {
            RouteOutcome::Matched(rule) => assert_eq!(rule.verdict, Verdict::Deny),
            other => panic!("mapped form must hit the CIDR:port deny; got {other:?}"),
        }
    }

    #[test]
    fn tcp_egress_cidr_matches_a_mapped_destination_ip() {
        // Same canonicalization gap on the raw path, for symmetry.
        let rules = parse_tcp_egress(
            &serde_json::from_str(r#"[{"match": "10.0.0.0/8:5432", "verdict": "deny"}]"#).unwrap(),
        )
        .unwrap();
        match find_matching_tcp_egress(&rules, TcpTarget::at("::ffff:10.0.0.5", &[]), 5432, None)
            .outcome
        {
            RouteOutcome::Matched(rule) => assert_eq!(rule.verdict, Verdict::Deny),
            other => panic!("mapped dst must hit the CIDR:port deny; got {other:?}"),
        }
    }

    #[test]
    fn tcp_egress_folds_a_mapped_ip_literal_to_its_ipv4_form() {
        // A policy-side mapped literal must normalize to the IPv4 /32, or it is
        // a V6 net that an always-V4 SO_ORIGINAL_DST can never match.
        let rules = parse_tcp_egress(
            &serde_json::from_str(r#"[{"match": "[::ffff:10.0.0.5]:5432", "verdict": "deny"}]"#)
                .unwrap(),
        )
        .unwrap();
        assert!(
            matches!(
                &rules[0].matcher,
                RouteMatcher::CidrPort(net, 5432) if net.to_string() == "10.0.0.5/32"
            ),
            "expected the IPv4 /32 form; got {:?}",
            rules[0].matcher
        );
    }

    #[test]
    fn slash_bearing_patterns_stay_inert_instead_of_failing_the_policy() {
        assert!(matches!(
            parse_matcher("https://api.example.com").unwrap(),
            RouteMatcher::Domain(d) if d == "https://api.example.com"
        ));
        assert!(matches!(
            parse_matcher("example.com/v1:8080").unwrap(),
            RouteMatcher::HostPort(h, 8080) if h == "example.com/v1"
        ));
    }

    #[test]
    fn parse_cidr_port_ipv4() {
        let routes = parse_routes(
            r#"[{"match": "10.0.0.0/24:5432", "verdict": "allow", "transport": "direct"}]"#,
        )
        .unwrap();
        assert!(matches!(
            &routes[0].matcher,
            RouteMatcher::CidrPort(net, 5432) if net.to_string() == "10.0.0.0/24"
        ));
    }

    #[test]
    fn parse_cidr_port_ipv6_bracketed() {
        let routes = parse_routes(
            r#"[{"match": "[2001:db8::/32]:5432", "verdict": "allow", "transport": "direct"}]"#,
        )
        .unwrap();
        assert!(matches!(
            &routes[0].matcher,
            RouteMatcher::CidrPort(net, 5432) if net.to_string() == "2001:db8::/32"
        ));
    }

    #[test]
    fn parse_bare_ipv6_bracketed_stays_host_port() {
        // A bracketed literal without a prefix length must remain HostPort so
        // existing `[::1]:6443` rules keep matching by exact host.
        let routes =
            parse_routes(r#"[{"match": "[::1]:6443", "verdict": "allow", "transport": "direct"}]"#)
                .unwrap();
        assert!(matches!(
            &routes[0].matcher,
            RouteMatcher::HostPort(h, 6443) if h == "::1"
        ));
    }

    #[test]
    fn match_cidr_port_enforces_both_range_and_port() {
        let routes = parse_routes(
            r#"[{"match": "10.0.0.0/24:5432", "verdict": "allow", "transport": "direct"}]"#,
        )
        .unwrap();
        // In-range IP on the right port matches.
        assert_eq!(
            match_route(
                &routes,
                "10.0.0.5:5432",
                Scheme::Https,
                Verdict::Deny,
                Transport::Upstream
            )
            .verdict,
            Verdict::Allow,
        );
        // In-range IP on a different port does NOT match.
        assert_eq!(
            match_route(
                &routes,
                "10.0.0.5:5433",
                Scheme::Https,
                Verdict::Deny,
                Transport::Upstream
            )
            .verdict,
            Verdict::Deny,
        );
        // Out-of-range IP on the right port does NOT match.
        assert_eq!(
            match_route(
                &routes,
                "10.0.1.5:5432",
                Scheme::Https,
                Verdict::Deny,
                Transport::Upstream
            )
            .verdict,
            Verdict::Deny,
        );
    }

    #[test]
    fn match_ip_port_via_host_port() {
        // A single `ip:port` needs no new matcher — it already round-trips
        // through HostPort exact-matching.
        let routes = parse_routes(
            r#"[{"match": "10.0.0.5:5432", "verdict": "allow", "transport": "direct"}]"#,
        )
        .unwrap();
        assert!(matches!(
            &routes[0].matcher,
            RouteMatcher::HostPort(h, 5432) if h == "10.0.0.5"
        ));
        assert_eq!(
            match_route(
                &routes,
                "10.0.0.5:5432",
                Scheme::Https,
                Verdict::Deny,
                Transport::Upstream
            )
            .verdict,
            Verdict::Allow,
        );
        assert_eq!(
            match_route(
                &routes,
                "10.0.0.5:5433",
                Scheme::Https,
                Verdict::Deny,
                Transport::Upstream
            )
            .verdict,
            Verdict::Deny,
        );
    }

    #[test]
    fn a_tcp_allow_shadows_an_http_rule_for_the_same_host() {
        let tcp = parse_tcp(r#"[{"match": "db.internal:5432", "verdict": "allow"}]"#).unwrap();
        let http =
            routes_from(r#"[{"match": "db.internal", "verdict": "allow", "transport": "direct"}]"#);
        assert_eq!(overlapping_http_rules(&tcp, &http).len(), 1);
    }

    #[test]
    fn a_tcp_rule_on_another_port_shadows_nothing() {
        // The port every `egress.tcp` rule must carry is what lets both tables
        // describe one host without colliding.
        let tcp = parse_tcp(r#"[{"match": "db.internal:5432", "verdict": "allow"}]"#).unwrap();
        let http = routes_from(
            r#"[{"match": "db.internal:443", "verdict": "allow", "transport": "direct"}]"#,
        );
        assert!(overlapping_http_rules(&tcp, &http).is_empty());
    }

    #[test]
    fn a_tcp_deny_shadows_nothing() {
        // A deny refuses the connection; it never splices one past inspection.
        let tcp = parse_tcp(r#"[{"match": "db.internal:5432", "verdict": "deny"}]"#).unwrap();
        let http =
            routes_from(r#"[{"match": "db.internal", "verdict": "allow", "transport": "direct"}]"#);
        assert!(overlapping_http_rules(&tcp, &http).is_empty());
    }

    #[test]
    fn a_wildcard_tcp_rule_shadows_a_concrete_route_under_it() {
        // Overlap is symmetric: the wildcard can be on either side.
        let tcp =
            parse_tcp(r#"[{"match": "*.rds.amazonaws.com:5432", "verdict": "allow"}]"#).unwrap();
        let http = routes_from(
            r#"[{"match": "db.rds.amazonaws.com", "verdict": "allow", "transport": "direct"}]"#,
        );
        assert_eq!(overlapping_http_rules(&tcp, &http).len(), 1);
    }

    #[test]
    fn a_cidr_tcp_rule_is_not_compared_against_a_hostname_route() {
        // Whether 10.0.0.0/8 covers db.internal is knowable only after resolving.
        let tcp = parse_tcp(r#"[{"match": "10.0.0.0/8:5432", "verdict": "allow"}]"#).unwrap();
        let http =
            routes_from(r#"[{"match": "db.internal", "verdict": "allow", "transport": "direct"}]"#);
        assert!(overlapping_http_rules(&tcp, &http).is_empty());
    }

    #[test]
    fn a_tcp_allow_shadows_a_wildcard_route_that_covers_it() {
        // The shape that actually costs enforcement: the wildcard route carries
        // method/path rules that the raw splice will not apply.
        let tcp = parse_tcp(r#"[{"match": "api.example.com:443", "verdict": "allow"}]"#).unwrap();
        let http = routes_from(
            r#"[{"match": "*.example.com", "verdict": "allow", "transport": "direct",
                 "rules": [{"method": "GET", "path": "/v1/*"}]}]"#,
        );
        assert!(
            !http[0].http_rules.is_empty(),
            "the route must carry the rules the splice will skip"
        );
        assert_eq!(overlapping_http_rules(&tcp, &http).len(), 1);
    }

    /// The `egress.http` DNS gate with no caller: ordered first-match.
    fn hostname_match(routes: &[RouteRule], hostname: &str) -> HostnameMatch {
        hostname_match_for_caller(routes, hostname, None, PortScope::FirstMatch)
    }

    fn parse_tcp(json: &str) -> Result<Vec<RouteRule>, String> {
        let val: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
        parse_tcp_egress(&val)
    }

    /// Build a `RouteRule` straight from a match pattern, bypassing the
    /// `egress.tcp` port requirement. `hostname_match_for_caller` is shared with
    /// the L7 gate (where portless hostnames are the norm), so its port-blind
    /// resolution logic is exercised here with rules constructed directly.
    /// One `egress.tcp` rule, built through the real parser so a test can only
    /// construct shapes a policy could actually carry — a hand-assembled
    /// `RouteRule` could carry a matcher the port requirement rules out, and
    /// keep the matching code for it alive on that basis alone.
    fn hostname_rule(pattern: &str, verdict: Verdict) -> RouteRule {
        parse_tcp(&format!(
            r#"[{{"match": "{pattern}", "verdict": "{}"}}]"#,
            serde_json::to_value(verdict).unwrap().as_str().unwrap()
        ))
        .expect("test rule must be a shape production accepts")
        .pop()
        .expect("one rule in, one rule out")
    }

    #[test]
    fn parse_tcp_egress_cidr_port() {
        let rules = parse_tcp(r#"[{"match": "10.0.0.0/24:5432", "verdict": "allow"}]"#).unwrap();
        assert_eq!(rules.len(), 1);
        assert!(matches!(
            &rules[0].matcher,
            RouteMatcher::CidrPort(net, 5432) if net.to_string() == "10.0.0.0/24"
        ));
        assert_eq!(rules[0].verdict, Verdict::Allow);
        // Raw TCP always egresses directly.
        assert_eq!(rules[0].transport, Transport::Direct);
    }

    #[test]
    fn parse_tcp_egress_ip_literal_hostport_normalizes_to_cidrport() {
        // An IP-literal `HostPort` folds into a single-address `CidrPort` so it
        // stays a direct IP match (and gets numeric, not string, comparison); a
        // CIDR:port stays `CidrPort`. Both keep their position in the one list.
        let rules = parse_tcp(
            r#"[
                {"match": "10.0.0.5:5432", "verdict": "allow"},
                {"match": "10.0.0.0/8:6379", "verdict": "allow"}
            ]"#,
        )
        .unwrap();
        assert_eq!(rules.len(), 2);
        assert!(matches!(
            &rules[0].matcher,
            RouteMatcher::CidrPort(net, 5432) if net.to_string() == "10.0.0.5/32"
        ));
        assert!(matches!(&rules[1].matcher, RouteMatcher::CidrPort(_, 6379)));
    }

    #[test]
    fn parse_tcp_egress_keeps_hostname_rules_in_order() {
        // Hostname rules stay `HostPort` (they can't match a raw IP directly;
        // they drive DNS-answer pinning) and keep their list position.
        let rules = parse_tcp(
            r#"[
                {"match": "db.internal:5432", "verdict": "allow"},
                {"match": "*.rds.amazonaws.com:5432", "verdict": "allow"}
            ]"#,
        )
        .unwrap();
        assert_eq!(rules.len(), 2);
        assert!(matches!(
            &rules[0].matcher,
            RouteMatcher::HostPort(h, 5432) if h == "db.internal"
        ));
        assert!(matches!(
            &rules[1].matcher,
            RouteMatcher::HostPort(h, 5432) if h == "*.rds.amazonaws.com"
        ));
    }

    #[test]
    fn parse_tcp_egress_rejects_a_portless_pattern() {
        // A raw connection is spliced opaquely, so a portless "any port" grant
        // is too broad — and a bare IP literal would silently never match. Every
        // portless form is rejected, failing the policy closed.
        for pattern in ["10.20.5.10", "10.20.0.0/16", "db.internal", "*.example.com"] {
            let json = format!(r#"[{{"match": "{pattern}", "verdict": "allow"}}]"#);
            let err = parse_tcp(&json).expect_err("portless pattern must be rejected");
            assert!(
                err.contains("must specify a port"),
                "unexpected error for {pattern:?}: {err}"
            );
        }
    }

    #[test]
    fn parse_tcp_egress_rejects_port_zero() {
        // Port 0 is not a connectable destination; such a rule would resolve and
        // pin at DNS yet never match a connect — reject it as a dead rule.
        for pattern in ["10.20.5.10:0", "10.20.0.0/16:0", "db.internal:0"] {
            let json = format!(r#"[{{"match": "{pattern}", "verdict": "allow"}}]"#);
            let err = parse_tcp(&json).expect_err("port 0 must be rejected");
            assert!(
                err.contains("port 0 is not a valid"),
                "unexpected error for {pattern:?}: {err}"
            );
        }
    }

    fn parse_udp(json: &str) -> Result<Vec<RouteRule>, String> {
        let val: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
        parse_udp_egress(&val)
    }

    #[test]
    fn parse_udp_egress_reads_every_shape_the_tcp_table_does() {
        // One parser serves both tables, so a pattern means the same thing in
        // each: the IP literal folds to `CidrPort`, the hostname stays
        // `HostPort` to drive DNS pinning, and order is the policy's order.
        let rules = parse_udp(
            r#"[
                {"match": "10.0.0.5:123", "verdict": "allow"},
                {"match": "10.0.0.0/8:161", "verdict": "deny"},
                {"match": "ntp.internal:123", "verdict": "ask"}
            ]"#,
        )
        .unwrap();
        assert!(matches!(
            &rules[0].matcher,
            RouteMatcher::CidrPort(net, 123) if net.to_string() == "10.0.0.5/32"
        ));
        assert!(matches!(&rules[1].matcher, RouteMatcher::CidrPort(_, 161)));
        assert!(matches!(
            &rules[2].matcher,
            RouteMatcher::HostPort(h, 123) if h == "ntp.internal"
        ));
        assert_eq!(rules[2].verdict, Verdict::Ask);
        assert_eq!(rules[0].transport, Transport::Direct);
    }

    #[test]
    fn parse_udp_egress_rejects_the_shapes_the_tcp_table_rejects() {
        for (pattern, expected) in [
            ("ntp.internal", "must specify a port"),
            ("10.20.0.0/16", "must specify a port"),
            ("ntp.internal:0", "port 0 is not a valid"),
        ] {
            let json = format!(r#"[{{"match": "{pattern}", "verdict": "allow"}}]"#);
            let err = parse_udp(&json).expect_err("dead pattern must be rejected");
            assert!(
                err.contains(expected),
                "unexpected error for {pattern:?}: {err}"
            );
        }
    }

    #[test]
    fn parse_udp_egress_rejects_port_53() {
        // The DNS stub claims every unmarked UDP/53 datagram, so such a rule is
        // dead, and a dead `deny` reads as protection that isn't there.
        for pattern in ["8.8.8.8:53", "10.0.0.0/8:53", "resolver.internal:53"] {
            let json = format!(r#"[{{"match": "{pattern}", "verdict": "deny"}}]"#);
            let err = parse_udp(&json).expect_err("port 53 must be rejected");
            assert!(
                err.contains("served by the sandbox DNS stub"),
                "unexpected error for {pattern:?}: {err}"
            );
        }
    }

    #[test]
    fn parse_tcp_egress_still_accepts_port_53() {
        // Only the UDP table loses port 53. Over TCP the transparent door drops
        // DNS rather than claiming it, so a rule naming that port still says
        // something true and must keep parsing.
        let rules = parse_tcp(r#"[{"match": "10.0.0.0/8:53", "verdict": "deny"}]"#).unwrap();
        assert!(matches!(&rules[0].matcher, RouteMatcher::CidrPort(_, 53)));
    }

    #[test]
    fn parse_udp_egress_names_its_own_table_in_an_error() {
        // The operator has two tables to look in; the message must say which.
        let err = parse_udp(r#"[{"match": "ntp.internal", "verdict": "allow"}]"#).unwrap_err();
        assert!(
            err.starts_with("egress.udp rule"),
            "unexpected error: {err}"
        );
        let err = parse_udp(r#"{"match": "ntp.internal:123"}"#).unwrap_err();
        assert_eq!(err, "egress.udp must be an array");
    }

    #[test]
    fn parse_tcp_egress_honors_binaries_filter() {
        let rules = parse_tcp(
            r#"[{"match": "10.0.0.0/24:5432", "verdict": "allow", "binaries": ["/usr/bin/psql"]}]"#,
        )
        .unwrap();
        assert_eq!(
            rules[0].binaries.as_deref(),
            Some(&[PathBuf::from("/usr/bin/psql")][..])
        );
    }

    #[test]
    fn fqdn_hostname_match_resolves_a_port_scoped_allow() {
        let rules = [hostname_rule("db.internal:5432", Verdict::Allow)];
        // DNS is port-blind: a port-scoped allow still resolves the name so the
        // answer can be pinned; the port itself is enforced at connect.
        assert_eq!(
            hostname_match_for_caller(&rules, "db.internal", None, PortScope::PerPort),
            HostnameMatch::Allowed
        );
        assert_eq!(
            hostname_match_for_caller(&rules, "other.example.com", None, PortScope::PerPort),
            HostnameMatch::Unmatched
        );
    }

    #[test]
    fn fqdn_hostname_match_port_scoped_deny_does_not_block_another_port() {
        // Ordered: deny :5432, allow :6379. The port-scoped deny must not veto
        // resolution the allowed port needs — the name resolves, and per-port
        // enforcement happens at connect.
        let rules = [
            hostname_rule("db.internal:5432", Verdict::Deny),
            hostname_rule("db.internal:6379", Verdict::Allow),
        ];
        assert_eq!(
            hostname_match_for_caller(&rules, "db.internal", None, PortScope::PerPort),
            HostnameMatch::Allowed
        );
    }

    #[test]
    fn hostname_match_portless_deny_is_terminal_under_first_match() {
        // A portless deny reaches only the L7 table, which is `FirstMatch` —
        // `egress.tcp` requires a port on every rule. There an earlier deny
        // covering the name kills every later allow, so the name cannot resolve.
        let rules = parse_routes(
            r#"[
                {"match": "db.internal", "verdict": "deny", "transport": "direct"},
                {"match": "db.internal:6379", "verdict": "allow", "transport": "direct"}
            ]"#,
        )
        .unwrap();
        assert_eq!(
            hostname_match_for_caller(&rules, "db.internal", None, PortScope::FirstMatch),
            HostnameMatch::Denied
        );
    }

    #[test]
    fn fqdn_hostname_match_same_port_deny_shadows_the_allow() {
        // deny :5432 then allow :5432 — the only allow is dead under first-match,
        // so resolving would leak the qname for a name that can never connect.
        let rules = [
            hostname_rule("db.internal:5432", Verdict::Deny),
            hostname_rule("db.internal:5432", Verdict::Allow),
        ];
        assert_eq!(
            hostname_match_for_caller(&rules, "db.internal", None, PortScope::PerPort),
            HostnameMatch::Denied
        );
    }

    #[test]
    fn fqdn_hostname_match_resolves_a_wildcard() {
        // DNS matches the host part alone, so the rule's port plays no role here
        // — it is enforced at connect.
        let rules = [hostname_rule("*.rds.amazonaws.com:5432", Verdict::Allow)];
        assert_eq!(
            hostname_match_for_caller(&rules, "prod.rds.amazonaws.com", None, PortScope::PerPort),
            HostnameMatch::Allowed
        );
        assert_eq!(
            hostname_match_for_caller(&rules, "other.example.com", None, PortScope::PerPort),
            HostnameMatch::Unmatched
        );
    }

    #[test]
    fn match_route_wildcard_domain() {
        let routes = parse_routes(
            r#"[{"match": "*.internal.co", "verdict": "allow", "transport": "direct"}]"#,
        )
        .unwrap();
        assert_eq!(
            match_route(
                &routes,
                "svc.internal.co:443",
                Scheme::Https,
                Verdict::Allow,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Allow,
                transport: Transport::Direct,
                tls_terminate: false,
            }
        );
        assert_eq!(
            match_route(
                &routes,
                "internal.co:443",
                Scheme::Https,
                Verdict::Allow,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Allow,
                transport: Transport::Direct,
                tls_terminate: false,
            }
        );
        assert_eq!(
            match_route(
                &routes,
                "evil.co:443",
                Scheme::Https,
                Verdict::Allow,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Allow,
                transport: Transport::Upstream,
                tls_terminate: false,
            }
        );
    }

    #[test]
    fn domain_matches_catch_all() {
        // Bare `*` matches any hostname — the catch-all "all internet" pattern.
        assert!(domain_matches("*", "github.com"));
        assert!(domain_matches("*", "a.b.c.example.com"));
        assert!(domain_matches("*", "1.2.3.4"));
        // Case-insensitive like every other pattern.
        assert!(domain_matches("*", "EXAMPLE.com"));
        // Empty hostname must NOT match — fail closed on malformed input.
        assert!(!domain_matches("*", ""));
    }

    #[test]
    fn match_route_catch_all_allows_everything() {
        let routes =
            parse_routes(r#"[{"match": "*", "verdict": "allow", "transport": "upstream"}]"#)
                .unwrap();
        for host in ["github.com:443", "anything.example.org:443", "1.2.3.4:443"] {
            assert_eq!(
                match_route(
                    &routes,
                    host,
                    Scheme::Https,
                    Verdict::Deny,
                    Transport::Upstream
                ),
                MatchedRoute {
                    verdict: Verdict::Allow,
                    transport: Transport::Upstream,
                    tls_terminate: false,
                },
                "host {host} should be allowed by catch-all",
            );
        }
    }

    #[test]
    fn match_route_deny_carveout_before_catch_all() {
        // First-match-wins: a `deny` listed before `allow *` wins for its host,
        // everything else falls through to the catch-all allow.
        let routes = parse_routes(
            r#"[
                {"match": "evil.com", "verdict": "deny", "transport": "upstream"},
                {"match": "*", "verdict": "allow", "transport": "upstream"}
            ]"#,
        )
        .unwrap();
        assert_eq!(
            match_route(
                &routes,
                "evil.com:443",
                Scheme::Https,
                Verdict::Deny,
                Transport::Upstream
            )
            .verdict,
            Verdict::Deny,
        );
        assert_eq!(
            match_route(
                &routes,
                "good.com:443",
                Scheme::Https,
                Verdict::Deny,
                Transport::Upstream
            )
            .verdict,
            Verdict::Allow,
        );
    }

    #[test]
    fn hostname_match_distinguishes_unmatched_allowed_denied() {
        let allow = parse_routes(
            r#"[{"match": "ok.example", "verdict": "allow", "transport": "upstream"}]"#,
        )
        .unwrap();
        let deny = parse_routes(
            r#"[{"match": "evil.example", "verdict": "deny", "transport": "upstream"}]"#,
        )
        .unwrap();
        assert_eq!(hostname_match(&[], "ok.example"), HostnameMatch::Unmatched);
        assert_eq!(hostname_match(&allow, "ok.example"), HostnameMatch::Allowed);
        assert_eq!(hostname_match(&deny, "evil.example"), HostnameMatch::Denied);
        // A name no rule covers is Unmatched, not Denied — the gate fallback
        // distinguishes these.
        assert_eq!(
            hostname_match(&deny, "other.example"),
            HostnameMatch::Unmatched
        );
    }

    #[test]
    fn hostname_match_first_match_deny_beats_later_allow() {
        let routes = parse_routes(
            r#"[
                {"match": "evil.example.com", "verdict": "deny", "transport": "upstream"},
                {"match": "*.example.com", "verdict": "allow", "transport": "upstream"}
            ]"#,
        )
        .unwrap();
        assert_eq!(
            hostname_match(&routes, "evil.example.com"),
            HostnameMatch::Denied
        );
        assert_eq!(
            hostname_match(&routes, "good.example.com"),
            HostnameMatch::Allowed
        );
    }

    #[test]
    fn domain_matches_mid_wildcard() {
        assert!(domain_matches(
            "bedrock-runtime.*.amazonaws.com",
            "bedrock-runtime.us-east-1.amazonaws.com"
        ));
        assert!(domain_matches(
            "bedrock-runtime.*.amazonaws.com",
            "bedrock-runtime.eu-west-1.amazonaws.com"
        ));
        assert!(!domain_matches(
            "bedrock-runtime.*.amazonaws.com",
            "s3.us-east-1.amazonaws.com"
        ));
        assert!(!domain_matches(
            "bedrock-runtime.*.amazonaws.com",
            "amazonaws.com"
        ));
        // Must not over-match when dot separator is missing
        assert!(!domain_matches(
            "bedrock-runtime.*.amazonaws.com",
            "bedrock-runtime.us-east-1amazonaws.com"
        ));
    }

    #[test]
    fn injection_matches_hostname_only_pattern() {
        // Pattern without port matches by hostname (port on target is ignored)
        assert!(injection_matches(
            "lens.example.com",
            "lens.example.com:443"
        ));
        assert!(injection_matches(
            "lens.example.com",
            "lens.example.com:8443"
        ));
        assert!(!injection_matches(
            "lens.example.com",
            "evil.example.com:443"
        ));
    }

    #[test]
    fn injection_matches_port_specific_pattern() {
        // Pattern with port requires exact host:port match (prevents token leaks
        // to other services on the same host)
        assert!(injection_matches(
            "lens.example.com:8443",
            "lens.example.com:8443"
        ));
        assert!(!injection_matches(
            "lens.example.com:8443",
            "lens.example.com:9999"
        ));
        assert!(!injection_matches(
            "lens.example.com:8443",
            "lens.example.com:443"
        ));
        assert!(!injection_matches(
            "lens.example.com:8443",
            "evil.example.com:8443"
        ));
    }

    #[test]
    fn injection_matches_wildcard_pattern() {
        // Wildcard patterns match by hostname regardless of target port
        assert!(injection_matches(
            "bedrock-runtime.*.amazonaws.com",
            "bedrock-runtime.us-east-1.amazonaws.com:443"
        ));
        assert!(injection_matches("*.example.com", "api.example.com:8443"));
        assert!(!injection_matches("*.example.com", "evil.com:443"));
    }

    #[test]
    fn match_route_exact_domain() {
        let routes = parse_routes(
            r#"[{"match": "api.github.com", "verdict": "deny", "transport": "upstream"}]"#,
        )
        .unwrap();
        assert_eq!(
            match_route(
                &routes,
                "api.github.com:443",
                Scheme::Https,
                Verdict::Allow,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Deny,
                transport: Transport::Upstream,
                tls_terminate: false,
            }
        );
        assert_eq!(
            match_route(
                &routes,
                "github.com:443",
                Scheme::Https,
                Verdict::Allow,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Allow,
                transport: Transport::Upstream,
                tls_terminate: false,
            }
        );
    }

    #[test]
    fn match_route_default_lens_sandbox() {
        let routes = parse_routes("[]").unwrap();
        assert_eq!(
            match_route(
                &routes,
                "anything.com:443",
                Scheme::Https,
                Verdict::Allow,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Allow,
                transport: Transport::Upstream,
                tls_terminate: false,
            }
        );
    }

    #[test]
    fn match_route_default_deny() {
        let routes = parse_routes("[]").unwrap();
        assert_eq!(
            match_route(
                &routes,
                "anything.com:443",
                Scheme::Https,
                Verdict::Deny,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Deny,
                transport: Transport::Upstream,
                tls_terminate: false,
            }
        );
    }

    #[test]
    fn match_route_deny_default_with_allowed_route() {
        let routes = parse_routes(
            r#"[{"match": "github.com", "verdict": "allow", "transport": "upstream"}]"#,
        )
        .unwrap();
        assert_eq!(
            match_route(
                &routes,
                "github.com:443",
                Scheme::Https,
                Verdict::Deny,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Allow,
                transport: Transport::Upstream,
                tls_terminate: false,
            }
        );
        assert_eq!(
            match_route(
                &routes,
                "evil.com:443",
                Scheme::Https,
                Verdict::Deny,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Deny,
                transport: Transport::Upstream,
                tls_terminate: false,
            }
        );
    }

    #[test]
    fn match_route_case_insensitive() {
        let routes = parse_routes(
            r#"[{"match": "API.GitHub.COM", "verdict": "deny", "transport": "upstream"}]"#,
        )
        .unwrap();
        assert_eq!(
            match_route(
                &routes,
                "api.github.com:443",
                Scheme::Https,
                Verdict::Allow,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Deny,
                transport: Transport::Upstream,
                tls_terminate: false,
            }
        );
        // Hostname in CONNECT line can also be mixed case
        assert_eq!(
            match_route(
                &routes,
                "Api.GitHub.Com:443",
                Scheme::Https,
                Verdict::Allow,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Deny,
                transport: Transport::Upstream,
                tls_terminate: false,
            }
        );
    }

    #[test]
    fn match_route_wildcard_case_insensitive() {
        let routes = parse_routes(
            r#"[{"match": "*.Internal.Co", "verdict": "allow", "transport": "direct"}]"#,
        )
        .unwrap();
        assert_eq!(
            match_route(
                &routes,
                "SVC.INTERNAL.CO:443",
                Scheme::Https,
                Verdict::Allow,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Allow,
                transport: Transport::Direct,
                tls_terminate: false,
            }
        );
    }

    #[test]
    fn match_route_bracketed_ipv6() {
        let routes = parse_routes(
            r#"[{"match": "2001:db8::/32", "verdict": "allow", "transport": "direct"}]"#,
        )
        .unwrap();
        assert_eq!(
            match_route(
                &routes,
                "[2001:db8::1]:443",
                Scheme::Https,
                Verdict::Allow,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Allow,
                transport: Transport::Direct,
                tls_terminate: false,
            }
        );
        assert_eq!(
            match_route(
                &routes,
                "[::1]:443",
                Scheme::Https,
                Verdict::Allow,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Allow,
                transport: Transport::Upstream,
                tls_terminate: false,
            }
        );
    }

    #[test]
    fn parse_host_port_rule() {
        let routes =
            parse_routes(r#"[{"match": "host.docker.internal:6443", "verdict": "allow", "transport": "direct"}]"#)
                .unwrap();
        assert_eq!(routes.len(), 1);
        assert!(matches!(
            &routes[0].matcher,
            RouteMatcher::HostPort(h, 6443) if h == "host.docker.internal"
        ));
    }

    #[test]
    fn match_host_port_exact() {
        let routes =
            parse_routes(r#"[{"match": "host.docker.internal:6443", "verdict": "allow", "transport": "direct"}]"#)
                .unwrap();
        assert_eq!(
            match_route(
                &routes,
                "host.docker.internal:6443",
                Scheme::Https,
                Verdict::Deny,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Allow,
                transport: Transport::Direct,
                tls_terminate: false,
            }
        );
        // Different port does NOT match
        assert_eq!(
            match_route(
                &routes,
                "host.docker.internal:8080",
                Scheme::Https,
                Verdict::Deny,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Deny,
                transport: Transport::Upstream,
                tls_terminate: false,
            }
        );
    }

    #[test]
    fn parse_bracketed_ipv6_host_port() {
        let routes =
            parse_routes(r#"[{"match": "[::1]:6443", "verdict": "allow", "transport": "direct"}]"#)
                .unwrap();
        assert_eq!(routes.len(), 1);
        assert!(matches!(
            &routes[0].matcher,
            RouteMatcher::HostPort(h, 6443) if h == "::1"
        ));
    }

    #[test]
    fn reject_raw_ipv6_without_brackets() {
        let result =
            parse_routes(r#"[{"match": "::1:6443", "verdict": "allow", "transport": "direct"}]"#);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("ambiguous IPv6"));
    }

    #[test]
    fn match_host_port_case_insensitive() {
        let routes =
            parse_routes(r#"[{"match": "Host.Docker.Internal:6443", "verdict": "allow", "transport": "direct"}]"#)
                .unwrap();
        assert_eq!(
            match_route(
                &routes,
                "host.docker.internal:6443",
                Scheme::Https,
                Verdict::Deny,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Allow,
                transport: Transport::Direct,
                tls_terminate: false,
            }
        );
    }

    #[test]
    fn parse_route_with_forward_config() {
        let json = r#"[{
            "match": "host.docker.internal:6443",
            "verdict": "allow", "transport": "direct",
            "forward": {
                "dialAddr": "host.docker.internal:6443",
                "tlsServerName": "127.0.0.1",
                "upstreamHostHeader": "127.0.0.1:6443",
                "certPem": "test-cert",
                "keyPem": "test-key",
                "caPem": "test-ca"
            }
        }]"#;
        let val: serde_json::Value = serde_json::from_str(json).unwrap();
        let parsed = parse_proxy_routes(&val).unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(matches!(
            &parsed[0].rule.matcher,
            RouteMatcher::HostPort(h, 6443) if h == "host.docker.internal"
        ));
        assert_eq!(parsed[0].rule.verdict, Verdict::Allow);
        assert_eq!(parsed[0].rule.transport, Transport::Direct);
        let fwd = parsed[0]
            .forward
            .as_ref()
            .expect("forward config should be present");
        assert_eq!(fwd.dial_addr, "host.docker.internal:6443");
        assert_eq!(fwd.tls_server_name, "127.0.0.1");
        assert_eq!(fwd.upstream_host_header.as_deref(), Some("127.0.0.1:6443"));
        assert_eq!(fwd.cert_pem, "test-cert");
        assert_eq!(fwd.key_pem, "test-key");
        assert_eq!(fwd.ca_pem.as_deref(), Some("test-ca"));
    }

    #[test]
    fn parse_route_without_forward_has_none() {
        let json = r#"[{"match": "api.example.com", "verdict": "allow", "transport": "direct"}]"#;
        let val: serde_json::Value = serde_json::from_str(json).unwrap();
        let parsed = parse_proxy_routes(&val).unwrap();
        assert!(parsed[0].forward.is_none());
    }

    // --- scheme filter tests ---

    #[test]
    fn scheme_filter_matches_https_rule_for_https_request() {
        let routes =
            parse_routes(r#"[{"match": "example.com", "verdict": "allow", "transport": "upstream", "scheme": "https"}]"#)
                .unwrap();
        assert_eq!(
            match_route(
                &routes,
                "example.com:443",
                Scheme::Https,
                Verdict::Deny,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Allow,
                transport: Transport::Upstream,
                tls_terminate: false,
            }
        );
    }

    #[test]
    fn scheme_filter_skips_https_rule_for_http_request() {
        // https-only rule must not match an http request — falls through to default.
        let routes =
            parse_routes(r#"[{"match": "example.com", "verdict": "allow", "transport": "upstream", "scheme": "https"}]"#)
                .unwrap();
        assert_eq!(
            match_route(
                &routes,
                "example.com:80",
                Scheme::Http,
                Verdict::Deny,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Deny,
                transport: Transport::Upstream,
                tls_terminate: false,
            }
        );
    }

    #[test]
    fn scheme_filter_skips_http_rule_for_https_request() {
        let routes =
            parse_routes(r#"[{"match": "example.com", "verdict": "allow", "transport": "upstream", "scheme": "http"}]"#)
                .unwrap();
        assert_eq!(
            match_route(
                &routes,
                "example.com:443",
                Scheme::Https,
                Verdict::Deny,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Deny,
                transport: Transport::Upstream,
                tls_terminate: false,
            }
        );
    }

    #[test]
    fn no_scheme_filter_matches_both_schemes() {
        let routes = parse_routes(
            r#"[{"match": "example.com", "verdict": "allow", "transport": "upstream"}]"#,
        )
        .unwrap();
        let matched_https = match_route(
            &routes,
            "example.com:443",
            Scheme::Https,
            Verdict::Deny,
            Transport::Upstream,
        );
        assert_eq!(matched_https.verdict, Verdict::Allow);
        assert_eq!(matched_https.transport, Transport::Upstream);
        let matched_http = match_route(
            &routes,
            "example.com:80",
            Scheme::Http,
            Verdict::Deny,
            Transport::Upstream,
        );
        assert_eq!(matched_http.verdict, Verdict::Allow);
        assert_eq!(matched_http.transport, Transport::Upstream);
    }

    #[test]
    fn scheme_filter_allows_https_deny_http_same_host() {
        // Express "allow https://example.com but deny http://example.com"
        // via two scheme-scoped rules — the classic motivating use case.
        let routes = parse_routes(
            r#"[
                {"match": "example.com", "verdict": "allow", "transport": "upstream", "scheme": "https"},
                {"match": "example.com", "verdict": "deny", "transport": "upstream", "scheme": "http"}
            ]"#,
        )
        .unwrap();
        let https = match_route(
            &routes,
            "example.com:443",
            Scheme::Https,
            Verdict::Deny,
            Transport::Upstream,
        );
        assert_eq!(https.verdict, Verdict::Allow);
        assert_eq!(https.transport, Transport::Upstream);
        let http = match_route(
            &routes,
            "example.com:80",
            Scheme::Http,
            Verdict::Deny,
            Transport::Upstream,
        );
        assert_eq!(http.verdict, Verdict::Deny);
    }

    #[test]
    fn scheme_filter_rejects_invalid_value() {
        let err = parse_routes(r#"[{"match": "example.com", "verdict": "allow", "transport": "upstream", "scheme": "ftp"}]"#)
            .unwrap_err();
        assert!(err.contains("scheme") || err.contains("ftp"), "got: {err}");
    }

    #[test]
    fn scheme_filter_composes_with_wildcard_domain() {
        // Scheme filter must apply after wildcard domain matching, so an http-only
        // rule for `*.example.com` still lets https subdomain requests fall through.
        let routes =
            parse_routes(r#"[{"match": "*.example.com", "verdict": "allow", "transport": "upstream", "scheme": "http"}]"#)
                .unwrap();
        let http = match_route(
            &routes,
            "api.example.com:80",
            Scheme::Http,
            Verdict::Deny,
            Transport::Upstream,
        );
        assert_eq!(http.verdict, Verdict::Allow);
        assert_eq!(http.transport, Transport::Upstream);
        let https = match_route(
            &routes,
            "api.example.com:443",
            Scheme::Https,
            Verdict::Deny,
            Transport::Upstream,
        );
        assert_eq!(https.verdict, Verdict::Deny);
        // Also verify a non-matching subdomain still misses regardless of scheme.
        let other = match_route(
            &routes,
            "other.com:80",
            Scheme::Http,
            Verdict::Deny,
            Transport::Upstream,
        );
        assert_eq!(other.verdict, Verdict::Deny);
    }

    #[test]
    fn scheme_filter_composes_with_cidr() {
        // Scheme filter must apply after CIDR matching.
        let routes =
            parse_routes(r#"[{"match": "10.0.0.0/8", "verdict": "allow", "transport": "direct", "scheme": "https"}]"#)
                .unwrap();
        let https = match_route(
            &routes,
            "10.1.2.3:443",
            Scheme::Https,
            Verdict::Deny,
            Transport::Upstream,
        );
        assert_eq!(https.verdict, Verdict::Allow);
        assert_eq!(https.transport, Transport::Direct);
        let http = match_route(
            &routes,
            "10.1.2.3:80",
            Scheme::Http,
            Verdict::Deny,
            Transport::Upstream,
        );
        assert_eq!(http.verdict, Verdict::Deny);
    }

    #[test]
    fn cidr_not_confused_with_host_port() {
        // "10.0.0.0/8" should still parse as CIDR, not host:port
        let routes =
            parse_routes(r#"[{"match": "10.0.0.0/8", "verdict": "allow", "transport": "direct"}]"#)
                .unwrap();
        assert!(matches!(routes[0].matcher, RouteMatcher::Cidr(_)));
        assert_eq!(
            match_route(
                &routes,
                "10.1.2.3:443",
                Scheme::Https,
                Verdict::Deny,
                Transport::Upstream
            ),
            MatchedRoute {
                verdict: Verdict::Allow,
                transport: Transport::Direct,
                tls_terminate: false,
            }
        );
    }

    // --- HTTP rule tests ---

    #[test]
    fn path_glob_exact_match() {
        assert!(path_glob_matches("/api/v1/download", "/api/v1/download"));
        assert!(!path_glob_matches("/api/v1/download", "/api/v1/upload"));
    }

    #[test]
    fn path_glob_trailing_star() {
        assert!(path_glob_matches("/api/v1/*", "/api/v1/download"));
        assert!(path_glob_matches("/api/v1/*", "/api/v1/users"));
        assert!(!path_glob_matches("/api/v1/*", "/api/v1/users/123"));
        assert!(!path_glob_matches("/api/v1/*", "/api/v2/download"));
    }

    #[test]
    fn path_glob_double_star() {
        assert!(path_glob_matches("/api/**", "/api/v1/users/123"));
        assert!(path_glob_matches("/api/**", "/api/v1"));
        assert!(path_glob_matches("/api/**", "/api"));
        assert!(!path_glob_matches("/api/**", "/other/v1"));
    }

    #[test]
    fn path_glob_wildcard_all() {
        assert!(path_glob_matches("*", "/anything"));
        assert!(path_glob_matches("**", "/anything/at/all"));
    }

    #[test]
    fn path_glob_middle_wildcard() {
        // Single wildcard in middle of pattern
        assert!(path_glob_matches(
            "/v1/projects/*/llm/*",
            "/v1/projects/123/llm/anthropic"
        ));
        assert!(path_glob_matches(
            "/v1/projects/*/llm/*",
            "/v1/projects/abc-def/llm/bedrock"
        ));
        assert!(!path_glob_matches(
            "/v1/projects/*/llm/*",
            "/v1/projects/123/other/anthropic"
        ));
        assert!(!path_glob_matches(
            "/v1/projects/*/llm/*",
            "/v1/clusters/123/proxy/api"
        ));

        // Double-star after middle wildcard
        assert!(path_glob_matches(
            "/v1/projects/*/llm/**",
            "/v1/projects/123/llm/bedrock/us-east-1/invoke"
        ));
        assert!(path_glob_matches(
            "/v1/projects/*/llm/**",
            "/v1/projects/123/llm/anthropic"
        ));
        assert!(!path_glob_matches(
            "/v1/projects/*/llm/**",
            "/v1/clusters/abc/proxy/api"
        ));
    }

    #[test]
    fn parse_routes_with_http_rules() {
        let json = r#"[{
            "match": "api.example.com",
            "verdict": "allow", "transport": "upstream",
            "rules": [
                {"method": "GET", "path": "/api/v1/*"},
                {"path": "/health"}
            ]
        }]"#;
        let routes = parse_routes(json).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].http_rules.len(), 2);
        assert_eq!(routes[0].http_rules[0].method.as_deref(), Some("GET"));
        assert_eq!(routes[0].http_rules[0].path.as_deref(), Some("/api/v1/*"));
        assert_eq!(routes[0].http_rules[1].method, None);
        assert_eq!(routes[0].http_rules[1].path.as_deref(), Some("/health"));
    }

    #[test]
    fn parse_routes_without_http_rules_is_empty() {
        let json = r#"[{"match": "github.com", "verdict": "allow", "transport": "direct"}]"#;
        let routes = parse_routes(json).unwrap();
        assert!(routes[0].http_rules.is_empty());
    }

    #[test]
    fn http_rules_empty_allows_all() {
        assert!(allows(&[], "GET", "/anything"));
        assert!(allows(&[], "POST", "/anything"));
    }

    #[test]
    fn http_rules_method_match() {
        let rules = vec![HttpRule {
            method: Some("GET".to_string()),
            path: None,
            graphql: None,
        }];
        assert!(allows(&rules, "GET", "/foo"));
        assert!(allows(&rules, "get", "/foo"));
        assert!(!allows(&rules, "POST", "/foo"));
    }

    #[test]
    fn http_rules_path_match() {
        let rules = vec![HttpRule {
            method: None,
            path: Some("/api/v1/*".to_string()),
            graphql: None,
        }];
        assert!(allows(&rules, "GET", "/api/v1/download"));
        assert!(allows(&rules, "POST", "/api/v1/upload"));
        assert!(!allows(&rules, "GET", "/api/v2/download"));
    }

    #[test]
    fn http_rules_method_and_path() {
        let rules = vec![HttpRule {
            method: Some("GET".to_string()),
            path: Some("/api/v1/*".to_string()),
            graphql: None,
        }];
        assert!(allows(&rules, "GET", "/api/v1/download"));
        assert!(!allows(&rules, "POST", "/api/v1/download"));
        assert!(!allows(&rules, "GET", "/api/v2/download"));
    }

    #[test]
    fn http_rules_multiple_rules_any_match() {
        let rules = vec![
            HttpRule {
                method: Some("GET".to_string()),
                path: Some("/api/v1/*".to_string()),
                graphql: None,
            },
            HttpRule {
                method: Some("POST".to_string()),
                path: Some("/api/v1/upload".to_string()),
                graphql: None,
            },
        ];
        assert!(allows(&rules, "GET", "/api/v1/download"));
        assert!(allows(&rules, "POST", "/api/v1/upload"));
        assert!(!allows(&rules, "DELETE", "/api/v1/download"));
        assert!(!allows(&rules, "POST", "/api/v1/download"));
    }

    #[test]
    fn normalize_path_resolves_dotdot() {
        assert_eq!(normalize_path("/api/v1/../../admin"), "/admin");
        assert_eq!(normalize_path("/api/../api/v1"), "/api/v1");
    }

    #[test]
    fn normalize_path_collapses_double_slashes() {
        assert_eq!(normalize_path("/api//v1//users"), "/api/v1/users");
        assert_eq!(normalize_path("//api/v1/"), "/api/v1");
    }

    #[test]
    fn normalize_path_handles_edge_cases() {
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("/.."), "/");
        assert_eq!(normalize_path("/api/v1/"), "/api/v1");
        assert_eq!(normalize_path("/./api/./v1"), "/api/v1");
    }

    #[test]
    fn http_rules_wildcard_method() {
        let rules = vec![HttpRule {
            method: Some("*".to_string()),
            path: Some("/health".to_string()),
            graphql: None,
        }];
        assert!(allows(&rules, "GET", "/health"));
        assert!(allows(&rules, "POST", "/health"));
        assert!(!allows(&rules, "GET", "/other"));
    }

    #[test]
    fn path_glob_single_star_trailing_slash() {
        // /api/v1/* requires at least the prefix "/api/v1/"
        // Trailing slash (empty segment) matches, bare path without slash does not
        assert!(path_glob_matches("/api/v1/*", "/api/v1/foo"));
        assert!(path_glob_matches("/api/v1/*", "/api/v1/"));
        assert!(!path_glob_matches("/api/v1/*", "/api/v1"));
    }

    #[test]
    fn normalize_path_decodes_percent_encoded_separators() {
        assert_eq!(normalize_path("/api/%2e%2e/admin"), "/admin");
        assert_eq!(normalize_path("/api/v1/%2F/secret"), "/api/v1/secret");
        // Uppercase hex decodes identically.
        assert_eq!(normalize_path("/api/%2E%2E/admin"), "/admin");
        assert_eq!(normalize_path("/api/v1/%2F/secret"), "/api/v1/secret");
    }

    #[test]
    fn normalize_path_decodes_double_encoded() {
        assert_eq!(normalize_path("/api/%252e%252e/admin"), "/admin");
        // Encoded backslash traversal resolves through the / fold.
        assert_eq!(normalize_path("/api/%2e%2e%5cadmin"), "/admin");
    }

    #[test]
    fn normalize_path_leaves_malformed_and_non_separator_encoding_intact() {
        assert_eq!(normalize_path("/api/%zz/v1"), "/api/%zz/v1");
        assert_eq!(normalize_path("/normal/path"), "/normal/path");
        // %20 (space) is not a separator and must stay encoded.
        assert_eq!(normalize_path("/api/%20/v1"), "/api/%20/v1");
    }

    #[test]
    fn http_rules_reject_percent_encoded_traversal() {
        let rules = vec![HttpRule {
            method: None,
            path: Some("/repos/**".to_string()),
            graphql: None,
        }];
        assert!(allows(&rules, "GET", &normalize_path("/repos/v1/list")));
        assert!(!allows(
            &rules,
            "GET",
            &normalize_path("/repos/%2e%2e/admin")
        ));
    }

    #[test]
    fn decode_path_separators_handles_each_case() {
        assert_eq!(decode_path_separators("/a/%2e%2e/b"), "/a/../b");
        assert_eq!(decode_path_separators("/a/%252e%252e/b"), "/a/../b");
        assert_eq!(decode_path_separators("/a/%2E%2F%5Cb"), "/a/.//b");
        assert_eq!(decode_path_separators("/a/%zz/b"), "/a/%zz/b");
        assert_eq!(decode_path_separators("/a/%20/b"), "/a/%20/b");
        assert_eq!(decode_path_separators("/a\\b"), "/a/b");
    }

    #[test]
    fn decode_separators_does_not_consume_across_a_bare_percent() {
        // A `%` that is not followed by two hex digits must be emitted
        // literally and advance by ONE, so it can't swallow the `%` of a
        // following encoded separator. Consuming two chars unconditionally
        // would leave the inner `%2f`/`%2e` undecoded here while a lenient
        // origin still decoded it — exactly the matcher/origin desync the
        // allowlist relies on not happening.
        assert_eq!(decode_path_separators("/a/%%2f/b"), "/a/%//b");
        assert_eq!(decode_path_separators("/a/%%2e%2e/b"), "/a/%../b");
        // Incomplete / non-hex sequences pass through unchanged.
        assert_eq!(decode_path_separators("/a/%"), "/a/%");
        assert_eq!(decode_path_separators("/a/%2"), "/a/%2");
        assert_eq!(decode_path_separators("/a/%2g/b"), "/a/%2g/b");
        assert_eq!(decode_path_separators("/a/%g2/b"), "/a/%g2/b");
    }

    #[test]
    fn find_matching_route_uses_first_match_rules() {
        // Exact domain rule (GET /api/v1/* only) listed before wildcard (any method, any path).
        // find_matching_route should return the first match's rules, not union them.
        let json = r#"[
            {
                "match": "api.github.com",
                "verdict": "allow", "transport": "upstream",
                "rules": [{"method": "GET", "path": "/api/v1/*"}]
            },
            {
                "match": "*.github.com",
                "verdict": "allow", "transport": "upstream",
                "rules": [{"method": "POST", "path": "/api/v1/upload"}]
            }
        ]"#;
        let val: serde_json::Value = serde_json::from_str(json).unwrap();
        let parsed = parse_proxy_routes(&val).unwrap();
        let routes: Vec<RouteRule> = parsed.into_iter().map(|p| p.rule).collect();

        let matched = match find_matching_route(&routes, "api.github.com:443", Scheme::Https, None)
        {
            RouteOutcome::Matched(rule) => rule,
            other => panic!("expected Matched, got {other:?}"),
        };
        // Should get the exact match's rules (GET /api/v1/*), not the wildcard's
        assert_eq!(matched.http_rules.len(), 1);
        assert_eq!(matched.http_rules[0].method.as_deref(), Some("GET"));
        assert_eq!(matched.http_rules[0].path.as_deref(), Some("/api/v1/*"));

        // POST /api/v1/upload should be denied by the exact match's rules
        assert!(!allows(&matched.http_rules, "POST", "/api/v1/upload"));
        // GET /api/v1/repos should be allowed
        assert!(allows(&matched.http_rules, "GET", "/api/v1/repos"));
    }

    // --- binaries filter ---

    fn routes_from(json: &str) -> Vec<RouteRule> {
        let val: serde_json::Value = serde_json::from_str(json).unwrap();
        parse_proxy_routes(&val)
            .unwrap()
            .into_iter()
            .map(|p| p.rule)
            .collect()
    }

    fn caller(exe: &str, ancestors: &[&str]) -> crate::peer_process::PeerProcess {
        crate::peer_process::PeerProcess {
            pid: 1234,
            name: exe.rsplit('/').next().unwrap_or(exe).to_string(),
            exe: Some(exe.into()),
            ancestors: ancestors.iter().map(Into::into).collect(),
        }
    }

    #[test]
    fn binaries_absent_matches_any_caller() {
        let routes = routes_from(
            r#"[{"match": "api.github.com", "verdict": "allow", "transport": "direct"}]"#,
        );
        let c = caller("/usr/bin/curl", &[]);
        assert!(matches!(
            find_matching_route(&routes, "api.github.com:443", Scheme::Https, Some(&c)),
            RouteOutcome::Matched(_)
        ));
    }

    #[test]
    fn binaries_filter_matches_exe() {
        let routes = routes_from(
            r#"[{"match": "api.github.com", "verdict": "allow", "transport": "direct",
                 "binaries": ["/usr/bin/curl"]}]"#,
        );
        let c = caller("/usr/bin/curl", &["/usr/bin/bash"]);
        assert!(matches!(
            find_matching_route(&routes, "api.github.com:443", Scheme::Https, Some(&c)),
            RouteOutcome::Matched(_)
        ));
    }

    #[test]
    fn binaries_filter_matches_ancestor() {
        // claude spawns node which opens the socket; the rule names claude.
        let routes = routes_from(
            r#"[{"match": "api.github.com", "verdict": "allow", "transport": "direct",
                 "binaries": ["/usr/local/bin/claude"]}]"#,
        );
        let c = caller("/usr/bin/node", &["/usr/local/bin/claude", "/usr/bin/bash"]);
        assert!(matches!(
            find_matching_route(&routes, "api.github.com:443", Scheme::Https, Some(&c)),
            RouteOutcome::Matched(_)
        ));
    }

    #[test]
    fn binaries_filter_excludes_unrelated_caller() {
        let routes = routes_from(
            r#"[{"match": "api.github.com", "verdict": "allow", "transport": "direct",
                 "binaries": ["/usr/bin/curl"]}]"#,
        );
        let c = caller("/usr/bin/wget", &["/usr/bin/bash"]);
        assert!(matches!(
            find_matching_route(&routes, "api.github.com:443", Scheme::Https, Some(&c)),
            RouteOutcome::NoMatch {
                binary_filtered: true
            }
        ));
    }

    #[test]
    fn binaries_filter_fails_closed_without_caller() {
        // No resolved caller (non-Linux, closed socket, /proc failure): a
        // binary-filtered rule must not match.
        let routes = routes_from(
            r#"[{"match": "api.github.com", "verdict": "allow", "transport": "direct",
                 "binaries": ["/usr/bin/curl"]}]"#,
        );
        assert!(matches!(
            find_matching_route(&routes, "api.github.com:443", Scheme::Https, None),
            RouteOutcome::NoMatch {
                binary_filtered: true
            }
        ));
    }

    #[test]
    fn binaries_filter_falls_through_to_a_later_rule() {
        // First rule restricts to curl; a wget caller skips it and matches the
        // later wildcard deny — first-match semantics still hold.
        let routes = routes_from(
            r#"[
                {"match": "api.github.com", "verdict": "allow", "transport": "direct",
                 "binaries": ["/usr/bin/curl"]},
                {"match": "*.github.com", "verdict": "deny", "transport": "direct"}
            ]"#,
        );
        let c = caller("/usr/bin/wget", &[]);
        match find_matching_route(&routes, "api.github.com:443", Scheme::Https, Some(&c)) {
            RouteOutcome::Matched(rule) => assert_eq!(rule.verdict, Verdict::Deny),
            other => panic!("expected Matched(deny), got {other:?}"),
        }
    }

    #[test]
    fn a_later_unrestricted_allow_does_not_reopen_a_binary_scoped_host() {
        // The narrow rule scopes registry.npmjs.org to npm; the broad wildcard
        // allow must NOT let an excluded caller back in.
        let routes = routes_from(
            r#"[
                {"match": "registry.npmjs.org", "verdict": "allow", "transport": "direct",
                 "binaries": ["/usr/local/bin/npm"]},
                {"match": "*.npmjs.org", "verdict": "allow", "transport": "direct"}
            ]"#,
        );
        let curl = caller("/usr/bin/curl", &[]);
        assert!(matches!(
            find_matching_route(
                &routes,
                "registry.npmjs.org:443",
                Scheme::Https,
                Some(&curl)
            ),
            RouteOutcome::NoMatch {
                binary_filtered: true
            }
        ));
        // The listed binary still matches its own rule.
        let npm = caller("/usr/local/bin/npm", &[]);
        match find_matching_route(&routes, "registry.npmjs.org:443", Scheme::Https, Some(&npm)) {
            RouteOutcome::Matched(rule) => assert_eq!(rule.verdict, Verdict::Allow),
            other => panic!("expected Matched(allow), got {other:?}"),
        }
    }

    #[test]
    fn a_later_unrestricted_ask_does_not_reopen_a_binary_scoped_host() {
        // A binary-scoped allow restricts the host; a later unrestricted `ask`
        // does not give the excluded caller a prompt — it fails closed.
        let routes = routes_from(
            r#"[
                {"match": "registry.npmjs.org", "verdict": "allow", "transport": "direct",
                 "binaries": ["/usr/local/bin/npm"]},
                {"match": "*.npmjs.org", "verdict": "ask", "transport": "direct"}
            ]"#,
        );
        let curl = caller("/usr/bin/curl", &[]);
        assert!(matches!(
            find_matching_route(
                &routes,
                "registry.npmjs.org:443",
                Scheme::Https,
                Some(&curl)
            ),
            RouteOutcome::NoMatch {
                binary_filtered: true
            }
        ));
    }

    #[test]
    fn a_later_binary_scoped_rule_that_lists_the_caller_still_matches() {
        // Two binary-scoped rules for the same host: an excluded-from-the-first
        // caller can still match the second, but an unlisted caller is denied.
        let routes = routes_from(
            r#"[
                {"match": "api.github.com", "verdict": "allow", "transport": "direct",
                 "binaries": ["/usr/bin/git"]},
                {"match": "api.github.com", "verdict": "allow", "transport": "direct",
                 "binaries": ["/usr/bin/gh"]}
            ]"#,
        );
        let gh = caller("/usr/bin/gh", &[]);
        match find_matching_route(&routes, "api.github.com:443", Scheme::Https, Some(&gh)) {
            RouteOutcome::Matched(rule) => {
                assert_eq!(
                    rule.binaries.as_deref().unwrap(),
                    [PathBuf::from("/usr/bin/gh")]
                );
            }
            other => panic!("expected Matched(gh rule), got {other:?}"),
        }
        let curl = caller("/usr/bin/curl", &[]);
        assert!(matches!(
            find_matching_route(&routes, "api.github.com:443", Scheme::Https, Some(&curl)),
            RouteOutcome::NoMatch {
                binary_filtered: true
            }
        ));
    }

    #[test]
    fn an_unrestricted_allow_before_a_binary_scoped_rule_still_wins() {
        // First-match order stands: an unrestricted rule placed first admits
        // any caller, even when a binary-scoped rule for the host follows.
        let routes = routes_from(
            r#"[
                {"match": "*.npmjs.org", "verdict": "allow", "transport": "direct"},
                {"match": "registry.npmjs.org", "verdict": "allow", "transport": "direct",
                 "binaries": ["/usr/local/bin/npm"]}
            ]"#,
        );
        let curl = caller("/usr/bin/curl", &[]);
        match find_matching_route(
            &routes,
            "registry.npmjs.org:443",
            Scheme::Https,
            Some(&curl),
        ) {
            RouteOutcome::Matched(rule) => assert!(rule.binaries.is_none()),
            other => panic!("expected Matched(unrestricted), got {other:?}"),
        }
    }

    #[test]
    fn host_miss_reports_binary_filtered_false() {
        let routes = routes_from(
            r#"[{"match": "api.github.com", "verdict": "allow", "transport": "direct",
                 "binaries": ["/usr/bin/curl"]}]"#,
        );
        let c = caller("/usr/bin/curl", &[]);
        assert!(matches!(
            find_matching_route(&routes, "elsewhere.com:443", Scheme::Https, Some(&c)),
            RouteOutcome::NoMatch {
                binary_filtered: false
            }
        ));
    }

    #[test]
    fn an_empty_binaries_filter_is_rejected() {
        // `[]` matches no caller, silently turning an allow into a deny for the
        // host — reject it at parse time instead.
        let val: serde_json::Value = serde_json::from_str(
            r#"[{"match": "api.github.com", "verdict": "allow", "transport": "direct",
                 "binaries": []}]"#,
        )
        .unwrap();
        let err = parse_proxy_routes(&val)
            .err()
            .expect("empty binaries rejected");
        assert!(err.contains("empty"), "unexpected error: {err}");
    }

    #[test]
    fn a_relative_binaries_entry_is_rejected() {
        // A relative path can never equal an absolute /proc/<pid>/exe target.
        let val: serde_json::Value = serde_json::from_str(
            r#"[{"match": "api.github.com", "verdict": "allow", "transport": "direct",
                 "binaries": ["curl"]}]"#,
        )
        .unwrap();
        let err = parse_proxy_routes(&val)
            .err()
            .expect("relative binaries rejected");
        assert!(err.contains("absolute"), "unexpected error: {err}");
    }

    #[test]
    fn binaries_field_parses_into_pathbufs() {
        let routes = routes_from(
            r#"[{"match": "api.github.com", "verdict": "allow", "transport": "direct",
                 "binaries": ["/usr/bin/curl", "/usr/local/bin/claude"]}]"#,
        );
        assert_eq!(
            routes[0].binaries.as_deref(),
            Some(
                [
                    PathBuf::from("/usr/bin/curl"),
                    PathBuf::from("/usr/local/bin/claude"),
                ]
                .as_slice()
            )
        );
    }

    #[test]
    fn hostname_match_for_caller_admits_the_listed_caller() {
        let routes = routes_from(
            r#"[{"match": "api.github.com", "verdict": "allow", "transport": "direct",
                 "binaries": ["/usr/bin/curl"]}]"#,
        );
        let curl = caller("/usr/bin/curl", &[]);
        assert_eq!(
            hostname_match_for_caller(
                &routes,
                "api.github.com",
                Some(&curl),
                PortScope::FirstMatch
            ),
            HostnameMatch::Allowed
        );
    }

    #[test]
    fn hostname_match_for_caller_reports_binary_denied_for_an_excluded_caller() {
        let routes = routes_from(
            r#"[{"match": "api.github.com", "verdict": "allow", "transport": "direct",
                 "binaries": ["/usr/bin/curl"]}]"#,
        );
        let wget = caller("/usr/bin/wget", &[]);
        assert_eq!(
            hostname_match_for_caller(
                &routes,
                "api.github.com",
                Some(&wget),
                PortScope::FirstMatch
            ),
            HostnameMatch::BinaryDenied
        );
        // No caller info fails closed the same way.
        assert_eq!(
            hostname_match_for_caller(&routes, "api.github.com", None, PortScope::FirstMatch),
            HostnameMatch::BinaryDenied
        );
    }

    #[test]
    fn hostname_match_for_caller_does_not_reopen_a_binary_scoped_host() {
        // Mirrors the TCP no-reopen guard at the DNS layer: a later unrestricted
        // allow must not resolve the name for an excluded caller.
        let routes = routes_from(
            r#"[
                {"match": "registry.npmjs.org", "verdict": "allow", "transport": "direct",
                 "binaries": ["/usr/local/bin/npm"]},
                {"match": "*.npmjs.org", "verdict": "allow", "transport": "direct"}
            ]"#,
        );
        let curl = caller("/usr/bin/curl", &[]);
        assert_eq!(
            hostname_match_for_caller(
                &routes,
                "registry.npmjs.org",
                Some(&curl),
                PortScope::FirstMatch
            ),
            HostnameMatch::BinaryDenied
        );
        let npm = caller("/usr/local/bin/npm", &[]);
        assert_eq!(
            hostname_match_for_caller(
                &routes,
                "registry.npmjs.org",
                Some(&npm),
                PortScope::FirstMatch
            ),
            HostnameMatch::Allowed
        );
    }

    #[test]
    fn hostname_match_for_caller_admits_the_listed_binary_over_a_later_deny() {
        // The listed binary must resolve even when a later unrestricted deny
        // covers the broader domain — matching the TCP layer. This is the case
        // a naive "re-resolve only on BinaryDenied" DNS gate would break: the
        // caller-less classification hits the later deny (a plain `Denied`), so
        // the real caller has to be used up front.
        let routes = routes_from(
            r#"[
                {"match": "api.github.com", "verdict": "allow", "transport": "direct",
                 "binaries": ["/usr/bin/git"]},
                {"match": "*.github.com", "verdict": "deny", "transport": "direct"}
            ]"#,
        );
        let git = caller("/usr/bin/git", &[]);
        assert_eq!(
            hostname_match_for_caller(&routes, "api.github.com", Some(&git), PortScope::FirstMatch),
            HostnameMatch::Allowed
        );
        // The excluded binary still falls through to the later deny.
        let curl = caller("/usr/bin/curl", &[]);
        assert_eq!(
            hostname_match_for_caller(
                &routes,
                "api.github.com",
                Some(&curl),
                PortScope::FirstMatch
            ),
            HostnameMatch::Denied
        );
    }

    #[test]
    fn l7_dns_gate_keeps_strict_first_match_for_a_port_scoped_deny() {
        // A later portless allow must not revive a name an earlier port-scoped
        // deny refused, or the denied name leaks to the upstream resolver.
        let routes = routes_from(
            r#"[
                {"match": "api.example.com:443", "verdict": "deny", "transport": "direct"},
                {"match": "*.example.com", "verdict": "allow", "transport": "direct"}
            ]"#,
        );
        assert_eq!(
            hostname_match_for_caller(&routes, "api.example.com", None, PortScope::FirstMatch),
            HostnameMatch::Denied
        );
    }

    #[test]
    fn hostname_match_for_caller_still_honours_a_later_deny() {
        // An explicit deny is never suppressed by the no-reopen guard.
        let routes = routes_from(
            r#"[
                {"match": "api.github.com", "verdict": "allow", "transport": "direct",
                 "binaries": ["/usr/bin/git"]},
                {"match": "*.github.com", "verdict": "deny", "transport": "direct"}
            ]"#,
        );
        let curl = caller("/usr/bin/curl", &[]);
        assert_eq!(
            hostname_match_for_caller(
                &routes,
                "api.github.com",
                Some(&curl),
                PortScope::FirstMatch
            ),
            HostnameMatch::Denied
        );
    }
}
