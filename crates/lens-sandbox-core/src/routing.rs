//! Route rules, hostname/path matching, and HTTP rule evaluation for the
//! sandbox proxy. Parses the policy JSON into `RouteRule`s and resolves a
//! CONNECT target (plus optional HTTP method/path) to an action.

use std::path::PathBuf;

use ipnet::IpNet;

pub use crate::policy_schema::{HttpRule, Scheme, Transport, Verdict};

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub enum RouteMatcher {
    Domain(String),
    Cidr(IpNet),
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

        let matcher = if let Ok(cidr) = raw.match_pattern.parse::<IpNet>() {
            // CIDR check first — avoids false match on IPv6 like "2001:db8::/32"
            RouteMatcher::Cidr(cidr)
        } else if raw.match_pattern.starts_with('[') {
            // Bracketed IPv6 with port: [::1]:6443
            let Some((bracket_part, port_str)) = raw.match_pattern.rsplit_once("]:") else {
                return Err(format!("invalid bracketed address: {}", raw.match_pattern));
            };
            let host = bracket_part.trim_start_matches('[');
            let port: u16 = port_str
                .parse()
                .map_err(|_| format!("invalid port in {}", raw.match_pattern))?;
            RouteMatcher::HostPort(host.to_ascii_lowercase(), port)
        } else if raw.match_pattern.matches(':').count() > 1 {
            // Raw unbracketed IPv6 (multiple colons without brackets) — reject
            return Err(format!(
                "ambiguous IPv6 address without brackets: {}; use [addr]:port notation",
                raw.match_pattern
            ));
        } else if let Some((host, port_str)) = raw.match_pattern.rsplit_once(':') {
            // Single colon — could be host:port
            if let Ok(port) = port_str.parse::<u16>() {
                RouteMatcher::HostPort(host.to_ascii_lowercase(), port)
            } else {
                // Port doesn't parse — treat as domain
                RouteMatcher::Domain(raw.match_pattern)
            }
        } else {
            RouteMatcher::Domain(raw.match_pattern)
        };

        let http_rules = raw
            .rules
            .into_iter()
            .filter_map(|r| {
                // Filter out empty rules — both fields absent is a match-all that
                // would silently bypass deny-by-default semantics.
                if r.method.is_none() && r.path.is_none() {
                    return None;
                }
                Some(HttpRule {
                    method: r.method,
                    path: r.path,
                })
            })
            .collect();

        let binaries = raw
            .binaries
            .map(|paths| paths.into_iter().map(PathBuf::from).collect());

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

/// Match result from `match_route`.
#[derive(Debug, Clone, PartialEq)]
pub struct MatchedRoute {
    pub verdict: Verdict,
    pub transport: Transport,
    pub tls_terminate: bool,
}

/// Return true if any non-Deny route rule covers the given bare hostname.
/// This is the DNS-layer gate: we know the QNAME but not the port or
/// scheme, so we accept a match from any `Domain` rule or from a
/// `HostPort` rule whose host matches (ignoring the port). Subsequent TCP
/// attempts still run through `find_matching_route`, which enforces both
/// port and scheme — this function intentionally errs toward "allow the
/// lookup" to avoid false-NXDOMAIN on names the policy actually permits.
///
/// Explicit `Deny` rules are excluded: forwarding the query upstream for
/// a hostname the policy says to deny would leak that name to the
/// upstream resolver (and any observer there) and let an adversary
/// enumerate the deny list via timing differences between stub-NXDOMAIN
/// and upstream-NXDOMAIN.
///
/// CIDR rules are also ignored: a DNS QNAME is a hostname, not an IP
/// address, so allowing a bare IP literal through the DNS gate would be
/// semantically wrong and would leak CIDR policy to any upstream. IP-based
/// access is still enforced at the TCP layer.
///
/// `Verdict::Ask` rules resolve as allow at the DNS layer. The approval
/// gate fires on the TCP attempt (see `gate::gate_or_deny`); denying DNS
/// here would NXDOMAIN before the gate surfaced any dialog, so the
/// developer would never get the chance to approve. The trade-off is that
/// the QNAME reaches the upstream resolver before the click, accepted as
/// the cost of having an interactive gate at all.
pub fn hostname_allowed(routes: &[RouteRule], hostname: &str) -> bool {
    matches!(hostname_match(routes, hostname), HostnameMatch::Allowed)
}

/// First-match outcome of matching a DNS QNAME against the route table,
/// distinguished so a caller can tell an explicit `Deny`, and a
/// binary-scoped exclusion, apart from "no rule matched" — the DNS stub
/// falls back to its JIT-approved set only on the latter. Matching semantics
/// (`Domain`/`HostPort`, CIDR skipped, `Ask` counts as allowed) are as
/// documented on [`hostname_allowed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostnameMatch {
    /// First admitting rule permits the lookup (its verdict is not `Deny`).
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

pub(crate) fn hostname_match(routes: &[RouteRule], hostname: &str) -> HostnameMatch {
    hostname_match_for_caller(routes, hostname, None)
}

/// [`hostname_match`] with the caller's identity, applying each rule's
/// `binaries` filter through the shared [`caller_admits_rule`] helper so the
/// DNS gate and `find_matching_route` never diverge on binary-scoping (the
/// no-reopen guard included). Passing `None` fails a binary-scoped host closed,
/// exactly as an unresolved caller does at the TCP layer.
pub(crate) fn hostname_match_for_caller(
    routes: &[RouteRule],
    hostname: &str,
    caller: Option<&crate::peer_process::PeerProcess>,
) -> HostnameMatch {
    let lower = hostname.to_ascii_lowercase();
    let mut binary_filtered = false;
    for rule in routes {
        if !qname_matches_rule(rule, &lower) {
            continue;
        }
        if caller_admits_rule(rule, caller, binary_filtered) {
            // First-match semantics (same as `find_matching_route`): a
            // `Deny evil.example.com` before `Allow *.example.com` denies the
            // lookup for `evil.example.com`, even though the wildcard matches.
            return if rule.verdict == Verdict::Deny {
                HostnameMatch::Denied
            } else {
                HostnameMatch::Allowed
            };
        }
        // A binary-scoped rule matched the hostname but excluded the caller (or
        // a later unrestricted rule was suppressed). Remember it so the tail
        // fails closed instead of falling back to the JIT-approved set.
        binary_filtered = true;
    }
    if binary_filtered {
        HostnameMatch::BinaryDenied
    } else {
        HostnameMatch::Unmatched
    }
}

/// Whether `rule`'s matcher covers a bare DNS QNAME. `Domain` and `HostPort`
/// (host part, port ignored) match; `Cidr` never does — a QNAME is a name, not
/// an IP literal (see [`hostname_allowed`]).
fn qname_matches_rule(rule: &RouteRule, lower: &str) -> bool {
    match &rule.matcher {
        RouteMatcher::Domain(pattern) => domain_matches(pattern, lower),
        RouteMatcher::HostPort(pattern_host, _) => domain_matches(pattern_host, lower),
        RouteMatcher::Cidr(_) => false,
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
                .is_ok_and(|ip| cidr.contains(&ip)),
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

/// Check a rule's `binaries` filter against the caller. Returns `true` when the
/// rule has no filter (any caller allowed) or when the caller's exe or an
/// ancestor is one of the listed paths. Returns `false` — fail closed — when
/// the filter is present but caller info is missing.
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

/// Check if an HTTP request matches any of the given rules.
/// Returns true if rules is empty (no restrictions) or any rule matches.
pub fn http_request_matches_rules(rules: &[HttpRule], method: &str, path: &str) -> bool {
    if rules.is_empty() {
        return true;
    }
    rules.iter().any(|rule| {
        let method_ok = match &rule.method {
            None => true,
            Some(m) if m == "*" => true,
            Some(m) => m.eq_ignore_ascii_case(method),
        };
        let path_ok = match &rule.path {
            None => true,
            Some(p) => path_glob_matches(p, path),
        };
        method_ok && path_ok
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn hostname_allowed_catch_all() {
        let routes =
            parse_routes(r#"[{"match": "*", "verdict": "allow", "transport": "upstream"}]"#)
                .unwrap();
        assert!(hostname_allowed(&routes, "anything.example.com"));
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
        assert!(http_request_matches_rules(&[], "GET", "/anything"));
        assert!(http_request_matches_rules(&[], "POST", "/anything"));
    }

    #[test]
    fn http_rules_method_match() {
        let rules = vec![HttpRule {
            method: Some("GET".to_string()),
            path: None,
        }];
        assert!(http_request_matches_rules(&rules, "GET", "/foo"));
        assert!(http_request_matches_rules(&rules, "get", "/foo"));
        assert!(!http_request_matches_rules(&rules, "POST", "/foo"));
    }

    #[test]
    fn http_rules_path_match() {
        let rules = vec![HttpRule {
            method: None,
            path: Some("/api/v1/*".to_string()),
        }];
        assert!(http_request_matches_rules(
            &rules,
            "GET",
            "/api/v1/download"
        ));
        assert!(http_request_matches_rules(&rules, "POST", "/api/v1/upload"));
        assert!(!http_request_matches_rules(
            &rules,
            "GET",
            "/api/v2/download"
        ));
    }

    #[test]
    fn http_rules_method_and_path() {
        let rules = vec![HttpRule {
            method: Some("GET".to_string()),
            path: Some("/api/v1/*".to_string()),
        }];
        assert!(http_request_matches_rules(
            &rules,
            "GET",
            "/api/v1/download"
        ));
        assert!(!http_request_matches_rules(
            &rules,
            "POST",
            "/api/v1/download"
        ));
        assert!(!http_request_matches_rules(
            &rules,
            "GET",
            "/api/v2/download"
        ));
    }

    #[test]
    fn http_rules_multiple_rules_any_match() {
        let rules = vec![
            HttpRule {
                method: Some("GET".to_string()),
                path: Some("/api/v1/*".to_string()),
            },
            HttpRule {
                method: Some("POST".to_string()),
                path: Some("/api/v1/upload".to_string()),
            },
        ];
        assert!(http_request_matches_rules(
            &rules,
            "GET",
            "/api/v1/download"
        ));
        assert!(http_request_matches_rules(&rules, "POST", "/api/v1/upload"));
        assert!(!http_request_matches_rules(
            &rules,
            "DELETE",
            "/api/v1/download"
        ));
        assert!(!http_request_matches_rules(
            &rules,
            "POST",
            "/api/v1/download"
        ));
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
        }];
        assert!(http_request_matches_rules(&rules, "GET", "/health"));
        assert!(http_request_matches_rules(&rules, "POST", "/health"));
        assert!(!http_request_matches_rules(&rules, "GET", "/other"));
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
        }];
        assert!(http_request_matches_rules(
            &rules,
            "GET",
            &normalize_path("/repos/v1/list")
        ));
        assert!(!http_request_matches_rules(
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
        assert!(!http_request_matches_rules(
            &matched.http_rules,
            "POST",
            "/api/v1/upload"
        ));
        // GET /api/v1/repos should be allowed
        assert!(http_request_matches_rules(
            &matched.http_rules,
            "GET",
            "/api/v1/repos"
        ));
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
            hostname_match_for_caller(&routes, "api.github.com", Some(&curl)),
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
            hostname_match_for_caller(&routes, "api.github.com", Some(&wget)),
            HostnameMatch::BinaryDenied
        );
        // No caller info fails closed the same way.
        assert_eq!(
            hostname_match_for_caller(&routes, "api.github.com", None),
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
            hostname_match_for_caller(&routes, "registry.npmjs.org", Some(&curl)),
            HostnameMatch::BinaryDenied
        );
        let npm = caller("/usr/local/bin/npm", &[]);
        assert_eq!(
            hostname_match_for_caller(&routes, "registry.npmjs.org", Some(&npm)),
            HostnameMatch::Allowed
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
            hostname_match_for_caller(&routes, "api.github.com", Some(&curl)),
            HostnameMatch::Denied
        );
    }
}
