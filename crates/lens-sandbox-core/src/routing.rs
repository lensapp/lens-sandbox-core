//! Route rules, hostname/path matching, and HTTP rule evaluation for the
//! sandbox proxy. Parses the policy JSON into `RouteRule`s and resolves a
//! CONNECT target (plus optional HTTP method/path) to an action.

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

        Ok(RouteRule {
            matcher,
            verdict,
            transport,
            tls_terminate: raw.tls_terminate,
            http_rules,
            scheme: raw.scheme,
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
    let lower = hostname.to_ascii_lowercase();
    for rule in routes {
        let matches = match &rule.matcher {
            RouteMatcher::Domain(pattern) => domain_matches(pattern, &lower),
            RouteMatcher::HostPort(pattern_host, _) => domain_matches(pattern_host, &lower),
            RouteMatcher::Cidr(_) => false,
        };
        if matches {
            // First-match semantics (same as `find_matching_route`): a
            // `Deny evil.example.com` rule listed before `Allow
            // *.example.com` must deny the DNS lookup for `evil.example.com`,
            // even though the wildcard would also match. Short-circuiting
            // on the first matching rule is what prevents the leak.
            return rule.verdict != Verdict::Deny;
        }
    }
    false
}

/// Match a host:port target against the route rules. Returns the first matching
/// rule reference, or `None` if nothing matches. Rules with a `scheme` filter
/// only match requests with the same scheme as the provided `request_scheme`;
/// rules without a scheme filter match both `http` and `https` requests.
pub fn find_matching_route<'a>(
    routes: &'a [RouteRule],
    host: &str,
    request_scheme: Scheme,
) -> Option<&'a RouteRule> {
    let hostname = if host.starts_with('[') {
        host.split(']')
            .next()
            .unwrap_or(host)
            .trim_start_matches('[')
    } else {
        host.split(':').next().unwrap_or(host)
    };

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
        if matched {
            return Some(rule);
        }
    }
    None
}

/// Match a host:port target against the route rules. Returns the matched route
/// config for the first matching rule, or defaults if nothing matches.
pub fn match_route(
    routes: &[RouteRule],
    host: &str,
    request_scheme: Scheme,
    default_verdict: Verdict,
    default_transport: Transport,
) -> MatchedRoute {
    if let Some(rule) = find_matching_route(routes, host, request_scheme) {
        MatchedRoute {
            verdict: rule.verdict,
            transport: rule.transport,
            tls_terminate: rule.tls_terminate,
        }
    } else {
        MatchedRoute {
            verdict: default_verdict,
            transport: default_transport,
            tls_terminate: false,
        }
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

/// Normalize a URL path for safe matching: collapse `//`, resolve `..`, strip trailing `/`.
/// Does NOT decode percent-encoding (clients send literal paths over HTTP/1.1).
pub fn normalize_path(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for seg in path.split('/') {
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
    fn normalize_path_does_not_decode_percent_encoding() {
        // Known accepted limitation: percent-encoded sequences are not decoded.
        // HTTP/1.1 clients (curl, SDKs) don't percent-encode path separators in
        // the request-target, so %2e%2e and %2F are not practical bypass vectors.
        assert_eq!(normalize_path("/api/%2e%2e/admin"), "/api/%2e%2e/admin");
        assert_eq!(normalize_path("/api/v1/%2F/secret"), "/api/v1/%2F/secret");
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

        let matched = find_matching_route(&routes, "api.github.com:443", Scheme::Https).unwrap();
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
}
