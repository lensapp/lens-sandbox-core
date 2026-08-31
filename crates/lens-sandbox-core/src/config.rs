use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Loopback port the explicit CONNECT proxy binds to. `network.rs` renders
/// this into the nftables script so the numeric value here is the single
/// source of truth; rule-ordering snapshot tests in `network.rs::tests`
/// catch accidental divergence.
pub const DEFAULT_PROXY_PORT: u16 = 3128;
/// Loopback port the transparent-redirect listener binds to.
pub const DEFAULT_TRANSPARENT_PORT: u16 = 3129;
/// Loopback port the DNS stub resolver binds to. The NAT chain REDIRECTs
/// sandbox-user UDP/53 to this port so queries can be allowlist-gated
/// (see `dns.rs`).
pub const DEFAULT_DNS_STUB_PORT: u16 = 5355;
/// NFQUEUE number the filter chain hands sandbox datagrams to, and the one the
/// UDP relay binds. Not a port — a queue index — but the same single-source-of-
/// truth rule applies: `network.rs` renders this value into the nftables script
/// and `udp_egress.rs` binds it (see `udp_egress.rs`).
pub const DEFAULT_UDP_QUEUE_NUM: u16 = 0;

/// Additional local addresses the redirect listeners accept, as a
/// comma-separated list of IPs.
///
/// The cage normally delivers redirected traffic to `127.0.0.1`, because the
/// nftables `redirect` rule rewrites the destination to the address of the
/// interface the packet arrived on, and that interface is the loopback. A
/// nested namespace changes that: traffic from it arrives on a veth, so
/// `redirect` picks the veth's address and nothing on `127.0.0.1` accepts it.
/// Naming the veth address here is what makes the cage reachable from inside
/// the nested namespace.
///
/// It applies to the transparent listener and the DNS stub only. The explicit
/// CONNECT proxy stays on loopback: it serves the agent process through
/// `HTTPS_PROXY`, and a nested namespace has no business reaching it.
pub const EXTRA_LISTEN_IPS_ENV: &str = "LENS_SANDBOX_EXTRA_LISTEN_IPS";

#[derive(Debug, Clone)]
pub enum SandboxMode {
    /// Connected to Lens Sandbox server via WebSocket
    Server { ws_url: String, token: String },
    /// Standalone mode — policy read from Docker volume, no server
    Standalone { policy_json: String },
}

/// Core configuration shared by all sandbox binaries.
pub struct CoreConfig {
    pub mode: SandboxMode,
    /// Idle shutdown timer. `None` disables it — the library default. Callers
    /// that want a self-terminating sandbox (e.g. the ephemeral shell-sandbox)
    /// set `IDLE_TIMEOUT_MS` in the container env to enable it.
    pub idle_timeout: Option<Duration>,
    pub proxy_listen_addr: SocketAddr,
    /// Transparent redirect listener — receives connections rewritten by the
    /// nftables redirect rule so agents that ignore `HTTPS_PROXY` still get
    /// proxied (see `transparent.rs`).
    pub transparent_listen_addr: SocketAddr,
    /// DNS stub resolver listener — receives UDP/53 queries rewritten by the
    /// NAT REDIRECT rule, filters them against the route allowlist, and
    /// forwards allowed queries to the host resolver (see `dns.rs`).
    pub dns_stub_listen_addr: SocketAddr,
    /// Local addresses the two redirect listeners accept in addition to
    /// loopback, on the same ports. Empty unless `LENS_SANDBOX_EXTRA_LISTEN_IPS`
    /// names some — see that constant for why a nested namespace needs it.
    pub extra_listen_ips: Vec<IpAddr>,
    /// True when running as root — local proxy + nftables enforcement is enabled.
    pub is_root: bool,
    /// Unix user to drop privileges to for child processes.
    pub sandbox_user: String,
}

/// Extract the hostnames the supervisor must resolve before any policy
/// arrives. Only the Lens Sandbox host (from the server-mode `ws_url`) today —
/// standalone mode reads policy from a file and never makes a bootstrap
/// DNS query. Returns an empty list when no bootstrap is needed.
pub fn bootstrap_dns_hosts(mode: &SandboxMode) -> Vec<String> {
    let SandboxMode::Server { ws_url, .. } = mode else {
        return Vec::new();
    };
    // vsock:// URLs carry a CID, not a DNS host. Schemes are
    // case-insensitive (RFC 3986 §3.1), so parse out the scheme instead
    // of substring-matching — otherwise `VSOCK://2:1024/...` would fall
    // through to `extract_host` and return `"2"` as a bogus hostname.
    let trimmed = ws_url.trim_start();
    let scheme = trimmed.split_once("://").map(|(s, _)| s).unwrap_or("");
    if scheme.eq_ignore_ascii_case("vsock") {
        return Vec::new();
    }
    extract_host(ws_url).map(|h| vec![h]).unwrap_or_default()
}

/// Pull the host portion out of `ws://host:port/path` (or `wss://...`).
/// We avoid pulling in the `url` crate for one call — the WS URL format
/// is fixed enough that splitting on `://` and the next delimiter is fine.
fn extract_host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let host_with_port = rest
        .split_once(['/', '?', '#'])
        .map(|(h, _)| h)
        .unwrap_or(rest);
    let host_with_port = host_with_port
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(host_with_port);
    let host = host_with_port
        .split_once(':')
        .map(|(h, _)| h)
        .unwrap_or(host_with_port);
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Load core config from environment variables.
/// Mode is derived from the environment:
/// - `LENS_SANDBOX_POLICY_FILE` set → standalone mode (read policy from that path)
/// - Otherwise → server mode (WebSocket via `LENS_SANDBOX_WS_URL` + `LENS_SANDBOX_TOKEN`)
pub fn load_core_config() -> CoreConfig {
    let mode = if let Ok(policy_path) = std::env::var("LENS_SANDBOX_POLICY_FILE") {
        let policy_json = std::fs::read_to_string(&policy_path)
            .unwrap_or_else(|e| panic!("Failed to read policy file {policy_path}: {e}"));
        SandboxMode::Standalone { policy_json }
    } else {
        let ws_url = std::env::var("LENS_SANDBOX_WS_URL")
            .expect("LENS_SANDBOX_WS_URL environment variable is required");
        let token = std::env::var("LENS_SANDBOX_TOKEN")
            .expect("LENS_SANDBOX_TOKEN environment variable is required");
        SandboxMode::Server { ws_url, token }
    };

    let idle_timeout = parse_idle_timeout(std::env::var("IDLE_TIMEOUT_MS").ok());

    let proxy_listen_addr = SocketAddr::from(([127, 0, 0, 1], DEFAULT_PROXY_PORT));
    let transparent_listen_addr = SocketAddr::from(([127, 0, 0, 1], DEFAULT_TRANSPARENT_PORT));
    let dns_stub_listen_addr = SocketAddr::from(([127, 0, 0, 1], DEFAULT_DNS_STUB_PORT));
    let extra_listen_ips =
        parse_extra_listen_ips(std::env::var(EXTRA_LISTEN_IPS_ENV).ok().as_deref());

    let is_root = nix::unistd::getuid().is_root();

    let sandbox_user = std::env::var("LENS_SANDBOX_USER").unwrap_or_else(|_| "sandbox".to_string());

    CoreConfig {
        mode,
        idle_timeout,
        proxy_listen_addr,
        transparent_listen_addr,
        dns_stub_listen_addr,
        extra_listen_ips,
        is_root,
        sandbox_user,
    }
}

/// Parse the `IDLE_TIMEOUT_MS` env value into an optional duration.
///
/// `None` means "disabled" — both when the env var is unset and when set
/// to `0`. The library default is disabled; callers opt in by setting a
/// positive number.
pub fn parse_idle_timeout(raw: Option<String>) -> Option<Duration> {
    let val = raw?;
    let ms: u64 = val
        .parse()
        .unwrap_or_else(|_| panic!("IDLE_TIMEOUT_MS must be a number, got: \"{val}\""));
    if ms == 0 {
        None
    } else {
        Some(Duration::from_millis(ms))
    }
}

/// Parse the value of `EXTRA_LISTEN_IPS_ENV`.
///
/// An entry that is not an IP address is dropped with a warning rather than
/// failing the whole list: the value reaches a `bind` call, and one typo should
/// not silently take the cage's other listeners with it.
pub fn parse_extra_listen_ips(raw: Option<&str>) -> Vec<IpAddr> {
    let Some(raw) = raw else {
        return Vec::new();
    };
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| match s.parse::<IpAddr>() {
            // `0.0.0.0` and `::` parse, and would bind every interface — the
            // pod address included. The safety of this whole setting rests on
            // the extra addresses reaching no further than the veth they live
            // on, which the unspecified address does not.
            Ok(ip) if ip.is_unspecified() => {
                tracing::warn!(
                    entry = %s,
                    "{EXTRA_LISTEN_IPS_ENV} entry names every interface rather than one address, ignoring it"
                );
                None
            }
            Ok(ip) => Some(ip),
            Err(_) => {
                tracing::warn!(
                    entry = %s,
                    "{EXTRA_LISTEN_IPS_ENV} entry is not an IP address, ignoring it"
                );
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extra_listen_ips_is_empty_without_the_variable() {
        assert!(parse_extra_listen_ips(None).is_empty());
        assert!(parse_extra_listen_ips(Some("")).is_empty());
        assert!(parse_extra_listen_ips(Some("  , ,")).is_empty());
    }

    #[test]
    fn extra_listen_ips_reads_a_comma_separated_list() {
        assert_eq!(
            parse_extra_listen_ips(Some("169.254.32.1")),
            vec!["169.254.32.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            parse_extra_listen_ips(Some(" 169.254.32.1 , fd00::1 ")),
            vec![
                "169.254.32.1".parse::<IpAddr>().unwrap(),
                "fd00::1".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn extra_listen_ips_drops_entries_that_are_not_addresses() {
        // The value reaches a `bind` call, so a hostname or a host:port pair
        // must not survive parsing. Dropping the bad entry keeps the good ones
        // — a typo in one address should not silently disable the whole cage.
        assert_eq!(
            parse_extra_listen_ips(Some("nope,169.254.32.1,169.254.32.2:3129")),
            vec!["169.254.32.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn extra_listen_ips_drops_the_wildcard_address() {
        // It parses, so only an explicit check keeps it out — and it would put
        // the transparent listener and the DNS stub on the pod address.
        assert_eq!(
            parse_extra_listen_ips(Some("0.0.0.0,::,169.254.32.1")),
            vec!["169.254.32.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn extract_host_handles_common_forms() {
        assert_eq!(
            extract_host("ws://host.docker.internal:3002/v1/sandbox"),
            Some("host.docker.internal".into())
        );
        assert_eq!(
            extract_host("wss://lens.example.com/v1/sandbox"),
            Some("lens.example.com".into())
        );
        assert_eq!(extract_host("ws://USER@lens:3002/x"), Some("lens".into()));
        assert_eq!(extract_host("not-a-url"), None);
        assert_eq!(extract_host("ws://"), None);
    }

    #[test]
    fn parse_idle_timeout_returns_none_when_unset() {
        assert_eq!(parse_idle_timeout(None), None);
    }

    #[test]
    fn parse_idle_timeout_returns_none_when_zero() {
        // Zero is the explicit "disabled" sentinel so callers (e.g. the
        // shell-sandbox provisioner) can opt out of the timer at runtime.
        assert_eq!(parse_idle_timeout(Some("0".into())), None);
    }

    #[test]
    fn parse_idle_timeout_returns_some_for_positive_value() {
        assert_eq!(
            parse_idle_timeout(Some("1800000".into())),
            Some(Duration::from_millis(1_800_000)),
        );
    }

    #[test]
    #[should_panic(expected = "IDLE_TIMEOUT_MS must be a number")]
    fn parse_idle_timeout_panics_on_non_number() {
        let _ = parse_idle_timeout(Some("abc".into()));
    }

    #[test]
    fn bootstrap_dns_hosts_returns_server_host_only() {
        let server = SandboxMode::Server {
            ws_url: "wss://lens.example.com:3002/v1/sandbox".into(),
            token: "t".into(),
        };
        assert_eq!(
            bootstrap_dns_hosts(&server),
            vec!["lens.example.com".to_string()]
        );

        let standalone = SandboxMode::Standalone {
            policy_json: "{}".into(),
        };
        assert!(bootstrap_dns_hosts(&standalone).is_empty());
    }

    #[test]
    fn bootstrap_dns_hosts_skips_vsock_urls() {
        // vsock://CID:PORT carries a CID, not a DNS host — DNS warming is
        // meaningless and `extract_host` would return the literal CID
        // string (e.g. "2"), which `nft` would then try to feed to the
        // resolver as an A query.
        let server = SandboxMode::Server {
            ws_url: "vsock://2:1024/v1/sandbox".into(),
            token: "t".into(),
        };
        assert!(bootstrap_dns_hosts(&server).is_empty());
    }

    #[test]
    fn bootstrap_dns_hosts_skips_vsock_urls_regardless_of_case() {
        // RFC 3986 schemes are case-insensitive. A raw `starts_with`
        // would let `VSOCK://` (or any mixed-case variant) fall through
        // to `extract_host` and return the CID as a bogus DNS hostname.
        for ws_url in [
            "VSOCK://2:1024/v1/sandbox",
            "Vsock://2:1024/v1/sandbox",
            "vSoCk://2:1024/v1/sandbox",
        ] {
            let server = SandboxMode::Server {
                ws_url: ws_url.into(),
                token: "t".into(),
            };
            assert!(
                bootstrap_dns_hosts(&server).is_empty(),
                "expected vsock skip for `{ws_url}`",
            );
        }
    }

    #[test]
    fn bootstrap_dns_hosts_skips_vsock_urls_with_leading_whitespace() {
        // Defensive: a stray leading space on `LENS_WS_URL` shouldn't
        // sneak past the vsock check and try to DNS-resolve the CID.
        let server = SandboxMode::Server {
            ws_url: "  vsock://2:1024/v1/sandbox".into(),
            token: "t".into(),
        };
        assert!(bootstrap_dns_hosts(&server).is_empty());
    }
}
