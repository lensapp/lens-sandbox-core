use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::config::{
    DEFAULT_DNS_STUB_PORT, DEFAULT_PROXY_PORT, DEFAULT_TRANSPARENT_PORT, DEFAULT_UDP_QUEUE_NUM,
};
use crate::sock_mark::{MARK_VALUE, REJECT_MARK};

const TABLE_NAME: &str = "lens_sandbox";
const LOG_PREFIX: &str = "lens:bypass:";

/// Path the agent-sandbox provisioner injects a statically-linked `nft`
/// binary into, alongside the supervisor. When present, we prefer it
/// over `nft` on PATH so the user's container image doesn't need an
/// nftables package installed. Falls back to PATH when absent (legacy
/// images that bundle nftables themselves, the shell-sandbox image, dev
/// hosts).
const INJECTED_NFT_PATH: &str = "/.lens/nft";

fn nft_command() -> Command {
    let mut cmd = if Path::new(INJECTED_NFT_PATH).exists() {
        Command::new(INJECTED_NFT_PATH)
    } else {
        Command::new("nft")
    };
    // Pin locale so any stderr substring match on nft output is deterministic
    // regardless of what LANG/LC_ALL the container image sets.
    cmd.env("LC_ALL", "C");
    cmd
}

/// Install nftables lockdown that confines every unmarked outbound packet
/// to loopback (filter chain) or redirects it to the transparent listener
/// (nat chain). The proxy/MITM/DNS-upstream sockets carry
/// `SO_MARK = MARK_VALUE` (see `sock_mark`), so their packets carry the
/// mark and bypass both chains; everything else (the agent's traffic)
/// falls into the cage regardless of which UID the image runs as.
///
/// The whole policy lives in one owned `inet lens_sandbox` table; the
/// `inet` family covers IPv4 and IPv6 in one pass.
///
/// Idempotency is handled at the Rust level, not inside the script: a
/// best-effort `nft delete table` runs first (ENOENT is treated as
/// success), then the atomic create transaction installs the rules. This
/// makes "supervisor restart in the same netns" — where the table from
/// the previous run is still present — a recoverable case without
/// relying on nft script-level "add then delete" tricks.
pub fn install_network_lockdown() -> Result<(), String> {
    if let Err(e) = delete_table_best_effort() {
        // Pre-install delete failed for some reason other than "table
        // doesn't exist". Log and continue — the create transaction below
        // will surface a clear error if the kernel can't accept it (e.g.
        // missing CAP_NET_ADMIN). Most likely scenario: leftover table
        // from a prior run; the create will fail with EEXIST and the
        // supervisor will exit fail-closed.
        tracing::warn!(
            "pre-install nft delete failed (continuing; create will fail with EEXIST if the table still exists): {e}"
        );
    }
    run_nft_script(&render_install_script())?;
    tracing::info!("unmarked traffic confined to loopback + transparent redirect (nftables inet)");
    Ok(())
}

/// Best-effort tear-down of the lockdown table.
pub fn cleanup_network_lockdown() {
    match delete_table_best_effort() {
        Ok(()) => tracing::info!("nftables rules cleaned up"),
        Err(e) => tracing::warn!("nftables cleanup failed: {e}"),
    }
}

/// Run `nft delete table inet lens_sandbox`. ENOENT (table absent) is
/// treated as success so callers don't have to know whether the table
/// existed.
fn delete_table_best_effort() -> Result<(), String> {
    let output = nft_command()
        .args(["delete", "table", "inet", TABLE_NAME])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("nft exec failed: {e}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    // nft 1.0.x writes "Error: Could not process rule: No such file or
    // directory" when the named table is absent. Treat that as success —
    // the absence is what we wanted.
    if stderr.contains("No such file or directory") {
        return Ok(());
    }
    Err(format!("nft delete failed: {}", stderr.trim()))
}

fn render_install_script() -> String {
    let proxy = DEFAULT_PROXY_PORT;
    let transparent = DEFAULT_TRANSPARENT_PORT;
    let dns = DEFAULT_DNS_STUB_PORT;
    let table = TABLE_NAME;
    let prefix = LOG_PREFIX;
    // Decimal — `nft` accepts plain integers for meta mark, no 0x prefix needed.
    let mark = MARK_VALUE;
    let reject_mark = REJECT_MARK;
    let queue = DEFAULT_UDP_QUEUE_NUM;

    // Pure create transaction. Any prior copy of the table was removed
    // by `delete_table_best_effort` before this script runs, so the
    // create can fail loudly if something unexpected is in the way.
    format!(
        "table inet {table} {{\n\
         \tchain output_nat {{\n\
         \t\t# Numeric priority (-100, equivalent to NF_IP_PRI_NAT_DST). The named\n\
         \t\t# `dstnat` alias is rejected by nft 1.0.6 in inet/nat/output context,\n\
         \t\t# even though it's documented as supported there.\n\
         \t\ttype nat hook output priority -100; policy accept;\n\
         \n\
         \t\t# DNS first — Docker's embedded 127.0.0.11:53 resolver would otherwise\n\
         \t\t# hit the loopback return below and bypass the allowlist gate, opening\n\
         \t\t# a QNAME-encoded covert channel.\n\
         \t\tmeta mark != {mark} udp dport 53 redirect to :{dns}\n\
         \n\
         \t\tmeta mark != {mark} oifname \"lo\" return\n\
         \t\tmeta mark != {mark} tcp dport {proxy} return\n\
         \t\tmeta mark != {mark} tcp dport {transparent} return\n\
         \n\
         \t\tmeta mark != {mark} meta l4proto tcp redirect to :{transparent}\n\
         \t}}\n\
         \n\
         \tchain output_filter {{\n\
         \t\t# Default DROP — the cage fails CLOSED. The explicit accepts below\n\
         \t\t# whitelist the flows that may leave; anything that slips past a\n\
         \t\t# removed/reordered rule hits this policy and is dropped rather\n\
         \t\t# than escaping the proxy. The terminal reject still gives unmarked\n\
         \t\t# traffic an immediate refusal; drop is the belt-and-suspenders.\n\
         \t\ttype filter hook output priority 0; policy drop;\n\
         \n\
         \t\t# Marked traffic is the proxy/MITM/DNS-upstream sockets' own egress.\n\
         \t\t# Under policy drop it needs an explicit accept or the proxy locks\n\
         \t\t# itself out of the network.\n\
         \t\tmeta mark {mark} accept\n\
         \n\
         \t\t# daddr loopback accept catches both direct loopback and the rewritten\n\
         \t\t# dst from output_nat's REDIRECT. oifname \"lo\" is a belt-and-suspenders\n\
         \t\t# fallback for older-kernel UDP-after-REDIRECT where dst isn't\n\
         \t\t# re-resolved.\n\
         \t\tmeta mark != {mark} ip daddr 127.0.0.0/8 accept\n\
         \t\tmeta mark != {mark} ip6 daddr ::1 accept\n\
         \t\tmeta mark != {mark} oifname \"lo\" accept\n\
         \t\t# Conntrack never answers for UDP: an entry names a flow, and a\n\
         \t\t# flow is five numbers a later program can rebind — see the\n\
         \t\t# `udp_egress` module docs. Every datagram reaches the queue below\n\
         \t\t# instead. Non-UDP keeps the fast path, where a connection is a\n\
         \t\t# socket and `related` is an ICMP error for a flow already accepted.\n\
         \t\tmeta mark != {mark} meta l4proto != udp ct state established,related accept\n\
         \n\
         \t\t# UDP is judged in userspace: the relay reads each datagram off\n\
         \t\t# queue {queue} and answers accept, drop, or — by stamping\n\
         \t\t# {reject_mark} and asking for another pass — the reject below.\n\
         \t\t# Both mark rules MUST precede the queue rule: a repeated packet\n\
         \t\t# re-enters this chain at the top, and would be queued again.\n\
         \t\t#\n\
         \t\t# DNS needs no exclusion here. The nat chain runs first (priority\n\
         \t\t# -100 against this chain's 0), so an unmarked UDP/53 datagram\n\
         \t\t# arrives already rewritten to the stub and is taken by the\n\
         \t\t# loopback accept above. A `udp dport 53` rule in this chain could\n\
         \t\t# only ever match one the nat chain did NOT redirect — which is the\n\
         \t\t# covert channel the stub exists to close.\n\
         \t\t#\n\
         \t\t# The queue carries no `bypass` flag, so a full queue drops rather\n\
         \t\t# than admits. With no relay attached, all UDP stops here.\n\
         \t\tmeta mark {reject_mark} limit rate 5/second burst 10 packets log prefix \"{prefix}\" level info\n\
         \t\tmeta mark {reject_mark} reject with icmpx type port-unreachable\n\
         \t\tmeta mark != {mark} meta l4proto udp queue num {queue}\n\
         \n\
         \t\t# Rate-limited LOG of TCP bypass attempts. UDP has no rule here:\n\
         \t\t# the queue above is terminal for every datagram — a verdict ends\n\
         \t\t# the packet, and an unread queue drops it — so nothing UDP can\n\
         \t\t# reach this far. Refused datagrams are logged at the reject rule.\n\
         \t\t#\n\
         \t\t# Unlike iptables' `--log-uid`, nftables `log` doesn't emit the\n\
         \t\t# originating UID into the kernel log — operators correlating\n\
         \t\t# `lens:bypass:` entries to a specific process must use `meta skuid`\n\
         \t\t# matches or audit subsystem hooks instead. Mark-based gating made\n\
         \t\t# UID attribution moot for the cage itself, but the diagnostic loss\n\
         \t\t# is worth a note.\n\
         \t\tmeta mark != {mark} tcp flags syn limit rate 5/second burst 10 packets log prefix \"{prefix}\" level info\n\
         \n\
         \t\tmeta mark != {mark} reject with icmpx type port-unreachable\n\
         \t}}\n\
         }}\n",
    )
}

fn run_nft_script(script: &str) -> Result<(), String> {
    let mut child = nft_command()
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("nft exec failed: {e}"))?;

    child
        .stdin
        .as_mut()
        .ok_or_else(|| "nft stdin not available".to_string())?
        .write_all(script.as_bytes())
        .map_err(|e| format!("nft stdin write failed: {e}"))?;

    // Close stdin so nft sees EOF before we wait. `wait_with_output` would
    // drop it for us, but doing it explicitly removes the deadlock risk if
    // nft ever reads until EOF before producing output.
    drop(child.stdin.take());

    let output = child
        .wait_with_output()
        .map_err(|e| format!("nft wait failed: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("nft failed: {}", stderr.trim()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rendered `output_filter` chain block, from its `chain` header up to
    /// (but not including) the chain's closing brace. Tests that assert
    /// properties scoped to this chain slice against it so they don't
    /// accidentally match rules in `output_nat`.
    fn output_filter_chain(script: &str) -> &str {
        let start = script
            .find("chain output_filter")
            .expect("output_filter chain");
        let rest = &script[start..];
        let end = rest.find("\n\t}").expect("output_filter chain end");
        &rest[..end]
    }

    /// The single `meta mark == MARK_VALUE accept` rule (the marked-traffic
    /// exemption). Shared so the rule text and its test guards can't drift.
    fn marked_accept_rule() -> String {
        format!("meta mark {MARK_VALUE} accept")
    }

    /// The `output_filter` rules with the commentary stripped. A test asking
    /// whether the chain *does* something must not be answered by prose that
    /// merely says so — several of these comments quote the very rule shapes
    /// the chain is asserted not to contain.
    fn output_filter_rules(script: &str) -> String {
        output_filter_chain(script)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn dns_redirect_precedes_loopback_return() {
        // Docker's embedded 127.0.0.11:53 resolver is loopback-addressed.
        // If `oifname "lo" return` fires before the UDP/53 REDIRECT,
        // unmarked DNS queries to 127.0.0.11 bypass the allowlist gate
        // entirely — the exact covert channel this feature closes.
        let s = render_install_script();
        let dns = s
            .find("udp dport 53 redirect to")
            .expect("DNS redirect rule");
        let lo_return = s
            .find("oifname \"lo\" return")
            .expect("loopback return rule");
        assert!(
            dns < lo_return,
            "DNS redirect ({dns}) must precede loopback return ({lo_return})"
        );
    }

    #[test]
    fn proxy_port_returns_precede_tcp_redirect() {
        // RETURN exclusions for explicit-proxy and transparent ports must
        // come before the catch-all TCP redirect, otherwise the kernel
        // rewrites the proxy's own upstream connections into an infinite
        // redirect loop on the transparent listener.
        let s = render_install_script();
        let proxy_ret = s
            .find(&format!("tcp dport {DEFAULT_PROXY_PORT} return"))
            .expect("explicit-proxy return rule");
        let transparent_ret = s
            .find(&format!("tcp dport {DEFAULT_TRANSPARENT_PORT} return"))
            .expect("transparent-listener return rule");
        let tcp_redirect = s
            .find("meta l4proto tcp redirect to")
            .expect("catch-all TCP redirect");
        assert!(proxy_ret < tcp_redirect);
        assert!(transparent_ret < tcp_redirect);
    }

    #[test]
    fn tcp_redirect_targets_transparent_listener() {
        let s = render_install_script();
        let expected = format!("meta l4proto tcp redirect to :{DEFAULT_TRANSPARENT_PORT}");
        assert!(
            s.contains(&expected),
            "TCP redirect must target transparent listener port {DEFAULT_TRANSPARENT_PORT}"
        );
    }

    #[test]
    fn dns_redirect_targets_stub() {
        let s = render_install_script();
        let expected = format!("udp dport 53 redirect to :{DEFAULT_DNS_STUB_PORT}");
        assert!(
            s.contains(&expected),
            "DNS redirect must target DNS stub port {DEFAULT_DNS_STUB_PORT}"
        );
    }

    #[test]
    fn restrictive_rules_match_unmarked_packets() {
        // Every restrictive rule (return/redirect/accept/log/reject) must
        // be gated on `meta mark != MARK_VALUE` so the proxy/MITM/DNS-upstream
        // sockets (which carry the mark) bypass the cage. A missing mark
        // match would lock the proxy itself out of the network. The sole
        // mark-equals rule is the explicit accept that lets marked
        // (proxy-origin) traffic out past the filter chain's drop policy.
        let s = render_install_script();
        let needle = format!("meta mark != {MARK_VALUE} ");
        let marked_accept = marked_accept_rule();
        // The relay's own refusal rules match `REJECT_MARK` instead. They are
        // consistent with the guard rather than an exception to it: the mark is
        // not MARK_VALUE, so only unmarked traffic the relay has judged can
        // carry it, and the workload can set neither mark — `privilege.rs`
        // drops CAP_NET_ADMIN and CAP_NET_RAW, and either one would do (see
        // `sock_mark.rs`).
        let reject_marked = format!("meta mark {REJECT_MARK} ");
        for line in s.lines() {
            let t = line.trim();
            if t.starts_with(&reject_marked) {
                continue;
            }
            // Header / scaffolding lines that are allowed to lack the mark match:
            // - empty
            // - comments (`#`)
            // - structural braces / table / chain headers / hook config
            if t.is_empty()
                || t.starts_with('#')
                || t.starts_with("table ")
                || t.starts_with("chain ")
                || t.starts_with("type ")
                || t == "}"
                || t == marked_accept
            {
                continue;
            }
            assert!(
                t.starts_with(&needle),
                "rule must be gated on unmarked packets: {t}"
            );
        }
    }

    #[test]
    fn log_rules_use_lens_sandbox_bypass_prefix() {
        // The `lens:bypass:` prefix is the documented signal operators
        // grep for in journald. Don't let it drift.
        let s = render_install_script();
        assert_eq!(
            s.matches("log prefix \"lens:bypass:\" level info").count(),
            2,
            "expected two LOG rules (TCP SYN + refused datagram) with the lens:bypass: prefix"
        );
    }

    #[test]
    fn the_relays_mark_rules_precede_the_queue() {
        // A rejected datagram is stamped and re-judged, so it re-enters this
        // chain at the top. If the queue rule came first it would be queued
        // again, and the relay would answer the same packet forever.
        let s = render_install_script();
        let chain = output_filter_chain(&s);
        let log = chain
            .find(&format!("meta mark {REJECT_MARK} limit rate"))
            .expect("refused datagrams must be logged");
        let reject = chain
            .find(&format!("meta mark {REJECT_MARK} reject"))
            .expect("refused datagrams must be rejected");
        let queue = chain
            .find(&format!("queue num {DEFAULT_UDP_QUEUE_NUM}"))
            .expect("udp must be queued to the relay");
        assert!(log < reject, "log the refusal before answering it");
        assert!(
            reject < queue,
            "reject ({reject}) must precede queue ({queue})"
        );
    }

    #[test]
    fn conntrack_never_answers_for_a_datagram() {
        // A conntrack entry names a flow, not a program, so it cannot carry a
        // verdict about one — see the `udp_egress` module docs.
        let rules = output_filter_rules(&render_install_script());
        let tracked: Vec<&str> = rules
            .lines()
            .filter(|rule| rule.contains("ct state"))
            .collect();
        assert!(!tracked.is_empty(), "expected a conntrack accept");
        for rule in tracked {
            assert!(
                rule.contains("meta l4proto != udp"),
                "a conntrack accept must not cover udp: {rule}"
            );
        }
    }

    #[test]
    fn the_filter_chain_never_accepts_dns_by_port() {
        // The nat chain runs first (priority -100 against this chain's 0), so a
        // DNS datagram arrives here already rewritten to the stub and the
        // loopback accept takes it. A `udp dport 53` rule in this chain could
        // therefore only ever match one the nat chain did NOT redirect — and
        // accepting that is the covert channel the stub exists to close.
        let rules = output_filter_rules(&render_install_script());
        assert!(
            !rules.contains("dport 53"),
            "output_filter must not name the DNS port"
        );
    }

    #[test]
    fn the_udp_queue_does_not_fail_open() {
        // `bypass` tells the kernel to accept what it cannot queue. On this
        // chain that would let every datagram past the cap leave unjudged,
        // exactly when something is flooding.
        let rules = output_filter_rules(&render_install_script());
        let queue_rule = rules
            .lines()
            .find(|line| line.contains("queue num"))
            .expect("udp must be queued to the relay");
        assert!(
            !queue_rule.contains("bypass"),
            "the queue rule must not carry the bypass flag: {queue_rule}"
        );
    }

    #[test]
    fn install_script_only_touches_owned_table() {
        // Lockdown must not modify anything outside `inet lens_sandbox`.
        // A stray edit elsewhere would either fail in production (no
        // permission) or, worse, mangle an operator's pre-existing
        // ruleset.
        let s = render_install_script();
        for line in s.lines() {
            let t = line.trim();
            if t.starts_with("table ") {
                assert!(
                    t.contains(&format!("inet {TABLE_NAME}")),
                    "table reference must be inet {TABLE_NAME}: {t}"
                );
            }
        }
    }

    #[test]
    fn install_script_has_no_pre_delete_prelude() {
        // Idempotency lives in Rust (`delete_table_best_effort`), not in
        // the script. A regression that re-introduces `add table` / `delete
        // table` here would re-couple the two and risk the same kind of
        // transaction-level breakage we hit when experimenting with
        // `destroy table`.
        let s = render_install_script();
        assert!(
            !s.contains("add table"),
            "script must not contain `add table`"
        );
        assert!(
            !s.contains("delete table"),
            "script must not contain `delete table`"
        );
        assert!(
            s.starts_with("table inet"),
            "script must start with the table block"
        );
    }

    #[test]
    fn filter_chain_defaults_to_drop() {
        // The egress filter chain must fail CLOSED. Three properties together
        // guarantee that, and each guards a distinct fail-open regression:
        //   1. it declares `policy drop` — an unmatched packet is dropped;
        //   2. it does NOT declare `policy accept` anywhere — a revert that
        //      reintroduces accept (even alongside a stray drop) escapes;
        //   3. it keeps the terminal `reject`, the immediate refusal for
        //      unmarked traffic that the drop policy backstops.
        let s = render_install_script();
        let chain = output_filter_chain(&s);
        assert!(
            chain.contains("policy drop;"),
            "output_filter must declare `policy drop` (fail closed)"
        );
        assert!(
            !chain.contains("policy accept"),
            "output_filter must not declare `policy accept` — that fails open"
        );
        assert!(
            chain.contains("reject with icmpx type port-unreachable"),
            "output_filter must keep its terminal reject"
        );
    }

    #[test]
    fn marked_proxy_traffic_is_explicitly_accepted_in_filter_chain() {
        // With the filter chain at `policy drop`, the proxy/MITM/DNS-upstream
        // sockets (SO_MARK == MARK_VALUE) need an explicit accept — and it must
        // appear BEFORE the terminal reject, or the reject fires first and the
        // proxy locks itself out of the network. Assert both presence and order.
        let s = render_install_script();
        let chain = output_filter_chain(&s);
        let accept_pos = chain
            .find(&marked_accept_rule())
            .expect("filter chain must explicitly accept marked (proxy-origin) traffic");
        let reject_pos = chain
            .find("reject with icmpx type port-unreachable")
            .expect("filter chain must keep its terminal reject");
        assert!(
            accept_pos < reject_pos,
            "marked-traffic accept ({accept_pos}) must precede the terminal reject ({reject_pos})"
        );
    }

    #[test]
    fn inet_family_covers_ipv6_loopback_and_redirect() {
        // `inet` covers IPv4 and IPv6 in one hook; loopback accepts are
        // split because the addresses differ. Dropping `ip6` breaks v6
        // loopback; switching `inet` → `ip` silently bypasses v6 entirely.
        let s = render_install_script();
        assert!(s.contains("ip daddr 127.0.0.0/8 accept"));
        assert!(s.contains("ip6 daddr ::1 accept"));
        assert!(s.contains(&format!("table inet {TABLE_NAME}")));
    }
}
