//! Netfilter packet marking for proxy outbound sockets.
//!
//! The sandbox's nftables redirect chain catches *all* outbound traffic except
//! packets carrying `MARK_VALUE`. The proxy stamps its own sockets with that
//! mark via `SO_MARK` so that proxy → upstream connections aren't recursively
//! caught by the very rule that's supposed to redirect the agent's traffic.
//!
//! Name lookups are marked too — see [`crate::resolver`] for why libc's
//! `getaddrinfo` cannot be.
//!
//! This decouples policy from the agent's UID — the nftables rules no longer
//! need to name a specific `meta skuid` value, so the agent can run as any user
//! the user-supplied image expects.
//!
//! Forging the mark takes `CAP_NET_ADMIN` **or** `CAP_NET_RAW` in the user
//! namespace that owns the socket's network namespace. `CAP_NET_RAW` has been
//! enough since Linux 5.17 — commit `079925cce1d0`, "net: allow SO_MARK with
//! CAP_NET_RAW" — and it is easy to miss: a container's *default* capability
//! set holds it. The agent keeps neither — `privilege.rs` drops both
//! before exec — so the workload cannot spoof its way out.
//!
//! The wider rule follows from the same fact. The cage covers every process in
//! the network namespace, so anything else placed there — a sidecar container,
//! say — is covered too, but only while it holds neither capability. A sidecar
//! started with default capabilities can stamp `MARK_VALUE` on its own sockets
//! and leave the cage entirely.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsFd;

use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// Lens Sandbox-internal mark applied to every outbound socket from proxy/MITM/DNS.
///
/// Any unused 32-bit value works; we pick a recognisable nibble pattern.
/// Inside the sandbox netns we control the namespace, so collisions with
/// other mark consumers are vanishingly unlikely.
pub const MARK_VALUE: u32 = 0x4E_58_55_53; // "NXUS" in ASCII

/// Mark the UDP relay stamps on a datagram it refuses, so the nftables chain
/// answers the sender with ICMP port-unreachable (see [`crate::udp_egress`]).
///
/// A verdict from userspace cannot send ICMP. It can set this mark and ask for
/// the packet to be judged again, which is what turns a refusal into the same
/// immediate error the cage gave before any of this existed.
///
/// The workload cannot forge it: `SO_MARK` needs `CAP_NET_ADMIN` or
/// `CAP_NET_RAW` (see the module docs), and `privilege.rs` drops both before the
/// agent execs. A forged mark would only reject the forger's own packet anyway.
/// It is deliberately not [`MARK_VALUE`] — that one means "this is ours, let it
/// out", which is the opposite instruction.
pub const REJECT_MARK: u32 = 0x4E_58_55_44; // "NXUD" in ASCII

/// Apply `SO_MARK = MARK_VALUE` to a socket. Linux-only — needs
/// `CAP_NET_ADMIN` or `CAP_NET_RAW` (see the module docs). On other platforms
/// this is a no-op so the rest of the crate continues to compile (nftables
/// enforcement is Linux-only anyway).
///
/// EPERM is tolerated: in production the supervisor holds the capability
/// before privilege drop, and in tests / hosts without nftables rules there
/// is nothing to bypass. Returning the error here would make every outbound
/// connection from an unprivileged Linux process fail.
#[cfg(target_os = "linux")]
pub(crate) fn mark<F: AsFd>(fd: &F) -> io::Result<()> {
    match nix::sys::socket::setsockopt(fd, nix::sys::socket::sockopt::Mark, &MARK_VALUE) {
        Err(nix::errno::Errno::EPERM) => {
            tracing::debug!("SO_MARK setsockopt: EPERM (no CAP_NET_ADMIN/CAP_NET_RAW); continuing");
            Ok(())
        }
        other => other.map_err(io::Error::from),
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn mark<F: AsFd>(_fd: &F) -> io::Result<()> {
    Ok(())
}

/// Whether `ip` is link-local — IPv4 `169.254.0.0/16` or IPv6 `fe80::/10`.
/// These reach the host's own metadata/autoconfig surface (notably the cloud
/// IMDS at `169.254.169.254`) and are never a legitimate sandbox egress target.
pub fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets()[0] == 169 && v4.octets()[1] == 254,
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Whether `ip` is a destination the sandbox must never reach directly:
/// loopback, unspecified (`0.0.0.0` / `::`), or link-local. Canonicalizes first
/// so an IPv4-mapped IPv6 form (`::ffff:127.0.0.1`) — which the raw
/// `is_loopback`/`is_link_local` checks miss but Linux still routes to the host
/// — is judged as its IPv4 form. Shared by every egress enforcement point (the
/// connect guard, the DNS pin filter, the CONNECT/SNI target check) so they
/// can't drift. Private ranges (10/8, 172.16/12, 192.168/16) deliberately pass:
/// reaching a private DB is the whole point of raw egress.
pub fn is_disallowed_egress_ip(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    ip.is_loopback() || ip.is_unspecified() || is_link_local(ip)
}

/// Resolve `host` (see [`crate::resolver`]) and connect to it on `port` via a
/// marked TCP socket.
///
/// UNCHECKED: connects to whatever `host` resolves to, including loopback and
/// link-local. Use only for trusted infra dials (the Lens upstream relay, the
/// control-plane socket, a server-injected forward bridge). For sandbox egress
/// — where `host` is a policy/SNI/Host hostname whose resolution an attacker
/// may influence — use [`connect_tcp_egress`], which rejects those addresses.
pub async fn connect_tcp_resolve(host: &str, port: u16) -> io::Result<TcpStream> {
    let resolved = crate::resolver::resolve_first(host, port).await?;
    connect_marked(resolved).await
}

/// Like [`connect_tcp_resolve`], but refuses a destination that resolves to a
/// loopback, link-local, or unspecified address (see [`is_disallowed_egress_ip`]
/// for the IPv4-mapped-IPv6 canonicalization). This is the SSRF floor for every
/// sandbox egress dial: an allowed *hostname* whose DNS answer (possibly
/// attacker-controlled — a wildcard-allowed name, DNS spoofing) points at
/// `127.0.0.1` or `169.254.169.254` would otherwise reach the host itself or
/// cloud metadata, since the marked socket bypasses the nftables cage. The IP
/// is checked *after* resolution, closing the gap that a string-level target
/// check (which only sees the hostname) leaves open.
pub async fn connect_tcp_egress(host: &str, port: u16) -> io::Result<TcpStream> {
    connect_tcp_egress_where(host, port, |_| true).await
}

/// [`connect_tcp_egress`] plus a caller-supplied check on the resolved address.
/// `admits` runs after the SSRF floor and before the dial, on the exact address
/// about to be connected, so a later DNS answer can't change the decision.
/// The predicate is a parameter so this module stays policy-free.
pub async fn connect_tcp_egress_where(
    host: &str,
    port: u16,
    admits: impl FnOnce(IpAddr) -> bool,
) -> io::Result<TcpStream> {
    let resolved = crate::resolver::resolve_first(host, port).await?;
    if is_disallowed_egress_ip(resolved.ip()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "egress to {} (loopback/link-local/unspecified) denied",
                resolved.ip()
            ),
        ));
    }
    if !admits(resolved.ip()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("egress to {} denied by policy", resolved.ip()),
        ));
    }
    connect_marked(resolved).await
}

async fn connect_marked(resolved: SocketAddr) -> io::Result<TcpStream> {
    let socket = if resolved.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    mark(&socket)?;
    socket.connect(resolved).await
}

/// Bind a UDP socket and mark it. Used by the DNS stub for its upstream
/// resolver socket, so query packets aren't redirected back to the stub.
pub async fn bind_udp(local: SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(local).await?;
    mark(&socket)?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_local_classification() {
        assert!(is_link_local("169.254.169.254".parse().unwrap()));
        assert!(is_link_local("169.254.0.1".parse().unwrap()));
        assert!(is_link_local("fe80::1".parse().unwrap()));
        assert!(is_link_local("febf::1".parse().unwrap()));
        // Not link-local: public, private, and the .254 boundary of 169.x.
        assert!(!is_link_local("1.2.3.4".parse().unwrap()));
        assert!(!is_link_local("10.20.0.5".parse().unwrap()));
        assert!(!is_link_local("169.253.0.1".parse().unwrap()));
        assert!(!is_link_local("fec0::1".parse().unwrap()));
    }

    #[tokio::test]
    async fn egress_rejects_loopback_literal() {
        let err = connect_tcp_egress("127.0.0.1", 9).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn the_policy_predicate_sees_the_resolved_address_and_can_refuse_it() {
        // A private address the SSRF floor deliberately permits, so only the
        // predicate can stop it.
        let mut seen = None;
        let err = connect_tcp_egress_where("10.0.0.5", 22, |ip| {
            seen = Some(ip);
            false
        })
        .await
        .unwrap_err();
        assert_eq!(seen, Some("10.0.0.5".parse().unwrap()));
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn egress_rejects_link_local_literal() {
        let err = connect_tcp_egress("169.254.169.254", 9).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn egress_rejects_mapped_loopback_literal() {
        // IPv4-mapped IPv6 must be canonicalized before the check — Linux still
        // routes ::ffff:127.0.0.1 to the host.
        let err = connect_tcp_egress("::ffff:127.0.0.1", 9).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn egress_rejects_unspecified_literal() {
        // 0.0.0.0 is a plausible (blackhole-list) A record and connect(2) sends
        // it to a host-local service.
        let err = connect_tcp_egress("0.0.0.0", 9).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn egress_rejects_hostname_resolving_to_loopback() {
        // The actual attack shape: an allowed hostname whose DNS answer points
        // back at the host. `localhost` resolves to a loopback address.
        let err = connect_tcp_egress("localhost", 9).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn resolve_still_connects_to_loopback() {
        // The unchecked primitive must remain usable for trusted infra dials
        // (e.g. a loopback Lens upstream relay) — guarding it would break them.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let _ = l.accept().await;
        });
        let stream = connect_tcp_resolve(&addr.ip().to_string(), addr.port()).await;
        assert!(
            stream.is_ok(),
            "trusted primitive must still reach loopback"
        );
        accept.abort();
    }
}
