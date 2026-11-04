//! How the judge opens a socket toward the internet, and what it never
//! reaches. The cage decides the socket: in the guest it is marked so the
//! nftables redirect lets it pass ([`crate::sock_mark::MarkedEgress`]); on a
//! host that judges for a guest it is plain, and refuses the host itself
//! ([`HostEgress`]). The SSRF floor — loopback, link-local, unspecified — is
//! the same for both, and lives here so no dialer can skip it.

use std::io;
use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// The sockets a judge dials with; the cage it runs in decides how they are built.
#[async_trait]
pub trait Egress: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<SocketAddr> {
        crate::resolver::resolve_first(host, port).await
    }
    async fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream>;
    /// The DNS stub's socket to its upstream resolver only; it carries no workload datagram and makes no own-address refusal.
    async fn bind_udp(&self, local: SocketAddr) -> io::Result<UdpSocket>;
}

/// A host that judges for a guest: plain sockets, and nothing that reaches the host's own services.
pub struct HostEgress;

#[async_trait]
impl Egress for HostEgress {
    async fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        if is_own_address(addr.ip()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("egress to {} (the host's own address) denied", addr.ip()),
            ));
        }
        plain_socket(addr)?.connect(addr).await
    }

    async fn bind_udp(&self, local: SocketAddr) -> io::Result<UdpSocket> {
        UdpSocket::bind(local).await
    }
}

pub(crate) fn plain_socket(addr: SocketAddr) -> io::Result<TcpSocket> {
    if addr.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
}

/// Whether an egress dialled from this process would reach this process's own host: loopback, or any address a socket can bind here.
pub fn is_own_address(ip: IpAddr) -> bool {
    ip.to_canonical().is_loopback() || std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok()
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

/// Resolve `host` (see [`crate::resolver`]) and connect to it on `port`.
///
/// Unchecked by the SSRF floor: connects to whatever `host` resolves to,
/// including loopback and link-local, though the port can still refuse
/// ([`HostEgress`] refuses this host's own addresses). Use only for trusted
/// infra dials (the Lens upstream relay, the control-plane socket, a
/// server-injected forward bridge). For sandbox egress — where `host` is a
/// policy/SNI/Host hostname whose resolution an attacker may influence — use
/// [`connect_tcp_egress`], which rejects those addresses.
pub async fn connect_tcp_resolve(
    egress: &dyn Egress,
    host: &str,
    port: u16,
) -> io::Result<TcpStream> {
    let resolved = egress.resolve(host, port).await?;
    egress.connect(resolved).await
}

/// Like [`connect_tcp_resolve`], but refuses a destination that resolves to a
/// loopback, link-local, or unspecified address (see [`is_disallowed_egress_ip`]
/// for the IPv4-mapped-IPv6 canonicalization). This is the SSRF floor for every
/// sandbox egress dial: an allowed *hostname* whose DNS answer (possibly
/// attacker-controlled — a wildcard-allowed name, DNS spoofing) points at
/// `127.0.0.1` or `169.254.169.254` would otherwise reach the host itself or
/// cloud metadata, since the judge's socket is not caged. The IP
/// is checked *after* resolution, closing the gap that a string-level target
/// check (which only sees the hostname) leaves open.
pub async fn connect_tcp_egress(
    egress: &dyn Egress,
    host: &str,
    port: u16,
) -> io::Result<TcpStream> {
    connect_tcp_egress_where(egress, host, port, |_| true).await
}

/// [`connect_tcp_egress`] plus a caller-supplied check on the resolved address.
/// `admits` runs after the SSRF floor and before the dial, on the exact address
/// about to be connected, so a later DNS answer can't change the decision.
/// The predicate is a parameter so this module stays policy-free.
pub async fn connect_tcp_egress_where(
    egress: &dyn Egress,
    host: &str,
    port: u16,
    admits: impl FnOnce(IpAddr) -> bool + Send,
) -> io::Result<TcpStream> {
    let resolved = egress.resolve(host, port).await?;
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
    egress.connect(resolved).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sock_mark::MarkedEgress;
    use std::net::Ipv4Addr;

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
        let err = connect_tcp_egress(&MarkedEgress, "127.0.0.1", 9)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn the_policy_predicate_sees_the_resolved_address_and_can_refuse_it() {
        // A private address the SSRF floor deliberately permits, so only the
        // predicate can stop it.
        let mut seen = None;
        let err = connect_tcp_egress_where(&MarkedEgress, "10.0.0.5", 22, |ip| {
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
        let err = connect_tcp_egress(&MarkedEgress, "169.254.169.254", 9)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn egress_rejects_mapped_loopback_literal() {
        // IPv4-mapped IPv6 must be canonicalized before the check — Linux still
        // routes ::ffff:127.0.0.1 to the host.
        let err = connect_tcp_egress(&MarkedEgress, "::ffff:127.0.0.1", 9)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn egress_rejects_unspecified_literal() {
        // 0.0.0.0 is a plausible (blackhole-list) A record and connect(2) sends
        // it to a host-local service.
        let err = connect_tcp_egress(&MarkedEgress, "0.0.0.0", 9)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn egress_rejects_hostname_resolving_to_loopback() {
        // The actual attack shape: an allowed hostname whose DNS answer points
        // back at the host. `localhost` resolves to a loopback address.
        let err = connect_tcp_egress(&MarkedEgress, "localhost", 9)
            .await
            .unwrap_err();
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
        let stream = connect_tcp_resolve(&MarkedEgress, &addr.ip().to_string(), addr.port()).await;
        assert!(
            stream.is_ok(),
            "trusted primitive must still reach loopback"
        );
        accept.abort();
    }

    #[test]
    fn the_embedder_host_is_its_own_address() {
        assert!(is_own_address(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_own_address("::1".parse().unwrap()));
        assert!(is_own_address("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_own_address("0.0.0.0".parse().unwrap()));
        assert!(!is_own_address("192.0.2.10".parse().unwrap()));
    }

    /// A host judging for a guest refuses even the dials the SSRF floor
    /// permits when they would land on the host itself: a service on the
    /// host's LAN address is the embedder's, not the workload's.
    #[tokio::test]
    async fn the_host_refuses_its_own_services() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let err = HostEgress.connect(addr).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("the host's own address"), "{err}");
    }

    #[tokio::test]
    async fn the_host_binds_a_plain_udp_socket() {
        let socket = HostEgress
            .bind_udp("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        assert!(socket.local_addr().unwrap().port() != 0);
    }
}
