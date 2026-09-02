//! Listening sockets that may be opened before their address exists.
//!
//! The supervisor binds loopback, which is always there, and — when
//! [`crate::config::EXTRA_LISTEN_IPS_ENV`] names one — a veth address, which is
//! not. The sidecar that owns the nested namespace creates that veth, and it
//! starts after the supervisor. A plain `bind` would return `EADDRNOTAVAIL` and
//! take the whole proxy down at startup, which is the cage failing to exist
//! rather than failing closed.
//!
//! `IP_FREEBIND` is the kernel's answer to exactly this: bind an address that is
//! not assigned yet. It grants no reach. The socket still only receives what
//! arrives for that address, and the address still only answers on the link it
//! is eventually assigned to — unlike `route_localnet`, which is the setting
//! this whole design refused.
//!
//! Every listener here also carries [`crate::sock_mark::MARK_VALUE`], because
//! what it sends is proxy-origin traffic and that is what the mark means. It
//! was not needed while the only listeners were on loopback: a reply then went
//! to a loopback destination, which `output_filter` accepts outright. A reply
//! to a nested namespace leaves over the veth instead, and walks the chain to
//! the UDP queue, where the shared egress floor refuses a link-local
//! destination — so a DNS answer would be dropped and would file a
//! `blocked-destination` audit event on the way. Marked, it is taken by the
//! chain's first rule. TCP replies already pass on `ct state established`, so
//! marking both lanes changes nothing there and keeps one rule to remember.

use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};

/// Deliberately above `std`'s 128. `somaxconn` caps it either way, and the
/// supervisor is the only thing between a burst of sandbox connections and a
/// refusal.
const BACKLOG: i32 = 1024;

/// Open a TCP listener on `addr`, whether or not `addr` is assigned yet.
pub(crate) fn tcp(addr: SocketAddr) -> io::Result<tokio::net::TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    // `std::net::TcpListener::bind` sets this; keep the behaviour identical.
    socket.set_reuse_address(true)?;
    allow_absent_address(&socket, addr)?;
    socket.bind(&addr.into())?;
    socket.listen(BACKLOG)?;
    mark_listener(&socket, addr)?;
    socket.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(socket.into())
}

/// Open a UDP socket on `addr`, whether or not `addr` is assigned yet.
pub(crate) fn udp(addr: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    // No `SO_REUSEADDR` here: `std::net::UdpSocket::bind` does not set it, and
    // two stubs answering one address is not a state worth reaching quietly.
    allow_absent_address(&socket, addr)?;
    socket.bind(&addr.into())?;
    mark_listener(&socket, addr)?;
    socket.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(socket.into())
}

/// Mark the socket, and say so when the mark did not take.
///
/// [`crate::sock_mark::mark`] tolerates `EPERM` — it has to, or every outbound
/// connection from an unprivileged process would fail — and reports it at
/// debug, because it cannot tell a listener from a dial. Here we know, and an
/// unmarked listener is worth a word: its replies to a nested namespace walk
/// past `meta mark {mark} accept` to the UDP queue, where the egress floor
/// refuses a link-local destination, so the cage silently drops its own DNS
/// answers. One read-back per listener buys a log line that names the address.
#[cfg(target_os = "linux")]
fn mark_listener(socket: &Socket, addr: SocketAddr) -> io::Result<()> {
    use std::os::fd::AsFd;

    crate::sock_mark::mark(socket)?;
    let applied =
        nix::sys::socket::getsockopt(&socket.as_fd(), nix::sys::socket::sockopt::Mark).unwrap_or(0);
    if applied != crate::sock_mark::MARK_VALUE {
        tracing::warn!(
            %addr,
            "listener carries no proxy mark; replies to a nested namespace \
             will be refused as ordinary egress"
        );
    }
    Ok(())
}

/// Elsewhere the mark is a no-op, so there is nothing to read back.
#[cfg(not(target_os = "linux"))]
fn mark_listener(socket: &Socket, _addr: SocketAddr) -> io::Result<()> {
    crate::sock_mark::mark(socket)
}

#[cfg(target_os = "linux")]
fn allow_absent_address(socket: &Socket, addr: SocketAddr) -> io::Result<()> {
    match addr {
        SocketAddr::V4(_) => socket.set_freebind_v4(true),
        SocketAddr::V6(_) => socket.set_freebind_v6(true),
    }
}

/// Elsewhere there is no such option, and no nested namespace either — the
/// address is expected to exist, and `bind` says so if it does not.
#[cfg(not(target_os = "linux"))]
fn allow_absent_address(_socket: &Socket, _addr: SocketAddr) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    fn read_mark<F: std::os::fd::AsFd>(fd: &F) -> u32 {
        nix::sys::socket::getsockopt(fd, nix::sys::socket::sockopt::Mark).expect("read SO_MARK")
    }

    #[tokio::test]
    async fn tcp_binds_loopback_like_the_std_listener() {
        let listener = tcp("127.0.0.1:0".parse().unwrap()).expect("bind");
        assert!(listener.local_addr().expect("local addr").port() != 0);
    }

    #[tokio::test]
    async fn udp_binds_loopback_like_the_std_socket() {
        let socket = udp("127.0.0.1:0".parse().unwrap()).expect("bind");
        assert!(socket.local_addr().expect("local addr").port() != 0);
    }

    /// A listener's replies must pass the cage's first rule, or a DNS answer to
    /// a nested namespace is judged as ordinary egress and refused.
    ///
    /// Compared against a socket [`crate::sock_mark::mark`] marked directly,
    /// not against `MARK_VALUE`. Setting `SO_MARK` needs a capability, and
    /// `mark` deliberately tolerates being refused it — so on a runner without
    /// that capability a bare `MARK_VALUE` assertion fails for a reason that
    /// has nothing to do with this module. The comparison says what is meant
    /// instead: a listener is marked exactly as the supervisor's own sockets
    /// are. Where the capability is absent both read zero and this holds only
    /// the shape — [`a_privileged_listener_carries_mark_value`] is the half
    /// that bites, and the cage job is where it runs.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_listener_is_marked_like_any_supervisor_socket() {
        let reference =
            Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).expect("socket");
        crate::sock_mark::mark(&reference).expect("mark");
        let expected = read_mark(&reference);

        let listener = tcp("127.0.0.1:0".parse().unwrap()).expect("bind");
        assert_eq!(read_mark(&listener), expected);
        let socket = udp("127.0.0.1:0".parse().unwrap()).expect("bind");
        assert_eq!(read_mark(&socket), expected);
    }

    /// The strict half of the test above: holding the capability, the mark must
    /// be `MARK_VALUE` itself, not merely whatever `mark` produced. Ignored
    /// because an unprivileged runner cannot set `SO_MARK` at all; the cage job
    /// runs it with `--ignored` under `sudo`, where the tolerated `EPERM` path
    /// can no longer hide a listener that was never marked.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "needs CAP_NET_ADMIN or CAP_NET_RAW; the cage job runs it"]
    async fn a_privileged_listener_carries_mark_value() {
        let listener = tcp("127.0.0.1:0".parse().unwrap()).expect("bind");
        assert_eq!(read_mark(&listener), crate::sock_mark::MARK_VALUE);
        let socket = udp("127.0.0.1:0".parse().unwrap()).expect("bind");
        assert_eq!(read_mark(&socket), crate::sock_mark::MARK_VALUE);
    }

    /// The point of the module. Without `IP_FREEBIND` this is `EADDRNOTAVAIL`.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tcp_binds_an_address_that_is_not_assigned_yet() {
        tcp("169.254.32.1:0".parse().unwrap()).expect("bind before assignment");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn udp_binds_an_address_that_is_not_assigned_yet() {
        udp("169.254.32.1:0".parse().unwrap()).expect("bind before assignment");
    }

    /// The limit of the trick, and the reason `parse_extra_listen_ips` accepts
    /// `169.254.0.0/16` alone. A v6 link-local bind needs a scope id, which a
    /// `SocketAddr` built from an `IpAddr` does not carry, and the kernel
    /// refuses it with `EINVAL` *before* it consults `IPV6_FREEBIND` — so this
    /// is not an address that merely does not exist yet. Measured: with the
    /// option set and without it, the errno is the same.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_v6_link_local_address_cannot_be_bound_at_all() {
        let err = tcp("[fe80::1]:0".parse().unwrap()).expect_err("must not bind");
        assert_eq!(err.raw_os_error(), Some(nix::libc::EINVAL));
    }
}
