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

use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};

/// Matches `std`'s own listener backlog, so nothing changes for loopback.
const BACKLOG: i32 = 1024;

/// Open a TCP listener on `addr`, whether or not `addr` is assigned yet.
pub(crate) fn tcp(addr: SocketAddr) -> io::Result<tokio::net::TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    // `std::net::TcpListener::bind` sets this; keep the behaviour identical.
    socket.set_reuse_address(true)?;
    allow_absent_address(&socket, addr)?;
    socket.bind(&addr.into())?;
    socket.listen(BACKLOG)?;
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
    socket.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(socket.into())
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
}
