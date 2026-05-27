//! Netfilter packet marking for proxy outbound sockets.
//!
//! The sandbox's nftables redirect chain catches *all* outbound traffic except
//! packets carrying `MARK_VALUE`. The proxy stamps its own sockets with that
//! mark via `SO_MARK` so that proxy → upstream connections aren't recursively
//! caught by the very rule that's supposed to redirect the agent's traffic.
//!
//! This decouples policy from the agent's UID — the nftables rules no longer
//! need to name a specific `meta skuid` value, so the agent can run as any user
//! the user-supplied image expects. Bypass via mark-spoofing requires
//! `CAP_NET_ADMIN`, which is dropped before exec'ing the agent.

use std::io;
use std::net::SocketAddr;
use std::os::fd::AsFd;

use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// Lens Sandbox-internal mark applied to every outbound socket from proxy/MITM/DNS.
///
/// Any unused 32-bit value works; we pick a recognisable nibble pattern.
/// Inside the sandbox netns we control the namespace, so collisions with
/// other mark consumers are vanishingly unlikely.
pub const MARK_VALUE: u32 = 0x4E_58_55_53; // "NXUS" in ASCII

/// Apply `SO_MARK = MARK_VALUE` to a socket. Linux-only — requires
/// `CAP_NET_ADMIN`. On other platforms this is a no-op so the rest of the
/// crate continues to compile (nftables enforcement is Linux-only anyway).
///
/// EPERM is tolerated: in production the supervisor holds CAP_NET_ADMIN
/// before privilege drop, and in tests / hosts without nftables rules there
/// is nothing to bypass. Returning the error here would make every outbound
/// connection from an unprivileged Linux process fail.
#[cfg(target_os = "linux")]
fn mark<F: AsFd>(fd: &F) -> io::Result<()> {
    match nix::sys::socket::setsockopt(fd, nix::sys::socket::sockopt::Mark, &MARK_VALUE) {
        Err(nix::errno::Errno::EPERM) => {
            tracing::debug!("SO_MARK setsockopt: EPERM (CAP_NET_ADMIN unavailable); continuing");
            Ok(())
        }
        other => other.map_err(io::Error::from),
    }
}

#[cfg(not(target_os = "linux"))]
fn mark<F: AsFd>(_fd: &F) -> io::Result<()> {
    Ok(())
}

/// Resolve `addr` (host:port) and connect via a marked TCP socket. Picks
/// the first DNS result; reconnect loops at the call site cover transient
/// failures of any single address.
pub async fn connect_tcp_resolve(addr: &str) -> io::Result<TcpStream> {
    let resolved = tokio::net::lookup_host(addr)
        .await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no addrs for {addr}")))?;
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
