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
use std::net::SocketAddr;
use std::os::fd::AsFd;

use tokio::net::{TcpStream, UdpSocket};

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
///
/// Noted at debug rather than warned about, because this is the per-dial
/// helper: `MarkedEgress::connect` and `bind_udp` call it for every outbound
/// socket, and one warning per socket says nothing a reader can act on. Where
/// a refusal does matter — a listener, whose replies to a nested namespace are
/// then judged as ordinary egress and refused — `listen.rs` reads the mark
/// back and warns there, once, in the code that knows what it just bound.
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

/// The guest judge's sockets: marked, so the nftables redirect lets them pass.
#[cfg(feature = "proxy")]
pub struct MarkedEgress;

#[cfg(feature = "proxy")]
#[async_trait::async_trait]
impl crate::egress::Egress for MarkedEgress {
    async fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        let socket = crate::egress::plain_socket(addr)?;
        mark(&socket)?;
        socket.connect(addr).await
    }

    async fn bind_udp(&self, local: SocketAddr) -> io::Result<UdpSocket> {
        bind_udp(local).await
    }
}

/// Bind a UDP socket and mark it, so the stub's own upstream query is not redirected back to the stub.
pub(crate) async fn bind_udp(local: SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(local).await?;
    mark(&socket)?;
    Ok(socket)
}
