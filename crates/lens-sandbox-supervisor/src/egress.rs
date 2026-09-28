//! A workload `connect()` that a runtime holds: the proxy judges and serves
//! it as it serves a redirected connection.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;

use bytes::Bytes;
use lens_sandbox_core::channel::{self, ConnectReply, Held};
use lens_sandbox_core::peer_process::ActorContext;
use lens_sandbox_core::proxy::{ProxyState, serve_egress};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tonic::Streaming;

/// The supervisor dials for the workload, so an address of the supervisor
/// host would reach the supervisor's own services. Only a local address can
/// be bound, so a bind decides it; loopback also without IPv6. A service
/// address that forwards to the supervisor is not local: the network policy
/// of the consumer must close that one.
pub(crate) fn is_own_address(ip: IpAddr) -> bool {
    ip.to_canonical().is_loopback() || UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok()
}

/// Replies with the decision. After `Allowed`, the exchange carries the
/// bytes of the connection, and the proxy can still close it.
pub(crate) async fn serve(
    held: Held,
    outbound: mpsc::Sender<Bytes>,
    mut inbound: Streaming<Bytes>,
    state: Arc<ProxyState>,
    is_own: fn(IpAddr) -> bool,
) {
    let destination = held.destination;
    let relay_side = if is_own(destination.ip()) {
        tracing::warn!(%destination, "refused a workload connect to the supervisor itself");
        None
    } else {
        match loopback_pair().await {
            Ok((proxy_side, relay_side)) => {
                let actor = ActorContext::attributed(held.process.into());
                tokio::spawn(async move {
                    if let Err(error) = serve_egress(proxy_side, destination, actor, state).await {
                        tracing::debug!(%destination, %error, "egress ended");
                    }
                });
                Some(relay_side)
            }
            Err(error) => {
                tracing::warn!(%destination, %error, "no loopback relay");
                None
            }
        }
    };
    let reply = match relay_side {
        Some(_) => ConnectReply::Allowed,
        None => ConnectReply::Denied,
    };
    if outbound.send(channel::encode(&reply)).await.is_err() {
        return;
    }
    let Some(relay_side) = relay_side else {
        // The runtime ends the call after a denial; ending it here first
        // would cancel the reply.
        drop(outbound);
        while let Ok(Some(_)) = inbound.message().await {}
        return;
    };
    if let Err(error) = channel::pump(relay_side, outbound, inbound).await {
        tracing::debug!(%destination, %error, "relay closed");
    }
}

/// `serve_egress` takes a TCP stream, so the relay is the other end of a
/// loopback connection.
async fn loopback_pair() -> std::io::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let relay_side = TcpStream::connect(listener.local_addr()?).await?;
    let expected = relay_side.local_addr()?;
    loop {
        let (proxy_side, peer) = listener.accept().await?;
        if peer == expected {
            return Ok((proxy_side, relay_side));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_supervisor_host_is_its_own_address() {
        assert!(is_own_address("127.0.0.1".parse().unwrap()));
        assert!(is_own_address("::1".parse().unwrap()));
        assert!(is_own_address("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_own_address("0.0.0.0".parse().unwrap()));
        assert!(!is_own_address("192.0.2.10".parse().unwrap()));
    }
}
