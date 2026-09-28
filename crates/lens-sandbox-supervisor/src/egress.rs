//! A workload `connect()` that a runtime holds: the proxy judges and serves
//! it as it serves a redirected connection.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;

use bytes::Bytes;
use lens_sandbox_core::channel::{self, ConnectReply, WireProcess};
use lens_sandbox_core::peer_process::ActorContext;
use lens_sandbox_core::proxy::{ProxyState, serve_egress};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tonic::{Status, Streaming};

use crate::relay;

/// The supervisor dials for the workload, so an address of the supervisor
/// host would reach the supervisor's own services. Only a local address can
/// be bound, so a bind decides it; loopback also without IPv6. A service
/// address that forwards to the supervisor is not local: the network policy
/// of the consumer must close that one.
pub(crate) fn is_own_address(ip: IpAddr) -> bool {
    ip.is_loopback() || UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok()
}

/// The first reply is the decision. After `Allowed`, the chunks are the
/// bytes of the connection, and the proxy can still close it.
pub(crate) async fn serve(
    destination: SocketAddr,
    process: WireProcess,
    inbound: Streaming<Bytes>,
    state: Arc<ProxyState>,
    is_own: fn(IpAddr) -> bool,
) -> Result<mpsc::Receiver<Result<Bytes, Status>>, Status> {
    let (outbound, outbound_rx) = mpsc::channel(relay::QUEUE);
    if is_own(destination.ip()) {
        tracing::warn!(%destination, "refused a workload connect to the supervisor itself");
        let _ = outbound.try_send(Ok(channel::encode(&ConnectReply::Denied)));
        return Ok(outbound_rx);
    }
    let (proxy_side, relay_side) = loopback_pair()
        .await
        .map_err(|e| Status::internal(format!("loopback relay: {e}")))?;
    let _ = outbound.try_send(Ok(channel::encode(&ConnectReply::Allowed)));
    let actor = ActorContext::attributed(process.into());
    tokio::spawn(async move {
        if let Err(error) = serve_egress(proxy_side, destination, actor, state).await {
            tracing::debug!(%destination, %error, "egress ended");
        }
    });
    tokio::spawn(async move {
        if let Err(error) = relay::pump(relay_side, outbound, inbound).await {
            tracing::debug!(%destination, %error, "relay closed");
        }
    });
    Ok(outbound_rx)
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
        assert!(is_own_address("0.0.0.0".parse().unwrap()));
        assert!(!is_own_address("192.0.2.10".parse().unwrap()));
    }
}
