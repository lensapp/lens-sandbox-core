//! One loopback forward: an `Exchange` of the supervisor to a port in the
//! workload.

use std::net::Ipv4Addr;

use bytes::Bytes;
use lens_sandbox_core::channel;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Status, Streaming};

use crate::linux::boundary::ChunkStream;

pub(crate) async fn serve(port: u16, inbound: Streaming<Bytes>) -> Result<ChunkStream, Status> {
    let local = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .map_err(|e| Status::unavailable(format!("nothing to forward to on port {port}: {e}")))?;
    let (outbound, outbound_rx) = mpsc::channel(channel::RELAY_QUEUE);
    tokio::spawn(async move {
        if let Err(error) = channel::pump(local, outbound, inbound).await {
            tracing::debug!(port, %error, "loopback forward closed");
        }
    });
    Ok(Box::pin(ReceiverStream::new(outbound_rx)))
}
