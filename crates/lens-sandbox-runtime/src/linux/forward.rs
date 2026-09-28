//! One loopback forward: an inbound stream of the supervisor to a port in
//! the workload.

use std::net::Ipv4Addr;

use lens_sandbox_core::channel::{
    self, Open, boundary::isolation_boundary_client::IsolationBoundaryClient,
};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;

use crate::linux::relay;

/// When nothing listens on the port, the `Exchange` opens and ends at once,
/// so the supervisor learns of the failure without a timeout.
pub(crate) async fn serve(id: u64, port: u16, mut client: IsolationBoundaryClient<Channel>) {
    let local = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await;
    let (outbound, outbound_rx) = mpsc::channel(relay::QUEUE);
    if outbound
        .send(channel::encode(&Open::Forward { id }))
        .await
        .is_err()
    {
        return;
    }
    let inbound = match client.exchange(ReceiverStream::new(outbound_rx)).await {
        Ok(response) => response.into_inner(),
        Err(status) => {
            tracing::warn!(id, %status, "loopback forward failed to open");
            return;
        }
    };
    match local {
        Ok(stream) => {
            if let Err(error) = relay::pump(stream, outbound, inbound).await {
                tracing::debug!(id, %error, "loopback forward closed");
            }
        }
        Err(error) => tracing::warn!(id, port, %error, "nothing to forward to"),
    }
}
