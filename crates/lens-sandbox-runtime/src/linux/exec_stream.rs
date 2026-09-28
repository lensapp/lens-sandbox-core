//! One exec session: `exec_protocol` frames between an `Exchange` and the
//! exec manager.

use bytes::Bytes;
use lens_sandbox_core::channel::{
    self, Open, boundary::isolation_boundary_client::IsolationBoundaryClient,
};
use lens_sandbox_core::exec_manager::ExecManager;
use lens_sandbox_core::exec_protocol::IncomingMessage;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;

use crate::linux::relay;

/// Runs until either side ends the session. An exec keeps running after
/// that, and a later session can reattach to it.
pub(crate) async fn serve(
    session: String,
    exec: ExecManager,
    mut client: IsolationBoundaryClient<Channel>,
) {
    let (outbound, outbound_rx) = mpsc::channel(relay::QUEUE);
    if outbound
        .send(channel::encode(&Open::Exec {
            session: session.clone(),
        }))
        .await
        .is_err()
    {
        return;
    }
    let mut inbound = match client.exchange(ReceiverStream::new(outbound_rx)).await {
        Ok(response) => response.into_inner(),
        Err(status) => {
            tracing::warn!(%session, %status, "exec session failed to open");
            return;
        }
    };
    let (frames, mut frames_rx) = mpsc::unbounded_channel::<String>();
    let upload = async {
        while let Some(frame) = frames_rx.recv().await {
            if outbound.send(Bytes::from(frame)).await.is_err() {
                return;
            }
        }
    };
    let download = async {
        loop {
            match inbound.message().await {
                Ok(Some(chunk)) => match serde_json::from_slice::<IncomingMessage>(&chunk) {
                    Ok(message) => exec.handle(message, &frames).await,
                    Err(error) => tracing::warn!(%session, %error, "malformed exec frame"),
                },
                Ok(None) => return,
                Err(status) => {
                    tracing::debug!(%session, %status, "exec session lost");
                    return;
                }
            }
        }
    };
    tokio::select! {
        () = upload => {}
        () = download => {}
    }
}
