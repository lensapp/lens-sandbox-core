//! One exec session: `exec_protocol` frames between an `Exchange` and the
//! exec manager.

use bytes::Bytes;
use lens_sandbox_core::channel;
use lens_sandbox_core::exec_manager::ExecManager;
use lens_sandbox_core::exec_protocol::IncomingMessage;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Streaming;

use crate::linux::boundary::ChunkStream;

/// Runs until either side ends the session. An exec keeps running after
/// that, and a later session can reattach to it.
pub(crate) fn serve(exec: ExecManager, mut inbound: Streaming<Bytes>) -> ChunkStream {
    let (outbound, outbound_rx) = mpsc::channel(channel::RELAY_QUEUE);
    tokio::spawn(async move {
        let (frames, mut frames_rx) = mpsc::unbounded_channel::<String>();
        let upload = async {
            while let Some(frame) = frames_rx.recv().await {
                if outbound.send(Ok(Bytes::from(frame))).await.is_err() {
                    return;
                }
            }
        };
        let download = async {
            loop {
                match inbound.message().await {
                    Ok(Some(chunk)) => match serde_json::from_slice::<IncomingMessage>(&chunk) {
                        Ok(message) => exec.handle(message, &frames).await,
                        Err(error) => tracing::warn!(%error, "malformed exec frame"),
                    },
                    Ok(None) => return,
                    Err(status) => {
                        tracing::debug!(%status, "exec session lost");
                        return;
                    }
                }
            }
        };
        tokio::select! {
            () = upload => {}
            () = download => {}
        }
    });
    Box::pin(ReceiverStream::new(outbound_rx))
}
