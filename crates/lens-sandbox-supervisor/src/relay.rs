//! Raw bytes between a local stream and one `Exchange`.

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tonic::{Status, Streaming};

pub(crate) const QUEUE: usize = 8;
const CHUNK: usize = 64 * 1024;

/// Copies bytes both ways until each side has closed. The local end of the
/// read half reaches the runtime as the end of the response stream.
pub(crate) async fn pump(
    local: impl AsyncRead + AsyncWrite,
    outbound: mpsc::Sender<Result<Bytes, Status>>,
    mut inbound: Streaming<Bytes>,
) -> std::io::Result<()> {
    let (mut from_local, mut to_local) = tokio::io::split(local);
    let upload = async move {
        let mut buffer = vec![0_u8; CHUNK];
        loop {
            let read = from_local.read(&mut buffer).await?;
            if read == 0 {
                return Ok::<_, std::io::Error>(());
            }
            if outbound
                .send(Ok(Bytes::copy_from_slice(&buffer[..read])))
                .await
                .is_err()
            {
                return Ok(());
            }
        }
    };
    let download = async move {
        while let Some(chunk) = inbound.message().await.map_err(std::io::Error::other)? {
            to_local.write_all(&chunk).await?;
        }
        to_local.shutdown().await
    };
    let (up, down) = tokio::join!(upload, download);
    up.and(down)
}
