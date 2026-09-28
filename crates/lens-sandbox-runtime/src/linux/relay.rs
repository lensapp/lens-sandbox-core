//! Raw bytes between a local TCP stream and one `Exchange`.

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tonic::Streaming;

pub(crate) const QUEUE: usize = 8;
const CHUNK: usize = 64 * 1024;

/// Copies bytes both ways until each side has closed. The local end of the
/// read half reaches the supervisor as the end of the client stream.
pub(crate) async fn pump(
    stream: TcpStream,
    outbound: mpsc::Sender<Bytes>,
    mut inbound: Streaming<Bytes>,
) -> std::io::Result<()> {
    let (mut from_local, mut to_local) = stream.into_split();
    let upload = async move {
        let mut buffer = vec![0_u8; CHUNK];
        loop {
            let read = from_local.read(&mut buffer).await?;
            if read == 0 {
                return Ok::<_, std::io::Error>(());
            }
            if outbound
                .send(Bytes::copy_from_slice(&buffer[..read]))
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
