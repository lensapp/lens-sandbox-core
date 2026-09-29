//! The mutual TLS client to one runtime.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

use hyper_util::rt::TokioIo;
use lens_sandbox_core::channel::{
    self, ChannelTls, boundary::isolation_boundary_client::IsolationBoundaryClient,
};
use tonic::transport::{Channel, Endpoint};

/// Where a runtime serves the channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeAddress {
    Tcp(SocketAddr),
    /// A socket on a volume that the supervisor shares with the workload.
    Unix(PathBuf),
}

/// The channel connects on first use and again after each loss.
pub(crate) fn client(
    container: &str,
    address: RuntimeAddress,
    tls: &ChannelTls,
) -> Result<IsolationBoundaryClient<Channel>, tonic::transport::Error> {
    let tls = tls.client(container);
    let channel = match address {
        RuntimeAddress::Tcp(address) => {
            channel::endpoint(Endpoint::from_shared(format!("https://{address}"))?)
                .tls_config(tls)?
                .connect_lazy()
        }
        RuntimeAddress::Unix(path) => {
            // TLS needs an https URI; the socket path replaces its address.
            let uri = format!("https://{}", channel::runtime_name(container));
            channel::endpoint(Endpoint::from_shared(uri)?)
                .tls_config(tls)?
                .connect_with_connector_lazy(tower::service_fn(move |_| {
                    let path = path.clone();
                    async move {
                        Ok::<_, io::Error>(TokioIo::new(
                            tokio::net::UnixStream::connect(path).await?,
                        ))
                    }
                }))
        }
    };
    Ok(IsolationBoundaryClient::new(channel))
}
