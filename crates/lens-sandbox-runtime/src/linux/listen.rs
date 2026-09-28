//! The mutual TLS listener of the channel.

use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

use lens_sandbox_core::channel::{
    self, ChannelTls,
    boundary::isolation_boundary_server::{IsolationBoundary, IsolationBoundaryServer},
};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::server::TcpIncoming;

use crate::linux::config::Listen;

/// Holds `ca.pem`, `cert.pem` and `key.pem` of the runtime. The key is safe
/// only inside the private root, which Landlock hides from the workload, so
/// the path is fixed.
pub(crate) const CHANNEL_DIR: &str = "/.lens/channel";

pub(crate) enum Incoming {
    Tcp(TcpIncoming),
    Unix(UnixListenerStream),
}

pub(crate) fn bind(listen: &Listen) -> io::Result<Incoming> {
    match listen {
        Listen::Tcp(address) => TcpIncoming::bind(*address).map(Incoming::Tcp),
        Listen::Unix(path) => bind_unix(path).map(Incoming::Unix),
    }
}

/// Replaces a socket that an earlier run left behind. A workload process can
/// connect to the socket, as Landlock does not stop a connect to a socket
/// path, but without the channel key it fails the TLS handshake.
fn bind_unix(path: &Path) -> io::Result<UnixListenerStream> {
    if std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket()) {
        std::fs::remove_file(path)?;
    }
    Ok(UnixListenerStream::new(tokio::net::UnixListener::bind(
        path,
    )?))
}

/// Returns only with the reason the listener stopped.
pub(crate) async fn serve(
    incoming: Incoming,
    tls: &ChannelTls,
    boundary: impl IsolationBoundary,
) -> io::Error {
    let router = match channel::server().tls_config(tls.server()) {
        Ok(mut server) => server.add_service(IsolationBoundaryServer::new(boundary)),
        Err(error) => return io::Error::other(error),
    };
    let served = match incoming {
        Incoming::Tcp(incoming) => router.serve_with_incoming(incoming).await,
        Incoming::Unix(incoming) => router.serve_with_incoming(incoming).await,
    };
    match served {
        Ok(()) => io::Error::other("the channel listener stopped"),
        Err(error) => io::Error::other(error),
    }
}

pub(crate) fn read_tls(dir: &Path) -> io::Result<ChannelTls> {
    let read = |name: &str| {
        let path = dir.join(name);
        std::fs::read(&path)
            .map_err(|e| io::Error::new(e.kind(), format!("read {}: {e}", path.display())))
    };
    Ok(ChannelTls {
        ca: read("ca.pem")?,
        cert: read("cert.pem")?,
        key: read("key.pem")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use hyper_util::rt::TokioIo;
    use lens_sandbox_core::channel::boundary::isolation_boundary_client::IsolationBoundaryClient;
    use std::path::PathBuf;
    use std::pin::Pin;
    use tokio_stream::Stream;
    use tonic::transport::Endpoint;
    use tonic::{Request, Response, Status, Streaming};

    type ChunkStream = Pin<Box<dyn Stream<Item = Result<Bytes, Status>> + Send>>;

    /// Answers each exchange with `hello`.
    struct Hello;

    #[tonic::async_trait]
    impl IsolationBoundary for Hello {
        type ExchangeStream = ChunkStream;
        type MediateStream = ChunkStream;

        async fn exchange(
            &self,
            _: Request<Streaming<Bytes>>,
        ) -> Result<Response<ChunkStream>, Status> {
            let answer = Bytes::from_static(b"hello");
            Ok(Response::new(Box::pin(tokio_stream::once(Ok(answer)))))
        }

        async fn mediate(
            &self,
            _: Request<Streaming<Bytes>>,
        ) -> Result<Response<ChunkStream>, Status> {
            Err(Status::unimplemented("mediate"))
        }
    }

    struct TestPki {
        supervisor: ChannelTls,
        runtime: ChannelTls,
    }

    fn test_pki() -> TestPki {
        // The dev-dependency on the supervisor adds a second rustls provider,
        // and the test server takes the default.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf = |name: String| {
            let key = rcgen::KeyPair::generate().unwrap();
            let params = rcgen::CertificateParams::new(vec![name]).unwrap();
            let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
            ChannelTls {
                ca: ca.pem().into_bytes(),
                cert: cert.pem().into_bytes(),
                key: key.serialize_pem().into_bytes(),
            }
        };
        TestPki {
            supervisor: leaf(channel::SUPERVISOR_NAME.into()),
            runtime: leaf(channel::runtime_name("agent")),
        }
    }

    async fn say_hello(socket: PathBuf, supervisor: &ChannelTls) -> Bytes {
        let channel = Endpoint::from_static("https://runtime")
            .tls_config(supervisor.client("agent"))
            .unwrap()
            .connect_with_connector(tower::service_fn(move |_| {
                let socket = socket.clone();
                async move {
                    Ok::<_, io::Error>(TokioIo::new(tokio::net::UnixStream::connect(socket).await?))
                }
            }))
            .await
            .unwrap();
        let mut answers = IsolationBoundaryClient::new(channel)
            .exchange(tokio_stream::empty())
            .await
            .unwrap()
            .into_inner();
        answers.message().await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn the_supervisor_reaches_the_runtime_over_a_unix_socket() {
        let TestPki {
            supervisor,
            runtime,
        } = test_pki();
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("channel.sock");
        // An earlier run left its socket behind.
        drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
        let incoming = bind(&Listen::Unix(socket.clone())).unwrap();
        tokio::spawn(async move { serve(incoming, &runtime, Hello).await });
        assert_eq!(say_hello(socket, &supervisor).await, "hello");
    }

    #[test]
    fn the_channel_key_is_inside_the_private_root() {
        let private_root = Path::new("/").join(crate::linux::landlock::PRIVATE_ROOT);
        assert!(Path::new(CHANNEL_DIR).starts_with(private_root));
    }

    #[test]
    fn a_missing_key_names_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let Err(error) = read_tls(dir.path()) else {
            panic!("read an empty directory");
        };
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().contains("ca.pem"), "{error}");
    }
}
