//! The mutual TLS client of the channel.

use std::io;
use std::path::{Path, PathBuf};

use hyper_util::rt::TokioIo;
use lens_sandbox_core::channel::{
    self, ChannelTls, SUPERVISOR_NAME, boundary::isolation_boundary_client::IsolationBoundaryClient,
};
use tonic::transport::{Channel, Endpoint};

use crate::linux::config::Supervisor;

/// The channel connects on first use and again after each loss, so the
/// client outlives a supervisor restart.
pub fn client(
    supervisor: &Supervisor,
    channel_dir: &Path,
) -> io::Result<IsolationBoundaryClient<Channel>> {
    let tls = read_tls(channel_dir)?.client();
    let channel = match supervisor {
        Supervisor::Tcp(uri) => channel::endpoint(Endpoint::from(uri.clone()))
            .tls_config(tls)
            .map_err(io::Error::other)?
            .connect_lazy(),
        Supervisor::Unix(path) => {
            // TLS needs an https URI; the socket path replaces its address.
            let endpoint = Endpoint::from_shared(format!("https://{SUPERVISOR_NAME}"))
                .map_err(io::Error::other)?;
            channel::endpoint(endpoint)
                .tls_config(tls)
                .map_err(io::Error::other)?
                .connect_with_connector_lazy(unix_connector(path.clone()))
        }
    };
    Ok(IsolationBoundaryClient::new(channel))
}

fn unix_connector(
    path: PathBuf,
) -> impl tower::Service<
    tonic::transport::Uri,
    Response = TokioIo<tokio::net::UnixStream>,
    Error = io::Error,
    Future = impl Send,
> + Send
+ 'static {
    tower::service_fn(move |_| {
        let path = path.clone();
        async move { Ok(TokioIo::new(tokio::net::UnixStream::connect(path).await?)) }
    })
}

fn read_tls(dir: &Path) -> io::Result<ChannelTls> {
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
    use lens_sandbox_core::channel::boundary::isolation_boundary_server::{
        IsolationBoundary, IsolationBoundaryServer,
    };
    use std::pin::Pin;
    use tokio_stream::Stream;
    use tonic::transport::server::{TlsConnectInfo, UdsConnectInfo};
    use tonic::{Request, Response, Status, Streaming};

    type ChunkStream = Pin<Box<dyn Stream<Item = Result<Bytes, Status>> + Send>>;

    /// Answers each exchange with whether the client showed a certificate.
    struct WhoAmI;

    #[tonic::async_trait]
    impl IsolationBoundary for WhoAmI {
        type ExchangeStream = ChunkStream;
        type MediateStream = ChunkStream;

        async fn exchange(
            &self,
            request: Request<Streaming<Bytes>>,
        ) -> Result<Response<ChunkStream>, Status> {
            let shown = request
                .extensions()
                .get::<TlsConnectInfo<UdsConnectInfo>>()
                .and_then(|info| info.peer_certs())
                .is_some_and(|certs| !certs.is_empty());
            let answer = Bytes::from_static(if shown { b"mtls" } else { b"plain" });
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
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf = |params: rcgen::CertificateParams| {
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
            ChannelTls {
                ca: ca.pem().into_bytes(),
                cert: cert.pem().into_bytes(),
                key: key.serialize_pem().into_bytes(),
            }
        };
        let mut runtime = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        runtime.subject_alt_names = vec![rcgen::SanType::URI(
            channel::container_uri("agent").try_into().unwrap(),
        )];
        TestPki {
            supervisor: leaf(rcgen::CertificateParams::new(vec![SUPERVISOR_NAME.into()]).unwrap()),
            runtime: leaf(runtime),
        }
    }

    fn write_tls(dir: &Path, tls: &ChannelTls) {
        std::fs::write(dir.join("ca.pem"), &tls.ca).unwrap();
        std::fs::write(dir.join("cert.pem"), &tls.cert).unwrap();
        std::fs::write(dir.join("key.pem"), &tls.key).unwrap();
    }

    #[tokio::test]
    async fn the_runtime_shows_its_certificate_over_a_unix_socket() {
        let pki = test_pki();
        let dir = tempfile::tempdir().unwrap();
        write_tls(dir.path(), &pki.runtime);
        let socket = dir.path().join("channel.sock");
        let incoming = tokio_stream::wrappers::UnixListenerStream::new(
            tokio::net::UnixListener::bind(&socket).unwrap(),
        );
        tokio::spawn(
            channel::server()
                .tls_config(pki.supervisor.server())
                .unwrap()
                .add_service(IsolationBoundaryServer::new(WhoAmI))
                .serve_with_incoming(incoming),
        );

        let mut client = client(&Supervisor::Unix(socket), dir.path()).unwrap();
        let mut answers = client
            .exchange(tokio_stream::empty())
            .await
            .unwrap()
            .into_inner();
        assert_eq!(answers.message().await.unwrap().unwrap(), "mtls");
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
