//! The certificates of one sandbox generation.

use std::collections::HashMap;

use lens_sandbox_core::channel::{self, ChannelTls, SUPERVISOR_NAME};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};

/// The supervisor leaf can only dial, and each runtime leaf can only serve
/// the name of its own container, so neither can act as the other. The CA
/// key is not kept, so nobody can add a leaf to the generation later.
pub struct ChannelPki {
    pub supervisor: ChannelTls,
    pub runtimes: HashMap<String, ChannelTls>,
}

impl ChannelPki {
    pub fn generate<'a>(
        containers: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, rcgen::Error> {
        let ca_key = KeyPair::generate()?;
        let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = ca_params.self_signed(&ca_key)?;
        let leaf = |name: String, usage: ExtendedKeyUsagePurpose| {
            let key = KeyPair::generate()?;
            let mut params = CertificateParams::new(vec![name])?;
            params.extended_key_usages = vec![usage];
            let cert = params.signed_by(&key, &ca, &ca_key)?;
            Ok::<_, rcgen::Error>(ChannelTls {
                ca: ca.pem().into_bytes(),
                cert: cert.pem().into_bytes(),
                key: key.serialize_pem().into_bytes(),
            })
        };
        let supervisor = leaf(SUPERVISOR_NAME.into(), ExtendedKeyUsagePurpose::ClientAuth)?;
        let runtimes = containers
            .into_iter()
            .map(|container| {
                let tls = leaf(
                    channel::runtime_name(container),
                    ExtendedKeyUsagePurpose::ServerAuth,
                )?;
                Ok((container.to_string(), tls))
            })
            .collect::<Result<_, rcgen::Error>>()?;
        Ok(Self {
            supervisor,
            runtimes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use lens_sandbox_core::channel::boundary::isolation_boundary_client::IsolationBoundaryClient;
    use lens_sandbox_core::channel::boundary::isolation_boundary_server::{
        IsolationBoundary, IsolationBoundaryServer,
    };
    use std::net::SocketAddr;
    use std::pin::Pin;
    use tokio_stream::Stream;
    use tonic::transport::server::TcpIncoming;
    use tonic::transport::{ClientTlsConfig, Endpoint};
    use tonic::{Request, Response, Status, Streaming};

    type ChunkStream = Pin<Box<dyn Stream<Item = Result<Bytes, Status>> + Send>>;

    struct Empty;

    #[tonic::async_trait]
    impl IsolationBoundary for Empty {
        type ExchangeStream = ChunkStream;
        type MediateStream = ChunkStream;

        async fn exchange(
            &self,
            _: Request<Streaming<Bytes>>,
        ) -> Result<Response<ChunkStream>, Status> {
            Ok(Response::new(Box::pin(tokio_stream::empty())))
        }

        async fn mediate(
            &self,
            _: Request<Streaming<Bytes>>,
        ) -> Result<Response<ChunkStream>, Status> {
            Err(Status::unimplemented("mediate"))
        }
    }

    fn serve(tls: &ChannelTls) -> SocketAddr {
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = incoming.local_addr().unwrap();
        tokio::spawn(
            channel::server()
                .tls_config(tls.server())
                .unwrap()
                .add_service(IsolationBoundaryServer::new(Empty))
                .serve_with_incoming(incoming),
        );
        addr
    }

    async fn reaches(addr: SocketAddr, tls: ClientTlsConfig) -> bool {
        let Ok(channel) = Endpoint::from_shared(format!("https://{addr}"))
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect()
            .await
        else {
            return false;
        };
        IsolationBoundaryClient::new(channel)
            .exchange(tokio_stream::empty())
            .await
            .is_ok()
    }

    fn pki() -> ChannelPki {
        let _ = rustls::crypto::ring::default_provider().install_default();
        ChannelPki::generate(["agent", "dockerd"]).unwrap()
    }

    #[tokio::test]
    async fn the_supervisor_reaches_each_runtime_by_its_name() {
        let pki = pki();
        let agent = serve(&pki.runtimes["agent"]);
        assert!(reaches(agent, pki.supervisor.client("agent")).await);
        assert!(!reaches(agent, pki.supervisor.client("dockerd")).await);
    }

    #[tokio::test]
    async fn a_runtime_leaf_cannot_dial_another_runtime() {
        let pki = pki();
        let agent = serve(&pki.runtimes["agent"]);
        assert!(!reaches(agent, pki.runtimes["dockerd"].client("agent")).await);
    }

    #[tokio::test]
    async fn the_supervisor_leaf_cannot_serve_as_a_runtime() {
        let pki = pki();
        let impostor = serve(&pki.supervisor);
        // Only the server certificate fails: the name and the client match.
        let supervisor = &pki.supervisor;
        let dialer = ClientTlsConfig::new()
            .ca_certificate(tonic::transport::Certificate::from_pem(&supervisor.ca))
            .identity(tonic::transport::Identity::from_pem(
                &supervisor.cert,
                &supervisor.key,
            ))
            .domain_name(SUPERVISOR_NAME);
        assert!(!reaches(impostor, dialer).await);
    }
}
