//! The channel between a runtime inside the workload and its supervisor.
//!
//! The runtime dials and the supervisor serves `IsolationBoundary` over mutual
//! TLS. Each operation is its own `Exchange` call, so it is its own HTTP/2
//! stream with its own flow-control window: a slow relay stalls only itself.
//! The first chunk of an `Exchange` is an [`Open`], and the open says what the
//! other chunks carry. `Mediate` is one persistent call for DNS.

use std::ffi::OsString;
use std::net::SocketAddr;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tonic::Status;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig};

use crate::peer_process::PeerProcess;

// Generated: it builds each codec with `Default::default()`.
#[allow(clippy::default_constructed_unit_structs)]
pub mod boundary {
    include!(concat!(
        env!("OUT_DIR"),
        "/lens.sandbox.channel.v1.IsolationBoundary.rs"
    ));
}

/// Bump when a message below changes shape. The supervisor refuses an
/// [`Open::Attach`] that names another version.
pub const PROTOCOL: u32 = 1;

/// The name the supervisor certificate holds and the runtime verifies. The
/// channel can be a Unix socket, which has no host name to check.
pub const SUPERVISOR_NAME: &str = "supervisor.lens-sandbox";

const CONTAINER_URI_PREFIX: &str = "urn:lens-sandbox:container:";

/// The URI subject alternative name of a runtime leaf certificate. The leaf is
/// mounted only into its own container, so the name identifies the runtime.
pub fn container_uri(container: &str) -> String {
    format!("{CONTAINER_URI_PREFIX}{container}")
}

/// The container that a runtime certificate names; `None` for any other URI.
pub fn container_from_uri(uri: &str) -> Option<&str> {
    uri.strip_prefix(CONTAINER_URI_PREFIX)
        .filter(|name| !name.is_empty())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "open", rename_all = "snake_case")]
pub enum Open {
    /// The control stream of one runtime connection. The supervisor sends
    /// [`Control`] messages on it; its end ends the connection.
    Attach { protocol: u32 },
    /// One exec session. Each chunk after the open is one `exec_protocol`
    /// JSON frame, in both directions.
    Exec { session: String },
    /// Raw bytes of the loopback forward that [`Control::OpenForward`] asked
    /// for.
    Forward { id: u64 },
    /// A workload `connect()` that the runtime holds. The supervisor replies
    /// with one [`ConnectReply`]; after `Allowed`, the chunks are raw bytes.
    Connect {
        destination: SocketAddr,
        process: WireProcess,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "control", rename_all = "snake_case")]
pub enum Control {
    OpenExec { session: String },
    OpenForward { id: u64, port: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum ConnectReply {
    Allowed,
    Denied,
}

/// A [`PeerProcess`] as the channel carries it. Paths are raw bytes, so an
/// executable path that is not UTF-8 still reaches the `binaries` filter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireProcess {
    pub pid: i64,
    pub name: String,
    pub exe: Option<Vec<u8>>,
    pub ancestors: Vec<Vec<u8>>,
}

impl From<&PeerProcess> for WireProcess {
    fn from(process: &PeerProcess) -> Self {
        let bytes = |path: &PathBuf| path.as_os_str().as_bytes().to_vec();
        Self {
            pid: process.pid,
            name: process.name.clone(),
            exe: process.exe.as_ref().map(bytes),
            ancestors: process.ancestors.iter().map(bytes).collect(),
        }
    }
}

impl From<WireProcess> for PeerProcess {
    fn from(wire: WireProcess) -> Self {
        let path = |bytes: Vec<u8>| PathBuf::from(OsString::from_vec(bytes));
        Self {
            pid: wire.pid,
            name: wire.name,
            exe: wire.exe.map(path),
            ancestors: wire.ancestors.into_iter().map(path).collect(),
        }
    }
}

pub fn encode<T: Serialize>(message: &T) -> Bytes {
    // A message of this module holds no map with non-string keys, so it
    // always serializes.
    Bytes::from(serde_json::to_vec(message).unwrap_or_default())
}

pub fn decode<T: DeserializeOwned>(chunk: &[u8]) -> Result<T, Status> {
    serde_json::from_slice(chunk)
        .map_err(|e| Status::invalid_argument(format!("malformed channel message: {e}")))
}

/// One DNS message on `Mediate`: a big-endian `u32` id, then the DNS wire
/// bytes. The reply carries the id of its query, so queries can overlap.
pub fn dns_frame(id: u32, packet: &[u8]) -> Bytes {
    let mut frame = Vec::with_capacity(4 + packet.len());
    frame.put_u32(id);
    frame.extend_from_slice(packet);
    Bytes::from(frame)
}

pub fn parse_dns_frame(mut frame: &[u8]) -> Option<(u32, &[u8])> {
    (frame.len() >= 4).then(|| (frame.get_u32(), frame))
}

const STREAM_WINDOW: u32 = 128 * 1024;
/// Each held workload `connect()` is one stream, so this is also how many
/// relays a runtime has open at once; a further open waits for a free stream.
const MAX_STREAMS: u32 = 512;
/// Larger than every stream window together, so relays cannot use the
/// connection credit that DNS, exec and control need.
const CONNECTION_WINDOW: u32 = STREAM_WINDOW * MAX_STREAMS + 4 * 1024 * 1024;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

pub fn server() -> Server {
    Server::builder()
        .initial_stream_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .max_concurrent_streams(MAX_STREAMS)
        .http2_keepalive_interval(Some(KEEPALIVE_INTERVAL))
        .http2_keepalive_timeout(Some(KEEPALIVE_TIMEOUT))
}

pub fn endpoint(base: Endpoint) -> Endpoint {
    base.initial_stream_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .http2_keep_alive_interval(KEEPALIVE_INTERVAL)
        .keep_alive_timeout(KEEPALIVE_TIMEOUT)
        .keep_alive_while_idle(true)
}

/// Certificates as PEM: the channel CA, and the leaf with its key.
pub struct ChannelTls {
    pub ca: Vec<u8>,
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
}

impl ChannelTls {
    pub fn server(&self) -> ServerTlsConfig {
        ServerTlsConfig::new()
            .identity(Identity::from_pem(&self.cert, &self.key))
            .client_ca_root(Certificate::from_pem(&self.ca))
    }

    pub fn client(&self) -> ClientTlsConfig {
        ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(&self.ca))
            .identity(Identity::from_pem(&self.cert, &self.key))
            .domain_name(SUPERVISOR_NAME)
    }
}

/// Every chunk is one gRPC message, as is: the messages above bring their own
/// framing, so the service needs no protobuf.
#[derive(Debug, Default)]
pub struct ChunkCodec;

impl Codec for ChunkCodec {
    type Encode = Bytes;
    type Decode = Bytes;
    type Encoder = ChunkCodec;
    type Decoder = ChunkCodec;

    fn encoder(&mut self) -> Self::Encoder {
        ChunkCodec
    }

    fn decoder(&mut self) -> Self::Decoder {
        ChunkCodec
    }
}

impl Encoder for ChunkCodec {
    type Item = Bytes;
    type Error = Status;

    fn encode(&mut self, item: Bytes, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        dst.put(item);
        Ok(())
    }
}

impl Decoder for ChunkCodec {
    type Item = Bytes;
    type Error = Status;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Bytes>, Status> {
        let len = src.remaining();
        Ok(Some(src.copy_to_bytes(len)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boundary::isolation_boundary_client::IsolationBoundaryClient;
    use boundary::isolation_boundary_server::{IsolationBoundary, IsolationBoundaryServer};
    use std::pin::Pin;
    use tokio_stream::{Stream, StreamExt};
    use tonic::transport::server::{TcpConnectInfo, TcpIncoming, TlsConnectInfo};
    use tonic::{Request, Response, Streaming};

    #[test]
    fn open_round_trips_through_a_chunk() {
        let open = Open::Connect {
            destination: "93.184.216.34:443".parse().unwrap(),
            process: WireProcess {
                pid: 7,
                name: "curl".into(),
                exe: Some(b"/usr/bin/curl".to_vec()),
                ancestors: vec![],
            },
        };
        assert_eq!(decode::<Open>(&encode(&open)).unwrap(), open);
    }

    #[test]
    fn decode_refuses_a_chunk_that_is_not_the_message() {
        let err = decode::<Open>(b"{\"open\":\"nope\"}").unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn a_non_utf8_executable_path_survives_the_wire() {
        let exe = PathBuf::from(OsString::from_vec(b"/opt/\xffbin".to_vec()));
        let process = PeerProcess {
            pid: 9,
            name: "tool".into(),
            exe: Some(exe.clone()),
            ancestors: vec![exe],
        };
        let wire: WireProcess = decode(&encode(&WireProcess::from(&process))).unwrap();
        assert_eq!(PeerProcess::from(wire), process);
    }

    #[test]
    fn a_dns_frame_carries_its_id() {
        let frame = dns_frame(0xdead_beef, b"query");
        assert_eq!(parse_dns_frame(&frame), Some((0xdead_beef, &b"query"[..])));
        assert_eq!(parse_dns_frame(b"abc"), None);
    }

    #[test]
    fn a_container_uri_names_its_container() {
        assert_eq!(container_from_uri(&container_uri("agent")), Some("agent"));
        assert_eq!(container_from_uri(&container_uri("")), None);
        assert_eq!(container_from_uri("urn:other:agent"), None);
    }

    type ChunkStream = Pin<Box<dyn Stream<Item = Result<Bytes, Status>> + Send>>;

    /// Echoes each chunk, prefixed by whether the client showed a
    /// certificate.
    struct Echo;

    #[tonic::async_trait]
    impl IsolationBoundary for Echo {
        type ExchangeStream = ChunkStream;
        type MediateStream = ChunkStream;

        async fn exchange(
            &self,
            request: Request<Streaming<Bytes>>,
        ) -> Result<Response<ChunkStream>, Status> {
            let has_client_cert = request
                .extensions()
                .get::<TlsConnectInfo<TcpConnectInfo>>()
                .and_then(|info| info.peer_certs())
                .map(|certs| !certs.is_empty())
                .unwrap_or(false);
            let tag = if has_client_cert { "mtls:" } else { "plain:" };
            let echoed = request
                .into_inner()
                .map(move |chunk| chunk.map(|c| Bytes::from([tag.as_bytes(), &c[..]].concat())));
            Ok(Response::new(Box::pin(echoed)))
        }

        async fn mediate(
            &self,
            request: Request<Streaming<Bytes>>,
        ) -> Result<Response<ChunkStream>, Status> {
            Ok(Response::new(Box::pin(request.into_inner())))
        }
    }

    struct TestPki {
        supervisor: ChannelTls,
        runtime: ChannelTls,
    }

    fn test_pki() -> TestPki {
        // With the `proxy` feature, rustls has two providers and picks none.
        let _ = rustls::crypto::ring::default_provider().install_default();
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
        let supervisor = leaf(rcgen::CertificateParams::new(vec![SUPERVISOR_NAME.into()]).unwrap());
        let mut runtime_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        runtime_params.subject_alt_names = vec![rcgen::SanType::URI(
            container_uri("agent").try_into().unwrap(),
        )];
        TestPki {
            supervisor,
            runtime: leaf(runtime_params),
        }
    }

    async fn spawn_supervisor(pki: &TestPki) -> SocketAddr {
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = incoming.local_addr().unwrap();
        let server_tls = pki.supervisor.server();
        tokio::spawn(async move {
            server()
                .tls_config(server_tls)
                .unwrap()
                .add_service(IsolationBoundaryServer::new(Echo))
                .serve_with_incoming(incoming)
                .await
        });
        addr
    }

    async fn exchange_once(
        addr: SocketAddr,
        tls: ClientTlsConfig,
        chunk: &'static [u8],
    ) -> Result<Bytes, Box<dyn std::error::Error>> {
        let channel = endpoint(Endpoint::from_shared(format!("https://{addr}"))?)
            .tls_config(tls)?
            .connect()
            .await?;
        let mut replies = IsolationBoundaryClient::new(channel)
            .exchange(tokio_stream::iter([Bytes::from_static(chunk)]))
            .await?
            .into_inner();
        Ok(replies.next().await.ok_or("no reply")??)
    }

    #[tokio::test]
    async fn a_chunk_crosses_the_mutual_tls_channel_unchanged() {
        let pki = test_pki();
        let addr = spawn_supervisor(&pki).await;
        assert_eq!(
            exchange_once(addr, pki.runtime.client(), b"\x00\xffraw")
                .await
                .unwrap(),
            Bytes::from_static(b"mtls:\x00\xffraw")
        );
    }

    #[tokio::test]
    async fn the_supervisor_refuses_a_runtime_without_a_certificate() {
        let pki = test_pki();
        let addr = spawn_supervisor(&pki).await;
        let anonymous = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(&pki.supervisor.ca))
            .domain_name(SUPERVISOR_NAME);
        assert!(exchange_once(addr, anonymous, b"x").await.is_err());
        assert!(
            exchange_once(addr, pki.runtime.client(), b"x")
                .await
                .is_ok(),
            "the supervisor still serves a runtime with a certificate"
        );
    }
}
