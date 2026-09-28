//! The channel between a supervisor and a runtime inside the workload.
//!
//! The runtime serves `IsolationBoundary` over mutual TLS, and the supervisor
//! dials it, so the workload needs no egress at all. Each operation is its own
//! `Exchange` call, so it is its own HTTP/2 stream with its own flow-control
//! window: a slow relay stalls only itself. The first chunk of an `Exchange`
//! is an [`Open`], and the open says what the other chunks carry. `Mediate` is
//! one persistent call, on which the runtime sends its DNS queries.

use std::ffi::OsString;
use std::io;
use std::net::SocketAddr;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig};
use tonic::{Status, Streaming};

use crate::peer_process::PeerProcess;

// Generated: it builds each codec with `Default::default()`.
#[allow(clippy::default_constructed_unit_structs)]
pub mod boundary {
    include!(concat!(
        env!("OUT_DIR"),
        "/lens.sandbox.channel.v1.IsolationBoundary.rs"
    ));
}

/// Bump when a message below changes shape. The runtime refuses an
/// [`Open::Hello`] that names another version.
pub const PROTOCOL: u32 = 1;

/// The name that the supervisor certificate holds.
pub const SUPERVISOR_NAME: &str = "supervisor.lens-sandbox";

/// The name that the certificate of a runtime holds and the supervisor
/// verifies. The leaf is mounted only into its own container, so the name
/// identifies the runtime; the channel can be a Unix socket, which has no
/// host name to check.
pub fn runtime_name(container: &str) -> String {
    format!("{container}.runtime.lens-sandbox")
}

/// What an `Exchange` carries. The supervisor opens every exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "open", rename_all = "snake_case")]
pub enum Open {
    /// The first exchange on a connection. The runtime ends it at once, with
    /// an error when it speaks another protocol or cannot mediate.
    Hello { protocol: u32 },
    /// The public CA of the proxy, for the trust bundle of the workload. The
    /// runtime ends the exchange when the bundle is in place.
    Trust { ca_pem: String },
    /// One exec session. Each chunk after the open is one `exec_protocol`
    /// JSON frame, in both directions.
    Exec,
    /// A [`pump`] to `127.0.0.1:port` in the workload. The runtime refuses
    /// the exchange when nothing listens there.
    Forward { port: u16 },
    /// Waits for the next workload `connect()` that the runtime holds. The
    /// runtime sends one [`Held`], the supervisor replies with one
    /// [`ConnectReply`], and after `Allowed` the exchange is a [`pump`].
    Accept,
}

/// A workload `connect()` that the runtime holds until the supervisor
/// decides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Held {
    pub destination: SocketAddr,
    pub process: WireProcess,
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

/// A DNS query on `Mediate`: a big-endian `u32` id, the length of the sender
/// as a big-endian `u32`, the sender as JSON (`null` when the runtime found
/// none), then the DNS wire bytes. Queries overlap, so a reply names its query
/// by the id.
pub fn dns_query_frame(id: u32, sender: Option<&WireProcess>, packet: &[u8]) -> Bytes {
    let sender = encode(&sender);
    let mut frame = Vec::with_capacity(8 + sender.len() + packet.len());
    frame.put_u32(id);
    frame.put_u32(u32::try_from(sender.len()).unwrap_or(u32::MAX));
    frame.extend_from_slice(&sender);
    frame.extend_from_slice(packet);
    Bytes::from(frame)
}

pub struct DnsQuery<'a> {
    pub id: u32,
    pub sender: Option<WireProcess>,
    pub packet: &'a [u8],
}

pub fn parse_dns_query(mut frame: &[u8]) -> Result<DnsQuery<'_>, Status> {
    let malformed = || Status::invalid_argument("malformed DNS query frame");
    if frame.len() < 8 {
        return Err(malformed());
    }
    let id = frame.get_u32();
    let sender_len = usize::try_from(frame.get_u32()).map_err(|_| malformed())?;
    let (sender, packet) = frame.split_at_checked(sender_len).ok_or_else(malformed)?;
    Ok(DnsQuery {
        id,
        sender: decode(sender)?,
        packet,
    })
}

/// A DNS reply on `Mediate`: the big-endian `u32` id of its query, then the
/// DNS wire bytes.
pub fn dns_reply_frame(id: u32, packet: &[u8]) -> Bytes {
    let mut frame = Vec::with_capacity(4 + packet.len());
    frame.put_u32(id);
    frame.extend_from_slice(packet);
    Bytes::from(frame)
}

pub fn parse_dns_reply(mut frame: &[u8]) -> Option<(u32, &[u8])> {
    (frame.len() >= 4).then(|| (frame.get_u32(), frame))
}

/// What one side of an exchange sends: a client sends bare chunks, and a
/// server sends results.
pub trait Outbound: Send + 'static {
    /// Whether the end of the stream ends only its own direction. A client
    /// can end its request stream and still read the response, but a server
    /// that ends its response ends the call, so it sends an empty chunk.
    const HALF_CLOSES: bool;

    fn chunk(bytes: Bytes) -> Self;
}

impl Outbound for Bytes {
    const HALF_CLOSES: bool = true;

    fn chunk(bytes: Bytes) -> Self {
        bytes
    }
}

impl Outbound for Result<Bytes, Status> {
    const HALF_CLOSES: bool = false;

    fn chunk(bytes: Bytes) -> Self {
        Ok(bytes)
    }
}

pub const RELAY_QUEUE: usize = 8;
const RELAY_CHUNK: usize = 64 * 1024;

/// Copies raw bytes both ways until each side has closed. The end of the
/// local read half reaches the other side as the end of the stream, or as an
/// empty chunk from a server.
pub async fn pump<T: Outbound>(
    local: impl AsyncRead + AsyncWrite,
    outbound: mpsc::Sender<T>,
    mut inbound: Streaming<Bytes>,
) -> io::Result<()> {
    let (mut from_local, mut to_local) = tokio::io::split(local);
    let upload = async move {
        let mut buffer = vec![0_u8; RELAY_CHUNK];
        loop {
            let read = from_local.read(&mut buffer).await?;
            if read == 0 && T::HALF_CLOSES {
                return Ok(None);
            }
            let chunk = T::chunk(Bytes::copy_from_slice(&buffer[..read]));
            if outbound.send(chunk).await.is_err() {
                return Ok(None);
            }
            if read == 0 {
                // The sender keeps the stream, and with it the call, open
                // until the download has ended too.
                return Ok(Some(outbound));
            }
        }
    };
    let download = async {
        while let Some(chunk) = inbound.message().await.map_err(io::Error::other)? {
            if chunk.is_empty() {
                break;
            }
            to_local.write_all(&chunk).await?;
        }
        to_local.shutdown().await?;
        // Dropping the inbound stream before its end cancels the call, and
        // with it the other direction.
        while inbound.message().await.map_err(io::Error::other)?.is_some() {}
        Ok(())
    };
    tokio::try_join!(upload, download).map(drop)
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

    /// Accepts only the runtime of `container`.
    pub fn client(&self, container: &str) -> ClientTlsConfig {
        ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(&self.ca))
            .identity(Identity::from_pem(&self.cert, &self.key))
            .domain_name(runtime_name(container))
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
    fn a_held_connect_round_trips_through_a_chunk() {
        let held = Held {
            destination: "93.184.216.34:443".parse().unwrap(),
            process: WireProcess {
                pid: 7,
                name: "curl".into(),
                exe: Some(b"/usr/bin/curl".to_vec()),
                ancestors: vec![],
            },
        };
        assert_eq!(decode::<Held>(&encode(&held)).unwrap(), held);
        assert_eq!(
            decode::<Open>(&encode(&Open::Accept)).unwrap(),
            Open::Accept
        );
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
    fn a_dns_query_carries_its_id_and_sender() {
        let sender = WireProcess {
            pid: 3,
            name: "dig".into(),
            exe: Some(b"/usr/bin/dig".to_vec()),
            ancestors: vec![],
        };
        let frame = dns_query_frame(0xdead_beef, Some(&sender), b"query");
        let query = parse_dns_query(&frame).unwrap();
        assert_eq!(query.id, 0xdead_beef);
        assert_eq!(query.sender, Some(sender));
        assert_eq!(query.packet, b"query");

        let anonymous = dns_query_frame(1, None, b"q");
        assert_eq!(parse_dns_query(&anonymous).unwrap().sender, None);
    }

    #[test]
    fn a_dns_query_frame_that_lies_about_its_sender_is_refused() {
        let mut frame = dns_query_frame(1, None, b"").to_vec();
        frame[7] = 200;
        assert!(parse_dns_query(&frame).is_err());
        assert!(parse_dns_query(b"short").is_err());
    }

    #[test]
    fn a_dns_reply_carries_its_id() {
        let frame = dns_reply_frame(0xdead_beef, b"answer");
        assert_eq!(parse_dns_reply(&frame), Some((0xdead_beef, &b"answer"[..])));
        assert_eq!(parse_dns_reply(b"abc"), None);
    }

    type ChunkStream = Pin<Box<dyn Stream<Item = Result<Bytes, Status>> + Send>>;

    /// A runtime that echoes each chunk, prefixed by whether the supervisor
    /// showed a certificate.
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

    /// Pumps each exchange to a workload that writes `pong`, closes its
    /// write half, and reports what it reads after that.
    struct HalfClosingWorkload {
        read: mpsc::UnboundedSender<Vec<u8>>,
    }

    #[tonic::async_trait]
    impl IsolationBoundary for HalfClosingWorkload {
        type ExchangeStream = ChunkStream;
        type MediateStream = ChunkStream;

        async fn exchange(
            &self,
            request: Request<Streaming<Bytes>>,
        ) -> Result<Response<ChunkStream>, Status> {
            let (local, mut workload) = tokio::io::duplex(64);
            let read = self.read.clone();
            tokio::spawn(async move {
                workload.write_all(b"pong").await.unwrap();
                workload.shutdown().await.unwrap();
                let mut received = Vec::new();
                workload.read_to_end(&mut received).await.unwrap();
                let _ = read.send(received);
            });
            let (outbound, outbound_rx) = mpsc::channel(RELAY_QUEUE);
            tokio::spawn(pump(local, outbound, request.into_inner()));
            Ok(Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(outbound_rx),
            )))
        }

        async fn mediate(
            &self,
            _: Request<Streaming<Bytes>>,
        ) -> Result<Response<ChunkStream>, Status> {
            Err(Status::unimplemented("mediate"))
        }
    }

    #[tokio::test]
    async fn a_relay_carries_bytes_after_the_server_closed_its_half() {
        let (read, mut workload_read) = mpsc::unbounded_channel();
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = incoming.local_addr().unwrap();
        tokio::spawn(
            server()
                .add_service(IsolationBoundaryServer::new(HalfClosingWorkload { read }))
                .serve_with_incoming(incoming),
        );
        let channel = endpoint(Endpoint::from_shared(format!("http://{addr}")).unwrap())
            .connect()
            .await
            .unwrap();
        let (outbound, outbound_rx) = mpsc::channel(RELAY_QUEUE);
        let inbound = IsolationBoundaryClient::new(channel)
            .exchange(tokio_stream::wrappers::ReceiverStream::new(outbound_rx))
            .await
            .unwrap()
            .into_inner();
        let (local, mut peer) = tokio::io::duplex(64);
        let relay = tokio::spawn(pump(local, outbound, inbound));

        let mut received = Vec::new();
        peer.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"pong");
        peer.write_all(b"ping").await.unwrap();
        peer.shutdown().await.unwrap();
        assert_eq!(workload_read.recv().await.unwrap(), b"ping");
        relay.await.unwrap().unwrap();
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
        TestPki {
            supervisor: leaf(rcgen::CertificateParams::new(vec![SUPERVISOR_NAME.into()]).unwrap()),
            runtime: leaf(rcgen::CertificateParams::new(vec![runtime_name("agent")]).unwrap()),
        }
    }

    async fn spawn_runtime(pki: &TestPki) -> SocketAddr {
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = incoming.local_addr().unwrap();
        let server_tls = pki.runtime.server();
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
        let addr = spawn_runtime(&pki).await;
        assert_eq!(
            exchange_once(addr, pki.supervisor.client("agent"), b"\x00\xffraw")
                .await
                .unwrap(),
            Bytes::from_static(b"mtls:\x00\xffraw")
        );
    }

    #[tokio::test]
    async fn the_runtime_refuses_a_client_without_a_certificate() {
        let pki = test_pki();
        let addr = spawn_runtime(&pki).await;
        let anonymous = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(&pki.runtime.ca))
            .domain_name(runtime_name("agent"));
        assert!(exchange_once(addr, anonymous, b"x").await.is_err());
        assert!(
            exchange_once(addr, pki.supervisor.client("agent"), b"x")
                .await
                .is_ok(),
            "the runtime still serves a supervisor with a certificate"
        );
    }

    #[tokio::test]
    async fn the_supervisor_refuses_a_runtime_of_another_container() {
        let pki = test_pki();
        let addr = spawn_runtime(&pki).await;
        assert!(
            exchange_once(addr, pki.supervisor.client("dockerd"), b"x")
                .await
                .is_err()
        );
    }
}
