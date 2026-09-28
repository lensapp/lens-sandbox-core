//! The channel server, and what the supervisor asks of its runtimes.

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use lens_sandbox_core::channel::boundary::isolation_boundary_server::{
    IsolationBoundary, IsolationBoundaryServer,
};
use lens_sandbox_core::channel::{self, Control, Open};
use lens_sandbox_core::proxy::ProxyState;
use tokio::io::DuplexStream;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::{ReceiverStream, UnboundedReceiverStream};
use tonic::{Request, Response, Status, Streaming};

use crate::registry::{Opened, Runtimes, Waiter};
use crate::{egress, identity, mediate, relay};

/// How long the supervisor waits for a runtime to open an exchange it asked
/// for.
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const FORWARD_BUFFER: usize = 64 * 1024;

type ChunkStream = Pin<Box<dyn Stream<Item = Result<Bytes, Status>> + Send>>;

/// Cheap to clone; every clone serves the same sandbox.
#[derive(Clone)]
pub struct Supervisor {
    inner: Arc<Inner>,
}

struct Inner {
    state: Arc<ProxyState>,
    dns_upstream: SocketAddr,
    runtimes: Runtimes,
    is_own_address: fn(IpAddr) -> bool,
}

/// One exec session on a runtime. The frames are `exec_protocol` JSON.
pub struct ExecSession {
    outbound: mpsc::Sender<Result<Bytes, Status>>,
    inbound: Streaming<Bytes>,
}

impl ExecSession {
    /// `false` when the runtime closed the session.
    pub async fn send(&self, frame: String) -> bool {
        self.outbound.send(Ok(Bytes::from(frame))).await.is_ok()
    }

    /// `None` when the session closed or broke.
    pub async fn recv(&mut self) -> Option<String> {
        let chunk = self.inbound.message().await.ok()??;
        String::from_utf8(chunk.to_vec()).ok()
    }
}

impl Supervisor {
    /// `containers` are the runtimes of the sandbox. `dns_upstream` answers
    /// the DNS queries that the policy allows; see
    /// [`lens_sandbox_core::dns::discover_upstream`].
    pub fn new(
        state: Arc<ProxyState>,
        containers: impl IntoIterator<Item = String>,
        dns_upstream: SocketAddr,
    ) -> Self {
        Self::with_own_address(state, containers, dns_upstream, egress::is_own_address)
    }

    fn with_own_address(
        state: Arc<ProxyState>,
        containers: impl IntoIterator<Item = String>,
        dns_upstream: SocketAddr,
        is_own_address: fn(IpAddr) -> bool,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                state,
                dns_upstream,
                runtimes: Runtimes::new(containers),
                is_own_address,
            }),
        }
    }

    /// Serve this with the TLS config of the supervisor leaf. The process
    /// must install a rustls crypto provider first.
    pub fn service(&self) -> IsolationBoundaryServer<Self> {
        IsolationBoundaryServer::new(self.clone())
    }

    /// Makes every runtime, now and after a reconnect, trust the proxy CA.
    pub fn trust(&self, ca_pem: String) {
        self.inner.runtimes.trust(ca_pem);
    }

    pub async fn open_exec(&self, container: &str) -> Result<ExecSession, Status> {
        let session = self.inner.runtimes.next_id().to_string();
        let waiter = Waiter::Exec {
            container: container.to_string(),
            session: session.clone(),
        };
        let opened = self.open(waiter, Control::OpenExec { session }).await?;
        Ok(ExecSession {
            outbound: opened.outbound,
            inbound: opened.inbound,
        })
    }

    /// A stream to `127.0.0.1:port` in the workload of `container`.
    pub async fn open_forward(&self, container: &str, port: u16) -> Result<DuplexStream, Status> {
        let id = self.inner.runtimes.next_id();
        let waiter = Waiter::Forward {
            container: container.to_string(),
            id,
        };
        let opened = self.open(waiter, Control::OpenForward { id, port }).await?;
        let (local, remote) = tokio::io::duplex(FORWARD_BUFFER);
        tokio::spawn(async move {
            if let Err(error) = relay::pump(remote, opened.outbound, opened.inbound).await {
                tracing::debug!(id, %error, "loopback forward closed");
            }
        });
        Ok(local)
    }

    async fn open(&self, waiter: Waiter, control: Control) -> Result<Opened, Status> {
        let opened = self.inner.runtimes.request(waiter.clone(), control)?;
        let result = tokio::time::timeout(OPEN_TIMEOUT, opened).await;
        self.inner.runtimes.cancel(&waiter);
        match result {
            Ok(Ok(opened)) => Ok(opened),
            Ok(Err(_)) => Err(Status::cancelled("the runtime detached")),
            Err(_) => Err(Status::deadline_exceeded(
                "the runtime did not open the exchange",
            )),
        }
    }

    fn container<T>(&self, request: &Request<T>) -> Result<String, Status> {
        let container = identity::container(request)
            .ok_or_else(|| Status::unauthenticated("no runtime certificate"))?;
        if !self.inner.runtimes.is_allowed(&container) {
            return Err(Status::permission_denied(format!(
                "{container} is not a runtime of this sandbox"
            )));
        }
        Ok(container)
    }

    fn attach(
        &self,
        container: String,
        protocol: u32,
        mut inbound: Streaming<Bytes>,
    ) -> Result<ChunkStream, Status> {
        if protocol != channel::PROTOCOL {
            return Err(Status::failed_precondition(format!(
                "protocol {protocol}, but the supervisor speaks {}",
                channel::PROTOCOL
            )));
        }
        let (id, controls) = self.inner.runtimes.attach(&container)?;
        tracing::info!(%container, "runtime attached");
        let supervisor = self.clone();
        tokio::spawn(async move {
            while let Ok(Some(_)) = inbound.message().await {}
            supervisor.inner.runtimes.detach(&container, id);
            tracing::info!(%container, "runtime detached");
        });
        let controls =
            UnboundedReceiverStream::new(controls).map(|control| Ok(channel::encode(&control)));
        Ok(Box::pin(controls))
    }

    fn deliver(&self, waiter: Waiter, inbound: Streaming<Bytes>) -> Result<ChunkStream, Status> {
        let (outbound, outbound_rx) = mpsc::channel(relay::QUEUE);
        self.inner
            .runtimes
            .deliver(&waiter, Opened { inbound, outbound })?;
        Ok(Box::pin(ReceiverStream::new(outbound_rx)))
    }
}

#[tonic::async_trait]
impl IsolationBoundary for Supervisor {
    type ExchangeStream = ChunkStream;
    type MediateStream = ChunkStream;

    async fn exchange(
        &self,
        request: Request<Streaming<Bytes>>,
    ) -> Result<Response<ChunkStream>, Status> {
        let container = self.container(&request)?;
        let mut inbound = request.into_inner();
        let first = inbound
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("an exchange without an open"))?;
        let stream = match channel::decode::<Open>(&first)? {
            Open::Attach { protocol } => self.attach(container, protocol, inbound)?,
            Open::Exec { session } => self.deliver(Waiter::Exec { container, session }, inbound)?,
            Open::Forward { id } => self.deliver(Waiter::Forward { container, id }, inbound)?,
            Open::Connect {
                destination,
                process,
            } => {
                let replies = egress::serve(
                    destination,
                    process,
                    inbound,
                    self.inner.state.clone(),
                    self.inner.is_own_address,
                )
                .await?;
                Box::pin(ReceiverStream::new(replies))
            }
        };
        Ok(Response::new(stream))
    }

    async fn mediate(
        &self,
        request: Request<Streaming<Bytes>>,
    ) -> Result<Response<ChunkStream>, Status> {
        self.container(&request)?;
        let replies = mediate::serve(
            request.into_inner(),
            self.inner.state.clone(),
            self.inner.dns_upstream,
        );
        Ok(Response::new(Box::pin(ReceiverStream::new(replies))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChannelPki;
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{DNSClass, Name, RecordType};
    use lens_sandbox_core::channel::boundary::isolation_boundary_client::IsolationBoundaryClient;
    use lens_sandbox_core::channel::{ConnectReply, WireProcess};
    use lens_sandbox_core::proxy::ProxyServer;
    use std::str::FromStr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tonic::transport::server::TcpIncoming;
    use tonic::transport::{Channel, Endpoint};

    struct Harness {
        supervisor: Supervisor,
        pki: ChannelPki,
        addr: SocketAddr,
    }

    fn state() -> Arc<ProxyState> {
        let any = "127.0.0.1:0".parse().unwrap();
        ProxyServer::new(any, any, any, None, Vec::new()).1
    }

    /// Serves only `agent`; the PKI also has a leaf for `intruder`.
    fn harness(state: Arc<ProxyState>, is_own_address: fn(IpAddr) -> bool) -> Harness {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pki = ChannelPki::generate(["agent", "intruder"]).unwrap();
        // Nothing listens on the discard port, so an upstream query fails.
        let dns_upstream = "127.0.0.1:9".parse().unwrap();
        let supervisor = Supervisor::with_own_address(
            state,
            ["agent".to_string()],
            dns_upstream,
            is_own_address,
        );
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = incoming.local_addr().unwrap();
        tokio::spawn(
            channel::server()
                .tls_config(pki.supervisor.server())
                .unwrap()
                .add_service(supervisor.service())
                .serve_with_incoming(incoming),
        );
        Harness {
            supervisor,
            pki,
            addr,
        }
    }

    impl Harness {
        async fn client(&self, container: &str) -> IsolationBoundaryClient<Channel> {
            let endpoint = Endpoint::from_shared(format!("https://{}", self.addr)).unwrap();
            let channel = channel::endpoint(endpoint)
                .tls_config(self.pki.runtimes[container].client())
                .unwrap()
                .connect()
                .await
                .unwrap();
            IsolationBoundaryClient::new(channel)
        }
    }

    /// Opens an exchange with `open` and returns its two directions.
    async fn open(
        client: &mut IsolationBoundaryClient<Channel>,
        open: &Open,
    ) -> Result<(mpsc::Sender<Bytes>, Streaming<Bytes>), Status> {
        let (outbound, outbound_rx) = mpsc::channel(8);
        outbound.send(channel::encode(open)).await.unwrap();
        let inbound = client
            .exchange(ReceiverStream::new(outbound_rx))
            .await?
            .into_inner();
        Ok((outbound, inbound))
    }

    async fn next_control(controls: &mut Streaming<Bytes>) -> Control {
        let chunk = tokio::time::timeout(Duration::from_secs(5), controls.message())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        channel::decode(&chunk).unwrap()
    }

    /// A runtime that answers each exchange the supervisor asks for by
    /// echoing its bytes.
    fn echo_runtime(mut client: IsolationBoundaryClient<Channel>, mut controls: Streaming<Bytes>) {
        tokio::spawn(async move {
            while let Ok(Some(chunk)) = controls.message().await {
                let request = match channel::decode::<Control>(&chunk).unwrap() {
                    Control::OpenExec { session } => Open::Exec { session },
                    Control::OpenForward { id, .. } => Open::Forward { id },
                    Control::Trust { .. } => continue,
                };
                let (outbound, mut inbound) = open(&mut client, &request).await.unwrap();
                tokio::spawn(async move {
                    while let Ok(Some(chunk)) = inbound.message().await {
                        let _ = outbound.send(chunk).await;
                    }
                });
            }
        });
    }

    const ATTACH: Open = Open::Attach {
        protocol: channel::PROTOCOL,
    };

    #[tokio::test]
    async fn an_attached_runtime_gets_the_trust_bundle_and_keeps_its_name() {
        let harness = harness(state(), egress::is_own_address);
        harness.supervisor.trust("proxy ca".into());
        let mut client = harness.client("agent").await;
        let (_hold, mut controls) = open(&mut client, &ATTACH).await.unwrap();
        assert_eq!(
            next_control(&mut controls).await,
            Control::Trust {
                ca_pem: "proxy ca".into()
            }
        );
        let second = open(&mut client, &ATTACH).await.unwrap_err();
        assert_eq!(second.code(), tonic::Code::AlreadyExists);
    }

    #[tokio::test]
    async fn a_runtime_of_another_sandbox_or_protocol_is_refused() {
        let harness = harness(state(), egress::is_own_address);
        let mut intruder = harness.client("intruder").await;
        let refused = open(&mut intruder, &ATTACH).await.unwrap_err();
        assert_eq!(refused.code(), tonic::Code::PermissionDenied);

        let mut agent = harness.client("agent").await;
        let old = Open::Attach { protocol: 0 };
        let refused = open(&mut agent, &old).await.unwrap_err();
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn a_runtime_cannot_open_an_exchange_nobody_asked_for() {
        let harness = harness(state(), egress::is_own_address);
        let mut client = harness.client("agent").await;
        let refused = open(&mut client, &Open::Forward { id: 42 })
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn a_forward_and_an_exec_reach_the_runtime() {
        let harness = harness(state(), egress::is_own_address);
        let mut client = harness.client("agent").await;
        harness.supervisor.trust("proxy ca".into());
        let (_hold, mut controls) = open(&mut client, &ATTACH).await.unwrap();
        // The replayed trust bundle shows that the attachment is in place.
        next_control(&mut controls).await;
        echo_runtime(client, controls);

        let mut forward = harness
            .supervisor
            .open_forward("agent", 8080)
            .await
            .unwrap();
        forward.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        forward.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");

        let mut exec = harness.supervisor.open_exec("agent").await.unwrap();
        assert!(exec.send("{\"type\":\"exec_stdin\"}".into()).await);
        assert_eq!(exec.recv().await.unwrap(), "{\"type\":\"exec_stdin\"}");

        let Err(detached) = harness.supervisor.open_exec("dockerd").await else {
            panic!("an exec reached a container that is not attached");
        };
        assert_eq!(detached.code(), tonic::Code::Unavailable);
    }

    fn curl() -> WireProcess {
        WireProcess {
            pid: 7,
            name: "curl".into(),
            exe: Some(b"/usr/bin/curl".to_vec()),
            ancestors: vec![],
        }
    }

    async fn connect_reply(inbound: &mut Streaming<Bytes>) -> ConnectReply {
        channel::decode(&inbound.message().await.unwrap().unwrap()).unwrap()
    }

    #[tokio::test]
    async fn a_connect_to_the_supervisor_itself_is_denied() {
        let harness = harness(state(), egress::is_own_address);
        let mut client = harness.client("agent").await;
        let connect = Open::Connect {
            destination: harness.addr,
            process: curl(),
        };
        let (_outbound, mut inbound) = open(&mut client, &connect).await.unwrap();
        assert_eq!(connect_reply(&mut inbound).await, ConnectReply::Denied);
    }

    /// An echo server on the address this host sends from, as the proxy
    /// never dials loopback. `None` when the host cannot reach that address,
    /// as with the address of some VPN tunnels.
    async fn outward_echo() -> Option<SocketAddr> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect("192.0.2.1:9").ok()?;
        let outward = socket.local_addr().ok()?.ip();
        let echo = tokio::net::TcpListener::bind((outward, 0)).await.ok()?;
        let addr = echo.local_addr().ok()?;
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let mut ping = [0_u8; 4];
                    if stream.read_exact(&mut ping).await.is_ok() {
                        let _ = stream.write_all(&ping).await;
                    }
                });
            }
        });
        let probe = tokio::net::TcpStream::connect(addr);
        tokio::time::timeout(Duration::from_secs(1), probe)
            .await
            .ok()?
            .ok()?;
        Some(addr)
    }

    #[tokio::test]
    async fn an_allowed_connect_carries_bytes_through_the_proxy() {
        let Some(destination) = outward_echo().await else {
            eprintln!("skipping: this host cannot reach its own outward address");
            return;
        };
        let state = state();
        state.policy.write().unwrap().tcp_egress = lens_sandbox_core::routing::parse_tcp_egress(
            &serde_json::json!([{ "match": destination.to_string(), "verdict": "allow" }]),
        )
        .unwrap();
        // The echo server is on this host, which the supervisor refuses.
        let harness = harness(state, |_| false);
        let mut client = harness.client("agent").await;
        let connect = Open::Connect {
            destination,
            process: curl(),
        };
        let (outbound, mut inbound) = open(&mut client, &connect).await.unwrap();
        assert_eq!(connect_reply(&mut inbound).await, ConnectReply::Allowed);
        outbound.send(Bytes::from_static(b"ping")).await.unwrap();
        let mut echoed = Vec::new();
        while echoed.len() < 4 {
            echoed.extend_from_slice(&inbound.message().await.unwrap().unwrap());
        }
        assert_eq!(echoed, b"ping");
    }

    #[tokio::test]
    async fn a_denied_name_gets_an_answer_on_the_mediate_stream() {
        let harness = harness(state(), egress::is_own_address);
        let mut client = harness.client("agent").await;
        let mut query = Message::new(0x1234, MessageType::Query, OpCode::Query);
        let mut question = Query::new();
        question.set_name(Name::from_str("denied.example.").unwrap());
        question.set_query_type(RecordType::A);
        question.set_query_class(DNSClass::IN);
        query.add_query(question);
        let frame = channel::dns_query_frame(9, Some(&curl()), &query.to_vec().unwrap());
        let mut replies = client
            .mediate(tokio_stream::iter([frame]).chain(tokio_stream::pending()))
            .await
            .unwrap()
            .into_inner();
        let reply = replies.message().await.unwrap().unwrap();
        let (id, answer) = channel::parse_dns_reply(&reply).unwrap();
        assert_eq!(id, 9);
        let answer = Message::from_vec(answer).unwrap();
        assert_eq!(answer.metadata.id, 0x1234);
        assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
    }
}
