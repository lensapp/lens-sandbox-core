//! The runtimes of one sandbox, and what the supervisor asks of them.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use bytes::Bytes;
use lens_sandbox_core::channel::{self, ChannelTls, Open};
use lens_sandbox_core::proxy::ProxyState;
use tokio::io::DuplexStream;
use tokio::sync::{mpsc, watch};
use tokio::task::AbortHandle;
use tonic::{Status, Streaming};

use crate::dial::{self, RuntimeAddress};
use crate::egress;
use crate::link::{self, Client, Link};

const FORWARD_BUFFER: usize = 64 * 1024;

/// Cheap to clone; every clone serves the same sandbox. The links to the
/// runtimes stop when the last clone drops.
#[derive(Clone)]
pub struct Supervisor {
    inner: Arc<Inner>,
}

struct Inner {
    state: Arc<ProxyState>,
    dns_upstream: SocketAddr,
    is_own_address: fn(IpAddr) -> bool,
    trust: watch::Sender<Option<String>>,
    runtimes: Mutex<HashMap<String, Runtime>>,
}

struct Runtime {
    client: Client,
    ready: watch::Receiver<bool>,
    link: AbortHandle,
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.link.abort();
    }
}

/// One exec session on a runtime. The frames are `exec_protocol` JSON.
pub struct ExecSession {
    outbound: mpsc::Sender<Bytes>,
    inbound: Streaming<Bytes>,
}

impl ExecSession {
    /// `false` when the runtime closed the session.
    pub async fn send(&self, frame: String) -> bool {
        self.outbound.send(Bytes::from(frame)).await.is_ok()
    }

    /// `None` when the session closed or broke.
    pub async fn recv(&mut self) -> Option<String> {
        let chunk = self.inbound.message().await.ok()??;
        String::from_utf8(chunk.to_vec())
            .inspect_err(
                |error| tracing::warn!(%error, "the runtime sent an exec frame that is not UTF-8"),
            )
            .ok()
    }
}

impl Supervisor {
    /// `dns_upstream` answers the DNS queries that the policy allows; see
    /// [`lens_sandbox_core::dns::discover_upstream`]. The process must
    /// install a rustls crypto provider first.
    pub fn new(state: Arc<ProxyState>, dns_upstream: SocketAddr) -> Self {
        Self::with_own_address(state, dns_upstream, egress::is_own_address)
    }

    fn with_own_address(
        state: Arc<ProxyState>,
        dns_upstream: SocketAddr,
        is_own_address: fn(IpAddr) -> bool,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                state,
                dns_upstream,
                is_own_address,
                trust: watch::Sender::new(None),
                runtimes: Mutex::default(),
            }),
        }
    }

    /// Dials the runtime of `container` with the supervisor leaf, and dials
    /// again after each loss, until [`Supervisor::detach`]. A second attach
    /// of a container replaces the first. Needs a tokio runtime.
    pub fn attach(
        &self,
        container: &str,
        address: RuntimeAddress,
        tls: &ChannelTls,
    ) -> Result<(), tonic::transport::Error> {
        let client = dial::client(container, address, tls)?;
        let (ready, ready_rx) = watch::channel(false);
        let link = Link {
            container: container.to_string(),
            client: client.clone(),
            state: self.inner.state.clone(),
            dns_upstream: self.inner.dns_upstream,
            is_own_address: self.inner.is_own_address,
            trust: self.inner.trust.subscribe(),
            ready,
        };
        let link = tokio::spawn(link.run()).abort_handle();
        self.runtimes().insert(
            container.to_string(),
            Runtime {
                client,
                ready: ready_rx,
                link,
            },
        );
        Ok(())
    }

    pub fn detach(&self, container: &str) {
        self.runtimes().remove(container);
    }

    /// Makes every runtime, now and after a reconnect, trust the proxy CA.
    pub fn trust(&self, ca_pem: String) {
        self.inner.trust.send_replace(Some(ca_pem));
    }

    pub async fn open_exec(&self, container: &str) -> Result<ExecSession, Status> {
        let (outbound, inbound) = link::open(self.ready_client(container)?, &Open::Exec).await?;
        Ok(ExecSession { outbound, inbound })
    }

    /// A stream to `127.0.0.1:port` in the workload of `container`.
    pub async fn open_forward(&self, container: &str, port: u16) -> Result<DuplexStream, Status> {
        let (outbound, inbound) =
            link::open(self.ready_client(container)?, &Open::Forward { port }).await?;
        let (local, remote) = tokio::io::duplex(FORWARD_BUFFER);
        tokio::spawn(async move {
            if let Err(error) = channel::pump(remote, outbound, inbound).await {
                tracing::debug!(port, %error, "loopback forward closed");
            }
        });
        Ok(local)
    }

    fn ready_client(&self, container: &str) -> Result<Client, Status> {
        let runtimes = self.runtimes();
        let runtime = runtimes
            .get(container)
            .ok_or_else(|| Status::not_found(format!("{container} is not attached")))?;
        if !*runtime.ready.borrow() {
            return Err(Status::unavailable(format!("{container} is not connected")));
        }
        Ok(runtime.client.clone())
    }

    fn runtimes(&self) -> MutexGuard<'_, HashMap<String, Runtime>> {
        self.inner
            .runtimes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChannelPki;
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{DNSClass, Name, RecordType};
    use lens_sandbox_core::channel::boundary::isolation_boundary_server::{
        IsolationBoundary, IsolationBoundaryServer,
    };
    use lens_sandbox_core::channel::{ConnectReply, Held, WireProcess};
    use lens_sandbox_core::proxy::ProxyServer;
    use std::pin::Pin;
    use std::str::FromStr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_stream::Stream;
    use tokio_stream::wrappers::ReceiverStream;
    use tonic::transport::server::TcpIncoming;
    use tonic::{Request, Response};

    type ChunkStream = Pin<Box<dyn Stream<Item = Result<Bytes, Status>> + Send>>;

    /// A call that reached the fake runtime, with its two directions.
    struct Call {
        open: Option<Open>,
        inbound: Streaming<Bytes>,
        outbound: mpsc::Sender<Result<Bytes, Status>>,
    }

    /// Ends each hello and trust at once, as the runtime does, and hands
    /// every call to the test. A `Mediate` call has no open.
    struct FakeRuntime {
        calls: mpsc::UnboundedSender<Call>,
    }

    #[tonic::async_trait]
    impl IsolationBoundary for FakeRuntime {
        type ExchangeStream = ChunkStream;
        type MediateStream = ChunkStream;

        async fn exchange(
            &self,
            request: Request<Streaming<Bytes>>,
        ) -> Result<Response<ChunkStream>, Status> {
            let mut inbound = request.into_inner();
            let first = inbound
                .message()
                .await?
                .ok_or_else(|| Status::aborted("empty"))?;
            let open = channel::decode::<Open>(&first)?;
            Ok(Response::new(self.hand_over(Some(open), inbound)))
        }

        async fn mediate(
            &self,
            request: Request<Streaming<Bytes>>,
        ) -> Result<Response<ChunkStream>, Status> {
            Ok(Response::new(self.hand_over(None, request.into_inner())))
        }
    }

    impl FakeRuntime {
        fn hand_over(&self, open: Option<Open>, inbound: Streaming<Bytes>) -> ChunkStream {
            let (outbound, outbound_rx) = mpsc::channel(channel::RELAY_QUEUE);
            let ends_at_once = matches!(open, Some(Open::Hello { .. } | Open::Trust { .. }));
            let _ = self.calls.send(Call {
                open,
                inbound,
                outbound: outbound.clone(),
            });
            if ends_at_once {
                Box::pin(tokio_stream::empty())
            } else {
                Box::pin(ReceiverStream::new(outbound_rx))
            }
        }
    }

    struct Harness {
        supervisor: Supervisor,
        calls: mpsc::UnboundedReceiver<Call>,
        addr: SocketAddr,
        /// Calls that a test passed over stay open here.
        passed: Vec<Call>,
    }

    fn state() -> Arc<ProxyState> {
        let any = "127.0.0.1:0".parse().unwrap();
        ProxyServer::new(any, any, any, None, Vec::new()).1
    }

    fn harness(state: Arc<ProxyState>, is_own_address: fn(IpAddr) -> bool) -> Harness {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pki = ChannelPki::generate(["agent"]).unwrap();
        let (calls_tx, calls) = mpsc::unbounded_channel();
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = incoming.local_addr().unwrap();
        tokio::spawn(
            channel::server()
                .tls_config(pki.runtimes["agent"].server())
                .unwrap()
                .add_service(IsolationBoundaryServer::new(FakeRuntime {
                    calls: calls_tx,
                }))
                .serve_with_incoming(incoming),
        );
        // Nothing listens on the discard port, so an upstream query fails.
        let dns_upstream = "127.0.0.1:9".parse().unwrap();
        let supervisor = Supervisor::with_own_address(state, dns_upstream, is_own_address);
        supervisor
            .attach("agent", RuntimeAddress::Tcp(addr), &pki.supervisor)
            .unwrap();
        Harness {
            supervisor,
            calls,
            addr,
            passed: Vec::new(),
        }
    }

    impl Harness {
        /// The next call that `wanted` picks.
        async fn next(&mut self, wanted: impl Fn(Option<&Open>) -> bool) -> Call {
            loop {
                let call = tokio::time::timeout(Duration::from_secs(5), self.calls.recv())
                    .await
                    .unwrap()
                    .unwrap();
                if wanted(call.open.as_ref()) {
                    return call;
                }
                self.passed.push(call);
            }
        }

        async fn next_open(&mut self, open: Open) -> Call {
            self.next(|call| call == Some(&open)).await
        }

        async fn accept(&mut self) -> Call {
            self.next_open(Open::Accept).await
        }

        async fn mediation(&mut self) -> Call {
            self.next(|call| call.is_none()).await
        }

        /// Waits until the supervisor takes exchanges for the runtime.
        async fn connected(&self) {
            let mut ready = self.supervisor.runtimes()["agent"].ready.clone();
            ready.wait_for(|ready| *ready).await.unwrap();
        }
    }

    #[tokio::test]
    async fn the_supervisor_says_hello_and_trusts_the_proxy_before_it_mediates() {
        let mut harness = harness(state(), egress::is_own_address);
        harness.supervisor.trust("proxy ca".into());
        let order: Vec<_> = [
            harness.next(|_| true).await.open,
            harness.next(|_| true).await.open,
            harness.next(|_| true).await.open,
        ]
        .into();
        assert_eq!(
            order,
            [
                Some(Open::Hello {
                    protocol: channel::PROTOCOL
                }),
                Some(Open::Trust {
                    ca_pem: "proxy ca".into()
                }),
                None,
            ]
        );
        harness.supervisor.trust("new ca".into());
        harness
            .next_open(Open::Trust {
                ca_pem: "new ca".into(),
            })
            .await;
    }

    #[tokio::test]
    async fn the_supervisor_dials_again_after_a_loss() {
        let mut harness = harness(state(), egress::is_own_address);
        let hello = Open::Hello {
            protocol: channel::PROTOCOL,
        };
        harness.next_open(hello.clone()).await;
        drop(harness.mediation().await);
        harness.next_open(hello).await;
    }

    #[tokio::test]
    async fn a_forward_and_an_exec_reach_the_runtime() {
        let mut harness = harness(state(), egress::is_own_address);
        harness.connected().await;
        let echo = |call: Call| {
            tokio::spawn(async move {
                let mut inbound = call.inbound;
                while let Ok(Some(chunk)) = inbound.message().await {
                    let _ = call.outbound.send(Ok(chunk)).await;
                }
            })
        };

        let supervisor = harness.supervisor.clone();
        let forward = tokio::spawn(async move { supervisor.open_forward("agent", 8080).await });
        echo(harness.next_open(Open::Forward { port: 8080 }).await);
        let mut forward = forward.await.unwrap().unwrap();
        forward.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        forward.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");

        let supervisor = harness.supervisor.clone();
        let exec = tokio::spawn(async move { supervisor.open_exec("agent").await });
        echo(harness.next_open(Open::Exec).await);
        let mut exec = exec.await.unwrap().unwrap();
        assert!(exec.send("{\"type\":\"exec_stdin\"}".into()).await);
        assert_eq!(exec.recv().await.unwrap(), "{\"type\":\"exec_stdin\"}");

        let Err(unknown) = harness.supervisor.open_exec("dockerd").await else {
            panic!("an exec reached a container that is not attached");
        };
        assert_eq!(unknown.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn a_runtime_is_not_used_before_it_is_connected() {
        let harness = harness(state(), egress::is_own_address);
        let Err(early) = harness.supervisor.open_exec("agent").await else {
            panic!("an exec reached a runtime before its hello");
        };
        assert_eq!(early.code(), tonic::Code::Unavailable);
    }

    fn curl() -> WireProcess {
        WireProcess {
            pid: 7,
            name: "curl".into(),
            exe: Some(b"/usr/bin/curl".to_vec()),
            ancestors: vec![],
        }
    }

    /// Hands a held `connect()` to `destination` over, and returns the
    /// decision and the accept.
    async fn hand_over(harness: &mut Harness, destination: SocketAddr) -> (ConnectReply, Call) {
        let mut accept = harness.accept().await;
        let held = Held {
            destination,
            process: curl(),
        };
        accept
            .outbound
            .send(Ok(channel::encode(&held)))
            .await
            .unwrap();
        let reply = accept.inbound.message().await.unwrap().unwrap();
        (channel::decode(&reply).unwrap(), accept)
    }

    #[tokio::test]
    async fn a_connect_to_the_supervisor_itself_is_denied() {
        let mut harness = harness(state(), egress::is_own_address);
        let own = harness.addr;
        let (reply, _) = hand_over(&mut harness, own).await;
        assert_eq!(reply, ConnectReply::Denied);
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
        let mut harness = harness(state, |_| false);
        let (reply, mut accept) = hand_over(&mut harness, destination).await;
        assert_eq!(reply, ConnectReply::Allowed);
        accept
            .outbound
            .send(Ok(Bytes::from_static(b"ping")))
            .await
            .unwrap();
        let mut echoed = Vec::new();
        while echoed.len() < 4 {
            echoed.extend_from_slice(&accept.inbound.message().await.unwrap().unwrap());
        }
        assert_eq!(echoed, b"ping");
    }

    #[tokio::test]
    async fn a_denied_name_gets_an_answer_on_the_mediate_stream() {
        let mut harness = harness(state(), egress::is_own_address);
        let mut mediation = harness.mediation().await;
        let mut query = Message::new(0x1234, MessageType::Query, OpCode::Query);
        let mut question = Query::new();
        question.set_name(Name::from_str("denied.example.").unwrap());
        question.set_query_type(RecordType::A);
        question.set_query_class(DNSClass::IN);
        query.add_query(question);
        let frame = channel::dns_query_frame(9, Some(&curl()), &query.to_vec().unwrap());
        mediation.outbound.send(Ok(frame)).await.unwrap();
        let reply = mediation.inbound.message().await.unwrap().unwrap();
        let (id, answer) = channel::parse_dns_reply(&reply).unwrap();
        assert_eq!(id, 9);
        let answer = Message::from_vec(answer).unwrap();
        assert_eq!(answer.metadata.id, 0x1234);
        assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
    }
}
