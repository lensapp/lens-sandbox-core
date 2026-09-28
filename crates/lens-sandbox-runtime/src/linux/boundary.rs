//! The `IsolationBoundary` service that the runtime serves to its supervisor.

use std::path::PathBuf;
use std::pin::Pin;

use bytes::Bytes;
use lens_sandbox_core::channel::{
    self, Open, boundary::isolation_boundary_server::IsolationBoundary,
};
use lens_sandbox_core::exec_manager::ExecManager;
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

use crate::linux::broker::NetworkBroker;
use crate::linux::mediation::Mediation;
use crate::linux::{exec_stream, forward, mediator, trust};

pub(crate) type ChunkStream = Pin<Box<dyn Stream<Item = Result<Bytes, Status>> + Send>>;

pub(crate) struct Boundary {
    pub(crate) exec: ExecManager,
    pub(crate) broker: NetworkBroker,
    pub(crate) mediation: Mediation,
    pub(crate) ca_bundle: PathBuf,
    pub(crate) system_bundle: PathBuf,
}

#[tonic::async_trait]
impl IsolationBoundary for Boundary {
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
            .ok_or_else(|| Status::invalid_argument("an exchange without an open"))?;
        let stream = match channel::decode::<Open>(&first)? {
            Open::Hello { protocol } if protocol == channel::PROTOCOL => {
                self.broker
                    .confirm_healthy()
                    .map_err(|e| Status::unavailable(e.to_string()))?;
                ended()
            }
            Open::Hello { protocol } => {
                return Err(Status::failed_precondition(format!(
                    "the runtime speaks protocol {}, not {protocol}",
                    channel::PROTOCOL
                )));
            }
            Open::Trust { ca_pem } => {
                trust::write_bundle(&self.ca_bundle, &self.system_bundle, &ca_pem).map_err(
                    |e| Status::internal(format!("write {}: {e}", self.ca_bundle.display())),
                )?;
                ended()
            }
            Open::Exec => exec_stream::serve(self.exec.clone(), inbound),
            Open::Forward { port } => forward::serve(port, inbound).await?,
            Open::Accept => mediator::accept(self.broker.clone(), inbound),
        };
        Ok(Response::new(stream))
    }

    async fn mediate(
        &self,
        request: Request<Streaming<Bytes>>,
    ) -> Result<Response<ChunkStream>, Status> {
        let claim = self
            .mediation
            .claim()
            .ok_or_else(|| Status::already_exists("another stream mediates this runtime"))?;
        Ok(Response::new(mediator::mediate_dns(
            self.broker.clone(),
            request.into_inner(),
            claim,
        )))
    }
}

fn ended() -> ChunkStream {
    Box::pin(tokio_stream::empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::broker::NetworkBroker;
    use crate::linux::workload_launcher::{self, WorkloadLauncher};
    use lens_sandbox_core::channel::boundary::isolation_boundary_client::IsolationBoundaryClient;
    use lens_sandbox_core::channel::boundary::isolation_boundary_server::IsolationBoundaryServer;
    use lens_sandbox_core::channel::{ConnectReply, Held};
    use lens_sandbox_core::lifecycle::PidGuard;
    use std::io::{Read as _, Write as _};
    use std::net::{SocketAddr, TcpStream, UdpSocket};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;
    use tokio_stream::StreamExt as _;
    use tokio_stream::wrappers::ReceiverStream;
    use tonic::Code;
    use tonic::transport::Channel;

    const REMOTE: &str = "192.0.2.10:80";

    struct Harness {
        client: IsolationBoundaryClient<Channel>,
        launcher: Arc<WorkloadLauncher>,
        resolver: SocketAddr,
        ca_bundle: PathBuf,
        _dir: tempfile::TempDir,
    }

    async fn harness() -> Harness {
        let (launcher, listener) = workload_launcher::start().unwrap();
        let broker = NetworkBroker::start_for_test(listener).unwrap();
        let resolver = broker.dns_address();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("system.pem"), "roots\n").unwrap();
        let ca_bundle = dir.path().join("bundle/ca.pem");
        let boundary = Boundary {
            exec: ExecManager::new(None, false, PidGuard::default()),
            broker,
            mediation: Mediation::new(),
            ca_bundle: ca_bundle.clone(),
            system_bundle: dir.path().join("system.pem"),
        };
        let incoming =
            tonic::transport::server::TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = incoming.local_addr().unwrap();
        tokio::spawn(
            channel::server()
                .add_service(IsolationBoundaryServer::new(boundary))
                .serve_with_incoming(incoming),
        );
        let channel = channel::endpoint(
            tonic::transport::Endpoint::from_shared(format!("http://{addr}")).unwrap(),
        )
        .connect()
        .await
        .unwrap();
        Harness {
            client: IsolationBoundaryClient::new(channel),
            launcher: Arc::new(launcher),
            resolver,
            ca_bundle,
            _dir: dir,
        }
    }

    impl Harness {
        async fn open(
            &self,
            open: Open,
        ) -> Result<(mpsc::Sender<Bytes>, Streaming<Bytes>), Status> {
            let (outbound, outbound_rx) = mpsc::channel(channel::RELAY_QUEUE);
            outbound.send(channel::encode(&open)).await.unwrap();
            let inbound = self
                .client
                .clone()
                .exchange(ReceiverStream::new(outbound_rx))
                .await?
                .into_inner();
            Ok((outbound, inbound))
        }

        /// Runs `connect` on the thread that the workload filter traps.
        fn in_workload<T: Send + 'static>(
            &self,
            connect: impl FnOnce() -> T + Send + 'static,
        ) -> tokio::task::JoinHandle<T> {
            let launcher = self.launcher.clone();
            tokio::task::spawn_blocking(move || launcher.execute(connect).unwrap())
        }
    }

    /// The chunks up to the end of the stream or of its direction.
    async fn read_direction(inbound: &mut Streaming<Bytes>) -> Vec<u8> {
        let mut received = Vec::new();
        while let Some(chunk) = inbound.message().await.unwrap() {
            if chunk.is_empty() {
                break;
            }
            received.extend_from_slice(&chunk);
        }
        received
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hello_of_another_protocol_is_refused() {
        let harness = harness().await;
        let Err(refused) = harness
            .open(Open::Hello {
                protocol: channel::PROTOCOL + 1,
            })
            .await
        else {
            panic!("the runtime took another protocol");
        };
        assert_eq!(refused.code(), Code::FailedPrecondition);
        let (_, mut inbound) = harness
            .open(Open::Hello {
                protocol: channel::PROTOCOL,
            })
            .await
            .unwrap();
        assert_eq!(inbound.message().await.unwrap(), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_exec_after_a_trust_runs_with_the_bundle_in_place() {
        let harness = harness().await;
        let (_, mut trusted) = harness
            .open(Open::Trust {
                ca_pem: "proxy".into(),
            })
            .await
            .unwrap();
        assert_eq!(trusted.message().await.unwrap(), None);
        assert_eq!(
            std::fs::read_to_string(&harness.ca_bundle).unwrap(),
            "roots\n\nproxy\n"
        );

        let (outbound, mut inbound) = harness.open(Open::Exec).await.unwrap();
        let attach = serde_json::json!({
            "type": "exec_attach",
            "execId": "e1",
            "argv": ["/bin/sh", "-c", "printf hi"],
            "env": {"PATH": "/usr/bin:/bin"},
            "tty": false,
        });
        outbound
            .send(Bytes::from(attach.to_string()))
            .await
            .unwrap();
        let mut types = Vec::new();
        while let Some(chunk) = inbound.message().await.unwrap() {
            let frame: serde_json::Value = serde_json::from_slice(&chunk).unwrap();
            let kind = frame["type"].as_str().unwrap().to_string();
            types.push(kind.clone());
            if kind == "exec_exit" {
                break;
            }
        }
        assert!(types.contains(&"exec_stdout".to_string()), "{types:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_forward_carries_bytes_to_the_workload_port() {
        let harness = harness().await;
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            stream.write_all(&received).await.unwrap();
        });
        let (outbound, mut inbound) = harness.open(Open::Forward { port }).await.unwrap();
        outbound.send(Bytes::from_static(b"ping")).await.unwrap();
        drop(outbound);
        assert_eq!(read_direction(&mut inbound).await, b"ping");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_forward_to_a_closed_port_is_refused() {
        let harness = harness().await;
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let Err(refused) = harness.open(Open::Forward { port }).await else {
            panic!("a forward opened to a closed port");
        };
        assert_eq!(refused.code(), Code::Unavailable);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_allowed_workload_connect_carries_bytes_both_ways() {
        let harness = harness().await;
        let (outbound, mut inbound) = harness.open(Open::Accept).await.unwrap();
        let workload = harness.in_workload(|| -> std::io::Result<Vec<u8>> {
            let mut stream = TcpStream::connect(REMOTE)?;
            stream.write_all(b"ping")?;
            stream.shutdown(std::net::Shutdown::Write)?;
            let mut echoed = Vec::new();
            stream.read_to_end(&mut echoed)?;
            Ok(echoed)
        });

        let held: Held = channel::decode(&inbound.message().await.unwrap().unwrap()).unwrap();
        assert_eq!(held.destination, REMOTE.parse::<SocketAddr>().unwrap());
        outbound
            .send(channel::encode(&ConnectReply::Allowed))
            .await
            .unwrap();
        let received = read_direction(&mut inbound).await;
        outbound.send(Bytes::from(received)).await.unwrap();
        drop(outbound);
        assert_eq!(workload.await.unwrap().unwrap(), b"ping");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_connect_the_supervisor_denies_fails_in_the_workload() {
        let harness = harness().await;
        let (outbound, mut inbound) = harness.open(Open::Accept).await.unwrap();
        let workload = harness.in_workload(|| TcpStream::connect(REMOTE).map(|_| ()));
        inbound.message().await.unwrap().unwrap();
        outbound
            .send(channel::encode(&ConnectReply::Denied))
            .await
            .unwrap();
        let refused = workload.await.unwrap().unwrap_err();
        assert_eq!(refused.raw_os_error(), Some(libc::EACCES));
    }

    /// Answers each DNS query with the pid of its sender and the query.
    async fn mediate(harness: &Harness) -> Result<(), Status> {
        let (replies, replies_rx) = mpsc::channel(channel::RELAY_QUEUE);
        let mut queries = harness
            .client
            .clone()
            .mediate(ReceiverStream::new(replies_rx))
            .await?
            .into_inner();
        tokio::spawn(async move {
            while let Some(Ok(frame)) = queries.next().await {
                let query = channel::parse_dns_query(&frame).unwrap();
                let pid = query.sender.map_or(0, |sender| sender.pid);
                let answer = [format!("{pid}:").as_bytes(), query.packet].concat();
                let _ = replies
                    .send(channel::dns_reply_frame(query.id, &answer))
                    .await;
            }
        });
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dns_query_gets_the_supervisor_answer() {
        let harness = harness().await;
        mediate(&harness).await.unwrap();
        let resolver = harness.resolver;
        let answer = harness
            .in_workload(move || -> std::io::Result<Vec<u8>> {
                let socket = UdpSocket::bind("127.0.0.1:0")?;
                socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                socket.connect(resolver)?;
                socket.send(b"query")?;
                let mut answer = vec![0_u8; 512];
                let length = socket.recv(&mut answer)?;
                answer.truncate(length);
                Ok(answer)
            })
            .await
            .unwrap()
            .unwrap();
        // The test process sent the query and the broker in it holds the
        // socket, so the supervisor learns of no other sender.
        assert_eq!(answer, b"0:query");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_second_mediate_stream_is_refused() {
        let harness = harness().await;
        mediate(&harness).await.unwrap();
        let Err(refused) = mediate(&harness).await else {
            panic!("two streams mediate one runtime");
        };
        assert_eq!(refused.code(), Code::AlreadyExists);
    }
}
