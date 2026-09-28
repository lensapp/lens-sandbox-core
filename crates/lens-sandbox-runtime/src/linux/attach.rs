//! The control stream: the runtime attaches to its supervisor and does what
//! each [`Control`] asks, and attaches again after a loss.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use lens_sandbox_core::channel::{
    self, Control, Open, boundary::isolation_boundary_client::IsolationBoundaryClient,
};
use lens_sandbox_core::exec_manager::ExecManager;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tonic::{Status, Streaming};

use crate::linux::{exec_stream, forward, trust};

/// How long the runtime waits for a supervisor, at start and after a loss.
/// The runtime then exits, and its children with it.
const RECONNECT_WINDOW: Duration = Duration::from_secs(30);
const RETRY_DELAY: Duration = Duration::from_secs(1);

pub(crate) struct Services {
    pub(crate) client: IsolationBoundaryClient<Channel>,
    pub(crate) exec: ExecManager,
    pub(crate) ca_bundle: PathBuf,
    pub(crate) system_bundle: PathBuf,
}

/// Returns only when no supervisor took the runtime for the whole window.
pub(crate) async fn serve(services: Services) -> io::Error {
    serve_within(services, RECONNECT_WINDOW).await
}

async fn serve_within(services: Services, window: Duration) -> io::Error {
    let mut deadline = Instant::now() + window;
    loop {
        match attach(&services).await {
            Ok(()) => deadline = Instant::now() + window,
            Err(status) => tracing::warn!(%status, "the supervisor did not take the runtime"),
        }
        if Instant::now() >= deadline {
            return io::Error::new(
                io::ErrorKind::TimedOut,
                format!("no supervisor for {} s", window.as_secs()),
            );
        }
        tokio::time::sleep(RETRY_DELAY).await;
    }
}

/// `Ok` once the supervisor took the runtime, whatever ended the stream.
async fn attach(services: &Services) -> Result<(), Status> {
    // The runtime sends nothing after the open. Holding the sender keeps the
    // stream, and with it the attachment, open.
    let (outbound, outbound_rx) = mpsc::channel(1);
    outbound
        .send(channel::encode(&Open::Attach {
            protocol: channel::PROTOCOL,
        }))
        .await
        .map_err(|_| Status::internal("the attach stream closed before its open"))?;
    let controls = services
        .client
        .clone()
        .exchange(ReceiverStream::new(outbound_rx))
        .await?
        .into_inner();
    tracing::info!("attached to the supervisor");
    if let Err(status) = services.follow(controls).await {
        tracing::warn!(%status, "the control stream failed");
    }
    Ok(())
}

impl Services {
    async fn follow(&self, mut controls: Streaming<bytes::Bytes>) -> Result<(), Status> {
        while let Some(chunk) = controls.message().await? {
            match channel::decode::<Control>(&chunk) {
                Ok(control) => self.apply(control),
                Err(status) => tracing::warn!(%status, "unknown control"),
            }
        }
        Ok(())
    }

    /// Each control is done in order, so a trust bundle is in place before
    /// the exec that comes after it.
    fn apply(&self, control: Control) {
        match control {
            Control::Trust { ca_pem } => {
                if let Err(error) =
                    trust::write_bundle(&self.ca_bundle, &self.system_bundle, &ca_pem)
                {
                    tracing::warn!(bundle = %self.ca_bundle.display(), %error, "CA bundle not written");
                }
            }
            Control::OpenExec { session } => {
                tokio::spawn(exec_stream::serve(
                    session,
                    self.exec.clone(),
                    self.client.clone(),
                ));
            }
            Control::OpenForward { id, port } => {
                tokio::spawn(forward::serve(id, port, self.client.clone()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use lens_sandbox_core::channel::boundary::isolation_boundary_server::{
        IsolationBoundary, IsolationBoundaryServer,
    };
    use lens_sandbox_core::lifecycle::PidGuard;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_stream::{Stream, StreamExt as _};
    use tonic::{Request, Response};

    type ChunkStream = Pin<Box<dyn Stream<Item = Result<Bytes, Status>> + Send>>;

    /// An exchange other than the attach, handed to the test.
    struct Opened {
        open: Open,
        inbound: Streaming<Bytes>,
        outbound: mpsc::Sender<Result<Bytes, Status>>,
    }

    /// Sends its controls on each attach. `hold` keeps the attach open after
    /// them.
    struct FakeSupervisor {
        controls: Vec<Control>,
        hold: bool,
        attaches: Arc<AtomicUsize>,
        opened: mpsc::UnboundedSender<Opened>,
    }

    #[tonic::async_trait]
    impl IsolationBoundary for FakeSupervisor {
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
            let open: Open = channel::decode(&first)?;
            if let Open::Attach { .. } = open {
                self.attaches.fetch_add(1, Ordering::SeqCst);
                let controls: Vec<_> = self
                    .controls
                    .iter()
                    .map(|control| Ok(channel::encode(control)))
                    .collect();
                let controls = tokio_stream::iter(controls);
                return Ok(Response::new(if self.hold {
                    Box::pin(controls.chain(tokio_stream::pending()))
                } else {
                    Box::pin(controls)
                }));
            }
            let (outbound, outbound_rx) = mpsc::channel(8);
            let _ = self.opened.send(Opened {
                open,
                inbound,
                outbound,
            });
            Ok(Response::new(Box::pin(ReceiverStream::new(outbound_rx))))
        }

        async fn mediate(
            &self,
            _: Request<Streaming<Bytes>>,
        ) -> Result<Response<ChunkStream>, Status> {
            Err(Status::unimplemented("mediate"))
        }
    }

    struct Harness {
        services: Services,
        attaches: Arc<AtomicUsize>,
        opened: mpsc::UnboundedReceiver<Opened>,
        _dir: tempfile::TempDir,
    }

    async fn harness(controls: Vec<Control>, hold: bool) -> Harness {
        let attaches = Arc::new(AtomicUsize::new(0));
        let (opened_tx, opened) = mpsc::unbounded_channel();
        let supervisor = FakeSupervisor {
            controls,
            hold,
            attaches: attaches.clone(),
            opened: opened_tx,
        };
        let incoming =
            tonic::transport::server::TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = incoming.local_addr().unwrap();
        tokio::spawn(
            channel::server()
                .add_service(IsolationBoundaryServer::new(supervisor))
                .serve_with_incoming(incoming),
        );
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("system.pem"), "roots\n").unwrap();
        Harness {
            services: services(&format!("http://{addr}"), dir.path()),
            attaches,
            opened,
            _dir: dir,
        }
    }

    fn services(uri: &str, dir: &std::path::Path) -> Services {
        let channel =
            channel::endpoint(tonic::transport::Endpoint::from_shared(uri.to_string()).unwrap())
                .connect_lazy();
        Services {
            client: IsolationBoundaryClient::new(channel),
            exec: ExecManager::new(None, false, PidGuard::default()),
            ca_bundle: dir.join("bundle/ca.pem"),
            system_bundle: dir.join("system.pem"),
        }
    }

    async fn next_opened(opened: &mut mpsc::UnboundedReceiver<Opened>) -> Opened {
        tokio::time::timeout(Duration::from_secs(5), opened.recv())
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn an_exec_after_a_trust_runs_with_the_bundle_in_place() {
        let mut harness = harness(
            vec![
                Control::Trust {
                    ca_pem: "proxy".into(),
                },
                Control::OpenExec {
                    session: "s1".into(),
                },
            ],
            true,
        )
        .await;
        let bundle = harness.services.ca_bundle.clone();
        tokio::spawn(serve(harness.services));

        let mut exec = next_opened(&mut harness.opened).await;
        assert_eq!(
            exec.open,
            Open::Exec {
                session: "s1".into()
            }
        );
        assert_eq!(
            std::fs::read_to_string(&bundle).unwrap(),
            "roots\n\nproxy\n"
        );
        let attach = serde_json::json!({
            "type": "exec_attach",
            "execId": "e1",
            "argv": ["/bin/sh", "-c", "printf hi"],
            "env": {"PATH": "/usr/bin:/bin"},
            "tty": false,
        });
        exec.outbound
            .send(Ok(Bytes::from(attach.to_string())))
            .await
            .unwrap();
        let mut types = Vec::new();
        while let Some(chunk) = exec.inbound.message().await.unwrap() {
            let frame: serde_json::Value = serde_json::from_slice(&chunk).unwrap();
            let kind = frame["type"].as_str().unwrap().to_string();
            types.push(kind.clone());
            if kind == "exec_exit" {
                break;
            }
        }
        assert!(types.contains(&"exec_stdout".to_string()), "{types:?}");
    }

    #[tokio::test]
    async fn a_forward_carries_bytes_to_the_workload_port() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            stream.write_all(&received).await.unwrap();
        });
        let mut harness = harness(vec![Control::OpenForward { id: 7, port }], true).await;
        tokio::spawn(serve(harness.services));

        let mut forward = next_opened(&mut harness.opened).await;
        assert_eq!(forward.open, Open::Forward { id: 7 });
        forward
            .outbound
            .send(Ok(Bytes::from_static(b"ping")))
            .await
            .unwrap();
        drop(forward.outbound);
        let mut echoed = Vec::new();
        while let Some(chunk) = forward.inbound.message().await.unwrap() {
            echoed.extend_from_slice(&chunk);
        }
        assert_eq!(echoed, b"ping");
    }

    #[tokio::test]
    async fn a_forward_to_a_closed_port_ends_at_once() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let mut harness = harness(vec![Control::OpenForward { id: 8, port }], true).await;
        tokio::spawn(serve(harness.services));

        let mut forward = next_opened(&mut harness.opened).await;
        assert_eq!(forward.inbound.message().await.unwrap(), None);
    }

    #[tokio::test]
    async fn the_runtime_attaches_again_after_a_loss() {
        let harness = harness(vec![], false).await;
        let attaches = harness.attaches.clone();
        tokio::spawn(serve(harness.services));
        tokio::time::timeout(Duration::from_secs(10), async {
            while attaches.load(Ordering::SeqCst) < 2 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn the_runtime_gives_up_without_a_supervisor() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = closed.local_addr().unwrap();
        drop(closed);
        let dir = tempfile::tempdir().unwrap();
        let error = serve_within(
            services(&format!("http://{addr}"), dir.path()),
            Duration::from_millis(1500),
        )
        .await;
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
