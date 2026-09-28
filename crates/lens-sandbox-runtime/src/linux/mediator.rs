//! Carries what the broker holds to the supervisor: each workload `connect()`
//! as its own `Exchange`, and every DNS query on one `Mediate` stream.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use lens_sandbox_core::channel::{
    self, ConnectReply, Open, WireProcess,
    boundary::isolation_boundary_client::IsolationBoundaryClient,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;

use crate::linux::broker::{NetworkBroker, PendingDnsQuery, PendingTcpOpen};
use crate::linux::contract::{DnsTransport, TcpOpenDecision, TcpOpenDenial};
use crate::linux::relay;
use crate::linux::seccomp_notify::NotificationListener;

/// The broker gives up on a DNS query after this long, so a reply that comes
/// later has nobody to go to.
const DNS_ANSWER_WINDOW: Duration = Duration::from_secs(10);
const REOPEN_DELAY: Duration = Duration::from_secs(1);

/// Starts the broker on the workload's notification listener and carries
/// what it holds to the supervisor, until the broker stops. Needs a tokio
/// runtime.
pub fn start(
    listener: NotificationListener,
    client: IsolationBoundaryClient<Channel>,
) -> std::io::Result<NetworkBroker> {
    Ok(serve(NetworkBroker::start(listener, None)?, client))
}

fn serve(broker: NetworkBroker, client: IsolationBoundaryClient<Channel>) -> NetworkBroker {
    tokio::spawn(mediate_tcp(broker.clone(), client.clone()));
    tokio::spawn(keep_mediating_dns(broker.clone(), client));
    broker
}

/// Each open runs in its own task, so a slow supervisor decision holds only
/// its own `connect()`.
async fn mediate_tcp(broker: NetworkBroker, client: IsolationBoundaryClient<Channel>) {
    while let Ok(pending) = broker.accept().await {
        tokio::spawn(relay_tcp(pending, client.clone()));
    }
}

async fn relay_tcp(pending: PendingTcpOpen, mut client: IsolationBoundaryClient<Channel>) {
    tracing::debug!(
        destination = %pending.destination,
        socket_cookie = pending.socket.socket_cookie,
        notification_to_queue = ?pending.notification_to_queue,
        queue_wait = ?pending.queued_at.elapsed(),
        "mediating a workload connect"
    );
    let process = match &pending.identity {
        Ok(process) => WireProcess::from(process),
        Err(error) => {
            tracing::warn!(destination = %pending.destination, %error, "no identity for a workload connect");
            let _ = pending
                .complete(TcpOpenDecision::Denied(TcpOpenDenial::IdentityUnavailable))
                .await;
            return;
        }
    };
    let (outbound, outbound_rx) = mpsc::channel(relay::QUEUE);
    let open = Open::Connect {
        destination: pending.destination,
        process,
    };
    if outbound.send(channel::encode(&open)).await.is_err() {
        return;
    }
    let decision = async {
        let mut inbound = client
            .exchange(ReceiverStream::new(outbound_rx))
            .await?
            .into_inner();
        let reply = inbound
            .message()
            .await?
            .ok_or_else(|| tonic::Status::aborted("no connect reply"))?;
        Ok::<_, tonic::Status>((channel::decode::<ConnectReply>(&reply)?, inbound))
    };
    let (reply, inbound) = match decision.await {
        Ok(decided) => decided,
        Err(status) => {
            tracing::warn!(destination = %pending.destination, %status, "connect mediation failed");
            let _ = pending
                .complete(TcpOpenDecision::Denied(TcpOpenDenial::MediationUnavailable))
                .await;
            return;
        }
    };
    let decision = match reply {
        ConnectReply::Allowed => TcpOpenDecision::RelayReady,
        ConnectReply::Denied => TcpOpenDecision::Denied(TcpOpenDenial::PolicyDenied),
    };
    let relay = match pending.complete(decision).await {
        Ok(Some(relay)) => relay,
        Ok(None) => return,
        Err(error) => {
            tracing::warn!(%error, "relay setup failed");
            return;
        }
    };
    let relayed = async {
        relay.set_nonblocking(true)?;
        relay::pump(tokio::net::TcpStream::from_std(relay)?, outbound, inbound).await
    };
    if let Err(error) = relayed.await {
        tracing::debug!(%error, "relay closed");
    }
}

/// Queries wait here for their reply, by frame id.
type Waiting = Mutex<HashMap<u32, PendingDnsQuery>>;

/// A lost `Mediate` stream opens again; the channel below it reconnects.
async fn keep_mediating_dns(broker: NetworkBroker, client: IsolationBoundaryClient<Channel>) {
    while broker.confirm_healthy().is_ok()
        && mediate_dns(&broker, client.clone()).await == Ended::StreamLost
    {
        tokio::time::sleep(REOPEN_DELAY).await;
    }
}

#[derive(PartialEq, Eq)]
enum Ended {
    BrokerStopped,
    StreamLost,
}

/// Runs until the broker or the `Mediate` stream stops. A query that is still
/// waiting then gets an error, which the broker answers by dropping it.
async fn mediate_dns(
    broker: &NetworkBroker,
    mut client: IsolationBoundaryClient<Channel>,
) -> Ended {
    let (outbound, outbound_rx) = mpsc::channel(relay::QUEUE);
    let mut replies = match client.mediate(ReceiverStream::new(outbound_rx)).await {
        Ok(response) => response.into_inner(),
        Err(status) => {
            tracing::warn!(%status, "DNS mediation stream failed to open");
            return Ended::StreamLost;
        }
    };
    let waiting = Waiting::default();
    let send = async {
        let mut next_id = 0_u32;
        while let Ok(query) = broker.accept_dns().await {
            tracing::debug!(
                notification_to_queue = ?query.notification_to_queue,
                queue_wait = ?query.queued_at.elapsed(),
                "mediating a DNS query"
            );
            next_id = next_id.wrapping_add(1);
            let packet = match query.transport {
                DnsTransport::Udp => &query.request[..],
                DnsTransport::Tcp => query.request.get(2..).unwrap_or_default(),
            };
            let sender = query.identity.as_ref().ok().map(WireProcess::from);
            let frame = channel::dns_query_frame(next_id, sender.as_ref(), packet);
            wait_for_reply(&waiting, next_id, query);
            if outbound.send(frame).await.is_err() {
                return Ended::StreamLost;
            }
        }
        Ended::BrokerStopped
    };
    let receive = async {
        while let Ok(Some(frame)) = replies.message().await {
            let Some((id, answer)) = channel::parse_dns_reply(&frame) else {
                continue;
            };
            let Some(query) = lock(&waiting).remove(&id) else {
                continue;
            };
            let response = match query.transport {
                DnsTransport::Udp => Ok(answer.to_vec()),
                DnsTransport::Tcp => with_length_prefix(answer),
            };
            let _ = query.complete(response);
        }
        Ended::StreamLost
    };
    let ended = tokio::select! {
        ended = send => ended,
        ended = receive => ended,
    };
    for (_, query) in lock(&waiting).drain() {
        let _ = query.complete(Err(std::io::Error::other("DNS mediation stopped")));
    }
    ended
}

fn wait_for_reply(waiting: &Waiting, id: u32, query: PendingDnsQuery) {
    let mut waiting = lock(waiting);
    waiting.retain(|_, query| query.queued_at.elapsed() < DNS_ANSWER_WINDOW);
    waiting.insert(id, query);
}

fn with_length_prefix(answer: &[u8]) -> std::io::Result<Vec<u8>> {
    let length = u16::try_from(answer.len())
        .map_err(|_| std::io::Error::other("DNS answer is too long for TCP"))?;
    let mut framed = Vec::with_capacity(2 + answer.len());
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(answer);
    Ok(framed)
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use lens_sandbox_core::channel::boundary::isolation_boundary_server::{
        IsolationBoundary, IsolationBoundaryServer,
    };
    use std::io::{Read as _, Write as _};
    use std::net::{SocketAddr, TcpStream, UdpSocket};
    use std::pin::Pin;
    use tokio_stream::{Stream, StreamExt as _};
    use tonic::Streaming;
    use tonic::{Request, Response, Status};

    type ChunkStream = Pin<Box<dyn Stream<Item = Result<Bytes, Status>> + Send>>;

    const ALLOWED: &str = "192.0.2.10:80";

    /// Allows only [`ALLOWED`] and echoes its bytes; answers each DNS query
    /// with the pid of its sender and the query.
    struct FakeSupervisor;

    #[tonic::async_trait]
    impl IsolationBoundary for FakeSupervisor {
        type ExchangeStream = ChunkStream;
        type MediateStream = ChunkStream;

        async fn exchange(
            &self,
            request: Request<Streaming<Bytes>>,
        ) -> Result<Response<ChunkStream>, Status> {
            let mut chunks = request.into_inner();
            let first = chunks
                .message()
                .await?
                .ok_or_else(|| Status::aborted("empty"))?;
            let Open::Connect { destination, .. } = channel::decode(&first)? else {
                return Err(Status::invalid_argument("not a connect"));
            };
            let allowed = destination == ALLOWED.parse::<SocketAddr>().unwrap();
            let reply = if allowed {
                ConnectReply::Allowed
            } else {
                ConnectReply::Denied
            };
            let head = tokio_stream::once(Ok(channel::encode(&reply)));
            let echo = chunks.take_while(move |_| allowed);
            Ok(Response::new(Box::pin(head.chain(echo))))
        }

        async fn mediate(
            &self,
            request: Request<Streaming<Bytes>>,
        ) -> Result<Response<ChunkStream>, Status> {
            let answers = request.into_inner().map(|frame| {
                let frame = frame?;
                let query = channel::parse_dns_query(&frame)?;
                let pid = query.sender.map_or(0, |sender| sender.pid);
                let answer = [format!("{pid}:").as_bytes(), query.packet].concat();
                Ok(channel::dns_reply_frame(query.id, &answer))
            });
            Ok(Response::new(Box::pin(answers)))
        }
    }

    async fn client_of_a_fake_supervisor() -> IsolationBoundaryClient<Channel> {
        let incoming =
            tonic::transport::server::TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = incoming.local_addr().unwrap();
        tokio::spawn(
            channel::server()
                .add_service(IsolationBoundaryServer::new(FakeSupervisor))
                .serve_with_incoming(incoming),
        );
        let channel = channel::endpoint(
            tonic::transport::Endpoint::from_shared(format!("http://{addr}")).unwrap(),
        )
        .connect()
        .await
        .unwrap();
        IsolationBoundaryClient::new(channel)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_workload_connect_reaches_the_supervisor_and_carries_bytes() {
        let (launcher, listener) = crate::linux::workload_launcher::start().unwrap();
        let broker = NetworkBroker::start_for_test(listener).unwrap();
        let _broker = serve(broker, client_of_a_fake_supervisor().await);

        let echoed = tokio::task::spawn_blocking(move || {
            launcher
                .execute(|| -> std::io::Result<Vec<u8>> {
                    let mut stream = TcpStream::connect(ALLOWED)?;
                    stream.write_all(b"ping")?;
                    stream.shutdown(std::net::Shutdown::Write)?;
                    let mut echoed = Vec::new();
                    stream.read_to_end(&mut echoed)?;
                    Ok(echoed)
                })
                .unwrap()
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(echoed, b"ping");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_connect_the_supervisor_denies_fails_in_the_workload() {
        let (launcher, listener) = crate::linux::workload_launcher::start().unwrap();
        let broker = NetworkBroker::start_for_test(listener).unwrap();
        let _broker = serve(broker, client_of_a_fake_supervisor().await);

        let refused = tokio::task::spawn_blocking(move || {
            launcher
                .execute(|| TcpStream::connect("192.0.2.10:81").map(|_| ()))
                .unwrap()
        })
        .await
        .unwrap();
        assert_eq!(refused.unwrap_err().raw_os_error(), Some(libc::EACCES));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dns_query_gets_the_supervisor_answer() {
        let (launcher, listener) = crate::linux::workload_launcher::start().unwrap();
        let broker = NetworkBroker::start_for_test(listener).unwrap();
        let resolver = broker.dns_address();
        let _broker = serve(broker, client_of_a_fake_supervisor().await);

        let answer = tokio::task::spawn_blocking(move || {
            launcher
                .execute(move || -> std::io::Result<Vec<u8>> {
                    let socket = UdpSocket::bind("127.0.0.1:0")?;
                    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                    socket.connect(resolver)?;
                    socket.send(b"query")?;
                    let mut answer = vec![0_u8; 512];
                    let length = socket.recv(&mut answer)?;
                    answer.truncate(length);
                    Ok(answer)
                })
                .unwrap()
        })
        .await
        .unwrap()
        .unwrap();
        // The test process sent the query and the broker in it holds the
        // socket, so the supervisor learns of no other sender.
        assert_eq!(answer, b"0:query");
    }
}
