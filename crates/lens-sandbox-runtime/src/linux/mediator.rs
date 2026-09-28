//! Carries what the broker holds to the supervisor: each workload `connect()`
//! on an `Accept` exchange, and every DNS query on the `Mediate` stream.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use bytes::Bytes;
use lens_sandbox_core::channel::{self, ConnectReply, Held, WireProcess};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Status, Streaming};

use crate::linux::boundary::ChunkStream;
use crate::linux::broker::{NetworkBroker, PendingDnsQuery, PendingTcpOpen};
use crate::linux::contract::{DnsTransport, TcpOpenDecision, TcpOpenDenial};
use crate::linux::mediation::Claim;

/// The broker gives up on a DNS query after this long, so a reply that comes
/// later has nobody to go to.
const DNS_ANSWER_WINDOW: Duration = Duration::from_secs(10);

type Outbound = mpsc::Sender<Result<Bytes, Status>>;

/// Hands the next workload `connect()` to the supervisor, and relays it when
/// the supervisor allows it. The supervisor keeps some `Accept` exchanges
/// open, so a `connect()` waits only for a free one.
pub(crate) fn accept(broker: NetworkBroker, inbound: Streaming<Bytes>) -> ChunkStream {
    let (outbound, outbound_rx) = mpsc::channel(channel::RELAY_QUEUE);
    tokio::spawn(async move {
        let failure = outbound.clone();
        if let Err(error) = hand_over(&broker, outbound, inbound).await {
            tracing::debug!(%error, "workload connect ended");
            let _ = failure
                .send(Err(Status::unavailable(error.to_string())))
                .await;
        }
    });
    Box::pin(ReceiverStream::new(outbound_rx))
}

async fn hand_over(
    broker: &NetworkBroker,
    outbound: Outbound,
    mut inbound: Streaming<Bytes>,
) -> std::io::Result<()> {
    // A supervisor that went away takes no further `connect()`.
    let (pending, process) = tokio::select! {
        () = outbound.closed() => return Ok(()),
        next = next_attributed(broker) => next?,
    };
    tracing::debug!(
        destination = %pending.destination,
        socket_cookie = pending.socket.socket_cookie,
        notification_to_queue = ?pending.notification_to_queue,
        queue_wait = ?pending.queued_at.elapsed(),
        "mediating a workload connect"
    );
    let held = Held {
        destination: pending.destination,
        process,
    };
    let reply = match outbound.send(Ok(channel::encode(&held))).await {
        Ok(()) => match inbound.message().await {
            Ok(Some(chunk)) => channel::decode::<ConnectReply>(&chunk).ok(),
            _ => None,
        },
        Err(_) => None,
    };
    let decision = match reply {
        Some(ConnectReply::Allowed) => TcpOpenDecision::RelayReady,
        Some(ConnectReply::Denied) => TcpOpenDecision::Denied(TcpOpenDenial::PolicyDenied),
        None => TcpOpenDecision::Denied(TcpOpenDenial::MediationUnavailable),
    };
    let Some(relay) = pending.complete(decision).await? else {
        return Ok(());
    };
    relay.set_nonblocking(true)?;
    channel::pump(tokio::net::TcpStream::from_std(relay)?, outbound, inbound).await
}

/// The supervisor judges a `connect()` by its process, so one without an
/// identity is denied here, and the wait goes on.
async fn next_attributed(broker: &NetworkBroker) -> std::io::Result<(PendingTcpOpen, WireProcess)> {
    loop {
        let pending = broker.accept().await?;
        match &pending.identity {
            Ok(process) => {
                let process = WireProcess::from(process);
                return Ok((pending, process));
            }
            Err(error) => {
                tracing::warn!(destination = %pending.destination, %error, "no identity for a workload connect");
                let _ = pending
                    .complete(TcpOpenDecision::Denied(TcpOpenDenial::IdentityUnavailable))
                    .await;
            }
        }
    }
}

/// Queries wait here for their reply, by frame id.
type Waiting = Mutex<HashMap<u32, PendingDnsQuery>>;

/// Sends each DNS query of the workload to the supervisor, and completes it
/// with the reply that names it, as long as the stream holds `claim`.
pub(crate) fn mediate_dns(
    broker: NetworkBroker,
    replies: Streaming<Bytes>,
    claim: Claim,
) -> ChunkStream {
    let (outbound, outbound_rx) = mpsc::channel(channel::RELAY_QUEUE);
    tokio::spawn(async move {
        relay_dns(&broker, outbound, replies).await;
        drop(claim);
    });
    Box::pin(ReceiverStream::new(outbound_rx))
}

/// Runs until the broker or the stream stops. A query that is still waiting
/// then gets an error, which the broker answers by dropping it.
async fn relay_dns(broker: &NetworkBroker, outbound: Outbound, mut replies: Streaming<Bytes>) {
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
            if outbound.send(Ok(frame)).await.is_err() {
                return;
            }
        }
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
    };
    tokio::select! {
        () = send => {}
        () = receive => {}
    }
    for (_, query) in lock(&waiting).drain() {
        let _ = query.complete(Err(std::io::Error::other("DNS mediation stopped")));
    }
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
