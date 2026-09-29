//! DNS on the `Mediate` stream of a runtime.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use lens_sandbox_core::channel;
use lens_sandbox_core::dns;
use lens_sandbox_core::peer_process::PeerProcess;
use lens_sandbox_core::proxy::ProxyState;
use tokio::sync::{Semaphore, mpsc};
use tonic::Streaming;

/// Each query holds a task and an upstream socket, so a workload that floods
/// DNS could exhaust the supervisor. The core stub has the same bound.
const MAX_INFLIGHT_QUERIES: usize = 64;

/// Answers the queries until their stream ends. Each query is answered in
/// its own task, so a slow upstream holds only its own query. A query that
/// gets no answer, or finds no free task, gets no reply; the runtime drops it
/// after its own timeout.
pub(crate) async fn serve(
    mut queries: Streaming<Bytes>,
    replies: mpsc::Sender<Bytes>,
    state: Arc<ProxyState>,
    upstream: SocketAddr,
) {
    let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT_QUERIES));
    loop {
        let frame = match queries.message().await {
            Ok(Some(frame)) => frame,
            Ok(None) => return,
            Err(status) => {
                tracing::debug!(%status, "DNS mediation stream lost");
                return;
            }
        };
        let query = match channel::parse_dns_query(&frame) {
            Ok(query) => query,
            Err(status) => {
                tracing::warn!(%status, "the runtime sent a malformed DNS query");
                return;
            }
        };
        let Ok(permit) = inflight.clone().try_acquire_owned() else {
            tracing::warn!("DNS mediation at capacity ({MAX_INFLIGHT_QUERIES}), dropping a query");
            continue;
        };
        let id = query.id;
        let sender = query.sender.map(PeerProcess::from);
        let packet = query.packet.to_vec();
        let state = state.clone();
        let replies = replies.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Some(answer) = dns::answer(&packet, sender.as_ref(), &state, upstream).await {
                let _ = replies.send(channel::dns_reply_frame(id, &answer)).await;
            }
        });
    }
}
