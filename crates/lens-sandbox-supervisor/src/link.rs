//! One runtime connection: the hello, the trust bundle, the DNS mediation
//! and the parked accepts, and all of them again after each loss.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use lens_sandbox_core::channel::{
    self, Held, Open, boundary::isolation_boundary_client::IsolationBoundaryClient,
};
use lens_sandbox_core::proxy::ProxyState;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tonic::{Status, Streaming};

use crate::{egress, mediate};

const RETRY_DELAY: Duration = Duration::from_secs(1);
/// How many workload `connect()` calls the runtime can hand over at once; a
/// further one waits in the runtime for a free accept.
const PARKED_ACCEPTS: usize = 8;

pub(crate) type Client = IsolationBoundaryClient<Channel>;

pub(crate) struct Link {
    pub(crate) container: String,
    pub(crate) client: Client,
    pub(crate) state: Arc<ProxyState>,
    pub(crate) dns_upstream: SocketAddr,
    pub(crate) is_own_address: fn(IpAddr) -> bool,
    pub(crate) trust: watch::Receiver<Option<String>>,
    /// `true` while the runtime is connected and trusts the proxy.
    pub(crate) ready: watch::Sender<bool>,
}

impl Link {
    pub(crate) async fn run(mut self) {
        loop {
            let container = self.container.clone();
            match self.session().await {
                Ok(()) => tracing::warn!(%container, "lost the runtime"),
                Err(status) => tracing::warn!(%container, %status, "the runtime is unreachable"),
            }
            self.ready.send_replace(false);
            tokio::time::sleep(RETRY_DELAY).await;
        }
    }

    /// Runs until the `Mediate` stream ends. The accepts end with it.
    async fn session(&mut self) -> Result<(), Status> {
        call(
            self.client.clone(),
            &Open::Hello {
                protocol: channel::PROTOCOL,
            },
        )
        .await?;
        self.push_trust().await?;
        let (replies, replies_rx) = mpsc::channel(channel::RELAY_QUEUE);
        let queries = self
            .client
            .clone()
            .mediate(ReceiverStream::new(replies_rx))
            .await?
            .into_inner();
        let mut accepts = JoinSet::new();
        for _ in 0..PARKED_ACCEPTS {
            accepts.spawn(keep_accepting(
                self.client.clone(),
                self.state.clone(),
                self.is_own_address,
            ));
        }
        self.ready.send_replace(true);
        tracing::info!(container = %self.container, "runtime connected");
        let mediation = mediate::serve(queries, replies, self.state.clone(), self.dns_upstream);
        tokio::pin!(mediation);
        loop {
            tokio::select! {
                () = &mut mediation => return Ok(()),
                changed = self.trust.changed() => {
                    if changed.is_err() {
                        return Ok(());
                    }
                    self.push_trust().await?;
                }
            }
        }
    }

    async fn push_trust(&mut self) -> Result<(), Status> {
        let ca_pem = self.trust.borrow_and_update().clone();
        match ca_pem {
            Some(ca_pem) => call(self.client.clone(), &Open::Trust { ca_pem }).await,
            None => Ok(()),
        }
    }
}

/// Opens an exchange with `open` and returns its two directions.
pub(crate) async fn open(
    mut client: Client,
    open: &Open,
) -> Result<(mpsc::Sender<Bytes>, Streaming<Bytes>), Status> {
    let (outbound, outbound_rx) = mpsc::channel(channel::RELAY_QUEUE);
    outbound
        .send(channel::encode(open))
        .await
        .map_err(|_| Status::internal("the exchange closed before its open"))?;
    let inbound = client
        .exchange(ReceiverStream::new(outbound_rx))
        .await?
        .into_inner();
    Ok((outbound, inbound))
}

/// An exchange that the runtime ends at once, as a hello or a trust.
async fn call(client: Client, open: &Open) -> Result<(), Status> {
    let (_, mut inbound) = self::open(client, open).await?;
    while inbound.message().await?.is_some() {}
    Ok(())
}

async fn keep_accepting(
    client: Client,
    state: Arc<ProxyState>,
    is_own_address: fn(IpAddr) -> bool,
) {
    loop {
        if let Err(status) = accept_one(client.clone(), &state, is_own_address).await {
            tracing::debug!(%status, "accept failed");
            tokio::time::sleep(RETRY_DELAY).await;
        }
    }
}

/// Returns when the runtime has handed over one `connect()`, which then goes
/// on in its own task.
async fn accept_one(
    client: Client,
    state: &Arc<ProxyState>,
    is_own_address: fn(IpAddr) -> bool,
) -> Result<(), Status> {
    let (outbound, mut inbound) = open(client, &Open::Accept).await?;
    let chunk = inbound
        .message()
        .await?
        .ok_or_else(|| Status::aborted("the runtime ended an accept"))?;
    let held: Held = channel::decode(&chunk)?;
    tokio::spawn(egress::serve(
        held,
        outbound,
        inbound,
        state.clone(),
        is_own_address,
    ));
    Ok(())
}
