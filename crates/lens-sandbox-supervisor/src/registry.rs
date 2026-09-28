//! The runtimes of one sandbox: which may attach, which are attached, and
//! which exchanges the supervisor waits for.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, MutexGuard, PoisonError};

use bytes::Bytes;
use lens_sandbox_core::channel::Control;
use tokio::sync::{mpsc, oneshot};
use tonic::{Status, Streaming};

/// An exchange that the supervisor asked a runtime to open.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Waiter {
    Exec { container: String, session: String },
    Forward { container: String, id: u64 },
}

impl Waiter {
    fn container(&self) -> &str {
        match self {
            Waiter::Exec { container, .. } | Waiter::Forward { container, .. } => container,
        }
    }
}

/// The two directions of an exchange that a runtime opened.
pub(crate) struct Opened {
    pub(crate) inbound: Streaming<Bytes>,
    pub(crate) outbound: mpsc::Sender<Result<Bytes, Status>>,
}

pub(crate) struct Runtimes {
    allowed: HashSet<String>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    attached: HashMap<String, Attachment>,
    trust: Option<String>,
    waiting: HashMap<Waiter, oneshot::Sender<Opened>>,
    next_id: u64,
}

struct Attachment {
    id: u64,
    controls: mpsc::UnboundedSender<Control>,
}

impl Runtimes {
    pub(crate) fn new(allowed: impl IntoIterator<Item = String>) -> Self {
        Self {
            allowed: allowed.into_iter().collect(),
            state: Mutex::default(),
        }
    }

    pub(crate) fn is_allowed(&self, container: &str) -> bool {
        self.allowed.contains(container)
    }

    /// A container has at most one attachment, so a second copy of its key
    /// cannot take over its control stream. The trust bundle comes first.
    pub(crate) fn attach(
        &self,
        container: &str,
    ) -> Result<(u64, mpsc::UnboundedReceiver<Control>), Status> {
        let mut state = self.lock();
        if state.attached.contains_key(container) {
            return Err(Status::already_exists(format!(
                "{container} is already attached"
            )));
        }
        let (controls, controls_rx) = mpsc::unbounded_channel();
        if let Some(ca_pem) = state.trust.clone() {
            let _ = controls.send(Control::Trust { ca_pem });
        }
        let id = state.next_id();
        state
            .attached
            .insert(container.to_string(), Attachment { id, controls });
        Ok((id, controls_rx))
    }

    /// Only the attachment `id` goes, with the exchanges it was asked for: a
    /// later attachment of the same container stays.
    pub(crate) fn detach(&self, container: &str, id: u64) {
        let mut state = self.lock();
        if state
            .attached
            .get(container)
            .is_some_and(|attachment| attachment.id == id)
        {
            state.attached.remove(container);
            state
                .waiting
                .retain(|waiter, _| waiter.container() != container);
        }
    }

    pub(crate) fn trust(&self, ca_pem: String) {
        let mut state = self.lock();
        for attachment in state.attached.values() {
            let _ = attachment.controls.send(Control::Trust {
                ca_pem: ca_pem.clone(),
            });
        }
        state.trust = Some(ca_pem);
    }

    pub(crate) fn next_id(&self) -> u64 {
        self.lock().next_id()
    }

    /// Asks the runtime of the waiter's container to open an exchange.
    pub(crate) fn request(
        &self,
        waiter: Waiter,
        control: Control,
    ) -> Result<oneshot::Receiver<Opened>, Status> {
        let container = waiter.container();
        let mut state = self.lock();
        let attachment = state
            .attached
            .get(container)
            .ok_or_else(|| Status::unavailable(format!("{container} is not attached")))?;
        attachment
            .controls
            .send(control)
            .map_err(|_| Status::unavailable(format!("{container} is detaching")))?;
        let (opened, opened_rx) = oneshot::channel();
        state.waiting.insert(waiter, opened);
        Ok(opened_rx)
    }

    pub(crate) fn cancel(&self, waiter: &Waiter) {
        self.lock().waiting.remove(waiter);
    }

    /// A runtime can open only an exchange that the supervisor asked for.
    pub(crate) fn deliver(&self, waiter: &Waiter, opened: Opened) -> Result<(), Status> {
        let waiting = self
            .lock()
            .waiting
            .remove(waiter)
            .ok_or_else(|| Status::not_found("nothing waits for this exchange"))?;
        waiting
            .send(opened)
            .map_err(|_| Status::cancelled("the supervisor stopped waiting"))
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl State {
    fn next_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtimes() -> Runtimes {
        Runtimes::new(["agent".to_string()])
    }

    #[test]
    fn a_second_attachment_of_a_container_is_refused() {
        let runtimes = runtimes();
        let (first, _controls) = runtimes.attach("agent").unwrap();
        let refused = runtimes.attach("agent").unwrap_err();
        assert_eq!(refused.code(), tonic::Code::AlreadyExists);
        runtimes.detach("agent", first);
        assert!(runtimes.attach("agent").is_ok());
    }

    #[test]
    fn a_stale_detach_leaves_the_new_attachment() {
        let runtimes = runtimes();
        let (first, _) = runtimes.attach("agent").unwrap();
        runtimes.detach("agent", first);
        let (_second, _controls) = runtimes.attach("agent").unwrap();
        runtimes.detach("agent", first);
        assert_eq!(
            runtimes.attach("agent").unwrap_err().code(),
            tonic::Code::AlreadyExists
        );
    }

    #[test]
    fn the_trust_bundle_reaches_attached_and_later_runtimes() {
        let runtimes = runtimes();
        let (id, mut early) = runtimes.attach("agent").unwrap();
        runtimes.trust("ca".into());
        assert_eq!(
            early.try_recv().unwrap(),
            Control::Trust {
                ca_pem: "ca".into()
            }
        );
        runtimes.detach("agent", id);
        let (_, mut late) = runtimes.attach("agent").unwrap();
        assert_eq!(
            late.try_recv().unwrap(),
            Control::Trust {
                ca_pem: "ca".into()
            }
        );
    }

    #[test]
    fn nothing_is_requested_from_a_container_that_is_not_attached() {
        let waiter = Waiter::Forward {
            container: "agent".into(),
            id: 1,
        };
        let control = Control::OpenForward { id: 1, port: 80 };
        let Err(refused) = runtimes().request(waiter, control) else {
            panic!("a request reached a container that is not attached");
        };
        assert_eq!(refused.code(), tonic::Code::Unavailable);
    }

    #[test]
    fn a_detach_drops_the_waiters_of_its_container() {
        let runtimes = runtimes();
        let (id, _controls) = runtimes.attach("agent").unwrap();
        let waiter = Waiter::Forward {
            container: "agent".into(),
            id: 7,
        };
        let mut opened = runtimes
            .request(waiter, Control::OpenForward { id: 7, port: 80 })
            .unwrap();
        runtimes.detach("agent", id);
        assert!(matches!(
            opened.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
    }

    #[test]
    fn a_waiter_is_asked_for_on_the_control_stream() {
        let runtimes = runtimes();
        let (_, mut controls) = runtimes.attach("agent").unwrap();
        let waiter = Waiter::Forward {
            container: "agent".into(),
            id: 7,
        };
        let _opened = runtimes
            .request(waiter.clone(), Control::OpenForward { id: 7, port: 80 })
            .unwrap();
        assert_eq!(
            controls.try_recv().unwrap(),
            Control::OpenForward { id: 7, port: 80 }
        );
        runtimes.cancel(&waiter);
        assert!(runtimes.lock().waiting.is_empty());
    }
}
