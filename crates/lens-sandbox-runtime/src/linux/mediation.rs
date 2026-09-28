//! Whether a supervisor mediates the workload. The DNS queries go to one
//! place, so only one `Mediate` stream at a time holds the mediation. While
//! none does, the workload has no network: each held `connect()` fails after
//! the broker's decision timeout, and each DNS query gets no answer.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Default)]
pub(crate) struct Mediation(Arc<AtomicBool>);

/// Holds the mediation until it drops.
pub(crate) struct Claim(Arc<AtomicBool>);

impl Drop for Claim {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
        tracing::warn!("no supervisor mediates the workload");
    }
}

impl Mediation {
    /// `None` while another stream holds the mediation.
    pub(crate) fn claim(&self) -> Option<Claim> {
        self.0
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        tracing::info!("a supervisor mediates the workload");
        Some(Claim(self.0.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_stream_holds_the_mediation() {
        let mediation = Mediation::default();
        let claim = mediation.claim().unwrap();
        assert!(mediation.claim().is_none());
        drop(claim);
        assert!(mediation.claim().is_some());
    }
}
