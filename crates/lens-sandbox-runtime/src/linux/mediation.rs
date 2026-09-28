//! Whether a supervisor mediates the workload. The DNS queries go to one
//! place, so only one `Mediate` stream at a time holds the mediation.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

/// A runtime that no supervisor mediates cannot serve its workload, so it
/// exits after this long, at start and after a loss, and its children with it.
const WINDOW: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub(crate) struct Mediation(Arc<watch::Sender<bool>>);

/// Holds the mediation until it drops.
pub(crate) struct Claim(Arc<watch::Sender<bool>>);

impl Drop for Claim {
    fn drop(&mut self) {
        self.0.send_replace(false);
    }
}

impl Mediation {
    pub(crate) fn new() -> Self {
        Self(Arc::new(watch::Sender::new(false)))
    }

    /// `None` while another stream holds the mediation.
    pub(crate) fn claim(&self) -> Option<Claim> {
        self.0
            .send_if_modified(|held| !std::mem::replace(held, true))
            .then(|| Claim(self.0.clone()))
    }

    /// Returns only when no supervisor mediated for the whole window.
    pub(crate) async fn expire(&self) -> io::Error {
        self.expire_after(WINDOW).await
    }

    async fn expire_after(&self, window: Duration) -> io::Error {
        let mut held = self.0.subscribe();
        loop {
            let _ = held.wait_for(|held| !*held).await;
            if tokio::time::timeout(window, held.wait_for(|held| *held))
                .await
                .is_err()
            {
                return io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("no supervisor for {} s", window.as_secs()),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHORT: Duration = Duration::from_millis(200);

    #[test]
    fn only_one_stream_holds_the_mediation() {
        let mediation = Mediation::new();
        let claim = mediation.claim().unwrap();
        assert!(mediation.claim().is_none());
        drop(claim);
        assert!(mediation.claim().is_some());
    }

    #[tokio::test]
    async fn a_runtime_without_a_supervisor_expires() {
        let error = Mediation::new().expire_after(SHORT).await;
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn a_held_mediation_does_not_expire() {
        let mediation = Mediation::new();
        let _claim = mediation.claim().unwrap();
        assert!(
            tokio::time::timeout(SHORT * 3, mediation.expire_after(SHORT))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_lost_mediation_expires_after_the_window() {
        let mediation = Mediation::new();
        let claim = mediation.claim().unwrap();
        let expiry = tokio::spawn({
            let mediation = mediation.clone();
            async move { mediation.expire_after(SHORT).await }
        });
        drop(claim);
        let error = tokio::time::timeout(SHORT * 5, expiry)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
