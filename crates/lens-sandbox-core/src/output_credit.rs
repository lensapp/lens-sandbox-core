//! Output flow control for one exec session.
//!
//! The client gives a window of output bytes on attach and more credit as
//! it delivers them. With no credit left the pipe readers stop reading, so
//! a child that writes faster than the client takes blocks in `write`
//! instead of growing the queues between them. A reader can go past the
//! credit by one read per stream: it waits for credit before it reads, not
//! for the size of the read.
//!
//! Unmetered means no limit: a session whose client gave no window, and a
//! session with no client attached, which nobody would give credit to.

use tokio::sync::watch;

pub struct OutputCredit {
    /// `None` is unmetered.
    balance: watch::Sender<Option<i64>>,
}

impl OutputCredit {
    pub fn new(window: Option<u32>) -> Self {
        Self {
            balance: watch::Sender::new(window.map(i64::from)),
        }
    }

    /// Start again with a full window, or with no limit. A new client
    /// counts from zero, so credit left from the previous one is dropped.
    /// Credit the previous client sent before the reset can still arrive
    /// after it, and adds at most one window, once.
    pub fn reset(&self, window: Option<u32>) {
        self.balance.send_replace(window.map(i64::from));
    }

    pub fn grant(&self, bytes: u32) {
        self.balance.send_if_modified(|balance| match balance {
            Some(credit) => {
                *credit += i64::from(bytes);
                true
            }
            None => false,
        });
    }

    pub fn spend(&self, bytes: usize) {
        self.balance.send_if_modified(|balance| {
            if let Some(credit) = balance {
                *credit -= bytes as i64;
            }
            false
        });
    }

    pub async fn ready(&self) {
        let _ = self
            .balance
            .subscribe()
            .wait_for(|balance| balance.is_none_or(|credit| credit > 0))
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn is_ready(credit: &OutputCredit) -> bool {
        tokio::time::timeout(Duration::from_millis(50), credit.ready())
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn unmetered_is_always_ready() {
        let credit = OutputCredit::new(None);
        credit.spend(1 << 30);
        assert!(is_ready(&credit).await);
    }

    #[tokio::test]
    async fn a_spent_window_waits_for_a_grant() {
        let credit = OutputCredit::new(Some(10));
        credit.spend(10);
        assert!(!is_ready(&credit).await);

        credit.grant(4);
        assert!(is_ready(&credit).await);
    }

    #[tokio::test]
    async fn a_read_past_the_credit_is_paid_back_by_the_next_grant() {
        let credit = OutputCredit::new(Some(10));
        credit.spend(16);
        credit.grant(6);
        assert!(!is_ready(&credit).await);

        credit.grant(1);
        assert!(is_ready(&credit).await);
    }

    #[tokio::test]
    async fn a_waiting_reader_wakes_on_a_grant() {
        let credit = std::sync::Arc::new(OutputCredit::new(Some(1)));
        credit.spend(1);
        let waiter = tokio::spawn({
            let credit = credit.clone();
            async move { credit.ready().await }
        });
        tokio::task::yield_now().await;

        credit.grant(1);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("the grant wakes the reader")
            .unwrap();
    }

    #[tokio::test]
    async fn a_reset_to_unmetered_wakes_a_waiting_reader() {
        let credit = std::sync::Arc::new(OutputCredit::new(Some(1)));
        credit.spend(1);
        let waiter = tokio::spawn({
            let credit = credit.clone();
            async move { credit.ready().await }
        });
        tokio::task::yield_now().await;

        credit.reset(None);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("no limit wakes the reader")
            .unwrap();
    }

    #[tokio::test]
    async fn a_reset_drops_the_credit_of_the_previous_client() {
        let credit = OutputCredit::new(Some(10));
        credit.grant(1000);
        credit.reset(Some(10));
        credit.spend(10);
        assert!(!is_ready(&credit).await);
    }
}
