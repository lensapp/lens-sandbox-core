use tokio::sync::broadcast;

const CHANNEL_CAPACITY: usize = 256;

#[derive(Clone, Debug)]
pub struct ActivityEvent {
    pub summary: String,
}

/// A broadcast-based activity stream that allows multiple subscribers to
/// receive real-time activity events emitted by the sandbox.
#[derive(Clone)]
pub struct ActivityStream {
    tx: broadcast::Sender<ActivityEvent>,
}

impl Default for ActivityStream {
    fn default() -> Self {
        Self::new()
    }
}

impl ActivityStream {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self { tx }
    }

    pub fn emit(&self, summary: String) {
        // Ignore send errors — no subscribers is fine
        let _ = self.tx.send(ActivityEvent { summary });
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ActivityEvent> {
        self.tx.subscribe()
    }
}
