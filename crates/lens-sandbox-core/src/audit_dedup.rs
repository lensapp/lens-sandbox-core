//! The audit dedup. A failure event that repeats one sent less than
//! [`AUDIT_DEDUP_SECS`] ago is folded into that event's window instead of
//! being sent, which keeps a retry storm off the audit channel. A window that
//! folded anything closes with one summary event, so a consumer can still
//! count every refusal and knows when the last one happened.
//!
//! A summary is the event it folded, less the fields that name a connection
//! ([`refusal_identity`]), with three more `metadata` fields:
//!
//! - `summary`: `true`. Count the event as `suppressed` refusals, not as one.
//! - `suppressed`: how many repeats the window folded, the first event not
//!   included.
//! - `last_suppressed_at`: when the last of them was refused, RFC 3339 in UTC.
//!
//! The first fold in a window schedules a task on the current tokio runtime
//! that sends the summary when the window closes, so the summary never waits
//! for another refusal. A window still open when that runtime stops is not
//! summarised: the proxy has no shutdown hook to send it from. A summary that
//! closes while the audit channel is disconnected is held, up to
//! [`MAX_WINDOWS`] of them, and sent when the channel is next connected; a
//! refusal sent while it is disconnected is lost, like any other event.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use serde_json::{Map, Value};
use tokio::time::Instant;

/// How long repeats of a failure event are folded into the first one.
pub(crate) const AUDIT_DEDUP_SECS: u64 = 10;

const WINDOW: Duration = Duration::from_secs(AUDIT_DEDUP_SECS);

/// The most windows held at once. Reaching it closes them all, with their
/// summaries, rather than letting distinct refusals grow the map unbounded.
const MAX_WINDOWS: usize = 1024;

/// What makes two failure events the same refusal: everything but the fields
/// that name the connection (`src_endpoint`, the caller's pid), which change
/// on every retry a fresh process makes.
pub(crate) fn refusal_identity(event: &Value) -> Value {
    let mut identity = event.clone();
    if let Some(fields) = identity.as_object_mut() {
        fields.remove("src_endpoint");
        if let Some(process) = fields
            .get_mut("actor")
            .and_then(|actor| actor.get_mut("process"))
            .and_then(Value::as_object_mut)
        {
            process.remove("pid");
        }
    }
    identity
}

struct Window {
    opened: Instant,
    identity: Value,
    suppressed: u64,
    last_suppressed_at: SystemTime,
}

impl Window {
    fn summary(self) -> Option<Value> {
        if self.suppressed == 0 {
            return None;
        }
        let Value::Object(mut fields) = self.identity else {
            return None;
        };
        let mut metadata = match fields.remove("metadata") {
            Some(Value::Object(metadata)) => metadata,
            _ => Map::new(),
        };
        let last_suppressed_at = time::OffsetDateTime::from(self.last_suppressed_at)
            .format(&time::format_description::well_known::Rfc3339)
            .map_or(Value::Null, Value::from);
        metadata.insert("summary".into(), Value::Bool(true));
        metadata.insert("suppressed".into(), self.suppressed.into());
        metadata.insert("last_suppressed_at".into(), last_suppressed_at);
        fields.insert("metadata".into(), Value::Object(metadata));
        Some(Value::Object(fields))
    }
}

/// The window a scheduled close is for; a later window of the same refusal is
/// not it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowId {
    key: String,
    opened: Instant,
}

impl WindowId {
    pub(crate) fn closes_at(&self) -> Instant {
        self.opened + WINDOW
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum Admission {
    /// Send the event, after the summaries of the windows admitting it closed.
    Send { closed: Vec<Value> },
    /// The event was folded. `first` is set on a window's first fold: it names
    /// the window a close must now be scheduled for.
    Folded { first: Option<WindowId> },
}

/// The open dedup windows, one per refusal, and the summaries of closed ones
/// the audit channel was not connected to take.
#[derive(Default)]
pub(crate) struct DenyWindows {
    windows: HashMap<String, Window>,
    undelivered: Vec<String>,
}

impl DenyWindows {
    /// Folds `event` into the open window of the same refusal, or opens one
    /// for it. `refused_at` is the wall-clock time of the refusal.
    pub(crate) fn admit(
        &mut self,
        event: &Value,
        now: Instant,
        refused_at: SystemTime,
    ) -> Admission {
        let identity = refusal_identity(event);
        let key = identity.to_string();
        if let Some(window) = self.windows.get_mut(&key)
            && now.duration_since(window.opened) < WINDOW
        {
            window.suppressed += 1;
            window.last_suppressed_at = refused_at;
            let first = (window.suppressed == 1).then_some(WindowId {
                key,
                opened: window.opened,
            });
            return Admission::Folded { first };
        }
        let mut closed: Vec<Value> = self
            .windows
            .remove(&key)
            .and_then(Window::summary)
            .into_iter()
            .collect();
        if self.windows.len() >= MAX_WINDOWS {
            closed.extend(
                self.windows
                    .drain()
                    .filter_map(|(_, window)| window.summary()),
            );
        }
        self.windows.insert(
            key,
            Window {
                opened: now,
                identity,
                suppressed: 0,
                last_suppressed_at: refused_at,
            },
        );
        Admission::Send { closed }
    }

    /// Closes the window `id` names, returning its summary. `None` when the
    /// window folded nothing or was already closed by a later admission.
    pub(crate) fn close(&mut self, id: &WindowId) -> Option<Value> {
        if self.windows.get(&id.key)?.opened != id.opened {
            return None;
        }
        self.windows.remove(&id.key)?.summary()
    }

    /// Holds a summary the audit channel could not take; one past
    /// [`MAX_WINDOWS`] held is dropped.
    pub(crate) fn hold_undelivered(&mut self, summary: String) {
        if self.undelivered.len() < MAX_WINDOWS {
            self.undelivered.push(summary);
        }
    }

    /// The held summaries, oldest first, for a newly connected channel.
    pub(crate) fn take_undelivered(&mut self) -> Vec<String> {
        std::mem::take(&mut self.undelivered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn refused(host: &str) -> Value {
        json!({
            "type": "audit_event",
            "action": format!("CONNECT {host}:443"),
            "host": host,
            "result": "failure",
            "metadata": {"reason": "policy-deny"},
        })
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_760_000_000 + secs)
    }

    fn first_fold(admission: Admission) -> WindowId {
        match admission {
            Admission::Folded { first: Some(id) } => id,
            other => panic!("expected a window's first fold, got {other:?}"),
        }
    }

    #[test]
    fn a_refusal_after_the_window_closes_sends_the_summary_its_close_had_not_sent_yet() {
        // The close task and the next refusal race once the window is over;
        // whichever comes first sends the summary, and only once.
        let mut windows = DenyWindows::default();
        let opened = Instant::now();
        let event = refused("evil.com");
        assert_eq!(
            windows.admit(&event, opened, at(0)),
            Admission::Send { closed: vec![] }
        );
        let id = first_fold(windows.admit(&event, opened + Duration::from_secs(3), at(3)));

        let Admission::Send { closed } = windows.admit(&event, id.closes_at(), at(10)) else {
            panic!("a refusal after the window closed is sent");
        };
        let [summary] = closed.as_slice() else {
            panic!("expected the closed window's summary, got {closed:?}");
        };
        assert_eq!(summary["metadata"]["suppressed"], 1);
        assert_eq!(
            summary["metadata"]["last_suppressed_at"],
            "2025-10-09T08:53:23Z"
        );
        assert_eq!(
            windows.close(&id),
            None,
            "the new window is not the one the task closes"
        );
    }

    #[test]
    fn undelivered_summaries_are_held_up_to_the_window_cap_and_taken_once() {
        // Past the cap a summary is dropped, so a channel that never reconnects
        // cannot grow the proxy without bound; its refusals then go uncounted.
        let mut windows = DenyWindows::default();
        for n in 0..=MAX_WINDOWS {
            windows.hold_undelivered(n.to_string());
        }

        let held = windows.take_undelivered();
        assert_eq!(held.len(), MAX_WINDOWS);
        assert_eq!(held.first().map(String::as_str), Some("0"));
        assert!(windows.take_undelivered().is_empty());
    }

    #[test]
    fn closing_a_window_twice_summarises_it_once() {
        let mut windows = DenyWindows::default();
        let opened = Instant::now();
        let event = refused("evil.com");
        windows.admit(&event, opened, at(0));
        let id = first_fold(windows.admit(&event, opened, at(1)));

        assert!(windows.close(&id).is_some());
        assert_eq!(windows.close(&id), None);
    }

    #[test]
    fn only_a_windows_first_fold_schedules_its_close() {
        let mut windows = DenyWindows::default();
        let opened = Instant::now();
        let event = refused("evil.com");
        windows.admit(&event, opened, at(0));
        first_fold(windows.admit(&event, opened, at(1)));

        assert_eq!(
            windows.admit(&event, opened, at(2)),
            Admission::Folded { first: None }
        );
    }

    #[test]
    fn a_summary_keeps_the_metadata_of_the_refusal_it_folded() {
        let mut windows = DenyWindows::default();
        let opened = Instant::now();
        let event = refused("evil.com");
        windows.admit(&event, opened, at(0));
        let id = first_fold(windows.admit(&event, opened, at(1)));

        assert_eq!(
            windows.close(&id),
            Some(json!({
                "type": "audit_event",
                "action": "CONNECT evil.com:443",
                "host": "evil.com",
                "result": "failure",
                "metadata": {
                    "reason": "policy-deny",
                    "summary": true,
                    "suppressed": 1,
                    "last_suppressed_at": "2025-10-09T08:53:21Z",
                },
            }))
        );
    }

    #[test]
    fn a_summary_of_a_refusal_without_metadata_still_carries_its_count() {
        let mut windows = DenyWindows::default();
        let opened = Instant::now();
        let event =
            json!({"type": "audit_event", "action": "CONNECT evil.com:443", "result": "failure"});
        windows.admit(&event, opened, at(0));
        let id = first_fold(windows.admit(&event, opened, at(1)));

        let summary = windows.close(&id).unwrap();
        assert_eq!(summary["metadata"]["summary"], true);
        assert_eq!(summary["metadata"]["suppressed"], 1);
    }
}
