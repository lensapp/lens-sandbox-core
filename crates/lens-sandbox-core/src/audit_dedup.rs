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
//! - `suppressed`: how many refusals it counts: the repeats the window folded,
//!   the first event, which was sent, not included.
//! - `last_suppressed_at`: when the last of them was refused, RFC 3339 in UTC.
//!
//! The first fold in a window schedules a task on the current tokio runtime
//! that sends the summary when the window closes, so the summary never waits
//! for another refusal. A window still open when that runtime stops is not
//! summarised: the proxy has no shutdown hook to send it from.
//!
//! A summary that closes while the audit channel is disconnected is held and
//! sent when the channel is next connected. One is held per refusal: a later
//! summary of the same refusal folds into it, its count added. Past
//! [`MAX_WINDOWS`] refusals held, the rest are counted in one overflow summary,
//! `action` and `metadata.reason` `audit-overflow`, which names no destination,
//! so a channel that never reconnects cannot grow the proxy without bound and
//! still no refusal goes uncounted.
//!
//! A refusal no channel takes is held the same way, as a count of one: it
//! folds with the summary of the repeats its window goes on to fold, so one
//! summary counts them all. A held summary then counts the first event too,
//! as that was never sent.
//!
//! A failure event a channel took but did not write, because the connection
//! failed or closed first, is held the same way ([`Tally::unwritten`]): a
//! summary with its count, any other as one refusal, refused when it was sent
//! ([`QueuedRefusals`]), not when it was found unwritten.

use std::collections::{HashMap, VecDeque};
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
    /// The count of the repeats the window folded; `None` when it folded none.
    fn tally(self, key: String) -> Option<Tally> {
        (self.suppressed > 0).then_some(Tally {
            key,
            identity: self.identity,
            count: self.suppressed,
            last_at: self.last_suppressed_at,
        })
    }
}

/// Refusals of one kind counted but not yet sent: a closed window's repeats,
/// or refusals no audit channel took. Sent as one summary.
#[derive(Debug, PartialEq)]
pub(crate) struct Tally {
    key: String,
    identity: Value,
    count: u64,
    last_at: SystemTime,
}

impl Tally {
    /// One refusal of `event`, refused at `refused_at`.
    pub(crate) fn refused(event: &Value, refused_at: SystemTime) -> Tally {
        let identity = refusal_identity(event);
        Tally {
            key: identity.to_string(),
            identity,
            count: 1,
            last_at: refused_at,
        }
    }

    /// What a failure event the audit channel took but did not write counts:
    /// a summary's `suppressed`, refused at its `last_suppressed_at`, or one
    /// refusal at `refused_at`. `None` for any other message.
    pub(crate) fn unwritten(message: &str, refused_at: SystemTime) -> Option<Tally> {
        let event: Value = serde_json::from_str(message).ok()?;
        if event["type"] != "audit_event" || event["result"] != "failure" {
            return None;
        }
        if event["metadata"]["summary"] != true {
            return Some(Tally::refused(&event, refused_at));
        }
        let mut identity = event;
        let fields = identity.as_object_mut()?;
        let metadata = fields.get_mut("metadata")?.as_object_mut()?;
        metadata.remove("summary");
        let count = metadata.remove("suppressed")?.as_u64()?;
        let last_at = metadata
            .remove("last_suppressed_at")
            .and_then(|at| {
                let at = at.as_str()?;
                time::OffsetDateTime::parse(at, &time::format_description::well_known::Rfc3339).ok()
            })
            .map_or(refused_at, SystemTime::from);
        if metadata.is_empty() {
            fields.remove("metadata");
        }
        Some(Tally {
            key: identity.to_string(),
            identity,
            count,
            last_at,
        })
    }

    /// The summary event that counts the tally's refusals.
    pub(crate) fn summary(&self) -> Value {
        let mut fields = match &self.identity {
            Value::Object(fields) => fields.clone(),
            _ => Map::new(),
        };
        let mut metadata = match fields.remove("metadata") {
            Some(Value::Object(metadata)) => metadata,
            _ => Map::new(),
        };
        let last_suppressed_at = time::OffsetDateTime::from(self.last_at)
            .format(&time::format_description::well_known::Rfc3339)
            .map_or(Value::Null, Value::from);
        metadata.insert("summary".into(), Value::Bool(true));
        metadata.insert("suppressed".into(), self.count.into());
        metadata.insert("last_suppressed_at".into(), last_suppressed_at);
        fields.insert("metadata".into(), Value::Object(metadata));
        Value::Object(fields)
    }

    fn fold(&mut self, other: Tally) {
        self.count += other.count;
        self.last_at = self.last_at.max(other.last_at);
    }

    /// The tally counted in the overflow summary instead, once [`MAX_WINDOWS`]
    /// refusals are held.
    fn into_overflow(self) -> Tally {
        let identity = overflow_identity();
        Tally {
            key: identity.to_string(),
            identity,
            count: self.count,
            last_at: self.last_at,
        }
    }
}

/// What the overflow summary counts: refusals held while [`MAX_WINDOWS`] other
/// refusals already were. It names no destination, so `metadata.reason` is one
/// no refusal has, and a consumer counts them without filing them under one.
fn overflow_identity() -> Value {
    serde_json::json!({
        "type": "audit_event",
        "source": "sandbox-proxy",
        "action": "audit-overflow",
        "result": "failure",
        "metadata": {"reason": "audit-overflow"},
    })
}

/// The refusals sent on the audit channel as themselves and not yet written,
/// oldest first, each with when it was refused. An event does not say when it
/// was refused, so one the channel took but did not write is held as refused
/// then ([`Self::refused_at`]), not when the connection was found gone: a
/// summary of a later refusal, dated by its own, must still read as later.
///
/// They are in the order the channel carries them, and the writer writes in
/// that order, so each message it writes is compared with the oldest alone,
/// and no more are queued here than on the channel.
#[derive(Default)]
pub(crate) struct QueuedRefusals {
    queued: VecDeque<(String, SystemTime)>,
}

impl QueuedRefusals {
    /// `message` was sent on the channel, refused at `refused_at`.
    pub(crate) fn sent(&mut self, message: String, refused_at: SystemTime) {
        self.queued.push_back((message, refused_at));
    }

    /// The channel wrote `message`; it is no longer queued if it was a refusal.
    pub(crate) fn written(&mut self, message: &str) {
        self.refused_at(message);
    }

    /// When `message` was refused, if it is the oldest refusal still queued,
    /// which the first unwritten refusal is; it is no longer queued after.
    pub(crate) fn refused_at(&mut self, message: &str) -> Option<SystemTime> {
        let (oldest, _) = self.queued.front()?;
        if oldest != message {
            return None;
        }
        self.queued.pop_front().map(|(_, refused_at)| refused_at)
    }

    /// Forgets every refusal queued: the channel they were queued on is gone.
    pub(crate) fn clear(&mut self) {
        self.queued.clear();
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
    Send { closed: Vec<Tally> },
    /// The event was folded. `first` is set on a window's first fold: it names
    /// the window a close must now be scheduled for.
    Folded { first: Option<WindowId> },
}

/// The open dedup windows, one per refusal, and the counts the audit channel
/// was not connected to take.
#[derive(Default)]
pub(crate) struct DenyWindows {
    windows: HashMap<String, Window>,
    /// One per refusal, oldest first; at most [`MAX_WINDOWS`].
    held: Vec<Tally>,
    /// The refusals held past [`MAX_WINDOWS`], whatever they were.
    overflow: Option<Tally>,
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
        let mut closed: Vec<Tally> = self
            .windows
            .remove_entry(&key)
            .and_then(|(key, window)| window.tally(key))
            .into_iter()
            .collect();
        if self.windows.len() >= MAX_WINDOWS {
            closed.extend(
                self.windows
                    .drain()
                    .filter_map(|(key, window)| window.tally(key)),
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

    /// Closes the window `id` names, returning its count. `None` when the
    /// window folded nothing or was already closed by a later admission.
    pub(crate) fn close(&mut self, id: &WindowId) -> Option<Tally> {
        if self.windows.get(&id.key)?.opened != id.opened {
            return None;
        }
        self.windows.remove(&id.key)?.tally(id.key.clone())
    }

    /// Holds a count the audit channel could not take. It folds into the one
    /// held for the same refusal; with [`MAX_WINDOWS`] other refusals held, it
    /// folds into the overflow summary, so no refusal goes uncounted and the
    /// held counts stay bounded.
    pub(crate) fn hold(&mut self, tally: Tally) {
        if tally.identity == overflow_identity() {
            self.hold_overflow(tally);
            return;
        }
        if let Some(held) = self.held.iter_mut().find(|held| held.key == tally.key) {
            held.fold(tally);
            return;
        }
        if self.held.len() < MAX_WINDOWS {
            self.held.push(tally);
            return;
        }
        self.hold_overflow(tally.into_overflow());
    }

    fn hold_overflow(&mut self, tally: Tally) {
        match &mut self.overflow {
            Some(overflow) => overflow.fold(tally),
            None => self.overflow = Some(tally),
        }
    }

    /// The held counts, oldest first and the overflow last, for a newly
    /// connected channel.
    pub(crate) fn take_held(&mut self) -> Vec<Tally> {
        let mut held = std::mem::take(&mut self.held);
        held.extend(self.overflow.take());
        held
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
        let [tally] = closed.as_slice() else {
            panic!("expected the closed window's summary, got {closed:?}");
        };
        let summary = tally.summary();
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

    /// The count of `count` repeats of `event` a closed window holds, the last
    /// refused at `last_at`.
    fn repeats(event: &Value, count: u64, last_at: SystemTime) -> Tally {
        let identity = refusal_identity(event);
        Tally {
            key: identity.to_string(),
            identity,
            count,
            last_at,
        }
    }

    fn counts(held: &[Tally]) -> Vec<(Value, u64)> {
        held.iter()
            .map(|tally| {
                let summary = tally.summary();
                (summary["host"].clone(), tally.count)
            })
            .collect()
    }

    #[test]
    fn held_summaries_are_taken_oldest_first_and_once() {
        let mut windows = DenyWindows::default();
        windows.hold(repeats(&refused("a.com"), 1, at(0)));
        windows.hold(repeats(&refused("b.com"), 2, at(1)));

        let held = windows.take_held();
        assert_eq!(counts(&held), [(json!("a.com"), 1), (json!("b.com"), 2)]);
        assert!(windows.take_held().is_empty());
    }

    #[test]
    fn a_held_summary_of_a_refusal_already_held_folds_into_it() {
        let mut windows = DenyWindows::default();
        windows.hold(repeats(&refused("a.com"), 2, at(5)));
        windows.hold(repeats(&refused("b.com"), 1, at(6)));
        windows.hold(repeats(&refused("a.com"), 3, at(4)));

        let held = windows.take_held();
        assert_eq!(counts(&held), [(json!("a.com"), 5), (json!("b.com"), 1)]);
        assert_eq!(
            held[0].summary()["metadata"]["last_suppressed_at"],
            "2025-10-09T08:53:25Z",
            "the folded summary names the last refusal of either"
        );
    }

    #[test]
    fn refusals_held_past_the_cap_are_counted_in_the_overflow_summary() {
        // Past the cap a refusal is not held on its own, so a channel that
        // never reconnects cannot grow the proxy without bound, but it is still
        // counted. A refusal already held keeps folding into its own summary.
        let mut windows = DenyWindows::default();
        for n in 0..MAX_WINDOWS {
            windows.hold(repeats(&refused(&format!("{n}.com")), 1, at(0)));
        }
        windows.hold(repeats(&refused("past-the-cap.com"), 4, at(7)));
        windows.hold(repeats(&refused("another.com"), 2, at(9)));
        windows.hold(repeats(&refused("0.com"), 3, at(8)));

        let held = windows.take_held();
        assert_eq!(held.len(), MAX_WINDOWS + 1);
        assert_eq!(
            held[0].count, 4,
            "a refusal held before the cap still folds"
        );
        let overflow = held.last().unwrap().summary();
        assert_eq!(
            overflow,
            json!({
                "type": "audit_event",
                "source": "sandbox-proxy",
                "action": "audit-overflow",
                "result": "failure",
                "metadata": {
                    "reason": "audit-overflow",
                    "summary": true,
                    "suppressed": 6,
                    "last_suppressed_at": "2025-10-09T08:53:29Z",
                },
            })
        );
        let total: u64 = held.iter().map(|tally| tally.count).sum();
        assert_eq!(total, MAX_WINDOWS as u64 + 4 + 2 + 3);
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
            windows.close(&id).map(|tally| tally.summary()),
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

        let summary = windows.close(&id).unwrap().summary();
        assert_eq!(summary["metadata"]["summary"], true);
        assert_eq!(summary["metadata"]["suppressed"], 1);
    }

    #[test]
    fn an_unwritten_summary_is_held_as_the_count_it_carried() {
        // Its count folds with a later summary of the same refusal, so the
        // identity it is held under is the one the window counted under.
        let event = refused("evil.com");
        let written = repeats(&event, 3, at(4));
        let unwritten = Tally::unwritten(&written.summary().to_string(), at(9));
        assert_eq!(unwritten.as_ref(), Some(&written));

        let mut windows = DenyWindows::default();
        windows.hold(unwritten.unwrap());
        windows.hold(repeats(&event, 2, at(6)));
        assert_eq!(counts(&windows.take_held()), [(json!("evil.com"), 5)]);
    }

    #[test]
    fn an_unwritten_summary_of_a_refusal_without_metadata_keeps_its_identity() {
        let event =
            json!({"type": "audit_event", "action": "CONNECT evil.com:443", "result": "failure"});
        let written = repeats(&event, 2, at(4));
        assert_eq!(
            Tally::unwritten(&written.summary().to_string(), at(9)),
            Some(written)
        );
    }

    #[test]
    fn an_unwritten_refusal_is_held_as_one_refused_when_it_was_sent() {
        let mut event = refused("evil.com");
        event["src_endpoint"] = json!({"ip": "10.0.0.2", "port": 40000});
        assert_eq!(
            Tally::unwritten(&event.to_string(), at(9)),
            Some(Tally::refused(&event, at(9)))
        );
    }

    #[test]
    fn a_queued_refusal_is_dated_until_it_is_written() {
        let mut queued = QueuedRefusals::default();
        let (a, b) = (refused("a.com").to_string(), refused("b.com").to_string());
        queued.sent(a.clone(), at(1));
        queued.sent(b.clone(), at(2));

        assert_eq!(
            queued.refused_at(&b),
            None,
            "b.com is not the oldest queued"
        );
        queued.written(r#"{"type": "exec_result"}"#);
        queued.written(&a);
        assert_eq!(queued.refused_at(&a), None, "a.com was written");
        assert_eq!(queued.refused_at(&b), Some(at(2)));
        assert_eq!(queued.refused_at(&b), None, "b.com was taken");
    }

    #[test]
    fn an_unwritten_message_that_is_no_refusal_is_not_held() {
        for message in [
            r#"{"type": "audit_event", "action": "CONNECT ok.com:443", "result": "success"}"#,
            r#"{"type": "exec_result", "result": "failure"}"#,
            "not json",
        ] {
            assert_eq!(Tally::unwritten(message, at(0)), None, "{message}");
        }
    }

    #[test]
    fn an_unwritten_overflow_summary_folds_into_the_overflow_not_a_slot() {
        let mut windows = DenyWindows::default();
        windows.hold(repeats(&refused("a.com"), 1, at(0)));
        let overflow = repeats(&refused("b.com"), 3, at(1)).into_overflow();
        windows.hold(Tally::unwritten(&overflow.summary().to_string(), at(2)).unwrap());

        let held = windows.take_held();
        assert_eq!(held.len(), 2);
        assert_eq!(held[1], overflow);
    }
}
