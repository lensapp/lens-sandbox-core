//! Just-in-time approval gate.
//!
//! The proxy holds a request that a static policy rule has tagged as
//! `Verdict::Ask`, emits a `request_pending` frame on the audit channel,
//! and awaits a `request_decision` frame (or a timeout). Concurrent
//! retries to the same host dedup onto one pending entry so the developer
//! sees a single dialog.
//!
//! The relay-side notifier that turns `request_pending` into a developer
//! dialog and replies with `request_decision` is **not implemented in
//! this branch** — it lands in a follow-up. Until then, any policy that
//! emits `Verdict::Ask` will hang until `DECISION_TIMEOUT` and then deny.
//! Don't ship `verdict: "ask"` in user-visible policies until the
//! relay-side handler is in place.
//!
//! The gate is the v2 replacement for the audit-and-notify flow used today
//! for `policy-deny`: that flow surfaced the dialog after the request had
//! already failed, which made "Allow once" / "Deny once" semantically
//! meaningless on the held request. The gate surfaces the dialog *before*
//! the proxy commits, so all four decisions act on the held request.

use std::collections::HashMap;
use std::time::Duration;

use rand::RngCore;
use tokio::sync::watch;

use crate::protocol::{Decision, RequestPending};
use crate::proxy::ProxyState;

/// How long the proxy waits for a `request_decision` before defaulting to
/// `Decision::Timeout` (which the request handler treats as deny). We
/// can't see the caller's per-request HTTP timeout — agent SDKs choose
/// their own, often 30-120s — so any value here is a guess. 60s is the
/// best we can do for "long enough for a human to react"; callers whose
/// per-request timeout is shorter will see the agent abandon the request
/// before the developer's click resolves. Recommend bumping agent-side
/// request timeouts above this value when relying on the gate.
pub const DECISION_TIMEOUT: Duration = Duration::from_secs(60);

/// Hard cap on the number of in-flight pending entries. An agent that fires
/// thousands of distinct hostnames while no decisions arrive would otherwise
/// pin one entry per host for the full `DECISION_TIMEOUT`, growing the table
/// for tens of seconds. With the cap, beyond this many concurrent dialogs we
/// fail closed (Decision::Timeout) immediately rather than queuing — the
/// developer can only meaningfully answer one dialog at a time anyway, and
/// a flood that exceeds 1024 distinct hosts is unambiguously a misbehaving
/// or adversarial caller.
pub const MAX_PENDING_ENTRIES: usize = 1024;

/// Pending-decision entry held in `ProxyState::pending`, keyed by
/// `action` (full request string: method + URL for HTTP, `CONNECT
/// host:port` for tunnels). Concurrent gate calls for the *same exact
/// request* share one dialog; different requests on the same host each
/// get their own, so an `AllowOnce` click releases only what the user
/// actually saw described in the prompt.
pub(crate) struct PendingEntry {
    pub(crate) id: String,
    pub(crate) tx: watch::Sender<Option<Decision>>,
}

/// In-memory dedup + correlation state for the gate. Held inside
/// `ProxyState` so the WebSocket reader can resolve a `request_decision`
/// by id.
pub struct PendingTable {
    pub(crate) by_action: HashMap<String, PendingEntry>,
    pub(crate) action_by_id: HashMap<String, String>,
}

impl PendingTable {
    pub fn new() -> Self {
        Self {
            by_action: HashMap::new(),
            action_by_id: HashMap::new(),
        }
    }
}

impl Default for PendingTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Suspend the request until the developer answers the dialog or the
/// timeout fires. Emits the `request_pending` frame on first sight of an
/// `action`; subsequent concurrent retries of the *same* request join
/// the existing entry. Different requests to the same host (e.g.
/// `GET /safe` and `DELETE /danger`) each get their own dialog so an
/// `AllowOnce` click releases only what was shown in the prompt.
///
/// Returns the resolved `Decision` so callers can record the appropriate
/// audit event with `Decision::audit_reason()`.
pub async fn gate_or_deny(state: &ProxyState, host: &str, action: &str, reason: &str) -> Decision {
    let (rx, id, emitted) = match subscribe_or_open(state, host, action, reason) {
        Some(v) => v,
        None => return Decision::Timeout,
    };
    if !emitted {
        tracing::debug!(action, "gate: joined existing pending entry");
    }
    let timeout = *state.decision_timeout.read().unwrap();
    let decision = await_decision(rx, timeout).await;
    cleanup_after_decision(state, action, &id);
    decision
}

/// Subscribe to an action's pending entry, creating one if absent.
/// Returns `Some((rx, id, emitted))` where `id` is the entry's
/// correlation id and `emitted` is true when this call sent the
/// `request_pending` frame, false when joining an in-flight entry.
/// Returns `None` when a fresh entry can't be opened: the audit channel
/// is unwired, the relay receiver has been dropped (send fails), or the
/// pending-table cap is hit. In all three cases we fail closed
/// immediately rather than parking for `DECISION_TIMEOUT` with no way
/// to deliver the prompt.
fn subscribe_or_open(
    state: &ProxyState,
    host: &str,
    action: &str,
    reason: &str,
) -> Option<(watch::Receiver<Option<Decision>>, String, bool)> {
    let mut table = state.pending.lock().unwrap();
    if let Some(entry) = table.by_action.get(action) {
        return Some((entry.tx.subscribe(), entry.id.clone(), false));
    }
    if table.by_action.len() >= MAX_PENDING_ENTRIES {
        tracing::warn!(
            action,
            cap = MAX_PENDING_ENTRIES,
            "gate: pending table at cap; failing closed",
        );
        return None;
    }
    let id = mint_id();
    // Try the send while still holding the table lock so a
    // `request_decision` that races us blocks on `resolve_pending`'s
    // attempt to take the same lock until our entry is committed (or
    // not). Lets us cleanly abandon the dialog when the channel is
    // dead without ever leaving an orphan entry in the table.
    if !try_emit_request_pending(state, &id, host, action, reason) {
        return None;
    }
    let (tx, rx) = watch::channel::<Option<Decision>>(None);
    table.action_by_id.insert(id.clone(), action.to_string());
    table
        .by_action
        .insert(action.to_string(), PendingEntry { id: id.clone(), tx });
    drop(table);
    Some((rx, id, true))
}

/// Serialize and send a `request_pending` frame on the audit channel.
/// Returns true on successful enqueue. Treats both "no sender wired" and
/// "send failed (receiver dropped)" as failure so the caller fails closed
/// instead of parking a request the relay can never see.
fn try_emit_request_pending(
    state: &ProxyState,
    id: &str,
    host: &str,
    action: &str,
    reason: &str,
) -> bool {
    let frame = RequestPending::new(
        id.to_string(),
        host.to_string(),
        action.to_string(),
        reason.to_string(),
    );
    let serialized = match serde_json::to_string(&frame) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("gate: failed to serialize request_pending: {e}");
            return false;
        }
    };
    let tx = state.audit_tx.lock().unwrap().clone();
    match tx {
        Some(tx) => {
            if tx.send(serialized).is_err() {
                tracing::warn!(action, "gate: audit channel send failed; failing closed");
                false
            } else {
                true
            }
        }
        None => {
            tracing::warn!(
                action,
                "gate: audit_tx not wired; failing closed immediately"
            );
            false
        }
    }
}

async fn await_decision(mut rx: watch::Receiver<Option<Decision>>, timeout: Duration) -> Decision {
    // If the value was already set before we subscribed (late joiner),
    // borrow() returns Some(_) and we skip the wait entirely.
    if let Some(d) = *rx.borrow() {
        return d;
    }
    match tokio::time::timeout(timeout, rx.changed()).await {
        Ok(Ok(())) => rx.borrow().unwrap_or(Decision::Timeout),
        Ok(Err(_)) => {
            // Sender was dropped. The decision may have been sent first —
            // a watch channel retains the last value after sender drop, so
            // borrow() here recovers it. Without this fallback, a concurrent
            // retry that wakes after the first waiter's cleanup drops the
            // sender would lose the real decision and report Timeout.
            rx.borrow().unwrap_or(Decision::Timeout)
        }
        Err(_) => Decision::Timeout,
    }
}

/// Remove the entry only if it is still the one this caller subscribed
/// to. A late-waking concurrent caller for the same action may run after
/// the first waiter's cleanup already removed the original entry AND a
/// fresh `gate_or_deny` opened a new dialog (different id) for the same
/// action — blindly removing by action would drop that new entry and
/// silently strand any in-flight subscribers. Match on `id` to keep the
/// cleanup scoped to our own entry.
fn cleanup_after_decision(state: &ProxyState, action: &str, id: &str) {
    let mut table = state.pending.lock().unwrap();
    let still_ours = matches!(table.by_action.get(action), Some(entry) if entry.id == id);
    if still_ours && let Some(entry) = table.by_action.remove(action) {
        table.action_by_id.remove(&entry.id);
        // Dropping `entry` drops the Sender. Any subscribers that haven't
        // yet read the value can still .borrow() the last sent decision —
        // watch channels retain the last value for late readers.
    }
}

/// Resolve a pending decision by id. Called from the WebSocket reader on
/// inbound `request_decision` frames. Returns true when the id matched an
/// in-flight entry (useful for tests; production callers can ignore).
pub fn resolve_pending(state: &ProxyState, id: &str, decision: Decision) -> bool {
    let table = state.pending.lock().unwrap();
    let action = match table.action_by_id.get(id) {
        Some(a) => a.clone(),
        None => return false,
    };
    let entry = match table.by_action.get(&action) {
        Some(e) => e,
        None => return false,
    };
    // send() fails if all receivers have been dropped; the decision is
    // still recorded in the channel for late .borrow() readers.
    let _ = entry.tx.send(Some(decision));
    true
}

fn mint_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    let mut s = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_state() -> (
        std::sync::Arc<ProxyState>,
        tokio::sync::mpsc::UnboundedReceiver<String>,
    ) {
        crate::proxy::tests::test_state()
    }

    #[tokio::test]
    async fn gate_emits_request_pending_and_resolves_on_allow() {
        let (state, mut rx) = test_state();
        let handle = tokio::spawn({
            let state = state.clone();
            async move {
                gate_or_deny(
                    &state,
                    "evil.example.com",
                    "CONNECT evil.example.com:443",
                    "policy-ambiguous",
                )
                .await
            }
        });

        let frame = rx.recv().await.expect("request_pending emitted");
        let parsed: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(parsed["type"], "request_pending");
        assert_eq!(parsed["host"], "evil.example.com");
        let id = parsed["id"].as_str().unwrap().to_string();

        assert!(resolve_pending(&state, &id, Decision::AllowAlways));
        let decision = handle.await.unwrap();
        assert_eq!(decision, Decision::AllowAlways);
    }

    #[tokio::test]
    async fn concurrent_calls_for_same_host_dedup() {
        let (state, mut rx) = test_state();
        let h1 = tokio::spawn({
            let state = state.clone();
            async move { gate_or_deny(&state, "h", "CONNECT h:443", "policy-ambiguous").await }
        });
        // Ensure h1 has registered the pending entry before h2 races.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let h2 = tokio::spawn({
            let state = state.clone();
            async move { gate_or_deny(&state, "h", "CONNECT h:443", "policy-ambiguous").await }
        });

        let frame = rx.recv().await.unwrap();
        assert!(rx.try_recv().is_err(), "only one request_pending emitted");
        let id = serde_json::from_str::<serde_json::Value>(&frame).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(resolve_pending(&state, &id, Decision::DenyAlways));

        assert_eq!(h1.await.unwrap(), Decision::DenyAlways);
        assert_eq!(h2.await.unwrap(), Decision::DenyAlways);
    }

    #[tokio::test]
    async fn timeout_yields_timeout_decision() {
        let (state, _rx) = test_state();
        state.decision_timeout_override(Duration::from_millis(20));
        let d = gate_or_deny(&state, "slow", "CONNECT slow:443", "policy-ambiguous").await;
        assert_eq!(d, Decision::Timeout);
    }

    #[tokio::test]
    async fn fails_closed_immediately_when_audit_tx_not_wired() {
        // No relay → no possible decision. The gate must not park the
        // request for DECISION_TIMEOUT; it returns Timeout (deny) at once.
        let (state, _rx) = test_state();
        *state.audit_tx.lock().unwrap() = None;
        state.decision_timeout_override(Duration::from_secs(60));

        let start = std::time::Instant::now();
        let decision = gate_or_deny(&state, "h", "CONNECT h:443", "policy-ambiguous").await;
        let elapsed = start.elapsed();

        assert_eq!(decision, Decision::Timeout);
        assert!(
            elapsed < Duration::from_secs(1),
            "expected fast deny; took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn fails_closed_immediately_when_pending_table_full() {
        // Once the cap is reached, further unique actions deny at once
        // instead of growing the table for DECISION_TIMEOUT. We seed the
        // table with dummy entries to avoid spawning thousands of real
        // callers.
        let (state, _rx) = test_state();
        state.decision_timeout_override(Duration::from_secs(60));
        {
            let mut table = state.pending.lock().unwrap();
            for i in 0..MAX_PENDING_ENTRIES {
                let action = format!("CONNECT filler-{i}:443");
                let id = format!("id-{i}");
                let (tx, _rx) = watch::channel::<Option<Decision>>(None);
                table.action_by_id.insert(id.clone(), action.clone());
                table.by_action.insert(action, PendingEntry { id, tx });
            }
        }

        let start = std::time::Instant::now();
        let decision = gate_or_deny(
            &state,
            "overflow-host",
            "CONNECT overflow:443",
            "policy-ambiguous",
        )
        .await;
        let elapsed = start.elapsed();

        assert_eq!(decision, Decision::Timeout);
        assert!(
            elapsed < Duration::from_secs(1),
            "expected fast deny; took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn fails_closed_immediately_when_audit_receiver_dropped() {
        // audit_tx is wired (Some), but the receiver has been dropped —
        // simulating a WebSocket disconnect where the writer task has
        // exited without clearing the sender clone in state. The gate
        // must detect the dead channel and fail closed rather than park
        // for DECISION_TIMEOUT with nothing on the wire.
        let (state, rx) = test_state();
        state.decision_timeout_override(Duration::from_secs(60));
        drop(rx);

        let start = std::time::Instant::now();
        let decision = gate_or_deny(&state, "h", "CONNECT h:443", "policy-ambiguous").await;
        let elapsed = start.elapsed();

        assert_eq!(decision, Decision::Timeout);
        assert!(
            elapsed < Duration::from_secs(1),
            "expected fast deny; took {elapsed:?}"
        );
        // No orphan entry left behind: the gate must not have committed
        // table state for a frame it couldn't deliver.
        let table = state.pending.lock().unwrap();
        assert!(table.by_action.is_empty());
        assert!(table.action_by_id.is_empty());
    }

    #[tokio::test]
    async fn different_actions_on_same_host_get_separate_dialogs() {
        // Per-host dedup would let a user approving `GET /safe` also
        // silently release a concurrent `DELETE /danger` on the same
        // host. Scope the dedup to the action so each distinct request
        // surfaces its own prompt and AllowOnce releases only what the
        // user saw.
        let (state, mut rx) = test_state();
        let safe = "GET http://api.evil.com/safe";
        let danger = "DELETE http://api.evil.com/danger";
        let h1 = tokio::spawn({
            let state = state.clone();
            async move { gate_or_deny(&state, "api.evil.com", safe, "policy-ambiguous").await }
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        let h2 = tokio::spawn({
            let state = state.clone();
            async move { gate_or_deny(&state, "api.evil.com", danger, "policy-ambiguous").await }
        });

        let f1: serde_json::Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
        let f2: serde_json::Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
        assert_ne!(
            f1["id"], f2["id"],
            "each request must get a distinct dialog id"
        );
        let actions: std::collections::HashSet<_> = [
            f1["action"].as_str().unwrap(),
            f2["action"].as_str().unwrap(),
        ]
        .into_iter()
        .collect();
        assert!(
            actions.contains(safe) && actions.contains(danger),
            "both action strings must appear; got {actions:?}",
        );

        for frame in [&f1, &f2] {
            let action = frame["action"].as_str().unwrap();
            let id = frame["id"].as_str().unwrap();
            let decision = if action == safe {
                Decision::AllowOnce
            } else {
                Decision::DenyOnce
            };
            assert!(resolve_pending(&state, id, decision));
        }
        assert_eq!(h1.await.unwrap(), Decision::AllowOnce);
        assert_eq!(h2.await.unwrap(), Decision::DenyOnce);
    }

    #[tokio::test]
    async fn resolve_pending_unknown_id_is_noop() {
        let (state, _rx) = test_state();
        assert!(!resolve_pending(
            &state,
            "no-such-id",
            Decision::AllowAlways
        ));
    }

    #[tokio::test]
    async fn late_waiter_cleanup_does_not_drop_fresh_entry() {
        // Two waiters share an entry; the first's cleanup removes it after
        // resolution. Before the second's cleanup runs, a third caller opens
        // a fresh dialog for the same host (different id). The second
        // waiter's cleanup must NOT remove the new entry — only the entry
        // creator (or any subscriber to the SAME id) should clean up its
        // own entry.
        let (state, mut rx) = test_state();
        let h1 = tokio::spawn({
            let state = state.clone();
            async move { gate_or_deny(&state, "h", "x", "policy-ambiguous").await }
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        let h2 = tokio::spawn({
            let state = state.clone();
            async move { gate_or_deny(&state, "h", "x", "policy-ambiguous").await }
        });

        let frame1 = rx.recv().await.unwrap();
        let id1 = serde_json::from_str::<serde_json::Value>(&frame1).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        resolve_pending(&state, &id1, Decision::AllowOnce);
        // Wait for h1 to finish — its cleanup runs, removing the first entry.
        assert_eq!(h1.await.unwrap(), Decision::AllowOnce);

        // Concurrent retry on the same host opens a brand-new dialog with
        // a new id. h2 has NOT been polled yet, so its cleanup will run
        // after this insertion.
        let h3 = tokio::spawn({
            let state = state.clone();
            async move { gate_or_deny(&state, "h", "x", "policy-ambiguous").await }
        });
        let frame2 = rx.recv().await.unwrap();
        let id2 = serde_json::from_str::<serde_json::Value>(&frame2).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(id1, id2, "third caller opened a fresh entry");

        // h2 now wakes up and runs cleanup. Bug version: blindly removes
        // by host, evicting the entry h3 is waiting on. Fixed version:
        // sees its own id is gone and leaves the new entry alone.
        assert_eq!(h2.await.unwrap(), Decision::AllowOnce);

        // h3 must still be resolvable via its own id.
        assert!(
            resolve_pending(&state, &id2, Decision::DenyOnce),
            "h3's entry was wrongly evicted by h2's cleanup",
        );
        assert_eq!(h3.await.unwrap(), Decision::DenyOnce);
    }

    #[tokio::test]
    async fn second_call_after_cleanup_opens_new_dialog() {
        let (state, mut rx) = test_state();
        // first round
        let h = tokio::spawn({
            let state = state.clone();
            async move { gate_or_deny(&state, "h", "x", "policy-ambiguous").await }
        });
        let frame1 = rx.recv().await.unwrap();
        let id1 = serde_json::from_str::<serde_json::Value>(&frame1).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        resolve_pending(&state, &id1, Decision::DenyOnce);
        assert_eq!(h.await.unwrap(), Decision::DenyOnce);

        // second round — must emit fresh request_pending with a new id
        let h2 = tokio::spawn({
            let state = state.clone();
            async move { gate_or_deny(&state, "h", "x", "policy-ambiguous").await }
        });
        let frame2 = rx.recv().await.unwrap();
        let id2 = serde_json::from_str::<serde_json::Value>(&frame2).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(id1, id2, "second round must mint a new id");
        resolve_pending(&state, &id2, Decision::AllowOnce);
        assert_eq!(h2.await.unwrap(), Decision::AllowOnce);
    }
}
