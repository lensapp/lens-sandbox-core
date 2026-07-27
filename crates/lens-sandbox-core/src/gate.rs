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

use crate::protocol::{
    CredentialDecisionKind, CredentialPending, Decision, RequestPending, Treatment,
};
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

/// One in-flight gate dialog. The key (action / credential_id) is
/// stored on the table side via `by_key`; `id` is the proxy-minted
/// correlation token the relay echoes back in the decision frame.
pub(crate) struct PendingEntry<V: Copy> {
    pub(crate) id: String,
    pub(crate) tx: watch::Sender<Option<V>>,
}

/// In-memory dedup + correlation state for a gate. Held inside
/// `ProxyState` so the WebSocket reader can resolve an inbound decision
/// frame by id. Concurrent callers for the same key share one entry; a
/// single decision releases every joiner.
pub struct PendingTable<V: Copy> {
    pub(crate) by_key: HashMap<String, PendingEntry<V>>,
    pub(crate) key_by_id: HashMap<String, String>,
}

impl<V: Copy> PendingTable<V> {
    pub fn new() -> Self {
        Self {
            by_key: HashMap::new(),
            key_by_id: HashMap::new(),
        }
    }
}

impl<V: Copy> Default for PendingTable<V> {
    fn default() -> Self {
        Self::new()
    }
}

/// Generic subscribe-or-open against a `PendingTable<V>`. The caller
/// supplies `emit`, which serializes and sends the wakeup frame on the
/// audit channel while the table mutex is held — a stale send (channel
/// down, sender absent) leaves no orphan entry in the table.
///
/// Returns `Some((rx, id, emitted))` where `emitted` is true when this
/// call created a fresh entry, false when it joined an in-flight one.
/// `None` means fail-closed: the cap was hit or `emit` reported failure.
fn subscribe_or_open<V: Copy>(
    table: &std::sync::Mutex<PendingTable<V>>,
    key: &str,
    log_tag: &'static str,
    emit: impl FnOnce(&str) -> bool,
) -> Option<(watch::Receiver<Option<V>>, String, bool)> {
    let mut table = table.lock().unwrap();
    if let Some(entry) = table.by_key.get(key) {
        return Some((entry.tx.subscribe(), entry.id.clone(), false));
    }
    if table.by_key.len() >= MAX_PENDING_ENTRIES {
        tracing::warn!(
            key,
            cap = MAX_PENDING_ENTRIES,
            "{log_tag}: pending table at cap; failing closed",
        );
        return None;
    }
    let id = mint_id();
    if !emit(&id) {
        return None;
    }
    let (tx, rx) = watch::channel::<Option<V>>(None);
    table.key_by_id.insert(id.clone(), key.to_string());
    table
        .by_key
        .insert(key.to_string(), PendingEntry { id: id.clone(), tx });
    drop(table);
    Some((rx, id, true))
}

/// Await a decision on a subscribed receiver, falling back to
/// `timeout_val` on either an elapsed timer or a sender-dropped channel
/// with no buffered value.
async fn await_decision<V: Copy>(
    mut rx: watch::Receiver<Option<V>>,
    timeout: Duration,
    timeout_val: V,
) -> V {
    if let Some(d) = *rx.borrow() {
        return d;
    }
    match tokio::time::timeout(timeout, rx.changed()).await {
        Ok(Ok(())) => rx.borrow().unwrap_or(timeout_val),
        Ok(Err(_)) => rx.borrow().unwrap_or(timeout_val),
        Err(_) => timeout_val,
    }
}

/// Remove the entry only if it is still the one this caller subscribed
/// to. A late-waking joiner running after the original waiter's cleanup
/// AND after a fresh caller opened a new entry (different id) for the
/// same key must NOT evict that new entry — match on `id`.
fn cleanup_after_decision<V: Copy>(table: &std::sync::Mutex<PendingTable<V>>, key: &str, id: &str) {
    let mut table = table.lock().unwrap();
    let still_ours = matches!(table.by_key.get(key), Some(entry) if entry.id == id);
    if still_ours && let Some(entry) = table.by_key.remove(key) {
        table.key_by_id.remove(&entry.id);
    }
}

/// Resolve a pending decision by id. Returns true when the id matched an
/// in-flight entry.
fn resolve<V: Copy>(table: &std::sync::Mutex<PendingTable<V>>, id: &str, decision: V) -> bool {
    let table = table.lock().unwrap();
    let key = match table.key_by_id.get(id) {
        Some(k) => k.clone(),
        None => return false,
    };
    let entry = match table.by_key.get(&key) {
        Some(e) => e,
        None => return false,
    };
    let _ = entry.tx.send(Some(decision));
    true
}

/// Suspend the request until the developer answers the dialog or the
/// timeout fires. Emits the `request_pending` frame on first sight of an
/// `action`; subsequent concurrent retries of the *same* request join
/// the existing entry and inherit its `treatment`, which is well-defined
/// because treatment is a function of the destination under one policy
/// generation. Different requests to the same host (e.g.
/// `GET /safe` and `DELETE /danger`) each get their own dialog so an
/// `AllowOnce` click releases only what was shown in the prompt.
///
/// Returns the resolved `Decision` so callers can record the appropriate
/// audit event with `Decision::audit_reason()`.
pub async fn gate_or_deny(
    state: &ProxyState,
    host: &str,
    action: &str,
    reason: &str,
    treatment: Treatment,
) -> Decision {
    let (rx, id, emitted) = match subscribe_or_open(&state.pending, action, "gate", |id| {
        emit_pending_frame(
            state,
            "gate",
            action,
            &RequestPending::new(
                id.to_string(),
                host.to_string(),
                action.to_string(),
                reason.to_string(),
                treatment,
            ),
        )
    }) {
        Some(v) => v,
        None => return Decision::Timeout,
    };
    if !emitted {
        tracing::debug!(action, "gate: joined existing pending entry");
    }
    let timeout = *state.decision_timeout.read().unwrap();
    let decision = await_decision(rx, timeout, Decision::Timeout).await;
    cleanup_after_decision(&state.pending, action, &id);
    if decision.is_allow() {
        // Let the DNS stub resolve this host even with no standing route:
        // "allow once" persists none, and "allow always"'s route arrives in
        // a later `policy` frame this request can't await. Lowercased to
        // match the stub's normalized QNAME (see `dns::classify_query`).
        state
            .gate_resolved_hosts
            .write()
            .unwrap()
            .insert(host.to_ascii_lowercase());
    }
    decision
}

/// Resolve a pending decision by id. Called from the WebSocket reader on
/// inbound `request_decision` frames. Returns true when the id matched an
/// in-flight entry (useful for tests; production callers can ignore).
pub fn resolve_pending(state: &ProxyState, id: &str, decision: Decision) -> bool {
    resolve(&state.pending, id, decision)
}

/// Serialize and send a `*_pending` frame on the audit channel. Returns
/// true on successful enqueue. Treats both "no sender wired" and "send
/// failed (receiver dropped)" as failure so the caller fails closed
/// instead of parking a request the relay can never see.
fn emit_pending_frame<F: serde::Serialize>(
    state: &ProxyState,
    log_tag: &'static str,
    key: &str,
    frame: &F,
) -> bool {
    let serialized = match serde_json::to_string(frame) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("{log_tag}: failed to serialize pending frame: {e}");
            return false;
        }
    };
    let tx = state.audit_tx.lock().unwrap().clone();
    match tx {
        Some(tx) => {
            if tx.send(serialized).is_err() {
                tracing::warn!(key, "{log_tag}: audit channel send failed; failing closed");
                false
            } else {
                true
            }
        }
        None => {
            tracing::warn!(
                key,
                "{log_tag}: audit_tx not wired; failing closed immediately"
            );
            false
        }
    }
}

// ============================================================================
// Credential gate — same machinery as the request gate, different frame
// + decision shape. Unlike `Decision` (4 once/always variants + Timeout),
// credential decisions are sticky on the host side and arrive as just
// Allow / Deny / Timeout. The host arms the matching `Credential.injections`
// via a follow-up `policy` frame after `Allow`; the gate's only job is to
// release / fail the held request.
// ============================================================================

/// Suspend a request whose bytes carry a placeholder for `credential_id`
/// until the developer answers or the timeout fires. Concurrent placeholder
/// uses for the same credential_id dedup onto one dialog. Returns the
/// resolved [`CredentialDecisionKind`]; on `Allow` the caller is expected
/// to wait for the follow-up `policy` frame that arms `Credential.injections`
/// for this credential before forwarding.
pub async fn credential_gate_or_deny(
    state: &ProxyState,
    credential_id: &str,
    action: &str,
) -> CredentialDecisionKind {
    let (rx, id, emitted) = match subscribe_or_open(
        &state.credential_pending,
        credential_id,
        "credential_gate",
        |id| {
            emit_pending_frame(
                state,
                "credential_gate",
                credential_id,
                &CredentialPending::new(
                    id.to_string(),
                    credential_id.to_string(),
                    action.to_string(),
                    "placeholder-unauthorized".to_string(),
                ),
            )
        },
    ) {
        Some(v) => v,
        None => return CredentialDecisionKind::Timeout,
    };
    if !emitted {
        tracing::debug!(
            credential_id,
            "credential_gate: joined existing pending entry"
        );
    }
    let timeout = *state.decision_timeout.read().unwrap();
    let decision = await_decision(rx, timeout, CredentialDecisionKind::Timeout).await;
    cleanup_after_decision(&state.credential_pending, credential_id, &id);
    decision
}

/// Resolve a pending credential decision by id. Called from the WebSocket
/// reader on inbound `credential_decision` frames. Returns true when the id
/// matched an in-flight entry.
pub fn resolve_credential_pending(
    state: &ProxyState,
    id: &str,
    decision: CredentialDecisionKind,
) -> bool {
    resolve(&state.credential_pending, id, decision)
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

    /// Gate mechanics under test here are treatment-independent.
    async fn gate(state: &ProxyState, host: &str, action: &str) -> Decision {
        gate_or_deny(
            state,
            host,
            action,
            "policy-ambiguous",
            Treatment::Inspected,
        )
        .await
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
                    Treatment::Inspected,
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
    async fn allow_records_host_for_dns_resolution_lowercased() {
        // An allow decision must record the host so the DNS stub can resolve
        // it even with no standing route — the fix for "allow once" never
        // resolving. Recorded lowercased to match the stub's normalized
        // QNAME (see `dns::classify_query`).
        let (state, mut rx) = test_state();
        let handle = tokio::spawn({
            let state = state.clone();
            async move {
                gate_or_deny(
                    &state,
                    "Example.COM",
                    "CONNECT Example.COM:443",
                    "policy-ambiguous",
                    Treatment::Inspected,
                )
                .await
            }
        });
        let frame = rx.recv().await.unwrap();
        let id = serde_json::from_str::<serde_json::Value>(&frame).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(resolve_pending(&state, &id, Decision::AllowOnce));
        assert_eq!(handle.await.unwrap(), Decision::AllowOnce);
        assert!(
            state
                .gate_resolved_hosts
                .read()
                .unwrap()
                .contains("example.com"),
            "an allow decision must record the host (lowercased) for the DNS stub"
        );
    }

    #[tokio::test]
    async fn deny_does_not_record_host_for_dns_resolution() {
        // A deny must not open DNS resolution for the host.
        let (state, mut rx) = test_state();
        let handle = tokio::spawn({
            let state = state.clone();
            async move {
                gate_or_deny(
                    &state,
                    "evil.com",
                    "CONNECT evil.com:443",
                    "policy-ambiguous",
                    Treatment::Inspected,
                )
                .await
            }
        });
        let frame = rx.recv().await.unwrap();
        let id = serde_json::from_str::<serde_json::Value>(&frame).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(resolve_pending(&state, &id, Decision::DenyOnce));
        assert_eq!(handle.await.unwrap(), Decision::DenyOnce);
        assert!(
            state.gate_resolved_hosts.read().unwrap().is_empty(),
            "a deny must not record the host"
        );
    }

    #[tokio::test]
    async fn timeout_does_not_record_host_for_dns_resolution() {
        let (state, _rx) = test_state();
        state.decision_timeout_override(Duration::from_millis(20));
        let d = gate_or_deny(
            &state,
            "slow.com",
            "CONNECT slow.com:443",
            "policy-ambiguous",
            Treatment::Inspected,
        )
        .await;
        assert_eq!(d, Decision::Timeout);
        assert!(state.gate_resolved_hosts.read().unwrap().is_empty());
    }

    #[tokio::test]
    async fn concurrent_calls_for_same_host_dedup() {
        let (state, mut rx) = test_state();
        let h1 = tokio::spawn({
            let state = state.clone();
            async move { gate(&state, "h", "CONNECT h:443").await }
        });
        // Ensure h1 has registered the pending entry before h2 races.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let h2 = tokio::spawn({
            let state = state.clone();
            async move { gate(&state, "h", "CONNECT h:443").await }
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
        let d = gate(&state, "slow", "CONNECT slow:443").await;
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
        let decision = gate(&state, "h", "CONNECT h:443").await;
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
                table.key_by_id.insert(id.clone(), action.clone());
                table.by_key.insert(action, PendingEntry { id, tx });
            }
        }

        let start = std::time::Instant::now();
        let decision = gate_or_deny(
            &state,
            "overflow-host",
            "CONNECT overflow:443",
            "policy-ambiguous",
            Treatment::Inspected,
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
        let decision = gate(&state, "h", "CONNECT h:443").await;
        let elapsed = start.elapsed();

        assert_eq!(decision, Decision::Timeout);
        assert!(
            elapsed < Duration::from_secs(1),
            "expected fast deny; took {elapsed:?}"
        );
        // No orphan entry left behind: the gate must not have committed
        // table state for a frame it couldn't deliver.
        let table = state.pending.lock().unwrap();
        assert!(table.by_key.is_empty());
        assert!(table.key_by_id.is_empty());
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
            async move { gate(&state, "api.evil.com", safe).await }
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        let h2 = tokio::spawn({
            let state = state.clone();
            async move { gate(&state, "api.evil.com", danger).await }
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
            async move { gate(&state, "h", "x").await }
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        let h2 = tokio::spawn({
            let state = state.clone();
            async move { gate(&state, "h", "x").await }
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
            async move { gate(&state, "h", "x").await }
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

    // ---------- credential gate ----------

    #[tokio::test]
    async fn credential_gate_emits_pending_and_resolves_on_allow() {
        let (state, mut rx) = test_state();
        let handle = tokio::spawn({
            let state = state.clone();
            async move { credential_gate_or_deny(&state, "github", "use of github placeholder").await }
        });

        let frame = rx.recv().await.expect("credential_pending emitted");
        let parsed: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(parsed["type"], "credential_pending");
        assert_eq!(parsed["credentialId"], "github");
        let id = parsed["id"].as_str().unwrap().to_string();

        assert!(resolve_credential_pending(
            &state,
            &id,
            CredentialDecisionKind::Allow
        ));
        let decision = handle.await.unwrap();
        assert_eq!(decision, CredentialDecisionKind::Allow);
    }

    #[tokio::test]
    async fn credential_gate_concurrent_calls_for_same_credential_dedup() {
        let (state, mut rx) = test_state();
        let h1 = tokio::spawn({
            let state = state.clone();
            async move { credential_gate_or_deny(&state, "github", "x").await }
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        let h2 = tokio::spawn({
            let state = state.clone();
            async move { credential_gate_or_deny(&state, "github", "y").await }
        });

        let frame = rx.recv().await.unwrap();
        assert!(
            rx.try_recv().is_err(),
            "only one credential_pending emitted"
        );
        let id = serde_json::from_str::<serde_json::Value>(&frame).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(resolve_credential_pending(
            &state,
            &id,
            CredentialDecisionKind::Deny
        ));

        assert_eq!(h1.await.unwrap(), CredentialDecisionKind::Deny);
        assert_eq!(h2.await.unwrap(), CredentialDecisionKind::Deny);
    }

    #[tokio::test]
    async fn credential_gate_timeout_yields_timeout_decision() {
        let (state, _rx) = test_state();
        state.decision_timeout_override(Duration::from_millis(20));
        let d = credential_gate_or_deny(&state, "slow", "x").await;
        assert_eq!(d, CredentialDecisionKind::Timeout);
    }

    #[tokio::test]
    async fn credential_gate_fails_closed_when_audit_tx_not_wired() {
        let (state, _rx) = test_state();
        *state.audit_tx.lock().unwrap() = None;
        state.decision_timeout_override(Duration::from_secs(60));

        let start = std::time::Instant::now();
        let decision = credential_gate_or_deny(&state, "github", "x").await;
        let elapsed = start.elapsed();

        assert_eq!(decision, CredentialDecisionKind::Timeout);
        assert!(
            elapsed < Duration::from_secs(1),
            "expected fast deny; took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn credential_gate_fails_closed_when_receiver_dropped() {
        let (state, rx) = test_state();
        state.decision_timeout_override(Duration::from_secs(60));
        drop(rx);

        let start = std::time::Instant::now();
        let decision = credential_gate_or_deny(&state, "github", "x").await;
        let elapsed = start.elapsed();

        assert_eq!(decision, CredentialDecisionKind::Timeout);
        assert!(
            elapsed < Duration::from_secs(1),
            "expected fast deny; took {elapsed:?}"
        );
        let table = state.credential_pending.lock().unwrap();
        assert!(
            table.by_key.is_empty(),
            "no orphan entry left after fail-closed"
        );
        assert!(table.key_by_id.is_empty());
    }

    #[tokio::test]
    async fn credential_gate_fails_closed_when_pending_table_full() {
        let (state, _rx) = test_state();
        state.decision_timeout_override(Duration::from_secs(60));
        {
            let mut table = state.credential_pending.lock().unwrap();
            for i in 0..MAX_PENDING_ENTRIES {
                let cred = format!("filler-{i}");
                let id = format!("id-{i}");
                let (tx, _rx) = watch::channel::<Option<CredentialDecisionKind>>(None);
                table.key_by_id.insert(id.clone(), cred.clone());
                table.by_key.insert(cred, PendingEntry { id, tx });
            }
        }
        let start = std::time::Instant::now();
        let decision = credential_gate_or_deny(&state, "overflow", "x").await;
        let elapsed = start.elapsed();

        assert_eq!(decision, CredentialDecisionKind::Timeout);
        assert!(
            elapsed < Duration::from_secs(1),
            "expected fast deny; took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn resolve_credential_pending_unknown_id_is_noop() {
        let (state, _rx) = test_state();
        assert!(!resolve_credential_pending(
            &state,
            "no-such-id",
            CredentialDecisionKind::Allow
        ));
    }

    #[tokio::test]
    async fn credential_gate_second_call_after_cleanup_opens_new_dialog() {
        let (state, mut rx) = test_state();
        let h = tokio::spawn({
            let state = state.clone();
            async move { credential_gate_or_deny(&state, "github", "x").await }
        });
        let frame1 = rx.recv().await.unwrap();
        let id1 = serde_json::from_str::<serde_json::Value>(&frame1).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        resolve_credential_pending(&state, &id1, CredentialDecisionKind::Deny);
        assert_eq!(h.await.unwrap(), CredentialDecisionKind::Deny);

        let h2 = tokio::spawn({
            let state = state.clone();
            async move { credential_gate_or_deny(&state, "github", "x").await }
        });
        let frame2 = rx.recv().await.unwrap();
        let id2 = serde_json::from_str::<serde_json::Value>(&frame2).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(id1, id2, "second round must mint a new id");
        resolve_credential_pending(&state, &id2, CredentialDecisionKind::Allow);
        assert_eq!(h2.await.unwrap(), CredentialDecisionKind::Allow);
    }

    #[tokio::test]
    async fn second_call_after_cleanup_opens_new_dialog() {
        let (state, mut rx) = test_state();
        // first round
        let h = tokio::spawn({
            let state = state.clone();
            async move { gate(&state, "h", "x").await }
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
            async move { gate(&state, "h", "x").await }
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
