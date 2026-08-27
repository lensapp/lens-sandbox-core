//! Supervisor lifecycle helpers: signal forwarding and zombie reaping.
//!
//! The sandbox supervisor runs as PID 1 inside its container. PID 1 has
//! two responsibilities the OS expects of an init process:
//!
//! 1. Translate `docker stop` (SIGTERM to PID 1) into a graceful agent
//!    shutdown — handled by [`wait_with_signal_forwarding`].
//! 2. Reap any orphan grandchild whose parent died while it was still
//!    running, so it doesn't accumulate as a zombie — handled by
//!    [`OrphanReaper`].
//!
//! Both helpers cooperate with `tokio::process::Child`: the reaper never
//! touches the supervisor's own managed child (registered via
//! [`OrphanReaper::protect_pid`]) nor any short-lived direct child a
//! subsystem is waiting on itself (registered via a [`PidGuard`] handed
//! out by [`OrphanReaper::guard`]), so tokio still retrieves those
//! children's real exit status via `Child::wait()`.

use std::collections::HashSet;
use std::process::ExitStatus;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::process::Child;

/// Default supervisor → child grace period between SIGTERM and SIGKILL.
///
/// Picked to sit comfortably inside Docker's default 10-second stop
/// timeout: the supervisor's own SIGKILL escalation fires before Docker
/// would, so the agent's exit code reaches us instead of being masked
/// by Docker's SIGKILL.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(8);

/// Await the child's exit, forwarding shutdown signals to it.
///
/// Behaviour:
///   * If the child exits before any signal arrives, returns its exit
///     status unchanged.
///   * If the supervisor receives SIGTERM / SIGINT / SIGHUP, forwards
///     SIGTERM to the child and waits up to `grace` for it to exit.
///   * If a *second* signal arrives during the grace window, escalates
///     to SIGKILL immediately — operator intent overrides graciousness.
///   * Otherwise, on grace expiry, escalates to SIGKILL.
#[cfg(unix)]
pub async fn wait_with_signal_forwarding(
    child: &mut Child,
    grace: Duration,
) -> std::io::Result<ExitStatus> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut term = signal(SignalKind::terminate())?;
    let mut intr = signal(SignalKind::interrupt())?;
    let mut hup = signal(SignalKind::hangup())?;

    let trigger = tokio::select! {
        status = child.wait() => return status,
        _ = term.recv() => "SIGTERM",
        _ = intr.recv() => "SIGINT",
        _ = hup.recv() => "SIGHUP",
    };
    tracing::info!(
        signal = trigger,
        "supervisor signalled, forwarding SIGTERM to agent"
    );

    forward_sigterm(child);

    // Wait for the child to exit, the grace period to expire, or a
    // second signal to short-circuit straight to SIGKILL.
    let kill_reason = tokio::select! {
        status = child.wait() => return status,
        _ = tokio::time::sleep(grace) => "grace expired",
        _ = term.recv() => "second SIGTERM during grace",
        _ = intr.recv() => "second SIGINT during grace",
        _ = hup.recv() => "second SIGHUP during grace",
    };
    tracing::warn!(
        reason = kill_reason,
        grace_secs = grace.as_secs(),
        "escalating to SIGKILL"
    );
    if let Err(e) = child.start_kill() {
        tracing::warn!(error = %e, "SIGKILL on agent failed");
    }
    child.wait().await
}

#[cfg(not(unix))]
pub async fn wait_with_signal_forwarding(
    child: &mut Child,
    _grace: Duration,
) -> std::io::Result<ExitStatus> {
    child.wait().await
}

/// The status a caller reports for a child that has been waited on.
///
/// A signalled child has no exit code of its own, so it takes the shell's
/// convention of `128 + signal` — that is what a reader comparing the
/// number against `kill -l` expects. A child with neither, which the
/// platform should not produce, reports a plain failure rather than
/// success.
///
/// Unix only, and unguarded on purpose: the crate calls
/// `Command::pre_exec` in `privilege.rs`, which tokio defines only for
/// unix, so a non-unix build fails long before it reaches this line. A
/// second arm here would report a portability this crate does not have.
pub fn exit_code_of(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

/// Send SIGTERM to the child. Safe to call once: `child.id()` only
/// returns `None` after the child has been reaped via `wait()`, which
/// hasn't happened yet at this point in the call chain.
#[cfg(unix)]
fn forward_sigterm(child: &Child) {
    let Some(pid) = child.id() else { return };
    let pid = nix::unistd::Pid::from_raw(pid as i32);
    if let Err(e) = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM) {
        tracing::warn!(error = %e, %pid, "SIGTERM on agent failed");
    }
}

/// Background task that reaps orphan grandchildren reparented to this
/// PID-1 supervisor.
///
/// Why it's needed: when the agent forks a daemon (`nohup foo &`) and
/// the intermediate parent exits, the daemon reparents to us (PID 1).
/// When it eventually dies, only PID 1 can `waitpid` for it — otherwise
/// the kernel keeps the entry in the process table as a zombie. For
/// short-lived sandboxes this doesn't matter (the container dies first),
/// but managed sandboxes run for hours and accumulate them.
///
/// Why it's careful: `tokio::process::Child::wait()` calls
/// `waitpid(agent_pid, ...)` to retrieve the exit status. If we
/// `waitpid(-1, WNOHANG)` and win the race for the agent's PID, tokio
/// sees `ECHILD` and loses the real exit code. So the reaper scans the
/// supervisor's current direct children via `/proc/<pid>/task/<pid>/children`
/// and only calls `waitpid(pid, WNOHANG)` on PIDs that are *not* the
/// protected agent PID and *not* registered in the [`PidGuard`] set.
/// Grandchildren that reparented to us are in neither, so they get
/// reaped; the agent and any in-flight exec children are left to their
/// own `Child::wait()`.
#[cfg(target_os = "linux")]
pub struct OrphanReaper {
    protected: tokio::sync::watch::Sender<Option<i32>>,
    guard: PidGuard,
}

/// Cloneable handle for subsystems that spawn short-lived direct children
/// they `Child::wait()` on themselves (e.g. the exec manager). A PID
/// registered via [`protect`](PidGuard::protect) is skipped by the reaper
/// until [`release`](PidGuard::release)d, so the caller's own wait wins
/// the race for the exit status instead of losing it to the reaper's
/// `waitpid` (which would surface as `ECHILD` and drop the exit code).
///
/// Unlike the single agent PID, exec children come and go concurrently,
/// so this is a set rather than the `watch<Option<i32>>` slot.
///
/// Defined on all platforms so cross-platform callers (e.g. the shell
/// sandbox dispatcher) can construct one uniformly; only the reaper that
/// consults it is Linux-only, so on other hosts the set is simply never
/// read.
#[derive(Clone, Default)]
pub struct PidGuard {
    guarded: Arc<Mutex<HashSet<i32>>>,
}

impl PidGuard {
    /// Protect a live direct child PID from the reaper. Must be called
    /// before the current task yields after the spawn, so the reaper
    /// cannot observe the child's exit (via SIGCHLD, which only fires
    /// once the child has run) before the PID is registered.
    pub fn protect(&self, pid: u32) {
        self.guarded.lock().unwrap().insert(pid as i32);
    }

    /// Release a PID once the caller's own `Child::wait()` has reaped it.
    /// Idempotent — releasing an unknown PID is a no-op.
    pub fn release(&self, pid: u32) {
        self.guarded.lock().unwrap().remove(&(pid as i32));
    }

    #[cfg(target_os = "linux")]
    fn contains(&self, pid: i32) -> bool {
        self.guarded.lock().unwrap().contains(&pid)
    }
}

#[cfg(target_os = "linux")]
impl OrphanReaper {
    /// Start the reaper task. Returns a handle whose [`protect_pid`]
    /// method is called once the supervised child has been spawned.
    /// Dropping the handle stops the reaper.
    pub fn spawn() -> Self {
        let (tx, rx) = tokio::sync::watch::channel::<Option<i32>>(None);
        let guard = PidGuard::default();
        tokio::spawn(run_reaper(rx, guard.clone()));
        Self {
            protected: tx,
            guard,
        }
    }

    /// Register the supervisor's directly-managed child PID. The reaper
    /// will not touch this PID — tokio owns it and must observe its
    /// exit status. Subsequent calls replace the previous protected PID
    /// (e.g. on WS reconnect when a new session spawns a new agent).
    pub fn protect_pid(&self, pid: u32) {
        let _ = self.protected.send(Some(pid as i32));
    }

    /// A cloneable [`PidGuard`] sharing this reaper's exec-child set.
    /// Hand it to any subsystem that spawns direct children it waits on
    /// itself, so the reaper leaves those PIDs alone until released.
    pub fn guard(&self) -> PidGuard {
        self.guard.clone()
    }
}

#[cfg(target_os = "linux")]
async fn run_reaper(protected: tokio::sync::watch::Receiver<Option<i32>>, guard: PidGuard) {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigchld = match signal(SignalKind::child()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "could not register SIGCHLD listener; orphan reaping disabled");
            return;
        }
    };

    // SIGCHLD is the only wake source. The reaper task is process-scoped:
    // when the supervisor exits, tokio tears down the runtime and the
    // task ends. Polling `protected.changed()` as a second select arm
    // would fire on every `protect_pid` call and risk starving SIGCHLD
    // during reconnect storms.
    while sigchld.recv().await.is_some() {
        let Some(protected_pid) = *protected.borrow() else {
            // No agent yet — every running child PID is one the supervisor
            // itself spawned (iptables setup, network probes) and is
            // currently waiting on. Reaping here would steal the exit
            // status out from under the caller and produce ECHILD on
            // their `waitpid`. Wait until protect_pid() registers the
            // agent — by then no other direct-child waiters exist.
            continue;
        };
        reap_orphans(protected_pid, &guard);
    }
}

/// Reap every direct child of this process whose PID is neither
/// `protected_pid` nor registered in `guard`, taking a single snapshot of
/// `/proc/<self>/task/<self>/children` and calling `waitpid(pid, WNOHANG)`
/// per entry. SIGCHLD coalesces, but we don't loop here — a still-running
/// child returns `StillAlive` and the next SIGCHLD covers any new exits.
#[cfg(target_os = "linux")]
fn reap_orphans(protected_pid: i32, guard: &PidGuard) {
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
    use nix::unistd::Pid;

    for pid in current_children() {
        if pid == protected_pid || guard.contains(pid) {
            continue;
        }
        match waitpid(Some(Pid::from_raw(pid)), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, status)) => {
                tracing::debug!(orphan_pid = pid, exit = status, "reaped orphan");
            }
            Ok(WaitStatus::Signaled(_, sig, _)) => {
                tracing::debug!(orphan_pid = pid, signal = %sig, "reaped orphan (signal)");
            }
            // StillAlive means not yet exited; we'll catch it on a later SIGCHLD.
            // Any error here usually means the PID raced and was already
            // reaped (ECHILD) — nothing to do, and worth keeping quiet
            // about so we don't fill logs on every tick.
            _ => {}
        }
    }
}

/// Read this supervisor's *current* direct children from `/proc`. Iterates
/// every task (thread) under `/proc/<pid>/task/` because the kernel exposes
/// the children list per-task — a child fork()ed from a tokio worker only
/// shows up under that worker's tid, not the TGL's.
///
/// Returns an empty vec on any I/O error — the next SIGCHLD will trigger
/// another scan, so transient failures self-heal.
#[cfg(target_os = "linux")]
fn current_children() -> Vec<i32> {
    let pid = std::process::id();
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in tasks.flatten() {
        let path = entry.path().join("children");
        if let Ok(contents) = std::fs::read_to_string(&path) {
            out.extend(
                contents
                    .split_ascii_whitespace()
                    .filter_map(|s| s.parse::<i32>().ok()),
            );
        }
    }
    out
}

#[cfg(not(target_os = "linux"))]
pub struct OrphanReaper;

#[cfg(not(target_os = "linux"))]
impl OrphanReaper {
    pub fn spawn() -> Self {
        Self
    }
    pub fn protect_pid(&self, _pid: u32) {}
    pub fn guard(&self) -> PidGuard {
        PidGuard::default()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// The exec guard is the mechanism that keeps the reaper off an exec
    /// child until its owner has `wait()`ed it: `reap_orphans` skips any
    /// PID `guard.contains(...)` reports. Pin the set semantics and — just
    /// as importantly — that a clone shares the same underlying set, since
    /// `OrphanReaper::guard()` hands `ExecManager` a clone and relies on
    /// the reaper task seeing every PID the manager protects.
    #[cfg(target_os = "linux")]
    #[test]
    fn pid_guard_shares_set_across_clones() {
        let guard = PidGuard::default();
        assert!(!guard.contains(1234));

        guard.protect(1234);
        assert!(guard.contains(1234));
        guard.protect(1234); // idempotent — no double-insert surprises
        assert!(guard.contains(1234));

        // A clone (what the reaper task holds) sees the manager's inserts.
        let reaper_view = guard.clone();
        guard.protect(42);
        assert!(reaper_view.contains(42));

        // Release drops it from every clone; releasing twice is a no-op.
        guard.release(1234);
        assert!(!reaper_view.contains(1234));
        guard.release(1234);
        assert!(!guard.contains(1234));
        assert!(reaper_view.contains(42), "unrelated PID must stay guarded");
    }

    /// /proc-backed child enumeration matches `tokio::process::Child::id()`
    /// for processes we directly spawned. Cheap end-to-end check that the
    /// path parsing works on the test host.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn current_children_includes_spawned_child() {
        let mut child = tokio::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id().expect("child pid") as i32;

        let children = current_children();
        assert!(
            children.contains(&pid),
            "spawned PID {pid} not in /proc children: {children:?}"
        );

        let _ = child.kill().await;
        let _ = child.wait().await;
    }

    /// SIGTERM landing on the supervisor is forwarded to the child as
    /// SIGTERM. tokio's signal stream catches SIGTERM at the process
    /// level so the test runner itself is unharmed.
    ///
    /// Uses `std::os::unix::process::ExitStatusExt::signal()` to read
    /// the signal number the kernel recorded as the cause of the
    /// child's death; a value of `Some(15)` (SIGTERM) confirms the
    /// forward, not just that the child happens to have exited.
    #[tokio::test]
    async fn wait_with_signal_forwarding_propagates_sigterm() {
        use nix::libc;
        use std::os::unix::process::ExitStatusExt;
        use std::time::Duration;
        use tokio::signal::unix::{SignalKind, signal};

        // Install the SIGTERM stream *before* anything raises the signal.
        // tokio's `signal()` calls `sigaction` synchronously, so once this
        // line returns the OS will deliver SIGTERM to tokio's handler
        // instead of the default disposition — which would otherwise kill
        // the cargo test runner if the spawned `kill` below races ahead of
        // `wait_with_signal_forwarding`'s own `signal()` call.
        let _term = signal(SignalKind::terminate()).expect("install SIGTERM handler");

        let mut child = tokio::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");

        // Raise SIGTERM on ourselves once `wait_with_signal_forwarding`
        // has had a chance to install its own signal stream.
        tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(std::process::id() as i32),
                nix::sys::signal::Signal::SIGTERM,
            )
            .expect("raise SIGTERM on self");
        });

        let status = tokio::time::timeout(
            Duration::from_secs(5),
            wait_with_signal_forwarding(&mut child, Duration::from_secs(2)),
        )
        .await
        .expect("helper did not return in time")
        .expect("wait result");

        assert_eq!(
            status.signal(),
            Some(libc::SIGTERM),
            "child should have been killed by SIGTERM, got status {status:?}"
        );
    }

    /// If the child exits on its own before any signal arrives, the
    /// helper returns its real exit status — the signal-listening path
    /// must not corrupt the happy path.
    #[tokio::test]
    async fn wait_with_signal_forwarding_returns_natural_exit() {
        use std::time::Duration;

        let mut child = tokio::process::Command::new("true")
            .spawn()
            .expect("spawn true");

        let status = wait_with_signal_forwarding(&mut child, Duration::from_secs(2))
            .await
            .expect("wait result");

        assert!(status.success(), "expected success, got {status:?}");
    }

    #[cfg(unix)]
    #[test]
    fn a_child_that_exited_reports_its_own_code() {
        use std::os::unix::process::ExitStatusExt;

        // The wait status a child that called exit(100) leaves behind.
        assert_eq!(exit_code_of(ExitStatus::from_raw(100 << 8)), 100);
    }

    #[cfg(unix)]
    #[test]
    fn a_signalled_child_reports_the_signal_above_128() {
        use std::os::unix::process::ExitStatusExt;

        assert_eq!(
            exit_code_of(ExitStatus::from_raw(nix::libc::SIGKILL)),
            128 + 9,
            "a signalled child has no exit code of its own, and 128 + signal is what a reader comparing the number against `kill -l` expects"
        );
    }
}
