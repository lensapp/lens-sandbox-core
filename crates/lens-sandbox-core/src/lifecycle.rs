//! Supervisor lifecycle helpers: signal forwarding and zombie reaping.
//!
//! The sandbox supervisor runs as PID 1 inside its container. PID 1 has
//! two responsibilities the OS expects of an init process:
//!
//! 1. Translate `docker stop` (SIGTERM to PID 1) into a graceful agent
//!    shutdown — handled by [`wait_for_child_exit`].
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

/// How a child awaited by [`wait_for_child_exit`] ended.
///
/// The split is what lets a caller report a workload's result only when
/// the workload really finished: a child that the supervisor stopped
/// because the supervisor itself was told to stop has no result of its
/// own, whatever status the forwarded signal left behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildExit {
    /// The child exited before the supervisor received SIGTERM.
    Finished(ExitStatus),
    /// The supervisor received SIGTERM first and stopped the child.
    Stopped(ExitStatus),
}

impl ChildExit {
    pub fn status(self) -> ExitStatus {
        match self {
            Self::Finished(status) | Self::Stopped(status) => status,
        }
    }
}

/// Await the child's exit, forwarding shutdown signals to it.
///
/// The same as [`wait_for_child_exit`] for a caller that does not need to
/// know why the child ended.
pub async fn wait_with_signal_forwarding(
    child: &mut Child,
    grace: Duration,
) -> std::io::Result<ExitStatus> {
    wait_for_child_exit(child, grace)
        .await
        .map(ChildExit::status)
}

/// Await the child's exit, forwarding shutdown signals to it, and say
/// whether the child finished or was stopped.
///
/// Behaviour:
///   * If the child exits before SIGTERM arrives, returns
///     [`ChildExit::Finished`] with its exit status unchanged.
///   * SIGHUP, SIGINT and SIGQUIT go to the child unchanged at any time;
///     they do not stop it on their own.
///   * If the supervisor receives SIGTERM, forwards it to the child and
///     waits up to `grace` for it to exit.
///   * If a *second* SIGTERM arrives during the grace window, escalates
///     to SIGKILL immediately — operator intent overrides graciousness.
///   * Otherwise, on grace expiry, escalates to SIGKILL.
///
/// Every path after a SIGTERM returns [`ChildExit::Stopped`].
#[cfg(unix)]
pub async fn wait_for_child_exit(child: &mut Child, grace: Duration) -> std::io::Result<ChildExit> {
    wait_for_shutdown(child, Some(grace)).await
}

/// Await the child's exit with no deadline of its own after a shutdown
/// signal, and say whether the child finished or was stopped.
///
/// The same as [`wait_for_child_exit`] except that nothing here ends the
/// wait on a timer: after the first SIGTERM the helper waits for the
/// child for as long as the caller does. A second SIGTERM still sends
/// SIGKILL to the child's process group at once. A caller that owns the
/// end of the run (a host that stops a sandbox with a timeout) puts that
/// deadline on its own side and sends the second SIGTERM when the
/// timeout runs out.
#[cfg(unix)]
pub async fn wait_for_child_exit_host_owned(child: &mut Child) -> std::io::Result<ChildExit> {
    wait_for_shutdown(child, None).await
}

/// The shared body of the two unix waits. `grace` of `None` means no
/// deadline after the first SIGTERM.
#[cfg(unix)]
async fn wait_for_shutdown(
    child: &mut Child,
    grace: Option<Duration>,
) -> std::io::Result<ChildExit> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut term = signal(SignalKind::terminate())?;
    let mut passed_on = PassedOn::listen()?;

    loop {
        tokio::select! {
            status = child.wait() => return status.map(ChildExit::Finished),
            _ = term.recv() => break,
            signal = passed_on.recv() => pass_on(child, signal),
        }
    }
    tracing::info!("supervisor got SIGTERM, forwarding it to agent");
    kill_agent(child, nix::sys::signal::Signal::SIGTERM);

    let grace_expires = until_grace_expires(grace);
    tokio::pin!(grace_expires);
    let kill_reason = loop {
        tokio::select! {
            status = child.wait() => return status.map(ChildExit::Stopped),
            _ = &mut grace_expires => break "grace expired",
            _ = term.recv() => break "second SIGTERM during grace",
            signal = passed_on.recv() => pass_on(child, signal),
        }
    };
    tracing::warn!(reason = kill_reason, "escalating to SIGKILL");
    kill_agent(child, nix::sys::signal::Signal::SIGKILL);
    child.wait().await.map(ChildExit::Stopped)
}

#[cfg(unix)]
fn pass_on(child: &mut Child, signal: nix::sys::signal::Signal) {
    tracing::debug!(?signal, "passing signal to agent");
    kill_agent(child, signal);
}

/// The signals the supervisor passes on to the agent as they are.
#[cfg(unix)]
struct PassedOn {
    hup: tokio::signal::unix::Signal,
    int: tokio::signal::unix::Signal,
    quit: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl PassedOn {
    fn listen() -> std::io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};

        Ok(Self {
            hup: signal(SignalKind::hangup())?,
            int: signal(SignalKind::interrupt())?,
            quit: signal(SignalKind::quit())?,
        })
    }

    async fn recv(&mut self) -> nix::sys::signal::Signal {
        use nix::sys::signal::Signal;

        tokio::select! {
            _ = self.hup.recv() => Signal::SIGHUP,
            _ = self.int.recv() => Signal::SIGINT,
            _ = self.quit.recv() => Signal::SIGQUIT,
        }
    }
}

#[cfg(unix)]
async fn until_grace_expires(grace: Option<Duration>) {
    match grace {
        Some(grace) => tokio::time::sleep(grace).await,
        None => std::future::pending().await,
    }
}

#[cfg(not(unix))]
pub async fn wait_for_child_exit(
    child: &mut Child,
    _grace: Duration,
) -> std::io::Result<ChildExit> {
    child.wait().await.map(ChildExit::Finished)
}

#[cfg(not(unix))]
pub async fn wait_for_child_exit_host_owned(child: &mut Child) -> std::io::Result<ChildExit> {
    child.wait().await.map(ChildExit::Finished)
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

/// Send `signal` to the agent and, when the agent leads its own process
/// group, to every process in that group, so a wrapper's children get it
/// too (`child_spawner` starts the agent as a group leader). A SIGKILL also
/// goes to the child handle itself, so the wait can return.
#[cfg(unix)]
fn kill_agent(child: &mut Child, signal: nix::sys::signal::Signal) {
    use nix::sys::signal::{kill, killpg};
    use nix::unistd::{Pid, getpgid};

    let Some(pid) = child.id() else { return };
    let pid = Pid::from_raw(pid as i32);
    let leads_group = getpgid(Some(pid)).is_ok_and(|group| group == pid);
    let sent = if leads_group {
        killpg(pid, signal)
    } else {
        kill(pid, signal)
    };
    if let Err(e) = sent {
        tracing::warn!(error = %e, %pid, ?signal, "signal to agent failed");
    }
    if signal == nix::sys::signal::Signal::SIGKILL
        && let Err(e) = child.start_kill()
    {
        tracing::warn!(error = %e, "SIGKILL on agent failed");
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
/// sees `ECHILD` and loses the real exit code. So the reaper scans `/proc`
/// for the supervisor's current direct children and only calls
/// `waitpid(pid, WNOHANG)` on PIDs that are *not* the protected agent PID
/// and *not* registered in the [`PidGuard`] set.
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
/// the direct children in `/proc` and calling `waitpid(pid, WNOHANG)`
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

/// Read this supervisor's *current* direct children: every process in
/// `/proc` whose parent is this one. Not `/proc/<pid>/task/<tid>/children`,
/// which only a kernel built with `CONFIG_PROC_CHILDREN` has.
///
/// A process that exits during the scan is skipped; the next SIGCHLD
/// covers it.
#[cfg(target_os = "linux")]
fn current_children() -> Vec<i32> {
    let me = std::process::id() as i32;
    let entries = match std::fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(e) => {
            static WARNED: std::sync::Once = std::sync::Once::new();
            WARNED.call_once(|| {
                tracing::warn!(error = %e, "could not read /proc; orphans are not reaped");
            });
            return Vec::new();
        }
    };
    entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<i32>().ok())
        .filter(|pid| {
            std::fs::read(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|stat| parent_pid(&stat))
                == Some(me)
        })
        .collect()
}

/// The parent PID from a `/proc/<pid>/stat` line. The process name can hold
/// spaces and `)`, so the fields are counted from the last `)`. It need not
/// be UTF-8 either, so only the fields after it are decoded.
#[cfg(target_os = "linux")]
fn parent_pid(stat: &[u8]) -> Option<i32> {
    let name_end = stat.iter().rposition(|&b| b == b')')?;
    let fields = std::str::from_utf8(&stat[name_end + 1..]).ok()?;
    fields.split_ascii_whitespace().nth(1)?.parse().ok()
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

    #[cfg(target_os = "linux")]
    #[test]
    fn parent_pid_counts_fields_from_the_last_parenthesis() {
        assert_eq!(parent_pid(b"977 (sh) S 1 977 977 0 -1"), Some(1));
        assert_eq!(parent_pid(b"42 (a) (b) c) R 7 42 42 0 -1"), Some(7));
        assert_eq!(parent_pid(b"42 (no parent"), None);
    }

    /// The kernel cuts a name to 15 bytes, which can split a UTF-8
    /// character: such a process must still be found, or its zombie stays.
    #[cfg(target_os = "linux")]
    #[test]
    fn parent_pid_reads_a_name_that_is_not_utf8() {
        assert_eq!(
            parent_pid(b"977 (agent-\xe2\x82) Z 1 977 977 0 -1"),
            Some(1)
        );
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
    async fn a_forwarded_sigterm_stops_the_child() {
        use nix::libc;
        use std::os::unix::process::ExitStatusExt;
        use std::time::Duration;
        use tokio::signal::unix::{SignalKind, signal};

        let _serial = SIGNAL_TESTS.lock().await;
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

        let exit = tokio::time::timeout(
            Duration::from_secs(5),
            wait_for_child_exit(&mut child, Duration::from_secs(2)),
        )
        .await
        .expect("helper did not return in time")
        .expect("wait result");

        let ChildExit::Stopped(status) = exit else {
            panic!("a child ended by a forwarded signal was stopped, not finished: {exit:?}");
        };
        assert_eq!(
            status.signal(),
            Some(libc::SIGTERM),
            "child should have been killed by SIGTERM, got status {status:?}"
        );
    }

    /// The signal tests raise SIGTERM on this process, and every wait in
    /// the test binary that is listening hears it, so they run one at a time.
    static SIGNAL_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn raise_on_self(signal: nix::sys::signal::Signal) {
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(std::process::id() as i32),
            signal,
        )
        .expect("raise signal on self");
    }

    /// A shutdown reaches the agent's whole process group: a wrapper and
    /// the child it forked each get SIGTERM and write their marker.
    #[tokio::test]
    async fn a_forwarded_sigterm_reaches_every_process_in_the_agent_group() {
        use std::time::Duration;
        use tokio::signal::unix::{SignalKind, signal};

        let _serial = SIGNAL_TESTS.lock().await;
        let _term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let marker = std::env::temp_dir().join(format!("lens-core-group-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);

        let script = r#"trap 'echo wrapper >> "$MARK"; exit 0' TERM
sh -c 'trap "echo child >> \$MARK; exit 0" TERM; while :; do sleep 0.05; done' &
wait"#;
        let mut child = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .env("MARK", &marker)
            .process_group(0)
            .spawn()
            .expect("spawn wrapper");

        // Give the nested shell time to install its trap, then signal.
        tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            raise_on_self(nix::sys::signal::Signal::SIGTERM);
        });

        let exit = tokio::time::timeout(
            Duration::from_secs(5),
            wait_for_child_exit(&mut child, Duration::from_secs(2)),
        )
        .await
        .expect("helper did not return in time")
        .expect("wait result");
        assert!(matches!(exit, ChildExit::Stopped(_)), "got {exit:?}");

        // The grandchild may finish its trap a moment after the wrapper exits.
        let mut lines = String::new();
        for _ in 0..50 {
            lines = std::fs::read_to_string(&marker).unwrap_or_default();
            if lines.contains("wrapper") && lines.contains("child") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let _ = std::fs::remove_file(&marker);
        assert!(
            lines.contains("wrapper") && lines.contains("child"),
            "both the wrapper and its child should get SIGTERM, markers: {lines:?}"
        );
    }

    /// The host-owned wait has no deadline of its own: after a SIGTERM that
    /// the agent ignores it keeps waiting past the timed wait's grace, and a
    /// second signal sends SIGKILL to the whole group, including a grandchild
    /// that ignores TERM.
    #[tokio::test]
    async fn the_host_owned_wait_keeps_waiting_until_a_second_signal_kills_the_group() {
        use std::os::unix::process::ExitStatusExt;
        use std::time::Duration;
        use tokio::signal::unix::{SignalKind, signal};

        let _serial = SIGNAL_TESTS.lock().await;
        let _term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let pid_file = std::env::temp_dir().join(format!("lens-core-kill-{}", std::process::id()));
        let _ = std::fs::remove_file(&pid_file);

        let script = r#"trap '' TERM
sh -c 'trap "" TERM; while :; do sleep 0.05; done' &
echo $! > "$MARK"
wait"#;
        let mut child = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .env("MARK", &pid_file)
            .process_group(0)
            .spawn()
            .expect("spawn wrapper");

        let mut wait = Box::pin(wait_for_child_exit_host_owned(&mut child));
        tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            raise_on_self(nix::sys::signal::Signal::SIGTERM);
        });
        let early = tokio::time::timeout(Duration::from_millis(2500), &mut wait).await;
        assert!(
            early.is_err(),
            "the host-owned wait ended before a second signal"
        );

        raise_on_self(nix::sys::signal::Signal::SIGTERM);
        let exit = tokio::time::timeout(Duration::from_secs(5), &mut wait)
            .await
            .expect("second signal did not end the wait")
            .expect("wait result");
        let ChildExit::Stopped(status) = exit else {
            panic!("a child ended by a signal was stopped, not finished: {exit:?}");
        };
        assert_eq!(status.signal(), Some(nix::libc::SIGKILL));

        let grandchild: i32 = std::fs::read_to_string(&pid_file)
            .expect("grandchild pid")
            .trim()
            .parse()
            .expect("pid number");
        let _ = std::fs::remove_file(&pid_file);
        let mut gone = false;
        for _ in 0..50 {
            if process_is_gone(grandchild) {
                gone = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(gone, "the SIGKILL should reach the grandchild {grandchild}");
    }

    /// Only SIGTERM stops the agent: SIGHUP, SIGINT and SIGQUIT reach the
    /// agent unchanged, so its own exit is its result.
    #[tokio::test]
    async fn a_signal_other_than_sigterm_reaches_the_agent_unchanged() {
        use nix::sys::signal::Signal;
        use std::time::Duration;
        use tokio::signal::unix::{SignalKind, signal};

        let _serial = SIGNAL_TESTS.lock().await;
        let _hup = signal(SignalKind::hangup()).expect("install SIGHUP handler");
        let _int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        let _quit = signal(SignalKind::quit()).expect("install SIGQUIT handler");

        for (signal, code) in [
            (Signal::SIGHUP, 11),
            (Signal::SIGINT, 12),
            (Signal::SIGQUIT, 13),
        ] {
            let script = "trap 'exit 11' HUP; trap 'exit 12' INT; trap 'exit 13' QUIT; \
                          trap 'exit 99' TERM; while :; do sleep 0.05; done";
            let mut child = tokio::process::Command::new("sh")
                .arg("-c")
                .arg(script)
                .process_group(0)
                .spawn()
                .expect("spawn agent");

            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(500)).await;
                raise_on_self(signal);
            });

            let exit = tokio::time::timeout(
                Duration::from_secs(5),
                wait_for_child_exit_host_owned(&mut child),
            )
            .await
            .expect("helper did not return in time")
            .expect("wait result");
            let ChildExit::Finished(status) = exit else {
                panic!("{signal:?} stopped the agent instead of reaching it: {exit:?}");
            };
            assert_eq!(status.code(), Some(code), "{signal:?}");
        }
    }

    /// Whether `pid` is no longer running: absent, or a zombie waiting for
    /// its parent to reap it.
    fn process_is_gone(pid: i32) -> bool {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(_) => true,
            Ok(stat) => stat
                .rsplit(')')
                .next()
                .is_some_and(|rest| rest.trim_start().starts_with('Z')),
        }
    }

    /// If the child exits on its own before any signal arrives, the
    /// helper returns its real exit status — the signal-listening path
    /// must not corrupt the happy path.
    #[tokio::test]
    async fn a_child_that_exits_on_its_own_finishes() {
        use std::time::Duration;

        let _serial = SIGNAL_TESTS.lock().await;
        let mut child = tokio::process::Command::new("true")
            .spawn()
            .expect("spawn true");

        let exit = wait_for_child_exit(&mut child, Duration::from_secs(2))
            .await
            .expect("wait result");

        let ChildExit::Finished(status) = exit else {
            panic!("a child that exited on its own finished: {exit:?}");
        };
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
