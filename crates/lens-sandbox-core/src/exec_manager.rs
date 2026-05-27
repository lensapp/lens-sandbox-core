//! Registry of running exec children, shared across WS sessions.
//!
//! Lifetime is the dispatcher / sandbox process — a WS reconnect doesn't
//! recreate the manager, so execs survive WS disruption. The forwarder
//! task per exec also persists past dest loss (see "Output path"
//! below), and `exec_reattach` rebinds them to a fresh WS dest.
//!
//! Two attach modes: piped (separate stdout/stderr) and PTY (merged via
//! the slave's stdio, single `exec_stdout` stream, resize through ioctl
//! on the master fd).
//!
//! Output path: each exec gets a forwarder task that owns the WS dest
//! and a scrollback ring buffer. Pipe readers (and run_controller for
//! exec_exit / exec_error) emit `ForwarderEvent`s; the forwarder
//! serializes them and writes to its current dest. On dest loss
//! (WS close) the dest goes to `None` and the forwarder keeps
//! consuming chunks into scrollback — the exec persists past a
//! disconnect. `exec_reattach` sends a `SwapDest` event with a oneshot
//! reply so the manager can surface "busy — pass force=true" before
//! committing to the swap; on Swapped the forwarder emits
//! `exec_detached` to the old dest and replays the scrollback to the
//! new one. Owner-only steal: reattach refuses unless the calling
//! actor's `user_id` matches the original attacher's.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Child;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use crate::child_spawner::{self, ChildSpec};
use crate::exec_protocol::{
    ActorIdentity, DetachReason, IncomingMessage, OutgoingMessage, TerminalSize,
};
use crate::privilege::SandboxCredentials;
use crate::pty::OwnedRawFd;

/// Read buffer per chunk of stdout/stderr. Picks 4 KiB to amortize syscall
/// cost without inflating WS messages — base64 grows by 4/3, so a 4 KiB
/// read becomes a ~5.5 KiB JSON frame.
const READ_CHUNK: usize = 4096;

/// Bound on queued stdin frames per session. Typing throughput is bytes/sec,
/// so 32 frames is a generous backstop without buffering MBs of stdin.
const STDIN_QUEUE: usize = 32;

/// Default signal for `exec_cancel { signal: None }`.
const DEFAULT_KILL_SIGNAL: i32 = libc::SIGTERM;

/// Scrollback retained per exec so a reattach can replay the recent
/// output. 64 KiB caps memory per exec while still preserving "the last
/// screen or two" — long sessions can emit MBs of output that we don't
/// try to retain. Old chunks are evicted from the front.
const SCROLLBACK_CAPACITY_BYTES: usize = 64 * 1024;

/// Per-WS-session registry of running execs.
///
/// Cloned freely; the inner state is shared via `Arc<Mutex<...>>`.
#[derive(Clone)]
pub struct ExecManager {
    inner: std::sync::Arc<Inner>,
}

struct Inner {
    sessions: Mutex<HashMap<String, SessionHandle>>,
    creds: Option<SandboxCredentials>,
    is_root: bool,
}

/// Stdin frame sent from the manager to the writer task. Bytes are written
/// in send order; `Eof` makes the writer drop the child's stdin (signaling
/// EOF to the child). Single-channel design avoids a write/EOF race when
/// both fire in the same poll.
enum StdinFrame {
    Bytes(Vec<u8>),
    Eof,
}

struct SessionHandle {
    stdin_tx: mpsc::Sender<StdinFrame>,
    /// Flip to `true` on first cancel so a second cancel for the same
    /// exec_id is a no-op. Used in place of the old kill-oneshot
    /// indirection: cancel now calls `libc::killpg` directly, which
    /// removes one tokio task scheduling hop from the cancel→reap path
    /// — that hop was a measurable source of flakiness under runtime
    /// contention (CI runners pegged, parallel test load).
    cancelled: Mutex<bool>,
    /// PTY master fd, present only for `tty=true` sessions. The `Arc`
    /// is the ownership story: as long as the registry holds it, the fd
    /// is alive. A `resize` clones the Arc out under the lock, so the fd
    /// can't close mid-ioctl even if the controller removes the entry in
    /// between. `None` on piped sessions — resize is a no-op there.
    tty_master_fd: Option<Arc<OwnedRawFd>>,
    /// Channel into the forwarder task. `exec_reattach` sends `SwapDest`
    /// through here to redirect output to a new WS dest.
    fwd_tx: mpsc::UnboundedSender<ForwarderEvent>,
    /// Cached for replay in `exec_attached` on reattach so the new client
    /// can mirror the original attach response.
    pid: u32,
    /// Identity that originally attached this exec. `Some` is reattachable
    /// by the same `user_id`; `None` is unscoped (legacy / no-actor
    /// attach) and explicitly NOT reattachable.
    owner: Option<ActorIdentity>,
}

impl ExecManager {
    pub fn new(creds: Option<SandboxCredentials>, is_root: bool) -> Self {
        Self {
            inner: std::sync::Arc::new(Inner {
                sessions: Mutex::new(HashMap::new()),
                creds,
                is_root,
            }),
        }
    }

    /// Route one decoded incoming frame. The manager owns the spawn /
    /// stdin / kill bookkeeping; all responses go back via `ws_tx`.
    pub async fn handle(&self, msg: IncomingMessage, ws_tx: &mpsc::UnboundedSender<String>) {
        match msg {
            IncomingMessage::ExecAttach {
                exec_id,
                argv,
                env,
                cwd,
                tty,
                stdin: _,
                stdout: _,
                stderr: _,
                initial_size,
                actor,
            } => {
                if tty {
                    self.attach_pty(exec_id, argv, env, cwd, initial_size, actor, ws_tx);
                } else {
                    self.attach_piped(exec_id, argv, env, cwd, actor, ws_tx);
                }
            }
            IncomingMessage::ExecStdin { exec_id, data } => {
                self.forward_stdin(&exec_id, &data, ws_tx);
            }
            IncomingMessage::ExecStdinEof { exec_id } => {
                self.signal_stdin_eof(&exec_id).await;
            }
            IncomingMessage::ExecCancel { exec_id, signal } => {
                self.cancel(&exec_id, signal.unwrap_or(DEFAULT_KILL_SIGNAL));
            }
            IncomingMessage::ExecResize {
                exec_id,
                cols,
                rows,
            } => {
                self.resize(&exec_id, cols, rows);
            }
            IncomingMessage::ExecReattach {
                exec_id,
                force,
                initial_size,
                actor,
            } => {
                self.reattach(exec_id, actor, force, initial_size, ws_tx)
                    .await;
            }
        }
    }

    fn attach_piped(
        &self,
        exec_id: String,
        argv: Vec<String>,
        env: HashMap<String, String>,
        cwd: Option<String>,
        actor: Option<ActorIdentity>,
        ws_tx: &mpsc::UnboundedSender<String>,
    ) {
        if self.inner.sessions.lock().unwrap().contains_key(&exec_id) {
            emit(
                ws_tx,
                OutgoingMessage::ExecError {
                    exec_id,
                    message: "exec_id already in use".into(),
                },
            );
            return;
        }

        let spec = ChildSpec {
            argv,
            cwd,
            env,
            creds: self.inner.creds.clone(),
            is_root: self.inner.is_root,
        };

        let mut cmd = child_spawner::build_command(&spec);
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                emit(
                    ws_tx,
                    OutgoingMessage::ExecError {
                        exec_id,
                        message: format!("spawn failed: {e}"),
                    },
                );
                return;
            }
        };

        let pid = child.id().unwrap_or(0);
        let stdout = child.stdout.take().expect("stdout was piped");
        let stderr = child.stderr.take().expect("stderr was piped");
        let stdin = child.stdin.take().expect("stdin was piped");

        let fwd_tx = spawn_forwarder(exec_id.clone(), ws_tx.clone());

        let (stdin_tx, stdin_rx) = mpsc::channel::<StdinFrame>(STDIN_QUEUE);

        spawn_stdin_writer(stdin, stdin_rx);

        let owner = actor;
        let handle = SessionHandle {
            stdin_tx,
            cancelled: Mutex::new(false),
            tty_master_fd: None,
            fwd_tx: fwd_tx.clone(),
            pid,
            owner: owner.clone(),
        };
        // Register the handle BEFORE announcing the attach so a client that
        // sends stdin / cancel the instant it sees `exec_attached` cannot
        // race the registry insert and have its frame silently no-op.
        self.inner
            .sessions
            .lock()
            .unwrap()
            .insert(exec_id.clone(), handle);

        // Emit exec_attached BEFORE spawning pipe readers. On a multi-thread
        // runtime the forwarder may already be polling on another worker;
        // the moment a pipe reader exists it can produce Chunk events that
        // the forwarder races onto ws_tx ahead of this synchronous emit.
        // Spawning readers strictly after the emit is the simplest
        // serialisation — there is no Chunk producer in the system until
        // those tasks are queued, so exec_attached is guaranteed to be the
        // first frame the client sees.
        emit(
            ws_tx,
            OutgoingMessage::ExecAttached {
                exec_id: exec_id.clone(),
                pid,
                owner,
            },
        );

        let stdout_task = spawn_pipe_reader(stdout, Stream::Stdout, fwd_tx.clone());
        let stderr_task = spawn_pipe_reader(stderr, Stream::Stderr, fwd_tx.clone());

        let registry = self.inner.clone();
        tokio::spawn(async move {
            run_controller(
                child,
                exec_id,
                vec![stdout_task, stderr_task],
                fwd_tx,
                registry,
            )
            .await;
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn attach_pty(
        &self,
        exec_id: String,
        argv: Vec<String>,
        env: HashMap<String, String>,
        cwd: Option<String>,
        initial_size: Option<TerminalSize>,
        actor: Option<ActorIdentity>,
        ws_tx: &mpsc::UnboundedSender<String>,
    ) {
        if self.inner.sessions.lock().unwrap().contains_key(&exec_id) {
            emit(
                ws_tx,
                OutgoingMessage::ExecError {
                    exec_id,
                    message: "exec_id already in use".into(),
                },
            );
            return;
        }

        let spec = ChildSpec {
            argv,
            cwd,
            env,
            creds: self.inner.creds.clone(),
            is_root: self.inner.is_root,
        };

        let size = initial_size.map(|s| (s.cols, s.rows)).unwrap_or((80, 24));

        let pty = match child_spawner::spawn_pty(&spec, size) {
            Ok(p) => p,
            Err(e) => {
                emit(
                    ws_tx,
                    OutgoingMessage::ExecError {
                        exec_id,
                        message: format!("pty spawn failed: {e}"),
                    },
                );
                return;
            }
        };

        let crate::pty::PtyProcess {
            child,
            master_fd,
            reader,
            writer,
            pid,
        } = pty;
        // Wrap the master fd in an Arc so both the registry and any
        // in-flight resize call own a share; reader/writer keep their
        // own dup'd fds and aren't affected by this Arc.
        let master_fd = Arc::new(master_fd);

        // Single output stream — PTY slave merges stdout+stderr into the
        // master. The protocol contract reflects this: tty=true never
        // emits exec_stderr.
        let fwd_tx = spawn_forwarder(exec_id.clone(), ws_tx.clone());

        let (stdin_tx, stdin_rx) = mpsc::channel::<StdinFrame>(STDIN_QUEUE);

        spawn_stdin_writer(writer, stdin_rx);

        let owner = actor;
        let handle = SessionHandle {
            stdin_tx,
            cancelled: Mutex::new(false),
            tty_master_fd: Some(master_fd),
            fwd_tx: fwd_tx.clone(),
            pid,
            owner: owner.clone(),
        };
        self.inner
            .sessions
            .lock()
            .unwrap()
            .insert(exec_id.clone(), handle);

        // Emit exec_attached before spawning the pipe reader. Same
        // multi-thread frame-ordering reason as in attach_piped.
        emit(
            ws_tx,
            OutgoingMessage::ExecAttached {
                exec_id: exec_id.clone(),
                pid,
                owner,
            },
        );

        let output_task = spawn_pipe_reader(reader, Stream::Stdout, fwd_tx.clone());

        let registry = self.inner.clone();
        tokio::spawn(async move {
            run_controller(child, exec_id, vec![output_task], fwd_tx, registry).await;
        });
    }

    fn resize(&self, exec_id: &str, cols: u16, rows: u16) {
        let fd = {
            let sessions = self.inner.sessions.lock().unwrap();
            sessions.get(exec_id).and_then(|s| s.tty_master_fd.clone())
        };
        if let Some(fd) = fd
            && let Err(e) = crate::pty::resize(fd.raw(), cols, rows)
        {
            tracing::debug!(exec_id, ?e, "pty resize failed");
        }
    }

    fn forward_stdin(&self, exec_id: &str, b64_data: &str, ws_tx: &mpsc::UnboundedSender<String>) {
        let bytes = match B64.decode(b64_data) {
            Ok(b) => b,
            Err(e) => {
                emit(
                    ws_tx,
                    OutgoingMessage::ExecError {
                        exec_id: exec_id.to_string(),
                        message: format!("invalid base64 on stdin: {e}"),
                    },
                );
                return;
            }
        };
        let stdin_tx = {
            let sessions = self.inner.sessions.lock().unwrap();
            sessions.get(exec_id).map(|s| s.stdin_tx.clone())
        };
        if let Some(tx) = stdin_tx {
            // Drop on full → applies backpressure to whoever is generating
            // typing faster than the child can drain. With STDIN_QUEUE=32
            // and a real terminal this never trips; for non-interactive
            // bulk stdin the producer should pace itself.
            if let Err(e) = tx.try_send(StdinFrame::Bytes(bytes)) {
                tracing::debug!(exec_id, ?e, "stdin queue full, dropping bytes");
            }
        }
    }

    async fn signal_stdin_eof(&self, exec_id: &str) {
        let stdin_tx = {
            let sessions = self.inner.sessions.lock().unwrap();
            sessions.get(exec_id).map(|s| s.stdin_tx.clone())
        };
        if let Some(tx) = stdin_tx {
            // Queue EOF behind any pending stdin so the child sees them
            // before EOF. `send().await` instead of `try_send` because
            // `ExecStdinEof` is a one-shot edge — dropping it would
            // permanently leave the child waiting on stdin.
            let _ = tx.send(StdinFrame::Eof).await;
        }
    }

    fn cancel(&self, exec_id: &str, signal: i32) {
        // Capture the pid and flip the cancelled flag atomically while
        // holding the sessions lock so two concurrent cancels can't
        // both reach killpg.
        let pid = {
            let sessions = self.inner.sessions.lock().unwrap();
            let Some(session) = sessions.get(exec_id) else {
                return;
            };
            let mut cancelled = session.cancelled.lock().unwrap();
            if *cancelled {
                return;
            }
            *cancelled = true;
            session.pid
        };
        // killpg, not kill: every spawned exec is its own process-group
        // leader (pgid == pid; see child_spawner::build_command and
        // pty::spawn_pty which both create a new group). Signalling the
        // group catches descendants like `sleep` under `sh -c "sleep 60"`,
        // which `kill(pid, ...)` would strand. ESRCH is harmless and
        // expected (child already gone).
        if pid > 0 {
            unsafe { libc::killpg(pid as i32, signal) };
        }
    }

    /// Reattach the calling WS connection to an existing exec, enforcing
    /// owner-only takeover.
    ///
    /// Decision table:
    /// - exec not registered → `exec_error "no such exec"`.
    /// - owner is `None` (unscoped attach) → `exec_error "exec has no owner"`.
    /// - `actor.user_id` is missing or doesn't match `owner.user_id` →
    ///   `exec_error "owner mismatch"`. Admins included — admins kill
    ///   execs via `exec_cancel`, they don't silently take them over.
    /// - `force=false` and the forwarder still has a live dest →
    ///   `exec_error "exec already attached"`. The same-user reattacher
    ///   must explicitly request the steal.
    /// - else → forwarder emits `exec_detached` to the prior dest (if any),
    ///   replays scrollback to `ws_tx`, manager emits `exec_attached`
    ///   carrying the original owner and pid. PTY size is applied if the
    ///   reattach payload supplied one.
    async fn reattach(
        &self,
        exec_id: String,
        actor: Option<ActorIdentity>,
        force: bool,
        initial_size: Option<TerminalSize>,
        ws_tx: &mpsc::UnboundedSender<String>,
    ) {
        let (fwd_tx, owner, pid, is_tty) = {
            let sessions = self.inner.sessions.lock().unwrap();
            match sessions.get(&exec_id) {
                None => {
                    emit(
                        ws_tx,
                        OutgoingMessage::ExecError {
                            exec_id,
                            message: "no such exec".into(),
                        },
                    );
                    return;
                }
                Some(s) => (
                    s.fwd_tx.clone(),
                    s.owner.clone(),
                    s.pid,
                    s.tty_master_fd.is_some(),
                ),
            }
        };

        if let Err(message) = check_reattach_owner(&owner, actor.as_ref()) {
            emit(
                ws_tx,
                OutgoingMessage::ExecError {
                    exec_id,
                    message: message.into(),
                },
            );
            return;
        }

        let (reply_tx, reply_rx) = oneshot::channel::<SwapOutcome>();
        if fwd_tx
            .send(ForwarderEvent::SwapDest {
                new_dest: ws_tx.clone(),
                reason: DetachReason::Stolen,
                force,
                reply: reply_tx,
            })
            .is_err()
        {
            // Forwarder is gone — child must have just exited.
            emit(
                ws_tx,
                OutgoingMessage::ExecError {
                    exec_id,
                    message: "exec ended before reattach could complete".into(),
                },
            );
            return;
        }

        match reply_rx.await {
            Ok(SwapOutcome::Swapped) => {
                emit(
                    ws_tx,
                    OutgoingMessage::ExecAttached {
                        exec_id: exec_id.clone(),
                        pid,
                        owner,
                    },
                );
                if is_tty && let Some(sz) = initial_size {
                    self.resize(&exec_id, sz.cols, sz.rows);
                }
            }
            Ok(SwapOutcome::DestBusyNeedsForce) => {
                emit(
                    ws_tx,
                    OutgoingMessage::ExecError {
                        exec_id,
                        message: "exec already attached; pass force=true to steal".into(),
                    },
                );
            }
            Err(_) => {
                emit(
                    ws_tx,
                    OutgoingMessage::ExecError {
                        exec_id,
                        message: "exec ended before reattach could complete".into(),
                    },
                );
            }
        }
    }
}

/// Owner-only reattach gate. Returns `Ok(())` when the caller is allowed,
/// otherwise the precise error message to surface as `exec_error.message`.
/// Matching requires both sides to carry a non-empty `user_id` and for them
/// to be equal — email is display-only and never participates in the auth
/// decision.
fn check_reattach_owner(
    owner: &Option<ActorIdentity>,
    actor: Option<&ActorIdentity>,
) -> Result<(), &'static str> {
    match (owner, actor) {
        (None, _) => Err("exec has no owner — cannot reattach"),
        (_, None) => Err("owner mismatch — cannot reattach to another user's exec"),
        (Some(o), Some(a)) => match (&o.user_id, &a.user_id) {
            (Some(ou), Some(au)) if ou == au => Ok(()),
            _ => Err("owner mismatch — cannot reattach to another user's exec"),
        },
    }
}

#[derive(Copy, Clone)]
enum Stream {
    Stdout,
    Stderr,
}

/// Events the forwarder consumes. Three producers:
/// - pipe readers send `Chunk` for every read.
/// - `run_controller` sends `Final` once when the child exits.
/// - the `exec_reattach` handler sends `SwapDest` to redirect output to
///   a new WS client and emit `exec_detached` to the old one.
enum ForwarderEvent {
    Chunk {
        stream: Stream,
        bytes: Vec<u8>,
    },
    /// Disconnect the current dest (if any) and attach a new one. The
    /// new dest receives a base64'd replay of the scrollback in order,
    /// then resumes live chunks. The old dest receives `exec_detached`
    /// best-effort — failure is not surfaced.
    ///
    /// `force=false` declines the swap when there is already a live dest
    /// — the forwarder replies `DestBusyNeedsForce` and leaves state
    /// unchanged so the manager can surface a "use force=true" error to
    /// the would-be reattacher. The reply oneshot makes the decision
    /// observable to the caller without sharing atomic state.
    SwapDest {
        new_dest: mpsc::UnboundedSender<String>,
        reason: DetachReason,
        force: bool,
        reply: oneshot::Sender<SwapOutcome>,
    },
    /// Exec terminated. Carries the exec_exit / exec_error frame the
    /// forwarder emits last; receipt also tells the forwarder to drop
    /// its rx and exit.
    Final(OutgoingMessage),
}

/// Result of a `SwapDest` event, returned to the requester via a oneshot
/// reply. The manager translates this into a wire response.
#[derive(Debug, PartialEq, Eq)]
enum SwapOutcome {
    /// Old dest detached (if any), new dest now attached + scrollback
    /// replayed.
    Swapped,
    /// `force=false` and a live dest is still present. Manager should
    /// reject with a "exec already attached; pass force=true" error.
    DestBusyNeedsForce,
}

/// Ring buffer of (stream, bytes) chunks. New chunks append at the back;
/// when total bytes exceed `SCROLLBACK_CAPACITY_BYTES`, oldest chunks
/// are evicted from the front. Raw decoded bytes are stored — base64
/// encoding happens at replay time so memory accounting is straightforward
/// and we don't pay the 4/3 overhead in steady state.
struct Scrollback {
    chunks: std::collections::VecDeque<(Stream, Vec<u8>)>,
    bytes: usize,
}

impl Scrollback {
    fn new() -> Self {
        Self {
            chunks: std::collections::VecDeque::new(),
            bytes: 0,
        }
    }

    fn push(&mut self, stream: Stream, data: &[u8]) {
        self.bytes += data.len();
        self.chunks.push_back((stream, data.to_vec()));
        while self.bytes > SCROLLBACK_CAPACITY_BYTES {
            match self.chunks.pop_front() {
                Some((_, popped)) => self.bytes -= popped.len(),
                None => break,
            }
        }
    }
}

fn encode_chunk(exec_id: &str, stream: Stream, bytes: &[u8]) -> String {
    let data = B64.encode(bytes);
    let msg = match stream {
        Stream::Stdout => OutgoingMessage::ExecStdout {
            exec_id: exec_id.to_string(),
            data,
        },
        Stream::Stderr => OutgoingMessage::ExecStderr {
            exec_id: exec_id.to_string(),
            data,
        },
    };
    serde_json::to_string(&msg).unwrap()
}

/// Spawn the per-exec forwarder task and return its inbound channel.
///
/// The forwarder is the only writer of stdout/stderr/exit/error frames
/// for an exec. It owns the current WS dest (an `Option` — `None`
/// between disconnect and reattach) and a scrollback ring buffer so a
/// reattaching client gets the recent output replayed.
///
/// Persistence: when the current dest's send fails (WS closed) we set
/// `dest = None` instead of returning. Pipe readers keep producing,
/// scrollback keeps rotating, the child keeps running. The forwarder
/// only exits on `Final`, which is the controller's signal that the
/// child has exited and `output_tasks` have been drained.
fn spawn_forwarder(
    exec_id: String,
    initial_dest: mpsc::UnboundedSender<String>,
) -> mpsc::UnboundedSender<ForwarderEvent> {
    let (tx, mut rx) = mpsc::unbounded_channel::<ForwarderEvent>();
    tokio::spawn(async move {
        let mut dest: Option<mpsc::UnboundedSender<String>> = Some(initial_dest);
        let mut scrollback = Scrollback::new();
        while let Some(ev) = rx.recv().await {
            match ev {
                ForwarderEvent::Chunk { stream, bytes } => {
                    scrollback.push(stream, &bytes);
                    if let Some(d) = &dest {
                        let msg = encode_chunk(&exec_id, stream, &bytes);
                        if d.send(msg).is_err() {
                            // Dest gone (WS closed). Drop the dest and keep
                            // buffering — the exec persists; a future
                            // SwapDest replays everything we held onto.
                            dest = None;
                        }
                    }
                }
                ForwarderEvent::SwapDest {
                    new_dest,
                    reason,
                    force,
                    reply,
                } => {
                    // Reject the swap if a live dest is already attached and
                    // the caller didn't pass force=true. The reattacher must
                    // explicitly opt in to displacing whoever is there.
                    if !force && dest.is_some() {
                        let _ = reply.send(SwapOutcome::DestBusyNeedsForce);
                        continue;
                    }
                    if let Some(old) = dest.take() {
                        let detached = OutgoingMessage::ExecDetached {
                            exec_id: exec_id.clone(),
                            reason,
                        };
                        let _ = old.send(serde_json::to_string(&detached).unwrap());
                    }
                    let mut new_dest_live = true;
                    for (stream, bytes) in &scrollback.chunks {
                        let msg = encode_chunk(&exec_id, *stream, bytes);
                        if new_dest.send(msg).is_err() {
                            new_dest_live = false;
                            break;
                        }
                    }
                    dest = if new_dest_live { Some(new_dest) } else { None };
                    let _ = reply.send(SwapOutcome::Swapped);
                }
                ForwarderEvent::Final(msg) => {
                    // Send fire-and-forget — `exec_exit` for a client that's
                    // already gone is a no-op (matches the old `emit` path).
                    if let Some(d) = &dest {
                        let _ = d.send(serde_json::to_string(&msg).unwrap());
                    }
                    return;
                }
            }
        }
    });
    tx
}

fn spawn_pipe_reader<R>(
    mut reader: R,
    which: Stream,
    fwd_tx: mpsc::UnboundedSender<ForwarderEvent>,
) -> tokio::task::JoinHandle<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buf = vec![0u8; READ_CHUNK];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if fwd_tx
                        .send(ForwarderEvent::Chunk {
                            stream: which,
                            bytes: buf[..n].to_vec(),
                        })
                        .is_err()
                    {
                        // Forwarder gone (WS closed). Same effect as the
                        // pre-forwarder code where a failed ws_tx send
                        // broke the read loop.
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    })
}

fn spawn_stdin_writer<W>(mut sink: W, mut stdin_rx: mpsc::Receiver<StdinFrame>)
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        while let Some(frame) = stdin_rx.recv().await {
            match frame {
                StdinFrame::Bytes(bytes) => {
                    if sink.write_all(&bytes).await.is_err() {
                        return;
                    }
                    let _ = sink.flush().await;
                }
                StdinFrame::Eof => return,
            }
        }
        // Channel closed without explicit EOF (manager dropped). Falling
        // through here drops `sink` and the child sees EOF anyway.
    });
}

async fn run_controller(
    mut child: Child,
    exec_id: String,
    output_tasks: Vec<tokio::task::JoinHandle<()>>,
    fwd_tx: mpsc::UnboundedSender<ForwarderEvent>,
    registry: std::sync::Arc<Inner>,
) {
    let status = child.wait().await;

    // Drain output BEFORE emitting exit — the protocol contract says
    // exec_exit is the last frame for the exec_id, and clients trust it
    // as the stdout/stderr drain marker. Awaiting the readers guarantees
    // their last `Chunk` events have been enqueued on the forwarder, so
    // the `Final` we send next sits behind them in the queue.
    for t in output_tasks {
        let _ = t.await;
    }

    let exit = match status {
        Ok(st) => OutgoingMessage::ExecExit {
            exec_id: exec_id.clone(),
            code: st.code(),
            signal: signal_from_status(&st),
        },
        Err(e) => OutgoingMessage::ExecError {
            exec_id: exec_id.clone(),
            message: format!("wait failed: {e}"),
        },
    };
    let _ = fwd_tx.send(ForwarderEvent::Final(exit));

    registry.sessions.lock().unwrap().remove(&exec_id);
}

#[cfg(unix)]
fn signal_from_status(st: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    st.signal()
}

#[cfg(not(unix))]
fn signal_from_status(_: &std::process::ExitStatus) -> Option<i32> {
    None
}

fn emit(ws_tx: &mpsc::UnboundedSender<String>, msg: OutgoingMessage) {
    let _ = ws_tx.send(serde_json::to_string(&msg).unwrap());
}

#[cfg(test)]
mod tests {
    // Every test in this module spawns at least one child process and
    // awaits its exit via `tokio::process::Child::wait()`, which is
    // driven by a process-global SIGCHLD pipe. Under `cargo test`'s
    // default parallelism each test would otherwise run in its own
    // `current_thread` runtime: the SIGCHLD driver shares the only
    // worker with the test's compute, so a busy host can starve the
    // signal-pipe read long after the child has actually exited and
    // we time out in `drain_until_terminal` waiting for `exec_exit`.
    // `multi_thread` with 2 workers gives the signal driver its own
    // poll slot. Worker overhead is negligible per-test.
    use super::*;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    fn manager() -> ExecManager {
        ExecManager::new(None, false)
    }

    fn channel() -> (
        mpsc::UnboundedSender<String>,
        mpsc::UnboundedReceiver<String>,
    ) {
        mpsc::unbounded_channel()
    }

    /// Drain frames for `exec_id` until exec_exit or exec_error arrives.
    /// Returns the terminal frame value plus every prior frame for that id.
    async fn drain_until_terminal(
        rx: &mut mpsc::UnboundedReceiver<String>,
        exec_id: &str,
    ) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        loop {
            let text = timeout(Duration::from_secs(10), rx.recv())
                .await
                .expect("manager produced a terminal frame within 10s")
                .expect("ws channel still open");
            let v: serde_json::Value = serde_json::from_str(&text).unwrap();
            if v["execId"] != exec_id {
                continue;
            }
            let ty = v["type"].as_str().unwrap_or("").to_string();
            out.push(v);
            if ty == "exec_exit" || ty == "exec_error" {
                return out;
            }
        }
    }

    fn b64_of(s: &str) -> String {
        B64.encode(s.as_bytes())
    }

    fn decode_data(v: &serde_json::Value) -> Vec<u8> {
        B64.decode(v["data"].as_str().unwrap()).unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn attach_emits_attached_then_stdout_then_exit() {
        let mgr = manager();
        let (tx, mut rx) = channel();

        mgr.handle(
            IncomingMessage::ExecAttach {
                exec_id: "e1".into(),
                argv: vec!["sh".into(), "-c".into(), "printf hello".into()],
                env: HashMap::new(),
                cwd: None,
                tty: false,
                stdin: true,
                stdout: true,
                stderr: true,
                initial_size: None,
                actor: None,
            },
            &tx,
        )
        .await;

        let frames = drain_until_terminal(&mut rx, "e1").await;
        let types: Vec<_> = frames.iter().map(|f| f["type"].as_str().unwrap()).collect();
        assert_eq!(types.first(), Some(&"exec_attached"));
        assert_eq!(types.last(), Some(&"exec_exit"));

        let stdout_chunks: Vec<u8> = frames
            .iter()
            .filter(|f| f["type"] == "exec_stdout")
            .flat_map(decode_data)
            .collect();
        assert_eq!(String::from_utf8(stdout_chunks).unwrap(), "hello");

        let exit = frames.last().unwrap();
        assert_eq!(exit["code"], 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stdin_then_stdin_eof_routes_to_child() {
        // `cat` echoes stdin to stdout, then exits on EOF.
        let mgr = manager();
        let (tx, mut rx) = channel();

        mgr.handle(
            IncomingMessage::ExecAttach {
                exec_id: "e2".into(),
                argv: vec!["cat".into()],
                env: HashMap::new(),
                cwd: None,
                tty: false,
                stdin: true,
                stdout: true,
                stderr: true,
                initial_size: None,
                actor: None,
            },
            &tx,
        )
        .await;

        // Wait for exec_attached so the spawn race is gone.
        let attached = timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let attached_v: serde_json::Value = serde_json::from_str(&attached).unwrap();
        assert_eq!(attached_v["type"], "exec_attached");

        mgr.handle(
            IncomingMessage::ExecStdin {
                exec_id: "e2".into(),
                data: b64_of("ping\n"),
            },
            &tx,
        )
        .await;
        mgr.handle(
            IncomingMessage::ExecStdinEof {
                exec_id: "e2".into(),
            },
            &tx,
        )
        .await;

        let frames = drain_until_terminal(&mut rx, "e2").await;
        let stdout_bytes: Vec<u8> = frames
            .iter()
            .filter(|f| f["type"] == "exec_stdout")
            .flat_map(decode_data)
            .collect();
        assert_eq!(String::from_utf8(stdout_bytes).unwrap(), "ping\n");
        assert_eq!(frames.last().unwrap()["code"], 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_kills_running_child() {
        let mgr = manager();
        let (tx, mut rx) = channel();

        mgr.handle(
            IncomingMessage::ExecAttach {
                exec_id: "e3".into(),
                argv: vec!["sleep".into(), "30".into()],
                env: HashMap::new(),
                cwd: None,
                tty: false,
                stdin: true,
                stdout: true,
                stderr: true,
                initial_size: None,
                actor: None,
            },
            &tx,
        )
        .await;

        // Read past attached.
        let _ = timeout(Duration::from_secs(5), rx.recv()).await.unwrap();

        mgr.handle(
            IncomingMessage::ExecCancel {
                exec_id: "e3".into(),
                signal: Some(libc::SIGTERM),
            },
            &tx,
        )
        .await;

        let frames = drain_until_terminal(&mut rx, "e3").await;
        let exit = frames.last().unwrap();
        assert_eq!(exit["type"], "exec_exit");
        // Killed by SIGTERM → code is absent (None), signal=15.
        assert_eq!(exit["signal"], libc::SIGTERM);
        assert!(
            exit.get("code").is_none(),
            "exit code must be absent when killed by signal"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_kills_entire_process_group_not_just_immediate_child() {
        // `sh -c "sleep 60 & echo $!; wait $!"` spawns a sleeping grandchild,
        // prints its pid, then waits on it. Without process-group kill,
        // SIGTERM to the shell pid would reap the shell but reparent `sleep`
        // to PID 1, leaving the grandchild running. We assert the grandchild
        // is gone after exec_cancel — proves the kill router targeted the
        // pgroup, not just the immediate child.
        let mgr = manager();
        let (tx, mut rx) = channel();

        mgr.handle(
            IncomingMessage::ExecAttach {
                exec_id: "pg1".into(),
                argv: vec![
                    "sh".into(),
                    "-c".into(),
                    "sleep 60 & echo $!; wait $!".into(),
                ],
                env: HashMap::new(),
                cwd: None,
                tty: false,
                stdin: false,
                stdout: true,
                stderr: false,
                initial_size: None,
                actor: None,
            },
            &tx,
        )
        .await;

        // Read frames until stdout carries the grandchild's pid.
        let mut grandchild_pid: Option<i32> = None;
        for _ in 0..50 {
            let frame = timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("frame within 5s")
                .expect("ws still open");
            let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
            if v["type"] == "exec_stdout" {
                let bytes = decode_data(&v);
                let s = String::from_utf8_lossy(&bytes);
                if let Some(line) = s.trim().lines().next()
                    && let Ok(pid) = line.parse::<i32>()
                {
                    grandchild_pid = Some(pid);
                    break;
                }
            }
        }
        let grandchild_pid = grandchild_pid.expect("grandchild pid printed within 50 frames");

        mgr.handle(
            IncomingMessage::ExecCancel {
                exec_id: "pg1".into(),
                signal: Some(libc::SIGTERM),
            },
            &tx,
        )
        .await;

        let _ = drain_until_terminal(&mut rx, "pg1").await;

        // After sh exits, `sleep` is reparented to PID 1 and remains a
        // zombie until reaped — kill(pid, 0) returns 0 on a zombie. Poll
        // briefly so the test isn't a race against PID 1's reap.
        let mut probe = 0;
        for _ in 0..40 {
            probe = unsafe { libc::kill(grandchild_pid, 0) };
            if probe == -1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            probe, -1,
            "grandchild pid={grandchild_pid} must be gone after group cancel"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_unknown_exec_id_is_noop() {
        let mgr = manager();
        let (tx, mut rx) = channel();

        mgr.handle(
            IncomingMessage::ExecCancel {
                exec_id: "never-attached".into(),
                signal: None,
            },
            &tx,
        )
        .await;

        // Manager should not emit anything.
        assert!(
            timeout(Duration::from_millis(50), rx.recv()).await.is_err(),
            "no frame must be emitted for unknown exec_id"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spawn_failure_emits_exec_error_not_exit() {
        let mgr = manager();
        let (tx, mut rx) = channel();

        mgr.handle(
            IncomingMessage::ExecAttach {
                exec_id: "e4".into(),
                argv: vec!["/no/such/binary".into()],
                env: HashMap::new(),
                cwd: None,
                tty: false,
                stdin: true,
                stdout: true,
                stderr: true,
                initial_size: None,
                actor: None,
            },
            &tx,
        )
        .await;

        let frame = timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(v["type"], "exec_error");
        assert_eq!(v["execId"], "e4");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tty_attach_streams_pty_output_and_exits() {
        // PTY mode merges stdout+stderr through the master fd. We assert
        // `exec_stdout` is the only output channel and that the bytes round-trip.
        let mgr = manager();
        let (tx, mut rx) = channel();

        mgr.handle(
            IncomingMessage::ExecAttach {
                exec_id: "tty1".into(),
                argv: vec!["sh".into(), "-c".into(), "printf hello".into()],
                env: HashMap::new(),
                cwd: None,
                tty: true,
                stdin: true,
                stdout: true,
                stderr: true,
                initial_size: Some(TerminalSize { cols: 80, rows: 24 }),
                actor: None,
            },
            &tx,
        )
        .await;

        let frames = drain_until_terminal(&mut rx, "tty1").await;
        let types: Vec<_> = frames.iter().map(|f| f["type"].as_str().unwrap()).collect();
        assert_eq!(types.first(), Some(&"exec_attached"));
        assert_eq!(types.last(), Some(&"exec_exit"));
        assert!(
            !types.contains(&"exec_stderr"),
            "PTY mode must not emit exec_stderr — got {types:?}"
        );

        let stdout: Vec<u8> = frames
            .iter()
            .filter(|f| f["type"] == "exec_stdout")
            .flat_map(decode_data)
            .collect();
        let text = String::from_utf8(stdout).unwrap();
        // PTYs may inject CR or shell artifacts on some platforms; assert
        // containment rather than equality.
        assert!(
            text.contains("hello"),
            "expected PTY output to contain 'hello', got {text:?}"
        );
        assert_eq!(frames.last().unwrap()["code"], 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tty_resize_does_not_error() {
        let mgr = manager();
        let (tx, mut rx) = channel();

        mgr.handle(
            IncomingMessage::ExecAttach {
                exec_id: "tty2".into(),
                argv: vec!["cat".into()],
                env: HashMap::new(),
                cwd: None,
                tty: true,
                stdin: true,
                stdout: true,
                stderr: true,
                initial_size: Some(TerminalSize { cols: 80, rows: 24 }),
                actor: None,
            },
            &tx,
        )
        .await;
        // Wait past exec_attached so the PTY is up.
        let _ = timeout(Duration::from_secs(5), rx.recv()).await.unwrap();

        mgr.handle(
            IncomingMessage::ExecResize {
                exec_id: "tty2".into(),
                cols: 200,
                rows: 60,
            },
            &tx,
        )
        .await;
        // Kill so the test exits.
        mgr.handle(
            IncomingMessage::ExecCancel {
                exec_id: "tty2".into(),
                signal: Some(libc::SIGKILL),
            },
            &tx,
        )
        .await;

        let frames = drain_until_terminal(&mut rx, "tty2").await;
        assert!(
            !frames.iter().any(|f| f["type"] == "exec_error"),
            "resize must not produce exec_error — got {frames:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resize_on_piped_session_is_silent_noop() {
        // Resize on a non-PTY session should not emit anything; the child
        // continues to run unaffected.
        let mgr = manager();
        let (tx, mut rx) = channel();

        mgr.handle(
            IncomingMessage::ExecAttach {
                exec_id: "pip1".into(),
                argv: vec!["cat".into()],
                env: HashMap::new(),
                cwd: None,
                tty: false,
                stdin: true,
                stdout: true,
                stderr: true,
                initial_size: None,
                actor: None,
            },
            &tx,
        )
        .await;
        let _ = timeout(Duration::from_secs(5), rx.recv()).await.unwrap();

        mgr.handle(
            IncomingMessage::ExecResize {
                exec_id: "pip1".into(),
                cols: 200,
                rows: 60,
            },
            &tx,
        )
        .await;
        // Resize on piped must not produce a frame.
        let no_frame = timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(no_frame.is_err(), "resize on piped session must not emit");

        // Cleanly exit cat.
        mgr.handle(
            IncomingMessage::ExecStdinEof {
                exec_id: "pip1".into(),
            },
            &tx,
        )
        .await;
        let frames = drain_until_terminal(&mut rx, "pip1").await;
        assert_eq!(frames.last().unwrap()["type"], "exec_exit");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn duplicate_exec_id_returns_error() {
        let mgr = manager();
        let (tx, mut rx) = channel();

        // First attach: a long-running child so the registry slot stays held.
        mgr.handle(
            IncomingMessage::ExecAttach {
                exec_id: "dup".into(),
                argv: vec!["sleep".into(), "30".into()],
                env: HashMap::new(),
                cwd: None,
                tty: false,
                stdin: true,
                stdout: true,
                stderr: true,
                initial_size: None,
                actor: None,
            },
            &tx,
        )
        .await;
        // Drain exec_attached.
        let _ = timeout(Duration::from_secs(5), rx.recv()).await.unwrap();

        // Second attach with the same id.
        mgr.handle(
            IncomingMessage::ExecAttach {
                exec_id: "dup".into(),
                argv: vec!["true".into()],
                env: HashMap::new(),
                cwd: None,
                tty: false,
                stdin: true,
                stdout: true,
                stderr: true,
                initial_size: None,
                actor: None,
            },
            &tx,
        )
        .await;

        let frame = timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(v["type"], "exec_error");
        let msg = v["message"].as_str().unwrap();
        assert!(msg.contains("already in use"));

        // Clean up the long-running child so test exits promptly.
        mgr.handle(
            IncomingMessage::ExecCancel {
                exec_id: "dup".into(),
                signal: Some(libc::SIGKILL),
            },
            &tx,
        )
        .await;
        let _ = drain_until_terminal(&mut rx, "dup").await;
    }

    // --- Reattach handler --------------------------------------------------

    fn actor(user_id: &str) -> ActorIdentity {
        ActorIdentity {
            user_id: Some(user_id.into()),
            email: None,
        }
    }

    /// Attach a long-running exec with the given actor; returns (rx, exec_id)
    /// after exec_attached has been drained off rx.
    async fn attach_with_actor(
        mgr: &ExecManager,
        exec_id: &str,
        actor: Option<ActorIdentity>,
    ) -> (
        mpsc::UnboundedSender<String>,
        mpsc::UnboundedReceiver<String>,
    ) {
        let (tx, mut rx) = channel();
        mgr.handle(
            IncomingMessage::ExecAttach {
                exec_id: exec_id.into(),
                argv: vec!["sleep".into(), "30".into()],
                env: HashMap::new(),
                cwd: None,
                tty: false,
                stdin: true,
                stdout: true,
                stderr: true,
                initial_size: None,
                actor,
            },
            &tx,
        )
        .await;
        let frame = timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("attached in 5s")
            .expect("rx open");
        let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(v["type"], "exec_attached");
        (tx, rx)
    }

    async fn cleanup(mgr: &ExecManager, exec_id: &str, tx: &mpsc::UnboundedSender<String>) {
        mgr.handle(
            IncomingMessage::ExecCancel {
                exec_id: exec_id.into(),
                signal: Some(libc::SIGKILL),
            },
            tx,
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reattach_to_unknown_exec_returns_error() {
        let mgr = manager();
        let (tx, mut rx) = channel();
        mgr.handle(
            IncomingMessage::ExecReattach {
                exec_id: "ghost".into(),
                force: false,
                initial_size: None,
                actor: Some(actor("user-1")),
            },
            &tx,
        )
        .await;
        let frame = timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(v["type"], "exec_error");
        let msg = v["message"].as_str().unwrap();
        assert!(msg.contains("no such exec"), "got: {msg}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reattach_with_matching_owner_swaps_dest_and_replays() {
        let mgr = manager();
        let (_tx1, mut rx1) = attach_with_actor(&mgr, "r1", Some(actor("user-1"))).await;
        // Reattach via a new ws_tx.
        let (tx2, mut rx2) = channel();
        mgr.handle(
            IncomingMessage::ExecReattach {
                exec_id: "r1".into(),
                force: true,
                initial_size: None,
                actor: Some(actor("user-1")),
            },
            &tx2,
        )
        .await;

        // Old dest sees exec_detached.
        let detached = timeout(Duration::from_secs(2), rx1.recv())
            .await
            .expect("detached in 2s")
            .expect("rx1 open");
        let v: serde_json::Value = serde_json::from_str(&detached).unwrap();
        assert_eq!(v["type"], "exec_detached");
        assert_eq!(v["reason"], "stolen");

        // New dest sees exec_attached carrying the original owner.
        let attached = timeout(Duration::from_secs(2), rx2.recv())
            .await
            .expect("attached in 2s")
            .expect("rx2 open");
        let v: serde_json::Value = serde_json::from_str(&attached).unwrap();
        assert_eq!(v["type"], "exec_attached");
        assert_eq!(v["execId"], "r1");
        assert_eq!(v["owner"]["userId"], "user-1");

        cleanup(&mgr, "r1", &tx2).await;
        let _ = drain_until_terminal(&mut rx2, "r1").await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reattach_with_mismatched_owner_rejects() {
        let mgr = manager();
        let (tx1, _rx1) = attach_with_actor(&mgr, "r2", Some(actor("user-1"))).await;

        let (tx2, mut rx2) = channel();
        mgr.handle(
            IncomingMessage::ExecReattach {
                exec_id: "r2".into(),
                force: true,
                initial_size: None,
                actor: Some(actor("user-2")),
            },
            &tx2,
        )
        .await;

        let frame = timeout(Duration::from_secs(2), rx2.recv())
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(v["type"], "exec_error");
        let msg = v["message"].as_str().unwrap();
        assert!(
            msg.contains("owner mismatch"),
            "expected owner-mismatch error, got: {msg}"
        );

        cleanup(&mgr, "r2", &tx1).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reattach_without_actor_rejects() {
        // Same-named owner with `None` actor is still rejected — owner-only
        // semantics need an authenticated caller.
        let mgr = manager();
        let (tx1, _rx1) = attach_with_actor(&mgr, "r3", Some(actor("user-1"))).await;

        let (tx2, mut rx2) = channel();
        mgr.handle(
            IncomingMessage::ExecReattach {
                exec_id: "r3".into(),
                force: true,
                initial_size: None,
                actor: None,
            },
            &tx2,
        )
        .await;

        let frame = timeout(Duration::from_secs(2), rx2.recv())
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(v["type"], "exec_error");

        cleanup(&mgr, "r3", &tx1).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reattach_to_unscoped_exec_rejects() {
        // attach with actor=None → owner=None → not reattachable even with
        // a valid actor on the reattach side.
        let mgr = manager();
        let (tx1, _rx1) = attach_with_actor(&mgr, "r4", None).await;

        let (tx2, mut rx2) = channel();
        mgr.handle(
            IncomingMessage::ExecReattach {
                exec_id: "r4".into(),
                force: true,
                initial_size: None,
                actor: Some(actor("user-1")),
            },
            &tx2,
        )
        .await;

        let frame = timeout(Duration::from_secs(2), rx2.recv())
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(v["type"], "exec_error");
        let msg = v["message"].as_str().unwrap();
        assert!(msg.contains("no owner"), "got: {msg}");

        cleanup(&mgr, "r4", &tx1).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reattach_without_force_to_busy_session_rejects() {
        let mgr = manager();
        let (tx1, _rx1) = attach_with_actor(&mgr, "r5", Some(actor("user-1"))).await;

        let (tx2, mut rx2) = channel();
        mgr.handle(
            IncomingMessage::ExecReattach {
                exec_id: "r5".into(),
                force: false,
                initial_size: None,
                actor: Some(actor("user-1")),
            },
            &tx2,
        )
        .await;

        let frame = timeout(Duration::from_secs(2), rx2.recv())
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(v["type"], "exec_error");
        let msg = v["message"].as_str().unwrap();
        assert!(
            msg.contains("already attached") && msg.contains("force=true"),
            "got: {msg}"
        );

        cleanup(&mgr, "r5", &tx1).await;
    }

    // --- Forwarder unit tests ---------------------------------------------
    //
    // These exercise `spawn_forwarder` directly (bypassing the manager)
    // so we can drive `SwapDest` and dest loss in isolation.

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forwarder_replays_scrollback_to_new_dest_and_detaches_old() {
        let (dest1_tx, mut dest1_rx) = mpsc::unbounded_channel::<String>();
        let fwd = spawn_forwarder("e1".into(), dest1_tx);

        fwd.send(ForwarderEvent::Chunk {
            stream: Stream::Stdout,
            bytes: b"first".to_vec(),
        })
        .unwrap();

        // Drain the live frame so we know the chunk landed in scrollback
        // (the forwarder pushed to scrollback before attempting the send).
        let live = timeout(Duration::from_secs(2), dest1_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&live).unwrap();
        assert_eq!(v["type"], "exec_stdout");

        let (dest2_tx, mut dest2_rx) = mpsc::unbounded_channel::<String>();
        let (reply_tx, reply_rx) = oneshot::channel::<SwapOutcome>();
        fwd.send(ForwarderEvent::SwapDest {
            new_dest: dest2_tx,
            reason: DetachReason::Stolen,
            force: true,
            reply: reply_tx,
        })
        .unwrap();
        assert_eq!(reply_rx.await.unwrap(), SwapOutcome::Swapped);

        // Old dest sees exec_detached.
        let detached = timeout(Duration::from_secs(2), dest1_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&detached).unwrap();
        assert_eq!(v["type"], "exec_detached");
        assert_eq!(v["reason"], "stolen");
        assert_eq!(v["execId"], "e1");

        // New dest sees the replayed chunk.
        let replay = timeout(Duration::from_secs(2), dest2_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&replay).unwrap();
        assert_eq!(v["type"], "exec_stdout");
        let bytes = B64.decode(v["data"].as_str().unwrap()).unwrap();
        assert_eq!(bytes, b"first");

        // Live chunks after swap route to the new dest.
        fwd.send(ForwarderEvent::Chunk {
            stream: Stream::Stdout,
            bytes: b"second".to_vec(),
        })
        .unwrap();
        let live2 = timeout(Duration::from_secs(2), dest2_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&live2).unwrap();
        let bytes = B64.decode(v["data"].as_str().unwrap()).unwrap();
        assert_eq!(bytes, b"second");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forwarder_persists_past_dest_loss_and_replays_on_reattach() {
        // Regression: today dest loss tore the forwarder down. With
        // persistent exec the forwarder must keep buffering so a later
        // SwapDest can replay everything to a reattaching client.
        let (dest1_tx, dest1_rx) = mpsc::unbounded_channel::<String>();
        let fwd = spawn_forwarder("e2".into(), dest1_tx);

        // Drop the rx before we send anything — every send to dest fails.
        drop(dest1_rx);

        for i in 0..5 {
            fwd.send(ForwarderEvent::Chunk {
                stream: Stream::Stdout,
                bytes: format!("chunk-{i}").into_bytes(),
            })
            .unwrap();
        }

        let (dest2_tx, mut dest2_rx) = mpsc::unbounded_channel::<String>();
        let (reply_tx, reply_rx) = oneshot::channel::<SwapOutcome>();
        fwd.send(ForwarderEvent::SwapDest {
            new_dest: dest2_tx,
            reason: DetachReason::Stolen,
            force: true,
            reply: reply_tx,
        })
        .unwrap();
        assert_eq!(reply_rx.await.unwrap(), SwapOutcome::Swapped);

        let mut decoded = Vec::new();
        for _ in 0..5 {
            let frame = timeout(Duration::from_secs(2), dest2_rx.recv())
                .await
                .unwrap()
                .unwrap();
            let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
            let bytes = B64.decode(v["data"].as_str().unwrap()).unwrap();
            decoded.push(String::from_utf8(bytes).unwrap());
        }
        assert_eq!(
            decoded,
            vec!["chunk-0", "chunk-1", "chunk-2", "chunk-3", "chunk-4"]
        );
    }

    #[test]
    fn scrollback_evicts_oldest_chunks_when_over_capacity() {
        // Push 100 KiB in 1 KiB chunks. With a 64 KiB cap the buffer must
        // hold no more than the most recent ~64 KiB worth.
        let mut sb = Scrollback::new();
        let chunk = vec![0u8; 1024];
        for _ in 0..100 {
            sb.push(Stream::Stdout, &chunk);
        }
        assert!(
            sb.bytes <= SCROLLBACK_CAPACITY_BYTES,
            "scrollback bytes {} must not exceed cap {}",
            sb.bytes,
            SCROLLBACK_CAPACITY_BYTES
        );
        assert!(
            sb.chunks.len() <= SCROLLBACK_CAPACITY_BYTES / 1024,
            "chunk count {} exceeded chunks-fitting-in-cap",
            sb.chunks.len()
        );
    }
}
