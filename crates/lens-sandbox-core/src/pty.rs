use std::collections::HashMap;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

use nix::libc;

use crate::ca_env::apply_ca_env;
use crate::privilege::SandboxCredentials;

/// Owns a raw file descriptor and closes it on drop.
pub struct OwnedRawFd(RawFd);

impl OwnedRawFd {
    pub fn raw(&self) -> RawFd {
        self.0
    }
}

impl Drop for OwnedRawFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe { libc::close(self.0) };
        }
    }
}

pub struct PtyProcess {
    pub child: tokio::process::Child,
    /// Master fd for resize ioctl. Closed on drop.
    pub master_fd: OwnedRawFd,
    pub reader: tokio::fs::File,
    pub writer: tokio::fs::File,
    pub pid: u32,
}

pub fn spawn_pty(
    command: &str,
    args: &[String],
    cwd: Option<&str>,
    env: Option<&HashMap<String, String>>,
    creds: Option<&SandboxCredentials>,
    is_root: bool,
    initial_size: Option<(u16, u16)>,
) -> Result<PtyProcess, String> {
    let pty = nix::pty::openpty(None, None).map_err(|e| format!("openpty: {e}"))?;

    let master_raw = pty.master.as_raw_fd();
    let slave_raw = pty.slave.as_raw_fd();

    // Set initial terminal size on slave
    if let Some((cols, rows)) = initial_size {
        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let ret = unsafe { libc::ioctl(slave_raw, libc::TIOCSWINSZ as _, &ws) };
        if ret < 0 {
            tracing::warn!(
                "failed to set initial terminal size: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    let mut cmd = tokio::process::Command::new(command);
    cmd.args(args);
    cmd.kill_on_drop(true);

    // Stdio::null — we redirect to the PTY slave in pre_exec
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());

    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }

    // Env setup — clear parent env to avoid leaking LENS_SANDBOX_* etc.
    cmd.env_clear();
    if let Some(e) = env {
        cmd.envs(e);
    }
    apply_ca_env(&mut cmd);

    // pre_exec: set up PTY as controlling terminal + privilege drop
    // Same rule as the piped path, from the same function: root reaches the
    // capability drop rather than a `setuid(0)` that would keep CAP_NET_ADMIN.
    let privilege = crate::privilege::privilege_drop_for(creds, is_root);
    let creds_info = match privilege {
        crate::privilege::PrivilegeDrop::Setuid(creds) => Some(creds.uid_gid()),
        _ => None,
    };
    // `Some(gid)` means drop capabilities; the inner option is the group to
    // adopt first, which is `None` when the caller resolved no identity.
    // Matching rather than comparing, so the gid reaches the child here too
    // — an equality test would silently drop it on this path alone.
    let drop_capabilities = match privilege {
        crate::privilege::PrivilegeDrop::Capabilities { gid } => Some(gid),
        _ => None,
    };
    unsafe {
        cmd.pre_exec(move || {
            // New session so this process becomes session leader
            nix::unistd::setsid().map_err(|e| std::io::Error::other(format!("setsid: {e}")))?;

            // Set the slave as the controlling terminal
            if libc::ioctl(slave_raw, libc::TIOCSCTTY as _, 0i32) < 0 {
                return Err(std::io::Error::last_os_error());
            }

            // Redirect stdio to the slave PTY
            for &target_fd in &[libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
                if libc::dup2(slave_raw, target_fd) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }

            // Close original slave fd if it's not one of the stdio fds
            if slave_raw > libc::STDERR_FILENO {
                libc::close(slave_raw);
            }
            // Close master in child — only the parent needs it
            libc::close(master_raw);

            // Privilege drop + post-exec hardening. Mirrors the piped path
            // (build_agent_command -> creds.apply / apply_cap_drop) so a PTY
            // agent (e.g. Claude Code with TERM=xterm-256color) can't keep
            // CAP_NET_ADMIN or skip NO_NEW_PRIVS / pdeathsig.
            if let Some((uid, gid)) = creds_info {
                #[cfg(target_os = "linux")]
                nix::unistd::setgroups(&[])
                    .map_err(|e| std::io::Error::other(format!("setgroups: {e}")))?;
                nix::unistd::setgid(gid)
                    .map_err(|e| std::io::Error::other(format!("setgid: {e}")))?;
                nix::unistd::setuid(uid)
                    .map_err(|e| std::io::Error::other(format!("setuid: {e}")))?;
                crate::privilege::lock_down_after_setuid()?;
                crate::privilege::set_pdeathsig_sigterm()?;
            } else if let Some(gid) = drop_capabilities {
                // No UID drop — drop caps so the agent can't rewrite iptables
                // or set SO_MARK to bypass the proxy redirect. The gid, if the
                // caller resolved one, decides what group owns the files this
                // child writes; it confines nothing.
                if let Some(gid) = gid {
                    nix::unistd::setgid(gid).map_err(|e| {
                        std::io::Error::other(format!("setgid {}: {e}", gid.as_raw()))
                    })?;
                }
                crate::privilege::drop_capabilities_in_child()?;
                crate::privilege::set_pdeathsig_sigterm()?;
            } else {
                // Unprivileged supervisor: no privilege to drop, and
                // NO_NEW_PRIVS would guard a cage this parent never built.
                // pdeathsig needs no capability, so the child still dies
                // with us. See `PrivilegeDrop::Nothing`.
                crate::privilege::set_pdeathsig_sigterm()?;
            }

            Ok(())
        });
    }

    let child = cmd.spawn().map_err(|e| format!("spawn: {e}"))?;
    let pid = child.id().ok_or("failed to get child PID")?;

    // Close slave in parent — only master is needed
    drop(pty.slave);

    // Create separate read/write handles via dup before consuming the master OwnedFd
    let read_fd = nix::unistd::dup(&pty.master).map_err(|e| format!("dup (read): {e}"))?;
    let write_fd = nix::unistd::dup(&pty.master).map_err(|e| format!("dup (write): {e}"))?;

    // Take ownership of the master fd for resize ioctl (prevent OwnedFd from closing it)
    let master_owned = pty.master.into_raw_fd();

    let reader = unsafe { tokio::fs::File::from_raw_fd(read_fd.into_raw_fd()) };
    let writer = unsafe { tokio::fs::File::from_raw_fd(write_fd.into_raw_fd()) };

    Ok(PtyProcess {
        child,
        master_fd: OwnedRawFd(master_owned),
        reader,
        writer,
        pid,
    })
}

pub fn resize(master_fd: RawFd, cols: u16, rows: u16) -> Result<(), String> {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let ret = unsafe { libc::ioctl(master_fd, libc::TIOCSWINSZ as _, &ws) };
    if ret < 0 {
        Err(format!("TIOCSWINSZ: {}", std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn spawn_pty_runs_command() {
        let mut proc = spawn_pty(
            "/bin/sh",
            &["-c".into(), "echo hello".into()],
            Some("/tmp"),
            None,
            None,
            false,
            Some((80, 24)),
        )
        .expect("spawn should succeed");

        let mut output = String::new();
        let mut buf = vec![0u8; 4096];
        loop {
            match proc.reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => output.push_str(&String::from_utf8_lossy(&buf[..n])),
                Err(e) if e.raw_os_error() == Some(libc::EIO) => break, // PTY EOF
                Err(e) => panic!("read error: {e}"),
            }
        }

        assert!(output.contains("hello"), "output was: {output:?}");

        let status = proc.child.wait().await.expect("wait");
        assert!(status.success());
    }

    #[tokio::test]
    async fn pty_echo() {
        let mut proc = spawn_pty("/bin/cat", &[], Some("/tmp"), None, None, false, None)
            .expect("spawn should succeed");

        proc.writer
            .write_all(b"test\n")
            .await
            .expect("write should succeed");
        proc.writer.flush().await.expect("flush");

        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            proc.reader.read(&mut buf),
        )
        .await
        .expect("should not timeout")
        .expect("read should succeed");

        let output = String::from_utf8_lossy(&buf[..n]);
        // PTY echo + cat: we should see "test" at least once
        assert!(output.contains("test"), "output was: {output:?}");
    }

    #[tokio::test]
    async fn resize_succeeds() {
        let proc = spawn_pty(
            "/bin/sleep",
            &["1".into()],
            Some("/tmp"),
            None,
            None,
            false,
            Some((80, 24)),
        )
        .expect("spawn should succeed");

        resize(proc.master_fd.raw(), 120, 40).expect("resize should succeed");
    }

    /// Smoke test for the unprivileged + no-creds branch — the path used by
    /// every PTY agent in standard CI. Pre-fix this branch happened to work
    /// because no hardening was attempted; we keep that assertion green so
    /// the cap-drop wiring doesn't accidentally start firing capset in this
    /// branch and break exec with EPERM.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn spawn_pty_succeeds_when_unprivileged_and_no_creds() {
        let mut proc = spawn_pty(
            "/bin/sh",
            &["-c".into(), "true".into()],
            Some("/tmp"),
            None,
            None,
            false,
            Some((80, 24)),
        )
        .expect("spawn should succeed");

        let status = proc.child.wait().await.expect("wait");
        assert!(status.success(), "exit: {status:?}");
    }

    /// Verifies the agent-as-root branch applies cap drop + NO_NEW_PRIVS so a
    /// PTY agent (e.g. Claude Code with TERM=xterm-256color) can't escape the
    /// netfilter cage. Capset requires `CAP_SETPCAP`, which standard CI does
    /// not have — the test no-ops in that environment.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn spawn_pty_drops_caps_when_root_no_creds() {
        if !nix::unistd::geteuid().is_root() {
            eprintln!("skipping: needs root for capset()");
            return;
        }
        let mut proc = spawn_pty(
            "/bin/sh",
            &["-c".into(), "grep NoNewPrivs /proc/self/status".into()],
            Some("/tmp"),
            None,
            None,
            true,
            Some((80, 24)),
        )
        .expect("spawn should succeed");

        let mut output = String::new();
        let mut buf = vec![0u8; 4096];
        loop {
            match proc.reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => output.push_str(&String::from_utf8_lossy(&buf[..n])),
                Err(e) if e.raw_os_error() == Some(libc::EIO) => break,
                Err(e) => panic!("read: {e}"),
            }
        }
        let status = proc.child.wait().await.expect("wait");
        assert!(status.success(), "exit: {status:?}");
        assert!(output.contains("NoNewPrivs:\t1"), "got: {output:?}");
    }

    /// The PTY sibling of `child_spawner`'s group assertion: the group a
    /// caller resolved reaches a root child here too. The two paths run
    /// different code — this one inlines its own `pre_exec` — so an
    /// equality test on the decision would have dropped the gid on this
    /// path alone and no assertion over there would have noticed.
    ///
    /// Ignored for the same reason as its sibling: under a non-root
    /// parent these credentials take the `Nothing` arm, which adopts no
    /// group, and the child reports the parent's own.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires root: an unprivileged parent takes the Nothing arm and adopts no group"]
    async fn spawn_pty_applies_a_resolved_group_to_a_root_child() {
        assert!(
            nix::unistd::geteuid().is_root(),
            "this test runs as root only. As anyone else the decision takes the Nothing arm and adopts no group at all"
        );
        let ours = nix::unistd::getgid().as_raw();
        let other = if ours == 1 { 2 } else { 1 };
        let creds = SandboxCredentials::resolve_by_uid(0, other)
            .expect("resolve_by_uid never fails on a host");
        let mut proc = spawn_pty(
            "/bin/sh",
            &["-c".into(), "id -g".into()],
            Some("/tmp"),
            None,
            Some(&creds),
            true,
            Some((80, 24)),
        )
        .expect("spawn should succeed");

        let mut output = String::new();
        let mut buf = vec![0u8; 4096];
        loop {
            match proc.reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => output.push_str(&String::from_utf8_lossy(&buf[..n])),
                Err(e) if e.raw_os_error() == Some(libc::EIO) => break,
                Err(e) => panic!("read: {e}"),
            }
        }
        proc.child.wait().await.expect("wait");

        let reported = output
            .lines()
            .map(str::trim)
            .rfind(|line| !line.is_empty())
            .unwrap_or_default();

        assert_eq!(
            reported,
            other.to_string(),
            "a PTY child resolved to root:{other} has to write group-{other}, exactly as the piped path does"
        );
    }
}
