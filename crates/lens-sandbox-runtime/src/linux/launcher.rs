//! Forks every workload process from the one thread that holds the seccomp
//! notification filter, so each child inherits it, and confines the child
//! further before it runs.

use std::io;
use std::path::PathBuf;

use lens_sandbox_core::ca_env::apply_ca_env_at;
use lens_sandbox_core::child_spawner::Launcher;
use tokio::process::{Child, Command};

use crate::linux::workload_launcher::WorkloadLauncher;
use crate::linux::{child_seccomp, landlock};

pub struct RuntimeLauncher {
    launcher: WorkloadLauncher,
    runtime: tokio::runtime::Handle,
    ca_bundle: PathBuf,
}

impl RuntimeLauncher {
    /// `ca_bundle` is the trust bundle the runtime wrote, since it cannot
    /// write the system bundle. Takes the current tokio runtime, which the
    /// launcher thread enters to spawn.
    pub fn new(launcher: WorkloadLauncher, ca_bundle: PathBuf) -> Self {
        Self {
            launcher,
            runtime: tokio::runtime::Handle::current(),
            ca_bundle,
        }
    }
}

impl Launcher for RuntimeLauncher {
    fn spawn(&self, mut cmd: Command) -> io::Result<Child> {
        apply_ca_env_at(&mut cmd, &self.ca_bundle);
        // Built before the fork: the child may not allocate.
        let mut ruleset = Some(landlock::prepare_baseline()?);
        let mut hardening = child_seccomp::prepare(std::process::id())?;
        // SAFETY: the steps make only syscalls on memory prepared above.
        #[allow(unsafe_code)]
        unsafe {
            cmd.pre_exec(move || {
                ruleset
                    .take()
                    .ok_or_else(|| io::Error::other("Landlock ruleset already applied"))?
                    .restrict_self()
                    .map_err(io::Error::other)?;
                hardening.install()
            });
        }
        let runtime = self.runtime.clone();
        self.launcher.execute(move || {
            let _entered = runtime.enter();
            cmd.spawn()
        })?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lens_sandbox_core::exec_manager::ExecManager;
    use lens_sandbox_core::exec_protocol::IncomingMessage;
    use lens_sandbox_core::lifecycle::PidGuard;
    use std::collections::HashMap;
    use std::sync::Arc;

    async fn run(launcher: &RuntimeLauncher, script: &str) -> std::process::Output {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", script]);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        launcher
            .spawn(cmd)
            .unwrap()
            .wait_with_output()
            .await
            .unwrap()
    }

    fn runtime_launcher() -> RuntimeLauncher {
        let (launcher, _listener) = crate::linux::workload_launcher::start().unwrap();
        RuntimeLauncher::new(launcher, "/tmp/lens-sandbox/ca-bundle.pem".into())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_child_trusts_the_runtime_bundle() {
        let output = run(&runtime_launcher(), "printf %s \"$SSL_CERT_FILE\"").await;
        assert_eq!(output.stdout, b"/tmp/lens-sandbox/ca-bundle.pem");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_child_cannot_enter_a_new_user_namespace() {
        let mut direct = Command::new("unshare");
        direct.args(["-U", "true"]);
        if !direct.status().await.is_ok_and(|status| status.success()) {
            eprintln!("skipping: this host refuses unshare -U to every process");
            return;
        }
        let output = run(&runtime_launcher(), "unshare -U true").await;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success());
        assert!(stderr.contains("Operation not permitted"), "{stderr}");
    }

    fn seccomp_filters(status: &str) -> usize {
        status
            .lines()
            .find_map(|line| line.strip_prefix("Seccomp_filters:"))
            .and_then(|count| count.trim().parse().ok())
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_child_has_both_filters_and_no_new_privileges() {
        let own = seccomp_filters(&std::fs::read_to_string("/proc/self/status").unwrap());
        let output = run(&runtime_launcher(), "cat /proc/self/status").await;
        let status = String::from_utf8(output.stdout).unwrap();
        assert!(status.contains("NoNewPrivs:\t1"), "{status}");
        // The notification filter of the launcher thread, and the child's own.
        assert_eq!(seccomp_filters(&status), own + 2, "{status}");
    }

    /// The stdout of `script` in one exec session of the runtime launcher.
    async fn exec_stdout(is_root: bool, script: &str) -> Vec<u8> {
        let manager = ExecManager::with_launcher(
            None,
            is_root,
            PidGuard::default(),
            Arc::new(runtime_launcher()),
        );
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        manager
            .handle(
                IncomingMessage::ExecAttach {
                    exec_id: "e".into(),
                    argv: vec!["sh".into(), "-c".into(), script.into()],
                    env: HashMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
                    cwd: None,
                    tty: false,
                    stdin: false,
                    stdout: true,
                    stderr: true,
                    initial_size: None,
                    actor: None,
                },
                &tx,
            )
            .await;
        let mut stdout = Vec::new();
        while let Some(frame) = rx.recv().await {
            let frame: serde_json::Value = serde_json::from_str(&frame).unwrap();
            match frame["type"].as_str() {
                Some("exec_stdout") => {
                    use base64::Engine as _;
                    stdout.extend(
                        base64::engine::general_purpose::STANDARD
                            .decode(frame["data"].as_str().unwrap())
                            .unwrap(),
                    );
                }
                Some("exec_exit" | "exec_error") => break,
                _ => {}
            }
        }
        stdout
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_exec_session_runs_through_the_runtime_launcher() {
        let stdout = exec_stdout(false, "printf %s \"$SSL_CERT_FILE\"").await;
        assert_eq!(stdout, b"/tmp/lens-sandbox/ca-bundle.pem");
    }

    fn status_field<'a>(status: &'a str, field: &str) -> &'a str {
        status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .unwrap()
            .trim()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_root_exec_keeps_only_the_level_b_capabilities() {
        // CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, SETGID, SETUID.
        const LEVEL_B: u64 = 0xfb;
        if !rustix::process::geteuid().is_root() {
            eprintln!("skipping: needs uid 0");
            return;
        }
        let own = std::fs::read_to_string("/proc/self/status").unwrap();
        let permitted = u64::from_str_radix(status_field(&own, "CapPrm:"), 16).unwrap();
        let stdout = exec_stdout(true, "cat /proc/self/status").await;
        let status = String::from_utf8(stdout).unwrap();
        let effective = u64::from_str_radix(status_field(&status, "CapEff:"), 16).unwrap();
        assert_eq!(effective, LEVEL_B & permitted, "{status}");
        assert_eq!(status_field(&status, "NoNewPrivs:"), "1", "{status}");
    }
}
