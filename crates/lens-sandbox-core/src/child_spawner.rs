//! Hardened child-process spawning inside the sandbox cage.
//!
//! Single point of policy for everything the supervisor forks: the agent
//! today, exec children next. Captures the security contract — env_clear
//! then envs(); CA env wins over user env; a non-root identity takes the
//! uid drop, while root credentials and bare root both take the capability
//! drop — so callers can't accidentally let a child out of the cage.
//!
//! Env layering above this layer (proxy env, scrubbing internal vars,
//! HOME/USER from creds, project env vs caller env) is each caller's
//! concern. This module takes the *final* env and hands it to the kernel.

use std::collections::HashMap;

use crate::ca_env::apply_ca_env;
use crate::privilege::SandboxCredentials;
use tokio::process::Command;

/// Everything needed to fork one hardened child inside the cage.
///
/// Owned by value so a spec can be built once and handed across async
/// boundaries (the exec path will move specs into per-session tasks).
pub struct ChildSpec {
    /// argv[0] is the executable; rest are args. Use `["sh", "-c", cmd]`
    /// to run a shell string.
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    /// Final env handed to the child. Caller is responsible for layering
    /// (proxy env, scrubbing, etc.) before calling. CA env vars in here
    /// are clobbered by `apply_ca_env`.
    pub env: HashMap<String, String>,
    pub creds: Option<SandboxCredentials>,
    pub is_root: bool,
}

/// Build a piped-stdio `Command` with full sandbox hardening.
///
/// The returned `Command` is not yet spawned; the caller wires stdio and
/// calls `.spawn()` themselves. Useful for tests (inspect env / argv) and
/// for the agent's piped-output path.
///
/// The child is `kill_on_drop`: dropping its handle sends `SIGKILL` to
/// it. A caller that wants a child to outlive the handle has to keep the
/// handle. Nothing inside the cage may run unwatched, which is why this
/// is not the caller's knob.
pub fn build_command(spec: &ChildSpec) -> Command {
    assert!(!spec.argv.is_empty(), "ChildSpec::argv must not be empty");
    let mut cmd = Command::new(&spec.argv[0]);
    cmd.args(&spec.argv[1..]);
    if let Some(cwd) = &spec.cwd {
        cmd.current_dir(cwd);
    }
    cmd.env_clear();
    cmd.envs(&spec.env);

    // CA env applied last so the sandbox CA bundle overrides any user-supplied
    // SSL_CERT_FILE / NODE_EXTRA_CA_CERTS / REQUESTS_CA_BUNDLE / … in spec.env.
    apply_ca_env(&mut cmd);

    // New process group with pgid == child's pid. Lets the exec manager's
    // kill router signal the whole group via killpg, so a wrapper like
    // `sh -c "sleep 999"` doesn't strand its descendants when cancelled.
    // The PTY path does its own setsid() (which also creates a new pgrp)
    // — this only applies to the piped path.
    cmd.process_group(0);

    // A dropped future must not abandon a running child inside the cage.
    // Without this a caller that bounds a child with `tokio::time::timeout`
    // gets its timeout back and the child keeps running, unwatched. The PTY
    // path has always set it; this path was the outlier.
    //
    // It signals the immediate child only. A shell's own children survive
    // in the (now orphaned) process group, which is what `process_group(0)`
    // above makes killable: a caller that needs the whole group down uses
    // `killpg`, as `exec_manager::cancel` does.
    cmd.kill_on_drop(true);

    apply_privilege_drop(&mut cmd, spec);

    cmd
}

/// Spawn a hardened child attached to a PTY. The caller owns the master fd;
/// the child sees its slave as stdio.
pub fn spawn_pty(
    spec: &ChildSpec,
    initial_size: (u16, u16),
) -> Result<crate::pty::PtyProcess, String> {
    assert!(!spec.argv.is_empty(), "ChildSpec::argv must not be empty");
    crate::pty::spawn_pty(
        &spec.argv[0],
        &spec.argv[1..],
        spec.cwd.as_deref(),
        Some(&spec.env),
        spec.creds.as_ref(),
        spec.is_root,
        Some(initial_size),
    )
}

fn apply_privilege_drop(cmd: &mut Command, spec: &ChildSpec) {
    // `privilege_drop_for` owns the rule, including that root credentials
    // take the capability path — `setuid(0)` would leave the child holding
    // CAP_NET_ADMIN and able to escape the netfilter cage.
    match crate::privilege::privilege_drop_for(spec.creds.as_ref(), spec.is_root) {
        crate::privilege::PrivilegeDrop::Setuid(creds) => creds.apply(cmd),
        crate::privilege::PrivilegeDrop::Capabilities { gid } => {
            crate::privilege::apply_cap_drop(cmd, gid)
        }
        // An unprivileged parent honours no identity. `privilege_drop_for`
        // has already warned with the one it ignored; a caller that cannot
        // accept the substitute reads `requested` for itself before it
        // builds a spec.
        //
        // There is no privilege to drop, but pdeathsig needs none and the
        // orphan it prevents is real: a script outliving a crashed
        // supervisor keeps working on a guest nobody watches.
        // `NO_NEW_PRIVS` is deliberately absent — see `PrivilegeDrop`.
        crate::privilege::PrivilegeDrop::Nothing { .. } => unsafe {
            cmd.pre_exec(crate::privilege::set_pdeathsig_sigterm);
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca_env::CA_BUNDLE;

    fn spec_for(argv: Vec<String>, env: HashMap<String, String>, is_root: bool) -> ChildSpec {
        ChildSpec {
            argv,
            cwd: None,
            env,
            creds: None,
            is_root,
        }
    }

    fn envs_of(cmd: &Command) -> HashMap<String, String> {
        cmd.as_std()
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_str()?.to_string(), v?.to_str()?.to_string())))
            .collect()
    }

    #[test]
    fn build_command_clears_parent_env_and_sets_caller_env() {
        let argv = vec!["sh".into(), "-c".into(), "true".into()];
        let mut env = HashMap::new();
        env.insert("FOO".into(), "bar".into());

        let cmd = build_command(&spec_for(argv, env, false));
        let envs = envs_of(&cmd);

        assert_eq!(envs.get("FOO").map(String::as_str), Some("bar"));
        // env_clear means PATH from the test runner does not leak.
        assert!(
            !envs.contains_key("CARGO_PKG_NAME"),
            "parent env must be cleared"
        );
    }

    #[test]
    fn build_command_ca_env_overrides_caller_env() {
        let argv = vec!["sh".into(), "-c".into(), "true".into()];
        let mut env = HashMap::new();
        env.insert("SSL_CERT_FILE".into(), "/tmp/evil.pem".into());
        env.insert("NODE_EXTRA_CA_CERTS".into(), "/tmp/evil.pem".into());

        let cmd = build_command(&spec_for(argv, env, false));
        let envs = envs_of(&cmd);

        assert_eq!(
            envs.get("SSL_CERT_FILE").map(String::as_str),
            Some(CA_BUNDLE)
        );
        assert_eq!(
            envs.get("NODE_EXTRA_CA_CERTS").map(String::as_str),
            Some(CA_BUNDLE)
        );
    }

    #[tokio::test]
    async fn build_command_spawns_child_as_new_process_group_leader() {
        // exec_cancel sends a signal to the child PID. If the child is `sh -c
        // "sleep 999"`, signaling sh leaves sleep running. We force every
        // spawned child to be a new process group leader (pgid == pid) so the
        // exec_manager's kill router can target the whole group via killpg.
        let argv = vec!["sleep".into(), "30".into()];
        let env = HashMap::new();

        let mut cmd = build_command(&spec_for(argv, env, false));
        let mut child = cmd.spawn().expect("sleep should spawn");
        let pid = child.id().expect("child must have a pid") as i32;

        // SAFETY: pid is a child we just spawned and haven't waited on.
        let pgid = unsafe { libc::getpgid(pid) };
        let _ = child.kill().await;

        assert_eq!(
            pgid, pid,
            "child pid={pid} should be its own pgrp leader, got pgid={pgid}"
        );
    }

    #[tokio::test]
    async fn build_command_runs_with_unprivileged_supervisor_and_no_creds() {
        // Regression: when the supervisor isn't root and no creds resolved we
        // must NOT call capset() (that EPERMs in unprivileged CI). Spawning
        // a trivial command exercises the pre_exec chain.
        let argv = vec!["sh".into(), "-c".into(), "exit 0".into()];
        let env = HashMap::new();

        let mut cmd = build_command(&spec_for(argv, env, false));
        let status = cmd.status().await.expect("command should run");
        assert!(status.success(), "child must exit 0, got {status}");
    }

    /// Dropping a child's handle kills the child. Without this a caller
    /// that bounds a script with `tokio::time::timeout` gets its timeout
    /// back while the script runs on, unwatched, and the boot stays
    /// wedged.
    ///
    /// The retained stdout is the probe: it reaches EOF only once every
    /// writer is gone, so a `sleep 30` that survived the drop would hold
    /// the read open and the test would sit out its timeout instead.
    #[tokio::test]
    async fn dropping_a_childs_handle_kills_the_child() {
        let argv = vec!["sh".into(), "-c".into(), "sleep 30".into()];
        let mut cmd = build_command(&spec_for(argv, HashMap::new(), false));
        cmd.stdout(std::process::Stdio::piped());

        let mut child = cmd.spawn().expect("sh should spawn");
        let mut stdout = child.stdout.take().expect("stdout was piped");
        drop(child);

        let mut buf = Vec::new();
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::io::AsyncReadExt::read_to_end(&mut stdout, &mut buf),
        )
        .await;

        assert!(
            read.is_ok(),
            "the child outlived its handle: nothing inside the cage may run once the supervisor stops watching it"
        );
    }

    /// The `Nothing` arm hardens one thing and deliberately not another.
    /// It adds pdeathsig, which needs no capability. It leaves
    /// `NO_NEW_PRIVS` alone, because that flag exists to stop a child
    /// re-acquiring `CAP_NET_ADMIN` and leaving the netfilter cage — and
    /// an unprivileged parent never built a cage. Pinning it here would
    /// break the `sudo` a developer's own pre-start script may call.
    ///
    /// Compared against the parent rather than against `0`: a parent that
    /// already runs under `NO_NEW_PRIVS` passes it to every child, and
    /// this test is then vacuous rather than wrong. It still fails the
    /// moment somebody adds `set_no_new_privs` to this arm on a parent
    /// that does not have it.
    ///
    /// The pdeathsig half is not pinned here. Its observable is "the
    /// child dies when its parent dies", and the parent is the test
    /// binary; seeing it would need a re-exec'd helper that builds the
    /// child and then exits. That is a heavier seam than the claim earns.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn an_unprivileged_parent_adds_no_new_privs_to_its_child() {
        let ours = no_new_privs_of(
            &std::fs::read_to_string("/proc/self/status").expect("/proc/self/status reads"),
        );
        let argv = vec![
            "sh".into(),
            "-c".into(),
            "grep NoNewPrivs /proc/self/status".into(),
        ];

        let out = build_command(&spec_for(argv, HashMap::new(), false))
            .output()
            .await
            .expect("command should run");

        assert_eq!(
            no_new_privs_of(&String::from_utf8_lossy(&out.stdout)),
            ours,
            "this arm guards a cage its parent never built, so it must not pin NO_NEW_PRIVS and break a script that calls sudo"
        );
    }

    /// Parse the `NoNewPrivs:` line out of a `/proc/<pid>/status` dump.
    #[cfg(target_os = "linux")]
    fn no_new_privs_of(status: &str) -> String {
        status
            .lines()
            .find_map(|line| line.strip_prefix("NoNewPrivs:"))
            .expect("status names NoNewPrivs")
            .trim()
            .to_string()
    }

    /// `CAP_NET_ADMIN` is bit 12 of a capability set.
    #[cfg(target_os = "linux")]
    const CAP_NET_ADMIN_BIT: u32 = 12;

    /// The effective capability set this process holds, from `/proc`.
    #[cfg(target_os = "linux")]
    fn our_cap_eff() -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").expect("/proc/self/status reads");
        cap_eff_of(&status)
    }

    /// Parse the `CapEff:` line out of a `/proc/<pid>/status` dump.
    #[cfg(target_os = "linux")]
    fn cap_eff_of(status: &str) -> u64 {
        let hex = status
            .lines()
            .find_map(|line| line.strip_prefix("CapEff:"))
            .expect("status names CapEff")
            .trim();
        u64::from_str_radix(hex, 16).expect("CapEff is hex")
    }

    /// The property itself: a child resolved to uid 0 must not keep
    /// `CAP_NET_ADMIN`, or it can rewrite the netfilter cage and set
    /// `SO_MARK` to bypass the proxy redirect. `creds.apply` would
    /// `setuid(0)` — a no-op that keeps every capability — so a child
    /// still holding the bit is a child that took `apply`.
    ///
    /// Ignored by default, because it needs a parent that actually holds
    /// `CAP_NET_ADMIN`. Without it both paths yield a child without the
    /// bit and the assertion proves nothing. It asserts that rather than
    /// skipping: a check that reports green without running is worse than
    /// one that says it did not run. CI runs it in the `cage` job, which
    /// is privileged: `sudo -E env "PATH=$PATH" cargo test -p
    /// lens-sandbox-core --tests -- --ignored --test-threads=1`.
    ///
    /// The gid used to stand in for this, back when the capability path
    /// left the gid alone. It now applies the group the caller resolved,
    /// so the gid no longer tells the two paths apart and the real
    /// observable is the one that always meant something.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires a parent holding CAP_NET_ADMIN: without it both paths look alike"]
    async fn root_credentials_do_not_reach_the_setuid_path() {
        assert!(
            our_cap_eff() >> CAP_NET_ADMIN_BIT & 1 == 1,
            "this parent holds no CAP_NET_ADMIN. The child could not keep a capability we never had, so the assertion would pass without observing anything"
        );
        let creds =
            SandboxCredentials::resolve_by_uid(0, 0).expect("resolve_by_uid never fails on a host");
        let spec = ChildSpec {
            argv: vec![
                "sh".into(),
                "-c".into(),
                "grep CapEff /proc/self/status".into(),
            ],
            cwd: None,
            env: HashMap::new(),
            creds: Some(creds),
            is_root: true,
        };

        let out = build_command(&spec)
            .output()
            .await
            .expect("command should run");
        let child = cap_eff_of(&String::from_utf8_lossy(&out.stdout));

        assert_eq!(
            child >> CAP_NET_ADMIN_BIT & 1,
            0,
            "root credentials must reach the capability drop; a child keeping CAP_NET_ADMIN took `apply`, whose setuid(0) drops nothing. Child CapEff: {child:#x}"
        );
    }

    /// The group a caller resolved reaches the child even though the
    /// child stays root. It confines nothing — the child keeps
    /// `CAP_SETGID` — but it decides what group owns the files the child
    /// writes, which is what a step staged as `root:GROUP` asked for.
    ///
    /// Ignored for the same reason as its neighbours: under a non-root
    /// parent these credentials take the `Nothing` arm, where no group is
    /// adopted and the child would report the parent's own.
    #[tokio::test]
    #[ignore = "requires root: an unprivileged parent takes the Nothing arm and adopts no group"]
    async fn a_resolved_group_reaches_a_root_child() {
        assert!(
            nix::unistd::geteuid().is_root(),
            "this test runs as root only. As anyone else the decision takes the Nothing arm and adopts no group at all"
        );
        let ours = nix::unistd::getgid().as_raw();
        let other = if ours == 1 { 2 } else { 1 };
        let creds = SandboxCredentials::resolve_by_uid(0, other)
            .expect("resolve_by_uid never fails on a host");
        let spec = ChildSpec {
            argv: vec!["sh".into(), "-c".into(), "id -g".into()],
            cwd: None,
            env: HashMap::new(),
            creds: Some(creds),
            is_root: true,
        };

        let out = build_command(&spec)
            .output()
            .await
            .expect("command should run");

        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            other.to_string(),
            "a step staged as root:{other} to prepare a volume for a later non-root workload has to write group-{other}; discarding the group leaves that workload with EACCES and nothing naming the cause"
        );
    }

    /// The control for the assertion above: a non-root identity *does*
    /// reach `apply`, so the gid a child reports genuinely tells the two
    /// paths apart rather than always being the caller's own.
    ///
    /// Ignored by default, because only root may `setuid` to another
    /// identity and most dev boxes and much of CI are not root. It
    /// asserts that rather than returning early: a control that reports
    /// green without running is a skip wearing a pass. CI runs it in the
    /// `cage` job, which is root: `sudo -E env "PATH=$PATH" cargo test
    /// -p lens-sandbox-core --tests -- --ignored --test-threads=1`.
    #[tokio::test]
    #[ignore = "requires root: only root may setuid to another identity"]
    async fn non_root_credentials_still_reach_the_setuid_path() {
        assert!(
            nix::unistd::geteuid().is_root(),
            "this control runs as root only. As anyone else the setuid it exists to observe would EPERM"
        );
        let creds = SandboxCredentials::resolve_by_uid(65534, 65534)
            .expect("resolve_by_uid never fails on a host");
        let spec = ChildSpec {
            argv: vec!["sh".into(), "-c".into(), "id -g".into()],
            cwd: None,
            env: HashMap::new(),
            creds: Some(creds),
            is_root: true,
        };

        let out = build_command(&spec)
            .output()
            .await
            .expect("command should run");

        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "65534",
            "a non-root identity is what the uid drop is for, and the kernel zeroes the capability sets on the way"
        );
    }
}
