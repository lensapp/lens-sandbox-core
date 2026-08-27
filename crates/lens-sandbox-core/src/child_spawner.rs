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
        crate::privilege::PrivilegeDrop::Capabilities => crate::privilege::apply_cap_drop(cmd),
        // An unprivileged parent honours no identity. `privilege_drop_for`
        // has already warned with the one it ignored; a caller that cannot
        // accept the substitute reads `requested` for itself before it
        // builds a spec.
        crate::privilege::PrivilegeDrop::Nothing { .. } => {}
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

    /// The gid is the observable half of the bug: `creds.apply` would
    /// `setgid` before its no-op `setuid(0)`, whereas the capability path
    /// leaves the gid alone. A child that reports the *other* gid is a
    /// child that took `apply`, and so also skipped the capability drop.
    #[tokio::test]
    async fn root_credentials_do_not_reach_the_setuid_path() {
        let ours = nix::unistd::getgid().as_raw();
        let other = if ours == 1 { 2 } else { 1 };
        let creds = SandboxCredentials::resolve_by_uid(0, other)
            .expect("resolve_by_uid never fails on a host");
        let spec = ChildSpec {
            argv: vec!["sh".into(), "-c".into(), "id -g".into()],
            cwd: None,
            env: HashMap::new(),
            creds: Some(creds),
            is_root: nix::unistd::geteuid().is_root(),
        };

        let out = build_command(&spec)
            .output()
            .await
            .expect("command should run");
        let reported = String::from_utf8_lossy(&out.stdout).trim().to_string();

        assert_eq!(
            reported,
            ours.to_string(),
            "root credentials must take the capability path, which does not setgid; a child reporting {other} took `apply` and kept CAP_NET_ADMIN with it"
        );
    }

    /// The control for the assertion above: a non-root identity *does*
    /// reach `apply`, so the gid a child reports genuinely tells the two
    /// paths apart rather than always being the caller's own.
    #[tokio::test]
    async fn non_root_credentials_still_reach_the_setuid_path() {
        if !nix::unistd::geteuid().is_root() {
            eprintln!("skipping: only root may setuid to another identity");
            return;
        }
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
