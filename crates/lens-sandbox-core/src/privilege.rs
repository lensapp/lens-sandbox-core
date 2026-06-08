use std::collections::HashMap;
use std::io;
use std::path::Path;
use tokio::process::Command;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// All `LENS_SANDBOX_*` env vars are supervisor-internal and scrubbed
/// before the child process inherits the environment.
const INTERNAL_VAR_PREFIX: &str = "LENS_SANDBOX_";

/// Harden the supervisor against ptrace attaches from child processes.
///
/// Setting `PR_SET_DUMPABLE = 0` clears the process's "dumpable" attribute,
/// so a child (the agent) running in the same user namespace can no longer
/// `ptrace(PTRACE_ATTACH)` and read out the `LENS_SANDBOX_TOKEN`, policy
/// memory, or the proxy's credential injection map.
#[cfg(target_os = "linux")]
pub fn harden_supervisor() -> io::Result<()> {
    nix::sys::prctl::set_dumpable(false).map_err(io::Error::from)
}

#[cfg(not(target_os = "linux"))]
pub fn harden_supervisor() -> io::Result<()> {
    Ok(())
}

/// Capabilities kept in the child's permitted+effective sets. Picked to
/// let third-party image entrypoints do their normal root prelude
/// (chown shared volumes, then `setuid` to a service account via
/// gosu / su-exec / direct syscall) while removing every capability
/// that would let the agent break out of the netfilter cage or
/// otherwise escalate.
///
/// Identity-management caps (kept): `CHOWN`, `DAC_OVERRIDE`,
/// `FOWNER`, `FSETID`, `KILL`, `SETGID`, `SETUID`.
///
/// `SETPCAP` is intentionally excluded — the entrypoint's chown+setuid
/// prelude has no need to manipulate the bounding set, and
/// `NO_NEW_PRIVS` already prevents bounding-set promotion across exec.
///
/// Notable caps dropped: `NET_ADMIN` (iptables/SO_MARK — the cage),
/// `NET_RAW`, `SYS_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`, `SYS_RAWIO`,
/// `SYS_BOOT`, `MAC_*`, `AUDIT_*`, `SETFCAP`, `LINUX_IMMUTABLE`,
/// `NET_BIND_SERVICE`, everything else.
///
/// After a typical entrypoint `setuid(non-root)` the kernel auto-zeros
/// permitted/effective, so the final agent process inherits no caps
/// regardless of what's kept here.
#[cfg(target_os = "linux")]
const KEEP_CAP_MASK: u64 = (1u64 << 0)  // CAP_CHOWN
    | (1u64 << 1)  // CAP_DAC_OVERRIDE
    | (1u64 << 3)  // CAP_FOWNER
    | (1u64 << 4)  // CAP_FSETID
    | (1u64 << 5)  // CAP_KILL
    | (1u64 << 6)  // CAP_SETGID
    | (1u64 << 7); // CAP_SETUID

/// The root group, kept as the dropped workload's sole supplementary group.
#[cfg(target_os = "linux")]
pub(crate) const ROOT_GID: u32 = 0;

/// Reduce the child's capability set to `KEEP_CAP_MASK` and pin
/// `NO_NEW_PRIVS` so the upcoming `execve` cannot re-acquire dropped
/// caps via file caps or a setuid bit. Designed for `Command::pre_exec`
/// in the no-setuid path, where the child still has the supervisor's
/// caps.
///
/// Three syscalls cover the threat model:
///   - `PR_SET_NO_NEW_PRIVS = 1` — closes the `execve` re-acquisition path
///     (file caps, setuid binaries).
///   - `PR_CAP_AMBIENT_CLEAR_ALL` — ambient caps survive `execve` even
///     under NO_NEW_PRIVS for non-setuid binaries, so they must be
///     cleared explicitly.
///   - `capset` to `KEEP_CAP_MASK` — narrows permitted+effective to the
///     identity-management subset. Inheritable is zeroed; with
///     NO_NEW_PRIVS pinned, nothing can promote caps across exec via
///     the inheritable+bounding path either.
///
/// Bounding-set drop is intentionally omitted: with NO_NEW_PRIVS
/// pinned and inheritable=0, nothing can promote bounding caps into
/// permitted across an exec.
///
/// Returns an `io::Error` so `pre_exec` aborts the exec — failing closed.
#[cfg(target_os = "linux")]
pub fn drop_capabilities_in_child() -> io::Result<()> {
    use nix::libc;

    nix::sys::prctl::set_no_new_privs().map_err(io::Error::from)?;

    let rc = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    // capset v3 header (version 0x20080522) + two u32-per-set datums
    // covering the 64-bit cap set.
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = CapHeader {
        version: 0x20080522,
        pid: 0,
    };
    let keep_lo = (KEEP_CAP_MASK & 0xFFFF_FFFF) as u32;
    let keep_hi = (KEEP_CAP_MASK >> 32) as u32;
    let data = [
        CapData {
            effective: keep_lo,
            permitted: keep_lo,
            inheritable: 0,
        },
        CapData {
            effective: keep_hi,
            permitted: keep_hi,
            inheritable: 0,
        },
    ];
    let rc = unsafe { libc::syscall(libc::SYS_capset, &header as *const _, data.as_ptr()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn drop_capabilities_in_child() -> io::Result<()> {
    Ok(())
}

/// Remove sandbox-internal env vars from an env map so they don't leak to
/// child processes (exec, spawn, claude_code).
pub fn scrub_internal_vars(env: &mut HashMap<String, String>) {
    env.retain(|k, _| !k.starts_with(INTERNAL_VAR_PREFIX));
}

/// Make the declared writable directory root owned by the sandbox user
/// before a child process drops privileges. Chowns the declared path only
/// — never walks existing data inside it.
pub fn prepare_writable_dir(path: &Path, creds: &SandboxCredentials) -> Result<(), String> {
    // symlink_metadata, not metadata: refuse to follow symlinks so the
    // chown target is always the literal declared path. The provisioner
    // emits the operator's volume.mountPath verbatim; if that ever
    // resolves to a symlink, we want a clear error here rather than
    // silently chown'ing whatever the symlink points at.
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            tracing::debug!(
                path = %path.display(),
                "declared writable sandbox directory is absent; skipping"
            );
            return Ok(());
        }
        Err(e) => return Err(format!("stat {}: {e}", path.display())),
    };

    if metadata.file_type().is_symlink() {
        return Err(format!(
            "{} is a symlink; resolve to its target before declaring it as a writable mount",
            path.display()
        ));
    }
    if !metadata.file_type().is_dir() {
        return Err(format!("{} is not a directory", path.display()));
    }

    let (uid, gid) = creds.uid_gid();
    if metadata.uid() == uid.as_raw() && metadata.gid() == gid.as_raw() {
        tracing::debug!(
            path = %path.display(),
            uid = uid.as_raw(),
            gid = gid.as_raw(),
            "declared writable sandbox directory already has target ownership"
        );
        return Ok(());
    }

    nix::unistd::chown(path, Some(uid), Some(gid)).map_err(|e| {
        format!(
            "chown {} to {}:{}: {e}",
            path.display(),
            uid.as_raw(),
            gid.as_raw()
        )
    })?;
    tracing::info!(
        path = %path.display(),
        uid = uid.as_raw(),
        gid = gid.as_raw(),
        "prepared writable sandbox directory"
    );
    Ok(())
}

/// Resolved sandbox uid/gid/home, cached at startup.
#[derive(Debug, Clone)]
pub struct SandboxCredentials {
    uid: nix::unistd::Uid,
    gid: nix::unistd::Gid,
    username: String,
    home_dir: String,
}

impl SandboxCredentials {
    /// Look up `username` in passwd/group.
    ///
    /// Returns `Ok(Some(creds))` when both the user and the matching group
    /// exist, `Ok(None)` when the user is absent from the image, and
    /// `Err` only for unexpected NSS errors.
    pub fn resolve(username: &str) -> Result<Option<Self>, String> {
        let group = match nix::unistd::Group::from_name(username)
            .map_err(|e| format!("group lookup: {e}"))?
        {
            Some(g) => g,
            None => return Ok(None),
        };
        let user = match nix::unistd::User::from_name(username)
            .map_err(|e| format!("user lookup: {e}"))?
        {
            Some(u) => u,
            None => return Ok(None),
        };
        Ok(Some(Self {
            uid: user.uid,
            gid: group.gid,
            username: username.to_string(),
            home_dir: user.dir.to_string_lossy().into_owned(),
        }))
    }

    /// Build credentials from a raw uid/gid pair, looking up the
    /// matching passwd entry on a best-effort basis for `username` and
    /// `home_dir`. The lookup is best-effort because images may carry
    /// a numeric `USER` directive (e.g. `USER 1000`) with no matching
    /// `/etc/passwd` line — the supervisor must still be able to
    /// setuid; only the cosmetic fields are missing.
    pub fn resolve_by_uid(uid: u32, gid: u32) -> Result<Self, String> {
        let nix_uid = nix::unistd::Uid::from_raw(uid);
        let entry = nix::unistd::User::from_uid(nix_uid)
            .map_err(|e| format!("user lookup by uid {uid}: {e}"))?;
        let (username, home_dir) = match entry {
            Some(u) => (u.name, u.dir.to_string_lossy().into_owned()),
            None => (uid.to_string(), "/".to_string()),
        };
        Ok(Self {
            uid: nix_uid,
            gid: nix::unistd::Gid::from_raw(gid),
            username,
            home_dir,
        })
    }

    /// The sandbox user's home directory (from passwd).
    pub fn home(&self) -> &str {
        &self.home_dir
    }

    /// The sandbox username.
    pub fn user(&self) -> &str {
        &self.username
    }

    /// Raw uid/gid for chown operations.
    pub fn uid_gid(&self) -> (nix::unistd::Uid, nix::unistd::Gid) {
        (self.uid, self.gid)
    }

    pub fn apply(&self, cmd: &mut Command) {
        let uid = self.uid;
        let gid = self.gid;
        unsafe {
            cmd.pre_exec(move || {
                // Drop the supervisor's supplementary groups but keep the root
                // group (gid 0): images built for the "run as an arbitrary
                // non-root uid" model (bitnami, OpenShift) own their writable
                // dirs `root:0` with group-write and expect the process to be a
                // member of the root group rather than a specific uid.
                #[cfg(target_os = "linux")]
                nix::unistd::setgroups(&[nix::unistd::Gid::from_raw(ROOT_GID)])
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                nix::unistd::setgid(gid).map_err(|e| std::io::Error::other(e.to_string()))?;
                nix::unistd::setuid(uid).map_err(|e| std::io::Error::other(e.to_string()))?;
                // setuid(non-root) already zeroed effective/permitted/inheritable
                // and the ambient set; bounding-set drop now requires
                // CAP_SETPCAP we no longer have. Pinning NO_NEW_PRIVS is
                // enough to keep file-cap binaries from re-acquiring caps
                // across the upcoming exec.
                lock_down_after_setuid()?;
                // Make the agent die if we die.
                set_pdeathsig_sigterm()?;
                Ok(())
            });
        }
    }
}

/// Post-setuid hardening: pin `NO_NEW_PRIVS` so subsequent `execve` cannot
/// re-acquire caps via file capabilities or a setuid bit. Safe to call
/// after a UID drop — it requires no capabilities. The kernel has already
/// emptied permitted/effective/inheritable/ambient as a side effect of
/// `setuid(non-root)`, so this is the only remaining knob.
#[cfg(target_os = "linux")]
pub fn lock_down_after_setuid() -> io::Result<()> {
    nix::sys::prctl::set_no_new_privs().map_err(io::Error::from)
}

#[cfg(not(target_os = "linux"))]
pub fn lock_down_after_setuid() -> io::Result<()> {
    Ok(())
}

/// Attach `drop_capabilities_in_child` to a `Command` without changing the
/// child's UID/GID. Use this for agent commands that run as root (the
/// supervisor's UID) because the image had no `sandbox` user. The child
/// keeps `KEEP_CAP_MASK` (identity-management caps so third-party
/// entrypoints can `chown` shared volumes and `setuid` to a service
/// account); everything else — notably `CAP_NET_ADMIN` and `CAP_NET_RAW`
/// — is dropped, so the agent cannot set `SO_MARK` to bypass the
/// netfilter cage or rewrite iptables rules.
pub fn apply_cap_drop(cmd: &mut Command) {
    unsafe {
        cmd.pre_exec(|| {
            drop_capabilities_in_child()?;
            // Make the agent die if we die — see set_pdeathsig_sigterm.
            set_pdeathsig_sigterm()?;
            Ok(())
        });
    }
}

/// Ask the kernel to deliver SIGTERM to this process when its parent
/// (the supervisor) exits. Belt-and-braces against supervisor crashes
/// that don't take the whole container down — without this, an
/// orphaned agent would survive its supervisor and run outside the
/// netfilter cage.
///
/// Survives the upcoming `execve` because [`drop_capabilities_in_child`]
/// and [`lock_down_after_setuid`] both pin `NO_NEW_PRIVS`, which
/// suppresses the only conditions under which the kernel clears
/// pdeathsig at exec (setuid / setgid / file-caps binaries).
#[cfg(target_os = "linux")]
pub fn set_pdeathsig_sigterm() -> io::Result<()> {
    use nix::libc;
    let rc = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_pdeathsig_sigterm() -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_nonexistent_user_returns_none() {
        // A missing sandbox user is the common case for third-party agent
        // images that don't ship one. The supervisor falls back to running
        // the agent as the image's default user (capabilities dropped) —
        // an Err here would force every user to maintain a fork of every
        // image just to add a `sandbox` line to passwd.
        let result = SandboxCredentials::resolve("nonexistent_user_xyz_99");
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn scrub_internal_vars_removes_all_internal_vars() {
        let mut env: HashMap<String, String> = [
            ("LENS_SANDBOX_TOKEN", "secret"),
            ("LENS_SANDBOX_WS_URL", "ws://localhost"),
            ("LENS_SANDBOX_POLICY_FILE", "/run/policy.json"),
            ("LENS_SANDBOX_POLICY", "base64data"),
            ("LENS_SANDBOX_INGRESS_PORT", "8080"),
            ("LENS_SANDBOX_WRITABLE_DIR", "/workspace"),
            ("LENS_MCP_URL", "https:/.lens/mcp"),
            ("HOME", "/home/sandbox"),
            ("PATH", "/usr/bin"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();

        scrub_internal_vars(&mut env);

        assert!(!env.contains_key("LENS_SANDBOX_TOKEN"));
        assert!(!env.contains_key("LENS_SANDBOX_WS_URL"));
        assert!(!env.contains_key("LENS_SANDBOX_POLICY_FILE"));
        assert!(!env.contains_key("LENS_SANDBOX_POLICY"));
        assert!(!env.contains_key("LENS_SANDBOX_INGRESS_PORT"));
        assert!(!env.contains_key("LENS_SANDBOX_WRITABLE_DIR"));
        assert_eq!(env.get("LENS_MCP_URL").unwrap(), "https:/.lens/mcp");
        assert_eq!(env.get("HOME").unwrap(), "/home/sandbox");
        assert_eq!(env.get("PATH").unwrap(), "/usr/bin");
    }

    fn current_user_creds() -> SandboxCredentials {
        SandboxCredentials::resolve_by_uid(
            nix::unistd::getuid().as_raw(),
            nix::unistd::getgid().as_raw(),
        )
        .unwrap()
    }

    #[test]
    fn prepare_writable_dir_skips_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");

        prepare_writable_dir(&missing, &current_user_creds()).unwrap();
    }

    #[test]
    fn prepare_writable_dir_errors_on_non_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, "content").unwrap();

        let err = prepare_writable_dir(&file, &current_user_creds()).unwrap_err();
        assert!(err.contains("is not a directory"));
    }

    #[test]
    fn prepare_writable_dir_noops_when_already_owned() {
        let dir = tempfile::tempdir().unwrap();

        prepare_writable_dir(dir.path(), &current_user_creds()).unwrap();
    }

    #[test]
    fn prepare_writable_dir_chowns_root() {
        if !nix::unistd::getuid().is_root() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let target = SandboxCredentials::resolve_by_uid(60001, 60001).unwrap();

        prepare_writable_dir(dir.path(), &target).unwrap();

        let root_meta = std::fs::symlink_metadata(dir.path()).unwrap();
        assert_eq!(root_meta.uid(), 60001);
        assert_eq!(root_meta.gid(), 60001);
    }

    #[test]
    fn prepare_writable_dir_does_not_touch_inner_files() {
        // Pins the non-recursion contract in non-root CI. A future refactor
        // that swaps `nix::unistd::chown(path, ...)` for a recursive walker
        // would advance the inner file's ctime even if the parent chown
        // fails with EPERM.
        let dir = tempfile::tempdir().unwrap();
        let inner = dir.path().join("inner");
        std::fs::write(&inner, b"preexisting").unwrap();
        let inner_ctime_before = std::fs::symlink_metadata(&inner).unwrap().ctime();

        // Mismatched creds defeat the same-owner fast-path so the chown
        // syscall actually fires. It returns EPERM in unprivileged CI; we
        // don't care about its outcome — we care that whatever it did, it
        // didn't recurse into the directory's children.
        let other = SandboxCredentials::resolve_by_uid(60001, 60001).unwrap();
        let _ = prepare_writable_dir(dir.path(), &other);

        let inner_ctime_after = std::fs::symlink_metadata(&inner).unwrap().ctime();
        assert_eq!(
            inner_ctime_after, inner_ctime_before,
            "inner file ctime moved — non-recursion guarantee broken",
        );
    }

    #[test]
    fn prepare_writable_dir_errors_on_symlink_to_directory() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real");
        std::fs::create_dir(&target).unwrap();
        let link = dir.path().join("link");
        symlink(&target, &link).unwrap();

        let err = prepare_writable_dir(&link, &current_user_creds()).unwrap_err();
        assert!(
            err.contains("symlink"),
            "error should name the symlink: {err}",
        );
    }

    /// Only runs inside Docker where the `sandbox` user exists.
    #[test]
    fn resolve_sandbox_user_in_container() {
        if nix::unistd::User::from_name("sandbox")
            .ok()
            .flatten()
            .is_none()
        {
            // Not in a container with a sandbox user — skip
            return;
        }
        let creds = SandboxCredentials::resolve("sandbox").unwrap().unwrap();
        let (uid, _gid) = creds.uid_gid();
        assert!(uid.as_raw() > 0);
    }

    #[test]
    fn resolve_by_uid_known_root_populates_passwd_fields() {
        // Root exists on every platform we run on, so this test is
        // host-agnostic. We don't assert on the home directory value
        // because Linux uses /root and macOS uses /var/root.
        let creds = SandboxCredentials::resolve_by_uid(0, 0).unwrap();
        let (uid, gid) = creds.uid_gid();
        assert_eq!(uid.as_raw(), 0);
        assert_eq!(gid.as_raw(), 0);
        assert_eq!(creds.user(), "root");
        assert!(!creds.home().is_empty());
    }

    #[test]
    fn resolve_by_uid_unknown_synthesizes_fields() {
        // The image's USER directive may be a numeric uid with no matching
        // passwd entry inside the image. The supervisor must still be able
        // to setuid to it — the missing username/home is a UX nicety, not
        // a hard requirement, so we synthesize sensible fallbacks.
        let creds = SandboxCredentials::resolve_by_uid(60001, 60001).unwrap();
        let (uid, gid) = creds.uid_gid();
        assert_eq!(uid.as_raw(), 60001);
        assert_eq!(gid.as_raw(), 60001);
        assert_eq!(creds.user(), "60001");
        assert_eq!(creds.home(), "/");
    }
}
