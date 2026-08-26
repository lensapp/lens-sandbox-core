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
/// Notable caps dropped: `NET_ADMIN` and `NET_RAW` (either one sets
/// `SO_MARK` and so spoofs its way out of the cage — see `sock_mark.rs`;
/// `NET_ADMIN` also rewrites the rules), `SYS_ADMIN`, `SYS_PTRACE`,
/// `SYS_MODULE`, `SYS_RAWIO`,
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

/// The name-to-id tables an identity resolves against.
///
/// A port rather than a direct NSS call, so every branch of
/// [`SandboxCredentials::resolve_user_spec`] is reachable in a test
/// without the host's own passwd deciding the outcome.
pub trait Passwd: Send + Sync {
    /// The uid a passwd entry gives this name, if it has one.
    fn uid_of(&self, name: &str) -> Option<u32>;
    /// The primary gid on this name's passwd line, if it has one.
    fn primary_gid_of(&self, name: &str) -> Option<u32>;
    /// The gid the group file gives this group name, if it has one.
    fn gid_of_group(&self, group: &str) -> Option<u32>;
}

/// The tables the system itself answers with, over NSS.
pub struct SystemPasswd;

impl Passwd for SystemPasswd {
    fn uid_of(&self, name: &str) -> Option<u32> {
        nix::unistd::User::from_name(name)
            .ok()
            .flatten()
            .map(|user| user.uid.as_raw())
    }

    fn primary_gid_of(&self, name: &str) -> Option<u32> {
        nix::unistd::User::from_name(name)
            .ok()
            .flatten()
            .map(|user| user.gid.as_raw())
    }

    fn gid_of_group(&self, group: &str) -> Option<u32> {
        nix::unistd::Group::from_name(group)
            .ok()
            .flatten()
            .map(|group| group.gid.as_raw())
    }
}

/// Split a `USER[:GROUP]` into its segments, refusing the shapes that
/// name no identity at all.
fn split_user_spec(spec: &str) -> Result<(&str, Option<&str>), String> {
    let mut parts = spec.split(':');
    let name = parts.next().unwrap_or_default();
    let group = parts.next();
    if parts.next().is_some() {
        return Err(format!(
            "invalid user {spec:?}: expected USER or USER:GROUP"
        ));
    }
    if name.is_empty() || group.is_some_and(str::is_empty) {
        return Err(format!("invalid user {spec:?}: no segment may be empty"));
    }
    Ok((name, group))
}

/// A segment read as a bare id, which is all an image's `USER`
/// directive can carry. `str::parse` would also take a signed `+0`, a
/// shape no table ever answered and no directive ever wrote.
fn as_id(segment: &str) -> Option<u32> {
    segment
        .bytes()
        .all(|byte| byte.is_ascii_digit())
        .then(|| segment.parse().ok())
        .flatten()
}

/// Resolved sandbox uid/gid/home, cached at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    ///
    /// Note the "matching group" requirement: this needs a group *named*
    /// like the user, and answers `Ok(None)` for any identity without one
    /// — including every numeric `USER`, and any user whose primary group
    /// is named differently. Use [`Self::resolve_user_spec`] to resolve an
    /// arbitrary `USER[:GROUP]` the way the kernel and the image mean it.
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

    /// Resolve a `USER[:GROUP]` string against the given name tables.
    ///
    /// The two segments resolve differently, because that is how the
    /// kernel and an image's `USER` directive mean them:
    ///
    /// - the **user** is looked up by name first, so a name gets whatever
    ///   uid this image gave it, and falls back to being parsed as a
    ///   number. This is how the workload's own identity resolves, and a
    ///   caller asking for a user by name has to land on the same one;
    /// - the **group** is parsed as a number first, so a group merely
    ///   *named* for a numeral cannot outrank the id itself.
    ///
    /// With no group segment the user's primary gid applies, and failing
    /// that the uid doubles as the gid. That last step is deliberately
    /// not what `docker run` does: runc gives such an identity gid 0, and
    /// handing a numeric identity the root group is not something a
    /// sandbox should do on its own.
    ///
    /// A name neither table can resolve is an error, never a fallback:
    /// falling back would run the child as an identity nobody named, and
    /// root is the likeliest thing it would fall back to.
    pub fn resolve_user_spec(spec: &str, passwd: &dyn Passwd) -> Result<Self, String> {
        let (name, group) = split_user_spec(spec)?;
        let uid = passwd
            .uid_of(name)
            .or_else(|| as_id(name))
            .ok_or_else(|| format!("no user {name:?} in passwd"))?;
        let gid = match group {
            Some(group) => as_id(group)
                .or_else(|| passwd.gid_of_group(group))
                .ok_or_else(|| format!("no group {group:?} in the group file"))?,
            None => passwd.primary_gid_of(name).unwrap_or(uid),
        };
        Self::resolve_by_uid(uid, gid)
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

    /// Attach the uid drop to a `Command`.
    ///
    /// Correct only for a non-root identity: the kernel zeroes the
    /// capability sets on a `setuid` to a non-zero uid, and this function
    /// relies on that instead of dropping capabilities itself. Do not call
    /// it directly on credentials that may resolve to uid 0 — go through
    /// [`privilege_drop_for`], which routes those to
    /// [`apply_cap_drop`], or the child keeps `CAP_NET_ADMIN`.
    pub fn apply(&self, cmd: &mut Command) {
        let uid = self.uid;
        let gid = self.gid;
        unsafe {
            cmd.pre_exec(move || {
                #[cfg(target_os = "linux")]
                nix::unistd::setgroups(&[]).map_err(|e| std::io::Error::other(e.to_string()))?;
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
/// child's UID/GID. This is the path for every child that stays root —
/// whether no `sandbox` user resolved in the image, or the caller resolved
/// one that *is* root (see [`privilege_drop_for`]). The child
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

/// Which privilege drop a child earns before `exec`.
///
/// Deciding this separately from applying it keeps the one rule that
/// matters — root reaches the capability drop — in a pure function every
/// spawn path consults, rather than in a condition each of them repeats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivilegeDrop<'a> {
    /// Become this identity. The kernel zeroes the capability sets on a
    /// `setuid` to a non-zero uid, so nothing else is needed.
    Setuid(&'a SandboxCredentials),
    /// Stay root and drop the capabilities by hand.
    Capabilities,
    /// An unprivileged parent has neither a uid to drop nor a capability
    /// to lose, and `capset` would `EPERM`. It also cannot honour an
    /// identity it was asked for, so a step naming `root` runs as the
    /// parent's own identity instead; the decision warns when it does,
    /// because the child gains nothing but the caller asked for
    /// something it did not get.
    Nothing,
}

/// Decide how a child gives up privilege.
///
/// Root credentials take the capability path, not the `setuid` one:
/// `setuid(0)` is a no-op that leaves `CAP_NET_ADMIN` in place, and the
/// child could then rewrite the netfilter cage or set `SO_MARK` to bypass
/// the proxy redirect. A caller that resolved its workload to uid 0 —
/// because the image says `USER root`, or because a `pre-start` script
/// asks to install a package — must not have to know that.
///
/// The gid on root credentials is deliberately not applied: the child stays
/// uid 0 and keeps `CAP_SETGID` from `KEEP_CAP_MASK`, so a `setgid` would
/// confine nothing. `Capabilities` carries no gid rather than offering a
/// knob with no security meaning.
pub fn privilege_drop_for(creds: Option<&SandboxCredentials>, is_root: bool) -> PrivilegeDrop<'_> {
    match creds {
        Some(creds) if !creds.uid_gid().0.is_root() => PrivilegeDrop::Setuid(creds),
        _ if is_root => PrivilegeDrop::Capabilities,
        Some(creds) => {
            tracing::warn!(
                user = creds.user(),
                "requested identity ignored: this parent is not root, so the child runs as the parent's own identity"
            );
            PrivilegeDrop::Nothing
        }
        None => PrivilegeDrop::Nothing,
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

    fn creds_for(uid: u32, gid: u32) -> SandboxCredentials {
        SandboxCredentials::resolve_by_uid(uid, gid).expect("resolve_by_uid never fails on a host")
    }

    #[derive(Default)]
    struct FakePasswd {
        users: Vec<(&'static str, u32, u32)>,
        groups: Vec<(&'static str, u32)>,
    }

    impl Passwd for FakePasswd {
        fn uid_of(&self, name: &str) -> Option<u32> {
            self.users
                .iter()
                .find(|(n, ..)| *n == name)
                .map(|(_, uid, _)| *uid)
        }
        fn primary_gid_of(&self, name: &str) -> Option<u32> {
            self.users
                .iter()
                .find(|(n, ..)| *n == name)
                .map(|(.., gid)| *gid)
        }
        fn gid_of_group(&self, group: &str) -> Option<u32> {
            self.groups
                .iter()
                .find(|(g, _)| *g == group)
                .map(|(_, gid)| *gid)
        }
    }

    fn image() -> FakePasswd {
        FakePasswd {
            users: vec![("node", 1000, 20)],
            groups: vec![("staff", 50)],
        }
    }

    fn ids(spec: &str, passwd: &dyn Passwd) -> (u32, u32) {
        let creds =
            SandboxCredentials::resolve_user_spec(spec, passwd).expect("this identity resolves");
        let (uid, gid) = creds.uid_gid();
        (uid.as_raw(), gid.as_raw())
    }

    #[test]
    fn a_named_user_resolves_against_the_images_own_passwd() {
        assert_eq!(
            ids("node", &image()),
            (1000, 20),
            "a name means whatever uid this image gave it, so the answer has to come from the image rather than from whoever staged the run"
        );
    }

    #[test]
    fn a_user_named_for_a_numeral_is_the_passwd_entry_rather_than_the_number() {
        let passwd = FakePasswd {
            users: vec![("1000", 1500, 30)],
            groups: Vec::new(),
        };
        assert_eq!(
            ids("1000", &passwd),
            (1500, 30),
            "the user segment is name-first because that is how the workload's own identity resolves; reading it as the number instead would land a script on a different uid from the workload on exactly these images"
        );
    }

    #[test]
    fn a_named_user_takes_its_primary_group_when_none_is_declared() {
        let passwd = FakePasswd {
            users: vec![("node", 1000, 20)],
            groups: Vec::new(),
        };
        assert_eq!(
            ids("node", &passwd),
            (1000, 20),
            "the primary group is what the passwd line says, not a group that happens to share the user's name — `resolve` would have found nothing here"
        );
    }

    #[test]
    fn a_numeric_user_with_no_passwd_line_still_resolves() {
        assert_eq!(
            ids("1500", &FakePasswd::default()),
            (1500, 1500),
            "a number is the uid directly, so an image carrying a numeric USER and no matching passwd line must still resolve"
        );
    }

    #[test]
    fn a_declared_group_outranks_the_users_primary_one() {
        assert_eq!(ids("node:staff", &image()), (1000, 50));
    }

    #[test]
    fn a_numeric_group_resolves_without_a_group_file_entry() {
        assert_eq!(ids("node:77", &image()), (1000, 77));
    }

    #[test]
    fn a_numeral_group_is_the_gid_itself_even_when_a_group_is_named_for_it() {
        let passwd = FakePasswd {
            users: vec![("node", 1000, 20)],
            groups: vec![("77", 500)],
        };
        assert_eq!(
            ids("node:77", &passwd),
            (1000, 77),
            "a number names the id directly, so an image that names a group for a numeral must not be able to hand out a gid the number would never give"
        );
    }

    #[test]
    fn a_user_the_tables_cannot_resolve_is_an_error_rather_than_a_fallback() {
        let err = SandboxCredentials::resolve_user_spec("nobody-here", &image())
            .expect_err("an unknown name has no answer");
        assert!(
            err.contains("nobody-here"),
            "falling back would run as an identity nobody named, and root is the likeliest thing it would fall back to; got: {err}"
        );
    }

    #[test]
    fn only_digits_are_read_as_an_id() {
        for spec in ["+0", " 7", "node:+50", "node:0x10"] {
            assert!(
                SandboxCredentials::resolve_user_spec(spec, &image()).is_err(),
                "an id is what an image's USER directive can carry, and no directive wrote this — reading it as a number would resolve a spec no table ever answered: {spec:?}"
            );
        }
    }

    #[test]
    fn a_leading_zero_still_reads_as_decimal() {
        assert_eq!(
            ids("node:010", &image()),
            (1000, 10),
            "a leading zero is the one digits-only shape that could mean two things, and octal is not what the number says"
        );
    }

    #[test]
    fn a_group_the_tables_cannot_resolve_is_an_error() {
        let err = SandboxCredentials::resolve_user_spec("node:ghosts", &image())
            .expect_err("an unknown group has no answer");
        assert!(err.contains("ghosts"), "got: {err}");
    }

    #[test]
    fn a_spec_that_names_no_identity_is_refused() {
        for spec in ["", "node:staff:extra", ":staff", "node:"] {
            assert!(
                SandboxCredentials::resolve_user_spec(spec, &image()).is_err(),
                "this shape names no identity, so resolving it would invent one: {spec:?}"
            );
        }
    }

    #[test]
    fn the_system_tables_answer_for_root() {
        assert_eq!(
            SystemPasswd.uid_of("root"),
            Some(0),
            "root is the one entry every platform we run on carries, so this pins the NSS wiring without depending on the image"
        );
    }

    #[test]
    fn root_credentials_take_the_capability_path_rather_than_a_setuid_no_op() {
        assert_eq!(
            privilege_drop_for(Some(&creds_for(0, 0)), true),
            PrivilegeDrop::Capabilities,
            "setuid(0) is a no-op that leaves CAP_NET_ADMIN in place, so a child resolved to root has to reach the capability drop or it can rewrite the netfilter cage"
        );
    }

    #[test]
    fn a_root_uid_under_a_non_root_group_still_takes_the_capability_path() {
        assert_eq!(
            privilege_drop_for(Some(&creds_for(0, 20)), true),
            PrivilegeDrop::Capabilities,
            "the kernel only zeroes the capability sets on a setuid to a non-zero uid; the gid does not enter into it"
        );
    }

    #[test]
    fn a_non_root_identity_is_a_setuid_target() {
        let creds = creds_for(65534, 65534);
        assert_eq!(
            privilege_drop_for(Some(&creds), true),
            PrivilegeDrop::Setuid(&creds),
            "the kernel zeroes the capability sets for us here, so the uid drop is the whole drop"
        );
    }

    #[test]
    fn a_root_parent_with_no_resolved_identity_drops_capabilities() {
        assert_eq!(
            privilege_drop_for(None, true),
            PrivilegeDrop::Capabilities,
            "an image with no sandbox user still runs its workload as the supervisor's root, which must not keep CAP_NET_ADMIN"
        );
    }

    #[test]
    fn an_unprivileged_parent_drops_nothing() {
        assert_eq!(
            privilege_drop_for(None, false),
            PrivilegeDrop::Nothing,
            "capset would EPERM, and there is no cage to break out of when the parent never had the capability"
        );
    }

    #[test]
    fn an_unprivileged_parent_naming_root_drops_nothing() {
        assert_eq!(
            privilege_drop_for(Some(&creds_for(0, 0)), false),
            PrivilegeDrop::Nothing,
            "a parent that is not root cannot setuid to root nor capset, so there is nothing this branch could honour"
        );
    }

    #[derive(Clone, Default)]
    struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .expect("the capture buffer is uncontended")
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Captured {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("the capture buffer is uncontended"))
                .into_owned()
        }
    }

    /// The parent honours no identity here, so the one thing the caller
    /// gets is the report that it did not. Without it a script that asked
    /// for root runs as somebody else and only fails further downstream,
    /// where nothing names the identity as the cause.
    #[test]
    fn an_unprivileged_parent_says_which_identity_it_ignored() {
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_writer(move || writer.clone())
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            privilege_drop_for(Some(&creds_for(0, 0)), false);
        });

        let text = captured.text();
        assert!(
            text.contains("requested identity ignored") && text.contains(r#"user="root""#),
            "the warning has to name the identity that was asked for, and the sentence alone says only that somebody was ignored; got: {text:?}"
        );
    }

    #[test]
    fn every_other_decision_warns_about_nothing() {
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_writer(move || writer.clone())
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            privilege_drop_for(Some(&creds_for(0, 0)), true);
            privilege_drop_for(Some(&creds_for(65534, 65534)), true);
            privilege_drop_for(None, false);
        });

        assert_eq!(
            captured.text(),
            "",
            "a drop that happened is not news, and a warning on every spawn teaches a reader to skip the one that matters"
        );
    }
}
