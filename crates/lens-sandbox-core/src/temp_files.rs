use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use base64::Engine;
use nix::errno::Errno;

use crate::privilege::SandboxCredentials;
use crate::protocol::{FileOwner, TempFile};

const DEFAULT_ROOT: &str = "/tmp";
const DEFAULT_FILE_MODE: u32 = 0o600;
/// A directory the root supervisor creates under the shared `/tmp` root is only
/// a path-prefix waypoint to a file that gets chowned to the unprivileged
/// sandbox user. `0o711` (execute, no read) lets that user *traverse* to its
/// file without being able to list the directory, and root keeps ownership so
/// no workload can rename the waypoint out from under a later refresh.
const WAYPOINT_DIR_MODE: u32 = 0o711;
/// A directory the root supervisor creates inside the sandbox home belongs to
/// the workload: the agent has to list it and add siblings of the delivered
/// file (`~/.claude` needs `settings.json` and `todos/` next to
/// `.credentials.json`). It is chowned to the sandbox user with `0o700`.
const WORKLOAD_DIR_MODE: u32 = 0o700;

/// What the root supervisor does with a directory it *creates* on the way to
/// the delivered file. A directory that already exists is never chowned or
/// chmod'd under either variant — handing over a pre-existing directory would
/// let a policy frame grab any directory the supervisor can traverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NewDirs {
    /// Root-owned and traverse-only, for a shared root like `/tmp`.
    Waypoint,
    /// Chowned to the sandbox user and `0o700`, so the workload can use it.
    WorkloadOwned,
}

impl NewDirs {
    /// One source for the mode, because the walk that creates a directory and
    /// the hand-over that finishes it must not disagree about it.
    fn mode(self) -> u32 {
        match self {
            Self::Waypoint => WAYPOINT_DIR_MODE,
            Self::WorkloadOwned => WORKLOAD_DIR_MODE,
        }
    }
}

#[derive(Debug, Clone)]
struct Root {
    components: Vec<OsString>,
    new_dirs: NewDirs,
    /// Set only on the root `with_home` pushed, so refusing the home removes
    /// that one root and never a same-valued root somebody else added.
    from_home: bool,
}

/// Where policy files may land. Every requested path must resolve inside one of
/// the allowed roots; anything else is refused before a single syscall runs.
///
/// The default is `/tmp` alone, which is the whole path policy this module used
/// to hardcode. Widening it is an explicit caller decision, and the method that
/// does it names what happens to the directories it creates: a root added
/// through [`Self::allow_workload_owned`] hands them to the sandbox user, while
/// the default `/tmp` keeps them root-owned and traverse-only. A path binds to
/// the longest root that contains it, and to the last-added of two equal ones, so
/// a home nested inside another root — or duplicating one — still gets its own
/// policy.
#[derive(Debug, Clone)]
pub struct FileRoots {
    roots: Vec<Root>,
    home: Option<Vec<OsString>>,
}

impl Default for FileRoots {
    fn default() -> Self {
        Self {
            roots: vec![Root {
                components: DEFAULT_ROOT
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .map(OsString::from)
                    .collect(),
                new_dirs: NewDirs::Waypoint,
                from_home: false,
            }],
            home: None,
        }
    }
}

impl FileRoots {
    /// The roots policy files are allowed to land in for a given sandbox user:
    /// the default `/tmp`, plus that user's home so a `~/…` path resolves. A
    /// user whose passwd home is `/` contributes no root — widening to the
    /// whole filesystem is never implied.
    pub fn for_sandbox(sandbox_creds: Option<&SandboxCredentials>) -> Self {
        Self::rooted_at_home(sandbox_creds.map(SandboxCredentials::home))
    }

    /// The fallback is deliberate and loud: an unusable home contributes no
    /// root, so a `~/…` path is refused outright rather than quietly landing
    /// somewhere the sender did not name.
    fn rooted_at_home(home: Option<&str>) -> Self {
        let base = Self::default();
        let Some(home) = home else {
            return base;
        };
        match base.clone().with_home(home) {
            Ok(roots) => roots,
            Err(reason) => {
                tracing::warn!(
                    home,
                    reason,
                    "sandbox home is unusable as a policy-file root; `~/` paths will be refused"
                );
                base
            }
        }
    }

    /// Allow one more root whose created directories the workload owns. The
    /// hand-over is in the name because a root added later must state it rather
    /// than inherit whatever the last one chose. A root is absolute and
    /// lexically plain — one carrying `.` or `..` is a configuration error, not
    /// something to normalise away.
    pub fn allow_workload_owned(mut self, root: impl AsRef<Path>) -> Result<Self, String> {
        self.roots.push(Root {
            components: root_components(root.as_ref())?,
            new_dirs: NewDirs::WorkloadOwned,
            from_home: false,
        });
        Ok(self)
    }

    /// Set the home directory a leading `~` expands against, and allow it as a
    /// root.
    pub fn with_home(mut self, home: impl AsRef<Path>) -> Result<Self, String> {
        let components = root_components(home.as_ref())?;
        if components.is_empty() {
            return Err("sandbox home must not be the filesystem root".to_string());
        }
        self.home = Some(components.clone());
        self.roots.push(Root {
            components,
            new_dirs: NewDirs::WorkloadOwned,
            from_home: true,
        });
        Ok(self)
    }

    /// Drop a sandbox home this machine cannot safely use as a root, so an
    /// unusable home costs `~/` expansion rather than the whole batch.
    ///
    /// The home comes from passwd, which a custom image controls, so it is the
    /// one root that has to earn its place: a home pointing somewhere the
    /// sandbox user does not own would let `owner: root` plant a file in a
    /// privileged directory. The check reads the uid off the fd `open_root`
    /// returns rather than off the path, so it describes the inode the walk
    /// opened. It is still advisory across calls — the walk re-opens by path
    /// later, so a rename between the two is not covered; `O_NOFOLLOW` means a
    /// swap to a symlink fails closed, and a swap to another real directory the
    /// sandbox user owns grants nothing it did not already have.
    fn usable(&self, fs: &dyn TempFs, sandbox_uid: Option<u32>) -> Self {
        let Some(home) = &self.home else {
            return self.clone();
        };
        let path = render(home, &[]);
        let refuse = |reason: String| {
            tracing::warn!(
                home = %path.display(),
                reason,
                "refusing the sandbox home as a policy-file root; `~/` paths will be refused"
            );
            Self {
                roots: self
                    .roots
                    .iter()
                    .filter(|r| !r.from_home)
                    .cloned()
                    .collect(),
                home: None,
            }
        };
        let dir = match fs.open_root(&path) {
            Ok(dir) => dir,
            Err(e) => return refuse(format!("it cannot be opened ({e})")),
        };
        match (dir.owner_uid(), sandbox_uid) {
            (_, None) => {
                refuse("the sandbox uid is unknown, so its ownership cannot be checked".to_string())
            }
            (Err(e), _) => refuse(format!("its owner cannot be read ({e})")),
            (Ok(owner), Some(uid)) if owner != uid => refuse(format!(
                "it is owned by uid {owner}, not the sandbox user {uid}"
            )),
            _ => self.clone(),
        }
    }

    fn primary(&self) -> &[OsString] {
        self.roots
            .first()
            .map(|r| r.components.as_slice())
            .unwrap_or(&[])
    }

    /// Validate a requested path lexically and bind it to the allowed root it
    /// belongs to.
    ///
    /// Every separator-delimited segment must be a normal name; `..` and `.` are
    /// rejected so no component can redirect the directory walk. A leading `~/`
    /// expands against the sandbox home. A relative path resolves under the
    /// primary root. An absolute path must sit strictly inside one of the roots,
    /// and binds to the longest of them — the last added, where two are equal, so
    /// a home that duplicates an existing root still gets its own policy.
    fn resolve(&self, requested: &str) -> Result<ResolvedPath, String> {
        let absolute = self.to_absolute(requested)?;

        let mut best: Option<&Root> = None;
        for root in &self.roots {
            let len = root.components.len();
            if absolute.len() > len
                && absolute[..len] == root.components[..]
                && best.is_none_or(|b| len >= b.components.len())
            {
                best = Some(root);
            }
        }

        let root = best
            .ok_or_else(|| format!("temp file path is outside the allowed roots: {requested}"))?;

        Ok(ResolvedPath {
            root: render(&root.components, &[]),
            components: absolute[root.components.len()..].to_vec(),
            new_dirs: root.new_dirs,
        })
    }

    fn to_absolute(&self, requested: &str) -> Result<Vec<OsString>, String> {
        let bytes = requested.as_bytes();

        if bytes.first() == Some(&b'~') {
            let rest = match bytes.get(1) {
                None => return Err(format!("temp file path is empty: {requested}")),
                Some(&b'/') => &bytes[2..],
                Some(_) => {
                    return Err(format!(
                        "temp file path may only use `~/` for the sandbox home: {requested}"
                    ));
                }
            };
            let home = self.home.as_ref().ok_or_else(|| {
                format!("temp file path uses `~` but no sandbox home is known: {requested}")
            })?;
            return join(home, rest, requested);
        }

        if bytes.first() == Some(&b'/') {
            return join(&[], &bytes[1..], requested);
        }

        join(self.primary(), bytes, requested)
    }
}

/// An allowed root plus the safe, root-relative component sequence beneath it.
#[derive(Debug)]
struct ResolvedPath {
    root: PathBuf,
    components: Vec<OsString>,
    new_dirs: NewDirs,
}

impl ResolvedPath {
    fn display(&self) -> String {
        let mut path = self.root.clone();
        for comp in &self.components {
            path.push(comp);
        }
        path.to_string_lossy().to_string()
    }
}

fn render(root: &[OsString], components: &[OsString]) -> PathBuf {
    let mut path = PathBuf::from("/");
    for comp in root.iter().chain(components) {
        path.push(comp);
    }
    path
}

/// Append a requested tail to a prefix, one separator-delimited segment at a
/// time. An empty segment — a doubled or trailing separator — is dropped, which
/// is exactly what the `Path::strip_prefix` this replaced did via `Components`,
/// so a sender's `/tmp//x` or `/tmp/x/` keeps resolving instead of failing the
/// whole all-or-nothing batch. `.` and `..` are the unsafe forms and stay
/// rejected: they redirect the walk, whereas a redundant separator cannot.
fn join(prefix: &[OsString], tail: &[u8], requested: &str) -> Result<Vec<OsString>, String> {
    let mut components = prefix.to_vec();
    for segment in tail.split(|b| *b == b'/') {
        if segment.is_empty() {
            continue;
        }
        if segment == b"." || segment == b".." {
            return Err(format!(
                "temp file path contains an unsafe component: {requested}"
            ));
        }
        components.push(OsString::from_vec(segment.to_vec()));
    }
    Ok(components)
}

/// Split an allowed root into components, rejecting a relative root or one
/// carrying `.` / `..`. Repeated and trailing separators are tolerated because a
/// root is operator configuration, not an agent-supplied path.
fn root_components(root: &Path) -> Result<Vec<OsString>, String> {
    let bytes = root.as_os_str().as_bytes();
    if bytes.first() != Some(&b'/') {
        return Err(format!(
            "allowed root must be absolute: {}",
            root.to_string_lossy()
        ));
    }
    let mut components = Vec::new();
    for segment in bytes[1..].split(|b| *b == b'/') {
        if segment.is_empty() {
            continue;
        }
        if segment == b"." || segment == b".." {
            return Err(format!(
                "allowed root contains an unsafe component: {}",
                root.to_string_lossy()
            ));
        }
        components.push(OsString::from_vec(segment.to_vec()));
    }
    Ok(components)
}

/// Port over the directory-walk + file-create syscalls so symlink rejection,
/// EEXIST tolerance, O_EXCL collisions, chown, and chmod are unit-testable
/// without root or a real filesystem.
trait TempFs {
    fn open_root(&self, root: &Path) -> Result<Box<dyn DirHandle>, Errno>;
}

trait DirHandle {
    fn open_child_dir(&self, name: &OsStr) -> Result<Box<dyn DirHandle>, Errno>;
    fn make_child_dir(&self, name: &OsStr, mode: u32) -> Result<(), Errno>;
    fn create_child_file(&self, name: &OsStr, mode: u32) -> Result<Box<dyn FileHandle>, Errno>;
    /// Unlink a child of this directory by name. Operates on the directory fd,
    /// so a symlink at `name` unlinks the link itself rather than its target.
    fn unlink_child(&self, name: &OsStr) -> Result<(), Errno>;
    /// Remove an empty child directory. Only ever called on one this walk just
    /// created, to undo an open or a hand-over that failed after the mkdir.
    fn remove_child_dir(&self, name: &OsStr) -> Result<(), Errno>;
    /// The uid owning this directory, read from the open fd rather than the
    /// path, so the answer describes the inode the caller already holds.
    fn owner_uid(&self) -> Result<u32, Errno>;
    fn chown(&self, uid: u32, gid: u32) -> Result<(), Errno>;
    fn chmod(&self, mode: u32) -> Result<(), Errno>;
}

trait FileHandle {
    fn write_all(&mut self, data: &[u8]) -> Result<(), Errno>;
    fn chown(&self, uid: u32, gid: u32) -> Result<(), Errno>;
    fn chmod(&self, mode: u32) -> Result<(), Errno>;
}

pub async fn write_temp_files(
    files: &[TempFile],
    sandbox_creds: Option<&SandboxCredentials>,
    roots: &FileRoots,
) -> Result<Vec<String>, String> {
    let creds = sandbox_creds.map(|c| {
        let (uid, gid) = c.uid_gid();
        (uid.as_raw(), gid.as_raw())
    });
    write_temp_files_with(&RealTempFs, files, creds, roots)
}

fn write_temp_files_with(
    fs: &dyn TempFs,
    files: &[TempFile],
    creds: Option<(u32, u32)>,
    roots: &FileRoots,
) -> Result<Vec<String>, String> {
    // All-or-nothing: if any file fails, roll back the files already created so
    // the batch never leaves half-written, sandbox-owned secret files behind.
    // A leaked partial would otherwise be untracked by the caller (never
    // cleaned) and, because creation is `O_EXCL`, would make every later
    // refresh of that path fail closed forever as a phantom "hostile pre-plant".
    //
    // Rollback is file-only: `remove_one` unlinks the final (file) component but
    // does not `rmdir` the intermediate directories the walk may have created.
    // That residue is harmless — empty directories that the next refresh's
    // EEXIST-tolerant `mkdirat` + `O_NOFOLLOW` `openat` re-traverses cleanly — so
    // a fully clean, dir-inclusive rollback isn't worth the extra unwind.
    let roots = &roots.usable(fs, creds.map(|(uid, _)| uid));
    let mut written = Vec::with_capacity(files.len());
    for f in files {
        let result = roots.resolve(&f.path).and_then(|resolved| {
            let bytes = file_bytes(f)?;
            write_one(fs, &resolved, &bytes, f.mode, owner_creds(f, creds), creds)
                .map(|path| (resolved, path))
        });
        match result {
            Ok((resolved, path)) => written.push((resolved, path)),
            Err(e) => {
                for (resolved, _) in &written {
                    remove_one(fs, resolved);
                }
                return Err(e);
            }
        }
    }
    Ok(written.into_iter().map(|(_, path)| path).collect())
}

/// The exact bytes to deliver. `content` and `contentB64` are mutually
/// exclusive, and one of them is required — an entry that sets both, or
/// neither, is a malformed policy and fails the batch rather than silently
/// picking one or writing an empty file.
fn file_bytes(f: &TempFile) -> Result<Vec<u8>, String> {
    match (&f.content, &f.content_b64) {
        (Some(_), Some(_)) => Err(format!(
            "temp file sets both content and contentB64: {}",
            f.path
        )),
        (Some(text), None) => Ok(text.as_bytes().to_vec()),
        (None, Some(encoded)) => base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| format!("temp file contentB64 is not valid base64: {}: {e}", f.path)),
        (None, None) => Err(format!(
            "temp file sets neither content nor contentB64: {}",
            f.path
        )),
    }
}

/// The uid/gid the delivered file is chowned to, or `None` to leave it owned by
/// the root supervisor that created it.
fn owner_creds(f: &TempFile, sandbox: Option<(u32, u32)>) -> Option<(u32, u32)> {
    match f.owner.unwrap_or(FileOwner::Workload) {
        FileOwner::Workload => sandbox,
        FileOwner::Root => None,
    }
}

/// Best-effort symlink-safe removal of a previously-written temp file. Re-walks
/// the path with `O_NOFOLLOW` exactly like the writer, then unlinks the final
/// component via the directory fd — so a parent component the agent swapped for
/// a symlink between refreshes can't redirect the root supervisor's unlink at
/// an attacker-chosen target. A missing or planted-symlink component is treated
/// as "nothing safe to remove" and skipped.
fn remove_one(fs: &dyn TempFs, resolved: &ResolvedPath) {
    let Some((file_name, dir_components)) = resolved.components.split_last() else {
        return;
    };
    let Ok(mut dir) = fs.open_root(&resolved.root) else {
        return;
    };
    for comp in dir_components {
        match dir.open_child_dir(comp) {
            Ok(child) => dir = child,
            Err(_) => return,
        }
    }
    let _ = dir.unlink_child(file_name);
}

/// Open the directory that holds the delivered file, creating the missing
/// components on the way. A component this walk creates is finished according to
/// the root's [`NewDirs`] policy; a component that already exists is opened and
/// otherwise untouched.
fn walk_to_parent(
    fs: &dyn TempFs,
    resolved: &ResolvedPath,
    dir_components: &[OsString],
    workload: Option<(u32, u32)>,
) -> Result<Box<dyn DirHandle>, String> {
    let root = resolved.root.to_string_lossy().to_string();
    let mut dir = fs
        .open_root(&resolved.root)
        .map_err(|e| format!("open root {root}: {e}"))?;

    let dir_mode = resolved.new_dirs.mode();

    for comp in dir_components {
        let created = match dir.make_child_dir(comp, dir_mode) {
            Ok(()) => true,
            Err(Errno::EEXIST) => false,
            Err(e) => return Err(format!("mkdir {}: {e}", comp.to_string_lossy())),
        };
        let parent = dir;
        let finished = parent
            .open_child_dir(comp)
            .map_err(|e| {
                format!(
                    "open dir component {} under {root}: {e}",
                    comp.to_string_lossy()
                )
            })
            .and_then(|child| {
                if created && resolved.new_dirs == NewDirs::WorkloadOwned {
                    hand_dir_to_workload(child.as_ref(), comp, dir_mode, workload)?;
                }
                Ok(child)
            });
        dir = match finished {
            Ok(child) => child,
            // A dir left half-finished is wedged: the next refresh reads EEXIST
            // as pre-existing and by design never retries the hand-over, so undo
            // what this walk created and let that refresh start over.
            Err(failure) => {
                if created && let Err(e) = parent.remove_child_dir(comp) {
                    tracing::warn!(
                        dir = %comp.to_string_lossy(),
                        error = %e,
                        "could not undo a half-created policy directory; a later refresh will read it as pre-existing and skip the hand-over"
                    );
                }
                return Err(failure);
            }
        };
    }

    Ok(dir)
}

/// Finish a directory this walk just created so the workload can actually use
/// it: `0o700` and owned by the sandbox user. The chmod is explicit because the
/// supervisor's umask can strip bits off the `mkdirat` mode.
fn hand_dir_to_workload(
    dir: &dyn DirHandle,
    name: &OsStr,
    mode: u32,
    workload: Option<(u32, u32)>,
) -> Result<(), String> {
    let name = name.to_string_lossy();
    dir.chmod(mode)
        .map_err(|e| format!("chmod dir {name}: {e}"))?;
    if let Some((uid, gid)) = workload {
        dir.chown(uid, gid)
            .map_err(|e| format!("chown dir {name}: {e}"))?;
    }
    Ok(())
}

fn write_one(
    fs: &dyn TempFs,
    resolved: &ResolvedPath,
    content: &[u8],
    mode: Option<u32>,
    creds: Option<(u32, u32)>,
    workload: Option<(u32, u32)>,
) -> Result<String, String> {
    let display = resolved.display();

    let (file_name, dir_components) = resolved
        .components
        .split_last()
        .ok_or_else(|| format!("temp file path is empty: {display}"))?;

    let dir = walk_to_parent(fs, resolved, dir_components, workload)?;

    let file_mode = mode.unwrap_or(DEFAULT_FILE_MODE);
    let mut file = dir
        .create_child_file(file_name, file_mode)
        .map_err(|e| format!("create {display}: {e}"))?;

    file.write_all(content)
        .map_err(|e| format!("write {display}: {e}"))?;
    file.chmod(file_mode)
        .map_err(|e| format!("chmod {display}: {e}"))?;

    if let Some((uid, gid)) = creds {
        file.chown(uid, gid)
            .map_err(|e| format!("chown {display}: {e}"))?;
    }

    Ok(display)
}

/// Symlink-safe removal of previously-written temp files. Each path is
/// re-validated and re-walked with `O_NOFOLLOW`, so a parent component the
/// agent swapped for a symlink between refreshes can't redirect the root
/// supervisor's unlink at an attacker-chosen target — the same hazard the write
/// path guards against. Already-gone and planted-symlink paths are skipped
/// silently. A path that no longer resolves inside the allowed roots is
/// reported, because it names a file this cleanup is leaving behind.
pub async fn remove_temp_files(paths: &[String], roots: &FileRoots) {
    for reason in remove_temp_files_with(&RealTempFs, paths, roots) {
        tracing::warn!(
            reason,
            "policy file left in place: it is no longer removable"
        );
    }
}

/// Deliberately does not call [`FileRoots::usable`]: these paths are ones the
/// writer produced and recorded, so re-validating them against roots that may
/// have changed since could strand a file this process created. `O_NOFOLLOW`
/// still guards the walk.
fn remove_temp_files_with(fs: &dyn TempFs, paths: &[String], roots: &FileRoots) -> Vec<String> {
    let mut unresolved = Vec::new();
    for path in paths {
        match roots.resolve(path) {
            Ok(resolved) => remove_one(fs, &resolved),
            Err(reason) => unresolved.push(reason),
        }
    }
    unresolved
}

struct RealTempFs;

struct RealDir(std::os::fd::OwnedFd);

struct RealFile(std::os::fd::OwnedFd);

impl TempFs for RealTempFs {
    /// Walk the root one component at a time with `O_NOFOLLOW` instead of
    /// opening it by full path, so a symlink anywhere in the root — not just its
    /// final component — fails closed rather than redirecting the whole batch.
    fn open_root(&self, root: &Path) -> Result<Box<dyn DirHandle>, Errno> {
        let mut fd = open_dir_nofollow(&nix::fcntl::AT_FDCWD, "/")?;
        for segment in root
            .as_os_str()
            .as_bytes()
            .split(|b| *b == b'/')
            .filter(|s| !s.is_empty())
        {
            fd = open_dir_nofollow(&fd, segment)?;
        }
        Ok(Box::new(RealDir(fd)))
    }
}

impl DirHandle for RealDir {
    fn open_child_dir(&self, name: &OsStr) -> Result<Box<dyn DirHandle>, Errno> {
        let fd = open_dir_nofollow(&self.0, name.as_bytes())?;
        Ok(Box::new(RealDir(fd)))
    }

    fn make_child_dir(&self, name: &OsStr, mode: u32) -> Result<(), Errno> {
        nix::sys::stat::mkdirat(&self.0, name.as_bytes(), mode_from(mode))
    }

    fn create_child_file(&self, name: &OsStr, mode: u32) -> Result<Box<dyn FileHandle>, Errno> {
        use nix::fcntl::OFlag;
        let flags =
            OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_WRONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let fd = nix::fcntl::openat(&self.0, name.as_bytes(), flags, mode_from(mode))?;
        Ok(Box::new(RealFile(fd)))
    }

    fn unlink_child(&self, name: &OsStr) -> Result<(), Errno> {
        nix::unistd::unlinkat(
            &self.0,
            name.as_bytes(),
            nix::unistd::UnlinkatFlags::NoRemoveDir,
        )
    }

    fn remove_child_dir(&self, name: &OsStr) -> Result<(), Errno> {
        nix::unistd::unlinkat(
            &self.0,
            name.as_bytes(),
            nix::unistd::UnlinkatFlags::RemoveDir,
        )
    }

    fn owner_uid(&self) -> Result<u32, Errno> {
        nix::sys::stat::fstat(&self.0).map(|st| st.st_uid)
    }

    fn chown(&self, uid: u32, gid: u32) -> Result<(), Errno> {
        nix::unistd::fchown(
            &self.0,
            Some(nix::unistd::Uid::from_raw(uid)),
            Some(nix::unistd::Gid::from_raw(gid)),
        )
    }

    fn chmod(&self, mode: u32) -> Result<(), Errno> {
        nix::sys::stat::fchmod(&self.0, mode_from(mode))
    }
}

impl FileHandle for RealFile {
    fn write_all(&mut self, mut data: &[u8]) -> Result<(), Errno> {
        while !data.is_empty() {
            match nix::unistd::write(&self.0, data) {
                // A signal interrupting the write (the PID-1 supervisor reaps
                // children, so EINTR is routine) is retried, not surfaced as a
                // hard failure.
                Err(Errno::EINTR) => continue,
                Err(e) => return Err(e),
                Ok(0) => return Err(Errno::EIO),
                Ok(n) => data = &data[n..],
            }
        }
        Ok(())
    }

    fn chown(&self, uid: u32, gid: u32) -> Result<(), Errno> {
        nix::unistd::fchown(
            &self.0,
            Some(nix::unistd::Uid::from_raw(uid)),
            Some(nix::unistd::Gid::from_raw(gid)),
        )
    }

    fn chmod(&self, mode: u32) -> Result<(), Errno> {
        nix::sys::stat::fchmod(&self.0, mode_from(mode))
    }
}

fn open_dir_nofollow<Fd, P>(dirfd: &Fd, path: &P) -> Result<std::os::fd::OwnedFd, Errno>
where
    Fd: std::os::fd::AsFd,
    P: ?Sized + nix::NixPath,
{
    use nix::fcntl::OFlag;
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    nix::fcntl::openat(dirfd, path, flags, nix::sys::stat::Mode::empty())
}

fn mode_from(mode: u32) -> nix::sys::stat::Mode {
    nix::sys::stat::Mode::from_bits_truncate(mode as nix::sys::stat::mode_t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn tmp() -> FileRoots {
        FileRoots::default()
    }

    fn home_roots() -> FileRoots {
        FileRoots::default().with_home("/home/sandbox").unwrap()
    }

    #[test]
    fn safe_relative_path() {
        let result = tmp().resolve("creds/aws.json").unwrap();
        assert_eq!(
            result.components,
            vec![OsString::from("creds"), OsString::from("aws.json")]
        );
        assert_eq!(result.display(), "/tmp/creds/aws.json");
    }

    #[test]
    fn safe_already_under_tmp() {
        let result = tmp().resolve("/tmp/lens-sandbox/creds/aws.json").unwrap();
        assert_eq!(
            result.components,
            vec![
                OsString::from("lens-sandbox"),
                OsString::from("creds"),
                OsString::from("aws.json")
            ]
        );
    }

    #[test]
    fn safe_sandbox_kubeconfig() {
        let result = tmp().resolve("/tmp/sandbox-kubeconfig-abc123").unwrap();
        assert_eq!(
            result.components,
            vec![OsString::from("sandbox-kubeconfig-abc123")]
        );
    }

    #[test]
    fn reject_dotdot_component() {
        assert!(tmp().resolve("../etc/passwd").is_err());
    }

    #[test]
    fn reject_dotdot_mid_path() {
        assert!(tmp().resolve("creds/../../etc/passwd").is_err());
    }

    #[test]
    fn reject_single_dot_component() {
        assert!(tmp().resolve("creds/./aws.json").is_err());
    }

    #[test]
    fn reject_absolute_outside_tmp() {
        assert!(tmp().resolve("/etc/passwd").is_err());
    }

    #[test]
    fn reject_dotdot_in_tmp() {
        assert!(tmp().resolve("/tmp/../etc/passwd").is_err());
    }

    #[test]
    fn reject_empty_path() {
        assert!(tmp().resolve("").is_err());
        assert!(tmp().resolve("/tmp").is_err());
    }

    #[test]
    fn reject_path_outside_the_allowed_roots() {
        let roots = FileRoots::default()
            .allow_workload_owned("/opt/lens")
            .unwrap();
        let err = roots.resolve("/etc/passwd").unwrap_err();
        assert!(err.contains("/etc/passwd"), "{err}");
        assert!(roots.resolve("/opt/lens/x.json").is_ok());
        assert!(roots.resolve("/tmp/x.json").is_ok());
    }

    #[test]
    fn reject_root_prefix_that_is_only_a_string_prefix() {
        let roots = FileRoots::default()
            .allow_workload_owned("/opt/lens")
            .unwrap();
        assert!(roots.resolve("/opt/lens-evil/x").is_err());
        assert!(roots.resolve("/tmpfoo/x").is_err());
    }

    #[test]
    fn reject_dotdot_that_would_escape_an_allowed_root() {
        let roots = home_roots();
        assert!(roots.resolve("/home/sandbox/../../etc/passwd").is_err());
        assert!(roots.resolve("~/../../etc/passwd").is_err());
        assert!(roots.resolve("~/..").is_err());
    }

    #[test]
    fn tilde_resolves_under_the_sandbox_home() {
        let resolved = home_roots().resolve("~/.claude/settings.json").unwrap();
        assert_eq!(resolved.display(), "/home/sandbox/.claude/settings.json");
        assert_eq!(
            resolved.components,
            vec![OsString::from(".claude"), OsString::from("settings.json")]
        );
    }

    #[test]
    fn tilde_without_a_configured_home_is_refused() {
        assert!(tmp().resolve("~/x").is_err());
    }

    #[test]
    fn tilde_user_form_is_refused() {
        assert!(home_roots().resolve("~root/.ssh/authorized_keys").is_err());
        assert!(home_roots().resolve("~").is_err());
    }

    #[test]
    fn a_root_must_be_absolute_and_lexically_safe() {
        assert!(
            FileRoots::default()
                .allow_workload_owned("relative/dir")
                .is_err()
        );
        assert!(
            FileRoots::default()
                .allow_workload_owned("/opt/../etc")
                .is_err()
        );
        assert!(FileRoots::default().with_home("/").is_err());
    }

    #[test]
    fn for_sandbox_without_creds_is_the_default_root_set() {
        let roots = FileRoots::for_sandbox(None);
        assert!(roots.resolve("/tmp/x").is_ok());
        assert!(roots.resolve("/home/sandbox/x").is_err());
    }

    #[test]
    fn an_unusable_sandbox_home_keeps_the_default_roots_and_refuses_tilde() {
        let roots = FileRoots::rooted_at_home(Some("/"));
        assert!(roots.resolve("/tmp/x").is_ok());
        let err = roots.resolve("~/x").unwrap_err();
        assert!(err.contains("no sandbox home"), "{err}");
    }

    #[test]
    fn redundant_separators_resolve_like_the_old_strip_prefix() {
        // `Path::strip_prefix` normalised through `Components`, so an existing
        // sender's `//tmp/x`, `/tmp/x/` and `/tmp//x` were all accepted. The
        // batch is all-or-nothing, so rejecting them now would turn one sloppy
        // path into zero delivered policy files. Only `.` and `..` are unsafe.
        for requested in ["//tmp/x", "/tmp/x/", "/tmp//x"] {
            let resolved = tmp()
                .resolve(requested)
                .unwrap_or_else(|e| panic!("{requested}: {e}"));
            assert_eq!(resolved.display(), "/tmp/x", "{requested}");
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Event {
        MakeDir(String, u32),
        OpenDir(String),
        CreateFile(String, u32),
        Write(String, Vec<u8>),
        Chmod(String, u32),
        Chown(String, u32, u32),
        ChmodDir(String, u32),
        ChownDir(String, u32, u32),
        Unlink(String),
        RemoveDir(String),
    }

    #[derive(Default)]
    struct Recorder {
        events: Vec<Event>,
    }

    struct FakeTempFs {
        recorder: Rc<RefCell<Recorder>>,
        // Names that should fail to open as a directory with ELOOP (planted symlink).
        symlink_dirs: Vec<String>,
        // Names that already exist as a file (O_EXCL collision).
        existing_files: Vec<String>,
        // Directory components whose mkdir returns EEXIST.
        existing_dirs: Vec<String>,
        // If set, chown returns this error.
        chown_err: Option<Errno>,
        // If set, write returns this error.
        write_err: Option<Errno>,
        // If set, opening a child directory returns this error.
        open_err: Option<Errno>,
        // Roots that cannot be opened at all, as an absent home would be.
        unopenable_roots: Vec<String>,
        // The uid every directory reports as its owner.
        dir_uid: u32,
        // If set, reading a directory's owner returns this error.
        owner_uid_err: Option<Errno>,
    }

    impl FakeTempFs {
        fn new(recorder: Rc<RefCell<Recorder>>) -> Self {
            Self {
                recorder,
                symlink_dirs: Vec::new(),
                existing_files: Vec::new(),
                existing_dirs: Vec::new(),
                chown_err: None,
                write_err: None,
                open_err: None,
                unopenable_roots: Vec::new(),
                dir_uid: 1000,
                owner_uid_err: None,
            }
        }
    }

    struct FakeDir {
        recorder: Rc<RefCell<Recorder>>,
        name: String,
        symlink_dirs: Vec<String>,
        existing_files: Vec<String>,
        existing_dirs: Vec<String>,
        chown_err: Option<Errno>,
        write_err: Option<Errno>,
        open_err: Option<Errno>,
        dir_uid: u32,
        owner_uid_err: Option<Errno>,
    }

    struct FakeFile {
        recorder: Rc<RefCell<Recorder>>,
        name: String,
        chown_err: Option<Errno>,
        write_err: Option<Errno>,
    }

    impl TempFs for FakeTempFs {
        fn open_root(&self, root: &Path) -> Result<Box<dyn DirHandle>, Errno> {
            if self
                .unopenable_roots
                .contains(&root.to_string_lossy().to_string())
            {
                return Err(Errno::ENOENT);
            }
            Ok(Box::new(FakeDir {
                recorder: self.recorder.clone(),
                name: root.to_string_lossy().to_string(),
                symlink_dirs: self.symlink_dirs.clone(),
                existing_files: self.existing_files.clone(),
                existing_dirs: self.existing_dirs.clone(),
                chown_err: self.chown_err,
                write_err: self.write_err,
                open_err: self.open_err,
                dir_uid: self.dir_uid,
                owner_uid_err: self.owner_uid_err,
            }))
        }
    }

    impl DirHandle for FakeDir {
        fn open_child_dir(&self, name: &OsStr) -> Result<Box<dyn DirHandle>, Errno> {
            let n = name.to_string_lossy().to_string();
            if self.symlink_dirs.contains(&n) {
                return Err(Errno::ELOOP);
            }
            if let Some(e) = self.open_err {
                return Err(e);
            }
            self.recorder
                .borrow_mut()
                .events
                .push(Event::OpenDir(n.clone()));
            Ok(Box::new(FakeDir {
                recorder: self.recorder.clone(),
                name: n,
                symlink_dirs: self.symlink_dirs.clone(),
                existing_files: self.existing_files.clone(),
                existing_dirs: self.existing_dirs.clone(),
                chown_err: self.chown_err,
                write_err: self.write_err,
                open_err: self.open_err,
                dir_uid: self.dir_uid,
                owner_uid_err: self.owner_uid_err,
            }))
        }

        fn make_child_dir(&self, name: &OsStr, mode: u32) -> Result<(), Errno> {
            let n = name.to_string_lossy().to_string();
            if self.existing_dirs.contains(&n) {
                return Err(Errno::EEXIST);
            }
            self.recorder
                .borrow_mut()
                .events
                .push(Event::MakeDir(n, mode));
            Ok(())
        }

        fn create_child_file(&self, name: &OsStr, mode: u32) -> Result<Box<dyn FileHandle>, Errno> {
            let n = name.to_string_lossy().to_string();
            if self.existing_files.contains(&n) {
                return Err(Errno::EEXIST);
            }
            self.recorder
                .borrow_mut()
                .events
                .push(Event::CreateFile(n.clone(), mode));
            Ok(Box::new(FakeFile {
                recorder: self.recorder.clone(),
                name: n,
                chown_err: self.chown_err,
                write_err: self.write_err,
            }))
        }

        fn remove_child_dir(&self, name: &OsStr) -> Result<(), Errno> {
            let n = name.to_string_lossy().to_string();
            self.recorder.borrow_mut().events.push(Event::RemoveDir(n));
            Ok(())
        }

        fn owner_uid(&self) -> Result<u32, Errno> {
            match self.owner_uid_err {
                Some(e) => Err(e),
                None => Ok(self.dir_uid),
            }
        }

        fn unlink_child(&self, name: &OsStr) -> Result<(), Errno> {
            let n = name.to_string_lossy().to_string();
            self.recorder.borrow_mut().events.push(Event::Unlink(n));
            Ok(())
        }

        fn chown(&self, uid: u32, gid: u32) -> Result<(), Errno> {
            if let Some(e) = self.chown_err {
                return Err(e);
            }
            self.recorder
                .borrow_mut()
                .events
                .push(Event::ChownDir(self.name.clone(), uid, gid));
            Ok(())
        }

        fn chmod(&self, mode: u32) -> Result<(), Errno> {
            self.recorder
                .borrow_mut()
                .events
                .push(Event::ChmodDir(self.name.clone(), mode));
            Ok(())
        }
    }

    impl FileHandle for FakeFile {
        fn write_all(&mut self, data: &[u8]) -> Result<(), Errno> {
            if let Some(e) = self.write_err {
                return Err(e);
            }
            self.recorder
                .borrow_mut()
                .events
                .push(Event::Write(self.name.clone(), data.to_vec()));
            Ok(())
        }

        fn chown(&self, uid: u32, gid: u32) -> Result<(), Errno> {
            if let Some(e) = self.chown_err {
                return Err(e);
            }
            self.recorder
                .borrow_mut()
                .events
                .push(Event::Chown(self.name.clone(), uid, gid));
            Ok(())
        }

        fn chmod(&self, mode: u32) -> Result<(), Errno> {
            self.recorder
                .borrow_mut()
                .events
                .push(Event::Chmod(self.name.clone(), mode));
            Ok(())
        }
    }

    fn file(path: &str, content: &str, mode: Option<u32>) -> TempFile {
        TempFile {
            path: path.to_string(),
            content: Some(content.to_string()),
            content_b64: None,
            mode,
            owner: None,
        }
    }

    #[test]
    fn symlinked_parent_component_fails_closed() {
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let mut fs = FakeTempFs::new(rec.clone());
        fs.symlink_dirs.push("creds".to_string());
        let files = vec![file("creds/aws.json", "secret", None)];

        let result = write_temp_files_with(&fs, &files, Some((1000, 1000)), &tmp());
        let err = result.unwrap_err();
        assert!(
            err.contains("creds"),
            "error should name the bad component: {err}"
        );

        let events = &rec.borrow().events;
        // No file create, write, chown, or chmod recorded against the target.
        assert!(!events.iter().any(|e| matches!(
            e,
            Event::CreateFile(..) | Event::Write(..) | Event::Chown(..) | Event::Chmod(..)
        )));
    }

    #[test]
    fn existing_final_file_fails_closed() {
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let mut fs = FakeTempFs::new(rec.clone());
        fs.existing_files.push("aws.json".to_string());
        let files = vec![file("aws.json", "secret", None)];

        let result = write_temp_files_with(&fs, &files, Some((1000, 1000)), &tmp());
        assert!(result.is_err());

        let events = &rec.borrow().events;
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, Event::Write(..) | Event::Chown(..) | Event::Chmod(..)))
        );
    }

    #[test]
    fn happy_path_records_mode_and_chown_on_fd() {
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let fs = FakeTempFs::new(rec.clone());
        let files = vec![file("creds/aws.json", "secret", Some(0o640))];

        let written = write_temp_files_with(&fs, &files, Some((1000, 2000)), &tmp()).unwrap();
        assert_eq!(written, vec!["/tmp/creds/aws.json".to_string()]);

        let events = rec.borrow().events.clone();
        assert_eq!(
            events,
            vec![
                Event::MakeDir("creds".to_string(), WAYPOINT_DIR_MODE),
                Event::OpenDir("creds".to_string()),
                Event::CreateFile("aws.json".to_string(), 0o640),
                Event::Write("aws.json".to_string(), b"secret".to_vec()),
                Event::Chmod("aws.json".to_string(), 0o640),
                Event::Chown("aws.json".to_string(), 1000, 2000),
            ]
        );
    }

    #[test]
    fn default_mode_when_unspecified() {
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let fs = FakeTempFs::new(rec.clone());
        let files = vec![file("aws.json", "secret", None)];

        write_temp_files_with(&fs, &files, None, &tmp()).unwrap();
        let events = rec.borrow().events.clone();
        assert!(events.contains(&Event::CreateFile(
            "aws.json".to_string(),
            DEFAULT_FILE_MODE
        )));
        assert!(events.contains(&Event::Chmod("aws.json".to_string(), DEFAULT_FILE_MODE)));
    }

    #[test]
    fn no_creds_creates_but_does_not_chown() {
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let fs = FakeTempFs::new(rec.clone());
        let files = vec![file("aws.json", "secret", None)];

        write_temp_files_with(&fs, &files, None, &tmp()).unwrap();
        let events = rec.borrow().events.clone();
        assert!(events.iter().any(|e| matches!(e, Event::CreateFile(..))));
        assert!(events.iter().any(|e| matches!(e, Event::Write(..))));
        assert!(!events.iter().any(|e| matches!(e, Event::Chown(..))));
    }

    #[test]
    fn intermediate_dir_eexist_tolerated_and_walk_continues() {
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let mut fs = FakeTempFs::new(rec.clone());
        fs.existing_dirs.push("creds".to_string());
        let files = vec![file("creds/aws.json", "secret", None)];

        let written = write_temp_files_with(&fs, &files, None, &tmp()).unwrap();
        assert_eq!(written, vec!["/tmp/creds/aws.json".to_string()]);

        let events = rec.borrow().events.clone();
        // mkdir returned EEXIST (not recorded), but the walk still opened the dir and created the file.
        assert!(events.contains(&Event::OpenDir("creds".to_string())));
        assert!(events.iter().any(|e| matches!(e, Event::CreateFile(..))));
    }

    #[test]
    fn chown_eperm_propagates() {
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let mut fs = FakeTempFs::new(rec.clone());
        fs.chown_err = Some(Errno::EPERM);
        let files = vec![file("aws.json", "secret", None)];

        let result = write_temp_files_with(&fs, &files, Some((1000, 1000)), &tmp());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("chown"));
    }

    #[test]
    fn write_error_propagates() {
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let mut fs = FakeTempFs::new(rec.clone());
        fs.write_err = Some(Errno::EIO);
        let files = vec![file("aws.json", "secret", None)];

        let result = write_temp_files_with(&fs, &files, None, &tmp());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("write"));
    }

    #[test]
    fn partial_failure_rolls_back_already_written_files() {
        // A mid-batch failure must not leave the files created before it on
        // disk: they'd be untracked (never cleaned) and, being O_EXCL, would
        // wedge that path's future refreshes closed forever.
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let mut fs = FakeTempFs::new(rec.clone());
        fs.existing_files.push("second.json".to_string()); // 2nd create hits O_EXCL
        let files = vec![
            file("first.json", "one", None),
            file("second.json", "two", None),
        ];

        let result = write_temp_files_with(&fs, &files, None, &tmp());
        assert!(result.is_err(), "the batch must fail when any file fails");

        let events = rec.borrow().events.clone();
        assert!(
            events.contains(&Event::CreateFile(
                "first.json".to_string(),
                DEFAULT_FILE_MODE
            )),
            "first file should have been created: {events:?}"
        );
        assert!(
            events.contains(&Event::Unlink("first.json".to_string())),
            "the file written before the failure must be rolled back: {events:?}"
        );
    }

    #[test]
    fn remove_unlinks_via_nofollow_walk() {
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let fs = FakeTempFs::new(rec.clone());

        remove_temp_files_with(&fs, &["/tmp/creds/aws.json".to_string()], &tmp());

        let events = rec.borrow().events.clone();
        assert!(events.contains(&Event::OpenDir("creds".to_string())));
        assert!(events.contains(&Event::Unlink("aws.json".to_string())));
    }

    #[test]
    fn remove_skips_symlinked_parent_component() {
        // The cleanup walk must refuse to follow a parent component the agent
        // swapped for a symlink — otherwise the root supervisor's unlink could
        // be redirected at an attacker-chosen target.
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let mut fs = FakeTempFs::new(rec.clone());
        fs.symlink_dirs.push("creds".to_string());

        remove_temp_files_with(&fs, &["/tmp/creds/aws.json".to_string()], &tmp());

        let events = rec.borrow().events.clone();
        assert!(
            !events.iter().any(|e| matches!(e, Event::Unlink(..))),
            "must not unlink through a symlinked parent: {events:?}"
        );
    }

    #[test]
    fn symlinked_parent_under_the_home_root_fails_closed() {
        // Widening the allowed roots must not weaken the component walk: a
        // directory the agent swapped for a symlink between refreshes still
        // stops the root supervisor before it creates anything.
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let mut fs = FakeTempFs::new(rec.clone());
        fs.symlink_dirs.push(".claude".to_string());
        let files = vec![file("~/.claude/.credentials.json", "secret", None)];

        let err = write_temp_files_with(&fs, &files, Some((1000, 1000)), &home_roots())
            .expect_err("a symlinked parent must fail closed");
        assert!(err.contains(".claude"), "{err}");

        let events = &rec.borrow().events;
        assert!(!events.iter().any(|e| matches!(
            e,
            Event::CreateFile(..) | Event::Write(..) | Event::Chown(..) | Event::Chmod(..)
        )));
    }

    #[test]
    fn tilde_path_is_written_under_the_sandbox_home() {
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let fs = FakeTempFs::new(rec.clone());
        let files = vec![file("~/.claude/.credentials.json", "tok", None)];

        let written =
            write_temp_files_with(&fs, &files, Some((1000, 1000)), &home_roots()).unwrap();
        assert_eq!(
            written,
            vec!["/home/sandbox/.claude/.credentials.json".to_string()]
        );
    }

    fn b64(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn binary_file(path: &str, bytes: &[u8]) -> TempFile {
        TempFile {
            path: path.to_string(),
            content: None,
            content_b64: Some(b64(bytes)),
            mode: None,
            owner: None,
        }
    }

    #[test]
    fn base64_content_round_trips_byte_exact() {
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let fs = FakeTempFs::new(rec.clone());
        let bytes: Vec<u8> = vec![0x00, 0xff, 0x80, 0x0a, b'a', 0xc3, 0x28];
        let files = vec![binary_file("blob.bin", &bytes)];

        write_temp_files_with(&fs, &files, None, &tmp()).unwrap();
        let events = rec.borrow().events.clone();
        assert!(
            events.contains(&Event::Write("blob.bin".to_string(), bytes)),
            "{events:?}"
        );
    }

    #[test]
    fn invalid_base64_content_is_refused() {
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let fs = FakeTempFs::new(rec.clone());
        let files = vec![TempFile {
            path: "blob.bin".to_string(),
            content: None,
            content_b64: Some("not base64!!".to_string()),
            mode: None,
            owner: None,
        }];

        let err = write_temp_files_with(&fs, &files, None, &tmp()).unwrap_err();
        assert!(err.contains("contentB64"), "{err}");
        let events = rec.borrow().events.clone();
        assert!(!events.iter().any(|e| matches!(e, Event::CreateFile(..))));
    }

    #[test]
    fn content_and_content_b64_together_is_refused() {
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let fs = FakeTempFs::new(rec.clone());
        let files = vec![TempFile {
            path: "both.json".to_string(),
            content: Some("text".to_string()),
            content_b64: Some(b64(b"bytes")),
            mode: None,
            owner: None,
        }];

        let err = write_temp_files_with(&fs, &files, None, &tmp()).unwrap_err();
        assert!(err.contains("both"), "{err}");
        let events = rec.borrow().events.clone();
        assert!(!events.iter().any(|e| matches!(e, Event::CreateFile(..))));
    }

    #[test]
    fn neither_content_nor_content_b64_is_refused() {
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let fs = FakeTempFs::new(rec.clone());
        let files = vec![TempFile {
            path: "empty.json".to_string(),
            content: None,
            content_b64: None,
            mode: None,
            owner: None,
        }];

        assert!(write_temp_files_with(&fs, &files, None, &tmp()).is_err());
        let events = rec.borrow().events.clone();
        assert!(!events.iter().any(|e| matches!(e, Event::CreateFile(..))));
    }

    #[test]
    fn owner_root_leaves_the_file_root_owned() {
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let fs = FakeTempFs::new(rec.clone());
        let files = vec![TempFile {
            path: "root-only.json".to_string(),
            content: Some("secret".to_string()),
            content_b64: None,
            mode: None,
            owner: Some(FileOwner::Root),
        }];

        write_temp_files_with(&fs, &files, Some((1000, 2000)), &tmp()).unwrap();
        let events = rec.borrow().events.clone();
        assert!(events.iter().any(|e| matches!(e, Event::Write(..))));
        assert!(
            !events.iter().any(|e| matches!(e, Event::Chown(..))),
            "owner root must not chown to the sandbox user: {events:?}"
        );
    }

    #[test]
    fn real_root_walk_refuses_a_symlinked_root_component() {
        // Widening the roots must not hand the agent a followed symlink: the
        // root prefix is walked with O_NOFOLLOW just like the path beneath it.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir_all(real.join("inner")).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert!(RealTempFs.open_root(&real.join("inner")).is_ok());
        let err = RealTempFs
            .open_root(&link.join("inner"))
            .err()
            .expect("a symlinked root component must fail closed");
        assert!(
            matches!(err, Errno::ENOTDIR | Errno::ELOOP),
            "unexpected errno: {err}"
        );
    }

    #[test]
    fn a_created_dir_under_the_home_root_is_handed_to_the_workload() {
        // The motivating case: `~/.claude/.credentials.json`. If `.claude` were
        // left root-owned and traverse-only, the agent could not create
        // `settings.json` or `todos/` beside the delivered file.
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let fs = FakeTempFs::new(rec.clone());
        let files = vec![file("~/.claude/.credentials.json", "tok", None)];

        write_temp_files_with(&fs, &files, Some((1000, 2000)), &home_roots()).unwrap();

        let events = rec.borrow().events.clone();
        assert!(
            events.contains(&Event::MakeDir(".claude".to_string(), WORKLOAD_DIR_MODE)),
            "{events:?}"
        );
        assert!(
            events.contains(&Event::ChmodDir(".claude".to_string(), WORKLOAD_DIR_MODE)),
            "{events:?}"
        );
        assert!(
            events.contains(&Event::ChownDir(".claude".to_string(), 1000, 2000)),
            "{events:?}"
        );
    }

    #[test]
    fn refusing_a_home_that_duplicates_a_root_keeps_the_root() {
        // /tmp is uid 0 in every image, so a passwd home of exactly /tmp always
        // fails the ownership check. Removing the home by value would take the
        // hardcoded default with it and refuse the entire batch.
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let mut fs = FakeTempFs::new(rec.clone());
        fs.dir_uid = 0;
        let roots = FileRoots::default().with_home("/tmp").unwrap();
        let files = vec![file("/tmp/aws.json", "secret", None)];

        let written = write_temp_files_with(&fs, &files, Some((1000, 2000)), &roots).unwrap();

        assert_eq!(written, vec!["/tmp/aws.json"]);
    }

    #[test]
    fn refusing_a_home_that_duplicates_a_root_keeps_the_primary() {
        // The same collateral, seen through a relative path: it resolves under
        // the primary root, which is gone entirely if the refusal over-removes.
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let mut fs = FakeTempFs::new(rec.clone());
        fs.dir_uid = 0;
        let roots = FileRoots::default().with_home("/tmp").unwrap();
        let files = vec![file("aws.json", "secret", None)];

        let written = write_temp_files_with(&fs, &files, Some((1000, 2000)), &roots).unwrap();

        assert_eq!(written, vec!["/tmp/aws.json"]);
    }

    #[test]
    fn a_home_whose_owner_cannot_be_read_is_refused() {
        // The third refusal reason. An fstat that fails leaves the ownership
        // question unanswered, and unanswered is not the same as answered yes.
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let mut fs = FakeTempFs::new(rec.clone());
        fs.owner_uid_err = Some(Errno::EACCES);
        let roots = FileRoots::default().with_home("/etc/cron.d").unwrap();
        let files = vec![file("~/payload", "x", None)];

        let err = write_temp_files_with(&fs, &files, Some((1000, 2000)), &roots).unwrap_err();

        assert!(err.contains("no sandbox home is known"), "got: {err}");
        let events = rec.borrow().events.clone();
        assert!(
            !events.iter().any(|e| matches!(e, Event::CreateFile(..))),
            "a home whose owner we could not read must not be written to: {events:?}"
        );
    }

    #[test]
    fn a_home_is_refused_when_the_sandbox_uid_is_unknown() {
        // Nothing to compare the owner against is not a pass. This module fails
        // closed, and an unverifiable home is exactly the escalation vector the
        // ownership check exists to shut.
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let mut fs = FakeTempFs::new(rec.clone());
        fs.dir_uid = 0;
        let roots = FileRoots::default().with_home("/etc/cron.d").unwrap();
        let files = vec![file("~/payload", "x", None)];

        let err = write_temp_files_with(&fs, &files, None, &roots).unwrap_err();

        assert!(err.contains("no sandbox home is known"), "got: {err}");
        let events = rec.borrow().events.clone();
        assert!(
            !events.iter().any(|e| matches!(e, Event::CreateFile(..))),
            "an unverifiable home must not be written to: {events:?}"
        );
    }

    #[test]
    fn a_home_the_sandbox_user_does_not_own_is_refused_as_a_root() {
        // passwd is image-controlled, so a home can point at a privileged
        // directory. Trusting it would let `owner: root` plant a file there.
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let mut fs = FakeTempFs::new(rec.clone());
        fs.dir_uid = 0;
        let roots = FileRoots::default().with_home("/etc/cron.d").unwrap();
        let files = vec![file("~/payload", "x", None)];

        let err = write_temp_files_with(&fs, &files, Some((1000, 2000)), &roots).unwrap_err();

        assert!(
            err.contains("no sandbox home is known"),
            "the refusal must read as a missing home, not a mangled path: {err}"
        );
        let events = rec.borrow().events.clone();
        assert!(
            !events.iter().any(|e| matches!(e, Event::CreateFile(..))),
            "nothing may land under a home we refused: {events:?}"
        );
    }

    #[test]
    fn a_home_that_is_not_there_is_refused_before_the_walk_reaches_it() {
        // A user made without -m has a passwd home that does not exist. Caught
        // up front it reads as a missing home; left to the walk it surfaces as
        // an ENOENT on a root the operator never named, which is the same
        // outcome described far less usefully.
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let mut fs = FakeTempFs::new(rec.clone());
        fs.unopenable_roots = vec!["/home/sandbox".to_string()];
        let roots = FileRoots::default().with_home("/home/sandbox").unwrap();
        let files = vec![file("~/.claude/creds", "tok", None)];

        let err = write_temp_files_with(&fs, &files, Some((1000, 2000)), &roots).unwrap_err();

        assert!(
            err.contains("no sandbox home is known"),
            "an absent home must read as a missing home, not as a failed walk: {err}"
        );
    }

    #[test]
    fn a_failed_walk_leaves_a_directory_it_did_not_create_alone() {
        // The other half of the undo, and the security-relevant one: a dir that
        // was already there belongs to whoever made it. Removing it on a failure
        // this walk caused would let a policy frame delete a directory it only
        // ever traversed.
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let mut fs = FakeTempFs::new(rec.clone());
        fs.existing_dirs = vec![".claude".to_string()];
        fs.open_err = Some(Errno::EMFILE);
        let roots = FileRoots::default().with_home("/home/sandbox").unwrap();
        let files = vec![file("~/.claude/.credentials.json", "tok", None)];

        let err = write_temp_files_with(&fs, &files, Some((1000, 2000)), &roots).unwrap_err();

        assert!(err.contains("open dir component"), "got: {err}");
        let events = rec.borrow().events.clone();
        assert!(
            !events.iter().any(|e| matches!(e, Event::RemoveDir(_))),
            "a pre-existing directory is not this walk's to remove: {events:?}"
        );
    }

    #[test]
    fn a_failed_open_removes_the_directory_it_just_created() {
        // The sibling edge of the same wedge: mkdir succeeded, so the dir is
        // there, but the open that follows it can fail for reasons that have
        // nothing to do with a swap — EMFILE, ENFILE, ENOMEM. Returning then
        // leaves the same never-handed-over dir behind.
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let mut fs = FakeTempFs::new(rec.clone());
        fs.open_err = Some(Errno::EMFILE);
        let roots = FileRoots::default().with_home("/home/sandbox").unwrap();
        let files = vec![file("~/.claude/.credentials.json", "tok", None)];

        let err = write_temp_files_with(&fs, &files, Some((1000, 2000)), &roots).unwrap_err();

        assert!(err.contains("open dir component"), "got: {err}");
        let events = rec.borrow().events.clone();
        assert!(
            events.contains(&Event::RemoveDir(".claude".to_string())),
            "a created dir must not outlive the walk that failed to finish it: {events:?}"
        );
    }

    #[test]
    fn a_failed_hand_over_removes_the_directory_it_created() {
        // Leaving the dir behind wedges it forever: it is root-owned, and the
        // next refresh sees EEXIST, calls it pre-existing, and by design never
        // retries the hand-over. Removing it lets the next refresh start over.
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let mut fs = FakeTempFs::new(rec.clone());
        fs.chown_err = Some(Errno::EPERM);
        let roots = FileRoots::default().with_home("/home/sandbox").unwrap();
        let files = vec![file("~/.claude/.credentials.json", "tok", None)];

        let err = write_temp_files_with(&fs, &files, Some((1000, 2000)), &roots).unwrap_err();

        assert!(err.contains("chown dir"), "got: {err}");
        let events = rec.borrow().events.clone();
        assert!(
            events.contains(&Event::RemoveDir(".claude".to_string())),
            "a half-handed-over dir must not survive to be mistaken for pre-existing: {events:?}"
        );
    }

    #[test]
    fn a_home_equal_to_an_existing_root_still_binds_to_the_home() {
        // The tie the length comparison cannot see: a passwd home of exactly
        // /tmp duplicates the default root, and taking the earlier one gives
        // ~/.claude the waypoint semantics the home root exists to override.
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let fs = FakeTempFs::new(rec.clone());
        let roots = FileRoots::default().with_home("/tmp").unwrap();
        let files = vec![file("~/.claude/.credentials.json", "tok", None)];

        let written = write_temp_files_with(&fs, &files, Some((1000, 2000)), &roots).unwrap();

        assert_eq!(written, vec!["/tmp/.claude/.credentials.json"]);
        let events = rec.borrow().events.clone();
        assert!(
            events.contains(&Event::ChownDir(".claude".to_string(), 1000, 2000)),
            "the home root was added last and must win the tie: {events:?}"
        );
    }

    #[test]
    fn a_home_nested_inside_another_root_still_binds_to_the_home() {
        // A sandbox user whose passwd home sits under /tmp puts one root inside
        // another. The path must bind to the longest match: taking /tmp instead
        // would give ~/.claude root-owned waypoint semantics and lock the agent
        // out of its own home.
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let fs = FakeTempFs::new(rec.clone());
        let roots = FileRoots::default().with_home("/tmp/sandbox").unwrap();
        let files = vec![file("~/.claude/.credentials.json", "tok", None)];

        let written = write_temp_files_with(&fs, &files, Some((1000, 2000)), &roots).unwrap();

        assert_eq!(written, vec!["/tmp/sandbox/.claude/.credentials.json"]);
        let events = rec.borrow().events.clone();
        assert!(
            events.contains(&Event::MakeDir(".claude".to_string(), WORKLOAD_DIR_MODE)),
            "{events:?}"
        );
        assert!(
            events.contains(&Event::ChownDir(".claude".to_string(), 1000, 2000)),
            "{events:?}"
        );
    }

    #[test]
    fn a_created_dir_under_tmp_stays_a_root_owned_waypoint() {
        // `/tmp` is shared, so its intermediate dirs stay root-owned and
        // unlistable — exactly what this module always did.
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let fs = FakeTempFs::new(rec.clone());
        let files = vec![file("creds/aws.json", "secret", None)];

        write_temp_files_with(&fs, &files, Some((1000, 2000)), &tmp()).unwrap();

        let events = rec.borrow().events.clone();
        assert!(
            events.contains(&Event::MakeDir("creds".to_string(), WAYPOINT_DIR_MODE)),
            "{events:?}"
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, Event::ChmodDir(..) | Event::ChownDir(..))),
            "a /tmp waypoint must stay root-owned: {events:?}"
        );
    }

    #[test]
    fn an_existing_dir_is_never_chowned_or_chmoded() {
        // Handing over a directory the walk did not create would be a
        // privilege-escalation primitive: a policy frame naming `~/..`-free but
        // pre-existing paths could give the workload any directory the root
        // supervisor can traverse.
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let mut fs = FakeTempFs::new(rec.clone());
        fs.existing_dirs.push(".claude".to_string());
        let files = vec![file("~/.claude/.credentials.json", "tok", None)];

        write_temp_files_with(&fs, &files, Some((1000, 2000)), &home_roots()).unwrap();

        let events = rec.borrow().events.clone();
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, Event::ChmodDir(..) | Event::ChownDir(..))),
            "an existing directory must be left alone: {events:?}"
        );
        assert!(events.iter().any(|e| matches!(e, Event::CreateFile(..))));
    }

    #[test]
    fn a_root_owned_file_still_lands_in_a_workload_owned_home_dir() {
        // Directory ownership follows the root the path resolves in, not the
        // file's `owner` — otherwise a root-owned credential file would make its
        // whole parent directory unusable to the agent.
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let fs = FakeTempFs::new(rec.clone());
        let files = vec![TempFile {
            path: "~/.claude/.credentials.json".to_string(),
            content: Some("tok".to_string()),
            content_b64: None,
            mode: None,
            owner: Some(FileOwner::Root),
        }];

        write_temp_files_with(&fs, &files, Some((1000, 2000)), &home_roots()).unwrap();

        let events = rec.borrow().events.clone();
        assert!(
            events.contains(&Event::ChownDir(".claude".to_string(), 1000, 2000)),
            "{events:?}"
        );
        assert!(
            !events.iter().any(|e| matches!(e, Event::Chown(..))),
            "the file itself stays root-owned: {events:?}"
        );
    }

    #[test]
    fn remove_reports_a_path_it_can_no_longer_resolve() {
        // A file written under an older root policy would otherwise be skipped
        // in silence and never cleaned up.
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let fs = FakeTempFs::new(rec.clone());

        let unresolved = remove_temp_files_with(
            &fs,
            &["/tmp/a.json".to_string(), "/var/old.json".to_string()],
            &tmp(),
        );

        assert_eq!(unresolved.len(), 1, "{unresolved:?}");
        assert!(unresolved[0].contains("/var/old.json"), "{unresolved:?}");
        let events = rec.borrow().events.clone();
        assert!(events.contains(&Event::Unlink("a.json".to_string())));
    }

    #[test]
    fn owner_workload_chowns_like_the_default() {
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let fs = FakeTempFs::new(rec.clone());
        let files = vec![TempFile {
            path: "workload.json".to_string(),
            content: Some("secret".to_string()),
            content_b64: None,
            mode: None,
            owner: Some(FileOwner::Workload),
        }];

        write_temp_files_with(&fs, &files, Some((1000, 2000)), &tmp()).unwrap();
        let events = rec.borrow().events.clone();
        assert!(events.contains(&Event::Chown("workload.json".to_string(), 1000, 2000)));
    }
}
