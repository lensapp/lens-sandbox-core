use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

use nix::errno::Errno;

use crate::privilege::SandboxCredentials;
use crate::protocol::TempFile;

const TEMP_BASE: &str = "/tmp";
const DEFAULT_FILE_MODE: u32 = 0o600;
const DIR_MODE: u32 = 0o700;

/// Validate a temp file path lexically and return its base-relative component
/// sequence. Every separator-delimited segment must be a normal name; `..`,
/// `.`, and empty segments (from a leading slash or `//`) are rejected so no
/// component can redirect the directory walk. Legacy absolute `/tmp/...` inputs
/// are accepted by stripping the base prefix; absolute paths outside the base
/// are rejected.
fn safe_temp_path(requested: &str) -> Result<Vec<OsString>, String> {
    let path = Path::new(requested);

    let relative = if path.is_absolute() {
        path.strip_prefix(TEMP_BASE).map_err(|_| {
            format!("temp file path must be relative or under {TEMP_BASE}: {requested}")
        })?
    } else {
        path
    };

    let mut components = Vec::new();
    for segment in relative.as_os_str().as_bytes().split(|b| *b == b'/') {
        if segment.is_empty() || segment == b"." || segment == b".." {
            return Err(format!(
                "temp file path contains an unsafe component: {requested}"
            ));
        }
        components.push(OsString::from_vec(segment.to_vec()));
    }

    if components.is_empty() {
        return Err(format!("temp file path is empty: {requested}"));
    }

    Ok(components)
}

/// Port over the directory-walk + file-create syscalls so symlink rejection,
/// EEXIST tolerance, O_EXCL collisions, chown, and chmod are unit-testable
/// without root or a real filesystem.
trait TempFs {
    fn open_base(&self) -> Result<Box<dyn DirHandle>, Errno>;
}

trait DirHandle {
    fn open_child_dir(&self, name: &OsStr) -> Result<Box<dyn DirHandle>, Errno>;
    fn make_child_dir(&self, name: &OsStr, mode: u32) -> Result<(), Errno>;
    fn create_child_file(&self, name: &OsStr, mode: u32) -> Result<Box<dyn FileHandle>, Errno>;
}

trait FileHandle {
    fn write_all(&mut self, data: &[u8]) -> Result<(), Errno>;
    fn chown(&self, uid: u32, gid: u32) -> Result<(), Errno>;
    fn chmod(&self, mode: u32) -> Result<(), Errno>;
}

pub async fn write_temp_files(
    files: &[TempFile],
    sandbox_creds: Option<&SandboxCredentials>,
) -> Result<Vec<String>, String> {
    let creds = sandbox_creds.map(|c| {
        let (uid, gid) = c.uid_gid();
        (uid.as_raw(), gid.as_raw())
    });
    write_temp_files_with(&RealTempFs, files, creds)
}

fn write_temp_files_with(
    fs: &dyn TempFs,
    files: &[TempFile],
    creds: Option<(u32, u32)>,
) -> Result<Vec<String>, String> {
    let mut written = Vec::with_capacity(files.len());
    for f in files {
        let components = safe_temp_path(&f.path)?;
        let written_path = write_one(fs, &components, &f.content, f.mode, creds)?;
        written.push(written_path);
    }
    Ok(written)
}

fn write_one(
    fs: &dyn TempFs,
    components: &[OsString],
    content: &str,
    mode: Option<u32>,
    creds: Option<(u32, u32)>,
) -> Result<String, String> {
    let display = render_path(components);
    let mut dir = fs
        .open_base()
        .map_err(|e| format!("open base {TEMP_BASE}: {e}"))?;

    let (file_name, dir_components) = components
        .split_last()
        .ok_or_else(|| format!("temp file path is empty: {display}"))?;

    for comp in dir_components {
        match dir.make_child_dir(comp, DIR_MODE) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(e) => {
                return Err(format!("mkdir {}: {e}", comp.to_string_lossy()));
            }
        }
        dir = dir.open_child_dir(comp).map_err(|e| {
            format!(
                "open dir component {} under {TEMP_BASE}: {e}",
                comp.to_string_lossy()
            )
        })?;
    }

    let file_mode = mode.unwrap_or(DEFAULT_FILE_MODE);
    let mut file = dir
        .create_child_file(file_name, file_mode)
        .map_err(|e| format!("create {display}: {e}"))?;

    file.write_all(content.as_bytes())
        .map_err(|e| format!("write {display}: {e}"))?;
    file.chmod(file_mode)
        .map_err(|e| format!("chmod {display}: {e}"))?;

    if let Some((uid, gid)) = creds {
        file.chown(uid, gid)
            .map_err(|e| format!("chown {display}: {e}"))?;
    }

    Ok(display)
}

fn render_path(components: &[OsString]) -> String {
    let mut path = std::path::PathBuf::from(TEMP_BASE);
    for comp in components {
        path.push(comp);
    }
    path.to_string_lossy().to_string()
}

pub async fn cleanup_temp_files(paths: &[String]) {
    for path in paths {
        let _ = tokio::fs::remove_file(path).await;
    }
}

struct RealTempFs;

struct RealDir(std::os::fd::OwnedFd);

struct RealFile(std::os::fd::OwnedFd);

impl TempFs for RealTempFs {
    fn open_base(&self) -> Result<Box<dyn DirHandle>, Errno> {
        let fd = open_dir_nofollow(&nix::fcntl::AT_FDCWD, TEMP_BASE)?;
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
}

impl FileHandle for RealFile {
    fn write_all(&mut self, mut data: &[u8]) -> Result<(), Errno> {
        while !data.is_empty() {
            let n = nix::unistd::write(&self.0, data)?;
            if n == 0 {
                return Err(Errno::EIO);
            }
            data = &data[n..];
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

    #[test]
    fn safe_relative_path() {
        let result = safe_temp_path("creds/aws.json").unwrap();
        assert_eq!(
            result,
            vec![OsString::from("creds"), OsString::from("aws.json")]
        );
    }

    #[test]
    fn safe_already_under_tmp() {
        let result = safe_temp_path("/tmp/lens-sandbox/creds/aws.json").unwrap();
        assert_eq!(
            result,
            vec![
                OsString::from("lens-sandbox"),
                OsString::from("creds"),
                OsString::from("aws.json")
            ]
        );
    }

    #[test]
    fn safe_sandbox_kubeconfig() {
        let result = safe_temp_path("/tmp/sandbox-kubeconfig-abc123").unwrap();
        assert_eq!(result, vec![OsString::from("sandbox-kubeconfig-abc123")]);
    }

    #[test]
    fn reject_dotdot_component() {
        assert!(safe_temp_path("../etc/passwd").is_err());
    }

    #[test]
    fn reject_dotdot_mid_path() {
        assert!(safe_temp_path("creds/../../etc/passwd").is_err());
    }

    #[test]
    fn reject_single_dot_component() {
        assert!(safe_temp_path("creds/./aws.json").is_err());
    }

    #[test]
    fn reject_absolute_outside_tmp() {
        assert!(safe_temp_path("/etc/passwd").is_err());
    }

    #[test]
    fn reject_dotdot_in_tmp() {
        assert!(safe_temp_path("/tmp/../etc/passwd").is_err());
    }

    #[test]
    fn reject_empty_path() {
        assert!(safe_temp_path("").is_err());
        assert!(safe_temp_path("/tmp").is_err());
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Event {
        MakeDir(String, u32),
        OpenDir(String),
        CreateFile(String, u32),
        Write(String, Vec<u8>),
        Chmod(String, u32),
        Chown(String, u32, u32),
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
            }
        }
    }

    struct FakeDir {
        recorder: Rc<RefCell<Recorder>>,
        symlink_dirs: Vec<String>,
        existing_files: Vec<String>,
        existing_dirs: Vec<String>,
        chown_err: Option<Errno>,
        write_err: Option<Errno>,
    }

    struct FakeFile {
        recorder: Rc<RefCell<Recorder>>,
        name: String,
        chown_err: Option<Errno>,
        write_err: Option<Errno>,
    }

    impl TempFs for FakeTempFs {
        fn open_base(&self) -> Result<Box<dyn DirHandle>, Errno> {
            Ok(Box::new(FakeDir {
                recorder: self.recorder.clone(),
                symlink_dirs: self.symlink_dirs.clone(),
                existing_files: self.existing_files.clone(),
                existing_dirs: self.existing_dirs.clone(),
                chown_err: self.chown_err,
                write_err: self.write_err,
            }))
        }
    }

    impl DirHandle for FakeDir {
        fn open_child_dir(&self, name: &OsStr) -> Result<Box<dyn DirHandle>, Errno> {
            let n = name.to_string_lossy().to_string();
            if self.symlink_dirs.contains(&n) {
                return Err(Errno::ELOOP);
            }
            self.recorder.borrow_mut().events.push(Event::OpenDir(n));
            Ok(Box::new(FakeDir {
                recorder: self.recorder.clone(),
                symlink_dirs: self.symlink_dirs.clone(),
                existing_files: self.existing_files.clone(),
                existing_dirs: self.existing_dirs.clone(),
                chown_err: self.chown_err,
                write_err: self.write_err,
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
            content: content.to_string(),
            mode,
        }
    }

    #[test]
    fn symlinked_parent_component_fails_closed() {
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let mut fs = FakeTempFs::new(rec.clone());
        fs.symlink_dirs.push("creds".to_string());
        let files = vec![file("creds/aws.json", "secret", None)];

        let result = write_temp_files_with(&fs, &files, Some((1000, 1000)));
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

        let result = write_temp_files_with(&fs, &files, Some((1000, 1000)));
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

        let written = write_temp_files_with(&fs, &files, Some((1000, 2000))).unwrap();
        assert_eq!(written, vec!["/tmp/creds/aws.json".to_string()]);

        let events = rec.borrow().events.clone();
        assert_eq!(
            events,
            vec![
                Event::MakeDir("creds".to_string(), DIR_MODE),
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

        write_temp_files_with(&fs, &files, None).unwrap();
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

        write_temp_files_with(&fs, &files, None).unwrap();
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

        let written = write_temp_files_with(&fs, &files, None).unwrap();
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

        let result = write_temp_files_with(&fs, &files, Some((1000, 1000)));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("chown"));
    }

    #[test]
    fn write_error_propagates() {
        let rec = Rc::new(RefCell::new(Recorder::default()));
        let mut fs = FakeTempFs::new(rec.clone());
        fs.write_err = Some(Errno::EIO);
        let files = vec![file("aws.json", "secret", None)];

        let result = write_temp_files_with(&fs, &files, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("write"));
    }
}
