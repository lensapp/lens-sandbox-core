use std::collections::HashMap;
use std::ffi::OsString;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;

use nix::errno::Errno;
use nix::fcntl::OFlag;

#[cfg(target_os = "linux")]
const PIN_FLAGS: OFlag = OFlag::O_PATH
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);
#[cfg(not(target_os = "linux"))]
const PIN_FLAGS: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);

/// Where each trusted mount sat when it was read; a directory on a mount made or moved since is not trusted.
#[derive(Debug, Default)]
pub struct MountPoints {
    points: HashMap<u64, Vec<OsString>>,
    /// A mount with an open fd keeps its id, so the kernel cannot hand that id to a new mount.
    _pins: Vec<OwnedFd>,
}

impl MountPoints {
    pub fn current() -> std::io::Result<Self> {
        let listed = Self::parse(&std::fs::read("/proc/self/mountinfo")?);
        let mut pinned = Self::default();
        for point in listed.points.into_values() {
            let path = std::path::Path::new("/").join(point.iter().collect::<std::path::PathBuf>());
            let Ok(pin) = nix::fcntl::open(&path, PIN_FLAGS, nix::sys::stat::Mode::empty()) else {
                continue;
            };
            let Ok(id) = mount_id(std::os::fd::AsFd::as_fd(&pin)) else {
                continue;
            };
            pinned.points.insert(id, point);
            pinned._pins.push(pin);
        }
        Ok(pinned)
    }

    pub(crate) fn parse(mountinfo: &[u8]) -> Self {
        Self {
            points: mountinfo
                .split(|b| *b == b'\n')
                .filter_map(|line| {
                    let mut fields = line.split(|b| *b == b' ');
                    let id = std::str::from_utf8(fields.next()?).ok()?.parse().ok()?;
                    let point = fields.nth(3)?;
                    Some((id, components(&unescape(point))))
                })
                .collect(),
            _pins: Vec::new(),
        }
    }

    pub(crate) fn holds(&self, mount_id: u64, path: &[OsString]) -> bool {
        self.points
            .get(&mount_id)
            .is_some_and(|point| path.starts_with(point))
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn mount_id(fd: BorrowedFd) -> Result<u64, Errno> {
    use std::os::fd::AsRawFd;
    let mut stx = std::mem::MaybeUninit::<libc::statx>::zeroed();
    // SAFETY: the fd is open, the path is an empty NUL-terminated string, and statx writes only into `stx`.
    let rc = unsafe {
        libc::statx(
            fd.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_MNT_ID,
            stx.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(Errno::last());
    }
    // SAFETY: `stx` started zeroed and statx succeeded, so every field holds a valid integer.
    let stx = unsafe { stx.assume_init() };
    if stx.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(Errno::ENOSYS);
    }
    Ok(stx.stx_mnt_id)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn mount_id(_fd: BorrowedFd) -> Result<u64, Errno> {
    Err(Errno::ENOSYS)
}

/// mountinfo writes a space, tab, newline and backslash in a path as a three-digit octal escape.
fn unescape(field: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(field.len());
    let mut rest = field;
    while let Some((&byte, tail)) = rest.split_first() {
        let octal = tail
            .get(..3)
            .and_then(|digits| std::str::from_utf8(digits).ok())
            .and_then(|digits| u8::from_str_radix(digits, 8).ok());
        match (byte, octal) {
            (b'\\', Some(decoded)) => {
                out.push(decoded);
                rest = &tail[3..];
            }
            _ => {
                out.push(byte);
                rest = tail;
            }
        }
    }
    out
}

fn components(path: &[u8]) -> Vec<OsString> {
    path.split(|b| *b == b'/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| OsString::from_vec(segment.to_vec()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(text: &str) -> Vec<OsString> {
        components(text.as_bytes())
    }

    const MOUNTINFO: &[u8] = b"21 1 0:20 / / rw,relatime - overlay overlay rw\n\
        22 21 0:21 / /tmp rw - tmpfs tmpfs rw\n\
        23 21 0:22 / /work rw - virtiofs share0 rw\n\
        24 21 0:23 / /home/my\\040files rw - tmpfs tmpfs rw\n";

    #[test]
    fn a_mount_holds_the_paths_at_and_below_where_it_sat() {
        let mounts = MountPoints::parse(MOUNTINFO);
        assert!(mounts.holds(22, &path("/tmp")));
        assert!(mounts.holds(22, &path("/tmp/a/b")));
        assert!(mounts.holds(21, &path("/root/.provider")));
    }

    #[test]
    fn a_mount_moved_away_from_where_it_sat_holds_nothing_there() {
        let mounts = MountPoints::parse(MOUNTINFO);
        assert!(
            !mounts.holds(23, &path("/root/.provider")),
            "a share moved over a home directory keeps its id, so the id alone must not admit it"
        );
    }

    #[test]
    fn a_mount_made_after_the_snapshot_holds_nothing() {
        assert!(!MountPoints::parse(MOUNTINFO).holds(99, &path("/tmp/x")));
    }

    #[test]
    fn an_escaped_mount_point_is_read_as_the_path_it_names() {
        let mounts = MountPoints::parse(MOUNTINFO);
        assert!(mounts.holds(24, &path("/home/my files/x")));
    }

    #[test]
    fn a_line_without_a_mount_id_or_point_admits_nothing() {
        let mounts = MountPoints::parse(b"garbage\n7\n\n");
        assert!(!mounts.holds(7, &path("/")));
    }

    #[test]
    fn a_backslash_without_an_octal_escape_is_kept() {
        assert_eq!(unescape(b"a\\x\\0"), b"a\\x\\0");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn every_mount_the_snapshot_trusts_is_pinned_by_an_open_fd() {
        use std::os::fd::AsFd;
        let mounts = MountPoints::current().unwrap();
        let pinned: std::collections::HashSet<u64> = mounts
            ._pins
            .iter()
            .map(|pin| mount_id(pin.as_fd()).unwrap())
            .collect();
        assert!(!mounts.points.is_empty());
        assert!(
            mounts.points.keys().all(|id| pinned.contains(id)),
            "an id with no open fd can be freed by an unmount and given to a new mount at the same place"
        );
    }

    #[test]
    fn no_mounts_admit_nothing() {
        assert!(!MountPoints::default().holds(21, &path("/tmp")));
    }
}
