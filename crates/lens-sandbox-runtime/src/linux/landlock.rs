// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// Changed for lens-sandbox-runtime: only the self-protection baseline, with
// `io::Error` in place of miette, and `.lens` as the private root.

//! The Landlock baseline that hides the runtime's private root from the
//! workload.

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

use landlock::{
    ABI, Access, AccessFs, BitFlags, CompatLevel, Compatible, PathBeneath, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr,
};

pub(crate) const PRIVATE_ROOT: &str = ".lens";

/// Landlock is allow-list only. Granting `/` would also grant the private
/// `/.lens` subtree, so enumerate the root's children and omit that one
/// hierarchy. Entries this uid cannot open are already inaccessible and are
/// omitted.
pub(crate) fn prepare_baseline() -> io::Result<RulesetCreated> {
    prepare_baseline_at(Path::new("/"))
}

fn prepare_baseline_at(root: &Path) -> io::Result<RulesetCreated> {
    // Self-protection must cover pathname truncation as well as opens. Never
    // silently downgrade this ABI requirement.
    let abi = ABI::V3;
    let access = AccessFs::from_all(abi);
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(access)
        .map_err(io::Error::other)?
        .create()
        .map_err(io::Error::other)?;
    let entries = baseline_entries(root)?;
    if entries.is_empty() {
        return Err(io::Error::other(
            "Landlock baseline found no usable root entries",
        ));
    }
    for (_, fd) in entries {
        let allowed = access_for_path_fd(&fd, access, abi)?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, allowed))
            .map_err(io::Error::other)?;
    }
    Ok(ruleset)
}

fn baseline_entries(root: &Path) -> io::Result<Vec<(PathBuf, OwnedFd)>> {
    use rustix::fs::{Mode, OFlags, open, openat};

    let root_fd = open(
        root,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    // The reserved root itself must not redirect private child mounts into an
    // allowed subtree. Pin and validate it independently of the public entries.
    let _private_root = match openat(
        &root_fd,
        PRIVATE_ROOT,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Some(fd),
        Err(rustix::io::Errno::NOENT) => None,
        Err(error) => {
            return Err(io::Error::other(format!(
                "private sandbox root must be a real directory: {error}"
            )));
        }
    };
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_name() == PRIVATE_ROOT {
            continue;
        }
        // Open relative to the pinned root and classify this exact descriptor.
        // O_PATH|O_NOFOLLOW opens a symlink itself, never its target. A root
        // alias to `/` or `/.lens` therefore cannot broaden the allowlist.
        let fd = match openat(
            &root_fd,
            entry.file_name(),
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT | rustix::io::Errno::ACCESS) => continue,
            Err(error) => return Err(error.into()),
        };
        let stat = rustix::fs::fstat(&fd)?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) == rustix::fs::FileType::Symlink {
            continue;
        }
        entries.push((entry.path(), fd));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

/// Tailor a rule's access mask to the inode referenced by its already-open FD.
///
/// Landlock directory-only rights such as `ReadDir` are invalid for regular
/// files and device nodes in hard-requirement mode. Classifying through the
/// same `PathFd` used by the rule avoids a pathname TOCTOU race.
fn access_for_path_fd(
    path_fd: &impl AsFd,
    requested_access: BitFlags<AccessFs>,
    abi: ABI,
) -> io::Result<BitFlags<AccessFs>> {
    let stat = rustix::fs::fstat(path_fd.as_fd())?;
    Ok(match rustix::fs::FileType::from_raw_mode(stat.st_mode) {
        rustix::fs::FileType::Directory => requested_access,
        _ => requested_access & AccessFs::from_file(abi),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn landlock_v3() -> bool {
        // SAFETY: the VERSION operation takes a null ruleset and zero size.
        #[allow(unsafe_code)]
        let abi = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<libc::c_void>(),
                0,
                1_u32,
            )
        };
        abi >= 3
    }

    #[test]
    fn baseline_omits_only_private_root() {
        let root = tempfile::tempdir().unwrap();
        for name in ["bin", "etc", "sandbox", PRIVATE_ROOT] {
            std::fs::create_dir(root.path().join(name)).unwrap();
        }

        std::os::unix::fs::symlink(root.path(), root.path().join("root-alias")).unwrap();
        std::os::unix::fs::symlink(
            root.path().join(PRIVATE_ROOT),
            root.path().join("private-alias"),
        )
        .unwrap();
        let paths: Vec<_> = baseline_entries(root.path())
            .unwrap()
            .into_iter()
            .map(|(path, _)| path)
            .collect();
        assert_eq!(
            paths,
            ["bin", "etc", "sandbox"]
                .map(|name| root.path().join(name))
                .to_vec()
        );
    }

    #[test]
    fn baseline_rejects_private_root_redirect() {
        let root = tempfile::tempdir().unwrap();
        let public = root.path().join("public");
        let private = root.path().join(PRIVATE_ROOT);
        std::fs::create_dir(&public).unwrap();
        std::fs::write(public.join("secret"), b"private mount contents").unwrap();
        std::os::unix::fs::symlink(&public, &private).unwrap();
        assert!(baseline_entries(root.path()).is_err());
        std::fs::remove_file(&private).unwrap();
        std::fs::write(&private, b"not a directory").unwrap();
        assert!(baseline_entries(root.path()).is_err());
    }

    #[test]
    fn baseline_denies_alias_reads_and_path_truncation() {
        if !landlock_v3() {
            eprintln!("skipping: needs Landlock ABI 3");
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let public = root.path().join("public");
        let private = root.path().join(PRIVATE_ROOT);
        std::fs::create_dir(&public).unwrap();
        std::fs::create_dir(&private).unwrap();
        std::fs::write(public.join("sentinel"), b"allowed").unwrap();
        std::fs::write(private.join("secret"), b"protected").unwrap();
        std::os::unix::fs::symlink(root.path(), root.path().join("root-alias")).unwrap();
        std::os::unix::fs::symlink(&private, root.path().join("private-alias")).unwrap();
        let path = root.path().to_path_buf();
        std::thread::spawn(move || {
            prepare_baseline_at(&path).unwrap().restrict_self().unwrap();
            assert_eq!(
                std::fs::read(path.join("public/sentinel")).unwrap(),
                b"allowed"
            );
            for name in [
                ".lens/secret",
                "root-alias/.lens/secret",
                "private-alias/secret",
            ] {
                let target = path.join(name);
                assert_eq!(
                    std::fs::read(&target).unwrap_err().kind(),
                    std::io::ErrorKind::PermissionDenied
                );
                let target = std::ffi::CString::new(target.as_os_str().as_encoded_bytes()).unwrap();
                // SAFETY: target is a live, NUL-terminated path. The syscall
                // tests pathname truncation without opening a file first.
                #[allow(unsafe_code)]
                let result = unsafe { libc::truncate(target.as_ptr(), 0) };
                assert_eq!(result, -1);
                assert_eq!(
                    std::io::Error::last_os_error().kind(),
                    std::io::ErrorKind::PermissionDenied
                );
            }
        })
        .join()
        .unwrap();
        assert_eq!(std::fs::read(private.join("secret")).unwrap(), b"protected");
    }
}
