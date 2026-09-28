//! The trust bundle of the workload: the system roots and the proxy CA.

use std::fs::Permissions;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Replaces `bundle` in one rename, so a process never reads half a bundle.
/// A missing system bundle leaves only the proxy CA.
pub(crate) fn write_bundle(bundle: &Path, system: &Path, ca_pem: &str) -> io::Result<()> {
    let mut contents = match std::fs::read(system) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error),
    };
    contents.push(b'\n');
    contents.extend_from_slice(ca_pem.trim_end().as_bytes());
    contents.push(b'\n');
    let dir = bundle
        .parent()
        .ok_or_else(|| io::Error::other("the CA bundle path has no directory"))?;
    std::fs::create_dir_all(dir)?;
    let mut staged = tempfile::NamedTempFile::new_in(dir)?;
    staged.write_all(&contents)?;
    staged
        .as_file()
        .set_permissions(Permissions::from_mode(0o644))?;
    staged.persist(bundle).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROXY_CA: &str = "-----BEGIN CERTIFICATE-----\nproxy\n-----END CERTIFICATE-----\n";

    #[test]
    fn the_bundle_holds_the_system_roots_and_the_proxy_ca() {
        let dir = tempfile::tempdir().unwrap();
        let system = dir.path().join("system.pem");
        std::fs::write(&system, "roots\n").unwrap();
        let bundle = dir.path().join("lens/ca-bundle.pem");
        write_bundle(&bundle, &system, PROXY_CA).unwrap();
        assert_eq!(
            std::fs::read_to_string(&bundle).unwrap(),
            format!("roots\n\n{PROXY_CA}")
        );
    }

    #[test]
    fn a_new_proxy_ca_replaces_the_old_one() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path().join("ca-bundle.pem");
        let no_system = dir.path().join("missing.pem");
        write_bundle(&bundle, &no_system, "old").unwrap();
        write_bundle(&bundle, &no_system, PROXY_CA).unwrap();
        assert_eq!(
            std::fs::read_to_string(&bundle).unwrap(),
            format!("\n{PROXY_CA}")
        );
    }
}
