use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tokio::fs;

use crate::privilege::SandboxCredentials;
use crate::protocol::TempFile;

const TEMP_BASE: &str = "/tmp";

/// Validate that a temp file path is safe: must be inside /tmp,
/// must not contain `..`.
fn safe_temp_path(requested: &str) -> Result<PathBuf, String> {
    // Reject paths with `..` components
    if requested.contains("..") {
        return Err(format!("temp file path contains '..': {requested}"));
    }

    let path = Path::new(requested);

    // If the path is already under /tmp, use it as-is
    if path.starts_with(TEMP_BASE) {
        return Ok(path.to_path_buf());
    }

    // Reject absolute paths outside /tmp
    if path.is_absolute() {
        return Err(format!(
            "temp file path must be relative or under {TEMP_BASE}: {requested}"
        ));
    }

    // Relative paths are placed under /tmp
    Ok(Path::new(TEMP_BASE).join(path))
}

pub async fn write_temp_files(
    files: &[TempFile],
    sandbox_creds: Option<&SandboxCredentials>,
) -> Result<Vec<String>, String> {
    let mut written = Vec::with_capacity(files.len());
    for f in files {
        let path = safe_temp_path(&f.path)?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        fs::write(&path, &f.content)
            .await
            .map_err(|e| format!("write {}: {e}", path.display()))?;
        let mode = f.mode.unwrap_or(0o600);
        fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .await
            .map_err(|e| format!("chmod {}: {e}", path.display()))?;

        // Chown to sandbox user so the unprivileged process can read the file
        if let Some(creds) = sandbox_creds {
            let (uid, gid) = creds.uid_gid();
            nix::unistd::chown(&path, Some(uid), Some(gid))
                .map_err(|e| format!("chown {}: {e}", path.display()))?;
        }

        written.push(path.to_string_lossy().to_string());
    }
    Ok(written)
}

pub async fn cleanup_temp_files(paths: &[String]) {
    for path in paths {
        let _ = fs::remove_file(path).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_relative_path() {
        let result = safe_temp_path("creds/aws.json").unwrap();
        assert_eq!(result, PathBuf::from("/tmp/creds/aws.json"));
    }

    #[test]
    fn safe_already_under_tmp() {
        let result = safe_temp_path("/tmp/lens-sandbox/creds/aws.json").unwrap();
        assert_eq!(result, PathBuf::from("/tmp/lens-sandbox/creds/aws.json"));
    }

    #[test]
    fn safe_sandbox_kubeconfig() {
        let result = safe_temp_path("/tmp/sandbox-kubeconfig-abc123").unwrap();
        assert_eq!(result, PathBuf::from("/tmp/sandbox-kubeconfig-abc123"));
    }

    #[test]
    fn reject_dotdot() {
        assert!(safe_temp_path("../etc/passwd").is_err());
    }

    #[test]
    fn reject_absolute_outside_tmp() {
        assert!(safe_temp_path("/etc/passwd").is_err());
    }

    #[test]
    fn reject_dotdot_in_tmp() {
        assert!(safe_temp_path("/tmp/../etc/passwd").is_err());
    }
}
