//! What the runtime reads from its environment.

use std::io;
use std::path::PathBuf;

use tonic::transport::Uri;

const SUPERVISOR: &str = "LENS_SANDBOX_SUPERVISOR";
const CHANNEL_DIR: &str = "LENS_SANDBOX_CHANNEL_DIR";
const CA_BUNDLE: &str = "LENS_SANDBOX_CA_BUNDLE";

/// Inside the private root, which Landlock hides from the workload.
const DEFAULT_CHANNEL_DIR: &str = "/.lens/channel";
/// Outside the private root, so that the workload can read it.
const DEFAULT_CA_BUNDLE: &str = "/tmp/lens-sandbox/ca-bundle.pem";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Supervisor {
    Tcp(Uri),
    Unix(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub supervisor: Supervisor,
    /// Holds `ca.pem`, `cert.pem` and `key.pem` of the channel.
    pub channel_dir: PathBuf,
    pub ca_bundle: PathBuf,
}

impl RuntimeConfig {
    pub fn from_env() -> io::Result<Self> {
        Self::from_vars(|name| std::env::var(name).ok())
    }

    fn from_vars(var: impl Fn(&str) -> Option<String>) -> io::Result<Self> {
        let supervisor = var(SUPERVISOR)
            .ok_or_else(|| invalid(format!("{SUPERVISOR} is not set")))
            .and_then(|value| parse_supervisor(&value))?;
        Ok(Self {
            supervisor,
            channel_dir: var(CHANNEL_DIR).map_or_else(|| DEFAULT_CHANNEL_DIR.into(), PathBuf::from),
            ca_bundle: var(CA_BUNDLE).map_or_else(|| DEFAULT_CA_BUNDLE.into(), PathBuf::from),
        })
    }
}

/// `https://host:port`, or `unix:/path` for a socket on a shared volume. The
/// channel is always TLS, so plain `http` is refused.
fn parse_supervisor(value: &str) -> io::Result<Supervisor> {
    if let Some(path) = value.strip_prefix("unix:") {
        let path = path.strip_prefix("//").unwrap_or(path);
        return if path.starts_with('/') {
            Ok(Supervisor::Unix(path.into()))
        } else {
            Err(invalid(format!(
                "{SUPERVISOR} needs an absolute socket path"
            )))
        };
    }
    let uri: Uri = value
        .parse()
        .map_err(|e| invalid(format!("{SUPERVISOR} is not a URI: {e}")))?;
    if uri.scheme_str() != Some("https") {
        return Err(invalid(format!("{SUPERVISOR} must be https or unix")));
    }
    Ok(Supervisor::Tcp(uri))
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(vars: &[(&str, &str)]) -> io::Result<RuntimeConfig> {
        let vars: HashMap<_, _> = vars.iter().copied().collect();
        RuntimeConfig::from_vars(|name| vars.get(name).map(|value| value.to_string()))
    }

    #[test]
    fn only_the_supervisor_is_required() {
        let config = config(&[(SUPERVISOR, "https://supervisor:7443")]).unwrap();
        assert_eq!(
            config,
            RuntimeConfig {
                supervisor: Supervisor::Tcp("https://supervisor:7443".parse().unwrap()),
                channel_dir: DEFAULT_CHANNEL_DIR.into(),
                ca_bundle: DEFAULT_CA_BUNDLE.into(),
            }
        );
        assert!(config_error(&[]).contains(SUPERVISOR));
    }

    #[test]
    fn a_unix_supervisor_takes_both_spellings() {
        for value in [
            "unix:/run/lens/channel.sock",
            "unix:///run/lens/channel.sock",
        ] {
            assert_eq!(
                config(&[(SUPERVISOR, value)]).unwrap().supervisor,
                Supervisor::Unix("/run/lens/channel.sock".into())
            );
        }
    }

    #[test]
    fn a_supervisor_without_tls_or_an_absolute_path_is_refused() {
        for value in ["http://supervisor:7443", "unix:channel.sock", "not a uri"] {
            assert!(config_error(&[(SUPERVISOR, value)]).contains(SUPERVISOR));
        }
    }

    #[test]
    fn the_paths_can_be_moved() {
        let config = config(&[
            (SUPERVISOR, "https://supervisor:7443"),
            (CHANNEL_DIR, "/secrets/channel"),
            (CA_BUNDLE, "/var/lens/ca.pem"),
        ])
        .unwrap();
        assert_eq!(config.channel_dir, PathBuf::from("/secrets/channel"));
        assert_eq!(config.ca_bundle, PathBuf::from("/var/lens/ca.pem"));
    }

    fn config_error(vars: &[(&str, &str)]) -> String {
        config(vars).unwrap_err().to_string()
    }
}
