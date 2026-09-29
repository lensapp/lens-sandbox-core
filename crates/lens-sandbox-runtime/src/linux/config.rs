//! What the runtime reads from its environment.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

const LISTEN: &str = "LENS_SANDBOX_LISTEN";
const CA_BUNDLE: &str = "LENS_SANDBOX_CA_BUNDLE";

/// Outside the private root, so that the workload can read it.
const DEFAULT_CA_BUNDLE: &str = "/tmp/lens-sandbox/ca-bundle.pem";

/// Where the runtime serves the channel for its supervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listen {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl Listen {
    /// The broker refuses a workload `connect()` to this port on any
    /// address, so the workload cannot reach the channel.
    pub fn protected_port(&self) -> Option<u16> {
        match self {
            Listen::Tcp(address) => Some(address.port()),
            Listen::Unix(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub listen: Listen,
    pub ca_bundle: PathBuf,
}

impl RuntimeConfig {
    pub fn from_env() -> io::Result<Self> {
        Self::from_vars(|name| std::env::var(name).ok())
    }

    fn from_vars(var: impl Fn(&str) -> Option<String>) -> io::Result<Self> {
        let listen = var(LISTEN)
            .ok_or_else(|| invalid(format!("{LISTEN} is not set")))
            .and_then(|value| parse_listen(&value))?;
        Ok(Self {
            listen,
            ca_bundle: var(CA_BUNDLE).map_or_else(|| DEFAULT_CA_BUNDLE.into(), PathBuf::from),
        })
    }
}

/// `address:port`, or `unix:/path` for a socket on a shared volume. The
/// supervisor must know the port, so port 0 is refused.
fn parse_listen(value: &str) -> io::Result<Listen> {
    if let Some(path) = value.strip_prefix("unix:") {
        let path = path.strip_prefix("//").unwrap_or(path);
        return if path.starts_with('/') {
            Ok(Listen::Unix(path.into()))
        } else {
            Err(invalid(format!("{LISTEN} needs an absolute socket path")))
        };
    }
    let address: SocketAddr = value
        .parse()
        .map_err(|e| invalid(format!("{LISTEN} is not address:port or unix:/path: {e}")))?;
    if address.port() == 0 {
        return Err(invalid(format!("{LISTEN} needs a fixed port")));
    }
    Ok(Listen::Tcp(address))
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
    fn only_the_listen_address_is_required() {
        let config = config(&[(LISTEN, "0.0.0.0:7443")]).unwrap();
        assert_eq!(
            config,
            RuntimeConfig {
                listen: Listen::Tcp("0.0.0.0:7443".parse().unwrap()),
                ca_bundle: DEFAULT_CA_BUNDLE.into(),
            }
        );
        assert_eq!(config.listen.protected_port(), Some(7443));
        assert!(config_error(&[]).contains(LISTEN));
    }

    #[test]
    fn a_unix_listener_takes_both_spellings() {
        for value in [
            "unix:/run/lens/channel.sock",
            "unix:///run/lens/channel.sock",
        ] {
            assert_eq!(
                config(&[(LISTEN, value)]).unwrap().listen,
                Listen::Unix("/run/lens/channel.sock".into())
            );
        }
    }

    #[test]
    fn a_listener_without_a_fixed_port_or_an_absolute_path_is_refused() {
        for value in ["0.0.0.0:0", "unix:channel.sock", "runtime:7443"] {
            assert!(config_error(&[(LISTEN, value)]).contains(LISTEN));
        }
    }

    #[test]
    fn the_trust_bundle_can_be_moved() {
        let config = config(&[(LISTEN, "[::]:7443"), (CA_BUNDLE, "/var/lens/ca.pem")]).unwrap();
        assert_eq!(config.ca_bundle, PathBuf::from("/var/lens/ca.pem"));
    }

    fn config_error(vars: &[(&str, &str)]) -> String {
        config(vars).unwrap_err().to_string()
    }
}
