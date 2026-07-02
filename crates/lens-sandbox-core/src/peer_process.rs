//! Best-effort resolution of the guest process behind a proxied connection.
//!
//! The transparent/explicit proxy accepts a TCP connection from a workload
//! process; its `peer` address is that process's socket's *local* address as
//! seen inside the guest netns. We map `peer` → socket inode (via
//! `/proc/net/tcp{,6}`) → owning pid (via `/proc/<pid>/fd`) → command name.
//! Everything is best-effort: a closed socket, a foreign netns, or a
//! non-Linux host all yield `None`, and the caller simply omits the actor.

use serde_json::{Map, Value, json};
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerProcess {
    pub pid: i64,
    pub name: String,
}

/// The client endpoint and (best-effort) owning process for a proxied
/// connection, resolved once per connection and spliced into every audit
/// event it produces.
#[derive(Debug, Clone)]
pub struct ActorContext {
    peer: SocketAddr,
    process: Option<PeerProcess>,
}

impl ActorContext {
    pub fn resolve(peer: SocketAddr) -> Self {
        Self {
            peer,
            process: resolve(peer),
        }
    }

    /// Insert `src_endpoint` (always) and `actor.process` (when resolved) into
    /// an audit-event object, ready for the host to copy into OCSF.
    pub fn augment(&self, event: &mut Map<String, Value>) {
        event.insert(
            "src_endpoint".into(),
            json!({"ip": self.peer.ip().to_string(), "port": self.peer.port()}),
        );
        if let Some(p) = &self.process {
            event.insert(
                "actor".into(),
                json!({"process": {"name": p.name, "pid": p.pid}}),
            );
        }
    }
}

/// Parse a `/proc/net/tcp{,6}` `local_address` field (`HEXADDR:HEXPORT`) into a
/// `SocketAddr`. IPv4/IPv6 address words are little-endian; the port is big-endian.
pub fn parse_local_address(field: &str) -> Option<SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let (addr_hex, port_hex) = field.rsplit_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = match addr_hex.len() {
        8 => {
            let raw = u32::from_str_radix(addr_hex, 16).ok()?;
            IpAddr::V4(Ipv4Addr::from(raw.swap_bytes()))
        }
        32 => {
            let mut octets = [0u8; 16];
            for (word, chunk) in addr_hex.as_bytes().chunks(8).zip(octets.chunks_mut(4)) {
                let raw = u32::from_str_radix(std::str::from_utf8(word).ok()?, 16).ok()?;
                chunk.copy_from_slice(&raw.to_le_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// Extract `(local_address, inode)` from a `/proc/net/tcp{,6}` data row.
/// Columns: `sl local rem st tx:rx tr:when retrnsmt uid timeout inode …`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_row(line: &str) -> Option<(SocketAddr, u64)> {
    let mut fields = line.split_whitespace();
    let _sl = fields.next()?;
    let local = parse_local_address(fields.next()?)?;
    let inode = fields.nth(7)?.parse::<u64>().ok()?;
    Some((local, inode))
}

#[cfg(target_os = "linux")]
pub fn resolve(peer: SocketAddr) -> Option<PeerProcess> {
    let inode = socket_inode_for(peer)?;
    let pid = pid_owning_inode(inode)?;
    Some(PeerProcess {
        name: process_name(pid).unwrap_or_default(),
        pid,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn resolve(_peer: SocketAddr) -> Option<PeerProcess> {
    None
}

#[cfg(target_os = "linux")]
fn socket_inode_for(peer: SocketAddr) -> Option<u64> {
    let path = if peer.is_ipv6() {
        "/proc/net/tcp6"
    } else {
        "/proc/net/tcp"
    };
    let table = std::fs::read_to_string(path).ok()?;
    table
        .lines()
        .skip(1)
        .filter_map(parse_row)
        .find(|(local, _)| *local == peer)
        .map(|(_, inode)| inode)
}

#[cfg(target_os = "linux")]
fn pid_owning_inode(inode: u64) -> Option<i64> {
    let target = format!("socket:[{inode}]");
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i64>() else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path()).is_ok_and(|link| link.to_string_lossy() == target) {
                return Some(pid);
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn process_name(pid: i64) -> Option<String> {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(comm.trim_end().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_ipv4_local_address_little_endian_with_a_big_endian_port() {
        // 0100007F:1F90 → 127.0.0.1:8080
        assert_eq!(
            parse_local_address("0100007F:1F90"),
            Some("127.0.0.1:8080".parse().unwrap())
        );
    }

    #[test]
    fn parses_an_ipv6_local_address() {
        // ::1 is 0…01; the loopback word layout is 32 hex chars.
        let field = "00000000000000000000000001000000:0050";
        assert_eq!(
            parse_local_address(field),
            Some("[::1]:80".parse().unwrap())
        );
    }

    #[test]
    fn rejects_a_malformed_address() {
        assert!(parse_local_address("nope").is_none());
        assert!(parse_local_address("0100007F").is_none());
        assert!(parse_local_address("XYZ:0050").is_none());
    }

    #[test]
    fn parses_the_local_address_and_inode_from_a_proc_row() {
        let row = "   3: 0100007F:1F90 0100007F:C1A2 01 00000000:00000000 00:00000000 00000000  1000        0 424242 1 ffff 100";
        let (local, inode) = parse_row(row).expect("parses");
        assert_eq!(local, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(inode, 424242);
    }

    #[test]
    fn a_truncated_proc_row_is_ignored() {
        assert!(parse_row("   3: 0100007F:1F90 0100007F:C1A2 01").is_none());
        assert!(parse_row("").is_none());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn resolve_is_none_off_linux() {
        assert!(resolve("127.0.0.1:8080".parse().unwrap()).is_none());
    }
}
