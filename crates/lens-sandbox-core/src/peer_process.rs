//! Best-effort resolution of the guest process behind a proxied connection.
//!
//! The transparent/explicit proxy accepts a TCP connection from a workload
//! process; its `peer` address is that process's socket's *local* address as
//! seen inside the guest netns. We map `peer` → socket inode (via
//! `/proc/net/tcp{,6}`) → owning pid (via `/proc/<pid>/fd`) → command name,
//! executable path, and parent-process chain.
//! Everything is best-effort: a closed socket, a foreign netns, or a
//! non-Linux host all yield `None`, and the caller simply omits the actor.

use serde_json::{Map, Value, json};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// How far up the parent chain we walk when resolving ancestors. Deep enough
/// to see through a wrapper or two (e.g. `claude → node → curl`) without
/// unbounded `/proc` reads. `init` (pid 1) is never included.
const ANCESTOR_DEPTH_LIMIT: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerProcess {
    pub pid: i64,
    /// Command name from `/proc/<pid>/comm`. Emitted in audit events.
    pub name: String,
    /// Resolved `/proc/<pid>/exe` target, if readable. Used by the `binaries`
    /// route filter, which matches on absolute paths rather than the
    /// truncated, spoofable comm name.
    pub exe: Option<PathBuf>,
    /// Parent executables, immediate parent first, `init` excluded. Lets a
    /// `binaries` rule name a launcher (e.g. `claude`) and still match when
    /// the launcher spawns a child (`node`, `curl`) that opens the socket.
    pub ancestors: Vec<PathBuf>,
}

impl PeerProcess {
    /// The connecting exe plus its ancestor chain, immediate process first.
    /// This is the set of paths a `binaries` route filter matches against.
    pub fn binary_paths(&self) -> impl Iterator<Item = &Path> {
        self.exe
            .as_deref()
            .into_iter()
            .chain(self.ancestors.iter().map(PathBuf::as_path))
    }
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
    /// Resolve synchronously by walking `/proc`. This performs blocking
    /// filesystem I/O; async callers should use [`ActorContext::resolve_offloaded`]
    /// so the walk never occupies a tokio worker thread.
    pub fn resolve(peer: SocketAddr) -> Self {
        Self {
            peer,
            process: resolve(peer),
        }
    }

    /// Resolve on a blocking thread. The `/proc` walk (`read_dir` over every
    /// pid plus a `read_link` per fd) is synchronous filesystem I/O, so we
    /// offload it via `spawn_blocking` to keep the connection handler's tokio
    /// worker free. Resolution still happens once at connection setup, while
    /// the peer's socket is open and its owning process alive; a panicking
    /// blocking task degrades to the unresolved `src_endpoint`-only context.
    pub async fn resolve_offloaded(peer: SocketAddr) -> Self {
        tokio::task::spawn_blocking(move || Self::resolve(peer))
            .await
            .unwrap_or(Self {
                peer,
                process: None,
            })
    }

    /// The resolved owning process, if any. Used by the proxy to apply a
    /// rule's `binaries` filter against the caller's exe and ancestors.
    pub fn process(&self) -> Option<&PeerProcess> {
        self.process.as_ref()
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

fn parse_row(line: &str) -> Option<(SocketAddr, u64)> {
    let mut fields = line.split_whitespace();
    let _sl = fields.next()?;
    let local = parse_local_address(fields.next()?)?;
    let inode = fields.nth(7)?.parse::<u64>().ok()?;
    Some((local, inode))
}

trait ProcReader {
    fn read(&self, path: &str) -> std::io::Result<String>;
    fn list_dir(&self, path: &str) -> std::io::Result<Vec<String>>;
    fn read_link(&self, path: &str) -> std::io::Result<String>;
}

struct RealProc;

impl ProcReader for RealProc {
    fn read(&self, path: &str) -> std::io::Result<String> {
        std::fs::read_to_string(path)
    }

    fn list_dir(&self, path: &str) -> std::io::Result<Vec<String>> {
        Ok(std::fs::read_dir(path)?
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect())
    }

    fn read_link(&self, path: &str) -> std::io::Result<String> {
        Ok(std::fs::read_link(path)?.to_string_lossy().into_owned())
    }
}

pub fn resolve(peer: SocketAddr) -> Option<PeerProcess> {
    resolve_with(&RealProc, peer)
}

fn resolve_with<P: ProcReader>(proc: &P, peer: SocketAddr) -> Option<PeerProcess> {
    let inode = socket_inode_for(proc, peer)?;
    let pid = pid_owning_inode(proc, inode)?;
    Some(PeerProcess {
        name: process_name(proc, pid).unwrap_or_default(),
        exe: read_exe(proc, pid),
        ancestors: walk_ancestors(proc, pid),
        pid,
    })
}

fn socket_inode_for<P: ProcReader>(proc: &P, peer: SocketAddr) -> Option<u64> {
    let path = if peer.is_ipv6() {
        "/proc/net/tcp6"
    } else {
        "/proc/net/tcp"
    };
    let table = proc.read(path).ok()?;
    table
        .lines()
        .skip(1)
        .filter_map(parse_row)
        .find(|(local, _)| *local == peer)
        .map(|(_, inode)| inode)
}

fn pid_owning_inode<P: ProcReader>(proc: &P, inode: u64) -> Option<i64> {
    let target = format!("socket:[{inode}]");
    for name in proc.list_dir("/proc").ok()? {
        let Ok(pid) = name.parse::<i64>() else {
            continue;
        };
        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = proc.list_dir(&fd_dir) else {
            continue;
        };
        if fds.iter().any(|fd| {
            proc.read_link(&format!("{fd_dir}/{fd}"))
                .is_ok_and(|link| link == target)
        }) {
            return Some(pid);
        }
    }
    None
}

fn process_name<P: ProcReader>(proc: &P, pid: i64) -> Option<String> {
    Some(
        proc.read(&format!("/proc/{pid}/comm"))
            .ok()?
            .trim_end()
            .to_string(),
    )
}

fn read_exe<P: ProcReader>(proc: &P, pid: i64) -> Option<PathBuf> {
    let link = proc.read_link(&format!("/proc/{pid}/exe")).ok()?;
    // The kernel appends " (deleted)" to /proc/<pid>/exe when the running
    // binary has been unlinked or replaced on disk — a package upgrade or a
    // mise runtime swap under a live process. Strip it so the canonical path
    // still matches a `binaries` filter instead of silently failing closed.
    let path = link.strip_suffix(" (deleted)").unwrap_or(&link);
    Some(PathBuf::from(path))
}

fn read_ppid<P: ProcReader>(proc: &P, pid: i64) -> Option<i64> {
    proc.read(&format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("PPid:")?.trim().parse::<i64>().ok())
}

/// Walk the parent chain from `start`, collecting each ancestor's exe path.
/// Stops at `init` (pid ≤ 1), the depth limit, or the first unreadable link.
fn walk_ancestors<P: ProcReader>(proc: &P, start: i64) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut current = start;
    for _ in 0..ANCESTOR_DEPTH_LIMIT {
        let Some(ppid) = read_ppid(proc, current) else {
            break;
        };
        if ppid <= 1 {
            break;
        }
        let Some(exe) = read_exe(proc, ppid) else {
            break;
        };
        out.push(exe);
        current = ppid;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

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

    #[test]
    fn augment_stamps_src_endpoint_and_actor_process_when_resolved() {
        let actor = ActorContext {
            peer: "10.0.0.5:54321".parse().unwrap(),
            process: Some(PeerProcess {
                pid: 4242,
                name: "wget".into(),
                exe: Some("/usr/bin/wget".into()),
                ancestors: vec!["/usr/bin/bash".into()],
            }),
        };
        let mut event = Map::new();
        actor.augment(&mut event);
        assert_eq!(
            event["src_endpoint"],
            json!({"ip": "10.0.0.5", "port": 54321})
        );
        assert_eq!(
            event["actor"],
            json!({"process": {"name": "wget", "pid": 4242}})
        );
    }

    #[test]
    fn augment_omits_actor_when_the_process_is_unresolved() {
        let actor = ActorContext {
            peer: "10.0.0.5:54321".parse().unwrap(),
            process: None,
        };
        let mut event = Map::new();
        actor.augment(&mut event);
        assert_eq!(
            event["src_endpoint"],
            json!({"ip": "10.0.0.5", "port": 54321})
        );
        assert!(!event.contains_key("actor"));
    }

    const TCP_ROW: &str = "   3: 0100007F:1F90 0100007F:C1A2 01 00000000:00000000 00:00000000 00000000  1000        0 424242 1 ffff 100";

    struct FakeProc {
        files: HashMap<String, String>,
        dirs: HashMap<String, Vec<String>>,
        links: HashMap<String, String>,
    }

    impl ProcReader for FakeProc {
        fn read(&self, path: &str) -> std::io::Result<String> {
            self.files.get(path).cloned().ok_or_else(not_found)
        }

        fn list_dir(&self, path: &str) -> std::io::Result<Vec<String>> {
            self.dirs.get(path).cloned().ok_or_else(not_found)
        }

        fn read_link(&self, path: &str) -> std::io::Result<String> {
            self.links.get(path).cloned().ok_or_else(not_found)
        }
    }

    fn not_found() -> std::io::Error {
        std::io::Error::from(std::io::ErrorKind::NotFound)
    }

    fn owning_fixture() -> FakeProc {
        FakeProc {
            files: HashMap::from([
                ("/proc/net/tcp".into(), format!("header\n{TCP_ROW}")),
                ("/proc/100/comm".into(), "wget\n".into()),
                // pid 100 (wget) ← pid 7 (bash) ← init(1): the walk stops at
                // the parent whose PPid is init, yielding a single ancestor.
                ("/proc/100/status".into(), "Name:\twget\nPPid:\t7\n".into()),
                ("/proc/7/status".into(), "Name:\tbash\nPPid:\t1\n".into()),
            ]),
            dirs: HashMap::from([
                (
                    "/proc".into(),
                    vec!["net".into(), "7".into(), "1".into(), "100".into()],
                ),
                ("/proc/1/fd".into(), vec!["0".into()]),
                ("/proc/100/fd".into(), vec!["3".into(), "4".into()]),
            ]),
            links: HashMap::from([
                ("/proc/1/fd/0".into(), "pipe:[999]".into()),
                ("/proc/100/fd/3".into(), "socket:[111111]".into()),
                ("/proc/100/fd/4".into(), "socket:[424242]".into()),
                ("/proc/100/exe".into(), "/usr/bin/wget".into()),
                ("/proc/7/exe".into(), "/usr/bin/bash".into()),
            ]),
        }
    }

    #[test]
    fn resolve_with_walks_proc_net_tcp_then_fd_symlinks_to_the_owning_process() {
        let peer: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(
            resolve_with(&owning_fixture(), peer),
            Some(PeerProcess {
                pid: 100,
                name: "wget".into(),
                exe: Some("/usr/bin/wget".into()),
                ancestors: vec!["/usr/bin/bash".into()],
            })
        );
    }

    #[test]
    fn resolve_with_leaves_exe_none_and_no_ancestors_when_proc_links_are_unreadable() {
        let mut fake = owning_fixture();
        fake.links.remove("/proc/100/exe");
        fake.files.remove("/proc/100/status");
        let peer: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(
            resolve_with(&fake, peer),
            Some(PeerProcess {
                pid: 100,
                name: "wget".into(),
                exe: None,
                ancestors: vec![],
            })
        );
    }

    #[test]
    fn resolve_with_strips_the_kernel_deleted_suffix_from_exe_paths() {
        let mut fake = owning_fixture();
        // wget's binary was replaced on disk while the process is live, and
        // bash's link is clean — only the affected path carries the suffix.
        fake.links
            .insert("/proc/100/exe".into(), "/usr/bin/wget (deleted)".into());
        let peer: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(
            resolve_with(&fake, peer),
            Some(PeerProcess {
                pid: 100,
                name: "wget".into(),
                exe: Some("/usr/bin/wget".into()),
                ancestors: vec!["/usr/bin/bash".into()],
            })
        );
    }

    #[test]
    fn binary_paths_yields_exe_first_then_ancestors() {
        let p = PeerProcess {
            pid: 100,
            name: "node".into(),
            exe: Some("/usr/bin/node".into()),
            ancestors: vec!["/usr/local/bin/claude".into(), "/usr/bin/bash".into()],
        };
        assert_eq!(
            p.binary_paths().collect::<Vec<_>>(),
            vec![
                Path::new("/usr/bin/node"),
                Path::new("/usr/local/bin/claude"),
                Path::new("/usr/bin/bash"),
            ]
        );
    }

    #[test]
    fn resolve_with_is_none_when_no_socket_row_matches_the_peer() {
        let peer: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        assert!(resolve_with(&owning_fixture(), peer).is_none());
    }

    #[test]
    fn resolve_with_is_none_when_no_process_owns_the_socket_inode() {
        let mut fake = owning_fixture();
        fake.links
            .insert("/proc/100/fd/4".into(), "socket:[999999]".into());
        let peer: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert!(resolve_with(&fake, peer).is_none());
    }

    #[test]
    fn resolve_with_leaves_the_name_empty_when_comm_is_unreadable() {
        let mut fake = owning_fixture();
        fake.files.remove("/proc/100/comm");
        let peer: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(
            resolve_with(&fake, peer),
            Some(PeerProcess {
                pid: 100,
                name: String::new(),
                exe: Some("/usr/bin/wget".into()),
                ancestors: vec!["/usr/bin/bash".into()],
            })
        );
    }

    #[test]
    fn resolve_with_matches_ipv6_sockets_via_proc_net_tcp6() {
        const TCP6_ROW: &str = "   1: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 555555 1 ffff 100";
        let fake = FakeProc {
            files: HashMap::from([
                ("/proc/net/tcp6".into(), format!("header\n{TCP6_ROW}")),
                ("/proc/42/comm".into(), "busybox\n".into()),
                (
                    "/proc/42/status".into(),
                    "Name:\tbusybox\nPPid:\t1\n".into(),
                ),
            ]),
            dirs: HashMap::from([
                ("/proc".into(), vec!["42".into()]),
                ("/proc/42/fd".into(), vec!["5".into()]),
            ]),
            links: HashMap::from([
                ("/proc/42/fd/5".into(), "socket:[555555]".into()),
                ("/proc/42/exe".into(), "/bin/busybox".into()),
            ]),
        };
        let peer: SocketAddr = "[::1]:80".parse().unwrap();
        assert_eq!(
            resolve_with(&fake, peer),
            Some(PeerProcess {
                pid: 42,
                name: "busybox".into(),
                exe: Some("/bin/busybox".into()),
                ancestors: vec![],
            })
        );
    }
}
