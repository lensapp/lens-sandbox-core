//! Who is behind a socket the broker holds.

use std::fs;

use lens_sandbox_core::peer_process::{self, PeerProcess};

use crate::linux::contract::ResolveError;

/// The process of a thread that is parked in a syscall the broker intercepted,
/// so its `/proc` entry exists while this reads it.
pub(crate) fn resolve_task(tid: u32) -> Result<PeerProcess, ResolveError> {
    let status =
        fs::read_to_string(format!("/proc/{tid}/status")).map_err(|_| ResolveError::NotFound)?;
    let tgid = status
        .lines()
        .find_map(|line| line.strip_prefix("Tgid:"))
        .and_then(|value| value.trim().parse::<i64>().ok())
        .ok_or_else(|| ResolveError::Failed(format!("no Tgid in /proc/{tid}/status")))?;
    Ok(peer_process::resolve_pid(tgid))
}

/// The workload process that holds the DNS socket with this inode. The broker
/// holds every socket it made too, so its own descriptors do not count. A
/// socket that a fork shares names the first holder found: attribution here is
/// best effort, as it is for the DNS stub of the transparent proxy.
pub(crate) fn dns_sender(socket_inode: u64) -> Result<PeerProcess, ResolveError> {
    let own = std::process::id();
    let target = format!("socket:[{socket_inode}]");
    let holder = fs::read_dir("/proc")
        .map_err(|e| ResolveError::Failed(format!("read /proc: {e}")))?
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter(|&pid| pid != own)
        .find(|pid| holds(*pid, &target))
        .ok_or(ResolveError::NotFound)?;
    Ok(peer_process::resolve_pid(i64::from(holder)))
}

fn holds(pid: u32, target: &str) -> bool {
    let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return false;
    };
    fds.filter_map(Result::ok)
        .filter_map(|fd| fs::read_link(fd.path()).ok())
        .any(|link| link.as_os_str() == target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn a_task_resolves_to_its_process() {
        let process = resolve_task(std::process::id()).unwrap();
        assert_eq!(process.pid, i64::from(std::process::id()));
        assert!(process.exe.is_some());
    }

    #[test]
    fn a_thread_resolves_to_the_process_that_owns_it() {
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            tid_tx
                .send(rustix::thread::gettid().as_raw_nonzero().get())
                .unwrap();
            let _ = done_rx.recv();
        });
        let tid = tid_rx.recv().unwrap();
        let process = resolve_task(tid.cast_unsigned());
        done_tx.send(()).unwrap();
        thread.join().unwrap();
        assert_ne!(tid.cast_unsigned(), std::process::id());
        assert_eq!(process.unwrap().pid, i64::from(std::process::id()));
    }

    #[test]
    fn a_socket_that_only_the_broker_holds_has_no_sender() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let inode =
            crate::linux::proc_fd::socket_inode(std::process::id(), socket.as_raw_fd()).unwrap();
        assert!(matches!(dns_sender(inode), Err(ResolveError::NotFound)));
    }

    #[test]
    #[allow(unsafe_code)]
    fn a_socket_held_by_a_child_names_the_child() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let inode =
            crate::linux::proc_fd::socket_inode(std::process::id(), socket.as_raw_fd()).unwrap();
        let fd = socket.as_raw_fd();
        let mut child = std::process::Command::new("sleep");
        child.arg("5");
        // SAFETY: fcntl is async-signal-safe.
        unsafe {
            use std::os::unix::process::CommandExt as _;
            child.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = child.spawn().unwrap();
        let sender = dns_sender(inode);
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(sender.unwrap().pid, i64::from(child.id()));
    }
}
