//! The kernel features the runtime cannot work without. The runtime checks
//! them at start and does not start without them.

use std::io;

use crate::linux::{landlock, seccomp_notify};

pub(crate) fn kernel() -> io::Result<()> {
    let notify = seccomp_notify::probe_notification_api()
        .map_err(|e| unsupported(format!("seccomp user notification: {e}")))?;
    if !notify.wait_killable_recv {
        return Err(unsupported(
            "seccomp user notification needs WAIT_KILLABLE_RECV (Linux 5.19)".into(),
        ));
    }
    landlock::prepare_baseline()
        .map_err(|e| unsupported(format!("Landlock ABI 3 (Linux 6.2): {e}")))?;
    Ok(())
}

fn unsupported(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}
