//! The runtime from start to exit.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use lens_sandbox_core::ca_env::CA_BUNDLE;
use lens_sandbox_core::channel::ChannelTls;
use lens_sandbox_core::exec_manager::ExecManager;
use lens_sandbox_core::lifecycle::{OrphanReaper, PidGuard};
use rustix::process::{DumpableBehavior, geteuid, set_dumpable_behavior};

use crate::linux::boundary::Boundary;
use crate::linux::broker::NetworkBroker;
use crate::linux::config::RuntimeConfig;
use crate::linux::launcher::RuntimeLauncher;
use crate::linux::listen::{self, Incoming};
use crate::linux::mediation::Mediation;
use crate::linux::{qualify, workload_launcher};

/// Returns only with the reason the runtime stops.
pub async fn run(config: RuntimeConfig) -> io::Error {
    // A dropped reaper stops reaping, so it lives as long as the runtime.
    let reaper = OrphanReaper::spawn();
    let (boundary, incoming, tls) = match start(config, reaper.guard()) {
        Ok(started) => started,
        Err(error) => return error,
    };
    // Without the broker, the workload's network calls get no answer, so the
    // runtime stops and its orchestrator starts it again.
    let broker = boundary.broker.clone();
    tokio::select! {
        error = listen::serve(incoming, &tls, boundary) => error,
        () = broker.stopped() => io::Error::other("the network broker stopped"),
    }
}

fn start(
    config: RuntimeConfig,
    pid_guard: PidGuard,
) -> io::Result<(Boundary, Incoming, ChannelTls)> {
    qualify::kernel()?;
    // The workload has the same uid, so only this keeps it out of the
    // runtime's memory.
    set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
    let tls = listen::read_tls(Path::new(listen::CHANNEL_DIR))?;
    let incoming = listen::bind(&config.listen)?;
    let (launcher, listener) = workload_launcher::start()?;
    let broker = NetworkBroker::start(listener, config.listen.protected_port()).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("start the broker (the resolver binds port 53, so set net.ipv4.ip_unprivileged_port_start=0): {e}"),
        )
    })?;
    let exec = ExecManager::with_launcher(
        None,
        geteuid().is_root(),
        pid_guard,
        Arc::new(RuntimeLauncher::new(launcher, config.ca_bundle.clone())),
    );
    let boundary = Boundary {
        exec,
        broker,
        mediation: Mediation::default(),
        ca_bundle: config.ca_bundle,
        system_bundle: PathBuf::from(CA_BUNDLE),
    };
    Ok((boundary, incoming, tls))
}
