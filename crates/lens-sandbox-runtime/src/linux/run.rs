//! The runtime from start to exit.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use lens_sandbox_core::ca_env::CA_BUNDLE;
use lens_sandbox_core::exec_manager::ExecManager;
use lens_sandbox_core::lifecycle::{OrphanReaper, PidGuard};
use rustix::process::{DumpableBehavior, geteuid, set_dumpable_behavior};

use crate::linux::attach::{self, Services};
use crate::linux::broker::NetworkBroker;
use crate::linux::config::RuntimeConfig;
use crate::linux::launcher::RuntimeLauncher;
use crate::linux::{connect, mediator, qualify, workload_launcher};

/// Returns only with the reason the runtime stops.
pub async fn run(config: RuntimeConfig) -> io::Error {
    // A dropped reaper stops reaping, so it lives as long as the runtime.
    let reaper = OrphanReaper::spawn();
    match start(config, reaper.guard()).await {
        Ok((services, _broker)) => attach::serve(services).await,
        Err(error) => error,
    }
}

async fn start(
    config: RuntimeConfig,
    pid_guard: PidGuard,
) -> io::Result<(Services, NetworkBroker)> {
    qualify::kernel()?;
    // The workload has the same uid, so only this keeps it out of the
    // runtime's memory.
    set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
    let client = connect::client(&config.supervisor, &config.channel_dir)?;
    let (launcher, listener) = workload_launcher::start()?;
    let broker = mediator::start(listener, client.clone()).map_err(|e| {
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
    let services = Services {
        client,
        exec,
        ca_bundle: config.ca_bundle,
        system_bundle: PathBuf::from(CA_BUNDLE),
    };
    Ok((services, broker))
}
