//! The supervisor side of the channel to the runtimes of one sandbox. The
//! supervisor holds the policy, the proxy and the credentials; the runtimes
//! in the workload hold none of them.

mod egress;
mod identity;
mod mediate;
mod pki;
mod registry;
mod relay;
mod supervisor;

pub use pki::ChannelPki;
pub use supervisor::{ExecSession, Supervisor};
