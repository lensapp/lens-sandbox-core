//! The supervisor side of the channel to the runtimes of one sandbox. The
//! supervisor holds the policy, the proxy and the credentials; the runtimes
//! in the workload hold none of them.

mod dial;
mod egress;
mod link;
mod mediate;
mod pki;
mod supervisor;

pub use dial::RuntimeAddress;
pub use pki::ChannelPki;
pub use supervisor::{ExecSession, Supervisor};
