//! The runtime inside a sandbox workload. It holds no capabilities; the
//! supervisor outside the workload holds the policy.

#[cfg(target_os = "linux")]
pub mod linux;
