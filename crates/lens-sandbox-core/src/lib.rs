//! Core runtime library for governed sandbox execution.
//!
//! `lens-sandbox-core` provides the low-level enforcement primitives used by
//! Lens Sandbox and Lens Agents inside sandboxed execution environments. It
//! handles governed network, DNS, proxy, boundary credential exchange, policy
//! lifecycle, and activity reporting behavior.
//!
//! This crate is runtime plumbing, not an end-user sandbox product. The
//! effective security boundary depends on the caller's surrounding container,
//! microVM, Linux capabilities, filesystem mounts, process model, and policy
//! source.
//!
//! The default `proxy` feature carries the network side. Build with
//! `default-features = false` for the process modules alone.

#[cfg(feature = "proxy")]
pub mod activity;
#[cfg(feature = "proxy")]
pub mod aws_resign;
#[cfg(feature = "proxy")]
pub mod aws_sigv4;
#[cfg(feature = "proxy")]
pub mod body_field;
#[cfg(feature = "proxy")]
pub mod ca;
pub mod ca_env;
pub mod child_spawner;
#[cfg(feature = "proxy")]
pub mod client;
#[cfg(feature = "proxy")]
pub mod config;
#[cfg(feature = "proxy")]
pub mod connector;
#[cfg(feature = "proxy")]
pub mod dns;
pub mod exec_manager;
pub mod exec_protocol;
#[cfg(feature = "proxy")]
pub mod gate;
#[cfg(feature = "proxy")]
pub mod graphql;
#[cfg(feature = "proxy")]
pub(crate) mod graphql_ws;
#[cfg(feature = "proxy")]
pub mod http_body;
pub mod lifecycle;
#[cfg(feature = "proxy")]
pub(crate) mod listen;
#[cfg(feature = "proxy")]
pub mod llm;
#[cfg(feature = "proxy")]
pub mod mcp;
#[cfg(feature = "proxy")]
pub mod mitm;
#[cfg(feature = "proxy")]
pub mod network;
pub mod peer_process;
#[cfg(feature = "proxy")]
pub mod policy_schema;
#[cfg(feature = "proxy")]
pub mod prestart;
pub mod privilege;
#[cfg(feature = "proxy")]
pub mod protocol;
#[cfg(feature = "proxy")]
pub mod proxy;
pub mod pty;
#[cfg(feature = "proxy")]
pub mod resolver;
#[cfg(feature = "proxy")]
pub mod routing;
#[cfg(feature = "proxy")]
pub mod sock_mark;
#[cfg(feature = "proxy")]
pub mod temp_files;
#[cfg(feature = "proxy")]
pub mod token_answer;
#[cfg(feature = "proxy")]
pub mod transparent;
#[cfg(feature = "proxy")]
pub mod udp_egress;
