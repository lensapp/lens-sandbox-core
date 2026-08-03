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

pub mod activity;
pub mod aws_resign;
pub mod aws_sigv4;
pub mod ca;
pub mod ca_env;
pub mod child_spawner;
pub mod client;
pub mod config;
pub mod connector;
pub mod dns;
pub mod exec_manager;
pub mod exec_protocol;
pub mod gate;
pub mod graphql;
pub(crate) mod graphql_ws;
pub mod http_body;
pub mod lifecycle;
pub mod mitm;
pub mod network;
pub mod peer_process;
pub mod policy_schema;
pub mod privilege;
pub mod protocol;
pub mod proxy;
pub mod pty;
pub mod routing;
pub mod sock_mark;
pub mod temp_files;
pub mod transparent;
