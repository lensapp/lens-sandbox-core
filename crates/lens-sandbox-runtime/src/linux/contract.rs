// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// Changed for lens-sandbox-runtime: only the types and denial reasons the
// broker uses, without serde.

//! The types the broker hands to, and takes from, its mediator.

use std::fmt;

/// Why an identity resolution failed. Resolution failure fails closed: the
/// mediation service denies and audits the connection; it never authorizes.
#[derive(Debug, Clone)]
pub enum ResolveError {
    /// No process owns the connection (stale or unknown attribution).
    NotFound,
    /// Resolution attempted but could not produce trustworthy identity.
    Failed(String),
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "connection owner not found"),
            Self::Failed(m) => write!(f, "identity resolution failed: {m}"),
        }
    }
}

/// Immutable socket metadata supplied with a pending external TCP open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkSocketMetadata {
    /// Kernel socket cookie captured for the exact open-file description.
    pub socket_cookie: u64,
    /// Whether the workload requested nonblocking operation.
    pub nonblocking: bool,
    /// Workload process generation that owns the open.
    pub process_generation: u64,
}

/// Typed supervisor decision for one pending TCP open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpOpenDecision {
    /// L4 authorization and a bounded relay handler are ready. L7 policy still
    /// applies to bytes after the local connection commits.
    RelayReady,
    /// The socket remains unchanged and connect returns this positive errno.
    Denied(TcpOpenDenial),
}

/// Placement-neutral reason why a staged TCP open was not committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpOpenDenial {
    /// The admitted network policy rejected the request.
    PolicyDenied,
    /// The backend could not resolve authoritative executable identity.
    IdentityUnavailable,
    /// The mediation path became unavailable before commit.
    MediationUnavailable,
}

/// DNS transport used by one workload exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsTransport {
    /// One DNS wire datagram without a TCP length prefix.
    Udp,
    /// One DNS message received over a TCP resolver connection.
    Tcp,
}
