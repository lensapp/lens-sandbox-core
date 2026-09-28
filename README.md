# lens-sandbox-core

[![CI](https://github.com/lensapp/lens-sandbox-core/actions/workflows/ci.yml/badge.svg)](https://github.com/lensapp/lens-sandbox-core/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust 1.96.1+](https://img.shields.io/badge/rust-1.96.1%2B-orange.svg)](crates/lens-sandbox-core/Cargo.toml)

`lens-sandbox-core` is the Rust library used by Lens Sandbox and Lens Agents to enforce governed network, DNS, proxy, credential, and policy behavior inside sandboxed execution environments.

It is core runtime plumbing, not an end-user product. Applications embed it to give sandboxed workloads controlled access to external systems: DNS requests, outbound network traffic, HTTP CONNECT proxying, TLS interception paths, boundary credential exchange, policy lifecycle, and activity reporting.

## What This Crate Provides

- Policy-controlled outbound network access
- DNS filtering and allowlist behavior
- HTTP CONNECT proxy support
- Transparent proxy routing support
- TLS interception support for governed traffic
- Boundary credential exchange and request signing
- nftables-based network lockdown helpers
- WebSocket-driven policy lifecycle integration
- Activity and audit event primitives

## Split Supervisor

Two more crates run the sandbox with no root in the workload. The supervisor holds the policy, the proxy and the credentials outside the workload. The runtime in the workload holds none of them.

- `lens-sandbox-runtime` is the PID 1 of the workload container. It mediates the workload's sockets with seccomp user notification, hides its private root `/.lens` with Landlock, and sends each connect and DNS query to the supervisor. It needs Linux 6.2 or later, with Landlock enabled.
- `lens-sandbox-supervisor` serves the channel to the runtimes of one sandbox. It gives each connect to the proxy of this crate.

The runtime dials the supervisor over mutual TLS. It reads its configuration from the environment:

| Variable | Default | Use |
| --- | --- | --- |
| `LENS_SANDBOX_SUPERVISOR` | required | `https://host:port`, or `unix:/path` for a socket on a shared volume |
| `LENS_SANDBOX_CHANNEL_DIR` | `/.lens/channel` | `ca.pem`, `cert.pem` and `key.pem` of the runtime |
| `LENS_SANDBOX_CA_BUNDLE` | `/tmp/lens-sandbox/ca-bundle.pem` | where the runtime writes the trust bundle of the workload |

The runtime binds its resolver on `127.0.0.53:53`. Without `CAP_NET_BIND_SERVICE`, set `net.ipv4.ip_unprivileged_port_start=0`, and point the workload's `resolv.conf` at `127.0.0.53`.

## What This Crate Is Not

`lens-sandbox-core` is not a complete sandbox product by itself. It does not create the desktop app, enterprise platform, UI, packaging, distribution, or microVM lifecycle.

The effective security boundary depends on the caller's deployment model: container, microVM, Linux capabilities, filesystem mounts, process model, and policy source.

## Relationship to Lens Sandbox and Lens Agents

Lens Sandbox uses this crate as the local enforcement core for sandboxed workloads on a developer machine.

Lens Agents uses the same core enforcement model in organizational deployments where central IT manages policies, credentials, connections, and audit across many agents.

The shared crate keeps low-level runtime behavior consistent across both products.

## Open Source

This project is licensed under Apache 2.0. See:

- [CONTRIBUTING.md](CONTRIBUTING.md) for development workflow and contribution guidance.
- [SECURITY.md](SECURITY.md) for vulnerability reporting and security scope.
- [CHANGELOG.md](CHANGELOG.md) for release notes.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community expectations.
- [crates/lens-sandbox-runtime/THIRD-PARTY.md](crates/lens-sandbox-runtime/THIRD-PARTY.md) for code copied from NVIDIA OpenShell.

## Local Setup

```bash
git config core.hooksPath .githooks
```

## Building

```bash
cargo build -p lens-sandbox-core
cargo test -p lens-sandbox-core
cargo test -p lens-sandbox-supervisor
cargo test -p lens-sandbox-runtime -- --test-threads=1   # Linux only
```

Integration tests requiring Linux + nftables + `CAP_NET_ADMIN` are `#[ignore]`-gated. Run them with:

```bash
cargo test -p lens-sandbox-core -- --ignored
```

## Policy Schema

The canonical policy schema lives in `schemas/policy.schema.json`. Regenerate it with:

```bash
cargo run --bin generate-policy-schema > schemas/policy.schema.json
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
