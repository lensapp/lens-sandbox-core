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

## Local Setup

```bash
git config core.hooksPath .githooks
```

## Building

```bash
cargo build -p lens-sandbox-core
cargo test -p lens-sandbox-core
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
