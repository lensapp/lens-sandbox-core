# lens-sandbox-core

[![CI](https://github.com/lensapp/lens-sandbox-core/actions/workflows/ci.yml/badge.svg)](https://github.com/lensapp/lens-sandbox-core/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](crates/lens-sandbox-core/Cargo.toml)

Core library for the Lens Sandbox runtime. Provides the in-sandbox networking stack that enforces policy on sandboxed AI agents: HTTP CONNECT proxy, MITM TLS interception with boundary credential exchange, nftables-based network lockdown, DNS filtering, and WebSocket-driven policy lifecycle.

This repository contains a Rust library/crate, not an end-user product. It is the shared core used by Lens Sandbox and Lens Agents.

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
