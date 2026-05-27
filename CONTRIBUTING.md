# Contributing to lens-sandbox-core

Thanks for your interest in `lens-sandbox-core`.

This repository contains the shared Rust library used by Lens Sandbox and Lens Agents for sandbox policy enforcement, networking controls, boundary credential exchange, and runtime lifecycle integration. It is not an end-user application.

## Development Setup

Install a Rust toolchain compatible with the repository MSRV:

```bash
rustup toolchain install 1.85
rustup override set 1.85
```

Set up the repository hooks:

```bash
git config core.hooksPath .githooks
```

Run the standard checks before opening a pull request:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Integration tests that require Linux, nftables, and `CAP_NET_ADMIN` are ignored by default:

```bash
cargo test -p lens-sandbox-core -- --ignored
```

## Pull Request Guidelines

- Keep changes small and focused.
- Include tests for behavior changes when practical.
- Update documentation when changing public behavior, configuration, or policy schema.
- Avoid expanding the public Rust API unless the new API is intended to be stable.
- Prefer explicit errors over panics in library code.
- Do not commit credentials, tokens, generated certificates, private keys, or local policy files containing sensitive data.

## Policy Schema Changes

The canonical JSON schema is committed at `schemas/policy.schema.json`.

After changing policy types, regenerate the schema:

```bash
cargo run --bin generate-policy-schema > schemas/policy.schema.json
```

Then verify the generated file is committed with the source change.

## Commit Style

Use concise conventional commits where possible:

- `feat: add policy field`
- `fix: handle denied DNS route`
- `docs: explain boundary credential exchange`
- `test: cover transparent proxy classification`
- `ci: add audit check`

## Security-Sensitive Changes

Changes touching credential handling, TLS interception, DNS filtering, nftables rules, privilege dropping, process execution, or policy enforcement should include a short explanation of the security impact in the pull request description.
