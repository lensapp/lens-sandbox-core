# Lens Sandbox Core (Rust)

Shared library for all sandbox types (shell, agent). Provides WebSocket client, forward proxy, MITM TLS interception, nftables lockdown, privilege drop, and policy handling.

## Commands

```bash
cargo check -p lens-sandbox-core       # Type-check
cargo build -p lens-sandbox-core       # Build library
cargo test -p lens-sandbox-core        # Run unit tests
cargo clippy -p lens-sandbox-core      # Lint
cargo fmt --all -- --check             # Format check
```

Integration tests (network.rs script-render tests are pure; integration tests require Linux + nftables + CAP_NET_ADMIN):

```bash
cargo test -p lens-sandbox-core -- --ignored
```

## Conventions

- **Git**: Conventional commits (`feat:`, `fix:`, `chore:`, `refactor:`, `test:`, `ci:`)
- **Rust edition**: 2024, MSRV 1.85
- **No `any`-style shortcuts**: avoid `unsafe` unless strictly necessary, no `unwrap()` in library code outside tests
- **Tests**: new features and bug fixes should include tests

## Policy Schema

The canonical policy schema is defined in `policy_schema.rs` and exported as JSON Schema to `schemas/policy.schema.json`. The `committed_schema_is_up_to_date` test enforces they stay in sync — regenerate with:

```bash
cargo run --bin generate-policy-schema > schemas/policy.schema.json
```

## Protocol Date

When to bump `SANDBOX_PROTOCOL_DATE` is defined by its doc comment in `crates/lens-sandbox-core/src/protocol.rs` — that comment is the rule; follow it.
