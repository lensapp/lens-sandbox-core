# lens-sandbox-core

Core library for the Lens Sandbox runtime. Provides the in-container networking stack that enforces policy on sandboxed AI agents: HTTP CONNECT proxy, MITM TLS interception with credential injection, nftables-based network lockdown, DNS filtering, and WebSocket-driven policy lifecycle.

## Setup

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
