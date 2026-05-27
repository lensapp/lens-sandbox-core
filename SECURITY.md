# Security Policy

`lens-sandbox-core` is security-sensitive infrastructure. It includes policy enforcement, network mediation, DNS filtering, TLS handling, boundary credential exchange, privilege dropping, and sandbox lifecycle code used by Lens Sandbox and Lens Agents.

## Reporting Vulnerabilities

Please do not open a public issue for suspected vulnerabilities.

Report security issues by emailing:

```text
security@lenshq.io
```

Include as much detail as possible:

- Affected component or file path, if known
- Impact and expected security boundary
- Reproduction steps or proof of concept
- Environment details, such as OS, kernel, container runtime, microVM runtime, and required capabilities
- Whether credentials, audit records, network policy, DNS policy, or sandbox escape boundaries are involved

We will acknowledge reports as quickly as practical and coordinate remediation before public disclosure.

## Security Scope

Security-sensitive areas include:

- Policy parsing, validation, lifecycle, and enforcement
- HTTP CONNECT proxy behavior
- Transparent proxy classification and routing
- DNS filtering and allowlist behavior
- TLS certificate authority handling and interception paths
- Boundary credential exchange and request signing
- nftables rule generation and network lockdown
- Privilege dropping and process execution
- WebSocket control-plane communication
- Audit and activity event generation

## Security Boundaries

This crate provides core enforcement primitives used inside sandboxed environments. It is not, by itself, a complete end-user sandbox product. The effective boundary depends on how callers deploy it, including the surrounding container, microVM, Linux capabilities, filesystem mounts, process model, and policy source.

When in doubt, treat changes to network, credentials, process execution, or policy behavior as security-sensitive.
