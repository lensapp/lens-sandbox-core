# Changelog

All notable changes to `lens-sandbox-core` will be documented in this file.

This project will use versioned releases once public releases begin. Until then, the API should be treated as pre-1.0 and subject to change.

## [Unreleased]

- Initial open-source repository hygiene and contribution documentation.
- Add the `lens-sandbox-runtime` and `lens-sandbox-supervisor` crates, which run a sandbox with no root in the workload.
- Keep an exited exec, with its scrollback and its `exec_exit` / `exec_error`, until the client sends the new `exec_ack` frame or five minutes pass. A reattach to an exited exec gets `exec_attached`, the scrollback, then the final frame.
- Add `ExecManager::detach_for_shutdown` and split `ChildExit` into `Finished` and `Stopped`, so a supervisor can tell a workload exit from a stop signal.
- Bump the protocol date to 2026-10-09.
