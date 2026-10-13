# Changelog

All notable changes to `lens-sandbox-core` will be documented in this file.

This project will use versioned releases once public releases begin. Until then, the API should be treated as pre-1.0 and subject to change.

## [Unreleased]

- Initial open-source repository hygiene and contribution documentation.
- Add the `lens-sandbox-runtime` and `lens-sandbox-supervisor` crates, which run a sandbox with no root in the workload.
- Keep an exited exec, with its scrollback and its `exec_exit` / `exec_error`, until the client sends the new `exec_ack` frame or five minutes pass. A reattach to an exited exec gets `exec_attached`, the scrollback, then the final frame.
- Add `ExecManager::detach_for_shutdown` and split `ChildExit` into `Finished` and `Stopped`, so a supervisor can tell a workload exit from a stop signal.
- Bump the protocol date to 2026-10-09.
- The audit dedup folds a failure event only into the same refusal: one with another reason, port, path or caller is sent, so a consumer never files it under the wrong destination.
- A dedup window that folded repeats of a failure event now closes with one summary event: the folded event with `metadata.summary: true`, `metadata.suppressed` (the repeats folded) and `metadata.last_suppressed_at` (when the last of them was refused, RFC 3339), so a consumer can count every refusal. A summary is sent when its window closes, not when the next refusal arrives.
- Add the policy-message field `proxyUpstreamPlainHttp` (`"tunnel"` or `"forward"`). With `"forward"`, the proxy sends a plain-HTTP request to the upstream proxy as a forward-proxy request in absolute form, not through a `CONNECT host:80` tunnel. An absent or unknown value keeps `"tunnel"`.
- Bump the protocol date to 2026-10-13.
