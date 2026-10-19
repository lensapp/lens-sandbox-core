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
- A refused DNS lookup names its caller in `actor.process` (`file.path` and `lineage`), as a proxy refusal does, so a consumer can tell which `binaries` rule refused it. A lookup with no attributable caller, or under a policy with no `binaries` rule, has no actor.
- A refusal or dedup summary the audit channel does not deliver, because it is disconnected or its connection fails before the event is written, is held and sent first when the channel reconnects, so a reconnect no longer loses the refusals it counted. A held refusal is sent as a summary that counts it, dated when it was refused, folded with any later summary of the same refusal. One summary is held per refusal, up to 1024 of them; refusals past that are counted in one summary with `action` and `metadata.reason` set to `audit-overflow`. A refusal from the approval gate (`user-denied-once`, `decision-timeout`, …) is held the same way and is never folded, so each one is counted.
- The proxy door serves an absolute-form `https://` request (`GET https://host/path HTTP/1.1` in the clear, as BusyBox `wget` sends one) instead of closing the socket on it. It is admitted as the `CONNECT host:443` it names, with the same route, card and Always Allow, then judged and relayed by the MITM pipeline, so HTTP rules, credentials, `llm` routes and the audit apply. A request the door cannot read is answered with 400, and a destination the proxy never dials (loopback, link-local, `localhost`) with 403 on every door, instead of a closed socket, and audited as `blocked-destination` as the transparent door audits it.
- An exec can limit its output: with the new `outputWindow` on `exec_attach` and `exec_reattach`, the supervisor sends at most that many output bytes ahead of the client's new `exec_output_credit` frames, so a child that writes faster than the client reads waits in `write` instead of filling memory. The new `exec_release` frame lets a client that goes away keep the exec running, with no limit, for a reattach. An exec with no `outputWindow` has no limit, as before.
