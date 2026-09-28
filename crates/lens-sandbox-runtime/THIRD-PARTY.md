# Third-party code

## NVIDIA OpenShell

- Source: https://github.com/NVIDIA/OpenShell
- Commit: `a3ed8c79cfa162f1f490bc0dea1cb4191e8b83d9`
- License: Apache-2.0. Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. OpenShell has no NOTICE file; its `THIRD-PARTY-NOTICES` lists only its Cargo dependencies.

Each copied file keeps its SPDX header. A file that we changed has a line under the header that says what changed.

| File in this crate | File in OpenShell |
| --- | --- |
| `src/linux/child_seccomp.rs` | `crates/openshell-isolation-interface/src/linux/child_seccomp.rs` |
| `src/linux/proc_fd.rs` | `crates/openshell-isolation-interface/src/linux/proc_fd.rs` |
| `src/linux/process_signal.rs` | `crates/openshell-isolation-interface/src/linux/process_signal.rs` |
| `src/linux/seccomp_notify.rs` | `crates/openshell-isolation-interface/src/linux/seccomp_notify.rs` |
| `src/linux/socket_registry.rs` | `crates/openshell-isolation-interface/src/linux/socket_registry.rs` |
| `src/linux/task_memory.rs` | `crates/openshell-isolation-interface/src/linux/task_memory.rs` |
| `src/linux/workload_launcher.rs` | `crates/openshell-isolation-interface/src/linux/workload_launcher.rs` |
