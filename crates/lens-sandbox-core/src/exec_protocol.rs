//! Wire protocol between Lens Sandbox and the agent supervisor.
//!
//! Push-based exec channel. The supervisor serializes raw stdout/stderr
//! bytes as they arrive (base64'd into JSON) instead of buffering for a
//! poll, so keystroke latency is bounded by the supervisor→Lens Sandbox WS
//! one-way delay, not a polling interval.
//!
//! The dispatcher peeks the `type` field via core's `MessagePeek`; any
//! `exec_*` message routes here.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Initial PTY size on attach, in cells.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub struct TerminalSize {
    pub cols: u16,
    pub rows: u16,
}

/// Caller identity for ownership tracking. Lens Sandbox injects this on every
/// inbound `exec_attach` / `exec_reattach` (the multiplexed-WS deployment
/// has many users sharing the same supervisor connection, so identity
/// has to ride on the frame, not the WS). The supervisor stores it on
/// the session at attach time and compares it against the calling actor
/// on reattach to enforce owner-only takeover. Missing identity is
/// "unscoped" — such sessions are not reattachable.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ActorIdentity {
    /// OIDC sub of the user that initiated the action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Email if known (for audit/UX display only — never auth).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

/// Reason an exec session was detached from its current WS client.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DetachReason {
    /// Another client (same owner) took the session over with force=true.
    Stolen,
    /// The supervisor is shutting down (container stopping or restarting).
    SupervisorShutdown,
}

/// Inbound exec frames (Lens Sandbox → supervisor).
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
// The `Exec` prefix is the protocol namespace, not noise — keep it.
#[allow(clippy::enum_variant_names)]
// `stdin/stdout/stderr` booleans on ExecAttach are accepted on the wire
// but not yet honored — the v1 manager always opens all three. Kept on
// the type so the wire surface is stable; allow until the manager wires
// them up.
#[allow(dead_code)]
pub enum IncomingMessage {
    /// Open a new exec session. `argv[0]` is the executable; rest are args.
    /// Booleans default to permissive (`stdin=true`, `stdout=true`,
    /// `stderr=true`) to match the dominant interactive case; an output-only
    /// attach is the special case and is the caller's responsibility to set.
    /// `actor` becomes this exec's `owner` for the rest of its lifetime —
    /// only the same `actor.userId` can `exec_reattach` to it. Omitted
    /// `actor` produces an unscoped session that cannot be reattached.
    #[serde(rename = "exec_attach", rename_all = "camelCase")]
    ExecAttach {
        exec_id: String,
        argv: Vec<String>,
        #[serde(default)]
        env: HashMap<String, String>,
        #[serde(default)]
        cwd: Option<String>,
        #[serde(default)]
        tty: bool,
        #[serde(default = "default_true")]
        stdin: bool,
        #[serde(default = "default_true")]
        stdout: bool,
        #[serde(default = "default_true")]
        stderr: bool,
        #[serde(default)]
        initial_size: Option<TerminalSize>,
        #[serde(default)]
        actor: Option<ActorIdentity>,
    },

    /// base64-encoded bytes to write to the exec's stdin.
    #[serde(rename = "exec_stdin", rename_all = "camelCase")]
    ExecStdin { exec_id: String, data: String },

    /// Close the exec's stdin (no more bytes will follow). The child sees EOF.
    #[serde(rename = "exec_stdin_eof", rename_all = "camelCase")]
    ExecStdinEof { exec_id: String },

    /// Resize the PTY. Only meaningful for `tty=true` sessions; ignored otherwise.
    #[serde(rename = "exec_resize", rename_all = "camelCase")]
    ExecResize {
        exec_id: String,
        cols: u16,
        rows: u16,
    },

    /// Kill the exec child. `signal: None` lets the supervisor pick the
    /// default (SIGTERM); set it explicitly to send a different signal.
    /// No actor check here — Lens Sandbox gates who can hit the cancel endpoint
    /// (member-or-admin scope on the project), and the supervisor trusts
    /// what arrives. Owner-only enforcement is reserved for reattach where
    /// it has a real meaning (silent surveillance prevention).
    #[serde(rename = "exec_cancel", rename_all = "camelCase")]
    ExecCancel {
        exec_id: String,
        #[serde(default)]
        signal: Option<i32>,
    },

    /// Re-attach this WS connection to an existing exec session. Owner-only:
    /// the supervisor rejects attempts to reattach to a session whose
    /// `owner.userId` differs from this call's `actor.userId`. `force=true`
    /// evicts the currently attached WS client (same owner only — there is
    /// no cross-user override). On success, the supervisor replays the
    /// scrollback to the new client and resumes forwarding live output.
    #[serde(rename = "exec_reattach", rename_all = "camelCase")]
    ExecReattach {
        exec_id: String,
        #[serde(default)]
        force: bool,
        #[serde(default)]
        initial_size: Option<TerminalSize>,
        #[serde(default)]
        actor: Option<ActorIdentity>,
    },
}

/// Outbound exec frames (supervisor → Lens).
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "type")]
#[allow(clippy::enum_variant_names)]
pub enum OutgoingMessage {
    /// Spawn succeeded. Sent once per `exec_attach`. Also sent in response
    /// to a successful `exec_reattach`, in which case it's followed by an
    /// `exec_stdout` carrying the scrollback before live output resumes.
    /// `owner` lets clients display "this session belongs to X" and is the
    /// identity the supervisor compares against on future reattach attempts.
    #[serde(rename = "exec_attached", rename_all = "camelCase")]
    ExecAttached {
        exec_id: String,
        pid: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        owner: Option<ActorIdentity>,
    },

    /// Pushed when a previously-attached WS client loses ownership of the
    /// stream. Server-initiated; the client should stop expecting output
    /// for this exec_id on this connection.
    #[serde(rename = "exec_detached", rename_all = "camelCase")]
    ExecDetached {
        exec_id: String,
        reason: DetachReason,
    },

    /// base64-encoded stdout chunk. Multiple frames per session; arbitrary boundaries.
    #[serde(rename = "exec_stdout", rename_all = "camelCase")]
    ExecStdout { exec_id: String, data: String },

    /// base64-encoded stderr chunk. Never emitted when the attach used `tty=true`.
    #[serde(rename = "exec_stderr", rename_all = "camelCase")]
    ExecStderr { exec_id: String, data: String },

    /// Final frame for a successful spawn. After this no more frames carry this exec_id.
    #[serde(rename = "exec_exit", rename_all = "camelCase")]
    ExecExit {
        exec_id: String,
        /// Exit code if the child exited normally.
        #[serde(skip_serializing_if = "Option::is_none")]
        code: Option<i32>,
        /// Signal number if the child was killed by a signal.
        #[serde(skip_serializing_if = "Option::is_none")]
        signal: Option<i32>,
    },

    /// Spawn or runtime failure. Terminal for the exec_id, same as `exec_exit`.
    #[serde(rename = "exec_error", rename_all = "camelCase")]
    ExecError { exec_id: String, message: String },
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> IncomingMessage {
        serde_json::from_str(json).expect("incoming message should parse")
    }

    fn emit(msg: &OutgoingMessage) -> serde_json::Value {
        serde_json::to_value(msg).expect("outgoing message should serialize")
    }

    #[test]
    fn parse_exec_attach_full() {
        let json = r#"{
            "type": "exec_attach",
            "execId": "e1",
            "argv": ["bash", "-l"],
            "env": {"FOO":"bar"},
            "cwd": "/workspace",
            "tty": true,
            "stdin": true,
            "stdout": true,
            "stderr": false,
            "initialSize": {"cols": 120, "rows": 40},
            "actor": {"userId": "user-1", "email": "u@example.com"}
        }"#;

        match parse(json) {
            IncomingMessage::ExecAttach {
                exec_id,
                argv,
                env,
                cwd,
                tty,
                stdin,
                stdout,
                stderr,
                initial_size,
                actor,
            } => {
                assert_eq!(exec_id, "e1");
                assert_eq!(argv, vec!["bash".to_string(), "-l".to_string()]);
                assert_eq!(env.get("FOO").map(String::as_str), Some("bar"));
                assert_eq!(cwd.as_deref(), Some("/workspace"));
                assert!(tty);
                assert!(stdin);
                assert!(stdout);
                assert!(!stderr);
                assert_eq!(
                    initial_size,
                    Some(TerminalSize {
                        cols: 120,
                        rows: 40
                    })
                );
                assert_eq!(
                    actor,
                    Some(ActorIdentity {
                        user_id: Some("user-1".into()),
                        email: Some("u@example.com".into()),
                    })
                );
            }
            other => panic!("expected ExecAttach, got {other:?}"),
        }
    }

    #[test]
    fn parse_exec_attach_defaults_stdio_to_open() {
        // Minimal attach — stdin/stdout/stderr default to true, tty false,
        // no initialSize, empty env, no actor.
        let json = r#"{"type":"exec_attach","execId":"e2","argv":["true"]}"#;

        match parse(json) {
            IncomingMessage::ExecAttach {
                tty,
                stdin,
                stdout,
                stderr,
                initial_size,
                env,
                cwd,
                actor,
                ..
            } => {
                assert!(!tty, "tty must default to false");
                assert!(stdin && stdout && stderr, "stdio bools default to true");
                assert!(initial_size.is_none());
                assert!(env.is_empty());
                assert!(cwd.is_none());
                assert!(actor.is_none(), "actor must default to None");
            }
            other => panic!("expected ExecAttach, got {other:?}"),
        }
    }

    #[test]
    fn parse_exec_stdin_carries_base64_payload() {
        let json = r#"{"type":"exec_stdin","execId":"e1","data":"aGVsbG8="}"#;
        match parse(json) {
            IncomingMessage::ExecStdin { exec_id, data } => {
                assert_eq!(exec_id, "e1");
                assert_eq!(data, "aGVsbG8=");
            }
            other => panic!("expected ExecStdin, got {other:?}"),
        }
    }

    #[test]
    fn parse_exec_stdin_eof() {
        let json = r#"{"type":"exec_stdin_eof","execId":"e1"}"#;
        match parse(json) {
            IncomingMessage::ExecStdinEof { exec_id } => assert_eq!(exec_id, "e1"),
            other => panic!("expected ExecStdinEof, got {other:?}"),
        }
    }

    #[test]
    fn parse_exec_resize() {
        let json = r#"{"type":"exec_resize","execId":"e1","cols":200,"rows":60}"#;
        match parse(json) {
            IncomingMessage::ExecResize {
                exec_id,
                cols,
                rows,
            } => {
                assert_eq!(exec_id, "e1");
                assert_eq!((cols, rows), (200, 60));
            }
            other => panic!("expected ExecResize, got {other:?}"),
        }
    }

    #[test]
    fn parse_exec_cancel_defaults_signal_to_none() {
        let json = r#"{"type":"exec_cancel","execId":"e1"}"#;
        match parse(json) {
            IncomingMessage::ExecCancel { exec_id, signal } => {
                assert_eq!(exec_id, "e1");
                assert_eq!(signal, None);
            }
            other => panic!("expected ExecCancel, got {other:?}"),
        }
    }

    #[test]
    fn parse_exec_cancel_with_signal() {
        let json = r#"{"type":"exec_cancel","execId":"e1","signal":9}"#;
        match parse(json) {
            IncomingMessage::ExecCancel { signal, .. } => {
                assert_eq!(signal, Some(9));
            }
            other => panic!("expected ExecCancel, got {other:?}"),
        }
    }

    #[test]
    fn emit_exec_attached_omits_owner_when_none() {
        let v = emit(&OutgoingMessage::ExecAttached {
            exec_id: "e1".into(),
            pid: 4242,
            owner: None,
        });
        assert_eq!(
            v,
            serde_json::json!({"type":"exec_attached","execId":"e1","pid":4242})
        );
    }

    #[test]
    fn emit_exec_attached_includes_owner_when_set() {
        let v = emit(&OutgoingMessage::ExecAttached {
            exec_id: "e1".into(),
            pid: 4242,
            owner: Some(ActorIdentity {
                user_id: Some("user-123".into()),
                email: Some("alice@example.com".into()),
            }),
        });
        assert_eq!(
            v,
            serde_json::json!({
                "type": "exec_attached",
                "execId": "e1",
                "pid": 4242,
                "owner": { "userId": "user-123", "email": "alice@example.com" },
            }),
        );
    }

    #[test]
    fn parse_exec_reattach_defaults() {
        let json = r#"{"type":"exec_reattach","execId":"e1"}"#;
        match parse(json) {
            IncomingMessage::ExecReattach {
                exec_id,
                force,
                initial_size,
                actor,
            } => {
                assert_eq!(exec_id, "e1");
                assert!(!force, "force defaults to false");
                assert!(initial_size.is_none());
                assert!(actor.is_none());
            }
            other => panic!("expected ExecReattach, got {other:?}"),
        }
    }

    #[test]
    fn parse_exec_reattach_with_force_size_and_actor() {
        let json = r#"{"type":"exec_reattach","execId":"e1","force":true,"initialSize":{"cols":120,"rows":40},"actor":{"userId":"user-1"}}"#;
        match parse(json) {
            IncomingMessage::ExecReattach {
                exec_id,
                force,
                initial_size,
                actor,
            } => {
                assert_eq!(exec_id, "e1");
                assert!(force);
                assert_eq!(
                    initial_size,
                    Some(TerminalSize {
                        cols: 120,
                        rows: 40
                    })
                );
                assert_eq!(
                    actor,
                    Some(ActorIdentity {
                        user_id: Some("user-1".into()),
                        email: None,
                    })
                );
            }
            other => panic!("expected ExecReattach, got {other:?}"),
        }
    }

    #[test]
    fn emit_exec_detached_carries_reason() {
        let v = emit(&OutgoingMessage::ExecDetached {
            exec_id: "e1".into(),
            reason: DetachReason::Stolen,
        });
        assert_eq!(
            v,
            serde_json::json!({"type":"exec_detached","execId":"e1","reason":"stolen"}),
        );
    }

    #[test]
    fn emit_exec_stdout_carries_base64_payload() {
        let v = emit(&OutgoingMessage::ExecStdout {
            exec_id: "e1".into(),
            data: "aGVsbG8=".into(),
        });
        assert_eq!(
            v,
            serde_json::json!({"type":"exec_stdout","execId":"e1","data":"aGVsbG8="})
        );
    }

    #[test]
    fn emit_exec_exit_omits_signal_when_normal() {
        let v = emit(&OutgoingMessage::ExecExit {
            exec_id: "e1".into(),
            code: Some(0),
            signal: None,
        });
        assert_eq!(
            v,
            serde_json::json!({"type":"exec_exit","execId":"e1","code":0})
        );
    }

    #[test]
    fn emit_exec_exit_omits_code_when_killed_by_signal() {
        let v = emit(&OutgoingMessage::ExecExit {
            exec_id: "e1".into(),
            code: None,
            signal: Some(15),
        });
        assert_eq!(
            v,
            serde_json::json!({"type":"exec_exit","execId":"e1","signal":15})
        );
    }

    #[test]
    fn emit_exec_error() {
        let v = emit(&OutgoingMessage::ExecError {
            exec_id: "e1".into(),
            message: "spawn failed: no such file".into(),
        });
        assert_eq!(
            v,
            serde_json::json!({
                "type":"exec_error",
                "execId":"e1",
                "message":"spawn failed: no such file"
            })
        );
    }
}
