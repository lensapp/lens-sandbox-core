use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The protocol date this sandbox binary was built against (YYYY-MM-DD, zero-padded).
/// Must be >= SANDBOX_MIN_PROTOCOL_DATE in packages/lens-sandbox/src/infra/sandbox-provisioner/types.ts.
/// Bump to today's date when making breaking changes to the sandbox WebSocket protocol.
pub const SANDBOX_PROTOCOL_DATE: &str = "2026-05-13";

/// A temporary file to write before executing a command.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct TempFile {
    /// Absolute path inside the sandbox.
    pub path: String,
    /// File content (text).
    pub content: String,
    /// Unix file mode as integer (e.g. 384 for rw-------).
    pub mode: Option<u32>,
}

/// Check strict YYYY-MM-DD format: length 10, dashes at positions 4 and 7, digits elsewhere.
pub fn is_valid_protocol_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, &c)| i == 4 || i == 7 || c.is_ascii_digit())
}

/// Peek at just the `type` field of an incoming JSON message.
#[derive(Deserialize)]
pub struct MessagePeek {
    #[serde(rename = "type")]
    pub msg_type: String,
}

/// Developer's response to a `request_pending` dialog. The four primary
/// variants match the relay-side Go enum (notify.Decision); `Timeout` is
/// synthesised proxy-side when no decision arrives in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    AllowAlways,
    AllowOnce,
    DenyAlways,
    DenyOnce,
    Timeout,
}

impl Decision {
    /// Whether the held request should be forwarded (Allow*) or denied
    /// (Deny* / Timeout).
    pub fn is_allow(self) -> bool {
        matches!(self, Decision::AllowAlways | Decision::AllowOnce)
    }

    /// Reason string for the resolved audit event so the JSONL trail
    /// records why the request ultimately succeeded or failed.
    pub fn audit_reason(self) -> &'static str {
        match self {
            Decision::AllowAlways => "user-allowed-persisted",
            Decision::AllowOnce => "user-allowed-once",
            Decision::DenyAlways => "user-denied-persisted",
            Decision::DenyOnce => "user-denied-once",
            Decision::Timeout => "decision-timeout",
        }
    }
}

/// Outbound frame asking the relay to open a developer dialog for a
/// request the proxy is holding open. Emitted at the gate decision point;
/// the request handler awaits the matching `RequestDecision`.
#[derive(Debug, Clone, Serialize)]
pub struct RequestPending {
    #[serde(rename = "type")]
    pub msg_type: &'static str,
    pub id: String,
    pub host: String,
    pub action: String,
    pub reason: String,
}

impl RequestPending {
    pub fn new(id: String, host: String, action: String, reason: String) -> Self {
        Self {
            msg_type: "request_pending",
            id,
            host,
            action,
            reason,
        }
    }
}

/// Inbound frame carrying the developer's answer to a pending request.
#[derive(Debug, Clone, Deserialize)]
pub struct RequestDecision {
    pub id: String,
    pub decision: Decision,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_dates() {
        assert!(is_valid_protocol_date("2026-04-01"));
        assert!(is_valid_protocol_date("2099-12-31"));
        assert!(is_valid_protocol_date("0000-01-01"));
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(!is_valid_protocol_date("2026-04-01T00:00:00Z"));
        assert!(!is_valid_protocol_date("2026-4-1"));
        assert!(!is_valid_protocol_date(""));
    }

    #[test]
    fn rejects_missing_dashes() {
        assert!(!is_valid_protocol_date("2026/04/01"));
        assert!(!is_valid_protocol_date("2026-04.01"));
        assert!(!is_valid_protocol_date("20260401xx"));
    }

    #[test]
    fn rejects_non_digits() {
        assert!(!is_valid_protocol_date("abcd-ef-gh"));
        assert!(!is_valid_protocol_date("202X-04-01"));
    }

    #[test]
    fn compiled_constant_is_valid() {
        assert!(is_valid_protocol_date(SANDBOX_PROTOCOL_DATE));
    }

    #[test]
    fn decision_serializes_to_snake_case() {
        for (d, want) in [
            (Decision::AllowAlways, "\"allow_always\""),
            (Decision::AllowOnce, "\"allow_once\""),
            (Decision::DenyAlways, "\"deny_always\""),
            (Decision::DenyOnce, "\"deny_once\""),
            (Decision::Timeout, "\"timeout\""),
        ] {
            assert_eq!(serde_json::to_string(&d).unwrap(), want);
        }
    }

    #[test]
    fn decision_deserializes_from_snake_case() {
        let d: Decision = serde_json::from_str("\"deny_always\"").unwrap();
        assert_eq!(d, Decision::DenyAlways);
    }

    #[test]
    fn decision_is_allow_partitions_allow_vs_deny() {
        assert!(Decision::AllowAlways.is_allow());
        assert!(Decision::AllowOnce.is_allow());
        assert!(!Decision::DenyAlways.is_allow());
        assert!(!Decision::DenyOnce.is_allow());
        assert!(!Decision::Timeout.is_allow());
    }

    #[test]
    fn request_pending_serializes_with_envelope_type() {
        let p = RequestPending::new(
            "id-1".into(),
            "evil.example.com".into(),
            "CONNECT evil.example.com:443".into(),
            "policy-ambiguous".into(),
        );
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["type"], "request_pending");
        assert_eq!(json["id"], "id-1");
        assert_eq!(json["host"], "evil.example.com");
    }

    #[test]
    fn request_decision_deserializes() {
        let raw = r#"{"id":"id-1","decision":"allow_once"}"#;
        let d: RequestDecision = serde_json::from_str(raw).unwrap();
        assert_eq!(d.id, "id-1");
        assert_eq!(d.decision, Decision::AllowOnce);
    }
}
