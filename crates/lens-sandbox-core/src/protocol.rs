use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The protocol date this sandbox binary was built against (YYYY-MM-DD, zero-padded).
/// Must be >= SANDBOX_MIN_PROTOCOL_DATE in packages/lens-sandbox/src/infra/sandbox-provisioner/types.ts.
/// Bump to today's date in the same commit as any change to `policy_schema.rs`
/// or the wire types in this file — an older sandbox must not accept a policy it
/// cannot enforce.
pub const SANDBOX_PROTOCOL_DATE: &str = "2026-09-02";

/// A file to write before executing a command.
///
/// Exactly one of [`content`](Self::content) and
/// [`content_b64`](Self::content_b64) must be set; an entry setting both is
/// rejected and the whole batch fails closed.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TempFile {
    /// Path inside the sandbox. Absolute, relative to the primary allowed
    /// root, or `~/`-prefixed to resolve against the sandbox user's home.
    pub path: String,
    /// File content as text. Mutually exclusive with `contentB64`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// File content as standard base64, for bytes that are not valid text.
    /// Mutually exclusive with `content`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_b64: Option<String>,
    /// Unix file mode as integer (e.g. 384 for rw-------).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    /// Who owns the delivered file. Absent means `workload`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<FileOwner>,
}

/// Who a [`TempFile`] is chowned to after the root supervisor creates it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileOwner {
    /// The unprivileged sandbox user — the default, and the only owner that
    /// lets the workload read the file whatever its `mode`.
    Workload,
    /// Left owned by root, so a `mode` that denies other keeps the contents
    /// from the workload. Two things this does not claim: a world-readable
    /// `mode` is still world-readable, and unlink and rename permission comes
    /// from the parent directory, so a workload that owns the parent can still
    /// delete the file or put its own file at that path.
    Root,
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
    pub treatment: Treatment,
}

impl RequestPending {
    pub fn new(
        id: String,
        host: String,
        action: String,
        reason: String,
        treatment: Treatment,
    ) -> Self {
        Self {
            msg_type: "request_pending",
            id,
            host,
            action,
            reason,
            treatment,
        }
    }
}

/// What approving a pending request actually permits.
///
/// `action` cannot express this: a raw `egress.tcp` splice and an inspected
/// `egress.http` tunnel both render as `CONNECT host:port`, differing only by a
/// port number the reader would have to map back to the policy. The two are not
/// equally consequential — approving `Raw` accepts that the connection is opaque
/// to the proxy, so no HTTP rules, credential injection, or per-request audit
/// apply to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Treatment {
    /// Bytes are spliced through untouched — an `egress.tcp` rule claimed it.
    Raw,
    /// The proxy terminates and inspects — an `egress.http` route governs it.
    Inspected,
    /// A datagram an `egress.udp` rule claimed. Opaque like `Raw`, and one
    /// thing more: nothing is being held. The datagram that raised the dialog
    /// is already gone, so an approval governs what the workload sends next,
    /// not what it sent. A card for this must not promise to release anything.
    Datagram,
}

/// Inbound frame carrying the developer's answer to a pending request.
#[derive(Debug, Clone, Deserialize)]
pub struct RequestDecision {
    pub id: String,
    pub decision: Decision,
}

/// Developer's response to a `credential_pending` dialog. Unlike
/// [`Decision`] there is no once/always distinction — every credential
/// decision is sticky and recorded host-side (lens-sandbox writes them
/// to `~/.lns-credentials.json`). `Timeout` is synthesised
/// proxy-side when no decision arrives in time.
///
/// On `Allow`, the host arms the matching `Credential.injections` with a
/// `policy` frame that MUST arrive *before* the `credential_decision`: the
/// reader applies frames in order, so the held request re-reads credential
/// state the instant the decision wakes it. Decision-before-policy loses
/// the race and the held request fails closed as `policy-frame-missing`.
/// This enum does NOT carry the real credential value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialDecisionKind {
    Allow,
    Deny,
    Timeout,
}

impl CredentialDecisionKind {
    pub fn is_allow(self) -> bool {
        matches!(self, CredentialDecisionKind::Allow)
    }

    pub fn audit_reason(self) -> &'static str {
        match self {
            CredentialDecisionKind::Allow => "user-allowed",
            CredentialDecisionKind::Deny => "user-denied",
            CredentialDecisionKind::Timeout => "decision-timeout",
        }
    }
}

/// Outbound frame asking the relay to open a developer dialog for an
/// outbound request whose headers carry a value matching a registered
/// [`crate::policy_schema::Credential::placeholder`] whose `injections`
/// are empty. The request handler awaits the matching
/// [`CredentialDecision`]; on `Allow`, the host must arm the credential
/// with a `policy` frame sent *before* the decision, after which the held
/// request is forwarded with the substitution applied.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialPending {
    #[serde(rename = "type")]
    pub msg_type: &'static str,
    pub id: String,
    pub credential_id: String,
    pub action: String,
    pub reason: String,
}

impl CredentialPending {
    pub fn new(id: String, credential_id: String, action: String, reason: String) -> Self {
        Self {
            msg_type: "credential_pending",
            id,
            credential_id,
            action,
            reason,
        }
    }
}

/// Inbound frame carrying the developer's answer to a pending credential
/// dialog. The decision gates whether the held request is forwarded; the
/// real credential value, if any, arrives separately in a `policy` frame
/// the host must send *before* this decision (see [`CredentialDecisionKind`]).
#[derive(Debug, Clone, Deserialize)]
pub struct CredentialDecision {
    pub id: String,
    pub decision: CredentialDecisionKind,
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
            Treatment::Raw,
        );
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["type"], "request_pending");
        assert_eq!(json["id"], "id-1");
        assert_eq!(json["host"], "evil.example.com");
        assert_eq!(json["treatment"], "raw");
    }

    #[test]
    fn request_decision_deserializes() {
        let raw = r#"{"id":"id-1","decision":"allow_once"}"#;
        let d: RequestDecision = serde_json::from_str(raw).unwrap();
        assert_eq!(d.id, "id-1");
        assert_eq!(d.decision, Decision::AllowOnce);
    }

    #[test]
    fn credential_decision_kind_serializes_to_snake_case() {
        for (k, want) in [
            (CredentialDecisionKind::Allow, "\"allow\""),
            (CredentialDecisionKind::Deny, "\"deny\""),
            (CredentialDecisionKind::Timeout, "\"timeout\""),
        ] {
            assert_eq!(serde_json::to_string(&k).unwrap(), want);
        }
    }

    #[test]
    fn credential_decision_kind_deserializes_from_snake_case() {
        let k: CredentialDecisionKind = serde_json::from_str("\"deny\"").unwrap();
        assert_eq!(k, CredentialDecisionKind::Deny);
    }

    #[test]
    fn credential_decision_kind_is_allow_partitions_allow_vs_deny() {
        assert!(CredentialDecisionKind::Allow.is_allow());
        assert!(!CredentialDecisionKind::Deny.is_allow());
        assert!(!CredentialDecisionKind::Timeout.is_allow());
    }

    #[test]
    fn credential_decision_kind_audit_reason_per_variant() {
        assert_eq!(CredentialDecisionKind::Allow.audit_reason(), "user-allowed");
        assert_eq!(CredentialDecisionKind::Deny.audit_reason(), "user-denied");
        assert_eq!(
            CredentialDecisionKind::Timeout.audit_reason(),
            "decision-timeout"
        );
    }

    #[test]
    fn credential_pending_serializes_with_envelope_type_and_camel_case_credential_id() {
        let p = CredentialPending::new(
            "cred-1".into(),
            "github".into(),
            "POST https://api.github.com/issues".into(),
            "placeholder-unauthorized".into(),
        );
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["type"], "credential_pending");
        assert_eq!(json["id"], "cred-1");
        assert_eq!(json["credentialId"], "github");
        assert_eq!(json["action"], "POST https://api.github.com/issues");
        assert_eq!(json["reason"], "placeholder-unauthorized");
        assert!(
            json.get("credential_id").is_none(),
            "rust ident leaked: {json}"
        );
    }

    #[test]
    fn temp_file_from_an_old_sender_still_parses() {
        let raw = r#"{"path":"/tmp/x.json","content":"hi","mode":384}"#;
        let f: TempFile = serde_json::from_str(raw).unwrap();
        assert_eq!(f.content.as_deref(), Some("hi"));
        assert_eq!(f.content_b64, None);
        assert_eq!(f.mode, Some(384));
        assert_eq!(f.owner, None);
    }

    #[test]
    fn temp_file_reads_camel_case_content_b64_and_owner() {
        let raw = r#"{"path":"~/blob.bin","contentB64":"AAE=","owner":"root"}"#;
        let f: TempFile = serde_json::from_str(raw).unwrap();
        assert_eq!(f.content, None);
        assert_eq!(f.content_b64.as_deref(), Some("AAE="));
        assert_eq!(f.owner, Some(FileOwner::Root));
    }

    #[test]
    fn temp_file_serializes_content_b64_as_camel_case() {
        let f = TempFile {
            path: "/tmp/blob.bin".to_string(),
            content: None,
            content_b64: Some("AAE=".to_string()),
            mode: None,
            owner: Some(FileOwner::Workload),
        };
        let json = serde_json::to_value(&f).unwrap();
        assert_eq!(json["contentB64"], "AAE=");
        assert_eq!(json["owner"], "workload");
        assert!(
            json.get("content_b64").is_none(),
            "rust ident leaked: {json}"
        );
    }

    #[test]
    fn credential_decision_deserializes_with_snake_case_decision() {
        let raw = r#"{"id":"cred-1","decision":"allow"}"#;
        let d: CredentialDecision = serde_json::from_str(raw).unwrap();
        assert_eq!(d.id, "cred-1");
        assert_eq!(d.decision, CredentialDecisionKind::Allow);
    }
}
