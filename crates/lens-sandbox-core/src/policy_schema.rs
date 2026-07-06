//! Public policy types for JSON Schema generation.
//!
//! These types define the policy document the sandbox accepts. They serve as the
//! canonical schema for validating policies across components (sandbox, API, CLI, UI).
//!
//! Transport-only fields (proxyUpstream, proxyCaCert, minProtocolDate) are intentionally
//! excluded — they're filled by the server, not part of the policy definition.

use std::collections::HashMap;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

use crate::protocol::TempFile;

/// Deserialize a `Vec<T>` that tolerates JSON `null` by returning an empty vec.
/// `#[serde(default)]` only handles absent keys, not explicit `null` values.
fn deserialize_null_as_empty_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<Vec<T>>::deserialize(deserializer).map(|opt| opt.unwrap_or_default())
}

/// The sandbox policy document.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyDocument {
    /// Network routing rules and default verdict + transport.
    #[serde(default)]
    pub network: Option<NetworkPolicy>,

    /// Credentials delivered to the sandbox. Each entry carries a `kind`
    /// discriminator: `static` for fixed-value injection (header / URI
    /// placeholder), `awsSigv4` for MITM SigV4 re-signing.
    #[serde(default)]
    pub credentials: Option<Vec<Credential>>,

    /// Environment variables set in the sandbox.
    #[serde(default)]
    pub env: Option<HashMap<String, String>>,

    /// Files written into the sandbox before execution.
    #[serde(default)]
    pub files: Option<Vec<TempFile>>,
}

/// Network policy controlling which domains the sandbox can reach.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicy {
    /// Ordered list of route rules (first match wins).
    pub allowed_routes: Vec<RouteRule>,

    /// Verdict for destinations not matching any route rule.
    pub default_verdict: Verdict,

    /// Transport applied when the default verdict is `allow`. Ignored when the
    /// default verdict is `deny`.
    pub default_transport: Transport,
}

/// Verdict for a matched route or as default: should the connection be allowed,
/// blocked, or held for developer approval?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Allow the connection using `transport`.
    Allow,
    /// Block the connection. `transport` is ignored.
    Deny,
    /// Suspend the request and prompt the developer; on approval, allow using
    /// `transport`. Only meaningful in interactive environments (local CLI
    /// relay); remote/unattended consumers should keep using `Deny` so
    /// requests fail closed without waiting for a human.
    Ask,
}

/// How an allowed connection reaches its destination — through the Lens Sandbox
/// upstream proxy or by direct egress from the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// Route through the upstream Lens Sandbox proxy (audit, credential injection,
    /// usage tracking).
    Upstream,
    /// Direct egress from the sandbox (no proxy).
    Direct,
}

/// URI scheme a route rule applies to. When omitted on a rule, the rule matches
/// both schemes; when set, only requests with that scheme match. CONNECT is
/// always `https`; HTTP forward-proxy requests are always `http`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Http,
    Https,
}

/// A single first-match-wins route rule.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RouteRule {
    /// Domain pattern, wildcard (*.github.com), CIDR (10.0.0.0/8), or host:port.
    #[serde(rename = "match")]
    pub match_pattern: String,

    /// Policy verdict: allow or deny.
    pub verdict: Verdict,

    /// Transport for the connection when allowed. Required on every rule;
    /// ignored when `verdict` is `deny`.
    pub transport: Transport,

    /// Restrict this rule to a specific URI scheme (`http` or `https`).
    /// When omitted, the rule matches both schemes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<Scheme>,

    /// Human-readable description of this rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// When true, the proxy terminates client TLS and forwards through the tunnel.
    #[serde(default)]
    pub tls_terminate: bool,

    /// Forwarding config for tunnel-routed connections (mTLS bridge).
    /// Server-injected — not set in user-defined policies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forward: Option<ForwardConfig>,

    /// HTTP-level rules. When present, only matching requests are allowed (deny-by-default).
    /// When absent or empty, all HTTP requests to this destination are allowed.
    #[serde(default)]
    pub rules: Vec<HttpRule>,

    /// Restrict this rule to connections initiated by specific binaries.
    /// When omitted, the rule matches any caller. When present, the connecting
    /// process's executable path — or any ancestor's path up to `init` — must
    /// equal one of the listed absolute paths (e.g. `/usr/bin/curl`). Paths are
    /// matched against the kernel-resolved `/proc/<pid>/exe` target, so list the
    /// canonical binary path, not a symlink or PATH shim.
    ///
    /// The filter scopes the whole rule regardless of `verdict`: a rule whose
    /// host matches but whose binary filter excludes the caller fails closed —
    /// the connection is denied rather than falling through to the default
    /// action. On a `deny` rule this means every caller reaching the host is
    /// denied (the listed binaries by verdict, the rest by fail-closed), so
    /// `binaries` is only meaningful on `allow` rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binaries: Option<Vec<String>>,
}

/// HTTP method/path restriction within a route rule.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HttpRule {
    /// HTTP method (GET, POST, * for any). Omit for any method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// URL path glob pattern (/api/v1/*, /health, ** for any). Omit for any path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// TLS bridge forwarding config for tunnel-routed connections.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ForwardConfig {
    /// Address to dial through the tunnel.
    pub dial_addr: String,

    /// TLS server name for upstream verification.
    pub tls_server_name: String,

    /// Host header to send to upstream (for path-based gateways).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_host_header: Option<String>,

    /// Client certificate PEM.
    pub cert_pem: String,

    /// Client private key PEM.
    pub key_pem: String,

    /// CA certificate PEM for upstream verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem: Option<String>,
}

/// A credential delivered to the sandbox. The credential shape is uniform
/// — what differs is HOW each of its [`injections`](Self::injections) is
/// applied at the MITM (see [`CredentialInjection`]).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    /// Credential identifier.
    pub id: String,

    /// Environment variable name to expose a placeholder value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_var: Option<String>,

    /// Placeholder value set in the environment variable. For
    /// `awsSigv4` injections this doubles as the fake access key ID the
    /// sandbox SDK signs requests with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,

    /// Per-domain injection rules. Each entry carries its own
    /// `injectionType` discriminator and the fields required for that kind.
    /// An entry whose resolved `value` is empty is *unarmed*: its domain is
    /// declared so the proxy can gate the placeholder's first use, but no
    /// secret is substituted until a follow-up policy arms it. See
    /// [`CredentialInjection::unarmed_domain`].
    #[serde(default, deserialize_with = "deserialize_null_as_empty_vec")]
    pub injections: Vec<CredentialInjection>,
}

/// How a credential applies to outbound requests on a specific domain.
/// Tagged at the JSON level by `injectionType` — each variant carries the
/// fields it actually needs, required at compile time.
///
/// - **`header`**: replace an HTTP header on matching requests. The MITM
///   substitutes [`value`] into [`header`].
/// - **`uriPlaceholder`**: rewrite `__lens_cred:<name>__` placeholder
///   patterns in the request URI to the real credential value.
/// - **`awsSigv4`**: strip the fake AWS SigV4 signature (the SDK signs with
///   `placeholder` on the parent [`Credential`]) and re-sign with the real
///   STS credentials below. Real creds live only in sandbox-core process
///   memory — they never touch the sandbox filesystem.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "injectionType",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum CredentialInjection {
    Header {
        /// Domain this injection applies to.
        domain: String,
        /// HTTP header name to replace.
        header: String,
        /// Resolved header value (e.g. `Bearer <token>`).
        value: String,
        /// Optional path rules. When empty, inject for all requests.
        #[serde(default)]
        rules: Vec<HttpRule>,
    },
    UriPlaceholder {
        /// Domain this injection applies to.
        domain: String,
        /// Resolved credential value used for URI rewriting.
        value: String,
        /// Optional path rules. When empty, rewrite for all requests.
        #[serde(default)]
        rules: Vec<HttpRule>,
    },
    AwsSigv4 {
        /// Domain pattern this credential re-signs (e.g. `*.amazonaws.com`).
        domain: String,
        /// Real STS-derived access key ID (starts with `ASIA`).
        access_key_id: String,
        /// Real STS-derived secret access key.
        secret_access_key: String,
        /// Real STS session token.
        session_token: String,
        /// Optional path rules. When empty, re-sign for all requests.
        #[serde(default)]
        rules: Vec<HttpRule>,
    },
}

impl CredentialInjection {
    /// The domain this injection targets while it carries no resolved secret
    /// (`value` empty) — the credential-gate trigger for an unarmed
    /// credential. `None` for armed injections and for `awsSigv4`, whose
    /// secret is resolved out-of-band and is not gated this way.
    pub fn unarmed_domain(&self) -> Option<&str> {
        match self {
            CredentialInjection::Header { domain, value, .. }
            | CredentialInjection::UriPlaceholder { domain, value, .. }
                if value.is_empty() =>
            {
                Some(domain)
            }
            _ => None,
        }
    }
}

/// Generate the JSON Schema for [`PolicyDocument`].
pub fn generate_json_schema() -> schemars::Schema {
    schemars::schema_for!(PolicyDocument)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unarmed_domain_flags_empty_value_header_and_uri_only() {
        let armed_header = CredentialInjection::Header {
            domain: "api.github.com".into(),
            header: "Authorization".into(),
            value: "Bearer real".into(),
            rules: vec![],
        };
        let unarmed_header = CredentialInjection::Header {
            domain: "api.github.com".into(),
            header: "Authorization".into(),
            value: String::new(),
            rules: vec![],
        };
        let unarmed_uri = CredentialInjection::UriPlaceholder {
            domain: "api.telegram.org".into(),
            value: String::new(),
            rules: vec![],
        };
        let aws = CredentialInjection::AwsSigv4 {
            domain: "*.amazonaws.com".into(),
            access_key_id: String::new(),
            secret_access_key: String::new(),
            session_token: String::new(),
            rules: vec![],
        };

        assert_eq!(armed_header.unarmed_domain(), None);
        assert_eq!(unarmed_header.unarmed_domain(), Some("api.github.com"));
        assert_eq!(unarmed_uri.unarmed_domain(), Some("api.telegram.org"));
        // awsSigv4 is resolved out-of-band; empty fields are not a gate trigger.
        assert_eq!(aws.unarmed_domain(), None);
    }

    #[test]
    fn credential_injection_deserializes_header_variant() {
        let json = r#"{"injectionType":"header","domain":"api.example.com","header":"Authorization","value":"Bearer x"}"#;
        let inj: CredentialInjection = serde_json::from_str(json).unwrap();
        match inj {
            CredentialInjection::Header {
                domain,
                header,
                value,
                rules,
            } => {
                assert_eq!(domain, "api.example.com");
                assert_eq!(header, "Authorization");
                assert_eq!(value, "Bearer x");
                assert!(rules.is_empty());
            }
            _ => panic!("expected Header variant"),
        }
    }

    #[test]
    fn credential_injection_deserializes_uri_placeholder_variant() {
        let json =
            r#"{"injectionType":"uriPlaceholder","domain":"api.telegram.org","value":"123:ABC"}"#;
        let inj: CredentialInjection = serde_json::from_str(json).unwrap();
        match inj {
            CredentialInjection::UriPlaceholder { domain, value, .. } => {
                assert_eq!(domain, "api.telegram.org");
                assert_eq!(value, "123:ABC");
            }
            _ => panic!("expected UriPlaceholder variant"),
        }
    }

    #[test]
    fn credential_injection_deserializes_aws_sigv4_variant() {
        // `region` is present in the payload for back-compat with older
        // Lens Sandbox versions that still send it — serde drops it silently.
        let json = r#"{
            "injectionType": "awsSigv4",
            "domain": "*.amazonaws.com",
            "accessKeyId": "ASIAEXAMPLE",
            "secretAccessKey": "real-secret",
            "sessionToken": "real-session",
            "region": "us-east-1"
        }"#;
        let inj: CredentialInjection = serde_json::from_str(json).unwrap();
        match inj {
            CredentialInjection::AwsSigv4 {
                domain,
                access_key_id,
                secret_access_key,
                session_token,
                ..
            } => {
                assert_eq!(domain, "*.amazonaws.com");
                assert_eq!(access_key_id, "ASIAEXAMPLE");
                assert_eq!(secret_access_key, "real-secret");
                assert_eq!(session_token, "real-session");
            }
            _ => panic!("expected AwsSigv4 variant"),
        }
    }

    #[test]
    fn credential_injection_rejects_unknown_kind() {
        let json = r#"{"injectionType":"exotic","domain":"x"}"#;
        let result: Result<CredentialInjection, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn credential_injection_rejects_missing_injection_type() {
        let json = r#"{"domain":"api.example.com","header":"Authorization","value":"Bearer x"}"#;
        let result: Result<CredentialInjection, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "injectionType is required — no implicit default"
        );
    }

    #[test]
    fn credential_injection_aws_sigv4_requires_all_aws_fields() {
        // Missing `sessionToken` must fail.
        let json = r#"{
            "injectionType": "awsSigv4",
            "domain": "*.amazonaws.com",
            "accessKeyId": "ASIA",
            "secretAccessKey": "s"
        }"#;
        let result: Result<CredentialInjection, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "all AWS credential fields must be required"
        );
    }

    #[test]
    fn credential_with_aws_sigv4_injection_parses_inside_policy_document() {
        let json = r#"{
            "credentials": [{
                "id": "aws-prod",
                "placeholder": "LENSFAKE00AABB0000CC",
                "injections": [{
                    "injectionType": "awsSigv4",
                    "domain": "*.amazonaws.com",
                    "accessKeyId": "ASIAEXAMPLE",
                    "secretAccessKey": "s",
                    "sessionToken": "t",
                    "region": "us-east-1"
                }]
            }]
        }"#;
        let doc: PolicyDocument = serde_json::from_str(json).unwrap();
        let creds = doc.credentials.expect("credentials present");
        assert_eq!(creds.len(), 1);
        assert_eq!(
            creds[0].placeholder.as_deref(),
            Some("LENSFAKE00AABB0000CC")
        );
        assert!(matches!(
            creds[0].injections[0],
            CredentialInjection::AwsSigv4 { .. }
        ));
    }

    #[test]
    fn committed_schema_is_up_to_date() {
        let generated = serde_json::to_string_pretty(&generate_json_schema()).unwrap();
        let schema_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/policy.schema.json");
        let committed = std::fs::read_to_string(&schema_path).unwrap_or_else(|e| {
            panic!(
                "failed to read {}: {e} — run: npm run schema:policy",
                schema_path.display()
            )
        });
        assert_eq!(
            committed.trim(),
            generated.trim(),
            "schemas/policy.schema.json is stale — run: npm run schema:policy"
        );
    }
}
