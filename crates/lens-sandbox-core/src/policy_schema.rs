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

    /// Optional LLM routing: send a request the sandbox addressed to one LLM
    /// API to a different backend, and translate the wire format on the way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm: Option<LlmPolicy>,
}

/// Where LLM requests go, and what they are translated into.
///
/// This block **redirects, it does not grant**. The backend host is an ordinary
/// destination: it still needs its own [`Egress::http`] rule, and the request
/// still passes every rule on that route. It also names no credential — the
/// [`credentials`](PolicyDocument::credentials) list stays the one place that
/// decides what a host is sent. A redirect drops the credential the sandbox
/// wrote and injects the backend's own, so the key for the API the agent
/// thought it called never reaches the backend.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LlmPolicy {
    /// The backends routes can name. Every [`LlmRoute::backend`] must name one
    /// of these; an unknown id fails the policy.
    #[serde(default)]
    pub backends: Vec<LlmBackend>,

    /// Ordered routes, first match wins.
    #[serde(default)]
    pub routes: Vec<LlmRoute>,
}

/// One LLM backend: where the request goes, and what model it asks for there.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LlmBackend {
    /// Identifier a route points at.
    pub id: String,

    /// Full `https://host[:port]/path` URL of the backend endpoint. The scheme
    /// must be `https`: the proxy re-encrypts to the backend, and a plain-HTTP
    /// backend would carry the injected credential in the clear.
    pub url: String,

    /// Ordered model-name rules, first match wins. Each entry maps the model the
    /// sandbox asked for to the model this backend serves. A name no entry
    /// covers is sent unchanged — many OpenAI-compatible servers serve one model
    /// and ignore the field.
    #[serde(default)]
    pub model_map: Vec<LlmModelMapping>,

    /// What this backend accepts. A request that needs more than it declares is
    /// denied, not quietly cut down: an agent that asked for tools and got prose
    /// cannot tell the difference between a backend that has none and a model
    /// that chose not to use them.
    #[serde(default)]
    pub capabilities: LlmCapabilities,
}

/// One first-match-wins model-name rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LlmModelMapping {
    /// Glob over the model name the sandbox asked for (`claude-haiku-*`, `*`).
    #[serde(rename = "match")]
    pub match_pattern: String,

    /// Model name to ask the backend for.
    pub model: String,
}

/// The parts of a request a backend can serve. Every field defaults to true, so
/// an omitted `capabilities` block promises a backend that accepts everything —
/// which is what an OpenAI-compatible frontier model does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LlmCapabilities {
    /// The backend can be given tools and can call them.
    #[serde(default = "enabled")]
    pub tools: bool,

    /// The backend accepts images in a message.
    #[serde(default = "enabled")]
    pub images: bool,
}

fn enabled() -> bool {
    true
}

impl Default for LlmCapabilities {
    fn default() -> Self {
        Self {
            tools: true,
            images: true,
        }
    }
}

/// A single first-match-wins LLM route.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LlmRoute {
    /// The requests this route claims.
    #[serde(rename = "match")]
    pub match_request: LlmRouteMatch,

    /// The translation applied to the request and to the answer.
    pub translate: LlmTranslation,

    /// [`LlmBackend::id`] of the backend that serves these requests.
    pub backend: String,

    /// Human-readable description of this route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// The requests one [`LlmRoute`] claims. Every field that is set must match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LlmRouteMatch {
    /// Host the sandbox addressed, as a domain pattern (`api.anthropic.com`,
    /// `*.anthropic.com`).
    pub domain: String,

    /// URL path glob, matched exactly as [`HttpRule::path`] is.
    pub path: String,

    /// Glob over the model name in the request body. Omit to claim every model
    /// the domain and path cover — which is how one route sends a whole API to
    /// one backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// The wire formats a route translates between.
///
/// Any pair is allowed, including a pair that names the same format twice. That
/// is a route which changes only where the request goes: nothing in the body is
/// rewritten but the model it names, and the backend is reached with its own
/// credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LlmTranslation {
    /// The format the sandbox speaks, and the format its answer is written in.
    pub from: LlmFormat,

    /// The format the backend speaks.
    pub to: LlmFormat,
}

/// A wire format the proxy can read and write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum LlmFormat {
    /// Anthropic Messages, `POST /v1/messages`.
    AnthropicMessages,
    /// OpenAI Chat Completions, `POST /v1/chat/completions`.
    OpenaiChat,
    /// OpenAI Responses, `POST /v1/responses`.
    OpenaiResponses,
}

/// Network policy controlling what the sandbox can reach.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicy {
    /// **Deprecated** — use [`egress.http`](Egress::http). Accepted as a
    /// back-compat alias: when both are present, `egress.http` wins. Ordered
    /// list of application-layer route rules (first match wins).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_routes: Option<Vec<RouteRule>>,

    /// Egress rules grouped by the layer they filter at. Optional so older
    /// policies that only set the deprecated top-level `allowedRoutes` still
    /// parse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<Egress>,

    /// Verdict for destinations not matching any rule.
    pub default_verdict: Verdict,

    /// Transport applied when the default verdict is `allow`. Ignored when the
    /// default verdict is `deny`.
    pub default_transport: Transport,
}

/// Egress rules split by the protocol at which the destination is filtered.
///
/// - [`http`](Self::http) filters by hostname and can see and rewrite the
///   payload (HTTP rules, TLS termination, credential injection).
/// - [`tcp`](Self::tcp) filters by IP/CIDR and port and never inspects the
///   payload — an opaque byte splice for non-HTTP services.
/// - [`udp`](Self::udp) governs datagrams, which the other two never see.
///
/// `tcp` is a pre-filter: whatever it claims, it governs, and its verdict is
/// final. Only a destination no `tcp` rule matches falls through to `http`.
///
/// Hostname `tcp` rules apply however the traffic reaches the proxy. An IP/CIDR
/// rule can only match an address, so when the workload connects by name it
/// binds after resolution — in time to deny the connection, but not to grant a
/// raw splice, and only where the sandbox resolves the name itself. A route the
/// `http` table sends over `upstream` transport is tunnelled to Lens Sandbox
/// unresolved, so no IP/CIDR rule sees it. Write a hostname rule whenever you
/// want a `tcp` rule to bind by name.
///
/// So a `tcp` allow turns off HTTP rules, credential injection, and inspection
/// for the port it names — that is what asking for a raw splice means. Because
/// every `tcp` rule carries a port, the two lists can describe the same host
/// without colliding: `db.internal:5432` in `tcp` leaves `db.internal:443` to
/// `http`. An overlap on the same port is allowed, and logged at load.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Egress {
    /// Application-layer (hostname + HTTP/TLS) route rules, first match wins.
    /// Same rule type as the deprecated top-level `allowedRoutes`.
    #[serde(default)]
    pub http: Vec<RouteRule>,

    /// Raw TCP rules, first match wins. Each matches a destination by IP/CIDR
    /// or hostname scoped to a required port, and splices the connection
    /// through opaquely — no protocol classification, no TLS interception, no
    /// HTTP rules. Intended for databases, brokers, and caches, including those
    /// that speak TLS (the connection is not intercepted, so pinning works).
    ///
    /// A hostname rule permits its own DNS lookup and pins the resolved IPs, so
    /// it needs no paired [`http`](Self::http) rule (see [`TcpEgressRule`]).
    #[serde(default)]
    pub tcp: Vec<TcpEgressRule>,

    /// Raw UDP rules, first match wins. Matched exactly as [`tcp`](Self::tcp)
    /// is — by IP/CIDR or hostname, always scoped to a port — and never
    /// inspected. UDP is a different protocol from the other two tables, so
    /// this list cannot collide with them: it alone decides what leaves the
    /// sandbox as a datagram.
    ///
    /// UDP is denied unless a rule here allows it. [`default_verdict`] does not
    /// reach this table: it governs destinations the *connection* tables did
    /// not name, and reading it as a datagram grant would open every UDP port
    /// of every policy that allows by default.
    ///
    /// [`default_verdict`]: NetworkPolicy::default_verdict
    #[serde(default)]
    pub udp: Vec<UdpEgressRule>,
}

/// A single first-match-wins raw-TCP egress rule.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TcpEgressRule {
    /// Destination as `ip:port`, `cidr:port`, or `hostname:port` (e.g.
    /// `10.20.5.10:6379`, `10.20.0.0/24:5432`, `[2001:db8::/32]:5432`,
    /// `db.internal:5432`). A port is **required** — a raw connection is spliced
    /// opaquely with no inspection, so a portless "any port" grant would be too
    /// broad; a pattern without a port is rejected and fails the policy closed.
    ///
    /// IP/CIDR patterns match the resolved destination directly at connect
    /// time. Hostname patterns can only match via DNS forward-pinning: the DNS
    /// stub permits the lookup for a matching hostname rule, then pins the
    /// resolved A-record IPs so the raw TCP layer admits the follow-up
    /// connection. A hostname rule is self-sufficient — it gates its own DNS
    /// lookup, so no paired [`http`](Egress::http) rule is required.
    #[serde(rename = "match")]
    pub match_pattern: String,

    /// Policy verdict: allow, deny, or ask.
    pub verdict: Verdict,

    /// Restrict this rule to connections initiated by specific binaries. Same
    /// semantics as [`RouteRule::binaries`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binaries: Option<Vec<String>>,

    /// Human-readable description of this rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A single first-match-wins raw-UDP egress rule.
///
/// The fields are [`TcpEgressRule`]'s, and a destination is matched the same
/// way, including DNS forward-pinning for a hostname pattern. What differs is
/// what a rule can promise, because UDP carries no connection:
///
/// - There is nothing to hold open, so an `ask` verdict cannot suspend the
///   datagram that raised it — see [`Verdict::Ask`].
/// - A verdict is decided once per flow, keyed by address and port. A flow is
///   not a kernel object the way a connection is, so a source port freed by one
///   process and taken by another inherits the decision until the flow expires.
/// - [`binaries`](Self::binaries) needs the sending socket to still be open when
///   the datagram is judged. A program that sends and exits at once (statsd,
///   syslog) cannot be identified, and fails closed.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UdpEgressRule {
    /// Destination as `ip:port`, `cidr:port`, or `hostname:port`. A port is
    /// **required**, exactly as in [`TcpEgressRule::match_pattern`], and for the
    /// same reason: a datagram is forwarded uninspected, so a portless grant
    /// would be too broad.
    ///
    /// Port `53` is refused. Every unmarked DNS datagram is claimed by the
    /// sandbox's own DNS stub before any rule here can see it, so such a rule
    /// could never take effect — and a rule that cannot match is worse than no
    /// rule, because a dead `deny` fails open.
    #[serde(rename = "match")]
    pub match_pattern: String,

    /// Policy verdict: allow, deny, or ask.
    pub verdict: Verdict,

    /// Restrict this rule to datagrams sent by specific binaries. Same
    /// semantics as [`RouteRule::binaries`], with the caveat above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binaries: Option<Vec<String>>,

    /// Human-readable description of this rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
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
    ///
    /// On a [`UdpEgressRule`] there is no request to suspend, so the datagram
    /// that raised the dialog is dropped and the answer governs the ones that
    /// follow. A client that retries — which is every client that expects a
    /// reply — gets through on the retry.
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
    ///
    /// Once a binary-scoped rule claims a host, a later *unrestricted* `allow`
    /// or `ask` for the same host does not re-open it for the excluded caller
    /// (the excluded caller is denied, not prompted). To grant several
    /// binaries, list them together or add more binary-scoped rules; order an
    /// unrestricted rule before the scoped one only if you intend it to win for
    /// everyone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binaries: Option<Vec<String>>,
}

/// A request restriction within a route rule: the method and path it covers,
/// and for a GraphQL endpoint the operation it covers.
///
/// An unknown key fails the policy. Every field here narrows what the rule
/// admits, so a key serde could not place is a narrowing that would go missing:
/// a misspelt `graphql` would leave the bare method and path behind as an
/// unconditional allow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HttpRule {
    /// HTTP method (GET, POST, * for any). Omit for any method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// URL path glob pattern (/api/v1/*, /health, ** for any). Omit for any path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// GraphQL operation this rule covers. Set it only for a GraphQL endpoint:
    /// the proxy then reads the request body, because a GraphQL request puts
    /// the operation there and every call looks like the same `POST /graphql`.
    ///
    /// A GraphQL rule is authoritative over the requests its `method` and
    /// `path` cover. Once one of them matches a request, only a GraphQL rule
    /// can admit it — a rule with no `graphql` block does not apply, even if
    /// its method and path also match. Without that, a broad `POST /**` allow
    /// beside a narrow GraphQL rule would leave the GraphQL rule with no
    /// effect.
    ///
    /// A request the proxy cannot read is denied, never passed on. This covers
    /// a compressed or `multipart/*` body, a body above the inspection limit, a
    /// document that does not parse, and a persisted query that carries no
    /// document.
    ///
    /// A GraphQL rule also covers the WebSocket that carries subscriptions, on
    /// an `https` connection that the proxy terminates. A rule whose
    /// `operationType` is `subscription` or `*` is the only thing that grants a
    /// `Connection: upgrade`, because a GraphQL rule is the only one that can go
    /// on judging what crosses the connection: every graphql-ws message the
    /// sandbox sends is matched against these same rules, and one that no rule
    /// permits closes the connection. A `query` rule that also matches the
    /// handshake head grants nothing, so writing one for HTTP does not hand out a
    /// socket by accident.
    ///
    /// The handshake drops the client's compression offer, because a compressed
    /// frame hides the operation. Plain `ws://` through the forward proxy stays
    /// refused: that door relays a response without reading it, so it cannot tell
    /// an accepted upgrade from a declined one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graphql: Option<GraphqlMatcher>,
}

/// The GraphQL operations one [`HttpRule`] covers. Every field that is set must
/// match the operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GraphqlMatcher {
    /// The operation type this rule covers. It is required, with `*` for any
    /// type: a rule that left the type out would read as a query but would
    /// also cover every mutation.
    pub operation_type: GraphqlOperationTypeMatcher,

    /// The operation name the document must declare, as a glob (`Viewer`,
    /// `Get*`). Omit to cover any name, an unnamed operation included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_name: Option<String>,

    /// The root fields this rule permits, as globs.
    ///
    /// These bound the selection. They do not pick a part of it: **every** root
    /// field the operation selects must match one of the patterns. Thus
    /// `{ viewer deleteRepository }` does not satisfy a rule that lists only
    /// `viewer`. One rule must cover an operation alone — two rules that each
    /// permit one half of a selection do not combine.
    ///
    /// Omit to put no condition on the fields. A rule that names fields also
    /// denies every field it does not name, which includes introspection
    /// through `__schema`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
}

/// The operation types a [`GraphqlMatcher`] can cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum GraphqlOperationTypeMatcher {
    /// A read.
    Query,
    /// A write.
    Mutation,
    /// A stream. This is the type that grants a `Connection: upgrade`, so a rule
    /// naming it is what lets a subscription open at all. See the note on
    /// [`HttpRule::graphql`].
    Subscription,
    /// Any operation type, `subscription` included, so this grants an upgrade too.
    #[serde(rename = "*")]
    Any,
}

/// HTTP method/path restriction on a credential injection.
///
/// This is deliberately not [`HttpRule`]. An injection is decided from the
/// request head alone, so a GraphQL matcher would have nothing here to act on.
/// Two types keep that state unrepresentable instead of quietly ignored — and
/// an unknown key fails the policy, so `graphql` written here is refused at the
/// parse boundary rather than dropped on the way in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HttpRequestMatch {
    /// HTTP method (GET, POST, * for any). Omit for any method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// URL path glob pattern (/api/v1/*, /health, ** for any). Omit for any path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// What a GraphQL operation does. Names the three operation types the GraphQL
/// specification defines, with no wildcard: this is what a request *is*, either
/// as parsed from its document or as recorded for a persisted query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum GraphqlOperationType {
    /// A read.
    Query,
    /// A write.
    Mutation,
    /// A long-lived stream. Served over a WebSocket upgrade, where the proxy
    /// reads each message the sandbox sends — see [`crate::graphql_ws`].
    Subscription,
}

impl std::fmt::Display for GraphqlOperationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Query => write!(f, "query"),
            Self::Mutation => write!(f, "mutation"),
            Self::Subscription => write!(f, "subscription"),
        }
    }
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
        rules: Vec<HttpRequestMatch>,
    },
    UriPlaceholder {
        /// Domain this injection applies to.
        domain: String,
        /// Resolved credential value used for URI rewriting.
        value: String,
        /// Optional path rules. When empty, rewrite for all requests.
        #[serde(default)]
        rules: Vec<HttpRequestMatch>,
    },
    /// Re-signs every request to [`domain`](Self::AwsSigv4::domain). This
    /// variant takes no path rules: signing is decided by domain alone, and a
    /// `rules` key here is read and dropped.
    AwsSigv4 {
        /// Domain pattern this credential re-signs (e.g. `*.amazonaws.com`).
        domain: String,
        /// Real STS-derived access key ID (starts with `ASIA`).
        access_key_id: String,
        /// Real STS-derived secret access key.
        secret_access_key: String,
        /// Real STS session token.
        session_token: String,
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
