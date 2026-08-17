//! The LLM routing table: which requests are claimed, which backend serves
//! them, and which model name that backend is asked for.
//!
//! Everything here is decided at policy-load time. A route names its backend by
//! id in the policy and holds an index into [`LlmRouting::backends`] once
//! parsed, so a route pointing at a backend that does not exist is a load
//! failure rather than a request-time surprise.

use crate::policy_schema::{LlmBackend, LlmCapabilities, LlmPolicy, LlmRoute, LlmTranslation};
use crate::routing::{domain_matches, path_glob_matches};

/// The LLM policy, resolved and ready to match requests against.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LlmRouting {
    backends: Vec<Backend>,
    routes: Vec<Route>,
}

/// One backend, with its URL already split into the parts the dial needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backend {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub capabilities: LlmCapabilities,
    model_map: Vec<ModelMapping>,
}

/// One resolved route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    domain: String,
    path: String,
    model: Option<String>,
    pub translation: LlmTranslation,
    /// Index into [`LlmRouting::backends`], resolved at load.
    backend: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ModelMapping {
    match_pattern: String,
    model: String,
}

/// Default port for the `https` backend URLs this table accepts.
const HTTPS_PORT: u16 = 443;

impl Backend {
    /// The model name to ask this backend for, given the one the sandbox asked
    /// for. First match wins. A name no rule covers is passed through: many
    /// OpenAI-compatible servers serve one model and ignore the field, and
    /// inventing a name for them would be worse than repeating theirs.
    pub fn model_for(&self, requested: &str) -> String {
        self.model_map
            .iter()
            .find(|rule| glob_matches(&rule.match_pattern, requested))
            .map_or_else(|| requested.to_string(), |rule| rule.model.clone())
    }
}

impl LlmRouting {
    /// Resolve a policy block into a table, or say why it cannot be enforced.
    ///
    /// Every failure here fails the whole policy closed at the call site. A
    /// route the proxy cannot honour must not silently become a route it
    /// ignores: the sandbox would then reach the API the policy meant to
    /// redirect, with the credential the policy meant to withhold.
    pub fn from_policy(policy: &LlmPolicy) -> Result<Self, String> {
        let mut backends = Vec::with_capacity(policy.backends.len());
        for raw in &policy.backends {
            if raw.id.is_empty() {
                return Err("llm backend id must not be empty".to_string());
            }
            if backends.iter().any(|b: &Backend| b.id == raw.id) {
                return Err(format!("duplicate llm backend id {:?}", raw.id));
            }
            backends.push(parse_backend(raw)?);
        }

        let mut routes = Vec::with_capacity(policy.routes.len());
        for raw in &policy.routes {
            routes.push(resolve_route(raw, &backends)?);
        }

        Ok(Self { backends, routes })
    }

    /// Whether the table is empty, so the proxy can skip every LLM step.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Whether any route could claim a request to this host and path.
    ///
    /// Deliberately blind to the model: this answers the question the proxy asks
    /// before the TLS handshake, when it decides whether the connection is worth
    /// intercepting, and the body that carries the model does not exist yet. A
    /// model-scoped route therefore makes the proxy read the request that it may
    /// then leave untouched, which costs one parse and no policy.
    pub fn claims(&self, host: &str, path: &str) -> bool {
        self.routes
            .iter()
            .any(|route| route.matches_head(host, path))
    }

    /// Whether any route could claim a request to this host at all.
    ///
    /// This is the earliest question of the three, asked at CONNECT time to
    /// decide whether the connection is worth intercepting. Neither the path nor
    /// the model exists yet, so a host with any route on it is intercepted and
    /// the finer decisions are made once the request is readable. Answering
    /// `false` here is final: a connection that is not intercepted is a request
    /// no route can ever claim.
    pub fn claims_host(&self, host: &str) -> bool {
        self.routes
            .iter()
            .any(|route| domain_matches(&route.domain, hostname_of(host)))
    }

    /// The first route that claims this request, with the backend that serves
    /// it.
    pub fn route_for(&self, host: &str, path: &str, model: &str) -> Option<(&Route, &Backend)> {
        self.routes
            .iter()
            .find(|route| route.matches(host, path, model))
            .map(|route| (route, &self.backends[route.backend]))
    }
}

impl Route {
    /// Whether the head alone puts this request in reach of the route.
    fn matches_head(&self, host: &str, path: &str) -> bool {
        domain_matches(&self.domain, hostname_of(host)) && path_glob_matches(&self.path, path)
    }

    /// Whether this route claims the request, model included.
    fn matches(&self, host: &str, path: &str, model: &str) -> bool {
        self.matches_head(host, path)
            && self
                .model
                .as_deref()
                .is_none_or(|pattern| glob_matches(pattern, model))
    }
}

/// Split a backend URL into the host, port, and path a redirect needs.
fn parse_backend(raw: &LlmBackend) -> Result<Backend, String> {
    let rest = raw.url.strip_prefix("https://").ok_or_else(|| {
        format!(
            "llm backend {:?} url {:?} must start with https:// — the proxy re-encrypts to the \
             backend, and a plain-http backend would carry the injected credential in the clear",
            raw.id, raw.url
        )
    })?;

    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], rest[idx..].to_string()),
        None => (rest, "/".to_string()),
    };

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port_str)) => (
            host,
            port_str.parse::<u16>().map_err(|_| {
                format!(
                    "llm backend {:?} url {:?} has an invalid port",
                    raw.id, raw.url
                )
            })?,
        ),
        None => (authority, HTTPS_PORT),
    };

    if host.is_empty() {
        return Err(format!(
            "llm backend {:?} url {:?} names no host",
            raw.id, raw.url
        ));
    }

    let model_map = raw
        .model_map
        .iter()
        .map(|rule| {
            if rule.match_pattern.is_empty() || rule.model.is_empty() {
                return Err(format!(
                    "llm backend {:?} has a model mapping with an empty match or model",
                    raw.id
                ));
            }
            Ok(ModelMapping {
                match_pattern: rule.match_pattern.clone(),
                model: rule.model.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Backend {
        id: raw.id.clone(),
        host: host.to_ascii_lowercase(),
        port,
        path,
        capabilities: raw.capabilities.clone(),
        model_map,
    })
}

/// Bind a policy route to the backend it names.
fn resolve_route(raw: &LlmRoute, backends: &[Backend]) -> Result<Route, String> {
    if raw.match_request.domain.is_empty() {
        return Err("llm route match.domain must not be empty".to_string());
    }
    if raw.match_request.path.is_empty() {
        return Err("llm route match.path must not be empty".to_string());
    }
    let backend = backends
        .iter()
        .position(|b| b.id == raw.backend)
        .ok_or_else(|| format!("llm route names unknown backend {:?}", raw.backend))?;

    Ok(Route {
        domain: raw.match_request.domain.clone(),
        path: raw.match_request.path.clone(),
        model: raw.match_request.model.clone(),
        translation: raw.translate,
        backend,
    })
}

/// The hostname part of a `host` or `host:port` target.
fn hostname_of(host: &str) -> &str {
    if host.starts_with('[') {
        host.split(']')
            .next()
            .unwrap_or(host)
            .trim_start_matches('[')
    } else {
        host.split(':').next().unwrap_or(host)
    }
}

/// Whether a `*`-glob covers a value.
///
/// Model names are not hostnames and not paths, so neither of the crate's other
/// two matchers fits: `claude-*` must cover `claude-opus-5` without the dot
/// rules `domain_matches` applies, and without the `/` segments
/// `path_glob_matches` counts. `*` stands for any run of characters, anywhere,
/// as many times as the pattern uses it.
pub(crate) fn glob_matches(pattern: &str, value: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == value,
        Some((prefix, rest)) => {
            let Some(tail) = value.strip_prefix(prefix) else {
                return false;
            };
            // The `*` can stand for any run, so every split point is a candidate.
            tail.char_indices()
                .map(|(idx, _)| &tail[idx..])
                .chain(std::iter::once(""))
                .any(|suffix| glob_matches(rest, suffix))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(json: &str) -> LlmPolicy {
        serde_json::from_str(json).expect("policy parses")
    }

    fn table(json: &str) -> LlmRouting {
        LlmRouting::from_policy(&policy(json)).expect("table resolves")
    }

    const ONE_BACKEND: &str = r#"{
        "backends": [{
            "id": "local",
            "url": "https://vllm.internal/v1/chat/completions",
            "modelMap": [
                { "match": "claude-haiku-*", "model": "qwen3-4b-instruct" },
                { "match": "*", "model": "qwen3-coder-30b" }
            ]
        }],
        "routes": [{
            "match": { "domain": "api.anthropic.com", "path": "/v1/messages" },
            "translate": "anthropicMessagesToOpenaiChat",
            "backend": "local"
        }]
    }"#;

    // ----------------------------------------------------------------------
    // Glob
    // ----------------------------------------------------------------------

    #[test]
    fn a_glob_without_a_star_is_an_exact_name() {
        assert!(glob_matches("claude-opus-5", "claude-opus-5"));
        assert!(!glob_matches("claude-opus-5", "claude-opus-4-8"));
    }

    #[test]
    fn a_trailing_star_covers_the_rest_of_the_name() {
        assert!(glob_matches("claude-haiku-*", "claude-haiku-4-5"));
        assert!(!glob_matches("claude-haiku-*", "claude-sonnet-5"));
    }

    #[test]
    fn a_lone_star_covers_every_name() {
        assert!(glob_matches("*", "anything"));
        assert!(glob_matches("*", ""));
    }

    #[test]
    fn a_star_can_stand_in_the_middle_and_repeat() {
        assert!(glob_matches("claude-*-5", "claude-opus-5"));
        assert!(glob_matches("*coder*", "qwen3-coder-30b"));
        assert!(!glob_matches("claude-*-5", "claude-opus-4-8"));
    }

    #[test]
    fn a_star_does_not_let_the_tail_end_early() {
        // The greedy-first reading of `*b` would stop at the first `b`; the
        // pattern demands the name *end* there.
        assert!(!glob_matches("a*b", "abc"));
        assert!(glob_matches("a*b", "axxb"));
    }

    // ----------------------------------------------------------------------
    // Model mapping
    // ----------------------------------------------------------------------

    #[test]
    fn the_first_matching_model_rule_wins() {
        let routing = table(ONE_BACKEND);
        let (_, backend) = routing
            .route_for("api.anthropic.com", "/v1/messages", "claude-haiku-4-5")
            .expect("route claims the request");
        assert_eq!(backend.model_for("claude-haiku-4-5"), "qwen3-4b-instruct");
        assert_eq!(backend.model_for("claude-opus-5"), "qwen3-coder-30b");
    }

    #[test]
    fn a_model_no_rule_covers_keeps_the_name_the_sandbox_sent() {
        let routing = table(
            r#"{
                "backends": [{ "id": "b", "url": "https://x.internal/v1/chat/completions",
                    "modelMap": [{ "match": "claude-opus-*", "model": "big" }] }],
                "routes": [{ "match": { "domain": "api.anthropic.com", "path": "/v1/messages" },
                    "translate": "anthropicMessagesToOpenaiChat", "backend": "b" }]
            }"#,
        );
        let (_, backend) = routing
            .route_for("api.anthropic.com", "/v1/messages", "claude-sonnet-5")
            .expect("route claims the request");
        assert_eq!(backend.model_for("claude-sonnet-5"), "claude-sonnet-5");
    }

    // ----------------------------------------------------------------------
    // Route matching
    // ----------------------------------------------------------------------

    #[test]
    fn a_host_with_any_route_is_worth_intercepting() {
        // Asked at CONNECT time, when neither the path nor the model exists.
        let routing = table(ONE_BACKEND);
        assert!(routing.claims_host("api.anthropic.com"));
        assert!(routing.claims_host("api.anthropic.com:443"));
        assert!(!routing.claims_host("api.openai.com"));
    }

    #[test]
    fn a_route_claims_its_domain_and_path() {
        let routing = table(ONE_BACKEND);
        assert!(routing.claims("api.anthropic.com", "/v1/messages"));
        assert!(routing.claims("api.anthropic.com:443", "/v1/messages"));
        assert!(!routing.claims("api.anthropic.com", "/v1/complete"));
        assert!(!routing.claims("api.openai.com", "/v1/messages"));
    }

    #[test]
    fn a_model_scoped_route_is_skipped_for_another_model() {
        let routing = table(
            r#"{
                "backends": [
                    { "id": "small", "url": "https://small.internal/v1/chat/completions" },
                    { "id": "large", "url": "https://large.internal/v1/chat/completions" }
                ],
                "routes": [
                    { "match": { "domain": "api.anthropic.com", "path": "/v1/messages",
                        "model": "claude-haiku-*" },
                      "translate": "anthropicMessagesToOpenaiChat", "backend": "small" },
                    { "match": { "domain": "api.anthropic.com", "path": "/v1/messages" },
                      "translate": "anthropicMessagesToOpenaiChat", "backend": "large" }
                ]
            }"#,
        );
        let (_, small) = routing
            .route_for("api.anthropic.com", "/v1/messages", "claude-haiku-4-5")
            .expect("the scoped route claims haiku");
        assert_eq!(small.id, "small");
        let (_, large) = routing
            .route_for("api.anthropic.com", "/v1/messages", "claude-opus-5")
            .expect("the open route claims the rest");
        assert_eq!(large.id, "large");
    }

    #[test]
    fn a_model_scoped_route_still_makes_the_head_worth_reading() {
        // `claims` runs before the body exists, so it must say yes on the head
        // alone — otherwise the request is never read and the route never fires.
        let routing = table(
            r#"{
                "backends": [{ "id": "b", "url": "https://x.internal/v1/chat/completions" }],
                "routes": [{ "match": { "domain": "api.anthropic.com", "path": "/v1/messages",
                    "model": "claude-haiku-*" },
                    "translate": "anthropicMessagesToOpenaiChat", "backend": "b" }]
            }"#,
        );
        assert!(routing.claims("api.anthropic.com", "/v1/messages"));
        assert!(
            routing
                .route_for("api.anthropic.com", "/v1/messages", "claude-opus-5")
                .is_none()
        );
    }

    #[test]
    fn a_wildcard_domain_route_claims_its_subdomains() {
        let routing = table(
            r#"{
                "backends": [{ "id": "b", "url": "https://x.internal/v1/chat/completions" }],
                "routes": [{ "match": { "domain": "*.anthropic.com", "path": "/v1/**" },
                    "translate": "anthropicMessagesToOpenaiChat", "backend": "b" }]
            }"#,
        );
        assert!(routing.claims("api.anthropic.com", "/v1/messages"));
        assert!(!routing.claims("api.example.com", "/v1/messages"));
    }

    // ----------------------------------------------------------------------
    // Backend URLs
    // ----------------------------------------------------------------------

    #[test]
    fn a_backend_url_splits_into_host_port_and_path() {
        let routing = table(
            r#"{
                "backends": [{ "id": "b", "url": "https://VLLM.internal:8443/v1/chat/completions" }],
                "routes": [{ "match": { "domain": "api.anthropic.com", "path": "/v1/messages" },
                    "translate": "anthropicMessagesToOpenaiChat", "backend": "b" }]
            }"#,
        );
        let (_, backend) = routing
            .route_for("api.anthropic.com", "/v1/messages", "any")
            .expect("route claims the request");
        assert_eq!(backend.host, "vllm.internal");
        assert_eq!(backend.port, 8443);
        assert_eq!(backend.path, "/v1/chat/completions");
    }

    #[test]
    fn a_backend_url_without_a_port_defaults_to_https() {
        let routing = table(ONE_BACKEND);
        let (_, backend) = routing
            .route_for("api.anthropic.com", "/v1/messages", "any")
            .expect("route claims the request");
        assert_eq!(backend.port, 443);
    }

    #[test]
    fn a_plain_http_backend_fails_the_policy() {
        let err = LlmRouting::from_policy(&policy(
            r#"{
                "backends": [{ "id": "b", "url": "http://x.internal/v1/chat/completions" }],
                "routes": []
            }"#,
        ))
        .expect_err("a cleartext backend would carry the injected credential in the clear");
        assert!(err.contains("https://"), "{err}");
    }

    #[test]
    fn a_route_naming_an_unknown_backend_fails_the_policy() {
        let err = LlmRouting::from_policy(&policy(
            r#"{
                "backends": [{ "id": "b", "url": "https://x.internal/v1/chat/completions" }],
                "routes": [{ "match": { "domain": "api.anthropic.com", "path": "/v1/messages" },
                    "translate": "anthropicMessagesToOpenaiChat", "backend": "typo" }]
            }"#,
        ))
        .expect_err("a route that cannot be honoured must not become a route we ignore");
        assert!(err.contains("typo"), "{err}");
    }

    #[test]
    fn duplicate_backend_ids_fail_the_policy() {
        let err = LlmRouting::from_policy(&policy(
            r#"{
                "backends": [
                    { "id": "b", "url": "https://one.internal/v1/chat/completions" },
                    { "id": "b", "url": "https://two.internal/v1/chat/completions" }
                ],
                "routes": []
            }"#,
        ))
        .expect_err("a route naming a duplicated id would pick a backend by accident");
        assert!(err.contains("duplicate"), "{err}");
    }

    #[test]
    fn an_unknown_key_fails_the_policy() {
        // Every key here narrows or redirects. One serde could not place is a
        // redirect that would go missing without a sound.
        let err = serde_json::from_str::<LlmPolicy>(
            r#"{
                "backends": [{ "id": "b", "url": "https://x.internal/v1", "modlMap": [] }],
                "routes": []
            }"#,
        )
        .expect_err("a misspelt key must fail the policy");
        assert!(err.to_string().contains("modlMap"), "{err}");
    }

    #[test]
    fn an_omitted_capabilities_block_promises_everything() {
        let routing = table(ONE_BACKEND);
        let (_, backend) = routing
            .route_for("api.anthropic.com", "/v1/messages", "any")
            .expect("route claims the request");
        assert!(backend.capabilities.tools);
        assert!(backend.capabilities.images);
    }

    #[test]
    fn a_partial_capabilities_block_keeps_the_rest_promised() {
        let routing = table(
            r#"{
                "backends": [{ "id": "b", "url": "https://x.internal/v1/chat/completions",
                    "capabilities": { "images": false } }],
                "routes": [{ "match": { "domain": "api.anthropic.com", "path": "/v1/messages" },
                    "translate": "anthropicMessagesToOpenaiChat", "backend": "b" }]
            }"#,
        );
        let (_, backend) = routing
            .route_for("api.anthropic.com", "/v1/messages", "any")
            .expect("route claims the request");
        assert!(backend.capabilities.tools);
        assert!(!backend.capabilities.images);
    }
}
