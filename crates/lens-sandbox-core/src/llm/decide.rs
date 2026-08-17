//! What the LLM table makes of one request.
//!
//! This is where the table, the capability check, and the wire translation meet.
//! Each of them is decided elsewhere and tested on its own; the order they run
//! in is decided here, and it matters:
//!
//! 1. The model name is read first, because a route may be scoped to one.
//! 2. Capabilities are checked before anything is translated, so a request the
//!    backend cannot serve is refused rather than half-rewritten.
//! 3. So is every content block, because a translation drops what it cannot
//!    carry and this proxy refuses it instead.
//! 4. Only then is the body translated.

use serde_json::Value;

use super::table::{Backend, LlmRouting};
use super::{Outcome, Redirect, inspect, translate};
use crate::policy_schema::{LlmCapabilities, LlmTranslation};

/// Longest model name the table will match a glob against. Real names are a few
/// dozen characters; this is generous enough that no backend can outgrow it and
/// small enough that no request can make matching cost anything.
const MAX_MODEL_NAME_BYTES: usize = 256;

/// Decide what happens to a request the sandbox addressed to `host` `path`.
///
/// `body` is the request body as the sandbox wrote it.
pub fn decide(routing: &LlmRouting, host: &str, path: &str, body: &[u8]) -> Outcome {
    if !routing.claims(host, path) {
        return Outcome::Untouched;
    }
    // A request with no body is no request this table can translate. One route
    // may cover a whole API — `GET /v1/models` sits under the same `/v1/**` a
    // route claims — and the HTTP rules on this host have judged it already.
    // They are where a policy says which paths may be reached at all.
    if body.is_empty() {
        return Outcome::Untouched;
    }
    let Ok(request) = serde_json::from_slice::<Value>(body) else {
        return Outcome::Refused(
            "an llm route covers this request, but its body is not JSON and cannot be translated"
                .to_string(),
        );
    };

    let requested_model = inspect::model_of(&request);
    // A model name is a name. Every glob in the table is matched against this
    // string, so an arbitrarily long one turns a 4 MB body into proxy time.
    if requested_model.len() > MAX_MODEL_NAME_BYTES {
        return Outcome::Refused(format!(
            "the model name in this request is longer than {MAX_MODEL_NAME_BYTES} bytes"
        ));
    }
    let Some((route, backend)) = routing.route_for(host, path, requested_model) else {
        // Every route that covers this head is scoped to another model. The
        // request goes where the sandbox addressed it, unchanged.
        return Outcome::Untouched;
    };

    let reader = inspect::reader(route.translation.from);
    if let Some(missing) = missing_capability(reader, &request, &backend.capabilities) {
        return Outcome::Refused(format!(
            "llm backend {:?} does not support {missing}, and the request needs it",
            backend.id
        ));
    }
    // Only a route that rewrites the body can misrepresent it. A route that
    // names one format twice carries every part the sandbox wrote, whether this
    // proxy understands it or not, so there is nothing here to refuse.
    if !translate::is_passthrough(route.translation)
        && let Some(part) = reader.unsupported_part(&request)
    {
        // The name is quoted back from the request, so it is capped for the same
        // reason the model name above is.
        let part: String = part.chars().take(64).collect();
        return Outcome::Refused(format!(
            "this request carries {part:?}, which has no translation, and dropping it would \
             send the backend a different request from the one the sandbox wrote"
        ));
    }

    match redirect(route.translation, &request, backend) {
        Ok(redirect) => Outcome::Redirect(Box::new(redirect)),
        Err(reason) => Outcome::Refused(reason),
    }
}

/// The first capability the request needs and the backend does not declare.
fn missing_capability(
    reader: &dyn inspect::Reader,
    request: &Value,
    capabilities: &LlmCapabilities,
) -> Option<&'static str> {
    let needs = reader.requirements(request);
    if needs.tools && !capabilities.tools {
        return Some("tools");
    }
    if needs.images && !capabilities.images {
        return Some("images");
    }
    None
}

/// Apply a route's translation, producing the request that goes to the backend.
fn redirect(
    translation: LlmTranslation,
    request: &Value,
    backend: &Backend,
) -> Result<Redirect, String> {
    let model = backend.model_for(inspect::model_of(request));
    let translated = translate::request(translation, request, &model)?;
    Ok(Redirect {
        host: backend.host.clone(),
        port: backend.port,
        path: backend.path.clone(),
        body: serde_json::to_vec(&translated)
            .map_err(|e| format!("translated llm request is not serializable: {e}"))?,
        streaming: inspect::is_streaming(request),
        translation,
        model,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_schema::LlmPolicy;

    fn routing(json: &str) -> LlmRouting {
        LlmRouting::from_policy(&serde_json::from_str::<LlmPolicy>(json).expect("policy parses"))
            .expect("table resolves")
    }

    const POLICY: &str = r#"{
        "backends": [{
            "id": "local",
            "url": "https://vllm.internal/v1/chat/completions",
            "modelMap": [{ "match": "claude-*", "model": "qwen3-coder-30b" }]
        }],
        "routes": [{
            "match": { "domain": "api.anthropic.com", "path": "/v1/messages" },
            "translate": { "from": "anthropicMessages", "to": "openaiChat" },
            "backend": "local"
        }]
    }"#;

    fn decide_body(policy: &str, host: &str, path: &str, body: &str) -> Outcome {
        decide(&routing(policy), host, path, body.as_bytes())
    }

    #[test]
    fn a_claimed_request_is_translated_and_pointed_at_the_backend() {
        let outcome = decide_body(
            POLICY,
            "api.anthropic.com",
            "/v1/messages",
            r#"{"model":"claude-sonnet-5","max_tokens":64,
                "messages":[{"role":"user","content":"hi"}]}"#,
        );
        let Outcome::Redirect(redirect) = outcome else {
            panic!("expected a redirect, got {outcome:?}");
        };
        assert_eq!(redirect.host, "vllm.internal");
        assert_eq!(redirect.port, 443);
        assert_eq!(redirect.path, "/v1/chat/completions");
        assert_eq!(redirect.model, "qwen3-coder-30b");
        assert!(!redirect.streaming);

        let body: Value = serde_json::from_slice(&redirect.body).expect("body is JSON");
        assert_eq!(body["model"], "qwen3-coder-30b");
        assert_eq!(body["messages"][0]["content"], "hi");
    }

    #[test]
    fn a_streamed_request_says_so() {
        let outcome = decide_body(
            POLICY,
            "api.anthropic.com",
            "/v1/messages",
            r#"{"model":"claude-sonnet-5","stream":true,
                "messages":[{"role":"user","content":"hi"}]}"#,
        );
        let Outcome::Redirect(redirect) = outcome else {
            panic!("expected a redirect, got {outcome:?}");
        };
        assert!(redirect.streaming);
    }

    #[test]
    fn a_request_no_route_covers_is_left_alone() {
        let outcome = decide_body(POLICY, "api.openai.com", "/v1/messages", "{}");
        assert!(matches!(outcome, Outcome::Untouched), "{outcome:?}");
    }

    #[test]
    fn a_request_whose_model_no_route_claims_is_left_alone() {
        let policy = r#"{
            "backends": [{ "id": "b", "url": "https://x.internal/v1/chat/completions" }],
            "routes": [{ "match": { "domain": "api.anthropic.com", "path": "/v1/messages",
                "model": "claude-haiku-*" },
                "translate": { "from": "anthropicMessages", "to": "openaiChat" }, "backend": "b" }]
        }"#;
        let outcome = decide_body(
            policy,
            "api.anthropic.com",
            "/v1/messages",
            r#"{"model":"claude-opus-5","messages":[]}"#,
        );
        assert!(matches!(outcome, Outcome::Untouched), "{outcome:?}");
    }

    #[test]
    fn an_absurdly_long_model_name_is_refused() {
        let body = format!(
            r#"{{"model":"{}","messages":[]}}"#,
            "c".repeat(MAX_MODEL_NAME_BYTES + 1)
        );
        let outcome = decide_body(POLICY, "api.anthropic.com", "/v1/messages", &body);
        let Outcome::Refused(reason) = outcome else {
            panic!("expected a refusal, got {outcome:?}");
        };
        assert!(reason.contains("model name"), "{reason}");
    }

    #[test]
    fn a_request_with_no_body_is_left_alone() {
        // `GET /v1/models` under a route that claims the whole of `/v1`. There
        // is nothing here to translate, and the route rules on this host have
        // already said whether it may be asked at all.
        let policy = r#"{
            "backends": [{ "id": "b", "url": "https://x.internal/v1/chat/completions" }],
            "routes": [{ "match": { "domain": "api.anthropic.com", "path": "/v1/**" },
                "translate": { "from": "anthropicMessages", "to": "openaiChat" },
                "backend": "b" }]
        }"#;
        let outcome = decide_body(policy, "api.anthropic.com", "/v1/models", "");
        assert!(matches!(outcome, Outcome::Untouched), "{outcome:?}");
    }

    #[test]
    fn a_claimed_request_that_is_not_json_is_refused() {
        // Passing it on would send the sandbox's key to the API it named, which
        // is the one thing the redirect exists to prevent.
        let outcome = decide_body(POLICY, "api.anthropic.com", "/v1/messages", "not json");
        let Outcome::Refused(reason) = outcome else {
            panic!("expected a refusal, got {outcome:?}");
        };
        assert!(reason.contains("not JSON"), "{reason}");
    }

    #[test]
    fn a_request_needing_tools_a_backend_lacks_is_refused() {
        let policy = r#"{
            "backends": [{ "id": "b", "url": "https://x.internal/v1/chat/completions",
                "capabilities": { "tools": false } }],
            "routes": [{ "match": { "domain": "api.anthropic.com", "path": "/v1/messages" },
                "translate": { "from": "anthropicMessages", "to": "openaiChat" }, "backend": "b" }]
        }"#;
        let outcome = decide_body(
            policy,
            "api.anthropic.com",
            "/v1/messages",
            r#"{"model":"m","messages":[],"tools":[{"name":"w","input_schema":{}}]}"#,
        );
        let Outcome::Refused(reason) = outcome else {
            panic!("expected a refusal, got {outcome:?}");
        };
        assert!(reason.contains("tools"), "{reason}");
    }

    #[test]
    fn a_request_needing_images_a_backend_lacks_is_refused() {
        let policy = r#"{
            "backends": [{ "id": "b", "url": "https://x.internal/v1/chat/completions",
                "capabilities": { "images": false } }],
            "routes": [{ "match": { "domain": "api.anthropic.com", "path": "/v1/messages" },
                "translate": { "from": "anthropicMessages", "to": "openaiChat" }, "backend": "b" }]
        }"#;
        let outcome = decide_body(
            policy,
            "api.anthropic.com",
            "/v1/messages",
            r#"{"model":"m","messages":[{"role":"user","content":[
                {"type":"image","source":{"type":"url","url":"https://x/y.png"}}]}]}"#,
        );
        let Outcome::Refused(reason) = outcome else {
            panic!("expected a refusal, got {outcome:?}");
        };
        assert!(reason.contains("images"), "{reason}");
    }

    #[test]
    fn a_backend_that_declares_nothing_serves_everything() {
        let outcome = decide_body(
            POLICY,
            "api.anthropic.com",
            "/v1/messages",
            r#"{"model":"claude-opus-5","messages":[{"role":"user","content":[
                {"type":"image","source":{"type":"url","url":"https://x/y.png"}}]}],
                "tools":[{"name":"w","input_schema":{}}]}"#,
        );
        assert!(matches!(outcome, Outcome::Redirect(_)), "{outcome:?}");
    }

    #[test]
    fn a_route_that_translates_nothing_carries_what_a_translation_could_not() {
        // The same `document` block the route below refuses. Nothing rewrites it
        // here, so there is nothing to misrepresent and nothing to refuse.
        let policy = r#"{
            "backends": [{ "id": "b", "url": "https://x.internal/v1/messages" }],
            "routes": [{ "match": { "domain": "api.anthropic.com", "path": "/v1/messages" },
                "translate": { "from": "anthropicMessages", "to": "anthropicMessages" },
                "backend": "b" }]
        }"#;
        let outcome = decide_body(
            policy,
            "api.anthropic.com",
            "/v1/messages",
            r#"{"model":"claude-opus-5","messages":[{"role":"user","content":[
                {"type":"document","source":{}}]}]}"#,
        );
        let Outcome::Redirect(redirect) = outcome else {
            panic!("expected a redirect, got {outcome:?}");
        };
        let body: Value = serde_json::from_slice(&redirect.body).expect("body is JSON");
        assert_eq!(body["messages"][0]["content"][0]["type"], "document");
    }

    #[test]
    fn a_request_the_translation_cannot_carry_is_refused() {
        let outcome = decide_body(
            POLICY,
            "api.anthropic.com",
            "/v1/messages",
            r#"{"model":"claude-opus-5","messages":[{"role":"user","content":[
                {"type":"document","source":{}}]}]}"#,
        );
        let Outcome::Refused(reason) = outcome else {
            panic!("expected a refusal, got {outcome:?}");
        };
        assert!(reason.contains("document"), "{reason}");
    }
}
