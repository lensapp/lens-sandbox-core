//! Read an MCP request and judge it against the rules that cover its route.
//!
//! This reads MCP revision `2026-07-28`, in which the client sends every
//! JSON-RPC message as its own `POST` to a single endpoint, a body is one
//! request or notification and never a batch, and a server never sends a request
//! of its own. So one body carries one operation, and the sandbox is the only
//! side whose asks need judging.
//!
//! What crosses in the other direction is relayed unread, as it is for GraphQL.
//! A server that wants an LLM completion returns an `InputRequiredResult`, and
//! the client re-posts the original request carrying its answer — which arrives
//! here as an ordinary body this door reads.

use serde_json::{Map, Value};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::http_body::BodyFraming;
use crate::policy_schema::McpMatcher;
use crate::routing::glob_matches;

/// The prefix and suffix MCP wraps a Base64 header value in.
const SENTINEL_PREFIX: &str = "=?base64?";
const SENTINEL_SUFFIX: &str = "?=";

/// The revisions these rules can enforce.
///
/// Pinned rather than inferred. Every revision from `2025-03-26` to `2025-11-25`
/// lets a server send JSON-RPC requests of its own on the SSE stream this door
/// relays unread, so admitting one would put traffic beyond any rule's reach. An
/// upstream that serves both eras picks its handler from this header, so refusing
/// an absent or older value is what keeps the request inside the era the rules
/// were written for.
const SUPPORTED_PROTOCOL_VERSIONS: [&str; 1] = ["2026-07-28"];

/// The JSON-RPC version every MCP message declares.
const JSONRPC_VERSION: &str = "2.0";

/// What one MCP request asks the server to do.
#[derive(Debug, PartialEq, Eq)]
pub struct RequestInfo {
    /// The JSON-RPC method.
    pub method: String,
    /// `params.name`, which `tools/call` and `prompts/get` carry.
    pub name: Option<String>,
    /// `params.uri`, which `resources/read` carries.
    pub uri: Option<String>,
    /// `params.arguments`, held whole so a rule can point into it.
    arguments: Option<Value>,
}

impl RequestInfo {
    /// The value `Mcp-Name` is mirrored from: whichever of the two the request
    /// carries. A body carrying both is refused at classification, so this is
    /// never a choice between two live values.
    fn mirrored_name(&self) -> Option<&str> {
        self.name.as_deref().or(self.uri.as_deref())
    }
}

/// Which parameter names what a method acts on.
///
/// A method reads one of them and ignores the other, so a rule that bounds the
/// one being ignored bounds nothing: it would check a value the server never
/// reads while the server acted on the value beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Subject {
    /// `params.name`.
    Name,
    /// `params.uri`.
    Uri,
    /// The method acts on neither, so neither `tool` nor `uri` can bound it.
    Neither,
}

impl Subject {
    /// An unknown method reads as [`Subject::Neither`], so a new method in a
    /// later revision is one a rule must name on purpose rather than one an old
    /// rule admits by accident.
    fn of(method: &str) -> Self {
        match method {
            "tools/call" | "prompts/get" => Self::Name,
            "resources/read" | "resources/subscribe" | "resources/unsubscribe" => Self::Uri,
            _ => Self::Neither,
        }
    }
}

/// Whether a method carries `params.arguments`, which a condition can point into.
fn carries_arguments(method: &str) -> bool {
    matches!(method, "tools/call" | "prompts/get")
}

/// Read the operation an MCP request asks for.
///
/// Returns `Err` with a reason fit for an audit record when the request cannot be
/// classified. The caller denies on `Err`.
pub fn classify_request(body: &[u8]) -> Result<RequestInfo, String> {
    if body.is_empty() {
        return Err("an MCP rule cannot judge a request with no body".to_string());
    }

    let value = crate::http_body::parse_json_strict(body)
        .map_err(|err| format!("MCP request body does not parse: {err}"))?;

    let Value::Object(envelope) = value else {
        // An array is a JSON-RPC batch, which this revision removed. Reading one
        // member and forwarding all of them is how a rule gets walked past.
        return Err(
            "MCP request body is not a single JSON object, so no rule can judge it".to_string(),
        );
    };

    // A JSON-RPC message declares its version. A body that does not is not one
    // this door can read as MCP at all, and reading it as MCP anyway is how an
    // envelope of another shape gets judged by rules written for this one.
    match envelope.get("jsonrpc") {
        Some(Value::String(version)) if version == JSONRPC_VERSION => {}
        Some(Value::String(version)) => {
            return Err(format!(
                "MCP request body declares jsonrpc {version:?}, not {JSONRPC_VERSION:?}"
            ));
        }
        // A non-string `jsonrpc` is not the version any MCP message declares.
        _ => return Err("MCP request body declares no jsonrpc version string".to_string()),
    }

    let method = match envelope.get("method") {
        Some(Value::String(method)) => method.clone(),
        // A body with no method is a JSON-RPC *response*, which a client of this
        // revision never sends, or something else entirely. Either way there is
        // nothing for a rule to name.
        _ => return Err("MCP request body declares no method".to_string()),
    };

    let params = match envelope.get("params") {
        Some(Value::Object(params)) => Some(params),
        None => None,
        Some(_) => return Err(format!("MCP request \"{method}\" has non-object params")),
    };

    let name = params.and_then(|p| string_field(p, "name"));
    let uri = params.and_then(|p| string_field(p, "uri"));

    // One method acts on one of them. A body carrying both leaves which one the
    // server reads to the server, and no rule can bound a choice it cannot see.
    if name.is_some() && uri.is_some() {
        return Err(format!(
            "MCP request \"{method}\" carries both a name and a uri, so what it acts on is ambiguous"
        ));
    }

    Ok(RequestInfo {
        method,
        name,
        uri,
        arguments: params.and_then(|p| p.get("arguments").cloned()),
    })
}

fn string_field(params: &Map<String, Value>, key: &str) -> Option<String> {
    match params.get(key) {
        Some(Value::String(value)) => Some(value.clone()),
        _ => None,
    }
}

/// Read an MCP request and judge it against the rules that cover its head.
///
/// `header_block` is the request head, needed because MCP mirrors two body fields
/// into headers and this door must confirm they agree — see
/// [`check_headers_agree`].
///
/// Returns what it read, so a caller that goes on to change the head can bind the
/// agreement to the head it will actually send.
pub fn judge(
    header_block: &str,
    body: &[u8],
    matchers: &[&McpMatcher],
) -> Result<RequestInfo, String> {
    let info = classify_request(body)?;
    check_headers_agree(header_block, &info)?;
    check_operation(&info, matchers)?;
    Ok(info)
}

/// Judge one classified request.
///
/// One rule must cover a request by itself. Rules do not combine, for the reason
/// [`crate::policy_schema::GraphqlMatcher::fields`] gives: two rules that each
/// permit one half of a request would together permit a whole neither allows.
pub fn check_operation(info: &RequestInfo, matchers: &[&McpMatcher]) -> Result<(), String> {
    if matchers.iter().any(|matcher| covers(info, matcher)) {
        return Ok(());
    }
    Err(match info.mirrored_name() {
        Some(name) => format!(
            "no MCP rule permits method \"{}\" naming \"{name}\"",
            info.method
        ),
        None => format!("no MCP rule permits method \"{}\"", info.method),
    })
}

/// Whether one rule covers a request whole.
fn covers(info: &RequestInfo, matcher: &McpMatcher) -> bool {
    if !glob_matches(&matcher.method, &info.method) {
        return false;
    }
    let subject = Subject::of(&info.method);
    if let Some(tool) = &matcher.tool
        && (subject != Subject::Name
            || !info.name.as_deref().is_some_and(|n| glob_matches(tool, n)))
    {
        return false;
    }
    if let Some(uri) = &matcher.uri
        && (subject != Subject::Uri || !info.uri.as_deref().is_some_and(|u| glob_matches(uri, u)))
    {
        return false;
    }
    if !matcher.arguments.is_empty() && !carries_arguments(&info.method) {
        return false;
    }
    matcher.arguments.iter().all(|condition| {
        info.arguments
            .as_ref()
            .and_then(|args| args.pointer(&condition.pointer))
            .and_then(Value::as_str)
            .is_some_and(|value| glob_matches(&condition.glob, value))
    })
}

// ---------------------------------------------------------------------------
// Mirrored headers
// ---------------------------------------------------------------------------

/// Check the request head: the revision it names, the `Mcp-Param-*` headers it
/// must not carry, and the agreement of the headers MCP mirrors from the body.
///
/// The mirror check changes no verdict on its own, because the body is what a
/// rule judges and what a compliant server runs. It closes a gap behind this
/// door: a component that routes or meters on `Mcp-Method` or `Mcp-Name` would
/// otherwise act on a value the policy never read.
///
/// A missing mirrored header is not a mismatch. This revision leaves the header
/// rules for a notification `POST` undefined, so demanding one would refuse a
/// compliant client. The revision header is another matter: it is required.
pub fn check_headers_agree(header_block: &str, info: &RequestInfo) -> Result<(), String> {
    ensure_supported_revision(header_block)?;
    ensure_no_unverifiable_param_header(header_block)?;

    if let Some(claimed) = sole_header(header_block, "mcp-method")?
        && claimed != info.method
    {
        return Err(format!(
            "Mcp-Method header says \"{claimed}\" but the body says \"{}\"",
            info.method
        ));
    }

    if let Some(claimed) = sole_header(header_block, "mcp-name")? {
        let claimed = decode_sentinel(&claimed)?;
        match info.mirrored_name() {
            Some(actual) if claimed == actual => {}
            Some(actual) => {
                return Err(format!(
                    "Mcp-Name header says \"{claimed}\" but the body says \"{actual}\""
                ));
            }
            None => {
                return Err(format!(
                    "Mcp-Name header says \"{claimed}\" but the body names nothing"
                ));
            }
        }
    }

    Ok(())
}

/// Refuse a request that does not name a revision these rules can enforce.
///
/// The header is mandatory on every `POST` of this revision, so an absent one is
/// as much a refusal as an older one. [`SUPPORTED_PROTOCOL_VERSIONS`] says why.
fn ensure_supported_revision(header_block: &str) -> Result<(), String> {
    let Some(claimed) = sole_header(header_block, "mcp-protocol-version")? else {
        return Err(
            "request names no MCP-Protocol-Version, so the revision it speaks is unknown"
                .to_string(),
        );
    };
    if SUPPORTED_PROTOCOL_VERSIONS.contains(&claimed.as_str()) {
        return Ok(());
    }
    Err(format!(
        "MCP revision {claimed:?} is not one these rules enforce (expected one of {SUPPORTED_PROTOCOL_VERSIONS:?})"
    ))
}

/// Refuse an `Mcp-Param-*` header, which this door cannot check against the body.
///
/// A server names these through the `x-mcp-header` annotation on its own tool
/// schema, and the annotation's name need not be the argument's name. Without the
/// server's `inputSchema` there is no way to say which argument a given header
/// mirrors, so a rule that bounds an argument cannot tell whether the header
/// beside it agrees. Since something behind this door may route or meter on that
/// header, an unverifiable one is refused rather than forwarded.
///
/// The cost is real: a server that annotates its tools this way cannot be reached
/// through an MCP rule until this door can read its schema.
fn ensure_no_unverifiable_param_header(header_block: &str) -> Result<(), String> {
    for line in header_block.split("\r\n").skip(1) {
        let Some((field, _)) = line.split_once(':') else {
            continue;
        };
        if field.trim().to_ascii_lowercase().starts_with("mcp-param-") {
            return Err(format!(
                "request carries {}, which this door cannot check against the body",
                field.trim()
            ));
        }
    }
    Ok(())
}

/// Read a header that must appear at most once.
///
/// Two copies are refused rather than resolved: a server may read either, so a
/// rule must never judge the one it did not act on.
fn sole_header(header_block: &str, name: &str) -> Result<Option<String>, String> {
    let mut found: Option<String> = None;
    let lines: Vec<&str> = header_block.split("\r\n").collect();
    for (index, line) in lines.iter().enumerate().skip(1) {
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        if !field.trim().eq_ignore_ascii_case(name) {
            continue;
        }
        if found.is_some() {
            return Err(format!("request carries more than one {name} header"));
        }
        // An obsolete folded line (RFC 9110 §5.2) continues the value above, so
        // reading this line alone would compare a prefix of what upstream sees.
        if lines
            .get(index + 1)
            .is_some_and(|next| next.starts_with([' ', '\t']))
        {
            return Err(format!("{name} header is folded across lines"));
        }
        found = Some(value.trim().to_string());
    }
    Ok(found)
}

/// Undo the `=?base64?…?=` wrapper MCP uses for a value that is not plain ASCII.
///
/// A comparison that skipped this would pass any name the client chose to encode.
fn decode_sentinel(value: &str) -> Result<String, String> {
    let Some(encoded) = value
        .strip_prefix(SENTINEL_PREFIX)
        .and_then(|rest| rest.strip_suffix(SENTINEL_SUFFIX))
    else {
        return Ok(value.to_string());
    };
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|err| format!("Mcp-Name header is not valid Base64: {err}"))?;
    String::from_utf8(bytes).map_err(|_| "Mcp-Name header is not valid UTF-8".to_string())
}

// ---------------------------------------------------------------------------
// Reading the body
// ---------------------------------------------------------------------------

/// Refuse a method that carries no MCP message.
///
/// This revision sends every message as a `POST`. A body on any other method is
/// one the server ignores, so a rule judged by it has judged nothing — and a
/// `GET` is how the revisions before `2026-07-28` opened their server-to-client
/// stream, which is exactly what must not be admitted on a crafted body.
pub fn ensure_carries_an_mcp_message(method: &str) -> Result<(), String> {
    if method.eq_ignore_ascii_case("POST") {
        return Ok(());
    }
    Err(format!(
        "an MCP rule reads a POST body, so a {method} request carries no message it can judge"
    ))
}

/// Buffer the request body an MCP rule must read.
///
/// Bounded by [`crate::http_body::MAX_JUDGED_BODY_BYTES`], and a body over that
/// is refused rather than truncated.
pub async fn read_body_for_inspection<C>(
    tls_client: &mut C,
    header_str: &str,
    method: &str,
    framing: BodyFraming,
) -> Result<Vec<u8>, String>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    ensure_carries_an_mcp_message(method)?;
    crate::http_body::ensure_body_is_readable(header_str)?;

    // A client that was told to wait is waiting on us, and we hold the body it
    // has not sent yet. Answer so it sends.
    crate::http_body::answer_continue_if_expected(tls_client, header_str).await?;

    crate::http_body::read_body(tls_client, framing, crate::http_body::MAX_JUDGED_BODY_BYTES)
        .await
        .map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_schema::{McpArgumentMatch, McpMatcher};

    fn matcher(method: &str) -> McpMatcher {
        McpMatcher {
            method: method.to_string(),
            tool: None,
            uri: None,
            arguments: Vec::new(),
        }
    }

    fn tool_rule(method: &str, tool: &str) -> McpMatcher {
        McpMatcher {
            tool: Some(tool.to_string()),
            ..matcher(method)
        }
    }

    fn call(tool: &str) -> String {
        format!(r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{tool}"}}}}"#)
    }

    fn judge(body: &str, matchers: &[&McpMatcher]) -> Result<(), String> {
        super::judge(&head(""), body.as_bytes(), matchers).map(|_| ())
    }

    // ----------------------------------------------------------------------
    // Reading the envelope
    // ----------------------------------------------------------------------

    #[test]
    fn reads_a_tool_call() {
        let info = classify_request(call("get_weather").as_bytes()).expect("should classify");
        assert_eq!(info.method, "tools/call");
        assert_eq!(info.name.as_deref(), Some("get_weather"));
        assert_eq!(info.uri, None);
    }

    #[test]
    fn reads_a_resource_read() {
        let body =
            r#"{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file:///a/b.json"}}"#;
        let info = classify_request(body.as_bytes()).expect("should classify");
        assert_eq!(info.uri.as_deref(), Some("file:///a/b.json"));
    }

    #[test]
    fn a_body_declaring_no_jsonrpc_version_is_refused() {
        let err = classify_request(br#"{"method":"tools/call","params":{"name":"ls"}}"#)
            .expect_err("an envelope of unknown shape must not be judged as MCP");
        assert!(err.contains("no jsonrpc version"), "{err}");
    }

    #[test]
    fn a_body_declaring_another_jsonrpc_version_is_refused() {
        let err = classify_request(br#"{"jsonrpc":"1.0","method":"tools/call"}"#)
            .expect_err("only 2.0 is the version MCP messages declare");
        assert!(err.contains("jsonrpc \"1.0\""), "{err}");
    }

    #[test]
    fn a_body_carrying_both_a_name_and_a_uri_is_refused() {
        // Which one the server reads is the server's choice, and no rule can
        // bound a choice it cannot see.
        let body =
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"ls","uri":"file:///a"}}"#;
        let err = classify_request(body.as_bytes()).expect_err("the subject is ambiguous");
        assert!(err.contains("both a name and a uri"), "{err}");
    }

    #[test]
    fn a_batch_array_is_refused() {
        // This revision sends one message per POST. Judging one member of a batch
        // and forwarding every member is how a rule gets walked past.
        let err = classify_request(br#"[{"method":"tools/call"}]"#)
            .expect_err("a batch must not be judged");
        assert!(err.contains("single JSON object"), "{err}");
    }

    #[test]
    fn a_body_with_no_method_is_refused() {
        let err = classify_request(br#"{"jsonrpc":"2.0","id":1,"result":{}}"#)
            .expect_err("a response is not a request");
        assert!(err.contains("no method"), "{err}");
    }

    #[test]
    fn an_empty_body_is_refused() {
        assert!(classify_request(b"").is_err());
    }

    #[test]
    fn trailing_content_after_the_object_is_refused() {
        // Two documents in one body: the proxy would read the first and a server
        // might read the second.
        assert!(classify_request(br#"{"method":"ping"} {"method":"tools/call"}"#).is_err());
    }

    #[test]
    fn a_duplicate_key_is_refused() {
        let body = br#"{"method":"tools/call","method":"ping","params":{"name":"x"}}"#;
        let err = classify_request(body).expect_err("a repeated key must be refused");
        assert!(err.contains("duplicate key"), "{err}");
    }

    #[test]
    fn a_duplicate_key_nested_in_arguments_is_refused() {
        let body =
            br#"{"method":"tools/call","params":{"name":"x","arguments":{"h":"a","h":"b"}}}"#;
        let err = classify_request(body).expect_err("a nested repeated key must be refused");
        assert!(err.contains("duplicate key"), "{err}");
    }

    // ----------------------------------------------------------------------
    // Matching
    // ----------------------------------------------------------------------

    #[test]
    fn a_permitted_tool_passes() {
        let rule = tool_rule("tools/call", "read_*");
        assert!(judge(&call("read_file"), &[&rule]).is_ok());
    }

    #[test]
    fn a_tool_no_rule_names_is_denied() {
        let rule = tool_rule("tools/call", "read_*");
        let err = judge(&call("write_file"), &[&rule]).expect_err("must be denied");
        assert!(err.contains("write_file"), "{err}");
    }

    #[test]
    fn a_method_no_rule_names_is_denied() {
        let rule = tool_rule("tools/call", "*");
        let body = r#"{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file:///a"}}"#;
        assert!(judge(body, &[&rule]).is_err());
    }

    #[test]
    fn a_wildcard_method_covers_any_method() {
        let rule = matcher("*");
        assert!(judge(r#"{"jsonrpc":"2.0","method":"tools/list"}"#, &[&rule]).is_ok());
    }

    #[test]
    fn one_rule_must_cover_a_request_alone() {
        // The method comes from one rule and the tool from the other; neither
        // covers the request whole, so it is denied.
        let by_method = matcher("tools/call");
        let by_tool = tool_rule("*", "read_file");
        let permissive = tool_rule("tools/call", "other");
        assert!(judge(&call("read_file"), &[&permissive]).is_err());
        // Each of these does cover it alone, so either one admits it.
        assert!(judge(&call("read_file"), &[&by_method]).is_ok());
        assert!(judge(&call("read_file"), &[&by_tool]).is_ok());
    }

    #[test]
    fn a_uri_rule_reads_params_uri() {
        let rule = McpMatcher {
            uri: Some("file:///projects/*".to_string()),
            ..matcher("resources/read")
        };
        let inside = r#"{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file:///projects/a.json"}}"#;
        let outside =
            r#"{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file:///etc/shadow"}}"#;
        assert!(judge(inside, &[&rule]).is_ok());
        assert!(judge(outside, &[&rule]).is_err());
    }

    #[test]
    fn a_tool_rule_does_not_match_a_request_that_names_nothing() {
        let rule = tool_rule("tools/*", "*");
        assert!(judge(r#"{"jsonrpc":"2.0","method":"tools/list"}"#, &[&rule]).is_err());
    }

    #[test]
    fn a_uri_rule_does_not_cover_a_method_that_reads_a_name() {
        // `tools/call` reads `params.name` and ignores `params.uri`. A rule
        // bounding the uri would otherwise admit every tool on the host.
        let rule = McpMatcher {
            uri: Some("file:///safe/*".to_string()),
            ..matcher("tools/call")
        };
        let decoy = r#"{"jsonrpc":"2.0","method":"tools/call",
            "params":{"name":"delete_everything"}}"#;
        assert!(judge(decoy, &[&rule]).is_err());
    }

    #[test]
    fn a_tool_rule_does_not_cover_a_method_that_reads_a_uri() {
        let rule = tool_rule("resources/read", "*");
        let body = r#"{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file:///a"}}"#;
        assert!(judge(body, &[&rule]).is_err());
    }

    // ----------------------------------------------------------------------
    // Argument pointers
    // ----------------------------------------------------------------------

    fn argument_rule(pointer: &str, glob: &str) -> McpMatcher {
        McpMatcher {
            arguments: vec![McpArgumentMatch {
                pointer: pointer.to_string(),
                glob: glob.to_string(),
            }],
            ..tool_rule("tools/call", "fetch")
        }
    }

    fn fetch(arguments: &str) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","method":"tools/call","params":{{"name":"fetch","arguments":{arguments}}}}}"#
        )
    }

    #[test]
    fn an_argument_pointer_bounds_its_value() {
        let rule = argument_rule("/host", "*.example.com");
        assert!(judge(&fetch(r#"{"host":"api.example.com"}"#), &[&rule]).is_ok());
        assert!(judge(&fetch(r#"{"host":"evil.test"}"#), &[&rule]).is_err());
    }

    #[test]
    fn a_pointer_that_reaches_nothing_does_not_match() {
        // Fail closed: a mistyped pointer denies the request rather than widening
        // the rule to everything.
        let rule = argument_rule("/hsot", "*");
        assert!(judge(&fetch(r#"{"host":"api.example.com"}"#), &[&rule]).is_err());
    }

    #[test]
    fn a_pointer_that_reaches_a_non_string_does_not_match() {
        let rule = argument_rule("/host", "*");
        assert!(judge(&fetch(r#"{"host":{"name":"x"}}"#), &[&rule]).is_err());
        assert!(judge(&fetch(r#"{"host":42}"#), &[&rule]).is_err());
    }

    #[test]
    fn a_request_with_no_arguments_does_not_match_an_argument_rule() {
        let rule = argument_rule("/host", "*");
        assert!(judge(&call("fetch"), &[&rule]).is_err());
    }

    #[test]
    fn a_pointer_reaches_a_nested_argument() {
        let rule = argument_rule("/target/host", "*.example.com");
        assert!(judge(&fetch(r#"{"target":{"host":"a.example.com"}}"#), &[&rule]).is_ok());
    }

    #[test]
    fn a_pointer_reaches_a_key_holding_a_slash() {
        // RFC 6901 writes a `/` inside a key as `~1`. A pointer that did not
        // unescape it would reach nothing and deny every request.
        let rule = argument_rule("/io.modelcontextprotocol~1region", "us-*");
        let body = fetch(r#"{"io.modelcontextprotocol/region":"us-west1"}"#);
        assert!(judge(&body, &[&rule]).is_ok());
    }

    #[test]
    fn an_argument_condition_does_not_cover_a_method_carrying_no_arguments() {
        // Nothing else carries `params.arguments`, so the condition would read as
        // satisfied by a method it never bounded.
        let rule = McpMatcher {
            arguments: vec![McpArgumentMatch {
                pointer: "/host".to_string(),
                glob: "*".to_string(),
            }],
            ..matcher("*")
        };
        assert!(judge(r#"{"jsonrpc":"2.0","method":"tools/list"}"#, &[&rule]).is_err());
    }

    #[test]
    fn an_argument_condition_bounds_a_prompt_too() {
        // `prompts/get` carries `params.arguments` as well, so a condition on
        // them must bound it rather than read as satisfied.
        let rule = McpMatcher {
            arguments: vec![McpArgumentMatch {
                pointer: "/language".to_string(),
                glob: "en".to_string(),
            }],
            ..tool_rule("prompts/get", "summarise")
        };
        let prompt = |language: &str| {
            format!(
                r#"{{"jsonrpc":"2.0","method":"prompts/get","params":{{"name":"summarise","arguments":{{"language":"{language}"}}}}}}"#
            )
        };
        assert!(judge(&prompt("en"), &[&rule]).is_ok());
        assert!(judge(&prompt("fr"), &[&rule]).is_err());
    }

    #[test]
    fn every_argument_condition_must_match() {
        let rule = McpMatcher {
            arguments: vec![
                McpArgumentMatch {
                    pointer: "/host".to_string(),
                    glob: "*.example.com".to_string(),
                },
                McpArgumentMatch {
                    pointer: "/scheme".to_string(),
                    glob: "https".to_string(),
                },
            ],
            ..tool_rule("tools/call", "fetch")
        };
        let both = fetch(r#"{"host":"a.example.com","scheme":"https"}"#);
        let one = fetch(r#"{"host":"a.example.com","scheme":"http"}"#);
        assert!(judge(&both, &[&rule]).is_ok());
        assert!(judge(&one, &[&rule]).is_err());
    }

    // ----------------------------------------------------------------------
    // Mirrored headers
    // ----------------------------------------------------------------------

    /// A compliant head: this revision requires the version header on every POST.
    fn head(extra: &str) -> String {
        format!("POST /mcp HTTP/1.1\r\nHost: x\r\nMCP-Protocol-Version: 2026-07-28\r\n{extra}")
    }

    fn judge_with_head(extra: &str, body: &str) -> Result<(), String> {
        let rule = tool_rule("tools/call", "*");
        super::judge(&head(extra), body.as_bytes(), &[&rule]).map(|_| ())
    }

    #[test]
    fn an_agreeing_header_passes() {
        let extra = "Mcp-Method: tools/call\r\nMcp-Name: read_file";
        assert!(judge_with_head(extra, &call("read_file")).is_ok());
    }

    #[test]
    fn no_mirrored_header_is_not_a_mismatch() {
        // This revision leaves the header rules for a notification POST
        // undefined, so demanding one would refuse a compliant client.
        assert!(judge_with_head("", &call("read_file")).is_ok());
    }

    #[test]
    fn a_name_header_disagreeing_with_the_body_is_denied() {
        // The whole point: a rule that judged the body while a component behind
        // this door routed on the header would approve one thing and run another.
        let extra = "Mcp-Name: read_file";
        let err = judge_with_head(extra, &call("delete_everything"))
            .expect_err("a mismatch must be denied");
        assert!(err.contains("Mcp-Name"), "{err}");
    }

    #[test]
    fn a_method_header_disagreeing_with_the_body_is_denied() {
        let extra = "Mcp-Method: tools/list";
        let err = judge_with_head(extra, &call("read_file")).expect_err("must be denied");
        assert!(err.contains("Mcp-Method"), "{err}");
    }

    #[test]
    fn a_base64_name_header_is_decoded_before_it_is_compared() {
        // "read_file" encoded. A comparison that skipped the sentinel would pass
        // any name a client chose to wrap.
        let extra = "Mcp-Name: =?base64?cmVhZF9maWxl?=";
        assert!(judge_with_head(extra, &call("read_file")).is_ok());
        assert!(judge_with_head(extra, &call("write_file")).is_err());
    }

    #[test]
    fn a_name_header_on_a_body_that_names_nothing_is_denied() {
        let extra = "Mcp-Name: something";
        let rule = matcher("*");
        let err = super::judge(
            &head(extra),
            br#"{"jsonrpc":"2.0","method":"tools/list"}"#,
            &[&rule],
        )
        .expect_err("must be denied");
        assert!(err.contains("names nothing"), "{err}");
    }

    #[test]
    fn two_copies_of_a_mirrored_header_are_refused() {
        // A server may read either copy, so a rule must never judge the one it
        // did not act on.
        let extra = "Mcp-Name: read_file\r\nMcp-Name: write_file";
        let err = judge_with_head(extra, &call("read_file")).expect_err("must be refused");
        assert!(err.contains("more than one"), "{err}");
    }

    #[test]
    fn a_header_name_is_read_without_regard_to_case() {
        let extra = "mcp-name: write_file";
        assert!(judge_with_head(extra, &call("read_file")).is_err());
    }

    #[test]
    fn a_uri_is_the_mirrored_name_for_a_resource_read() {
        let rule = McpMatcher {
            uri: Some("*".to_string()),
            ..matcher("resources/read")
        };
        let body = r#"{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file:///a"}}"#;
        let agreeing = head("Mcp-Name: file:///a");
        let disagreeing = head("Mcp-Name: file:///b");
        assert!(super::judge(&agreeing, body.as_bytes(), &[&rule]).is_ok());
        assert!(super::judge(&disagreeing, body.as_bytes(), &[&rule]).is_err());
    }

    #[test]
    fn only_a_post_carries_a_message_a_rule_can_judge() {
        // A GET body is one the server ignores, and a GET is how the older
        // revisions opened their server-to-client stream. Admitting one on a
        // crafted body would hand that stream back.
        assert!(ensure_carries_an_mcp_message("POST").is_ok());
        assert!(ensure_carries_an_mcp_message("post").is_ok());
        for method in ["GET", "PUT", "DELETE", "HEAD", "PATCH"] {
            let err = ensure_carries_an_mcp_message(method)
                .expect_err("only a POST carries an MCP message");
            assert!(err.contains(method), "{err}");
        }
    }

    #[test]
    fn a_folded_mirrored_header_is_refused() {
        // An obs-fold continuation belongs to the value above, so comparing this
        // line alone would check a prefix of what upstream receives.
        let head = head("Mcp-Name: read_file\r\n write_file");
        let rule = tool_rule("tools/call", "*");
        let err = super::judge(&head, call("read_file").as_bytes(), &[&rule])
            .expect_err("a folded value must not be compared piecemeal");
        assert!(err.contains("folded"), "{err}");
    }

    #[tokio::test]
    async fn a_body_over_the_inspection_limit_is_refused() {
        // The limit is what makes the rules affordable, so it has to hold: a body
        // above it is refused rather than truncated, because a rule cannot be
        // judged against bytes the proxy declined to read.
        let oversized = crate::http_body::MAX_JUDGED_BODY_BYTES + 1;
        let head = format!(
            "POST /mcp HTTP/1.1\r\nHost: x\r\nMCP-Protocol-Version: 2026-07-28\r\nContent-Length: {oversized}"
        );
        let (mut near, mut far) = tokio::io::duplex(64 * 1024);
        let writer = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt as _;
            // The reader gives up at the limit, so this write half is expected to
            // break part way through.
            let _ = far.write_all(&vec![b'x'; oversized]).await;
        });

        let err = read_body_for_inspection(
            &mut near,
            &head,
            "POST",
            BodyFraming::Fixed(oversized as u64),
        )
        .await
        .expect_err("a body over the limit must be refused");
        assert!(
            err.contains(&crate::http_body::MAX_JUDGED_BODY_BYTES.to_string()),
            "the reason must name the limit so the need is visible: {err}"
        );
        writer.abort();
    }

    #[test]
    fn the_returned_info_lets_a_caller_rebind_the_agreement_to_a_new_head() {
        // Credential injection changes the head after the rule judged it, so a
        // door re-checks with what `judge` handed back.
        let rule = tool_rule("tools/call", "read_*");
        let info = super::judge(&head(""), call("read_file").as_bytes(), &[&rule])
            .expect("should pass on its own");

        assert!(check_headers_agree(&head("Mcp-Name: read_file"), &info).is_ok());
        let err = check_headers_agree(&head("Mcp-Name: write_file"), &info)
            .expect_err("an injected header disagreeing with the body must be caught");
        assert!(err.contains("Mcp-Name"), "{err}");
    }

    #[test]
    fn a_request_naming_no_revision_is_refused() {
        let bare = "POST /mcp HTTP/1.1\r\nHost: x";
        let rule = tool_rule("tools/call", "*");
        let err = super::judge(bare, call("read_file").as_bytes(), &[&rule])
            .expect_err("an unnamed revision may be one whose server talks back unread");
        assert!(err.contains("MCP-Protocol-Version"), "{err}");
    }

    #[test]
    fn a_request_naming_an_older_revision_is_refused() {
        let old = "POST /mcp HTTP/1.1\r\nHost: x\r\nMCP-Protocol-Version: 2025-06-18";
        let rule = tool_rule("tools/call", "*");
        let err = super::judge(old, call("read_file").as_bytes(), &[&rule])
            .expect_err("an older revision puts server-initiated traffic beyond the rules");
        assert!(err.contains("2025-06-18"), "{err}");
    }

    #[test]
    fn an_mcp_param_header_is_refused() {
        // Which argument it mirrors is named by the server's own schema, which
        // this door cannot read, so the header cannot be checked against the body.
        let err = judge_with_head("Mcp-Param-Host: evil.test", &call("read_file"))
            .expect_err("an unverifiable mirror must not be forwarded");
        assert!(err.contains("Mcp-Param-Host"), "{err}");
    }

    #[test]
    fn a_malformed_base64_name_header_is_refused() {
        let extra = "Mcp-Name: =?base64?not-base64!!?=";
        assert!(judge_with_head(extra, &call("read_file")).is_err());
    }
}
