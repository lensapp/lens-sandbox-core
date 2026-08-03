//! GraphQL-over-HTTP request inspection.
//!
//! An HTTP rule matches on method and path, which is all a REST request needs
//! to be told apart from its neighbours. GraphQL puts the operation in the
//! request body instead: every call is the same `POST /graphql`, so method and
//! path cannot tell a read from a write. This module reads what the request
//! actually asks for — the operation type, its name, and the root fields it
//! selects — so a rule can bind to that.
//!
//! # Everything here fails closed
//!
//! A body that will not parse, a document whose operation cannot be identified,
//! a batch above the cap, and a persisted query that carries no document are
//! all errors, never an empty result that a caller might read as "nothing to
//! object to". The caller denies the request on `Err`.
//!
//! # What this cannot read
//!
//! A persisted query that sends only a hash or a document id shows nothing about
//! its operation, so it is denied. A request that sends the document as well as
//! the hash is read from the document, which is what the server runs.
//!
//! Subscriptions run over a WebSocket upgrade, where the operation is in a
//! frame rather than in a request body. [`crate::graphql_ws`] reads those, and
//! judges each one with the [`check_envelope`] entry point here.

use std::collections::{HashMap, HashSet};

use apollo_parser::{Parser, cst};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::http_body::BodyFraming;
use crate::policy_schema::{GraphqlMatcher, GraphqlOperationType, GraphqlOperationTypeMatcher};

/// Recursion depth the document parser accepts. A document nested deeper than
/// this is refused rather than parsed, so a deeply nested selection cannot cost
/// unbounded stack.
const PARSER_RECURSION_LIMIT: usize = 128;

/// Token count the document parser accepts, bounding the work one body can ask
/// for regardless of how few bytes expresses it.
const PARSER_TOKEN_LIMIT: usize = 20_000;

/// Operations one request may carry. A batch beyond this is refused: each member
/// costs a parse, and no legitimate client sends hundreds in one envelope.
const MAX_OPERATIONS_PER_REQUEST: usize = 32;

/// One operation a request asks the server to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationInfo {
    /// The operation type, or `None` when the request carried no document at
    /// all — a persisted query that names only a hash or an id. Such an
    /// operation says nothing about itself, so no rule can cover it and
    /// [`check_operations`] denies it.
    pub operation_type: Option<GraphqlOperationType>,

    /// The operation name the document declares, when it declares one.
    pub operation_name: Option<String>,

    /// Root fields the operation selects, deduplicated and sorted.
    ///
    /// These are field names, never aliases: `mutation { safe: deleteRepo }`
    /// selects `deleteRepo`, and a rule that permits only `safe` must not match
    /// it.
    pub fields: Vec<String>,

    /// The persisted-query identifier the request carried: the Apollo APQ
    /// sha256 hash when present, otherwise a document id. Set whether or not
    /// the request also carried a document.
    pub persisted_key: Option<String>,
}

impl OperationInfo {
    /// Whether the request hid what this operation does. True only when it
    /// carried no document, so nothing about the operation is readable and no
    /// rule can cover it.
    pub fn is_opaque(&self) -> bool {
        self.operation_type.is_none()
    }
}

/// Every operation one GraphQL request carries. A batch envelope produces
/// several; the ordinary case produces one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestInfo {
    pub operations: Vec<OperationInfo>,
}

/// Read the operations a GraphQL request asks for.
///
/// `raw_target` is the request target with its query string still attached,
/// because a GraphQL GET carries the document there. `body` is the buffered
/// request body, empty for methods that have none.
///
/// Returns `Err` with a reason fit for an audit record when the request cannot
/// be classified. The caller denies on `Err`.
pub fn classify_request(
    method: &str,
    raw_target: &str,
    body: &[u8],
) -> Result<RequestInfo, String> {
    let operations = match method.to_ascii_uppercase().as_str() {
        "GET" => classify_get(raw_target)?,
        "POST" => classify_post(body)?,
        other => {
            return Err(format!(
                "GraphQL over HTTP {other} is not supported; only GET and POST carry an operation"
            ));
        }
    };

    // No path through the classifiers returns an empty list, but a rule reading
    // this as "no operation to object to" would fail open, so refuse it here
    // rather than rely on that.
    if operations.is_empty() {
        return Err("GraphQL request declares no operation".to_string());
    }
    Ok(RequestInfo { operations })
}

/// Classify a GraphQL GET, whose document and controls live in query
/// parameters.
fn classify_get(raw_target: &str) -> Result<Vec<OperationInfo>, String> {
    let params = parse_query_params(raw_target)?;
    let query = unique_param(&params, "query")?;
    let operation_name = unique_param(&params, "operationName")?;
    let extensions = match unique_param(&params, "extensions")? {
        Some(raw) => Some(
            serde_json::from_str::<serde_json::Value>(&raw)
                .map_err(|err| format!("GraphQL extensions parameter is not valid JSON: {err}"))?,
        ),
        None => None,
    };
    let persisted_id = unique_persisted_query_id(&params)?;

    Ok(vec![classify_envelope(
        query.as_deref(),
        operation_name.as_deref(),
        extensions.as_ref(),
        persisted_id,
    )?])
}

/// Classify a GraphQL POST, whose envelope is a JSON object, or an array of
/// them for a batch.
fn classify_post(body: &[u8]) -> Result<Vec<OperationInfo>, String> {
    if body.is_empty() {
        return Err("GraphQL POST body is empty".to_string());
    }
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|err| format!("GraphQL request body is not valid JSON: {err}"))?;

    match value {
        serde_json::Value::Array(items) => {
            if items.is_empty() {
                return Err("GraphQL batch request carries no operation".to_string());
            }
            if items.len() > MAX_OPERATIONS_PER_REQUEST {
                return Err(format!(
                    "GraphQL batch request carries {} operations, more than the limit of {MAX_OPERATIONS_PER_REQUEST}",
                    items.len()
                ));
            }
            items.iter().map(classify_json_envelope).collect()
        }
        serde_json::Value::Object(_) => Ok(vec![classify_json_envelope(&value)?]),
        _ => Err("GraphQL request body must be a JSON object or array".to_string()),
    }
}

/// Read one JSON envelope: the document, the operation name that selects
/// within it, and any persisted-query identifier.
fn classify_json_envelope(value: &serde_json::Value) -> Result<OperationInfo, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "GraphQL envelope must be a JSON object".to_string())?;
    let query = object.get("query").and_then(serde_json::Value::as_str);
    let operation_name = object
        .get("operationName")
        .and_then(serde_json::Value::as_str);
    let persisted_id = ["id", "documentId", "queryId"]
        .iter()
        .filter_map(|key| object.get(*key))
        .find_map(serde_json::Value::as_str)
        .map(ToString::to_string);

    classify_envelope(
        query,
        operation_name,
        object.get("extensions"),
        persisted_id,
    )
}

/// Turn one envelope's parts into an operation.
///
/// A document present means the operation describes itself, and it is read even
/// when a persisted-query hash rides along — the document is what the server
/// will run. A document absent leaves only the identifier, and the operation
/// stays unnamed until a registry resolves it.
fn classify_envelope(
    query: Option<&str>,
    operation_name: Option<&str>,
    extensions: Option<&serde_json::Value>,
    persisted_id: Option<String>,
) -> Result<OperationInfo, String> {
    let persisted_key = persisted_query_hash(extensions).or(persisted_id);
    let query = query.filter(|document| !document.trim().is_empty());

    match query {
        Some(document) => {
            let mut operation = classify_document(document, operation_name)?;
            operation.persisted_key = persisted_key;
            Ok(operation)
        }
        None => {
            let persisted_key = persisted_key.ok_or_else(|| {
                "GraphQL request carries neither a document nor a persisted-query identifier"
                    .to_string()
            })?;
            Ok(OperationInfo {
                operation_type: None,
                operation_name: operation_name.map(ToString::to_string),
                fields: Vec::new(),
                persisted_key: Some(persisted_key),
            })
        }
    }
}

/// Parse a GraphQL document and read the one operation the request runs.
fn classify_document(
    document: &str,
    operation_name: Option<&str>,
) -> Result<OperationInfo, String> {
    let parsed = Parser::new(document)
        .recursion_limit(PARSER_RECURSION_LIMIT)
        .token_limit(PARSER_TOKEN_LIMIT)
        .parse();
    if let Some(error) = parsed.errors().next() {
        return Err(format!("GraphQL document does not parse: {error}"));
    }

    let mut operations = Vec::new();
    let mut fragments = HashMap::new();
    for definition in parsed.document().definitions() {
        match definition {
            cst::Definition::OperationDefinition(operation) => operations.push(operation),
            cst::Definition::FragmentDefinition(fragment) => {
                if let Some(name) = fragment.fragment_name().and_then(|name| name.name()) {
                    fragments.insert(name.text().to_string(), fragment);
                }
            }
            // Type-system definitions cannot be executed, so they select
            // nothing and name no operation.
            _ => {}
        }
    }

    if operations.is_empty() {
        return Err("GraphQL document carries no operation to run".to_string());
    }

    // Which operation runs is the client's choice, expressed by operationName.
    // Without it a document may hold only one, else the server could not tell
    // either.
    let selected = match operation_name.filter(|name| !name.is_empty()) {
        Some(wanted) => operations
            .into_iter()
            .find(|operation| {
                operation
                    .name()
                    .is_some_and(|name| name.text().as_ref() == wanted)
            })
            .ok_or_else(|| format!("GraphQL document declares no operation named {wanted:?}"))?,
        None if operations.len() == 1 => operations.remove(0),
        None => {
            return Err(
                "GraphQL document declares several operations but names none to run".to_string(),
            );
        }
    };

    let selection_set = selected
        .selection_set()
        .ok_or_else(|| "GraphQL operation selects no field".to_string())?;
    let mut fields = HashSet::new();
    let mut visited = HashSet::new();
    collect_root_fields(selection_set, &fragments, &mut visited, &mut fields);
    let mut fields: Vec<String> = fields.into_iter().collect();
    fields.sort();

    Ok(OperationInfo {
        operation_type: Some(operation_type(&selected)),
        operation_name: selected.name().map(|name| name.text().to_string()),
        fields,
        persisted_key: None,
    })
}

/// Read an operation's type. A document may leave it out, which the
/// specification defines as a query.
fn operation_type(operation: &cst::OperationDefinition) -> GraphqlOperationType {
    match operation.operation_type() {
        None => GraphqlOperationType::Query,
        Some(declared) if declared.mutation_token().is_some() => GraphqlOperationType::Mutation,
        Some(declared) if declared.subscription_token().is_some() => {
            GraphqlOperationType::Subscription
        }
        Some(_) => GraphqlOperationType::Query,
    }
}

/// Collect the root field names a selection set reaches.
///
/// Fragments are followed, because a fragment spread at the root selects root
/// fields just as a plain field does — a rule that did not see through it could
/// be walked past with `query { ...Everything }`. Each fragment is followed once,
/// so a cyclic document cannot spin here.
fn collect_root_fields(
    selection_set: cst::SelectionSet,
    fragments: &HashMap<String, cst::FragmentDefinition>,
    visited: &mut HashSet<String>,
    fields: &mut HashSet<String>,
) {
    for selection in selection_set.selections() {
        match selection {
            // The field name, not its alias: an alias renames the response key
            // and cannot change which field the server runs.
            cst::Selection::Field(field) => {
                if let Some(name) = field.name() {
                    fields.insert(name.text().to_string());
                }
            }
            cst::Selection::InlineFragment(fragment) => {
                if let Some(inner) = fragment.selection_set() {
                    collect_root_fields(inner, fragments, visited, fields);
                }
            }
            cst::Selection::FragmentSpread(spread) => {
                let Some(name) = spread.fragment_name().and_then(|name| name.name()) else {
                    continue;
                };
                let name = name.text().to_string();
                if !visited.insert(name.clone()) {
                    continue;
                }
                if let Some(fragment) = fragments.get(&name)
                    && let Some(inner) = fragment.selection_set()
                {
                    collect_root_fields(inner, fragments, visited, fields);
                }
            }
        }
    }
}

/// Read an Apollo automatic-persisted-query hash out of the `extensions` block.
fn persisted_query_hash(extensions: Option<&serde_json::Value>) -> Option<String> {
    extensions?
        .get("persistedQuery")?
        .get("sha256Hash")?
        .as_str()
        .filter(|hash| !hash.is_empty())
        .map(ToString::to_string)
}

/// Split a request target's query string into parameters.
///
/// Values are percent-decoded, and `+` decodes to a space as the form encoding
/// requires. A malformed escape is an error rather than a literal `%`: a rule
/// must never match a document that a server would read differently.
fn parse_query_params(raw_target: &str) -> Result<HashMap<String, Vec<String>>, String> {
    let mut params: HashMap<String, Vec<String>> = HashMap::new();
    let Some((_, query)) = raw_target.split_once('?') else {
        return Ok(params);
    };

    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(raw_key)
            .ok_or_else(|| "GraphQL request target holds a malformed escape".to_string())?;
        let value = percent_decode(raw_value)
            .ok_or_else(|| "GraphQL request target holds a malformed escape".to_string())?;
        params.entry(key).or_default().push(value);
    }
    Ok(params)
}

/// Percent-decode one query-string component, treating `+` as a space.
/// Returns `None` for an incomplete or non-hexadecimal escape, and for a body
/// of bytes that is not UTF-8.
fn percent_decode(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' => {
                let high = bytes.get(index + 1).and_then(hex_value)?;
                let low = bytes.get(index + 2).and_then(hex_value)?;
                out.push(high * 16 + low);
                index += 3;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// One hexadecimal digit's value.
fn hex_value(byte: &u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Read a control parameter that must appear at most once.
///
/// A repeated `query` is refused rather than resolved: servers disagree on which
/// copy wins, so a rule that picked one could permit a document the server does
/// not run — or miss the one it does.
fn unique_param(
    params: &HashMap<String, Vec<String>>,
    key: &str,
) -> Result<Option<String>, String> {
    let Some(values) = params.get(key) else {
        return Ok(None);
    };
    if values.len() > 1 {
        return Err(format!(
            "GraphQL request target repeats the {key:?} parameter"
        ));
    }
    Ok(values
        .first()
        .filter(|value| !value.is_empty())
        .map(ToString::to_string))
}

/// Read the one persisted-query identifier a target may carry. Two different
/// spellings at once is an error for the same reason a repeated `query` is.
fn unique_persisted_query_id(
    params: &HashMap<String, Vec<String>>,
) -> Result<Option<String>, String> {
    let mut found: Option<(&str, String)> = None;
    for key in ["id", "documentId", "queryId"] {
        let Some(value) = unique_param(params, key)? else {
            continue;
        };
        if let Some((seen, _)) = found {
            return Err(format!(
                "GraphQL request target combines the {seen:?} and {key:?} parameters"
            ));
        }
        found = Some((key, value));
    }
    Ok(found.map(|(_, value)| value))
}

/// Read a GraphQL request and judge it against the rules that cover its head.
///
/// The two halves always belong together: a caller that read the body and did
/// not judge it would have paid for the inspection and decided nothing.
pub fn check_request(
    method: &str,
    raw_target: &str,
    body: &[u8],
    matchers: &[&GraphqlMatcher],
) -> Result<(), String> {
    let info = classify_request(method, raw_target, body)?;
    check_operations(&info, matchers)
}

/// Read one operation out of a JSON envelope and judge it against the rules
/// that cover the route.
///
/// This is the envelope on its own, without the HTTP request around it: a
/// GraphQL WebSocket message carries the same `query` / `operationName` /
/// `extensions` object inside its `payload`.
pub(crate) fn check_envelope(
    envelope: &serde_json::Value,
    matchers: &[&GraphqlMatcher],
) -> Result<(), String> {
    let info = RequestInfo {
        operations: vec![classify_json_envelope(envelope)?],
    };
    check_operations(&info, matchers)
}

/// Check every operation a request carries against the rules that cover its
/// head.
///
/// One rule must cover an operation by itself — see
/// [`GraphqlMatcher::fields`] for why rules do not combine.
///
/// Returns `Err` with a reason fit for an audit record. The caller denies on
/// `Err`.
pub fn check_operations(info: &RequestInfo, matchers: &[&GraphqlMatcher]) -> Result<(), String> {
    for operation in &info.operations {
        // A request that shows only a persisted-query identifier describes
        // nothing that a rule could read, so no rule can cover it.
        if operation.is_opaque() {
            let key = operation.persisted_key.as_deref().unwrap_or("unknown");
            return Err(format!(
                "GraphQL persisted query {key} carries no document, so its operation cannot be read"
            ));
        }
        if !matchers
            .iter()
            .any(|matcher| covers_operation(matcher, operation))
        {
            return Err(format!("no rule permits {}", describe(operation)));
        }
    }
    Ok(())
}

/// Whether one matcher covers one operation whole.
fn covers_operation(matcher: &GraphqlMatcher, operation: &OperationInfo) -> bool {
    type_covered(matcher.operation_type, operation.operation_type)
        && name_covered(
            matcher.operation_name.as_deref(),
            operation.operation_name.as_deref(),
        )
        && fields_covered(&matcher.fields, &operation.fields)
}

/// Whether the matcher's operation type covers the operation's own.
fn type_covered(wanted: GraphqlOperationTypeMatcher, actual: Option<GraphqlOperationType>) -> bool {
    let Some(actual) = actual else {
        // An operation with no readable type is denied before this point.
        return false;
    };
    match wanted {
        GraphqlOperationTypeMatcher::Any => true,
        GraphqlOperationTypeMatcher::Query => actual == GraphqlOperationType::Query,
        GraphqlOperationTypeMatcher::Mutation => actual == GraphqlOperationType::Mutation,
        GraphqlOperationTypeMatcher::Subscription => actual == GraphqlOperationType::Subscription,
    }
}

/// Whether the matcher's name glob covers the operation's name. An unnamed
/// operation is matched as an empty name, so `*` covers it and `Get*` does not.
fn name_covered(pattern: Option<&str>, actual: Option<&str>) -> bool {
    match pattern {
        None => true,
        Some(pattern) => glob_matches(pattern, actual.unwrap_or_default()),
    }
}

/// Whether the matcher's field globs cover every root field the operation
/// selects.
///
/// This bounds the selection rather than picking part of it: one unlisted field
/// fails the whole operation, so a permitted field cannot carry a forbidden one
/// alongside it.
fn fields_covered(permitted: &[String], selected: &[String]) -> bool {
    if permitted.is_empty() {
        // The rule places no condition on fields.
        return true;
    }
    // A rule that names fields is about a selection, so an operation with no
    // readable selection cannot satisfy it.
    !selected.is_empty()
        && selected
            .iter()
            .all(|field| permitted.iter().any(|pattern| glob_matches(pattern, field)))
}

/// Describe an operation for an audit record.
fn describe(operation: &OperationInfo) -> String {
    let kind = match operation.operation_type {
        Some(operation_type) => operation_type.to_string(),
        None => "operation".to_string(),
    };
    let name = operation.operation_name.as_deref().unwrap_or("anonymous");
    if operation.fields.is_empty() {
        format!("GraphQL {kind} {name}")
    } else {
        format!(
            "GraphQL {kind} {name} selecting {}",
            operation.fields.join(", ")
        )
    }
}

/// Buffer the request body so a GraphQL rule can read it.
///
/// The one place in this module that touches a socket. It sits here rather than
/// in a door because both doors need the same refusals, and because what makes
/// a GraphQL body readable is this module's business.
///
/// Refuses anything that would leave the rule judging bytes it cannot see.
pub async fn read_body_for_inspection<C>(
    tls_client: &mut C,
    header_str: &str,
    method: &str,
    framing: BodyFraming,
) -> Result<Vec<u8>, String>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    ensure_body_is_readable(header_str)?;

    // A GraphQL GET puts its document in the query string. A body on one is a
    // second account of the request that the origin might read instead, and
    // this door would have judged the wrong one.
    if method.eq_ignore_ascii_case("GET") && framing != BodyFraming::None {
        return Err(
            "GraphQL GET request carries a body, which the proxy does not read".to_string(),
        );
    }

    // A client that was told to wait is waiting on us, and we hold the body it
    // has not sent yet. Answer so it sends. Clients must accept more than one
    // 1xx, so a later `100 Continue` from upstream is forwarded harmlessly.
    if expects_continue(header_str) {
        tls_client
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .map_err(|err| format!("could not answer Expect: 100-continue: {err}"))?;
    }

    crate::http_body::read_body(tls_client, framing, crate::http_body::MAX_INSPECT_BYTES)
        .await
        .map_err(|err| err.to_string())
}

/// Whether the request head asks the proxy to confirm before the body is sent.
fn expects_continue(header_block: &str) -> bool {
    header_block.split("\r\n").skip(1).any(|line| {
        let lower = line.to_ascii_lowercase();
        lower
            .strip_prefix("expect:")
            .is_some_and(|value| value.trim() == "100-continue")
    })
}

/// Confirm that a request head does not hide its body from inspection.
///
/// A body the proxy cannot read is a body a rule cannot judge, so a coding it
/// does not undo and a format it does not split are refused rather than passed
/// on unread.
pub fn ensure_body_is_readable(header_block: &str) -> Result<(), String> {
    for line in header_block.split("\r\n").skip(1) {
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("content-encoding:") {
            let coding = value.trim();
            if !coding.is_empty() && coding != "identity" {
                return Err(format!(
                    "GraphQL request body uses content-encoding {coding}, which the proxy does not decode"
                ));
            }
        }
        if let Some(value) = lower.strip_prefix("content-type:")
            && value.trim_start().starts_with("multipart/")
        {
            return Err("GraphQL multipart request bodies are not inspected".to_string());
        }
    }
    Ok(())
}

/// Match `text` against a pattern in which `*` stands for any run of
/// characters, including none. Every other character matches itself.
///
/// Field and operation names have no separator to respect, so `*` spans the
/// whole name — unlike a path glob, where a wildcard stops at `/`.
pub(crate) fn glob_matches(pattern: &str, text: &str) -> bool {
    // `split` always yields at least one part, so `first` is the literal head
    // the text must open with.
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or(pattern);
    let Some(mut rest) = text.strip_prefix(first) else {
        return false;
    };

    // Every part but the last may sit anywhere after the one before it; the
    // last must land at the end.
    let mut pending: Option<&str> = None;
    for part in parts {
        if let Some(previous) = pending.replace(part) {
            match rest.find(previous) {
                Some(at) => rest = &rest[at + previous.len()..],
                None => return false,
            }
        }
    }
    match pending {
        // No `*` at all: the whole pattern had to match exactly.
        None => rest.is_empty(),
        Some(last) => rest.ends_with(last),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn post(body: &str) -> Result<RequestInfo, String> {
        classify_request("POST", "/graphql", body.as_bytes())
    }

    fn one(body: &str) -> OperationInfo {
        let info = post(body).expect("body should classify");
        assert_eq!(info.operations.len(), 1, "expected a single operation");
        info.operations.into_iter().next().expect("one operation")
    }

    // ----------------------------------------------------------------------
    // Documents
    // ----------------------------------------------------------------------

    #[test]
    fn reads_a_plain_query() {
        let op = one(r#"{"query":"query Viewer { viewer { login } }"}"#);
        assert_eq!(op.operation_type, Some(GraphqlOperationType::Query));
        assert_eq!(op.operation_name.as_deref(), Some("Viewer"));
        assert_eq!(op.fields, ["viewer"]);
    }

    #[test]
    fn reads_a_shorthand_query_as_a_query() {
        let op = one(r#"{"query":"{ viewer { login } }"}"#);
        assert_eq!(op.operation_type, Some(GraphqlOperationType::Query));
        assert_eq!(op.operation_name, None);
        assert_eq!(op.fields, ["viewer"]);
    }

    #[test]
    fn reads_a_mutation() {
        let op = one(r#"{"query":"mutation M { createIssue { id } }"}"#);
        assert_eq!(op.operation_type, Some(GraphqlOperationType::Mutation));
        assert_eq!(op.fields, ["createIssue"]);
    }

    #[test]
    fn reads_a_subscription() {
        let op = one(r#"{"query":"subscription S { events { id } }"}"#);
        assert_eq!(op.operation_type, Some(GraphqlOperationType::Subscription));
    }

    #[test]
    fn reads_the_field_and_not_its_alias() {
        // The alias renames the response key only. A rule that permitted
        // `viewer` must not be satisfied by a hidden `deleteRepository`.
        let op = one(r#"{"query":"mutation M { viewer: deleteRepository { id } }"}"#);
        assert_eq!(op.fields, ["deleteRepository"]);
    }

    #[test]
    fn reads_every_root_field() {
        let op = one(r#"{"query":"{ viewer { login } rateLimit { cost } }"}"#);
        assert_eq!(op.fields, ["rateLimit", "viewer"]);
    }

    #[test]
    fn follows_a_root_fragment_spread() {
        let op = one(
            r#"{"query":"query Q { ...Root } fragment Root on Query { viewer repository { id } }"}"#,
        );
        assert_eq!(op.fields, ["repository", "viewer"]);
    }

    #[test]
    fn follows_a_nested_fragment_spread() {
        let op = one(
            r#"{"query":"query Q { ...A } fragment A on Query { ...B } fragment B on Query { viewer }"}"#,
        );
        assert_eq!(op.fields, ["viewer"]);
    }

    #[test]
    fn follows_an_inline_fragment() {
        let op = one(r#"{"query":"query Q { ... on Query { viewer } }"}"#);
        assert_eq!(op.fields, ["viewer"]);
    }

    #[test]
    fn a_cyclic_fragment_does_not_spin() {
        let op = one(
            r#"{"query":"query Q { ...A } fragment A on Query { viewer ...B } fragment B on Query { ...A }"}"#,
        );
        assert_eq!(op.fields, ["viewer"]);
    }

    #[test]
    fn selects_the_named_operation_from_several() {
        let op =
            one(r#"{"query":"query A { viewer } mutation B { createIssue }","operationName":"B"}"#);
        assert_eq!(op.operation_type, Some(GraphqlOperationType::Mutation));
        assert_eq!(op.fields, ["createIssue"]);
    }

    #[test]
    fn several_operations_without_a_name_is_refused() {
        let err = post(r#"{"query":"query A { viewer } query B { rateLimit }"}"#)
            .expect_err("ambiguous document should be refused");
        assert!(err.contains("names none to run"), "{err}");
    }

    #[test]
    fn a_missing_named_operation_is_refused() {
        let err = post(r#"{"query":"query A { viewer }","operationName":"B"}"#)
            .expect_err("absent operation should be refused");
        assert!(err.contains("no operation named"), "{err}");
    }

    #[test]
    fn a_document_of_only_fragments_is_refused() {
        let err = post(r#"{"query":"fragment A on Query { viewer }"}"#)
            .expect_err("no runnable operation should be refused");
        assert!(err.contains("no operation to run"), "{err}");
    }

    #[test]
    fn a_document_that_does_not_parse_is_refused() {
        let err = post(r#"{"query":"query { viewer "}"#)
            .expect_err("a broken document should be refused");
        assert!(err.contains("does not parse"), "{err}");
    }

    #[test]
    fn a_comment_does_not_hide_a_field() {
        let op = one(r#"{"query":"query Q { # viewer\n createIssue }"}"#);
        assert_eq!(op.fields, ["createIssue"]);
    }

    // ----------------------------------------------------------------------
    // Envelopes
    // ----------------------------------------------------------------------

    #[test]
    fn an_empty_body_is_refused() {
        let err = post("").expect_err("an empty body should be refused");
        assert!(err.contains("body is empty"), "{err}");
    }

    #[test]
    fn a_body_that_is_not_json_is_refused() {
        let err = post("not json").expect_err("a non-JSON body should be refused");
        assert!(err.contains("not valid JSON"), "{err}");
    }

    #[test]
    fn a_json_scalar_body_is_refused() {
        let err = post("42").expect_err("a scalar body should be refused");
        assert!(err.contains("must be a JSON object or array"), "{err}");
    }

    #[test]
    fn an_envelope_with_neither_document_nor_identifier_is_refused() {
        let err = post(r#"{"variables":{}}"#).expect_err("an empty envelope should be refused");
        assert!(err.contains("neither a document nor"), "{err}");
    }

    #[test]
    fn a_blank_document_is_refused() {
        let err = post(r#"{"query":"   "}"#).expect_err("a blank document should be refused");
        assert!(err.contains("neither a document nor"), "{err}");
    }

    #[test]
    fn reads_every_member_of_a_batch() {
        let info = post(r#"[{"query":"query { viewer }"},{"query":"mutation { createIssue }"}]"#)
            .expect("a batch should classify");
        assert_eq!(info.operations.len(), 2);
        assert_eq!(
            info.operations[0].operation_type,
            Some(GraphqlOperationType::Query)
        );
        assert_eq!(
            info.operations[1].operation_type,
            Some(GraphqlOperationType::Mutation)
        );
    }

    #[test]
    fn an_empty_batch_is_refused() {
        let err = post("[]").expect_err("an empty batch should be refused");
        assert!(err.contains("carries no operation"), "{err}");
    }

    #[test]
    fn a_batch_beyond_the_cap_is_refused() {
        let member = r#"{"query":"query { viewer }"}"#;
        let body = format!("[{}]", [member; MAX_OPERATIONS_PER_REQUEST + 1].join(","));
        let err = post(&body).expect_err("an oversized batch should be refused");
        assert!(err.contains("more than the limit"), "{err}");
    }

    #[test]
    fn a_batch_at_the_cap_is_read() {
        let member = r#"{"query":"query { viewer }"}"#;
        let body = format!("[{}]", [member; MAX_OPERATIONS_PER_REQUEST].join(","));
        let info = post(&body).expect("a batch at the cap should classify");
        assert_eq!(info.operations.len(), MAX_OPERATIONS_PER_REQUEST);
    }

    #[test]
    fn one_bad_member_refuses_the_whole_batch() {
        let err = post(r#"[{"query":"query { viewer }"},{"variables":{}}]"#)
            .expect_err("a batch is refused whole");
        assert!(err.contains("neither a document nor"), "{err}");
    }

    // ----------------------------------------------------------------------
    // Persisted queries
    // ----------------------------------------------------------------------

    #[test]
    fn reads_an_apq_hash_with_no_document() {
        let op = one(
            r#"{"operationName":"Viewer","extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc123"}}}"#,
        );
        assert!(op.is_opaque());
        assert_eq!(op.operation_type, None);
        assert_eq!(op.persisted_key.as_deref(), Some("abc123"));
        assert_eq!(op.operation_name.as_deref(), Some("Viewer"));
    }

    #[test]
    fn reads_a_document_id_with_no_document() {
        let op = one(r#"{"documentId":"doc-1"}"#);
        assert!(op.is_opaque());
        assert_eq!(op.persisted_key.as_deref(), Some("doc-1"));
    }

    #[test]
    fn a_document_beside_a_hash_is_read_from_the_document() {
        // The server runs the document it was sent, so that is what a rule
        // must judge. The hash is recorded but decides nothing.
        let op = one(
            r#"{"query":"mutation M { createIssue }","extensions":{"persistedQuery":{"sha256Hash":"abc123"}}}"#,
        );
        assert!(!op.is_opaque());
        assert_eq!(op.operation_type, Some(GraphqlOperationType::Mutation));
        assert_eq!(op.fields, ["createIssue"]);
        assert_eq!(op.persisted_key.as_deref(), Some("abc123"));
    }

    #[test]
    fn an_apq_hash_wins_over_a_document_id() {
        let op = one(r#"{"id":"doc-1","extensions":{"persistedQuery":{"sha256Hash":"abc"}}}"#);
        assert_eq!(op.persisted_key.as_deref(), Some("abc"));
    }

    #[test]
    fn an_empty_apq_hash_is_not_an_identifier() {
        let err = post(r#"{"extensions":{"persistedQuery":{"sha256Hash":""}}}"#)
            .expect_err("an empty hash identifies nothing");
        assert!(err.contains("neither a document nor"), "{err}");
    }

    // ----------------------------------------------------------------------
    // GET transport
    // ----------------------------------------------------------------------

    #[test]
    fn reads_a_get_query_parameter() {
        let info = classify_request(
            "GET",
            "/graphql?query=query%20Viewer%20%7B%20viewer%20%7D",
            b"",
        )
        .expect("a GET should classify");
        assert_eq!(
            info.operations[0].operation_type,
            Some(GraphqlOperationType::Query)
        );
        assert_eq!(info.operations[0].fields, ["viewer"]);
    }

    #[test]
    fn decodes_a_plus_as_a_space_in_a_get() {
        let info = classify_request("GET", "/graphql?query=query+Q+%7B+viewer+%7D", b"")
            .expect("a form-encoded GET should classify");
        assert_eq!(info.operations[0].fields, ["viewer"]);
    }

    #[test]
    fn a_get_with_no_query_string_is_refused() {
        let err = classify_request("GET", "/graphql", b"")
            .expect_err("a GET carrying nothing should be refused");
        assert!(err.contains("neither a document nor"), "{err}");
    }

    #[test]
    fn a_repeated_get_query_parameter_is_refused() {
        let err = classify_request(
            "GET",
            "/graphql?query=query+A+%7B+viewer+%7D&query=mutation+B+%7B+deleteRepo+%7D",
            b"",
        )
        .expect_err("a repeated document should be refused");
        assert!(err.contains("repeats the \"query\""), "{err}");
    }

    #[test]
    fn combined_get_persisted_identifiers_are_refused() {
        let err = classify_request("GET", "/graphql?id=one&queryId=two", b"")
            .expect_err("two identifiers should be refused");
        assert!(err.contains("combines the"), "{err}");
    }

    #[test]
    fn a_malformed_escape_in_a_get_is_refused() {
        let err = classify_request("GET", "/graphql?query=%zz", b"")
            .expect_err("a bad escape should be refused");
        assert!(err.contains("malformed escape"), "{err}");
    }

    #[test]
    fn a_truncated_escape_in_a_get_is_refused() {
        let err = classify_request("GET", "/graphql?query=%4", b"")
            .expect_err("a truncated escape should be refused");
        assert!(err.contains("malformed escape"), "{err}");
    }

    #[test]
    fn a_get_reads_an_apq_hash_from_extensions() {
        let info = classify_request(
            "GET",
            "/graphql?extensions=%7B%22persistedQuery%22%3A%7B%22sha256Hash%22%3A%22abc%22%7D%7D",
            b"",
        )
        .expect("a GET APQ should classify");
        assert_eq!(info.operations[0].persisted_key.as_deref(), Some("abc"));
        assert!(info.operations[0].is_opaque());
    }

    #[test]
    fn a_get_extensions_parameter_that_is_not_json_is_refused() {
        let err = classify_request("GET", "/graphql?extensions=nonsense", b"")
            .expect_err("bad extensions should be refused");
        assert!(err.contains("not valid JSON"), "{err}");
    }

    // ----------------------------------------------------------------------
    // Other methods
    // ----------------------------------------------------------------------

    #[test]
    fn a_method_that_carries_no_operation_is_refused() {
        for method in ["PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
            let err =
                classify_request(method, "/graphql", b"").expect_err("method should be refused");
            assert!(err.contains("is not supported"), "{err}");
        }
    }

    #[test]
    fn the_method_is_read_without_regard_to_case() {
        let info = classify_request("post", "/graphql", br#"{"query":"{ viewer }"}"#)
            .expect("a lowercase method should classify");
        assert_eq!(info.operations[0].fields, ["viewer"]);
    }

    // ----------------------------------------------------------------------
    // Matching operations against rules
    // ----------------------------------------------------------------------

    fn matcher(
        operation_type: GraphqlOperationTypeMatcher,
        operation_name: Option<&str>,
        fields: &[&str],
    ) -> GraphqlMatcher {
        GraphqlMatcher {
            operation_type,
            operation_name: operation_name.map(ToString::to_string),
            fields: fields.iter().map(ToString::to_string).collect(),
        }
    }

    fn judge(body: &str, matchers: &[GraphqlMatcher]) -> Result<(), String> {
        let candidates: Vec<&GraphqlMatcher> = matchers.iter().collect();
        check_request("POST", "/graphql", body.as_bytes(), &candidates)
    }

    #[test]
    fn a_query_rule_permits_a_query() {
        let rules = [matcher(
            GraphqlOperationTypeMatcher::Query,
            None,
            &["viewer"],
        )];
        assert!(judge(r#"{"query":"{ viewer }"}"#, &rules).is_ok());
    }

    #[test]
    fn a_query_rule_refuses_a_mutation() {
        let rules = [matcher(
            GraphqlOperationTypeMatcher::Query,
            None,
            &["createIssue"],
        )];
        let err = judge(r#"{"query":"mutation { createIssue }"}"#, &rules)
            .expect_err("a query rule must not permit a write");
        assert!(err.contains("no rule permits"), "{err}");
    }

    #[test]
    fn a_wildcard_type_rule_permits_any_type() {
        let rules = [matcher(GraphqlOperationTypeMatcher::Any, None, &["thing"])];
        assert!(judge(r#"{"query":"{ thing }"}"#, &rules).is_ok());
        assert!(judge(r#"{"query":"mutation { thing }"}"#, &rules).is_ok());
    }

    #[test]
    fn an_operation_name_glob_is_honoured() {
        let rules = [matcher(
            GraphqlOperationTypeMatcher::Query,
            Some("Get*"),
            &[],
        )];
        assert!(judge(r#"{"query":"query GetViewer { viewer }"}"#, &rules).is_ok());
        assert!(judge(r#"{"query":"query ListRepos { repos }"}"#, &rules).is_err());
    }

    #[test]
    fn a_named_rule_refuses_an_unnamed_operation() {
        let rules = [matcher(
            GraphqlOperationTypeMatcher::Query,
            Some("Get*"),
            &[],
        )];
        assert!(judge(r#"{"query":"{ viewer }"}"#, &rules).is_err());
    }

    #[test]
    fn a_rule_without_fields_places_no_field_condition() {
        let rules = [matcher(GraphqlOperationTypeMatcher::Query, None, &[])];
        assert!(judge(r#"{"query":"{ viewer secrets }"}"#, &rules).is_ok());
    }

    #[test]
    fn every_selected_field_must_be_permitted() {
        // The containment rule. A permitted field must not carry an
        // unpermitted one through beside it.
        let rules = [matcher(
            GraphqlOperationTypeMatcher::Query,
            None,
            &["viewer"],
        )];
        let err = judge(r#"{"query":"{ viewer deleteRepository }"}"#, &rules)
            .expect_err("one unlisted field must fail the whole operation");
        assert!(err.contains("no rule permits"), "{err}");
    }

    #[test]
    fn a_field_glob_is_honoured() {
        let rules = [matcher(
            GraphqlOperationTypeMatcher::Query,
            None,
            &["repo*", "viewer"],
        )];
        assert!(judge(r#"{"query":"{ viewer repository repos }"}"#, &rules).is_ok());
        assert!(judge(r#"{"query":"{ viewer organization }"}"#, &rules).is_err());
    }

    #[test]
    fn rules_do_not_combine_to_permit_one_operation() {
        // Two rules that each permit one half permit neither half's partner:
        // a permission nobody wrote must not appear by addition.
        let rules = [
            matcher(GraphqlOperationTypeMatcher::Query, None, &["viewer"]),
            matcher(GraphqlOperationTypeMatcher::Query, None, &["rateLimit"]),
        ];
        assert!(judge(r#"{"query":"{ viewer }"}"#, &rules).is_ok());
        assert!(judge(r#"{"query":"{ rateLimit }"}"#, &rules).is_ok());
        let err = judge(r#"{"query":"{ viewer rateLimit }"}"#, &rules)
            .expect_err("field permissions must not add up across rules");
        assert!(err.contains("no rule permits"), "{err}");
    }

    #[test]
    fn an_alias_does_not_launder_a_forbidden_field() {
        let rules = [matcher(GraphqlOperationTypeMatcher::Any, None, &["viewer"])];
        let err = judge(
            r#"{"query":"mutation { viewer: deleteRepository { id } }"}"#,
            &rules,
        )
        .expect_err("the field decides, not the alias");
        assert!(err.contains("deleteRepository"), "{err}");
    }

    #[test]
    fn a_fragment_does_not_hide_a_forbidden_field() {
        let rules = [matcher(
            GraphqlOperationTypeMatcher::Query,
            None,
            &["viewer"],
        )];
        let err = judge(
            r#"{"query":"query Q { ...R } fragment R on Query { viewer deleteRepository }"}"#,
            &rules,
        )
        .expect_err("a spread at the root selects root fields");
        assert!(err.contains("deleteRepository"), "{err}");
    }

    #[test]
    fn a_rule_that_names_fields_refuses_an_empty_selection() {
        // Guards the containment rule: "selects nothing" must not vacuously
        // satisfy "selects only these".
        let operation = OperationInfo {
            operation_type: Some(GraphqlOperationType::Query),
            operation_name: None,
            fields: Vec::new(),
            persisted_key: None,
        };
        let rule = matcher(GraphqlOperationTypeMatcher::Query, None, &["viewer"]);
        let info = RequestInfo {
            operations: vec![operation],
        };
        assert!(check_operations(&info, &[&rule]).is_err());
    }

    #[test]
    fn every_member_of_a_batch_must_be_permitted() {
        let rules = [matcher(
            GraphqlOperationTypeMatcher::Query,
            None,
            &["viewer"],
        )];
        assert!(judge(r#"[{"query":"{ viewer }"},{"query":"{ viewer }"}]"#, &rules).is_ok());
        let err = judge(
            r#"[{"query":"{ viewer }"},{"query":"mutation { deleteRepository }"}]"#,
            &rules,
        )
        .expect_err("one forbidden member must fail the batch");
        assert!(err.contains("deleteRepository"), "{err}");
    }

    #[test]
    fn a_persisted_query_with_no_document_is_refused() {
        let rules = [matcher(GraphqlOperationTypeMatcher::Any, None, &[])];
        let err = judge(
            r#"{"extensions":{"persistedQuery":{"sha256Hash":"abc123"}}}"#,
            &rules,
        )
        .expect_err("an operation the proxy cannot read must be refused");
        assert!(err.contains("abc123"), "{err}");
        assert!(err.contains("carries no document"), "{err}");
    }

    #[test]
    fn a_document_sent_beside_a_hash_is_judged_on_the_document() {
        let rules = [matcher(
            GraphqlOperationTypeMatcher::Query,
            None,
            &["viewer"],
        )];
        assert!(
            judge(
                r#"{"query":"{ viewer }","extensions":{"persistedQuery":{"sha256Hash":"abc"}}}"#,
                &rules
            )
            .is_ok()
        );
    }

    #[test]
    fn no_candidate_rule_refuses_everything() {
        let err = judge(r#"{"query":"{ viewer }"}"#, &[]).expect_err("no rule means no permission");
        assert!(err.contains("no rule permits"), "{err}");
    }

    // ----------------------------------------------------------------------
    // Bodies the proxy cannot read
    // ----------------------------------------------------------------------

    #[test]
    fn a_plain_head_is_readable() {
        let head = "POST /graphql HTTP/1.1\r\nHost: x\r\nContent-Type: application/json";
        assert!(ensure_body_is_readable(head).is_ok());
    }

    #[test]
    fn an_identity_encoding_is_readable() {
        let head = "POST /graphql HTTP/1.1\r\nContent-Encoding: identity";
        assert!(ensure_body_is_readable(head).is_ok());
    }

    #[test]
    fn a_compressed_body_is_refused() {
        for coding in ["gzip", "deflate", "br", "zstd"] {
            let head = format!("POST /graphql HTTP/1.1\r\nContent-Encoding: {coding}");
            let err = ensure_body_is_readable(&head)
                .expect_err("a coding the proxy cannot undo must be refused");
            assert!(err.contains(coding), "{err}");
        }
    }

    #[test]
    fn a_multipart_body_is_refused() {
        let head = "POST /graphql HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=xyz";
        assert!(ensure_body_is_readable(head).is_err());
    }

    #[test]
    fn a_header_name_is_read_without_regard_to_case() {
        let head = "POST /graphql HTTP/1.1\r\nCONTENT-ENCODING: GZIP";
        assert!(ensure_body_is_readable(head).is_err());
    }

    #[test]
    fn a_request_line_that_looks_like_a_header_is_not_read_as_one() {
        // The first line is the request line, never a field.
        let head = "POST /content-encoding:gzip HTTP/1.1\r\nHost: x";
        assert!(ensure_body_is_readable(head).is_ok());
    }

    // ----------------------------------------------------------------------
    // Name globs
    // ----------------------------------------------------------------------

    #[test]
    fn a_glob_without_a_wildcard_matches_exactly() {
        assert!(glob_matches("viewer", "viewer"));
        assert!(!glob_matches("viewer", "viewerLogin"));
        assert!(!glob_matches("viewer", "Viewer"));
    }

    #[test]
    fn a_lone_wildcard_matches_anything() {
        assert!(glob_matches("*", "viewer"));
        assert!(glob_matches("*", ""));
    }

    #[test]
    fn a_wildcard_spans_any_run_of_characters() {
        assert!(glob_matches("repo*", "repository"));
        assert!(glob_matches("repo*", "repo"));
        assert!(!glob_matches("repo*", "myrepo"));
        assert!(glob_matches("*Issue", "createIssue"));
        assert!(glob_matches("create*Issue", "createSubIssue"));
        assert!(!glob_matches("create*Issue", "createIssueComment"));
    }

    #[test]
    fn a_wildcard_crosses_a_separator() {
        // Unlike a path glob, nothing stops a field-name wildcard.
        assert!(glob_matches("a*b", "a/x/b"));
    }

    #[test]
    fn several_wildcards_match_in_order() {
        assert!(glob_matches("a*b*c", "axxbyyc"));
        assert!(!glob_matches("a*b*c", "axxcyyb"));
    }
}
