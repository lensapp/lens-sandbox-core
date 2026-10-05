//! The `oauthTokenAnswer` and `oauthRefreshAnswer` credential injections: an
//! OAuth 2.0 client-credentials (RFC 6749 §4.4) or refresh-token (§6) request
//! answered by the proxy instead of forwarded.
//!
//! The sandbox's SDK runs its usual grant against the token endpoint, with a
//! placeholder where the client secret or the refresh token goes. The proxy answers that request
//! with a placeholder access token, so neither the request nor anything in it
//! leaves the sandbox. A `header` injection on each API domain then replaces
//! the placeholder token with the real one on the way out. The real secret and
//! the real token stay with the host that sends the policy.
//!
//! A request is answered only when it is a `POST` to a configured path whose
//! form body asks for `grant_type=client_credentials` for a configured client,
//! or for `grant_type=refresh_token` with a configured placeholder refresh
//! token. Any other request to the host is forwarded as the sandbox sent it, so
//! a client the sandbox holds its own secret or refresh token for keeps working.

use std::collections::BTreeSet;

use base64::Engine;

/// A token request the proxy answers at one token endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenAnswer {
    /// Token endpoint path, normalized as request paths are.
    pub path: String,
    pub grant: Grant,
    /// The placeholder handed to the sandbox as `access_token`.
    pub access_token: String,
    /// Seconds reported as `expires_in`.
    pub expires_in: u64,
}

/// The grant a [`TokenAnswer`] answers, and what identifies a request for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Grant {
    ClientCredentials {
        client_id: String,
        /// The requested scope must equal this set; an empty set answers a
        /// request that names no scope.
        scope: BTreeSet<String>,
    },
    /// Identified by the placeholder alone, because public clients share one
    /// client id across every user and a refresh may narrow its scope.
    RefreshToken { refresh_token: String },
}

impl TokenAnswer {
    pub(crate) fn client_credentials(
        path: &str,
        client_id: &str,
        scope: &str,
        access_token: &str,
        expires_in: u64,
    ) -> Result<Self, &'static str> {
        if client_id.is_empty() {
            return Err("clientId is empty");
        }
        let grant = Grant::ClientCredentials {
            client_id: client_id.to_string(),
            scope: scope_set(scope),
        };
        Self::new(path, grant, access_token, expires_in)
    }

    pub(crate) fn refresh_token(
        path: &str,
        refresh_token: &str,
        access_token: &str,
        expires_in: u64,
    ) -> Result<Self, &'static str> {
        if refresh_token.is_empty() {
            return Err("refreshToken is empty");
        }
        let grant = Grant::RefreshToken {
            refresh_token: refresh_token.to_string(),
        };
        Self::new(path, grant, access_token, expires_in)
    }

    fn new(
        path: &str,
        grant: Grant,
        access_token: &str,
        expires_in: u64,
    ) -> Result<Self, &'static str> {
        if !path.starts_with('/') {
            return Err("path must start with '/'");
        }
        if access_token.is_empty() {
            return Err("accessToken is empty");
        }
        Ok(Self {
            path: crate::routing::normalize_path(path),
            grant,
            access_token: access_token.to_string(),
            expires_in,
        })
    }
}

/// What the proxy does with a request to a host that has token answers.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Decision<'a> {
    /// Not a request any answer covers: forward it.
    NotOurs,
    /// Answer with this placeholder token.
    Answer(&'a TokenAnswer),
    /// A configured client asked for a scope the policy holds no token for.
    InvalidScope,
}

/// Whether a request to this host may be one the proxy answers, judged from
/// its head. Only a urlencoded `POST` to a configured path can be, so no other
/// body is read and every other request is forwarded as it came.
pub(crate) fn may_answer(answers: &[TokenAnswer], method: &str, path: &str, head: &str) -> bool {
    method.eq_ignore_ascii_case("POST")
        && answers.iter().any(|answer| answer.path == path)
        && crate::body_field::is_urlencoded(head)
}

/// Decide from the request head and its urlencoded body.
pub(crate) fn decide<'a>(
    answers: &'a [TokenAnswer],
    method: &str,
    path: &str,
    head: &str,
    body: &[u8],
) -> Decision<'a> {
    if !may_answer(answers, method, path, head) {
        return Decision::NotOurs;
    }
    let form = parse_form(body);
    let field = |name: &str| {
        form.iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    let mut at_path = answers.iter().filter(|answer| answer.path == path);
    match field("grant_type") {
        Some("client_credentials") => {
            let Some(client_id) = field("client_id")
                .map(str::to_string)
                .or_else(|| basic_auth_client_id(head))
            else {
                return Decision::NotOurs;
            };
            let requested = scope_set(field("scope").unwrap_or(""));
            decide_client_credentials(at_path, &client_id, &requested)
        }
        Some("refresh_token") => {
            let Some(sent) = field("refresh_token") else {
                return Decision::NotOurs;
            };
            at_path
                .find(|answer| {
                    matches!(&answer.grant, Grant::RefreshToken { refresh_token } if refresh_token == sent)
                })
                .map_or(Decision::NotOurs, Decision::Answer)
        }
        _ => Decision::NotOurs,
    }
}

fn decide_client_credentials<'a>(
    at_path: impl Iterator<Item = &'a TokenAnswer>,
    client_id: &str,
    requested: &BTreeSet<String>,
) -> Decision<'a> {
    let mut for_client = at_path
        .filter_map(|answer| match &answer.grant {
            Grant::ClientCredentials {
                client_id: id,
                scope,
            } if id == client_id => Some((answer, scope)),
            _ => None,
        })
        .peekable();
    if for_client.peek().is_none() {
        return Decision::NotOurs;
    }
    for_client
        .find(|(_, scope)| *scope == requested)
        .map_or(Decision::InvalidScope, |(answer, _)| {
            Decision::Answer(answer)
        })
}

/// The response for a decision the proxy answers itself.
pub(crate) fn response(decision: &Decision<'_>) -> Option<Vec<u8>> {
    let (status, body) = match decision {
        Decision::NotOurs => return None,
        Decision::Answer(answer) => {
            let mut body = serde_json::json!({
                "token_type": "Bearer",
                "access_token": answer.access_token,
                "expires_in": answer.expires_in,
            });
            if let Grant::RefreshToken { refresh_token } = &answer.grant {
                body["refresh_token"] = refresh_token.as_str().into();
            }
            ("200 OK", body)
        }
        Decision::InvalidScope => (
            "400 Bad Request",
            serde_json::json!({
                "error": "invalid_scope",
                "error_description": "the sandbox holds no token for this scope",
            }),
        ),
    };
    let body = body.to_string();
    // RFC 6749 §5.1: a token response must not be cached.
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n\
         Pragma: no-cache\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    Some([head.as_bytes(), body.as_bytes()].concat())
}

fn scope_set(scope: &str) -> BTreeSet<String> {
    scope.split_whitespace().map(str::to_string).collect()
}

fn parse_form(body: &[u8]) -> Vec<(String, String)> {
    body.split(|byte| *byte == b'&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair
                .iter()
                .position(|byte| *byte == b'=')
                .map_or((pair, &b""[..]), |eq| (&pair[..eq], &pair[eq + 1..]));
            (
                String::from_utf8_lossy(&crate::body_field::form_decode(key)).into_owned(),
                String::from_utf8_lossy(&crate::body_field::form_decode(value)).into_owned(),
            )
        })
        .collect()
}

/// The client id of an `Authorization: Basic` header (RFC 6749 §2.3.1), which
/// form-encodes the id before joining it to the secret.
fn basic_auth_client_id(head: &str) -> Option<String> {
    let value = head.split("\r\n").skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("authorization")
            .then(|| value.trim())
    })?;
    let (scheme, credentials) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(credentials.trim())
        .ok()?;
    let id = decoded.split(|byte| *byte == b':').next()?;
    Some(String::from_utf8_lossy(&crate::body_field::form_decode(id)).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FORM: &str = "Content-Type: application/x-www-form-urlencoded";

    fn answer(scope: &str) -> TokenAnswer {
        TokenAnswer::client_credentials(
            "/oauth2/token",
            "client-1",
            scope,
            "placeholder-token",
            3600,
        )
        .unwrap()
    }

    fn head(extra: &str) -> String {
        format!("POST /oauth2/token HTTP/1.1\r\nHost: login.example.com\r\n{FORM}\r\n{extra}")
    }

    #[test]
    fn a_client_credentials_request_for_the_client_and_scope_is_answered() {
        let answers = [answer("https://api.example.com/.default")];
        let body =
            b"grant_type=client_credentials&client_id=client-1&client_secret=__lens_cred:x__\
                     &scope=https%3A%2F%2Fapi.example.com%2F.default";

        assert_eq!(
            decide(&answers, "POST", "/oauth2/token", &head(""), body),
            Decision::Answer(&answers[0])
        );
    }

    #[test]
    fn the_answer_for_the_requested_scope_is_chosen() {
        let answers = [answer("scope-a"), answer("scope-b other")];
        let body = b"grant_type=client_credentials&client_id=client-1&scope=other+scope-b";

        assert_eq!(
            decide(&answers, "POST", "/oauth2/token", &head(""), body),
            Decision::Answer(&answers[1])
        );
    }

    #[test]
    fn a_scope_the_policy_holds_no_token_for_is_refused() {
        let answers = [answer("scope-a")];
        let body = b"grant_type=client_credentials&client_id=client-1&scope=scope-b";

        assert_eq!(
            decide(&answers, "POST", "/oauth2/token", &head(""), body),
            Decision::InvalidScope
        );
    }

    #[test]
    fn a_client_id_in_basic_auth_is_recognized() {
        let answers = [answer("scope-a")];
        let credentials = base64::engine::general_purpose::STANDARD.encode("client-1:secret");
        let head = head(&format!("Authorization: Basic {credentials}\r\n"));
        let body = b"grant_type=client_credentials&scope=scope-a";

        assert_eq!(
            decide(&answers, "POST", "/oauth2/token", &head, body),
            Decision::Answer(&answers[0])
        );
    }

    #[test]
    fn requests_for_another_client_grant_path_or_method_are_forwarded() {
        let answers = [answer("scope-a")];
        let ours = b"grant_type=client_credentials&client_id=client-1&scope=scope-a";

        let other_client = b"grant_type=client_credentials&client_id=client-2&scope=scope-a";
        assert_eq!(
            decide(&answers, "POST", "/oauth2/token", &head(""), other_client),
            Decision::NotOurs
        );
        let other_grant = b"grant_type=authorization_code&client_id=client-1&code=c";
        assert_eq!(
            decide(&answers, "POST", "/oauth2/token", &head(""), other_grant),
            Decision::NotOurs
        );
        assert_eq!(
            decide(&answers, "POST", "/other", &head(""), ours),
            Decision::NotOurs
        );
        assert_eq!(
            decide(&answers, "GET", "/oauth2/token", &head(""), ours),
            Decision::NotOurs
        );
    }

    #[test]
    fn a_body_that_is_not_urlencoded_is_forwarded() {
        let answers = [answer("scope-a")];
        let head = "POST /oauth2/token HTTP/1.1\r\nContent-Type: application/json\r\n";
        let body = br#"{"grant_type":"client_credentials","client_id":"client-1"}"#;

        assert_eq!(
            decide(&answers, "POST", "/oauth2/token", head, body),
            Decision::NotOurs
        );
    }

    #[test]
    fn the_answer_is_an_uncached_bearer_token_response() {
        let answers = [answer("scope-a")];
        let answered =
            String::from_utf8(response(&Decision::Answer(&answers[0])).unwrap()).unwrap();
        let (head, body) = answered.split_once("\r\n\r\n").unwrap();

        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        assert!(head.contains("Cache-Control: no-store"), "{head}");
        assert!(
            head.contains(&format!("Content-Length: {}", body.len())),
            "{head}"
        );
        let json: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(json["token_type"], "Bearer");
        assert_eq!(json["access_token"], "placeholder-token");
        assert_eq!(json["expires_in"], 3600);
    }

    #[test]
    fn a_refused_scope_answers_invalid_scope() {
        let refused = String::from_utf8(response(&Decision::InvalidScope).unwrap()).unwrap();

        assert!(
            refused.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "{refused}"
        );
        assert!(refused.contains(r#""error":"invalid_scope""#), "{refused}");
        assert!(response(&Decision::NotOurs).is_none());
    }

    fn refresh_answer() -> TokenAnswer {
        TokenAnswer::refresh_token(
            "/oauth2/token",
            "placeholder-refresh",
            "placeholder-token",
            3600,
        )
        .unwrap()
    }

    #[test]
    fn a_refresh_request_with_the_placeholder_is_answered_for_any_client_and_scope() {
        let answers = [refresh_answer()];
        let body = b"grant_type=refresh_token&refresh_token=placeholder-refresh\
                     &client_id=shared-public-client&scope=narrower";

        assert_eq!(
            decide(&answers, "POST", "/oauth2/token", &head(""), body),
            Decision::Answer(&answers[0])
        );
    }

    #[test]
    fn a_refresh_request_with_another_refresh_token_is_forwarded() {
        let answers = [refresh_answer()];
        let real = b"grant_type=refresh_token&refresh_token=a-real-token-the-sandbox-holds";
        let missing = b"grant_type=refresh_token&client_id=shared-public-client";

        assert_eq!(
            decide(&answers, "POST", "/oauth2/token", &head(""), real),
            Decision::NotOurs
        );
        assert_eq!(
            decide(&answers, "POST", "/oauth2/token", &head(""), missing),
            Decision::NotOurs
        );
    }

    #[test]
    fn a_client_credentials_answer_does_not_answer_a_refresh_request() {
        let answers = [answer("")];
        let body = b"grant_type=refresh_token&refresh_token=placeholder-token&client_id=client-1";

        assert_eq!(
            decide(&answers, "POST", "/oauth2/token", &head(""), body),
            Decision::NotOurs
        );
    }

    #[test]
    fn a_refresh_answer_does_not_answer_a_client_credentials_request() {
        let answers = [refresh_answer()];
        let body = b"grant_type=client_credentials&client_id=placeholder-refresh";

        assert_eq!(
            decide(&answers, "POST", "/oauth2/token", &head(""), body),
            Decision::NotOurs
        );
    }

    #[test]
    fn the_refresh_answer_hands_back_the_placeholder_refresh_token() {
        let answers = [refresh_answer()];
        let answered =
            String::from_utf8(response(&Decision::Answer(&answers[0])).unwrap()).unwrap();
        let (_, body) = answered.split_once("\r\n\r\n").unwrap();
        let json: serde_json::Value = serde_json::from_str(body).unwrap();

        assert_eq!(json["token_type"], "Bearer");
        assert_eq!(json["access_token"], "placeholder-token");
        assert_eq!(json["refresh_token"], "placeholder-refresh");
        assert_eq!(json["expires_in"], 3600);
    }

    #[test]
    fn a_client_credentials_answer_hands_back_no_refresh_token() {
        let answers = [answer("")];
        let answered =
            String::from_utf8(response(&Decision::Answer(&answers[0])).unwrap()).unwrap();
        let (_, body) = answered.split_once("\r\n\r\n").unwrap();
        let json: serde_json::Value = serde_json::from_str(body).unwrap();

        assert!(json.get("refresh_token").is_none(), "{json}");
    }

    #[test]
    fn a_refresh_answer_needs_a_path_a_refresh_token_and_a_token() {
        assert!(TokenAnswer::refresh_token("oauth2/token", "r", "t", 1).is_err());
        assert!(TokenAnswer::refresh_token("/oauth2/token", "", "t", 1).is_err());
        assert!(TokenAnswer::refresh_token("/oauth2/token", "r", "", 1).is_err());
    }

    #[test]
    fn an_answer_needs_a_path_a_client_and_a_token() {
        assert!(TokenAnswer::client_credentials("oauth2/token", "c", "", "t", 1).is_err());
        assert!(TokenAnswer::client_credentials("/oauth2/token", "", "", "t", 1).is_err());
        assert!(TokenAnswer::client_credentials("/oauth2/token", "c", "", "", 1).is_err());
    }
}
