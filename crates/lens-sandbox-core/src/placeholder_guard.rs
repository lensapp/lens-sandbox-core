//! The placeholder guards: a request that carries a granted placeholder to a
//! host its credential does not name is refused before it leaves.
//!
//! A placeholder is worthless off its hosts, so the guard protects no secret:
//! it gives the workload a clear refusal instead of the service's confusing
//! one, and keeps the placeholder off the wire. The scan is best-effort. It
//! reads the head and a body the door already holds, each as sent and
//! percent-decoded, and every base64 run in them decoded; a compressed or
//! opaque body is not scanned.

use std::collections::HashMap;

/// Why a request that carries a placeholder is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The request carries the placeholder of `credential` to a host that
    /// credential does not name.
    OffHost { credential: String },
}

/// The placeholders a policy granted: each one's credential, and the hosts
/// that credential names.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Granted {
    placeholders: HashMap<String, Placeholder>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Placeholder {
    credential: String,
    hosts: Vec<String>,
}

impl Granted {
    /// Grant `placeholder` to `credential`, on `hosts`. A placeholder two
    /// credentials share works on the hosts of both, and the last one names it.
    pub(crate) fn grant(&mut self, placeholder: &str, credential: &str, hosts: &[String]) {
        if placeholder.is_empty() {
            return;
        }
        let entry = self
            .placeholders
            .entry(placeholder.to_string())
            .or_default();
        entry.credential = credential.to_string();
        entry.hosts.extend(hosts.iter().cloned());
    }

    /// Whether a placeholder the policy granted would be off its hosts on a
    /// request to `host`, so a body to it is worth reading for the scan.
    pub(crate) fn any_off_host(&self, host: &str) -> bool {
        self.placeholders
            .values()
            .any(|granted| granted.is_off_host(host))
    }

    /// Why this request to `host` (as `injection_matches` reads it) is refused,
    /// or `None` when it carries no placeholder off its hosts. `body` is the
    /// body the door holds, already known to be uncompressed.
    pub(crate) fn judge(&self, head: &str, body: Option<&[u8]>, host: &str) -> Option<Refusal> {
        let views = views(head, body);
        let mut off_host: Vec<&str> = self
            .placeholders
            .iter()
            .filter(|(placeholder, granted)| {
                granted.is_off_host(host)
                    && views.iter().any(|view| view.contains(placeholder.as_str()))
            })
            .map(|(_, granted)| granted.credential.as_str())
            .collect();
        off_host.sort_unstable();
        off_host.first().map(|credential| Refusal::OffHost {
            credential: (*credential).to_string(),
        })
    }
}

impl Placeholder {
    /// A credential that names no host is left to the credential gate.
    fn is_off_host(&self, host: &str) -> bool {
        !self.hosts.is_empty()
            && !self
                .hosts
                .iter()
                .any(|pattern| crate::routing::injection_matches(pattern, host))
    }
}

/// Shortest run of the base64 alphabet that is decoded: the base64 of the
/// shortest placeholder a document may declare (16 characters).
const MIN_BASE64_RUN: usize = 20;

/// The texts a request is scanned as: the head and the body as sent, each
/// percent-decoded, and every base64 run in those decoded.
fn views(head: &str, body: Option<&[u8]>) -> Vec<String> {
    let mut sent = vec![head.to_string()];
    if let Some(body) = body {
        sent.push(String::from_utf8_lossy(body).into_owned());
    }
    let mut views = Vec::with_capacity(sent.len() * 2);
    for text in sent {
        let decoded = crate::proxy::percent_decode(&text);
        if decoded != text {
            views.push(decoded);
        }
        views.push(text);
    }
    let decoded: Vec<String> = views
        .iter()
        .flat_map(|view| base64_runs(view))
        .filter_map(decode_base64)
        .collect();
    views.extend(decoded);
    views
}

fn base64_runs(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '-' | '_')))
        .filter(|run| run.len() >= MIN_BASE64_RUN)
}

fn decode_base64(run: &str) -> Option<String> {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
    let bytes = STANDARD_NO_PAD
        .decode(run)
        .or_else(|_| URL_SAFE_NO_PAD.decode(run))
        .ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    const GITHUB: &str = "github_LNSPLACEHOLDER0000000000";

    fn github() -> Granted {
        let mut granted = Granted::default();
        granted.grant(GITHUB, "github", &["api.github.com".to_string()]);
        granted
    }

    fn off_host(credential: &str) -> Option<Refusal> {
        Some(Refusal::OffHost {
            credential: credential.to_string(),
        })
    }

    fn head(lines: &str) -> String {
        format!("POST /upload HTTP/1.1\r\nHost: evil.example\r\n{lines}")
    }

    #[test]
    fn a_placeholder_on_its_own_host_passes() {
        let head = format!("GET /user HTTP/1.1\r\nAuthorization: Bearer {GITHUB}");
        assert_eq!(github().judge(&head, None, "api.github.com:443"), None);
    }

    #[test]
    fn a_placeholder_in_a_header_off_its_hosts_is_refused_with_its_credential() {
        let head = head(&format!("Authorization: Bearer {GITHUB}"));
        assert_eq!(
            github().judge(&head, None, "evil.example:443"),
            off_host("github")
        );
    }

    #[test]
    fn a_placeholder_in_the_url_off_its_hosts_is_refused() {
        let head = format!("GET /collect?t={GITHUB} HTTP/1.1\r\nHost: evil.example");
        assert_eq!(
            github().judge(&head, None, "evil.example"),
            off_host("github")
        );
    }

    #[test]
    fn a_percent_encoded_placeholder_is_found() {
        let encoded = GITHUB.replace('_', "%5F");
        let head = format!("GET /collect?t={encoded} HTTP/1.1\r\nHost: evil.example");
        assert_eq!(
            github().judge(&head, None, "evil.example"),
            off_host("github")
        );
    }

    #[test]
    fn a_placeholder_in_a_body_is_found_as_sent_percent_encoded_and_in_base64() {
        let standard = base64::engine::general_purpose::STANDARD.encode(GITHUB);
        let url_safe =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("token:{GITHUB}"));
        for body in [
            format!("{{\"token\":\"{GITHUB}\"}}"),
            format!("token={}", GITHUB.replace('_', "%5f")),
            format!("{{\"blob\":\"{standard}\"}}"),
            format!("blob={url_safe}&a=1"),
        ] {
            assert_eq!(
                github().judge(&head(""), Some(body.as_bytes()), "evil.example"),
                off_host("github"),
                "{body}"
            );
        }
    }

    #[test]
    fn a_basic_password_is_found_in_its_base64() {
        let basic =
            base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{GITHUB}"));
        let head = head(&format!("Authorization: Basic {basic}"));
        assert_eq!(
            github().judge(&head, None, "evil.example"),
            off_host("github")
        );
    }

    #[test]
    fn a_body_the_door_does_not_hold_is_not_scanned() {
        assert_eq!(github().judge(&head(""), None, "evil.example"), None);
    }

    #[test]
    fn a_placeholder_whose_credential_names_no_host_is_left_to_the_credential_gate() {
        let mut granted = Granted::default();
        granted.grant(GITHUB, "github", &[]);
        let head = head(&format!("Authorization: Bearer {GITHUB}"));
        assert_eq!(granted.judge(&head, None, "evil.example"), None);
    }

    #[test]
    fn a_wildcard_host_covers_its_family_and_a_port_pattern_its_port() {
        let mut granted = Granted::default();
        granted.grant(GITHUB, "aws", &["*.amazonaws.com".to_string()]);
        granted.grant(
            "db_LNSPLACEHOLDER0000000000",
            "db",
            &["db.example:5432".to_string()],
        );
        let carrying = |placeholder: &str| head(&format!("X-Token: {placeholder}"));
        assert_eq!(
            granted.judge(&carrying(GITHUB), None, "sts.amazonaws.com:443"),
            None
        );
        assert_eq!(
            granted.judge(
                &carrying("db_LNSPLACEHOLDER0000000000"),
                None,
                "db.example:5432"
            ),
            None
        );
        assert_eq!(
            granted.judge(
                &carrying("db_LNSPLACEHOLDER0000000000"),
                None,
                "db.example:6543"
            ),
            off_host("db")
        );
    }

    #[test]
    fn a_placeholder_two_credentials_share_works_on_the_hosts_of_both() {
        let mut granted = github();
        granted.grant(GITHUB, "github-app", &["uploads.github.com".to_string()]);
        let head = head(&format!("Authorization: Bearer {GITHUB}"));
        assert_eq!(granted.judge(&head, None, "uploads.github.com"), None);
        assert_eq!(granted.judge(&head, None, "api.github.com"), None);
        assert_eq!(
            granted.judge(&head, None, "evil.example"),
            off_host("github-app")
        );
    }

    #[test]
    fn of_two_placeholders_off_their_hosts_the_first_credential_by_name_is_named() {
        let mut granted = github();
        granted.grant(
            "gitlab_LNSPLACEHOLDER000000000",
            "gitlab",
            &["gitlab.com".to_string()],
        );
        let head = head(&format!(
            "X-A: gitlab_LNSPLACEHOLDER000000000\r\nX-B: {GITHUB}"
        ));
        assert_eq!(
            granted.judge(&head, None, "evil.example"),
            off_host("github")
        );
    }

    #[test]
    fn a_body_is_worth_reading_only_where_a_granted_placeholder_is_off_its_hosts() {
        let mut granted = github();
        granted.grant("hub_LNSPLACEHOLDER0000000000", "hub", &[]);
        assert!(granted.any_off_host("evil.example:443"));
        assert!(!granted.any_off_host("api.github.com:443"));
        assert!(!Granted::default().any_off_host("evil.example:443"));
    }

    #[test]
    fn an_empty_placeholder_is_never_granted() {
        let mut granted = Granted::default();
        granted.grant("", "empty", &["api.example".to_string()]);
        assert_eq!(granted.judge(&head(""), None, "evil.example"), None);
    }

    #[test]
    fn a_short_base64_run_is_not_decoded() {
        assert_eq!(decode_base64_runs("Zm9v"), Vec::<String>::new());
        assert_eq!(
            decode_base64_runs("not base64 at all ~~~"),
            Vec::<String>::new()
        );
    }

    fn decode_base64_runs(text: &str) -> Vec<String> {
        base64_runs(text).filter_map(decode_base64).collect()
    }
}
