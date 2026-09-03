//! The `bodyField` half of a `header` credential injection: the same secret,
//! written into a `application/x-www-form-urlencoded` request body.
//!
//! Some SDKs send their token twice — in an `Authorization` header and in a
//! body field — and the server reads the body first. Replacing the header alone
//! leaves the placeholder where the server looks, so the injection can also
//! name the body field that carries it. Only a urlencoded body is rewritten; any
//! other body passes through unchanged, and a field that is absent is not added.

use tokio::io::{AsyncRead, AsyncWrite};

use crate::http_body::BodyFraming;
use crate::proxy::CredentialInjection;

/// The body field a `header` injection also fills.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyField {
    pub field: String,
    pub value: String,
}

/// Largest urlencoded body rewritten for a body field.
///
/// A rewritten body is only split on `&`, never parsed as a whole, so it gets
/// the budget of a judged body rather than an inspected one: a Slack message
/// carries its blocks as form-encoded JSON, and that outgrows
/// [`crate::http_body::MAX_INSPECT_BYTES`] long before it stops being a message.
pub const MAX_REWRITTEN_BODY_BYTES: usize = crate::http_body::MAX_JUDGED_BODY_BYTES;

/// Write every matching injection's body field into the request body.
///
/// A body still on the socket is read here, since the bytes have to be in hand
/// to be rewritten; the caller reframes the head from `buffered_body` as it
/// already does for a body a rule read. Returns the reason when the body cannot
/// be read in full: a field the proxy could not reach is a placeholder that
/// would go upstream, so the request is refused rather than sent as is.
pub(crate) async fn inject_body_fields<C>(
    client: &mut C,
    head: &str,
    injections: &[&CredentialInjection],
    body_mode: BodyFraming,
    buffered_body: &mut Option<Vec<u8>>,
) -> Result<(), String>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let fields: Vec<&BodyField> = injections
        .iter()
        .filter_map(|inj| inj.body.as_ref())
        .collect();
    if fields.is_empty() || !is_urlencoded(head) {
        return Ok(());
    }
    let mut body = match buffered_body.take() {
        Some(body) => body,
        None if body_mode == BodyFraming::None => return Ok(()),
        None => {
            crate::http_body::ensure_body_is_readable(head)?;
            crate::http_body::answer_continue_if_expected(client, head).await?;
            crate::http_body::read_body(client, body_mode, MAX_REWRITTEN_BODY_BYTES)
                .await
                .map_err(|err| err.to_string())?
        }
    };
    for field in fields {
        body = rewrite_urlencoded_field(&body, &field.field, &field.value);
    }
    *buffered_body = Some(body);
    Ok(())
}

fn is_urlencoded(head: &str) -> bool {
    head.split("\r\n").skip(1).any(|line| {
        let lower = line.to_ascii_lowercase();
        lower
            .strip_prefix("content-type:")
            .and_then(|value| value.split(';').next())
            .is_some_and(|media| media.trim() == "application/x-www-form-urlencoded")
    })
}

/// Replace the value of every `field` pair in a urlencoded body. The rest of the
/// body is kept byte for byte, so pairs the server reads by position or by
/// repetition arrive as the client sent them.
fn rewrite_urlencoded_field(body: &[u8], field: &str, value: &str) -> Vec<u8> {
    let encoded_value = form_encode(value);
    let pairs: Vec<Vec<u8>> = body
        .split(|byte| *byte == b'&')
        .map(|pair| {
            let (key, _) = pair
                .iter()
                .position(|byte| *byte == b'=')
                .map_or((pair, None), |eq| (&pair[..eq], Some(&pair[eq + 1..])));
            if form_decode(key) == field.as_bytes() {
                let mut out = key.to_vec();
                out.push(b'=');
                out.extend_from_slice(encoded_value.as_bytes());
                out
            } else {
                pair.to_vec()
            }
        })
        .collect();
    pairs.join(&b'&')
}

fn form_decode(key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len());
    let mut bytes = key.iter();
    while let Some(byte) = bytes.next() {
        match byte {
            b'+' => out.push(b' '),
            b'%' => {
                let hex: Vec<u8> = bytes.clone().take(2).copied().collect();
                match std::str::from_utf8(&hex)
                    .ok()
                    .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                {
                    Some(decoded) if hex.len() == 2 => {
                        out.push(decoded);
                        bytes.nth(1);
                    }
                    _ => out.push(b'%'),
                }
            }
            other => out.push(*other),
        }
    }
    out
}

fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_named_field_takes_the_value_and_the_rest_is_untouched() {
        let out = rewrite_urlencoded_field(
            b"channel=C1&token=__lens_cred:slack__&text=hi",
            "token",
            "xoxb-real",
        );
        assert_eq!(out, b"channel=C1&token=xoxb-real&text=hi");
    }

    #[test]
    fn an_absent_field_is_not_added() {
        let out = rewrite_urlencoded_field(b"channel=C1&text=hi", "token", "xoxb-real");
        assert_eq!(out, b"channel=C1&text=hi");
    }

    #[test]
    fn every_repeat_of_the_field_is_replaced() {
        let out = rewrite_urlencoded_field(b"token=a&token=b", "token", "real");
        assert_eq!(out, b"token=real&token=real");
    }

    #[test]
    fn a_field_without_a_value_gets_one() {
        let out = rewrite_urlencoded_field(b"token&x=1", "token", "real");
        assert_eq!(out, b"token=real&x=1");
    }

    #[test]
    fn the_field_name_is_matched_after_decoding_and_kept_as_sent() {
        let out = rewrite_urlencoded_field(b"api%5Ftoken=old", "api_token", "real");
        assert_eq!(out, b"api%5Ftoken=real");
    }

    #[test]
    fn the_value_is_form_encoded() {
        let out = rewrite_urlencoded_field(b"token=old", "token", "a b&c=d/e");
        assert_eq!(out, b"token=a%20b%26c%3Dd%2Fe");
    }

    #[test]
    fn a_prefix_of_the_field_name_does_not_match() {
        let out = rewrite_urlencoded_field(b"tokens=old&token=old", "token", "real");
        assert_eq!(out, b"tokens=old&token=real");
    }

    #[test]
    fn an_empty_body_stays_empty() {
        assert_eq!(rewrite_urlencoded_field(b"", "token", "real"), b"");
    }

    #[test]
    fn only_a_urlencoded_content_type_is_rewritten() {
        assert!(is_urlencoded(
            "POST /x HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded; charset=utf-8\r\n"
        ));
        assert!(!is_urlencoded(
            "POST /x HTTP/1.1\r\nContent-Type: application/json\r\n"
        ));
        assert!(!is_urlencoded("POST /x HTTP/1.1\r\nHost: a\r\n"));
    }
}
