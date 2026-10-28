//! What an origin answered a request the proxy terminated and forwarded.
//!
//! The audit record of a forwarded request says what the proxy decided, and
//! what came back is the origin's business. A consumer still needs the answer:
//! an inference router refuses a run that is out of credit with `402`, and one
//! that reached its spending limit with `429 limit_exceeded`, and only the
//! proxy sees either. So the record of a forwarded request waits for the
//! answer's head, and carries it apart from the proxy's own decision:
//!
//! - `upstream_status_code`: the status of the final answer. The proxy's own
//!   `status_code` is not set on a forwarded request, so the two never mix.
//! - `upstream_error_code`: for a `4xx` whose body is JSON of at most
//!   [`MAX_ERROR_BODY_BYTES`], the error's `error.code` (OpenAI's shape), or
//!   `error.type` in Anthropic's envelope (`{"type":"error","error":{...}}`).
//!
//! The body is read as it is relayed, never ahead of the workload, and nothing
//! of it is changed.

use std::sync::Mutex;

use tokio::sync::mpsc::UnboundedSender;

/// The most of a refusal's body the proxy keeps to read its error code. A
/// longer body is relayed whole and not read.
pub const MAX_ERROR_BODY_BYTES: usize = 16 * 1024;

/// The longest error code the record carries. A code is a short identifier; a
/// longer value is not one, and is left out.
const MAX_ERROR_CODE_LEN: usize = 64;

/// The audit record of a forwarded request, held until its answer is known.
///
/// It is sent once: by [`answered`](Self::answered), or when it is dropped
/// without one, because the origin never answered.
pub(crate) struct PendingAudit {
    held: Mutex<Option<Held>>,
}

struct Held {
    tx: UnboundedSender<String>,
    event: serde_json::Value,
}

impl PendingAudit {
    /// A record to send on `tx` once the answer is known.
    pub(crate) fn new(tx: UnboundedSender<String>, event: serde_json::Value) -> Self {
        Self {
            held: Mutex::new(Some(Held { tx, event })),
        }
    }

    /// No record: there is no audit channel, or the record has already gone.
    pub(crate) fn none() -> Self {
        Self {
            held: Mutex::new(None),
        }
    }

    /// Record that the request was sent once more, with a renewed credential.
    pub(crate) fn resent_after_renewal(&self) {
        if let Some(held) = self.lock().as_mut()
            && let Some(metadata) = held
                .event
                .get_mut("metadata")
                .and_then(serde_json::Value::as_object_mut)
        {
            metadata.insert("resent_after_renewal".into(), true.into());
        }
    }

    /// Send the record with what the origin answered.
    pub(crate) fn answered(&self, status: u16, error_code: Option<String>) {
        let Some(mut held) = self.lock().take() else {
            return;
        };
        if let Some(event) = held.event.as_object_mut() {
            event.insert("upstream_status_code".into(), status.into());
            if let Some(code) = error_code {
                event.insert("upstream_error_code".into(), code.into());
            }
        }
        let _ = held.tx.send(held.event.to_string());
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Held>> {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Drop for PendingAudit {
    fn drop(&mut self) {
        if let Some(held) = self.lock().take() {
            let _ = held.tx.send(held.event.to_string());
        }
    }
}

/// Whether the error code of the answer with this head is worth reading: a
/// `4xx` with a JSON body the proxy can read as sent.
pub(crate) fn may_carry_error_code(status: u16, head: &str) -> bool {
    if !(400..500).contains(&status) {
        return false;
    }
    let mut json = false;
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim().to_ascii_lowercase();
        if name.eq_ignore_ascii_case("content-type") {
            let media = value.split(';').next().unwrap_or("").trim();
            json = media == "application/json" || media.ends_with("+json");
        } else if name.eq_ignore_ascii_case("content-encoding") && value != "identity" {
            return false;
        }
    }
    json
}

/// The error code in a refusal's body, as the origin framed it in `head` and
/// sent it in `raw`. `None` when the body is not all there, is not JSON, or
/// names no code.
pub(crate) async fn error_code(head: &str, raw: &[u8]) -> Option<String> {
    let framing = crate::http_body::determine_response_framing(head);
    let mut reader = raw;
    let mut body = crate::http_body::ResponseBody::new(framing);
    let mut decoded = Vec::new();
    while let Some(part) = body.next(&mut reader).await.ok()? {
        decoded.extend_from_slice(&part);
    }
    code_in(&decoded)
}

/// The error code in a decoded JSON error body.
fn code_in(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let error = value.get("error")?;
    let code = match error.get("code").and_then(serde_json::Value::as_str) {
        Some(code) => code,
        None if value.get("type").and_then(serde_json::Value::as_str) == Some("error") => {
            error.get("type")?.as_str()?
        }
        None => return None,
    };
    let readable = !code.is_empty()
        && code.len() <= MAX_ERROR_CODE_LEN
        && code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    readable.then(|| code.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const JSON_402: &str =
        "HTTP/1.1 402 Payment Required\r\nContent-Type: application/json\r\n\r\n";

    #[test]
    fn only_a_4xx_json_answer_is_read() {
        assert!(may_carry_error_code(402, JSON_402));
        assert!(may_carry_error_code(
            429,
            "HTTP/1.1 429 X\r\ncontent-type: Application/Problem+JSON; charset=utf-8\r\n\r\n"
        ));
        assert!(!may_carry_error_code(500, JSON_402));
        assert!(!may_carry_error_code(200, JSON_402));
        assert!(!may_carry_error_code(
            402,
            "HTTP/1.1 402 X\r\nContent-Type: text/html\r\n\r\n"
        ));
        assert!(!may_carry_error_code(402, "HTTP/1.1 402 X\r\n\r\n"));
    }

    #[test]
    fn a_compressed_body_is_not_read() {
        assert!(!may_carry_error_code(
            402,
            "HTTP/1.1 402 X\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\n\r\n"
        ));
        assert!(may_carry_error_code(
            402,
            "HTTP/1.1 402 X\r\nContent-Type: application/json\r\nContent-Encoding: identity\r\n\r\n"
        ));
    }

    #[test]
    fn the_code_comes_from_either_envelope() {
        assert_eq!(
            code_in(br#"{"error":{"code":"insufficient_credit","message":"m"}}"#).as_deref(),
            Some("insufficient_credit")
        );
        assert_eq!(
            code_in(br#"{"type":"error","error":{"type":"billing_error","message":"m"}}"#)
                .as_deref(),
            Some("billing_error")
        );
        // An OpenAI error's `type` is a category, not the code.
        assert_eq!(
            code_in(br#"{"error":{"type":"invalid_request_error","message":"m"}}"#),
            None
        );
    }

    #[test]
    fn a_value_that_is_no_identifier_is_left_out() {
        assert_eq!(code_in(br#"{"error":{"code":"two words"}}"#), None);
        assert_eq!(code_in(br#"{"error":{"code":""}}"#), None);
        assert_eq!(code_in(br#"{"error":{"code":42}}"#), None);
        let long = format!(r#"{{"error":{{"code":"{}"}}}}"#, "a".repeat(65));
        assert_eq!(code_in(long.as_bytes()), None);
        assert_eq!(code_in(b"not json"), None);
    }

    #[tokio::test]
    async fn a_body_cut_short_has_no_code() {
        let head =
            "HTTP/1.1 402 X\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n";
        assert_eq!(error_code(head, br#"{"error":{"code":"x"}}"#).await, None);
    }

    #[test]
    fn a_record_is_sent_once_with_its_answer() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let pending = PendingAudit::new(tx, serde_json::json!({"metadata": {}}));
        pending.resent_after_renewal();
        pending.answered(402, Some("insufficient_credit".into()));
        pending.answered(200, None);
        drop(pending);
        let event: serde_json::Value = serde_json::from_str(&rx.try_recv().unwrap()).unwrap();
        assert_eq!(event["upstream_status_code"], 402);
        assert_eq!(event["upstream_error_code"], "insufficient_credit");
        assert_eq!(event["metadata"]["resent_after_renewal"], true);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn a_record_with_no_answer_is_sent_when_dropped() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        drop(PendingAudit::new(
            tx,
            serde_json::json!({"result": "success"}),
        ));
        let event: serde_json::Value = serde_json::from_str(&rx.try_recv().unwrap()).unwrap();
        assert_eq!(event["result"], "success");
        assert!(event.get("upstream_status_code").is_none());
    }
}
