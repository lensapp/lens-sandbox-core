//! Optional LLM routing: send a request the sandbox addressed to one LLM API to
//! a different backend, translating the wire format on the way.
//!
//! The sandbox believes it is calling the API its policy named — the same host,
//! the same path, the same key. What actually leaves the proxy is a request in
//! the backend's format, carrying the backend's own credential, and what comes
//! back is translated into the answer the sandbox expects. Nothing in the
//! sandbox has to know.
//!
//! The pieces, in the order one request meets them:
//!
//! - [`decide`] is the composition root: it puts the pieces below in the one
//!   order they are correct in.
//! - [`table`] holds the policy: which requests are claimed, which backend
//!   serves them, and which model name it is asked for.
//! - [`anthropic_request`] and [`openai_response`] / [`openai_stream`] are the
//!   wire translations, one per direction. They are pure functions over JSON,
//!   and every one of them is tested against a recorded payload.
//! - [`head`] rewrites the request head for the backend, and [`relay`] carries
//!   the answer back.
//!
//! What this module never does is grant. A redirect changes where a request
//! goes; the backend host is judged by its own `egress.http` rule, dialled
//! through the same policy-aware egress path as any other destination, and sent
//! only the credentials the policy binds to *it*.

pub mod anthropic_request;
pub mod decide;
pub mod head;
pub mod openai_response;
pub mod openai_stream;
pub mod relay;
pub mod table;

pub use decide::decide;
pub use table::LlmRouting;

/// Largest LLM request body the proxy reads in order to translate it.
///
/// This is its own limit, well above [`crate::http_body::MAX_INSPECT_BYTES`],
/// because an LLM request carries the whole conversation: a coding agent a few
/// turns in sends hundreds of kilobytes, and the general inspection cap would
/// refuse the request it was translating. A body over this cap is still refused
/// rather than truncated — half a conversation is not the request the sandbox
/// sent.
pub const MAX_LLM_BODY_BYTES: usize = 4 * 1024 * 1024;

/// What the LLM table makes of one request.
#[derive(Debug)]
pub enum Outcome {
    /// No route claims this request. Nothing about it changes.
    Untouched,
    /// The request is claimed, translated, and bound for a backend.
    Redirect(Box<Redirect>),
    /// A route claims the request but it cannot be served. The caller denies it;
    /// the string is the sentence that goes to the client and to the audit.
    Refused(String),
}

/// Everything the MITM needs to send a claimed request to its backend and to
/// read the answer.
#[derive(Debug)]
pub struct Redirect {
    /// Backend hostname, for the dial, the SNI, and the `Host` header.
    pub host: String,
    /// Backend port.
    pub port: u16,
    /// Backend request path.
    pub path: String,
    /// The request body in the backend's format.
    pub body: Vec<u8>,
    /// Whether the sandbox asked for a streamed answer. Decides which of the two
    /// response translations reads the backend's reply.
    pub streaming: bool,
    /// The translation this route applies, so the answer comes back in the
    /// format the sandbox is waiting for.
    pub translation: crate::policy_schema::LlmTranslation,
    /// The model the backend was asked for, for the audit record.
    pub model: String,
}

impl Redirect {
    /// `host:port`, as the dial and the credential collectors want it.
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
