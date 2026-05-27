//! Transparent-redirect plumbing: classify the first bytes of a connection,
//! recover the original pre-redirect destination via `SO_ORIGINAL_DST`, and
//! peek without consuming so the real handler can take over.
//!
//! The nftables REDIRECT statement rewrites the packet's destination to the
//! transparent listener (`127.0.0.1:3129`) before the socket is opened, so
//! `getpeername()` on the server side sees only the local loopback. The
//! pre-redirect destination (IP + port the sandbox process actually dialed)
//! is preserved in a per-connection kernel conntrack entry and exposed via
//! the `SO_ORIGINAL_DST` socket option on Linux.

use std::net::SocketAddr;

use tokio::net::TcpStream;

/// Protocol identified from the first bytes of a TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tls,
    Http,
    Unknown,
}

/// Classify the first bytes of a connection as TLS, HTTP/1.x, or Unknown.
///
/// TLS: a ClientHello record starts with `0x16` (handshake), `0x03`
/// (SSL 3 / TLS major), and a minor version in `0x00..=0x04` (SSL 3.0
/// through TLS 1.3).
///
/// HTTP: the first token is one of the RFC 7231 / RFC 7540 methods
/// followed by a space. Only the common methods are matched — anything
/// else is Unknown and gets dropped. HTTP/2 prior-knowledge (`PRI * HTTP/2.0`)
/// is deliberately NOT accepted here; in practice no agent tooling uses it.
pub fn classify(bytes: &[u8]) -> Protocol {
    if bytes.len() >= 3 && bytes[0] == 0x16 && bytes[1] == 0x03 && matches!(bytes[2], 0x00..=0x04) {
        return Protocol::Tls;
    }

    // HTTP method prefixes, longest first so shorter prefixes don't eat them.
    const METHODS: &[&[u8]] = &[
        b"OPTIONS ",
        b"CONNECT ",
        b"DELETE ",
        b"PATCH ",
        b"TRACE ",
        b"POST ",
        b"HEAD ",
        b"GET ",
        b"PUT ",
    ];
    for method in METHODS {
        if bytes.len() >= method.len() && &bytes[..method.len()] == *method {
            return Protocol::Http;
        }
    }

    Protocol::Unknown
}

/// Peek up to `n` bytes from the stream without consuming them.
///
/// `peek` with `MSG_PEEK` returns immediately as long as the kernel buffer
/// has any data, so a peer that sends e.g. 3 bytes and then stalls would
/// send us into a tight loop if we just retried — the same bytes come
/// back every call. We back off with a short sleep between partial-read
/// retries so a stalling client can't burn CPU; the 500ms deadline still
/// bounds the total wait.
///
/// On timeout we return whatever was peeked; the classifier deals with
/// short reads by returning `Protocol::Unknown`.
pub async fn peek_first_bytes(stream: &TcpStream, n: usize) -> std::io::Result<Vec<u8>> {
    use tokio::time::{Duration, Instant, sleep_until, timeout_at};

    let mut buf = vec![0u8; n];
    let deadline = Instant::now() + Duration::from_millis(500);
    // Backoff between partial-read retries. Short enough that a real
    // client that just TCP-segmented its ClientHello lands on the next
    // tick; long enough that a stalling peer doesn't dominate the CPU.
    let backoff = Duration::from_millis(10);
    let mut last_len = 0usize;

    loop {
        match timeout_at(deadline, stream.peek(&mut buf)).await {
            Ok(Ok(0)) => return Ok(Vec::new()),
            Ok(Ok(got)) if got >= n => return Ok(buf),
            Ok(Ok(got)) => {
                last_len = got;
                // Short peek — sleep briefly, then retry. If the deadline
                // fires first, return what we have.
                let wake = Instant::now() + backoff;
                if wake >= deadline {
                    buf.truncate(last_len);
                    return Ok(buf);
                }
                sleep_until(wake).await;
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                buf.truncate(last_len);
                return Ok(buf);
            }
        }
    }
}

/// Recover the pre-redirect destination for a connection handled by a
/// Linux nftables REDIRECT rule. Works for both IPv4 and IPv6 sockets.
#[cfg(target_os = "linux")]
pub fn so_original_dst(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::fd::AsFd;

    use nix::sys::socket::sockopt;

    let local = stream.local_addr()?;
    let fd = stream.as_fd();

    match local {
        SocketAddr::V4(_) => {
            let sa = nix::sys::socket::getsockopt(&fd, sockopt::OriginalDst)
                .map_err(std::io::Error::from)?;
            let ip = Ipv4Addr::from(sa.sin_addr.s_addr.to_ne_bytes());
            let port = u16::from_be(sa.sin_port);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        SocketAddr::V6(_) => {
            let sa = nix::sys::socket::getsockopt(&fd, sockopt::Ip6tOriginalDst)
                .map_err(std::io::Error::from)?;
            let ip = Ipv6Addr::from(sa.sin6_addr.s6_addr);
            let port = u16::from_be(sa.sin6_port);
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
    }
}

/// Non-Linux stub so the rest of the crate compiles on macOS developer
/// machines. Transparent redirect needs Linux nftables; on other platforms
/// the listener can run, but any connection reaching it returns this error.
#[cfg(not(target_os = "linux"))]
pub fn so_original_dst(_stream: &TcpStream) -> std::io::Result<SocketAddr> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "SO_ORIGINAL_DST requires Linux",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_tls_1_0() {
        // TLS 1.0: handshake 0x16, major 0x03, minor 0x01
        assert_eq!(classify(&[0x16, 0x03, 0x01, 0x00, 0x01]), Protocol::Tls);
    }

    #[test]
    fn classify_tls_1_2() {
        assert_eq!(classify(&[0x16, 0x03, 0x03, 0x00, 0x9b]), Protocol::Tls);
    }

    #[test]
    fn classify_tls_1_3() {
        assert_eq!(classify(&[0x16, 0x03, 0x04, 0x01, 0x00]), Protocol::Tls);
    }

    #[test]
    fn classify_tls_ssl3() {
        // SSL 3.0 — still TLS record-layer byte-compatible with our detector
        assert_eq!(classify(&[0x16, 0x03, 0x00, 0x00, 0x01]), Protocol::Tls);
    }

    #[test]
    fn classify_tls_too_short() {
        // Need at least 3 bytes to be confident
        assert_eq!(classify(&[0x16, 0x03]), Protocol::Unknown);
        assert_eq!(classify(&[0x16]), Protocol::Unknown);
        assert_eq!(classify(&[]), Protocol::Unknown);
    }

    #[test]
    fn classify_tls_bad_version() {
        // Minor version outside the SSL3/TLS1.x range
        assert_eq!(classify(&[0x16, 0x03, 0x99, 0x00]), Protocol::Unknown);
        // Not a handshake record
        assert_eq!(classify(&[0x17, 0x03, 0x03, 0x00]), Protocol::Unknown);
    }

    #[test]
    fn classify_http_get() {
        assert_eq!(classify(b"GET / HTTP/1.1\r\n"), Protocol::Http);
    }

    #[test]
    fn classify_http_post() {
        assert_eq!(classify(b"POST /path HTTP/1.1"), Protocol::Http);
    }

    #[test]
    fn classify_http_put() {
        assert_eq!(classify(b"PUT /x HTTP/1.1"), Protocol::Http);
    }

    #[test]
    fn classify_http_head() {
        assert_eq!(classify(b"HEAD / HTTP/1.1"), Protocol::Http);
    }

    #[test]
    fn classify_http_delete() {
        assert_eq!(classify(b"DELETE /x HTTP/1.1"), Protocol::Http);
    }

    #[test]
    fn classify_http_patch() {
        assert_eq!(classify(b"PATCH /x HTTP/1.1"), Protocol::Http);
    }

    #[test]
    fn classify_http_options() {
        assert_eq!(classify(b"OPTIONS * HTTP/1.1"), Protocol::Http);
    }

    #[test]
    fn classify_http_connect() {
        assert_eq!(classify(b"CONNECT host:443 HTTP/1.1"), Protocol::Http);
    }

    #[test]
    fn classify_http_trace() {
        assert_eq!(classify(b"TRACE / HTTP/1.1"), Protocol::Http);
    }

    #[test]
    fn classify_http_requires_trailing_space() {
        // A method prefix without a space is not a valid HTTP request start.
        // `GETX/...` isn't a GET request, and `GE` is an incomplete token.
        assert_eq!(classify(b"GETX /path"), Protocol::Unknown);
        assert_eq!(classify(b"PO"), Protocol::Unknown);
    }

    #[test]
    fn classify_ssh_banner_is_unknown() {
        // A plausible non-HTTP/non-TLS protocol: the SSH server banner.
        // Even though the nftables reject in the current design blocks this
        // at the filter layer, the transparent listener sees it as Unknown
        // and drops cleanly.
        assert_eq!(classify(b"SSH-2.0-OpenSSH"), Protocol::Unknown);
    }

    #[test]
    fn classify_zero_bytes_is_unknown() {
        assert_eq!(classify(&[0x00, 0x00, 0x00, 0x00]), Protocol::Unknown);
    }

    #[test]
    fn classify_random_bytes_is_unknown() {
        assert_eq!(classify(&[0xDE, 0xAD, 0xBE, 0xEF]), Protocol::Unknown);
    }

    #[test]
    fn classify_http2_prior_knowledge_is_unknown() {
        // Per the plan, HTTP/2 prior-knowledge cleartext is treated as
        // Unknown for now. Agents don't use this in practice.
        assert_eq!(
            classify(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
            Protocol::Unknown
        );
    }
}
