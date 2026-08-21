//! Pluggable byte-transport seam for the WebSocket client.
//!
//! `tokio_tungstenite::client_async{_tls}_with_config` accepts any
//! `AsyncRead + AsyncWrite` stream — it doesn't care whether the
//! bytes underneath travel over TCP, vsock, a Unix socket, or an
//! in-memory pipe. This module makes that flexibility explicit by
//! splitting "open the byte stream" (the [`Connector`] trait) from
//! "run the WebSocket handshake on it" (in [`super::client`]).
//!
//! Two transports ship today:
//!
//!   - `ws://` / `wss://` → [`TcpConnector`]: DNS resolve + SO_MARK'd
//!     TCP socket. Identical wire behaviour to the previous
//!     `sock_mark::connect_tcp_resolve` call inside `connect_and_run`.
//!   - `vsock://CID:PORT` (Linux) → [`VsockConnector`]: dial AF_VSOCK
//!     directly. Used by Lens Sandbox to talk between the host's
//!     `lns-service` and the in-guest supervisor without going
//!     through the guest NIC. The named CIDs `host` (2), `local` (1),
//!     and `any` (`u32::MAX`) are accepted in place of a numeric
//!     value.
//!
//! [`for_scheme`] is the dispatch entry point: callers hand it a URL
//! scheme and get back the matching connector, or `None` if the
//! scheme isn't recognised (which `connect_and_run` translates into
//! a clean `Rejected` result rather than a tungstenite parse error).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::http::Uri;

use crate::sock_mark;

/// Duplex byte stream a [`Connector`] hands back. Concrete enum
/// rather than a `Box<dyn AsyncRead + AsyncWrite>` so the WebSocket
/// handshake's trait bounds (`Send + Unpin + 'static`) line up
/// without dance, and so callers can pattern-match on transport
/// where it matters (TLS on TCP only; never on vsock).
pub enum Stream {
    Tcp(TcpStream),
    #[cfg(target_os = "linux")]
    Vsock(tokio_vsock::VsockStream),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(target_os = "linux")]
            Stream::Vsock(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(target_os = "linux")]
            Stream::Vsock(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(s) => Pin::new(s).poll_flush(cx),
            #[cfg(target_os = "linux")]
            Stream::Vsock(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(target_os = "linux")]
            Stream::Vsock(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Open a byte-transport connection to the URI's authority. The
/// caller then runs the WebSocket handshake on top of the returned
/// stream.
#[async_trait]
pub trait Connector: Send + Sync {
    async fn connect(&self, uri: &Uri) -> io::Result<Stream>;
}

/// Default connector: DNS resolve + SO_MARK'd TCP socket. Mirrors
/// the pre-seam behaviour of `connect_and_run` exactly.
pub struct TcpConnector;

#[async_trait]
impl Connector for TcpConnector {
    async fn connect(&self, uri: &Uri) -> io::Result<Stream> {
        let host = uri
            .host()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "URL missing host"))?;
        // Default-port selection is case-insensitive on the scheme so
        // `WSS://...` picks 443 too. Matches the case-insensitivity in
        // [`for_scheme`].
        let scheme = uri.scheme_str().unwrap_or("").to_ascii_lowercase();
        let port = uri.port_u16().unwrap_or(match scheme.as_str() {
            "wss" | "https" => 443,
            _ => 80,
        });
        let tcp = sock_mark::connect_tcp_resolve(host, port).await?;
        Ok(Stream::Tcp(tcp))
    }
}

/// `vsock://CID:PORT/...` connector. CID is a numeric u32 or one of
/// the named aliases `host` (2), `local` (1), `any` (u32::MAX).
#[cfg(target_os = "linux")]
pub struct VsockConnector;

#[cfg(target_os = "linux")]
#[async_trait]
impl Connector for VsockConnector {
    async fn connect(&self, uri: &Uri) -> io::Result<Stream> {
        let (cid, port) = parse_vsock_authority(uri)?;
        let stream =
            tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(cid, port)).await?;
        Ok(Stream::Vsock(stream))
    }
}

/// Pick the connector matching the URL scheme. `None` means "this
/// crate doesn't know how to open `<scheme>://...`" — `connect_and_run`
/// surfaces that as a clean rejection.
///
/// Comparison is ASCII-case-insensitive: RFC 3986 §3.1 makes scheme
/// case-insensitive, so `VSOCK://...` and `WS://...` resolve to the
/// same connectors as their lowercase forms. Mirrors the case-handling
/// in [`crate::config::bootstrap_dns_hosts`].
pub fn for_scheme(scheme: &str) -> Option<Box<dyn Connector>> {
    match scheme.to_ascii_lowercase().as_str() {
        "ws" | "wss" => Some(Box::new(TcpConnector)),
        #[cfg(target_os = "linux")]
        "vsock" => Some(Box::new(VsockConnector)),
        _ => None,
    }
}

/// Parse the authority of a `vsock://CID:PORT/...` URI into a
/// `(cid, port)` pair. Exposed at module scope so the unit tests can
/// pin the named-CID aliases and the malformed-input error paths
/// without standing up a vsock socket.
///
/// `http::Uri` exposes ports as `u16` (RFC 3986 §3.2.3 reserves the
/// IP transport range), but AF_VSOCK ports are `u32` — and
/// `VsockAddr::new` accepts a `u32`. `vsock://2:70000/v1/sandbox`
/// parses fine in the URI but `Authority::port()` and `port_u16()`
/// both return `None`. So we re-split the authority string ourselves
/// to preserve the full 32-bit range. `rsplit_once(':')` is safe
/// here because vsock authorities never have IPv6-style `[...]:port`
/// brackets — CIDs are bare integers or named aliases.
#[cfg(target_os = "linux")]
pub(crate) fn parse_vsock_authority(uri: &Uri) -> io::Result<(u32, u32)> {
    let authority = uri.authority().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "vsock URL missing CID:PORT authority",
        )
    })?;
    let (host_str, port_str) = authority.as_str().rsplit_once(':').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "vsock URL missing port in authority",
        )
    })?;
    let port: u32 = port_str.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("vsock port must be a u32, got {port_str:?}"),
        )
    })?;
    let cid: u32 = match host_str {
        "host" => 2,
        "local" => 1,
        "any" => u32::MAX,
        n => n.parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("vsock CID must be a number or one of host/local/any, got {n}"),
            )
        })?,
    };
    Ok((cid, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn for_scheme_returns_tcp_connector_for_ws() {
        assert!(for_scheme("ws").is_some());
        assert!(for_scheme("wss").is_some());
    }

    #[test]
    fn for_scheme_returns_none_for_unknown_scheme() {
        assert!(for_scheme("http").is_none());
        assert!(for_scheme("ftp").is_none());
        assert!(for_scheme("").is_none());
    }

    #[test]
    fn for_scheme_is_case_insensitive() {
        // RFC 3986 §3.1: URI schemes are case-insensitive. Mirrors the
        // case-handling in `config::bootstrap_dns_hosts` so the two
        // entry points agree on what `VSOCK://...` means.
        assert!(for_scheme("WS").is_some());
        assert!(for_scheme("WSS").is_some());
        assert!(for_scheme("Wss").is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn for_scheme_is_case_insensitive_for_vsock_on_linux() {
        for variant in ["VSOCK", "Vsock", "vSoCk"] {
            assert!(
                for_scheme(variant).is_some(),
                "expected {variant} to dispatch to VsockConnector",
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn for_scheme_returns_vsock_connector_on_linux() {
        assert!(for_scheme("vsock").is_some());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn for_scheme_rejects_vsock_off_linux() {
        // On non-Linux hosts the vsock branch is compiled out, so the
        // scheme is unrecognised and the caller emits Rejected — matches
        // the "AF_VSOCK is Linux-only" message in lns-vsock-bridge.
        assert!(for_scheme("vsock").is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_vsock_authority_accepts_numeric_cid() {
        let uri = Uri::from_str("vsock://2:1024/v1/sandbox").unwrap();
        assert_eq!(parse_vsock_authority(&uri).unwrap(), (2, 1024));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_vsock_authority_accepts_named_cids() {
        for (alias, expected) in [("host", 2u32), ("local", 1), ("any", u32::MAX)] {
            let uri = Uri::from_str(&format!("vsock://{alias}:1024/v1/sandbox")).unwrap();
            assert_eq!(parse_vsock_authority(&uri).unwrap(), (expected, 1024));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_vsock_authority_rejects_unknown_name() {
        let uri = Uri::from_str("vsock://nope:1024/v1/sandbox").unwrap();
        let err = parse_vsock_authority(&uri).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("nope"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_vsock_authority_requires_port() {
        // `Uri::from_str("vsock://2/")` parses but yields port=None;
        // we surface that as InvalidInput rather than silently defaulting.
        let uri = Uri::from_str("vsock://2/v1/sandbox").unwrap();
        let err = parse_vsock_authority(&uri).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("port"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_vsock_authority_accepts_port_above_u16_range() {
        // AF_VSOCK ports are u32; relying on `Uri::port_u16()` silently
        // dropped ports > 65535. Re-splitting the authority preserves
        // the full range.
        let uri = Uri::from_str("vsock://2:70000/v1/sandbox").unwrap();
        assert_eq!(parse_vsock_authority(&uri).unwrap(), (2, 70_000));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_vsock_authority_accepts_port_u32_max() {
        let uri = Uri::from_str("vsock://2:4294967295/v1/sandbox").unwrap();
        assert_eq!(parse_vsock_authority(&uri).unwrap(), (2, u32::MAX));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_vsock_authority_rejects_port_above_u32_max() {
        // u32::MAX + 1 — overflow on parse, surfaced as InvalidInput.
        let uri = Uri::from_str("vsock://2:4294967296/v1/sandbox").unwrap();
        let err = parse_vsock_authority(&uri).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("u32"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_vsock_authority_rejects_non_numeric_port() {
        let uri = Uri::from_str("vsock://2:abc/v1/sandbox").unwrap();
        let err = parse_vsock_authority(&uri).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("port"));
    }

    #[tokio::test]
    async fn tcp_connector_dials_local_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let uri = Uri::from_str(&format!("ws://{addr}/v1/sandbox")).unwrap();
        let accept = tokio::spawn(async move { listener.accept().await });

        let stream = TcpConnector.connect(&uri).await.unwrap();
        assert!(matches!(stream, Stream::Tcp(_)));
        accept.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn tcp_connector_rejects_missing_host() {
        // A path-only URI parses but yields `uri.host() == None`, so the
        // connector surfaces InvalidInput instead of trying to dial an
        // empty authority. (`http::Uri` itself rejects `ws:///path` as a
        // malformed URI, so that variant can't even reach the connector.)
        let uri = Uri::from_static("/v1/sandbox");
        let Err(err) = TcpConnector.connect(&uri).await else {
            panic!("expected InvalidInput");
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
