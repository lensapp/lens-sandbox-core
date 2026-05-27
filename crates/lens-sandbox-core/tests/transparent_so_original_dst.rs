//! Integration test for `transparent::so_original_dst`.
//!
//! The real test requires a local nftables REDIRECT rule to synthesize the
//! pre-redirect destination, which needs `CAP_NET_ADMIN`. We gate the test
//! behind `#[ignore]` + Linux so a default `cargo test` on developer macs
//! skips it; CI runs with `cargo test -- --ignored` on Linux.
//!
//! The non-capability path (plain loopback connect without REDIRECT) is
//! still useful as a smoke test — `SO_ORIGINAL_DST` returns the
//! pre-redirect destination when REDIRECT is active, and the actual
//! destination otherwise. On a non-REDIRECTed connection it returns the
//! local listener address, which we assert.

#![cfg(target_os = "linux")]

use lens_sandbox_core::transparent;
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
#[ignore]
async fn so_original_dst_returns_local_addr_without_redirect() {
    // Without a REDIRECT rule in place, getsockopt(SO_ORIGINAL_DST)
    // returns the actual local connection address — i.e. the listener
    // we dialed. This exercises the getsockopt plumbing end-to-end.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client = tokio::spawn(async move {
        let _sock = TcpStream::connect(addr).await.unwrap();
        // Hold the connection so the server can inspect it.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    });

    let (server, _) = listener.accept().await.unwrap();
    let orig_dst = transparent::so_original_dst(&server).expect("so_original_dst");

    assert_eq!(orig_dst.port(), addr.port());
    assert!(
        orig_dst.ip().is_loopback(),
        "expected loopback, got {orig_dst}"
    );

    let _ = client.await;
}
