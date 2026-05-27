//! Integration tests for `transparent::classify` + `peek_first_bytes` over
//! real TCP sockets. These verify the plumbing in isolation — the full
//! MITM / routing pipeline is covered by the E2E suite.
//!
//! Runs on any platform (doesn't need nftables) but is gated behind
//! `#[ignore]` so a default `cargo test` stays quick; CI opts in with
//! `cargo test -- --ignored`.

use std::time::Duration;

use lens_sandbox_core::transparent::{self, Protocol};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

async fn with_connected_pair<F, Fut>(client_bytes: &'static [u8], check: F)
where
    F: FnOnce(TcpStream) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client_task = tokio::spawn(async move {
        let mut sock = TcpStream::connect(addr).await.unwrap();
        sock.write_all(client_bytes).await.unwrap();
        // Keep the socket alive for the duration of the peek.
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let (server_stream, _) = listener.accept().await.unwrap();
    check(server_stream).await;
    let _ = client_task.await;
}

#[tokio::test]
#[ignore]
async fn peek_and_classify_tls_client_hello() {
    // Fabricated ClientHello prefix — the classifier only needs the record
    // header bytes (0x16 0x03 0x03 + length), but we send a plausible
    // ClientHello body so the socket looks realistic.
    let bytes: &[u8] = &[
        0x16, 0x03, 0x03, 0x00, 0x31, // record header: handshake, TLS 1.2, len 0x31
        0x01, 0x00, 0x00, 0x2d, // ClientHello, length 0x2d
        0x03, 0x03, // version TLS 1.2
    ];
    with_connected_pair(bytes, |stream| async move {
        let peeked = transparent::peek_first_bytes(&stream, 6).await.unwrap();
        assert!(
            peeked.len() >= 3,
            "should peek at least 3 bytes: {peeked:?}"
        );
        assert_eq!(transparent::classify(&peeked), Protocol::Tls);
    })
    .await;
}

#[tokio::test]
#[ignore]
async fn peek_and_classify_http_get() {
    with_connected_pair(
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        |stream| async move {
            let peeked = transparent::peek_first_bytes(&stream, 6).await.unwrap();
            assert_eq!(transparent::classify(&peeked), Protocol::Http);
        },
    )
    .await;
}

#[tokio::test]
#[ignore]
async fn peek_and_classify_raw_bytes_unknown() {
    // Raw bytes with no HTTP or TLS signature — classifier drops.
    with_connected_pair(b"hello transparent\n", |stream| async move {
        let peeked = transparent::peek_first_bytes(&stream, 6).await.unwrap();
        assert_eq!(transparent::classify(&peeked), Protocol::Unknown);
    })
    .await;
}

#[tokio::test]
#[ignore]
async fn partial_send_then_stall_does_not_spin() {
    // Regression guard for a previously-found tight loop: a peer that
    // sends fewer than `n` bytes and then stalls must NOT cause
    // `peek_first_bytes` to spin the CPU until the deadline. The peek
    // helper now backs off between partial-read retries, so the call
    // should return at the deadline having used effectively no CPU.
    //
    // We assert the return happens inside the 500 ms deadline window and
    // the caller gets whatever bytes were sent before the stall.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client_task = tokio::spawn(async move {
        let mut sock = TcpStream::connect(addr).await.unwrap();
        // 3 bytes — fewer than the `n = 6` the peek requests — then stall
        // for well past the peek deadline.
        sock.write_all(&[0x16, 0x03, 0x03]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1500)).await;
    });

    let (server_stream, _) = listener.accept().await.unwrap();
    let started = std::time::Instant::now();
    let peeked = transparent::peek_first_bytes(&server_stream, 6)
        .await
        .unwrap();
    let elapsed = started.elapsed();

    // Deadline is 500ms — allow a modest fudge for scheduler latency.
    assert!(
        elapsed < Duration::from_millis(900),
        "peek_first_bytes took {elapsed:?}, suggests a tight loop or deadline bug"
    );
    // Whatever we got back should be the bytes the peer actually sent.
    assert_eq!(peeked.as_slice(), &[0x16, 0x03, 0x03]);

    let _ = client_task.await;
}

#[tokio::test]
#[ignore]
async fn peek_does_not_consume() {
    // Peek once, then read from the stream — the bytes are still there.
    use tokio::io::AsyncReadExt;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client_task = tokio::spawn(async move {
        let mut sock = TcpStream::connect(addr).await.unwrap();
        sock.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        // Hold the connection briefly so the server can both peek and read.
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let (mut server_stream, _) = listener.accept().await.unwrap();
    let peeked = transparent::peek_first_bytes(&server_stream, 6)
        .await
        .unwrap();
    assert_eq!(&peeked, b"GET / ");

    let mut after = vec![0u8; 4];
    server_stream.read_exact(&mut after).await.unwrap();
    assert_eq!(&after, b"GET ", "peek must not consume");

    let _ = client_task.await;
}
