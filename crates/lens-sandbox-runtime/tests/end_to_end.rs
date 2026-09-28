//! The real supervisor against the runtime binary, over mutual TLS on a Unix
//! socket.
//!
//! The runtime binds its resolver on `127.0.0.53:53`, so the test needs root
//! and a network namespace where nothing else holds that address. CI runs it
//! with `unshare -n`.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::net::IpAddr;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use lens_sandbox_core::proxy::{ProxyServer, ProxyState};
use lens_sandbox_supervisor::{ChannelPki, ExecSession, RuntimeAddress, Supervisor};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PROXY_CA: &str = "-----BEGIN CERTIFICATE-----\nproxy\n-----END CERTIFICATE-----";

struct Runtime(Child);

impl Drop for Runtime {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Sandbox {
    supervisor: Supervisor,
    ca_bundle: std::path::PathBuf,
    _runtime: Runtime,
    _dir: tempfile::TempDir,
}

fn state() -> Arc<ProxyState> {
    let any = "127.0.0.1:0".parse().unwrap();
    ProxyServer::new(any, any, any, None, Vec::new()).1
}

async fn sandbox() -> Sandbox {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let pki = ChannelPki::generate(["agent"]).unwrap();
    let channel_dir = dir.path().join("channel");
    std::fs::create_dir(&channel_dir).unwrap();
    let runtime_tls = &pki.runtimes["agent"];
    std::fs::write(channel_dir.join("ca.pem"), &runtime_tls.ca).unwrap();
    std::fs::write(channel_dir.join("cert.pem"), &runtime_tls.cert).unwrap();
    std::fs::write(channel_dir.join("key.pem"), &runtime_tls.key).unwrap();

    let socket = dir.path().join("channel.sock");
    let ca_bundle = dir.path().join("trust/ca-bundle.pem");
    let runtime = Command::new(env!("CARGO_BIN_EXE_lens-sandbox-runtime"))
        .env("LENS_SANDBOX_LISTEN", format!("unix:{}", socket.display()))
        .env("LENS_SANDBOX_CHANNEL_DIR", &channel_dir)
        .env("LENS_SANDBOX_CA_BUNDLE", &ca_bundle)
        .spawn()
        .unwrap();

    let dns_upstream = "127.0.0.1:9".parse().unwrap();
    let supervisor = Supervisor::new(state(), dns_upstream);
    supervisor.trust(PROXY_CA.into());
    supervisor
        .attach("agent", RuntimeAddress::Unix(socket), &pki.supervisor)
        .unwrap();
    Sandbox {
        supervisor,
        ca_bundle,
        _runtime: Runtime(runtime),
        _dir: dir,
    }
}

async fn exec(sandbox: &Sandbox, script: &str) -> String {
    let mut session = open_exec(&sandbox.supervisor).await;
    let attach = serde_json::json!({
        "type": "exec_attach",
        "execId": "e1",
        "argv": ["/bin/bash", "-c", script],
        "env": {"PATH": "/usr/bin:/bin"},
    });
    assert!(session.send(attach.to_string()).await);
    let mut output = Vec::new();
    while let Some(frame) = session.recv().await {
        let frame: serde_json::Value = serde_json::from_str(&frame).unwrap();
        match frame["type"].as_str() {
            Some("exec_stdout" | "exec_stderr") => output.extend(
                base64::engine::general_purpose::STANDARD
                    .decode(frame["data"].as_str().unwrap())
                    .unwrap(),
            ),
            Some("exec_exit" | "exec_error") => break,
            _ => {}
        }
    }
    String::from_utf8(output).unwrap()
}

/// Polls until the supervisor has connected to the runtime.
async fn open_exec(supervisor: &Supervisor) -> ExecSession {
    for _ in 0..100 {
        if let Ok(session) = supervisor.open_exec("agent").await {
            return session;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the supervisor did not connect to the runtime");
}

/// An address of this host that is not loopback: the supervisor refuses a
/// connect to it.
fn own_address() -> IpAddr {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect("192.0.2.1:9").unwrap();
    socket.local_addr().unwrap().ip()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs root and a free 127.0.0.53:53; CI runs it in its own network namespace"]
async fn a_workload_runs_under_the_supervisor() {
    let sandbox = sandbox().await;

    let bundle = exec(&sandbox, "cat \"$SSL_CERT_FILE\"").await;
    assert!(bundle.ends_with(&format!("{PROXY_CA}\n")), "{bundle}");
    assert_eq!(std::fs::read_to_string(&sandbox.ca_bundle).unwrap(), bundle);

    let refused = exec(&sandbox, &format!("exec 3<>/dev/tcp/{}/80", own_address())).await;
    assert!(refused.contains("Permission denied"), "{refused}");

    let status = exec(
        &sandbox,
        "grep -E '^(CapEff|NoNewPrivs):' /proc/self/status",
    )
    .await;
    let fields: HashMap<_, _> = status
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key, value.trim()))
        .collect();
    assert_eq!(fields["NoNewPrivs"], "1", "{status}");
    let effective = u64::from_str_radix(fields["CapEff"], 16).unwrap();
    // CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, SETGID, SETUID.
    assert_eq!(effective & !0xfb, 0, "{status}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs root and a free 127.0.0.53:53; CI runs it in its own network namespace"]
async fn a_forward_reaches_a_workload_port() {
    let sandbox = sandbox().await;
    open_exec(&sandbox.supervisor).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut ping = [0_u8; 4];
        stream.read_exact(&mut ping).await.unwrap();
        stream.write_all(&ping).await.unwrap();
    });
    let mut forward = sandbox
        .supervisor
        .open_forward("agent", port)
        .await
        .unwrap();
    forward.write_all(b"ping").await.unwrap();
    let mut echoed = [0_u8; 4];
    forward.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");
}
