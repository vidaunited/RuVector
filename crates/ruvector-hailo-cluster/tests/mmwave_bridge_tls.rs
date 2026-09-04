//! End-to-end TLS test for `ruvector-mmwave-bridge --tls-ca` (iter 121).
//!
//! Iter 120 added the `--tls-ca` / `--tls-domain` / `--tls-client-cert`
//! / `--tls-client-key` flags to the bridge; this test proves the
//! flag wiring composes correctly with a real TLS server — bridge
//! posts decoded events to a TLS-enabled fakeworker, full handshake
//! end-to-end. Gated on `feature = "tls"`.
//!
//! Iter 121 also added env-driven TLS support to the fakeworker (matching
//! the iter-99 pattern in worker.rs). This test exercises that.

#![cfg(feature = "tls")]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rcgen::{generate_simple_self_signed, CertifiedKey};

mod common;
use common::{free_port, FAKEWORKER};

const BRIDGE: &str = env!("CARGO_BIN_EXE_ruvector-mmwave-bridge");

/// Stage cert + key PEMs to a unique temp dir so parallel test cases
/// don't fight over the same files. Returns (dir, cert_path, key_path).
///
/// The suffix is a process-wide counter. It used to be
/// `Instant::now().elapsed().as_nanos()`, which is the gap between two
/// adjacent calls (tens of nanoseconds) and so repeats across tests in
/// the same process: `bridge_partial_mtls_config_refused` and
/// `bridge_posts_via_tls_to_tls_fakeworker` both got
/// `ruvector-bridge-tls-<pid>-70`, the first test's `remove_dir_all`
/// deleted the second test's certs, and the fakeworker died with
/// "stat server cert pem ...: No such file or directory" (PR #4 CI,
/// 2026-09-04; the same shape as the PR #1 failure that added the
/// stderr capture).
fn stage_self_signed_cert() -> (PathBuf, PathBuf, PathBuf) {
    static STAGED: AtomicUsize = AtomicUsize::new(0);

    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
            .expect("rcgen self-signed");
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let dir = std::env::temp_dir().join(format!(
        "ruvector-bridge-tls-{}-{}",
        std::process::id(),
        STAGED.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("server.pem");
    let key_path = dir.join("server.key");
    std::fs::File::create(&cert_path)
        .unwrap()
        .write_all(cert_pem.as_bytes())
        .unwrap();
    std::fs::File::create(&key_path)
        .unwrap()
        .write_all(key_pem.as_bytes())
        .unwrap();
    (dir, cert_path, key_path)
}

/// Spawn a fakeworker with TLS env vars set so it accepts only TLS
/// connections. Polls the TCP port (TLS handshake fails on plaintext,
/// but the listening socket itself is reachable).
fn spawn_tls_fakeworker(
    port: u16,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    fingerprint: &str,
) -> std::process::Child {
    let bind = format!("127.0.0.1:{}", port);
    let mut cmd = Command::new(FAKEWORKER);
    cmd.env("RUVECTOR_FAKE_BIND", &bind)
        .env("RUVECTOR_FAKE_DIM", "4")
        .env("RUVECTOR_TLS_CERT", cert_path)
        .env("RUVECTOR_TLS_KEY", key_path)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        // Piped, not null: when the worker dies before it binds, the only
        // diagnostic is the `Error: ...` line its `main` prints, and a
        // panic that quotes the exit status alone cannot say whether the
        // PEM was rejected, the port was taken, or the TLS acceptor failed.
        .stderr(Stdio::piped());
    if !fingerprint.is_empty() {
        cmd.env("RUVECTOR_FAKE_FINGERPRINT", fingerprint);
    }
    let mut child = cmd.spawn().expect("spawn tls fakeworker");
    // Drain stderr on a helper thread so a chatty worker can never block
    // on a full pipe; the buffer is only read back on the failure paths.
    let stderr_buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    if let Some(mut pipe) = child.stderr.take() {
        let buf = std::sync::Arc::clone(&stderr_buf);
        std::thread::spawn(move || {
            let mut out = Vec::new();
            let _ = std::io::Read::read_to_end(&mut pipe, &mut out);
            if let Ok(mut b) = buf.lock() {
                *b = out;
            }
        });
    }
    let worker_stderr = move || -> String {
        // Give the drain thread a moment to observe EOF after the exit.
        std::thread::sleep(Duration::from_millis(100));
        stderr_buf
            .lock()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default()
    };
    // Poll TCP connect; TLS handshake will fail without a client cert
    // but the socket itself is bound.
    let bind_addr: std::net::SocketAddr = bind.parse().unwrap();
    let start = Instant::now();
    // 10 s rather than 2 s: before it can bind, the fakeworker has to parse
    // the PEMs and build its TLS acceptor, and a loaded CI runner has lost
    // that race (the two plaintext siblings in common.rs never do this
    // work). Polling still returns as soon as the socket accepts, so the
    // happy path costs nothing extra; a worker that dies is reported with
    // its exit status instead of waiting out the budget.
    while start.elapsed() < Duration::from_secs(10) {
        if std::net::TcpStream::connect_timeout(&bind_addr, Duration::from_millis(50)).is_ok() {
            return child;
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!(
                "tls fakeworker on {} exited before accepting connections: {}\n--- fakeworker stderr ---\n{}",
                bind,
                status,
                worker_stderr()
            );
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!(
        "tls fakeworker on {} never accepted connections\n--- fakeworker stderr ---\n{}",
        bind,
        worker_stderr()
    );
}

#[test]
fn bridge_posts_via_tls_to_tls_fakeworker() {
    let port = free_port();
    let (tmpdir, cert_path, key_path) = stage_self_signed_cert();
    let mut worker = spawn_tls_fakeworker(port, &cert_path, &key_path, "fp:tls-bridge");

    // The same self-signed cert is its own CA — bridge trusts it via
    // --tls-ca. SNI must match a SAN on the cert (we issued for both
    // localhost and 127.0.0.1).
    let mut child = Command::new(BRIDGE)
        .args([
            "--simulator",
            "--rate",
            "10",
            "--workers",
            &format!("localhost:{}", port),
            "--dim",
            "4",
            "--fingerprint",
            "fp:tls-bridge",
            "--tls-ca",
            cert_path.to_str().unwrap(),
            "--tls-domain",
            "localhost",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bridge with --tls-ca");

    std::thread::sleep(Duration::from_millis(1200));
    let _ = child.kill();
    let out = child.wait_with_output().expect("wait bridge");
    let _ = worker.kill();
    let _ = worker.wait();
    let _ = std::fs::remove_dir_all(&tmpdir);

    let stderr = String::from_utf8_lossy(&out.stderr);
    let post_count = stderr.matches("posted text=").count();
    assert!(
        post_count >= 3,
        "expected ≥ 3 successful TLS posts, saw {}: stderr={}",
        post_count,
        stderr
    );
    assert!(
        !stderr.contains("cluster post failed"),
        "no posts should have failed under TLS: {}",
        stderr
    );
}

#[test]
fn bridge_partial_mtls_config_refused() {
    // --tls-client-cert without --tls-client-key (or vice versa) must
    // refuse before any RPC is attempted (ADR-172 §1b parity gate).
    let (tmpdir, cert_path, _) = stage_self_signed_cert();
    let out = Command::new(BRIDGE)
        .args([
            "--simulator",
            "--workers",
            "127.0.0.1:1",
            "--dim",
            "4",
            "--fingerprint",
            "fp:x",
            "--tls-ca",
            cert_path.to_str().unwrap(),
            "--tls-client-cert",
            cert_path.to_str().unwrap(), // intentionally without --tls-client-key
        ])
        .output()
        .expect("run bridge");

    let _ = std::fs::remove_dir_all(&tmpdir);

    assert!(!out.status.success(), "expected non-zero exit");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ADR-172 §1b") || stderr.contains("must both be set"),
        "stderr should reference the §1b mTLS gate, got: {}",
        stderr
    );
}

#[test]
fn bridge_tls_flags_without_ca_refused() {
    // Any --tls-* flag must fail without --tls-ca (the rest of the
    // TLS settings are meaningless without a CA bundle).
    let out = Command::new(BRIDGE)
        .args([
            "--simulator",
            "--workers",
            "127.0.0.1:1",
            "--dim",
            "4",
            "--fingerprint",
            "fp:x",
            "--tls-domain",
            "example.com",
            // intentionally no --tls-ca
        ])
        .output()
        .expect("run bridge");

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--tls-ca") || stderr.contains("required when any --tls-* flag"),
        "stderr should require --tls-ca: {}",
        stderr
    );
}
