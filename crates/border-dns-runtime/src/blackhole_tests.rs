//! Tests for the BlackholeAcceptor.

use std::sync::Arc;

use runtime_config::BlackholeConfig;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

use super::BlackholeAcceptor;

/// Helper: create a BlackholeConfig for testing on a specific high port.
fn test_config(port: u16) -> BlackholeConfig {
    BlackholeConfig {
        enabled: true,
        listen: "127.0.0.1".into(),
        ports: vec![port],
        max_header_bytes: 4096,
    }
}

/// Test that blackhole acceptor returns 202 for a simple HTTP GET.
#[tokio::test]
async fn test_blackhole_returns_202() {
    // Use a high ephemeral port to avoid conflicts.
    let port = 19080;
    let config = test_config(port);
    let shutdown = Arc::new(tokio::sync::Notify::new());

    let acceptor = BlackholeAcceptor::new(config, Arc::clone(&shutdown));
    acceptor.start().await.expect("blackhole start failed");

    // Give the listener a moment to bind.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Connect and send an HTTP request.
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect failed");

    let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    stream.write_all(request).await.expect("write failed");

    // Read the response.
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf))
            .await
            .expect("read timeout")
            .expect("read failed");
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        // Check for complete response.
        if response.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let response_str = String::from_utf8_lossy(&response);
    assert!(
        response_str.contains("202 Accepted"),
        "expected 202 Accepted in response, got: {response_str}"
    );
    assert!(
        response_str.contains("Connection: close"),
        "expected Connection: close header"
    );

    // Shutdown.
    shutdown.notify_waiters();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
}

/// Test that blackhole acceptor handles POST requests too.
#[tokio::test]
async fn test_blackhole_post_returns_202() {
    let port = 19081;
    let config = test_config(port);
    let shutdown = Arc::new(tokio::sync::Notify::new());

    let acceptor = BlackholeAcceptor::new(config, Arc::clone(&shutdown));
    acceptor.start().await.expect("blackhole start failed");

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect failed");

    let request = b"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n";
    stream.write_all(request).await.expect("write failed");

    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf))
            .await
            .expect("read timeout")
            .expect("read failed");
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        if response.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let response_str = String::from_utf8_lossy(&response);
    assert!(
        response_str.contains("202 Accepted"),
        "expected 202 Accepted, got: {response_str}"
    );

    shutdown.notify_waiters();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
}

/// Test that disabled blackhole acceptor does nothing.
#[tokio::test]
async fn test_blackhole_disabled_returns_ok() {
    let config = BlackholeConfig {
        enabled: false,
        listen: "127.0.0.1".into(),
        ports: vec![19082],
        max_header_bytes: 4096,
    };
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let acceptor = BlackholeAcceptor::new(config, Arc::clone(&shutdown));

    // start() returns Ok(()) immediately when disabled.
    assert!(acceptor.start().await.is_ok());

    // Connection should fail because nothing is listening.
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        tokio::net::TcpStream::connect("127.0.0.1:19082"),
    )
    .await;
    assert!(result.is_err(), "connection should have timed out");
}
