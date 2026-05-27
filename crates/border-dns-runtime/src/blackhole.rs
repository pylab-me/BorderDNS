//! Blackhole HTTP acceptor for BorderDNS.
//!
//! Listens on HTTP ports (default: 80, 443) and returns 202 Accepted for
//! any request. This consumes HTTP traffic redirected by blackhole DNS
//! responses, preventing client connection hangs.

use std::sync::Arc;

use runtime_config::BlackholeConfig;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tracing::debug;
use tracing::info;

/// HTTP 202 response with empty body.
const RESPONSE_202: &[u8] =
    b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Blackhole HTTP acceptor.
///
/// Spawns lightweight TCP listeners on configured ports that consume
/// and discard HTTP requests, returning 202 Accepted.
#[derive(Debug)]
pub struct BlackholeAcceptor {
    config: BlackholeConfig,
    shutdown: Arc<tokio::sync::Notify>,
}

impl BlackholeAcceptor {
    /// Create a new blackhole acceptor.
    #[must_use]
    pub fn new(config: BlackholeConfig, shutdown: Arc<tokio::sync::Notify>) -> Self {
        Self { config, shutdown }
    }

    /// Start all configured blackhole listeners.
    ///
    /// Each port runs in its own task. Returns after all tasks are spawned.
    pub async fn start(&self) -> anyhow::Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let listen_addr: std::net::IpAddr = self
            .config
            .listen
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid blackhole listen address: {e}"))?;

        for &port in &self.config.ports {
            let addr = std::net::SocketAddr::new(listen_addr, port);
            let max_header = self.config.max_header_bytes;
            let shutdown = Arc::clone(&self.shutdown);

            info!(address = %addr, "blackhole HTTP listener starting");

            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(
                        address = %addr,
                        error = %e,
                        "blackhole HTTP bind failed"
                    );
                    continue;
                }
            };

            tokio::spawn(async move {
                Self::run_listener(listener, max_header, shutdown).await;
            });
        }

        Ok(())
    }

    /// Run a single blackhole listener loop.
    async fn run_listener(
        listener: tokio::net::TcpListener,
        max_header_bytes: usize,
        shutdown: Arc<tokio::sync::Notify>,
    ) {
        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((mut stream, peer_addr)) => {
                            let max_header = max_header_bytes;
                            tokio::spawn(async move {
                                Self::handle_connection(&mut stream, max_header, peer_addr).await;
                            });
                        }
                        Err(e) => {
                            debug!(error = %e, "blackhole accept error");
                        }
                    }
                }
                _ = shutdown.notified() => {
                    info!("blackhole listener shutting down");
                    break;
                }
            }
        }
    }

    /// Handle a single connection: drain headers, send 202, close.
    async fn handle_connection(
        stream: &mut tokio::net::TcpStream,
        max_header_bytes: usize,
        peer_addr: std::net::SocketAddr,
    ) {
        // Read and discard request headers with a tight byte limit.
        let mut total_read = 0usize;
        let mut buf = [0u8; 1024];
        loop {
            let n = match tokio::time::timeout(
                std::time::Duration::from_secs(2),
                stream.read(&mut buf),
            )
            .await
            {
                Ok(Ok(n)) => n,
                _ => break,
            };
            if n == 0 {
                break;
            }
            total_read += n;
            if total_read > max_header_bytes {
                debug!(peer = %peer_addr, "blackhole header limit exceeded");
                break;
            }
            // Check for double-CRLF (end of headers).
            if let Some(pos) = buf[..n].windows(2).position(|w| w == b"\r\n\r\n") {
                let _ = pos; // headers complete
                break;
            }
        }

        // Send 202 response.
        let _ = stream.write_all(RESPONSE_202).await;
        debug!(peer = %peer_addr, "blackhole 202 sent");
    }
}

#[cfg(test)]
#[path = "blackhole_tests.rs"]
mod tests;
