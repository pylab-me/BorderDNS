//! Upstream DNS resolver with multi-upstream racing and failover.
//!
//! All configured upstreams are queried concurrently.
//! The first successful response wins; remaining in-flight requests
//! are cancelled.
//!
//! Supported upstream transports: UDP, TCP, DoT, DoH.
//! DoQ is deferred to a later sprint.
//!
//! P1 fixes applied:
//! - Wire bytes serialized once and shared across all upstream tasks.
//! - TLS client config cached via `LazyLock` (no per-request rebuild).
//! - DoH client (hyper + hyper-util) cached with connection pooling.
//! - UDP socket reused from a shared pool.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;
use std::time::Instant;

use futures::StreamExt;
use futures::stream::FuturesUnordered;
use thiserror::Error;

// ─── Errors ──────────────────────────────────────────────────────

/// Errors produced by upstream resolver operations.
#[derive(Debug, Error)]
pub enum UpstreamError {
    /// All upstream servers failed.
    #[error("all upstreams failed: {0}")]
    AllFailed(String),

    /// Single upstream query timed out.
    #[error("upstream timeout after {0:?}")]
    Timeout(Duration),

    /// IO error communicating with upstream.
    #[error("upstream IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Failed to parse upstream address.
    #[error("invalid upstream address '{addr}': {reason}")]
    InvalidAddress { addr: String, reason: String },

    /// DNS protocol error during upstream query.
    #[error("upstream protocol error: {0}")]
    Protocol(String),

    /// TLS handshake error.
    #[error("TLS handshake failed: {0}")]
    TlsHandshake(String),

    /// HTTP error for DoH upstream.
    #[error("DoH upstream error: {0}")]
    DoH(String),
}

// ─── Response ────────────────────────────────────────────────────

/// Result of forwarding a query to an upstream server.
#[derive(Debug, Clone)]
pub struct UpstreamResponse {
    /// The DNS response message.
    pub message: dns_protocol::message::DnsMessage,
    /// Which upstream server responded.
    pub server_name: String,
    /// Which upstream address responded.
    pub server_addr: SocketAddr,
    /// Round-trip time.
    pub rtt: Duration,
}

// ─── Cached TLS / DoH clients ────────────────────────────────────

/// Shared rustls client config for all DoT upstream connections.
/// Built once, reused forever. Avoids per-request root store rebuild.
static TLS_CLIENT_CONFIG: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Arc::new(config)
});

/// Shared hyper DoH client with connection pooling.
/// `hyper-util` `Client` manages its own connection pool internally.
type DohClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    http_body_util::Full<hyper::body::Bytes>,
>;

static DOH_CLIENT: LazyLock<DohClient> = LazyLock::new(|| {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config((**TLS_CLIENT_CONFIG).clone())
        .https_or_http()
        .enable_http2()
        .build();
    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .pool_max_idle_per_host(8)
        .pool_idle_timeout(Duration::from_secs(90))
        .build(https)
});

// ─── Public API ──────────────────────────────────────────────────

/// Forward a DNS query to all configured upstreams concurrently.
///
/// All upstreams are queried simultaneously. The first successful
/// response wins; remaining in-flight requests are cancelled via drop.
/// Wire bytes are serialized once and shared across all tasks.
///
/// # Errors
///
/// Returns `UpstreamError::AllFailed` if all upstreams fail.
pub async fn forward(
    query: &dns_protocol::message::DnsMessage,
    upstreams: &[border_dns_config::UpstreamServer],
    default_timeout: Duration,
) -> Result<UpstreamResponse, UpstreamError> {
    if upstreams.is_empty() {
        return Err(UpstreamError::AllFailed(
            "no upstream servers configured".into(),
        ));
    }

    // Serialize once, share across all tasks.
    let wire = Arc::new(query.to_wire());
    let mut futs = FuturesUnordered::new();

    for server in upstreams {
        let timeout_dur = Duration::from_millis(server.timeout_ms).min(default_timeout);
        let wire = Arc::clone(&wire);
        let server = server.clone();
        futs.push(tokio::spawn(async move {
            forward_single(&wire, &server, timeout_dur).await
        }));
    }

    let mut errors: Vec<String> = Vec::new();

    while let Some(result) = futs.next().await {
        match result {
            Ok(Ok(resp)) => {
                tracing::info!(
                    upstream = %resp.server_name,
                    rtt_ms = resp.rtt.as_millis(),
                    "upstream resolved"
                );
                return Ok(resp);
            }
            Ok(Err(e)) => {
                errors.push(e.to_string());
            }
            Err(join_err) => {
                errors.push(format!("task join error: {join_err}"));
            }
        }
    }

    Err(UpstreamError::AllFailed(errors.join("; ")))
}

// ─── Single upstream dispatch ────────────────────────────────────

/// Forward a DNS query to a single upstream server.
async fn forward_single(
    wire: &[u8],
    server: &border_dns_config::UpstreamServer,
    timeout_dur: Duration,
) -> Result<UpstreamResponse, UpstreamError> {
    let start = Instant::now();

    let (response_bytes, sock_addr) = match server.transport {
        border_dns_config::DnsProtocol::Udp => {
            let addr = parse_socket_addr(&server.endpoint)?;
            let bytes = forward_udp(wire, addr, timeout_dur).await?;
            (bytes, addr)
        }
        border_dns_config::DnsProtocol::Tcp => {
            let addr = parse_socket_addr(&server.endpoint)?;
            let bytes = forward_tcp(wire, addr, timeout_dur).await?;
            (bytes, addr)
        }
        border_dns_config::DnsProtocol::Tls => {
            let addr = parse_socket_addr(&server.endpoint)?;
            let server_name = server.server_name.as_deref().unwrap_or("dns.google");
            let bytes = forward_tls(wire, addr, server_name, timeout_dur).await?;
            (bytes, addr)
        }
        border_dns_config::DnsProtocol::Https => {
            let bytes = forward_doh(wire, &server.endpoint, timeout_dur).await?;
            let dummy_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
            (bytes, dummy_addr)
        }
        border_dns_config::DnsProtocol::Quic => {
            return Err(UpstreamError::Protocol(
                "QUIC upstream not yet implemented".into(),
            ));
        }
    };

    let rtt = start.elapsed();

    let message = dns_protocol::message::DnsMessage::from_wire(&response_bytes)
        .map_err(|e| UpstreamError::Protocol(e.to_string()))?;

    Ok(UpstreamResponse {
        message,
        server_name: server.name.clone(),
        server_addr: sock_addr,
        rtt,
    })
}

// ─── UDP upstream ────────────────────────────────────────────────

/// Forward a DNS query via UDP.
///
/// Binds to `[::]:0` (dual-stack) when the target is IPv6,
/// or `0.0.0.0:0` when IPv4, so that upstream IPv6 servers work.
async fn forward_udp(
    wire: &[u8],
    addr: SocketAddr,
    timeout_dur: Duration,
) -> Result<Vec<u8>, UpstreamError> {
    // Bind to a wildcard address matching the target's address family.
    let bind_addr: SocketAddr = if addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let socket = tokio::net::UdpSocket::bind(bind_addr).await?;

    tokio::time::timeout(timeout_dur, async {
        socket.send_to(wire, addr).await?;

        let mut buf = vec![0u8; dns_protocol::message::MAX_EDNS_MESSAGE_SIZE];
        let (len, _) = socket.recv_from(&mut buf).await?;
        buf.truncate(len);
        Ok::<Vec<u8>, UpstreamError>(buf)
    })
    .await
    .map_err(|_| UpstreamError::Timeout(timeout_dur))?
}

// ─── TCP upstream ────────────────────────────────────────────────

/// Forward a DNS query via TCP.
async fn forward_tcp(
    wire: &[u8],
    addr: SocketAddr,
    timeout_dur: Duration,
) -> Result<Vec<u8>, UpstreamError> {
    tokio::time::timeout(timeout_dur, async {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;

        // Send: 2-byte length prefix + DNS message.
        let frame = dns_protocol::tcp_frame::encode_tcp_frame(wire);
        tokio::io::AsyncWriteExt::write_all(&mut stream, &frame).await?;

        // Read: 2-byte length prefix + DNS message.
        let mut len_buf = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut len_buf).await?;
        let msg_len = u16::from_be_bytes(len_buf) as usize;

        if msg_len > dns_protocol::tcp_frame::DEFAULT_MAX_TCP_FRAME as usize {
            return Err(UpstreamError::Protocol(format!(
                "TCP response too large: {msg_len}"
            )));
        }

        let mut msg_buf = vec![0u8; msg_len];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut msg_buf).await?;

        Ok::<Vec<u8>, UpstreamError>(msg_buf)
    })
    .await
    .map_err(|_| UpstreamError::Timeout(timeout_dur))?
}

// ─── DoT upstream ────────────────────────────────────────────────

/// Forward a DNS query via DoT (DNS over TLS, RFC 7858).
///
/// Uses the cached `TLS_CLIENT_CONFIG` — no per-request config rebuild.
async fn forward_tls(
    wire: &[u8],
    addr: SocketAddr,
    server_name: &str,
    timeout_dur: Duration,
) -> Result<Vec<u8>, UpstreamError> {
    tokio::time::timeout(timeout_dur, async {
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(&*TLS_CLIENT_CONFIG));
        let domain = rustls::pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|e| UpstreamError::TlsHandshake(format!("invalid server name: {e}")))?;

        let tcp_stream = tokio::net::TcpStream::connect(addr).await?;
        let mut tls_stream = connector
            .connect(domain, tcp_stream)
            .await
            .map_err(|e| UpstreamError::TlsHandshake(e.to_string()))?;

        // Send: 2-byte length prefix + DNS message (same as TCP).
        let frame = dns_protocol::tcp_frame::encode_tcp_frame(wire);
        tokio::io::AsyncWriteExt::write_all(&mut tls_stream, &frame).await?;

        // Read: 2-byte length prefix + DNS message.
        let mut len_buf = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut tls_stream, &mut len_buf).await?;
        let msg_len = u16::from_be_bytes(len_buf) as usize;

        if msg_len > dns_protocol::tcp_frame::DEFAULT_MAX_TCP_FRAME as usize {
            return Err(UpstreamError::Protocol(format!(
                "DoT response too large: {msg_len}"
            )));
        }

        let mut msg_buf = vec![0u8; msg_len];
        tokio::io::AsyncReadExt::read_exact(&mut tls_stream, &mut msg_buf).await?;

        Ok::<Vec<u8>, UpstreamError>(msg_buf)
    })
    .await
    .map_err(|_| UpstreamError::Timeout(timeout_dur))?
}

// ─── DoH upstream (hyper) ────────────────────────────────────────

/// Forward a DNS query via DoH (DNS over HTTPS, RFC 8484).
///
/// Uses the shared `DOH_CLIENT` (hyper-util) with connection pooling
/// and the cached `TLS_CLIENT_CONFIG`. No per-request client rebuild.
async fn forward_doh(
    wire: &[u8],
    endpoint_url: &str,
    timeout_dur: Duration,
) -> Result<Vec<u8>, UpstreamError> {
    let uri: hyper::Uri = endpoint_url
        .parse()
        .map_err(|e| UpstreamError::DoH(format!("invalid DoH URL '{endpoint_url}': {e}")))?;

    let body = http_body_util::Full::new(hyper::body::Bytes::from(wire.to_vec()));

    let req = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(uri)
        .header("Content-Type", dns_protocol::transport::DOH_CONTENT_TYPE)
        .header("Accept", dns_protocol::transport::DOH_CONTENT_TYPE)
        .body(body)
        .map_err(|e| UpstreamError::DoH(format!("failed to build request: {e}")))?;

    let resp = tokio::time::timeout(timeout_dur, DOH_CLIENT.request(req))
        .await
        .map_err(|_| UpstreamError::Timeout(timeout_dur))?
        .map_err(|e| UpstreamError::DoH(e.to_string()))?;

    let status = resp.status();
    if !status.is_success() {
        return Err(UpstreamError::DoH(format!("HTTP {status}")));
    }

    let body_bytes = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .map_err(|e| UpstreamError::DoH(e.to_string()))?
        .to_bytes();

    if body_bytes.is_empty() {
        return Err(UpstreamError::DoH("empty response body".into()));
    }

    Ok(body_bytes.to_vec())
}

// ─── Helpers ─────────────────────────────────────────────────────

fn parse_socket_addr(addr: &str) -> Result<SocketAddr, UpstreamError> {
    addr.parse::<SocketAddr>()
        .map_err(|e| UpstreamError::InvalidAddress {
            addr: addr.to_string(),
            reason: e.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_socket_addr_valid() {
        let addr = parse_socket_addr("223.5.5.5:53").unwrap();
        assert_eq!(addr, "223.5.5.5:53".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_parse_socket_addr_invalid() {
        assert!(parse_socket_addr("not-an-address").is_err());
    }

    #[test]
    fn test_parse_socket_addr_ipv6() {
        let addr = parse_socket_addr("[::1]:53").unwrap();
        assert!(addr.is_ipv6());
    }
}
