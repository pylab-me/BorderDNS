//! Upstream DNS resolver with UDP/TCP/DoT/DoH transport and failover.
//!
//! Sprint 1-1: adds DoT upstream (TLS + TCP framing) and DoH upstream
//! (HTTP POST/GET with `application/dns-message`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;

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

/// Forward a DNS query to the configured upstream servers with failover.
///
/// Tries each upstream in order. Returns the first successful response.
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

    let mut last_error = String::new();

    for server in upstreams {
        let timeout_dur = Duration::from_millis(server.timeout_ms).min(default_timeout);
        match forward_single(query, server, timeout_dur).await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                tracing::warn!(
                    name = %server.name,
                    transport = %server.transport,
                    error = %e,
                    "upstream query failed, trying next"
                );
                last_error = e.to_string();
            }
        }
    }

    Err(UpstreamError::AllFailed(last_error))
}

/// Forward a DNS query to a single upstream server.
async fn forward_single(
    query: &dns_protocol::message::DnsMessage,
    server: &border_dns_config::UpstreamServer,
    timeout_dur: Duration,
) -> Result<UpstreamResponse, UpstreamError> {
    let start = std::time::Instant::now();

    let (response_bytes, sock_addr) = match server.transport {
        border_dns_config::DnsProtocol::Udp => {
            let addr = parse_socket_addr(&server.endpoint)?;
            let bytes = forward_udp(query, addr, timeout_dur).await?;
            (bytes, addr)
        }
        border_dns_config::DnsProtocol::Tcp => {
            let addr = parse_socket_addr(&server.endpoint)?;
            let bytes = forward_tcp(query, addr, timeout_dur).await?;
            (bytes, addr)
        }
        border_dns_config::DnsProtocol::Tls => {
            let addr = parse_socket_addr(&server.endpoint)?;
            let server_name = server.server_name.as_deref().unwrap_or("dns.google");
            let bytes = forward_tls(query, addr, server_name, timeout_dur).await?;
            (bytes, addr)
        }
        border_dns_config::DnsProtocol::Https => {
            let bytes = forward_doh(query, &server.endpoint, timeout_dur).await?;
            // DoH uses the URL endpoint, not a socket addr for metrics.
            let dummy_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
            (bytes, dummy_addr)
        }
        border_dns_config::DnsProtocol::Quic => {
            // QUIC upstream is deferred to a later sprint.
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

/// Forward a DNS query via UDP.
async fn forward_udp(
    query: &dns_protocol::message::DnsMessage,
    addr: SocketAddr,
    timeout_dur: Duration,
) -> Result<Vec<u8>, UpstreamError> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    let query_bytes = query.to_wire();

    tokio::time::timeout(timeout_dur, async {
        socket.send_to(&query_bytes, addr).await?;

        let mut buf = vec![0u8; dns_protocol::message::MAX_EDNS_MESSAGE_SIZE];
        let (len, _) = socket.recv_from(&mut buf).await?;
        buf.truncate(len);
        Ok::<Vec<u8>, UpstreamError>(buf)
    })
    .await
    .map_err(|_| UpstreamError::Timeout(timeout_dur))?
}

/// Forward a DNS query via TCP.
async fn forward_tcp(
    query: &dns_protocol::message::DnsMessage,
    addr: SocketAddr,
    timeout_dur: Duration,
) -> Result<Vec<u8>, UpstreamError> {
    let query_bytes = query.to_wire();

    tokio::time::timeout(timeout_dur, async {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;

        // Send: 2-byte length prefix + DNS message.
        let frame = dns_protocol::tcp_frame::encode_tcp_frame(&query_bytes);
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

/// Forward a DNS query via DoT (DNS over TLS, RFC 7858).
///
/// Uses TLS + TCP framing (same wire format as TCP DNS).
async fn forward_tls(
    query: &dns_protocol::message::DnsMessage,
    addr: SocketAddr,
    server_name: &str,
    timeout_dur: Duration,
) -> Result<Vec<u8>, UpstreamError> {
    let query_bytes = query.to_wire();

    tokio::time::timeout(timeout_dur, async {
        // Build rustls client config.
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Enable ALPN for "dns" if desired (DoT doesn't strictly require it).
        tls_config.alpn_protocols = vec![];

        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
        let domain = rustls::pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|e| UpstreamError::TlsHandshake(format!("invalid server name: {e}")))?;

        let tcp_stream = tokio::net::TcpStream::connect(addr).await?;
        let mut tls_stream = connector
            .connect(domain, tcp_stream)
            .await
            .map_err(|e| UpstreamError::TlsHandshake(e.to_string()))?;

        // Send: 2-byte length prefix + DNS message (same as TCP).
        let frame = dns_protocol::tcp_frame::encode_tcp_frame(&query_bytes);
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

/// Forward a DNS query via DoH (DNS over HTTPS, RFC 8484).
///
/// Uses HTTP POST with `application/dns-message` content type.
async fn forward_doh(
    query: &dns_protocol::message::DnsMessage,
    endpoint_url: &str,
    timeout_dur: Duration,
) -> Result<Vec<u8>, UpstreamError> {
    let query_bytes = query.to_wire();

    let client = reqwest::Client::builder()
        .timeout(timeout_dur)
        .build()
        .map_err(|e| UpstreamError::DoH(e.to_string()))?;

    let response = client
        .post(endpoint_url)
        .header("Content-Type", dns_protocol::transport::DOH_CONTENT_TYPE)
        .header("Accept", dns_protocol::transport::DOH_CONTENT_TYPE)
        .body(query_bytes)
        .send()
        .await
        .map_err(|e| UpstreamError::DoH(e.to_string()))?;

    let status = response.status();
    if !status.is_success() {
        return Err(UpstreamError::DoH(format!("HTTP {status}")));
    }

    let body = response
        .bytes()
        .await
        .map_err(|e| UpstreamError::DoH(e.to_string()))?;

    if body.is_empty() {
        return Err(UpstreamError::DoH("empty response body".into()));
    }

    Ok(body.to_vec())
}

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
