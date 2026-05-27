//! Upstream DNS resolver with UDP/TCP transport and failover.
//!
//! Sprint 1 upstream forwards queries to configured upstream servers,
//! with timeout and failover across the upstream group.

use std::net::SocketAddr;
use std::time::Duration;

use border_dns_config::DnsProtocol;
use border_dns_config::UpstreamServer;
use dns_protocol::message::DnsMessage;
use dns_protocol::message::MAX_EDNS_MESSAGE_SIZE;
use dns_protocol::tcp_frame;
use dns_protocol::tcp_frame::DEFAULT_MAX_TCP_FRAME;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::warn;

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
}

/// Result of forwarding a query to an upstream server.
#[derive(Debug, Clone)]
pub struct UpstreamResponse {
    /// The DNS response message.
    pub message: DnsMessage,
    /// Which upstream server responded.
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
    query: &DnsMessage,
    upstreams: &[UpstreamServer],
    default_timeout: Duration,
) -> Result<UpstreamResponse, UpstreamError> {
    if upstreams.is_empty() {
        return Err(UpstreamError::AllFailed(
            "no upstream servers configured".into(),
        ));
    }

    let mut last_error = String::new();

    for server in upstreams {
        let timeout_dur = Duration::from_secs(server.timeout_secs).min(default_timeout);
        match forward_single(query, server, timeout_dur).await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                warn!(
                    server = %server.addr,
                    protocol = ?server.protocol,
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
    query: &DnsMessage,
    server: &UpstreamServer,
    timeout_dur: Duration,
) -> Result<UpstreamResponse, UpstreamError> {
    let sock_addr = parse_socket_addr(&server.addr)?;

    let start = std::time::Instant::now();
    let response_bytes = match server.protocol {
        DnsProtocol::Udp => forward_udp(query, sock_addr, timeout_dur).await?,
        DnsProtocol::Tcp => forward_tcp(query, sock_addr, timeout_dur).await?,
    };
    let rtt = start.elapsed();

    let message = DnsMessage::from_wire(&response_bytes)
        .map_err(|e| UpstreamError::Protocol(e.to_string()))?;

    Ok(UpstreamResponse {
        message,
        server_addr: sock_addr,
        rtt,
    })
}

/// Forward a DNS query via UDP.
async fn forward_udp(
    query: &DnsMessage,
    addr: SocketAddr,
    timeout_dur: Duration,
) -> Result<Vec<u8>, UpstreamError> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let query_bytes = query.to_wire();

    timeout(timeout_dur, async {
        socket.send_to(&query_bytes, addr).await?;

        let mut buf = vec![0u8; MAX_EDNS_MESSAGE_SIZE];
        let (len, _) = socket.recv_from(&mut buf).await?;
        buf.truncate(len);
        Ok::<Vec<u8>, UpstreamError>(buf)
    })
    .await
    .map_err(|_| UpstreamError::Timeout(timeout_dur))?
}

/// Forward a DNS query via TCP.
async fn forward_tcp(
    query: &DnsMessage,
    addr: SocketAddr,
    timeout_dur: Duration,
) -> Result<Vec<u8>, UpstreamError> {
    let query_bytes = query.to_wire();

    timeout(timeout_dur, async {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;

        // Send: 2-byte length prefix + DNS message.
        let frame = tcp_frame::encode_tcp_frame(&query_bytes);
        tokio::io::AsyncWriteExt::write_all(&mut stream, &frame).await?;

        // Read: 2-byte length prefix + DNS message.
        let mut len_buf = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut len_buf).await?;
        let msg_len = u16::from_be_bytes(len_buf) as usize;

        if msg_len > DEFAULT_MAX_TCP_FRAME as usize {
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
