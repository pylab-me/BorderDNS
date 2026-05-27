//! Transport abstraction layer for BorderDNS.
//!
//! All inbound transports (UDP, TCP, DoT, DoH, DoQ, DoJ) normalize
//! their DNS wire messages through a single `DnsRequestHandler`.
//! This crate defines the common types and traits that every transport
//! must use to interact with the resolver pipeline.
//!
//! Design principle:
//! ```text
//! Inbound Transport → DNS wire / JSON adapter → [same resolver pipeline]
//! ```
//! No transport may bypass the unified handler.

use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use dns_protocol::message::DnsMessage;
use dns_types::QType;

/// Transport types supported by BorderDNS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::enum_variant_names)]
pub enum TransportKind {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
    Json,
}

impl TransportKind {
    /// Human-readable name for metrics and logging.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::Https => "https",
            Self::Quic => "quic",
            Self::Json => "json",
        }
    }
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Metadata associated with an inbound DNS request.
#[derive(Debug, Clone)]
pub struct RequestMeta {
    /// Peer address (available for UDP, TCP, TLS, QUIC).
    pub peer_addr: Option<SocketAddr>,
    /// Transport that delivered this request.
    pub transport: TransportKind,
    /// When the request was received.
    pub received_at: Instant,
}

impl RequestMeta {
    /// Create a new request metadata entry.
    #[must_use]
    pub fn new(transport: TransportKind, peer_addr: Option<SocketAddr>) -> Self {
        Self {
            peer_addr,
            transport,
            received_at: Instant::now(),
        }
    }
}

/// Result of resolving a DNS request through the unified pipeline.
#[derive(Debug, Clone)]
pub struct ResolvedDns {
    /// The DNS response message.
    pub message: DnsMessage,
    /// Time spent resolving (including cache lookup and upstream).
    pub resolve_duration: Duration,
    /// Whether the response was served from cache.
    pub cache_hit: bool,
    /// Query name (for logging).
    pub query_name: String,
    /// Query type (for logging).
    pub qtype: QType,
}

/// Errors from the transport layer.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// IO error.
    #[error("transport IO error: {0}")]
    Io(#[from] std::io::Error),

    /// TLS handshake error.
    #[error("TLS handshake failed: {0}")]
    TlsHandshake(String),

    /// HTTP error for DoH.
    #[error("DoH error: {0}")]
    DoH(String),

    /// Request timed out.
    #[error("request timeout after {0:?}")]
    Timeout(Duration),

    /// Malformed request.
    #[error("malformed request: {0}")]
    MalformedRequest(String),

    /// Protocol error.
    #[error("DNS protocol error: {0}")]
    Protocol(#[from] dns_types::ProtocolError),
}

/// Per-transport metrics counters.
#[derive(Debug, Default)]
pub struct TransportMetrics {
    pub requests_total: AtomicU64,
    pub responses_total: AtomicU64,
    pub errors_total: AtomicU64,
    pub cache_hits_total: AtomicU64,
}

impl TransportMetrics {
    pub fn record_request(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_response(&self) {
        self.responses_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_error(&self) {
        self.errors_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits_total.fetch_add(1, Ordering::Relaxed);
    }
}

/// All transport metrics keyed by transport kind.
#[derive(Debug, Default)]
pub struct MetricsRegistry {
    pub udp: TransportMetrics,
    pub tcp: TransportMetrics,
    pub tls: TransportMetrics,
    pub https: TransportMetrics,
    pub quic: TransportMetrics,
    pub json: TransportMetrics,
}

impl MetricsRegistry {
    /// Get metrics for a specific transport.
    #[must_use]
    pub fn for_transport(&self, kind: TransportKind) -> &TransportMetrics {
        match kind {
            TransportKind::Udp => &self.udp,
            TransportKind::Tcp => &self.tcp,
            TransportKind::Tls => &self.tls,
            TransportKind::Https => &self.https,
            TransportKind::Quic => &self.quic,
            TransportKind::Json => &self.json,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_kind_as_str() {
        assert_eq!(TransportKind::Udp.as_str(), "udp");
        assert_eq!(TransportKind::Tcp.as_str(), "tcp");
        assert_eq!(TransportKind::Tls.as_str(), "tls");
        assert_eq!(TransportKind::Https.as_str(), "https");
        assert_eq!(TransportKind::Quic.as_str(), "quic");
        assert_eq!(TransportKind::Json.as_str(), "json");
    }

    #[test]
    fn test_request_meta_creation() {
        let meta = RequestMeta::new(TransportKind::Udp, None);
        assert_eq!(meta.transport, TransportKind::Udp);
        assert!(meta.peer_addr.is_none());
    }

    #[test]
    fn test_metrics_counter() {
        let metrics = TransportMetrics::default();
        assert_eq!(metrics.requests_total.load(Ordering::Relaxed), 0);

        metrics.record_request();
        metrics.record_request();
        metrics.record_response();

        assert_eq!(metrics.requests_total.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.responses_total.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_metrics_registry() {
        let registry = MetricsRegistry::default();
        registry.udp.record_request();
        registry.tls.record_request();

        assert_eq!(registry.udp.requests_total.load(Ordering::Relaxed), 1);
        assert_eq!(registry.tls.requests_total.load(Ordering::Relaxed), 1);
        assert_eq!(registry.tcp.requests_total.load(Ordering::Relaxed), 0);
    }
}
