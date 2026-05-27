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
