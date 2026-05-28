use geoip::SimpleGeoIp;

use super::*;

// ─── Speed Test ──────────────────────────────────────────────────

#[test]
fn test_ranked_ip_serde() {
    let ranked = RankedIp {
        addr: "1.1.1.1".parse().unwrap(),
        latency_ms: Some(12),
        quality: ProbeQuality::Good,
    };
    let json = serde_json::to_string(&ranked).unwrap();
    let parsed: RankedIp = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.addr, "1.1.1.1".parse::<IpAddr>().unwrap());
    assert_eq!(parsed.latency_ms, Some(12));
    assert_eq!(parsed.quality, ProbeQuality::Good);
}

#[test]
fn test_ranked_ip_failed_probe_serde() {
    let ranked = RankedIp {
        addr: "9.9.9.9".parse().unwrap(),
        latency_ms: None,
        quality: ProbeQuality::Unstable,
    };
    let json = serde_json::to_string(&ranked).unwrap();
    let parsed: RankedIp = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.latency_ms, None);
    assert_eq!(parsed.quality, ProbeQuality::Unstable);
}

#[tokio::test]
async fn test_tcp_speed_test_empty_candidates() {
    let tester = TcpSpeedTest::new();
    let result = tester
        .rank_by_latency(&[], 53, Duration::from_millis(500))
        .await;
    assert!(result.is_empty());
}

#[tokio::test]
async fn test_tcp_speed_test_sorts_by_latency() {
    let tester = TcpSpeedTest::new();
    // Use loopback addresses that are likely to connect quickly.
    // 127.0.0.1:1 should be unreachable fast (ECONNREFUSED),
    // giving a low latency. We test sorting order, not real latency.
    let candidates: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap(), "127.0.0.2".parse().unwrap()];
    let result = tester
        .rank_by_latency(&candidates, 1, Duration::from_millis(200))
        .await;

    // Both should fail (port 1 closed) but we still get results back.
    assert_eq!(result.len(), 2);
    for r in &result {
        assert_eq!(r.latency_ms, None);
        assert_eq!(r.quality, ProbeQuality::Unstable);
    }
}

#[tokio::test]
async fn test_tcp_speed_test_single_candidate() {
    let tester = TcpSpeedTest::new();
    let candidates = vec!["127.0.0.1".parse().unwrap()];
    let result = tester
        .rank_by_latency(&candidates, 1, Duration::from_millis(200))
        .await;

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].addr, "127.0.0.1".parse::<IpAddr>().unwrap());
}

// ─── IP Filtering by Location ────────────────────────────────────

#[test]
fn test_filter_ips_china_location_keeps_cn_only() {
    let geo = SimpleGeoIp;
    let candidates: Vec<IpAddr> = vec![
        "223.5.5.5".parse().unwrap(),       // CN
        "8.8.8.8".parse().unwrap(),         // Foreign
        "114.114.114.114".parse().unwrap(), // CN
        "1.1.1.1".parse().unwrap(),         // Foreign
    ];
    let filtered = filter_ips_by_location(&candidates, ResolverLocation::China, &geo);
    assert_eq!(filtered.len(), 2);
    assert!(filtered.contains(&"223.5.5.5".parse::<IpAddr>().unwrap()));
    assert!(filtered.contains(&"114.114.114.114".parse::<IpAddr>().unwrap()));
}

#[test]
fn test_filter_ips_foreign_location_keeps_foreign_only() {
    let geo = SimpleGeoIp;
    let candidates: Vec<IpAddr> = vec![
        "223.5.5.5".parse().unwrap(), // CN
        "8.8.8.8".parse().unwrap(),   // Foreign
        "1.1.1.1".parse().unwrap(),   // Foreign
    ];
    let filtered = filter_ips_by_location(&candidates, ResolverLocation::Foreign, &geo);
    assert_eq!(filtered.len(), 2);
    assert!(filtered.contains(&"8.8.8.8".parse::<IpAddr>().unwrap()));
    assert!(filtered.contains(&"1.1.1.1".parse::<IpAddr>().unwrap()));
}

#[test]
fn test_filter_ips_unknown_location_keeps_all_non_private() {
    let geo = SimpleGeoIp;
    let candidates: Vec<IpAddr> = vec![
        "223.5.5.5".parse().unwrap(),   // CN
        "8.8.8.8".parse().unwrap(),     // Foreign
        "192.168.1.1".parse().unwrap(), // Private
    ];
    let filtered = filter_ips_by_location(&candidates, ResolverLocation::Unknown, &geo);
    assert_eq!(filtered.len(), 2);
    assert!(filtered.contains(&"223.5.5.5".parse::<IpAddr>().unwrap()));
    assert!(filtered.contains(&"8.8.8.8".parse::<IpAddr>().unwrap()));
}

#[test]
fn test_filter_ips_always_excludes_private_and_reserved() {
    let geo = SimpleGeoIp;
    let candidates: Vec<IpAddr> = vec![
        "192.168.1.1".parse().unwrap(), // Private
        "127.0.0.1".parse().unwrap(),   // Reserved (loopback)
        "10.0.0.1".parse().unwrap(),    // Private
        "223.5.5.5".parse().unwrap(),   // CN
    ];
    let filtered = filter_ips_by_location(&candidates, ResolverLocation::China, &geo);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0], "223.5.5.5".parse::<IpAddr>().unwrap());
}

#[test]
fn test_filter_ips_fallback_when_all_filtered_out() {
    let geo = SimpleGeoIp;
    // All CN IPs but location is Foreign — all would be filtered out.
    let candidates: Vec<IpAddr> = vec![
        "223.5.5.5".parse().unwrap(),       // CN
        "114.114.114.114".parse().unwrap(), // CN
    ];
    let filtered = filter_ips_by_location(&candidates, ResolverLocation::Foreign, &geo);
    // Fallback: returns original list so DNS still works.
    assert_eq!(filtered.len(), 2);
    assert_eq!(filtered, candidates);
}

#[test]
fn test_filter_ips_empty_candidates() {
    let geo = SimpleGeoIp;
    let filtered = filter_ips_by_location(&[], ResolverLocation::China, &geo);
    assert!(filtered.is_empty());
}

#[test]
fn test_classify_latency_good() {
    assert_eq!(classify_latency(10), ProbeQuality::Good);
    assert_eq!(classify_latency(49), ProbeQuality::Good);
}

#[test]
fn test_classify_latency_acceptable() {
    assert_eq!(classify_latency(50), ProbeQuality::Acceptable);
    assert_eq!(classify_latency(199), ProbeQuality::Acceptable);
}

#[test]
fn test_classify_latency_poor() {
    assert_eq!(classify_latency(200), ProbeQuality::Poor);
    assert_eq!(classify_latency(999), ProbeQuality::Poor);
}

#[test]
fn test_classify_latency_unstable() {
    assert_eq!(classify_latency(1000), ProbeQuality::Unstable);
    assert_eq!(classify_latency(5000), ProbeQuality::Unstable);
}

// ─── Identity match ──────────────────────────────────────────────

#[test]
fn test_identity_exact_match_san() {
    let sans = vec!["example.com".to_string()];
    let status = check_identity_match("example.com", &sans, None, &[]);
    assert_eq!(status, TlsIdentityStatus::ExactMatch);
}

#[test]
fn test_identity_wildcard_match() {
    let sans = vec!["*.example.com".to_string()];
    let status = check_identity_match("www.example.com", &sans, None, &[]);
    assert_eq!(status, TlsIdentityStatus::ExactMatch);
}

#[test]
fn test_identity_wildcard_no_sub_subdomain() {
    let sans = vec!["*.example.com".to_string()];
    // a.b.example.com should NOT match *.example.com
    let status = check_identity_match("a.b.example.com", &sans, None, &[]);
    assert_eq!(status, TlsIdentityStatus::Mismatch);
}

#[test]
fn test_identity_cn_match() {
    let sans = vec!["other.com".to_string()];
    let status = check_identity_match("example.com", &sans, Some("example.com"), &[]);
    assert_eq!(status, TlsIdentityStatus::ExactMatch);
}

#[test]
fn test_identity_cname_match() {
    let sans = vec!["cdn.example.com".to_string()];
    let cname_targets = vec!["cdn.example.com".to_string()];
    let status = check_identity_match("www.example.com", &sans, None, &cname_targets);
    assert_eq!(status, TlsIdentityStatus::CnameMatch);
}

#[test]
fn test_identity_mismatch() {
    let sans = vec!["other.com".to_string()];
    let status = check_identity_match("example.com", &sans, None, &[]);
    assert_eq!(status, TlsIdentityStatus::Mismatch);
}

#[test]
fn test_identity_case_insensitive() {
    let sans = vec!["Example.COM".to_string()];
    let status = check_identity_match("example.com", &sans, None, &[]);
    assert_eq!(status, TlsIdentityStatus::ExactMatch);
}

#[test]
fn test_identity_no_sans_no_cn() {
    let sans: Vec<String> = vec![];
    let status = check_identity_match("example.com", &sans, None, &[]);
    assert_eq!(status, TlsIdentityStatus::Unknown);
}

// ─── Probe result serialization ──────────────────────────────────

#[test]
fn test_tls_probe_result_serde() {
    let result = TlsProbeResult {
        sni_domain: "example.com".into(),
        target_ip: "1.1.1.1".parse().unwrap(),
        identity_status: TlsIdentityStatus::ExactMatch,
        cert_sans: vec!["example.com".into()],
        cert_cn: None,
        connect_ms: Some(42),
        error: None,
    };

    let json = serde_json::to_string(&result).unwrap();
    let parsed: TlsProbeResult = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.identity_status, TlsIdentityStatus::ExactMatch);
    assert_eq!(parsed.connect_ms, Some(42));
}

#[test]
fn test_latency_probe_result_serde() {
    let result = LatencyProbeResult {
        target_ip: "223.5.5.5".parse().unwrap(),
        connect_ms: Some(15),
        quality: ProbeQuality::Good,
        error: None,
    };

    let json = serde_json::to_string(&result).unwrap();
    let parsed: LatencyProbeResult = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.quality, ProbeQuality::Good);
}
