use super::*;

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
