use std::sync::Arc;

use domain_knowledge::BuiltInDomainKnowledge;
use geoip::SimpleGeoIp;
use route_cache::DnsCache;
use runtime_config::Config;

use super::Pipeline;

fn test_config() -> Config {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[[upstreams.default]]
name = "test"
endpoint = "223.5.5.5:53"
"#;
    runtime_config::load_from_str(toml_str).unwrap()
}

/// Build a minimal DNS query wire message for the given domain and qtype.
fn build_query_wire(domain: &str, qtype: dns_types::QType) -> Vec<u8> {
    let qname = dns_protocol::name::DomainName::from_str(domain).expect("valid domain");
    let question = dns_protocol::question::DnsQuestion::new(
        qname,
        qtype,
        dns_types::QClass::Class(dns_types::RecordClass::In),
    );
    let msg = dns_protocol::message::DnsMessage::query(0x1234, question);
    msg.to_wire()
}

fn test_meta() -> dns_transport::RequestMeta {
    dns_transport::RequestMeta::new(dns_transport::TransportKind::Udp, None)
}

#[tokio::test]
async fn test_pipeline_creation() {
    let config = Arc::new(test_config());
    let cache = Arc::new(DnsCache::new(config.cache.clone()));
    let knowledge = Arc::new(BuiltInDomainKnowledge::new());
    let geoip = Arc::new(SimpleGeoIp);
    let pipeline = Pipeline::new(config, cache, knowledge, geoip);
    assert!(pipeline.governance_store().is_empty());
}

// ─── Hosts Override Tests ───────────────────────────────────────

#[tokio::test]
async fn test_hosts_override_returns_configured_ip() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[[upstreams.default]]
name = "test"
endpoint = "223.5.5.5:53"

[hosts]
enabled = true
ttl_secs = 120

[hosts.entries]
"blocked.local" = ["1.2.3.4"]
"#;
    let config = Arc::new(runtime_config::load_from_str(toml_str).unwrap());
    let cache = Arc::new(DnsCache::new(config.cache.clone()));
    let knowledge = Arc::new(BuiltInDomainKnowledge::new());
    let geoip = Arc::new(SimpleGeoIp);
    let pipeline = Pipeline::new(config, cache, knowledge, geoip);

    let wire = build_query_wire(
        "blocked.local",
        dns_types::QType::Type(dns_types::RecordType::A),
    );
    let meta = test_meta();
    let resp = pipeline.resolve(&wire, &meta).await;

    assert_eq!(
        resp.header.rcode,
        dns_protocol::header::ResponseCode::NoError
    );
    assert_eq!(resp.answers.len(), 1);
    match &resp.answers[0].rdata {
        dns_protocol::rr::RData::A(ip) => {
            assert_eq!(*ip, "1.2.3.4".parse::<std::net::Ipv4Addr>().unwrap());
        }
        other => panic!("expected A record, got {:?}", other),
    }
    assert_eq!(resp.answers[0].ttl, 120);
}

#[tokio::test]
async fn test_hosts_override_v6() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[[upstreams.default]]
name = "test"
endpoint = "223.5.5.5:53"

[hosts]
enabled = true

[hosts.entries]
"ipv6.local" = ["2001:db8::1"]
"#;
    let config = Arc::new(runtime_config::load_from_str(toml_str).unwrap());
    let cache = Arc::new(DnsCache::new(config.cache.clone()));
    let knowledge = Arc::new(BuiltInDomainKnowledge::new());
    let geoip = Arc::new(SimpleGeoIp);
    let pipeline = Pipeline::new(config, cache, knowledge, geoip);

    let wire = build_query_wire(
        "ipv6.local",
        dns_types::QType::Type(dns_types::RecordType::AAAA),
    );
    let meta = test_meta();
    let resp = pipeline.resolve(&wire, &meta).await;

    assert_eq!(resp.answers.len(), 1);
    match &resp.answers[0].rdata {
        dns_protocol::rr::RData::AAAA(ip) => {
            assert_eq!(*ip, "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap());
        }
        other => panic!("expected AAAA record, got {:?}", other),
    }
}

#[tokio::test]
async fn test_hosts_override_non_matching_domain_falls_through() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[[upstreams.default]]
name = "test"
endpoint = "223.5.5.5:53"

[hosts]
enabled = true

[hosts.entries]
"blocked.local" = ["1.2.3.4"]
"#;
    let config = Arc::new(runtime_config::load_from_str(toml_str).unwrap());
    let cache = Arc::new(DnsCache::new(config.cache.clone()));
    let knowledge = Arc::new(BuiltInDomainKnowledge::new());
    let geoip = Arc::new(SimpleGeoIp);
    let pipeline = Pipeline::new(config, cache, knowledge, geoip);

    // "other.local" is NOT in the hosts table, so it falls through to upstream.
    // The upstream may return NXDomain or ServFail — the key point is hosts did NOT intercept.
    let wire = build_query_wire(
        "other.local",
        dns_types::QType::Type(dns_types::RecordType::A),
    );
    let meta = test_meta();
    let resp = pipeline.resolve(&wire, &meta).await;

    // Hosts did NOT intercept: response must not contain 1.2.3.4.
    for ans in &resp.answers {
        if let dns_protocol::rr::RData::A(ip) = &ans.rdata {
            assert_ne!(
                *ip,
                "1.2.3.4".parse::<std::net::Ipv4Addr>().unwrap(),
                "hosts should not have intercepted this query"
            );
        }
    }
}

#[tokio::test]
async fn test_hosts_disabled_does_not_intercept() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[[upstreams.default]]
name = "test"
endpoint = "223.5.5.5:53"

[hosts]
enabled = false

[hosts.entries]
"blocked.local" = ["1.2.3.4"]
"#;
    let config = Arc::new(runtime_config::load_from_str(toml_str).unwrap());
    let cache = Arc::new(DnsCache::new(config.cache.clone()));
    let knowledge = Arc::new(BuiltInDomainKnowledge::new());
    let geoip = Arc::new(SimpleGeoIp);
    let pipeline = Pipeline::new(config, cache, knowledge, geoip);

    let wire = build_query_wire(
        "blocked.local",
        dns_types::QType::Type(dns_types::RecordType::A),
    );
    let meta = test_meta();
    let resp = pipeline.resolve(&wire, &meta).await;

    // Disabled hosts should fall through to upstream.
    // The response should not contain 1.2.3.4 (hosts did NOT intercept).
    for ans in &resp.answers {
        if let dns_protocol::rr::RData::A(ip) = &ans.rdata {
            assert_ne!(
                *ip,
                "1.2.3.4".parse::<std::net::Ipv4Addr>().unwrap(),
                "disabled hosts should not have intercepted this query"
            );
        }
    }
}

// ─── Domain Block Tests ─────────────────────────────────────────

#[tokio::test]
async fn test_block_exact_domain_returns_blackhole_ip() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[[upstreams.default]]
name = "test"
endpoint = "223.5.5.5:53"

[block]
enabled = true
blackhole_ipv4 = "198.18.0.1"
blackhole_ipv6 = "fc00::"
domains = ["ads.example.com"]
suffixes = []
"#;
    let config = Arc::new(runtime_config::load_from_str(toml_str).unwrap());
    let cache = Arc::new(DnsCache::new(config.cache.clone()));
    let knowledge = Arc::new(BuiltInDomainKnowledge::new());
    let geoip = Arc::new(SimpleGeoIp);
    let pipeline = Pipeline::new(config, cache, knowledge, geoip);

    let wire = build_query_wire(
        "ads.example.com",
        dns_types::QType::Type(dns_types::RecordType::A),
    );
    let meta = test_meta();
    let resp = pipeline.resolve(&wire, &meta).await;

    assert_eq!(
        resp.header.rcode,
        dns_protocol::header::ResponseCode::NoError
    );
    assert_eq!(resp.answers.len(), 1);
    match &resp.answers[0].rdata {
        dns_protocol::rr::RData::A(ip) => {
            assert_eq!(*ip, "198.18.0.1".parse::<std::net::Ipv4Addr>().unwrap());
        }
        other => panic!("expected A record with blackhole IP, got {:?}", other),
    }
    assert_eq!(resp.answers[0].ttl, 60);
}

#[tokio::test]
async fn test_block_suffix_match() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[[upstreams.default]]
name = "test"
endpoint = "223.5.5.5:53"

[block]
enabled = true
blackhole_ipv4 = "0.0.0.0"
blackhole_ipv6 = "::"
domains = []
suffixes = ["doubleclick.net"]
"#;
    let config = Arc::new(runtime_config::load_from_str(toml_str).unwrap());
    let cache = Arc::new(DnsCache::new(config.cache.clone()));
    let knowledge = Arc::new(BuiltInDomainKnowledge::new());
    let geoip = Arc::new(SimpleGeoIp);
    let pipeline = Pipeline::new(config, cache, knowledge, geoip);

    let wire = build_query_wire(
        "ad.doubleclick.net",
        dns_types::QType::Type(dns_types::RecordType::A),
    );
    let meta = test_meta();
    let resp = pipeline.resolve(&wire, &meta).await;

    assert_eq!(resp.answers.len(), 1);
    match &resp.answers[0].rdata {
        dns_protocol::rr::RData::A(ip) => {
            assert_eq!(*ip, std::net::Ipv4Addr::UNSPECIFIED);
        }
        other => panic!("expected blackhole A record, got {:?}", other),
    }
}

#[tokio::test]
async fn test_block_aaaa_returns_blackhole_ipv6() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[[upstreams.default]]
name = "test"
endpoint = "223.5.5.5:53"

[block]
enabled = true
blackhole_ipv4 = "198.18.0.1"
blackhole_ipv6 = "fc00::1"
domains = ["tracker.evil.com"]
"#;
    let config = Arc::new(runtime_config::load_from_str(toml_str).unwrap());
    let cache = Arc::new(DnsCache::new(config.cache.clone()));
    let knowledge = Arc::new(BuiltInDomainKnowledge::new());
    let geoip = Arc::new(SimpleGeoIp);
    let pipeline = Pipeline::new(config, cache, knowledge, geoip);

    let wire = build_query_wire(
        "tracker.evil.com",
        dns_types::QType::Type(dns_types::RecordType::AAAA),
    );
    let meta = test_meta();
    let resp = pipeline.resolve(&wire, &meta).await;

    assert_eq!(resp.answers.len(), 1);
    match &resp.answers[0].rdata {
        dns_protocol::rr::RData::AAAA(ip) => {
            assert_eq!(*ip, "fc00::1".parse::<std::net::Ipv6Addr>().unwrap());
        }
        other => panic!("expected blackhole AAAA record, got {:?}", other),
    }
}

#[tokio::test]
async fn test_block_mx_query_returns_soa() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[[upstreams.default]]
name = "test"
endpoint = "223.5.5.5:53"

[block]
enabled = true
domains = ["ads.example.com"]
"#;
    let config = Arc::new(runtime_config::load_from_str(toml_str).unwrap());
    let cache = Arc::new(DnsCache::new(config.cache.clone()));
    let knowledge = Arc::new(BuiltInDomainKnowledge::new());
    let geoip = Arc::new(SimpleGeoIp);
    let pipeline = Pipeline::new(config, cache, knowledge, geoip);

    let wire = build_query_wire(
        "ads.example.com",
        dns_types::QType::Type(dns_types::RecordType::MX),
    );
    let meta = test_meta();
    let resp = pipeline.resolve(&wire, &meta).await;

    // For non-A/AAAA queries, block returns NOERROR with SOA authority.
    assert_eq!(
        resp.header.rcode,
        dns_protocol::header::ResponseCode::NoError
    );
    assert!(resp.answers.is_empty());
    assert_eq!(resp.authorities.len(), 1);
    assert_eq!(resp.authorities[0].rr_type, dns_types::RecordType::SOA);
}

#[tokio::test]
async fn test_block_disabled_does_not_intercept() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[[upstreams.default]]
name = "test"
endpoint = "223.5.5.5:53"

[block]
enabled = false
domains = ["ads.example.com"]
"#;
    let config = Arc::new(runtime_config::load_from_str(toml_str).unwrap());
    let cache = Arc::new(DnsCache::new(config.cache.clone()));
    let knowledge = Arc::new(BuiltInDomainKnowledge::new());
    let geoip = Arc::new(SimpleGeoIp);
    let pipeline = Pipeline::new(config, cache, knowledge, geoip);

    let wire = build_query_wire(
        "ads.example.com",
        dns_types::QType::Type(dns_types::RecordType::A),
    );
    let meta = test_meta();
    let resp = pipeline.resolve(&wire, &meta).await;

    // Block disabled → should NOT return blackhole IP 198.18.0.1.
    for ans in &resp.answers {
        if let dns_protocol::rr::RData::A(ip) = &ans.rdata {
            assert_ne!(
                *ip,
                "198.18.0.1".parse::<std::net::Ipv4Addr>().unwrap(),
                "disabled block should not have intercepted this query"
            );
        }
    }
}

// ─── Hosts + Block Interaction ──────────────────────────────────

#[tokio::test]
async fn test_hosts_override_takes_priority_over_block() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[[upstreams.default]]
name = "test"
endpoint = "223.5.5.5:53"

[hosts]
enabled = true

[hosts.entries]
"example.local" = ["10.0.0.1"]

[block]
enabled = true
domains = ["example.local"]
"#;
    let config = Arc::new(runtime_config::load_from_str(toml_str).unwrap());
    let cache = Arc::new(DnsCache::new(config.cache.clone()));
    let knowledge = Arc::new(BuiltInDomainKnowledge::new());
    let geoip = Arc::new(SimpleGeoIp);
    let pipeline = Pipeline::new(config, cache, knowledge, geoip);

    let wire = build_query_wire(
        "example.local",
        dns_types::QType::Type(dns_types::RecordType::A),
    );
    let meta = test_meta();
    let resp = pipeline.resolve(&wire, &meta).await;

    // Hosts stage runs BEFORE block stage, so hosts should win.
    assert_eq!(resp.answers.len(), 1);
    match &resp.answers[0].rdata {
        dns_protocol::rr::RData::A(ip) => {
            assert_eq!(*ip, "10.0.0.1".parse::<std::net::Ipv4Addr>().unwrap());
        }
        other => panic!("expected hosts A record, got {:?}", other),
    }
}

// ─── Malformed Query ────────────────────────────────────────────

#[tokio::test]
async fn test_pipeline_malformed_query_returns_formerr() {
    let config = Arc::new(test_config());
    let cache = Arc::new(DnsCache::new(config.cache.clone()));
    let knowledge = Arc::new(BuiltInDomainKnowledge::new());
    let geoip = Arc::new(SimpleGeoIp);
    let pipeline = Pipeline::new(config, cache, knowledge, geoip);

    let meta = test_meta();
    let resp = pipeline.resolve(b"\x00", &meta).await;

    assert_eq!(
        resp.header.rcode,
        dns_protocol::header::ResponseCode::FormErr
    );
}
