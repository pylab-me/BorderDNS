use std::net::Ipv4Addr;

use dns_protocol::question::DnsQuestion;
use dns_protocol::rr::RData;
use dns_protocol::rr::ResourceRecord;
use dns_types::QClass;
use dns_types::RecordClass;
use dns_types::RecordType;

use super::*;

fn make_test_response(name: &str, ip: Ipv4Addr, ttl: u32) -> DnsMessage {
    let q = DnsQuestion::new(
        DomainName::from_str(name).unwrap(),
        QType::Type(RecordType::A),
        QClass::Class(RecordClass::In),
    );
    let mut msg = DnsMessage::query(0x1234, q);
    msg.header.qr = true;
    msg.add_answer(ResourceRecord {
        name: DomainName::from_str(name).unwrap(),
        rr_type: RecordType::A,
        class: RecordClass::In,
        ttl,
        rdata: RData::A(ip),
    });
    msg
}

#[test]
fn test_cache_hit_and_miss() {
    let config = CacheConfig::default();
    let cache = DnsCache::new(config);
    let name = DomainName::from_str("example.com").unwrap();
    let qtype = QType::Type(RecordType::A);

    // Miss.
    assert!(cache.get(qtype, &name).is_none());
    assert_eq!(cache.stats().misses, 1);

    // Insert.
    let resp = make_test_response("example.com", Ipv4Addr::new(1, 2, 3, 4), 300);
    cache.insert(qtype, &name, &resp);

    // Hit.
    let cached = cache.get(qtype, &name).unwrap();
    assert_eq!(cached.message().header.id, 0x1234);
    assert_eq!(cache.stats().hits, 1);
}

#[test]
fn test_ttl_clamping() {
    let config = CacheConfig {
        min_ttl_secs: 10,
        max_ttl_secs: 3600,
        ..CacheConfig::default()
    };
    let cache = DnsCache::new(config);
    let name = DomainName::from_str("example.com").unwrap();
    let qtype = QType::Type(RecordType::A);

    // TTL below min should be clamped to min.
    let resp = make_test_response("example.com", Ipv4Addr::new(1, 2, 3, 4), 1);
    cache.insert(qtype, &name, &resp);

    let cached = cache.get(qtype, &name).unwrap();
    assert_eq!(cached.message().answers[0].ttl, 10);
}

#[test]
fn test_negative_cache() {
    let config = CacheConfig {
        negative_ttl_secs: 5,
        ..CacheConfig::default()
    };
    let cache = DnsCache::new(config);
    let name = DomainName::from_str("nonexistent.example.com").unwrap();
    let qtype = QType::Type(RecordType::A);

    let resp = make_test_response("nonexistent.example.com", Ipv4Addr::new(0, 0, 0, 0), 0);
    cache.insert_negative(qtype, &name, &resp);

    // Should be in cache.
    assert!(cache.get(qtype, &name).is_some());
}

#[test]
fn test_clear() {
    let config = CacheConfig::default();
    let cache = DnsCache::new(config);
    let name = DomainName::from_str("example.com").unwrap();
    let qtype = QType::Type(RecordType::A);

    let resp = make_test_response("example.com", Ipv4Addr::new(1, 2, 3, 4), 300);
    cache.insert(qtype, &name, &resp);
    assert!(cache.get(qtype, &name).is_some());

    cache.clear();
    assert!(cache.get(qtype, &name).is_none());
}

#[test]
fn test_cache_returns_arc_no_deep_clone() {
    let config = CacheConfig::default();
    let cache = DnsCache::new(config);
    let name = DomainName::from_str("example.com").unwrap();
    let qtype = QType::Type(RecordType::A);

    let resp = make_test_response("example.com", Ipv4Addr::new(1, 2, 3, 4), 300);
    cache.insert(qtype, &name, &resp);

    let cached1 = cache.get(qtype, &name).unwrap();
    let cached2 = cache.get(qtype, &name).unwrap();
    // Both should point to the same Arc allocation.
    assert!(Arc::ptr_eq(cached1.wire(), cached2.wire()));
    assert!(Arc::ptr_eq(cached1.message(), cached2.message()));
}
