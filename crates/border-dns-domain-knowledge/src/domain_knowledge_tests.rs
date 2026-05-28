use dns_types::CnameHint;
use dns_types::DomainPrior;
use dns_types::QType;
use dns_types::RecordType;

use crate::BuiltInDomainKnowledge;
use crate::DomainKnowledge;
use crate::HostsTable;

#[test]
fn test_china_domain_classification() {
    let knowledge = BuiltInDomainKnowledge::new();
    assert_eq!(knowledge.classify_domain("qq.com"), DomainPrior::China);
    assert_eq!(knowledge.classify_domain("taobao.com"), DomainPrior::China);
    assert_eq!(knowledge.classify_domain("baidu.com"), DomainPrior::China);
    assert_eq!(knowledge.classify_domain("xiaomi.com"), DomainPrior::China);
    assert_eq!(
        knowledge.classify_domain("bilibili.com"),
        DomainPrior::China
    );
}

#[test]
fn test_china_domain_with_trailing_dot() {
    let knowledge = BuiltInDomainKnowledge::new();
    assert_eq!(knowledge.classify_domain("qq.com."), DomainPrior::China);
}

#[test]
fn test_foreign_domain_classification() {
    let knowledge = BuiltInDomainKnowledge::new();
    assert_eq!(
        knowledge.classify_domain("openai.com"),
        DomainPrior::Foreign
    );
    assert_eq!(
        knowledge.classify_domain("github.com"),
        DomainPrior::Foreign
    );
    assert_eq!(
        knowledge.classify_domain("google.com"),
        DomainPrior::Foreign
    );
    assert_eq!(
        knowledge.classify_domain("youtube.com"),
        DomainPrior::Foreign
    );
}

#[test]
fn test_cdn_domain_classification() {
    let knowledge = BuiltInDomainKnowledge::new();
    assert_eq!(
        knowledge.classify_domain("cloudflare.com"),
        DomainPrior::GlobalCdn
    );
    assert_eq!(
        knowledge.classify_domain("akamaized.net"),
        DomainPrior::GlobalCdn
    );
    assert_eq!(
        knowledge.classify_domain("cloudfront.net"),
        DomainPrior::GlobalCdn
    );
}

#[test]
fn test_unknown_domain() {
    let knowledge = BuiltInDomainKnowledge::new();
    assert_eq!(
        knowledge.classify_domain("random-unknown-domain-xyz.com"),
        DomainPrior::Unknown
    );
}

#[test]
fn test_cname_china_provider() {
    let knowledge = BuiltInDomainKnowledge::new();
    let cnames = vec!["cdn.example.com", "something.chinacache.com"];
    assert_eq!(
        knowledge.classify_cname_chain(&cnames),
        CnameHint::ChinaProvider
    );
}

#[test]
fn test_cname_foreign_provider() {
    let knowledge = BuiltInDomainKnowledge::new();
    let cnames = vec!["cdn.example.com", "cloudflare.com"];
    assert_eq!(
        knowledge.classify_cname_chain(&cnames),
        CnameHint::GlobalCdn
    );
}

#[test]
fn test_cname_none() {
    let knowledge = BuiltInDomainKnowledge::new();
    let cnames = vec!["cdn.unknown-provider.com"];
    assert_eq!(knowledge.classify_cname_chain(&cnames), CnameHint::None);
}

#[test]
fn test_domain_set_size() {
    let knowledge = BuiltInDomainKnowledge::new();
    assert!(knowledge.china_domains.len() > 0);
    assert!(knowledge.foreign_domains.len() > 0);
}

// ─── HostsTable tests ─────────────────────────────────────────────

#[test]
fn test_hosts_table_inline_entry_match_a() {
    let table = HostsTable::new()
        .with_entry("example.com", "1.2.3.4")
        .with_entry("example.com", "::1")
        .build();

    let result = table.match_domain("example.com", QType::Type(RecordType::A));
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], "1.2.3.4".parse::<std::net::IpAddr>().unwrap());
}

#[test]
fn test_hosts_table_inline_entry_match_aaaa() {
    let table = HostsTable::new()
        .with_entry("example.com", "1.2.3.4")
        .with_entry("example.com", "2001:db8::1")
        .build();

    let result = table.match_domain("example.com", QType::Type(RecordType::AAAA));
    assert_eq!(result.len(), 1);
    assert_eq!(
        result[0],
        "2001:db8::1".parse::<std::net::IpAddr>().unwrap()
    );
}

#[test]
fn test_hosts_table_no_match() {
    let table = HostsTable::new()
        .with_entry("example.com", "1.2.3.4")
        .build();

    let result = table.match_domain("other.com", QType::Type(RecordType::A));
    assert!(result.is_empty());
}

#[test]
fn test_hosts_table_trailing_dot_handling() {
    let table = HostsTable::new()
        .with_entry("example.com", "1.2.3.4")
        .build();

    let result = table.match_domain("example.com.", QType::Type(RecordType::A));
    assert_eq!(result.len(), 1);
}

#[test]
fn test_hosts_table_non_a_aaaa_qtype_returns_empty() {
    let table = HostsTable::new()
        .with_entry("example.com", "1.2.3.4")
        .build();

    let result = table.match_domain("example.com", QType::Type(RecordType::MX));
    assert!(result.is_empty());
}
