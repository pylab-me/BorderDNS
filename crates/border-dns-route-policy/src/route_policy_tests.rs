use std::net::Ipv4Addr;

use border_dns_domain_knowledge::BuiltInDomainKnowledge;

use super::*;

fn test_geoip() -> border_dns_geoip::SimpleGeoIp {
    border_dns_geoip::SimpleGeoIp
}

#[test]
fn test_china_domain_prior() {
    let policy = RoutePolicy::new(ResolverLocation::China);
    let knowledge = BuiltInDomainKnowledge::new();
    let decision = policy.decide_by_domain_prior("qq.com", &knowledge);
    assert_eq!(decision.execution_route, Route::China);
    assert_eq!(decision.route_source, RouteSource::DomainPrior);
    assert_eq!(decision.confidence, Confidence::Strong);
}

#[test]
fn test_foreign_domain_prior() {
    let policy = RoutePolicy::new(ResolverLocation::China);
    let knowledge = BuiltInDomainKnowledge::new();
    let decision = policy.decide_by_domain_prior("openai.com", &knowledge);
    assert_eq!(decision.execution_route, Route::Foreign);
    assert_eq!(decision.confidence, Confidence::Strong);
}

#[test]
fn test_unknown_domain_fallback() {
    let policy = RoutePolicy::new(ResolverLocation::China);
    let knowledge = BuiltInDomainKnowledge::new();
    let decision = policy.decide_by_domain_prior("unknown-xyz.com", &knowledge);
    assert_eq!(decision.execution_route, Route::China);
    assert_eq!(decision.confidence, Confidence::None);
}

#[test]
fn test_unknown_domain_foreign_location() {
    let policy = RoutePolicy::new(ResolverLocation::Foreign);
    let knowledge = BuiltInDomainKnowledge::new();
    let decision = policy.decide_by_domain_prior("unknown-xyz.com", &knowledge);
    assert_eq!(decision.execution_route, Route::Foreign);
}

#[test]
fn test_cname_refine_boosts_china() {
    let policy = RoutePolicy::new(ResolverLocation::China);
    let knowledge = BuiltInDomainKnowledge::new();
    let mut decision = policy.decide_by_domain_prior("qq.com", &knowledge);
    let cnames = vec!["cdn.example.com", "alicdn.com"];
    policy.refine_by_cname(&mut decision, &cnames, &knowledge);
    assert_eq!(decision.confidence, Confidence::Strong);
}

#[test]
fn test_answer_geo_analysis() {
    let policy = RoutePolicy::new(ResolverLocation::China);
    let geoip = test_geoip();

    let answers = vec![
        dns_protocol::rr::ResourceRecord {
            name: dns_protocol::name::DomainName::from_str("example.com").unwrap(),
            rr_type: dns_protocol::types::RecordType::A,
            class: dns_protocol::types::RecordClass::In,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(223, 5, 5, 5)),
        },
        dns_protocol::rr::ResourceRecord {
            name: dns_protocol::name::DomainName::from_str("example.com").unwrap(),
            rr_type: dns_protocol::types::RecordType::A,
            class: dns_protocol::types::RecordClass::In,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(1, 1, 1, 1)),
        },
    ];

    let evidence = policy.analyze_answer_geo(&answers, &geoip);
    assert_eq!(evidence.cn_count, 1);
    assert_eq!(evidence.foreign_count, 1);
    assert_eq!(evidence.total, 2);
}

#[test]
fn test_select_candidates_china_route() {
    let policy = RoutePolicy::new(ResolverLocation::China);
    let geoip = test_geoip();

    let answers = vec![
        dns_protocol::rr::ResourceRecord {
            name: dns_protocol::name::DomainName::from_str("example.com").unwrap(),
            rr_type: dns_protocol::types::RecordType::A,
            class: dns_protocol::types::RecordClass::In,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(1, 1, 1, 1)),
        },
        dns_protocol::rr::ResourceRecord {
            name: dns_protocol::name::DomainName::from_str("example.com").unwrap(),
            rr_type: dns_protocol::types::RecordType::A,
            class: dns_protocol::types::RecordClass::In,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(223, 5, 5, 5)),
        },
    ];

    let selected = policy.select_answer_candidates(&answers, &geoip, Route::China);
    assert_eq!(selected.len(), 2);
    if let RData::A(addr) = &selected[0].rdata {
        assert_eq!(*addr, Ipv4Addr::new(223, 5, 5, 5));
    } else {
        panic!("Expected A record first");
    }
}

#[test]
fn test_select_candidates_foreign_location() {
    let policy = RoutePolicy::new(ResolverLocation::Foreign);
    let geoip = test_geoip();

    let answers = vec![
        dns_protocol::rr::ResourceRecord {
            name: dns_protocol::name::DomainName::from_str("example.com").unwrap(),
            rr_type: dns_protocol::types::RecordType::A,
            class: dns_protocol::types::RecordClass::In,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(1, 1, 1, 1)),
        },
        dns_protocol::rr::ResourceRecord {
            name: dns_protocol::name::DomainName::from_str("example.com").unwrap(),
            rr_type: dns_protocol::types::RecordType::A,
            class: dns_protocol::types::RecordClass::In,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(223, 5, 5, 5)),
        },
    ];

    let selected = policy.select_answer_candidates(&answers, &geoip, Route::China);
    assert_eq!(selected.len(), 2);
}

#[test]
fn test_route_decision_default() {
    let decision = RouteDecision::default();
    assert_eq!(decision.execution_route, Route::Fallback);
    assert_eq!(decision.confidence, Confidence::None);
}
