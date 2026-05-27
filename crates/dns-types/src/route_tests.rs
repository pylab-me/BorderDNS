use super::*;

#[test]
fn test_route_display() {
    assert_eq!(Route::China.to_string(), "china");
    assert_eq!(Route::Foreign.to_string(), "foreign");
    assert_eq!(Route::Bootstrap.to_string(), "bootstrap");
    assert_eq!(Route::Fallback.to_string(), "fallback");
}

#[test]
fn test_route_default() {
    assert_eq!(Route::default(), Route::Fallback);
}

#[test]
fn test_resolver_location_default() {
    assert_eq!(ResolverLocation::default(), ResolverLocation::Unknown);
}

#[test]
fn test_domain_prior_display() {
    assert_eq!(DomainPrior::China.as_str(), "china");
    assert_eq!(DomainPrior::Foreign.as_str(), "foreign");
    assert_eq!(DomainPrior::GlobalCdn.as_str(), "global_cdn");
    assert_eq!(DomainPrior::Unknown.as_str(), "unknown");
}

#[test]
fn test_ip_geo_scope_display() {
    assert_eq!(IpGeoScope::Cn.as_str(), "cn");
    assert_eq!(IpGeoScope::Foreign.as_str(), "foreign");
    assert_eq!(IpGeoScope::Private.as_str(), "private");
    assert_eq!(IpGeoScope::Reserved.as_str(), "reserved");
}

#[test]
fn test_confidence_ordering() {
    assert!(Confidence::None < Confidence::Weak);
    assert!(Confidence::Weak < Confidence::Moderate);
    assert!(Confidence::Moderate < Confidence::Strong);
}

#[test]
fn test_route_source_display() {
    assert_eq!(RouteSource::DomainPrior.as_str(), "domain_prior");
    assert_eq!(RouteSource::GeoIpEvidence.as_str(), "geoip_evidence");
    assert_eq!(RouteSource::CnameEvidence.as_str(), "cname_evidence");
    assert_eq!(RouteSource::DefaultPolicy.as_str(), "default_policy");
    assert_eq!(RouteSource::FallbackPolicy.as_str(), "fallback_policy");
}

#[test]
fn test_reason_code_display() {
    assert_eq!(ReasonCode::DomainPriorCn.as_str(), "domain_prior_cn");
    assert_eq!(ReasonCode::MixedGeo.as_str(), "mixed_geo");
    assert_eq!(ReasonCode::DefaultRoute.as_str(), "default_route");
}

#[test]
fn test_cname_hint_display() {
    assert_eq!(CnameHint::ChinaProvider.as_str(), "china_provider");
    assert_eq!(CnameHint::ForeignProvider.as_str(), "foreign_provider");
    assert_eq!(CnameHint::GlobalCdn.as_str(), "global_cdn");
    assert_eq!(CnameHint::None.as_str(), "none");
}

#[test]
fn test_route_serialize_roundtrip() {
    let route = Route::China;
    let json = serde_json::to_string(&route).unwrap();
    let parsed: Route = serde_json::from_str(&json).unwrap();
    assert_eq!(route, parsed);
}
