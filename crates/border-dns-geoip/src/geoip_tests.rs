use super::*;

#[test]
fn test_china_ip_lookup() {
    let geo = SimpleGeoIp;
    let result = geo.lookup("223.5.5.5".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(result.scope, IpGeoScope::Cn);
    assert_eq!(result.country_code.as_deref(), Some("CN"));
}

#[test]
fn test_china_ip_183() {
    let geo = SimpleGeoIp;
    let result = geo.lookup("183.3.0.1".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(result.scope, IpGeoScope::Cn);
}

#[test]
fn test_china_ip_114() {
    let geo = SimpleGeoIp;
    let result = geo.lookup("114.114.114.114".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(result.scope, IpGeoScope::Cn);
}

#[test]
fn test_private_ip() {
    let geo = SimpleGeoIp;
    let result = geo.lookup("192.168.1.1".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(result.scope, IpGeoScope::Private);
    assert!(result.country_code.is_none());
}

#[test]
fn test_reserved_ip() {
    let geo = SimpleGeoIp;
    let result = geo.lookup("0.0.0.0".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(result.scope, IpGeoScope::Reserved);
}

#[test]
fn test_loopback_ip() {
    let geo = SimpleGeoIp;
    let result = geo.lookup("127.0.0.1".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(result.scope, IpGeoScope::Reserved);
}

#[test]
fn test_foreign_ip() {
    let geo = SimpleGeoIp;
    let result = geo.lookup("8.8.8.8".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(result.scope, IpGeoScope::Foreign);
}

#[test]
fn test_cloudflare_ip() {
    let geo = SimpleGeoIp;
    let result = geo.lookup("1.1.1.1".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(result.scope, IpGeoScope::Foreign);
}

#[test]
fn test_ipv6_private() {
    let geo = SimpleGeoIp;
    let result = geo.lookup("fe80::1".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(result.scope, IpGeoScope::Private);
}

#[test]
fn test_ipv6_china() {
    let geo = SimpleGeoIp;
    let result = geo.lookup("2400:3200::1".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(result.scope, IpGeoScope::Cn);
    assert_eq!(result.country_code.as_deref(), Some("CN"));
}

#[test]
fn test_ipv4_mapped() {
    let geo = SimpleGeoIp;
    let result = geo.lookup("::ffff:192.168.1.1".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(result.scope, IpGeoScope::Private);
}

#[test]
fn test_trait_object() {
    let geo: Box<dyn GeoIpLookup> = Box::new(SimpleGeoIp);
    let result = geo.lookup("1.1.1.1".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(result.scope, IpGeoScope::Foreign);
}
