use super::*;

#[test]
fn test_parse_socket_addr_valid() {
    let addr = parse_socket_addr("223.5.5.5:53").unwrap();
    assert_eq!(addr, "223.5.5.5:53".parse::<SocketAddr>().unwrap());
}

#[test]
fn test_parse_socket_addr_invalid() {
    assert!(parse_socket_addr("not-an-address").is_err());
}

#[test]
fn test_parse_socket_addr_ipv6() {
    let addr = parse_socket_addr("[::1]:53").unwrap();
    assert!(addr.is_ipv6());
}
