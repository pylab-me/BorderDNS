use super::*;

#[test]
fn test_config_minimal_valid() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[[upstreams.default]]
name = "alidns"
endpoint = "223.5.5.5:53"
"#;
    let config: RuntimeConfig = toml::from_str(toml_str).unwrap();
    assert!(config.validate().is_ok());
}

#[test]
fn test_config_no_listener_rejected() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = false

[[upstreams.default]]
name = "alidns"
endpoint = "223.5.5.5:53"
"#;
    let config: RuntimeConfig = toml::from_str(toml_str).unwrap();
    assert!(config.validate().is_err());
}

#[test]
fn test_config_dot_listener() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[listeners.dot]
enabled = true
listen = "0.0.0.0:853"
cert_file = "./certs/server.crt"
key_file = "./certs/server.key"

[[upstreams.default]]
name = "alidns"
endpoint = "223.5.5.5:53"
"#;
    let config: RuntimeConfig = toml::from_str(toml_str).unwrap();
    assert!(config.validate().is_ok());
    let dot = config.listeners.dot.unwrap();
    assert!(dot.enabled);
    assert_eq!(dot.listen, "0.0.0.0:853");
}

#[test]
fn test_config_doh_listener() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[listeners.doh]
enabled = true
listen = "0.0.0.0:8443"
path = "/dns-query"
cert_file = "./certs/server.crt"
key_file = "./certs/server.key"

[[upstreams.default]]
name = "alidns"
endpoint = "223.5.5.5:53"
"#;
    let config: RuntimeConfig = toml::from_str(toml_str).unwrap();
    assert!(config.validate().is_ok());
    let doh = config.listeners.doh.unwrap();
    assert_eq!(doh.path, "/dns-query");
    assert!(doh.allow_get);
    assert!(doh.allow_post);
}

#[test]
fn test_config_doq_listener() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[listeners.doq]
enabled = true
listen = "0.0.0.0:8853"
cert_file = "./certs/server.crt"
key_file = "./certs/server.key"

[[upstreams.default]]
name = "alidns"
endpoint = "223.5.5.5:53"
"#;
    let config: RuntimeConfig = toml::from_str(toml_str).unwrap();
    assert!(config.validate().is_ok());
    let doq = config.listeners.doq.unwrap();
    assert_eq!(doq.alpn, vec!["doq".to_string()]);
}

#[test]
fn test_config_doh_upstream() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[[upstreams.default]]
name = "cloudflare-doh"
transport = "https"
endpoint = "https://1.1.1.1/dns-query"

[[upstreams.default]]
name = "cloudflare-dot"
transport = "tls"
endpoint = "1.1.1.1:853"
server_name = "cloudflare-dns.com"
"#;
    let config: RuntimeConfig = toml::from_str(toml_str).unwrap();
    assert!(config.validate().is_ok());
    assert_eq!(config.upstreams.default.len(), 2);
    assert_eq!(config.upstreams.default[0].transport, DnsProtocol::Https);
    assert_eq!(config.upstreams.default[1].transport, DnsProtocol::Tls);
    assert_eq!(
        config.upstreams.default[1].server_name.as_deref(),
        Some("cloudflare-dns.com")
    );
}

#[test]
fn test_config_upstream_tls_no_server_name_rejected() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[[upstreams.default]]
name = "broken-dot"
transport = "tls"
endpoint = "1.1.1.1:853"
"#;
    let config: RuntimeConfig = toml::from_str(toml_str).unwrap();
    assert!(config.validate().is_err());
}

#[test]
fn test_config_doh_bad_endpoint_rejected() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[[upstreams.default]]
name = "broken-doh"
transport = "https"
endpoint = "not-a-url"
"#;
    let config: RuntimeConfig = toml::from_str(toml_str).unwrap();
    assert!(config.validate().is_err());
}

#[test]
fn test_config_empty_upstreams_rejected() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[upstreams]
default = []
"#;
    let config: RuntimeConfig = toml::from_str(toml_str).unwrap();
    assert!(config.validate().is_err());
}

#[test]
fn test_config_bootstrap_only() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[[upstreams.bootstrap]]
name = "alidns"
endpoint = "223.5.5.5:53"
"#;
    let config: RuntimeConfig = toml::from_str(toml_str).unwrap();
    assert!(config.validate().is_ok());
    assert!(config.upstreams.is_route_aware());
    assert_eq!(config.upstreams.bootstrap.len(), 1);
    assert!(config.upstreams.default.is_empty());
}

#[test]
fn test_config_default_only() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[[upstreams.default]]
name = "alidns"
endpoint = "223.5.5.5:53"
"#;
    let config: RuntimeConfig = toml::from_str(toml_str).unwrap();
    assert!(config.validate().is_ok());
    assert!(!config.upstreams.is_route_aware());
    assert_eq!(config.upstreams.default_upstreams().len(), 1);
}

#[test]
fn test_config_bootstrap_with_china_foreign() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[[upstreams.bootstrap]]
name = "bootstrap"
endpoint = "223.5.5.5:53"

[[upstreams.china]]
name = "alidns"
endpoint = "223.5.5.5:53"

[[upstreams.foreign]]
name = "cloudflare"
endpoint = "1.1.1.1:53"
"#;
    let config: RuntimeConfig = toml::from_str(toml_str).unwrap();
    assert!(config.validate().is_ok());
    assert!(config.upstreams.is_route_aware());
}

#[test]
fn test_config_no_bootstrap_no_default_rejected() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[[upstreams.china]]
name = "alidns"
endpoint = "223.5.5.5:53"
"#;
    let config: RuntimeConfig = toml::from_str(toml_str).unwrap();
    assert!(config.validate().is_err());
}

#[test]
fn test_dns_protocol_as_str() {
    assert_eq!(DnsProtocol::Udp.as_str(), "udp");
    assert_eq!(DnsProtocol::Tcp.as_str(), "tcp");
    assert_eq!(DnsProtocol::Tls.as_str(), "tls");
    assert_eq!(DnsProtocol::Https.as_str(), "https");
    assert_eq!(DnsProtocol::Quic.as_str(), "quic");
}

#[test]
fn test_listener_addr_parse() {
    let addr: ListenerAddr = "udp://0.0.0.0:5353".parse().unwrap();
    assert_eq!(addr.protocol, DnsProtocol::Udp);
    assert_eq!(addr.addr, "0.0.0.0:5353");
}

#[test]
fn test_config_serialize_roundtrip() {
    let config = RuntimeConfig {
        server: ServerConfig {
            default_timeout_ms: 5000,
            graceful_shutdown_ms: 10_000,
            max_concurrent: 256,
        },
        listeners: ListenersConfig {
            udp: Some(UdpListenerConfig {
                enabled: true,
                listen: "0.0.0.0:5353".into(),
                ipv6_only: None,
            }),
            ..ListenersConfig::default()
        },
        upstreams: UpstreamGroupConfig {
            default: vec![UpstreamServer {
                name: "test".into(),
                transport: DnsProtocol::Udp,
                endpoint: "223.5.5.5:53".into(),
                server_name: None,
                timeout_ms: 3000,
            }],
            china: Vec::new(),
            foreign: Vec::new(),
            bootstrap: Vec::new(),
        },
        cache: CacheConfig::default(),
        resolver: ResolverConfig::default(),
        third_party: ThirdPartyConfig::default(),
        hosts: HostsConfig::default(),
        block: BlockConfig::default(),
        blackhole: BlackholeConfig::default(),
    };

    let toml_str = toml::to_string(&config).unwrap();
    let parsed: RuntimeConfig = toml::from_str(&toml_str).unwrap();
    assert_eq!(parsed.server.default_timeout_ms, 5000);
    assert_eq!(parsed.upstreams.default.len(), 1);
}

#[test]
fn test_config_defaults() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[[upstreams.default]]
name = "test"
endpoint = "223.5.5.5:53"
"#;
    let config: RuntimeConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.server.default_timeout_ms, 3000);
    assert_eq!(config.server.graceful_shutdown_ms, 5000);
    assert_eq!(config.cache.max_entries, 4096);
    assert_eq!(
        config.resolver.location,
        dns_types::ResolverLocation::Unknown
    );
    assert_eq!(config.upstreams.default[0].transport, DnsProtocol::Udp);
}

#[test]
fn test_dot_tls_empty_cert_rejected() {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true

[listeners.dot]
enabled = true
listen = "0.0.0.0:853"
cert_file = ""
key_file = "./certs/server.key"

[[upstreams.default]]
name = "test"
endpoint = "223.5.5.5:53"
"#;
    let config: RuntimeConfig = toml::from_str(toml_str).unwrap();
    assert!(config.validate().is_err());
}
