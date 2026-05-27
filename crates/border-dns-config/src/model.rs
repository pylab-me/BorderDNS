//! Configuration model for BorderDNS runtime.
//!
//! Sprint 1-1: Supports named listeners for UDP, TCP, DoT, DoH, DoQ, DoJ
//! with per-listener TLS certificate configuration and expanded upstream
//! transport types.

use serde::Deserialize;
use serde::Serialize;

use crate::error::ConfigError;

// ─── Top-level config ─────────────────────────────────────────────

/// Top-level BorderDNS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server-level defaults (timeouts, concurrency).
    pub server: ServerConfig,
    /// Named listener configurations.
    pub listeners: ListenersConfig,
    /// Upstream resolver configuration.
    pub upstreams: UpstreamGroupConfig,
    /// Cache configuration.
    #[serde(default)]
    pub cache: CacheConfig,
    /// Resolver configuration.
    #[serde(default)]
    pub resolver: ResolverConfig,
}

impl Config {
    /// Validate the configuration.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::Validation` if any field is invalid.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // At least one listener must be enabled.
        if !self.listeners.any_enabled() {
            return Err(ConfigError::Validation(
                "at least one listener must be enabled".into(),
            ));
        }

        // Validate listen addresses.
        if let Some(ref udp) = self.listeners.udp {
            if udp.enabled {
                validate_socket_addr(&udp.listen, "listeners.udp.listen")?;
            }
        }
        if let Some(ref tcp) = self.listeners.tcp {
            if tcp.enabled {
                validate_socket_addr(&tcp.listen, "listeners.tcp.listen")?;
            }
        }
        if let Some(ref dot) = self.listeners.dot {
            if dot.enabled {
                validate_socket_addr(&dot.listen, "listeners.dot.listen")?;
                validate_tls_paths(dot.cert_file.as_str(), dot.key_file.as_str())?;
            }
        }
        if let Some(ref doh) = self.listeners.doh {
            if doh.enabled {
                validate_socket_addr(&doh.listen, "listeners.doh.listen")?;
                validate_tls_paths(doh.cert_file.as_str(), doh.key_file.as_str())?;
            }
        }
        if let Some(ref doq) = self.listeners.doq {
            if doq.enabled {
                validate_socket_addr(&doq.listen, "listeners.doq.listen")?;
                validate_tls_paths(doq.cert_file.as_str(), doq.key_file.as_str())?;
            }
        }
        if let Some(ref doj) = self.listeners.doj {
            if doj.enabled {
                validate_socket_addr(&doj.listen, "listeners.doj.listen")?;
            }
        }

        // Validate upstreams.
        if self.upstreams.default.is_empty() {
            return Err(ConfigError::Validation(
                "at least one default upstream is required".into(),
            ));
        }
        for server in &self.upstreams.default {
            server.validate()?;
        }

        Ok(())
    }
}

// ─── Server config ────────────────────────────────────────────────

/// Server-level defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Default per-request timeout in milliseconds (default: 3000).
    #[serde(default = "default_timeout_ms")]
    pub default_timeout_ms: u64,
    /// Graceful shutdown timeout in milliseconds (default: 5000).
    #[serde(default = "default_graceful_shutdown_ms")]
    pub graceful_shutdown_ms: u64,
    /// Maximum concurrent requests (default: 1024).
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            default_timeout_ms: default_timeout_ms(),
            graceful_shutdown_ms: default_graceful_shutdown_ms(),
            max_concurrent: default_max_concurrent(),
        }
    }
}

// ─── Listeners config ─────────────────────────────────────────────

/// Named listener configurations. Each transport type is optional;
/// only enabled listeners are started.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListenersConfig {
    pub udp: Option<UdpListenerConfig>,
    pub tcp: Option<TcpListenerConfig>,
    pub dot: Option<TlsListenerConfig>,
    pub doh: Option<DoHListenerConfig>,
    pub doq: Option<DoQListenerConfig>,
    pub doj: Option<DoJListenerConfig>,
}

impl ListenersConfig {
    /// Whether any listener is enabled.
    #[must_use]
    pub fn any_enabled(&self) -> bool {
        self.udp.as_ref().is_some_and(|l| l.enabled)
            || self.tcp.as_ref().is_some_and(|l| l.enabled)
            || self.dot.as_ref().is_some_and(|l| l.enabled)
            || self.doh.as_ref().is_some_and(|l| l.enabled)
            || self.doq.as_ref().is_some_and(|l| l.enabled)
            || self.doj.as_ref().is_some_and(|l| l.enabled)
    }
}

/// UDP DNS listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpListenerConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Socket address (e.g., "0.0.0.0:5353").
    #[serde(default = "default_udp_listen")]
    pub listen: String,
}

impl Default for UdpListenerConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            listen: default_udp_listen(),
        }
    }
}

/// TCP DNS listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpListenerConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Socket address (e.g., "0.0.0.0:5353").
    #[serde(default = "default_tcp_listen")]
    pub listen: String,
}

impl Default for TcpListenerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_tcp_listen(),
        }
    }
}

/// TLS-based listener configuration (shared by DoT, DoH, DoQ).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsListenerConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Socket address (e.g., "0.0.0.0:853").
    pub listen: String,
    /// Path to TLS certificate file (PEM).
    pub cert_file: String,
    /// Path to TLS private key file (PEM).
    pub key_file: String,
    /// Connection idle timeout in milliseconds (default: 30000).
    #[serde(default = "default_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
}

/// DNS-over-HTTPS listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoHListenerConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Socket address (e.g., "0.0.0.0:8443").
    pub listen: String,
    /// DoH endpoint path (default: "/dns-query").
    #[serde(default = "default_doh_path")]
    pub path: String,
    /// Path to TLS certificate file (PEM).
    pub cert_file: String,
    /// Path to TLS private key file (PEM).
    pub key_file: String,
    /// Allow GET queries (RFC 8484 Section 2.1).
    #[serde(default = "default_true")]
    pub allow_get: bool,
    /// Allow POST queries (RFC 8484 Section 4.1).
    #[serde(default = "default_true")]
    pub allow_post: bool,
}

/// DNS-over-QUIC listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoQListenerConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Socket address (e.g., "0.0.0.0:8853").
    pub listen: String,
    /// Path to TLS certificate file (PEM).
    pub cert_file: String,
    /// Path to TLS private key file (PEM).
    pub key_file: String,
    /// ALPN protocol identifiers (default: ["doq"]).
    #[serde(default = "default_doq_alpn")]
    pub alpn: Vec<String>,
}

/// DNS-over-JSON facade listener configuration.
///
/// DoJ is not a strong-standard transport like DoH/DoT/DoQ.
/// It provides a JSON query/response facade (RFC 8427-inspired).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoJListenerConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Socket address (e.g., "0.0.0.0:8080").
    pub listen: String,
    /// DoJ endpoint path (default: "/resolve").
    #[serde(default = "default_doj_path")]
    pub path: String,
    /// Profile: "borderdns" or "google-compat".
    #[serde(default = "default_doj_profile")]
    pub profile: String,
}

// ─── Upstream config ──────────────────────────────────────────────

/// Upstream resolver group configuration.
///
/// Supports named upstream groups: `default`, `china`, `foreign`.
/// Route-aware pipeline selects the upstream group based on the
/// execution route for each query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamGroupConfig {
    /// Default upstream servers (fallback for all routes).
    #[serde(default)]
    pub default: Vec<UpstreamServer>,
    /// China-specific upstream servers (used when route = China).
    #[serde(default)]
    pub china: Vec<UpstreamServer>,
    /// Foreign-specific upstream servers (used when route = Foreign).
    #[serde(default)]
    pub foreign: Vec<UpstreamServer>,
}

impl UpstreamGroupConfig {
    /// Get upstream servers for a given route.
    ///
    /// Falls back to `default` if the route-specific group is empty.
    #[must_use]
    pub fn for_route(&self, route: dns_types::Route) -> &[UpstreamServer] {
        let group = match route {
            dns_types::Route::China => &self.china,
            dns_types::Route::Foreign => &self.foreign,
            dns_types::Route::Bootstrap | dns_types::Route::Fallback => &self.default,
        };
        if group.is_empty() {
            &self.default
        } else {
            group
        }
    }
}

/// A single upstream DNS server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamServer {
    /// Human-readable name for metrics/logging.
    #[serde(default = "default_upstream_name")]
    pub name: String,
    /// Transport protocol.
    #[serde(default = "default_upstream_transport")]
    pub transport: DnsProtocol,
    /// Server endpoint.
    /// For UDP/TCP: "223.5.5.5:53"
    /// For TLS: "1.1.1.1:853"
    /// For HTTPS: "https://1.1.1.1/dns-query"
    /// For QUIC: "1.1.1.1:853"
    pub endpoint: String,
    /// TLS server name for SNI (required for TLS/HTTPS/QUIC).
    pub server_name: Option<String>,
    /// Per-upstream timeout in milliseconds (default: 3000).
    #[serde(default = "default_upstream_timeout_ms")]
    pub timeout_ms: u64,
}

impl UpstreamServer {
    /// Validate the upstream server configuration.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::Validation` if the configuration is invalid.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.endpoint.is_empty() {
            return Err(ConfigError::Validation(format!(
                "upstream '{}' endpoint must not be empty",
                self.name
            )));
        }
        match self.transport {
            DnsProtocol::Udp | DnsProtocol::Tcp => {
                // Endpoint must be host:port
                if !self.endpoint.contains(':') {
                    return Err(ConfigError::Validation(format!(
                        "upstream '{}' endpoint must be in 'host:port' format for {}",
                        self.name,
                        self.transport.as_str()
                    )));
                }
            }
            DnsProtocol::Https => {
                // Endpoint must be a URL
                if !self.endpoint.starts_with("http://") && !self.endpoint.starts_with("https://") {
                    return Err(ConfigError::Validation(format!(
                        "upstream '{}' endpoint must be a URL for DoH (e.g., https://1.1.1.1/dns-query)",
                        self.name
                    )));
                }
            }
            DnsProtocol::Tls | DnsProtocol::Quic => {
                // Endpoint must be host:port, server_name required
                if !self.endpoint.contains(':') {
                    return Err(ConfigError::Validation(format!(
                        "upstream '{}' endpoint must be in 'host:port' format for {}",
                        self.name,
                        self.transport.as_str()
                    )));
                }
                if self.server_name.is_none() {
                    return Err(ConfigError::Validation(format!(
                        "upstream '{}' requires server_name for {}",
                        self.name,
                        self.transport.as_str()
                    )));
                }
            }
        }
        Ok(())
    }
}

// ─── DNS Protocol (transport types) ───────────────────────────────

/// DNS transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsProtocol {
    /// UDP DNS (RFC 1035).
    Udp,
    /// TCP DNS (RFC 7766).
    Tcp,
    /// DNS over TLS (RFC 7858).
    Tls,
    /// DNS over HTTPS (RFC 8484).
    Https,
    /// DNS over QUIC (RFC 9250).
    Quic,
}

impl DnsProtocol {
    /// Human-readable name.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::Https => "https",
            Self::Quic => "quic",
        }
    }
}

impl Default for DnsProtocol {
    fn default() -> Self {
        Self::Udp
    }
}

impl std::fmt::Display for DnsProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── Cache config ─────────────────────────────────────────────────

/// Cache configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Maximum number of cache entries (default: 4096).
    #[serde(default = "default_max_cache_entries")]
    pub max_entries: usize,
    /// Minimum TTL in seconds (default: 5).
    #[serde(default = "default_min_ttl")]
    pub min_ttl_secs: u32,
    /// Maximum TTL in seconds (default: 86400 = 24 hours).
    #[serde(default = "default_max_ttl")]
    pub max_ttl_secs: u32,
    /// Negative cache TTL in seconds (default: 30).
    #[serde(default = "default_negative_ttl")]
    pub negative_ttl_secs: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: default_max_cache_entries(),
            min_ttl_secs: default_min_ttl(),
            max_ttl_secs: default_max_ttl(),
            negative_ttl_secs: default_negative_ttl(),
        }
    }
}

// ─── Resolver config ──────────────────────────────────────────────

/// Resolver configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverConfig {
    /// Resolver location hint — determines default route behavior.
    #[serde(default)]
    pub location: dns_types::ResolverLocation,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            location: dns_types::ResolverLocation::default(),
        }
    }
}

// ─── Legacy compatibility: ListenerAddr ────────────────────────────

/// Listener address (e.g., "udp://0.0.0.0:5353").
///
/// Kept for backward compatibility with the simple string-based
/// listener configuration.
#[derive(Debug, Clone)]
pub struct ListenerAddr {
    /// Transport protocol.
    pub protocol: DnsProtocol,
    /// Socket address (host:port).
    pub addr: String,
}

impl std::str::FromStr for ListenerAddr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (proto, addr) = if let Some(rest) = s.strip_prefix("udp://") {
            (DnsProtocol::Udp, rest)
        } else if let Some(rest) = s.strip_prefix("tcp://") {
            (DnsProtocol::Tcp, rest)
        } else {
            return Err(format!(
                "listener address '{s}' must start with 'udp://' or 'tcp://'"
            ));
        };
        if addr.is_empty() {
            return Err(format!("listener address '{s}' has empty host:port"));
        }
        Ok(Self {
            protocol: proto,
            addr: addr.to_string(),
        })
    }
}

// ─── Default value functions ──────────────────────────────────────

fn default_timeout_ms() -> u64 {
    3000
}

fn default_graceful_shutdown_ms() -> u64 {
    5000
}

fn default_max_concurrent() -> usize {
    1024
}

fn default_enabled() -> bool {
    true
}

fn default_true() -> bool {
    true
}

fn default_udp_listen() -> String {
    "0.0.0.0:5353".into()
}

fn default_tcp_listen() -> String {
    "0.0.0.0:5353".into()
}

fn default_idle_timeout_ms() -> u64 {
    30_000
}

fn default_doh_path() -> String {
    "/dns-query".into()
}

fn default_doq_alpn() -> Vec<String> {
    vec!["doq".into()]
}

fn default_doj_path() -> String {
    "/resolve".into()
}

fn default_doj_profile() -> String {
    "borderdns".into()
}

fn default_upstream_name() -> String {
    "unnamed".into()
}

fn default_upstream_transport() -> DnsProtocol {
    DnsProtocol::Udp
}

fn default_upstream_timeout_ms() -> u64 {
    3000
}

fn default_max_cache_entries() -> usize {
    4096
}

fn default_min_ttl() -> u32 {
    5
}

fn default_max_ttl() -> u32 {
    86_400
}

fn default_negative_ttl() -> u32 {
    30
}

// ─── Validation helpers ───────────────────────────────────────────

fn validate_socket_addr(addr: &str, field: &str) -> Result<(), ConfigError> {
    if addr.is_empty() {
        return Err(ConfigError::Validation(format!(
            "{field} must not be empty"
        )));
    }
    addr.parse::<std::net::SocketAddr>()
        .map_err(|e| ConfigError::Validation(format!("{field} is invalid: {e}")))?;
    Ok(())
}

fn validate_tls_paths(cert_file: &str, key_file: &str) -> Result<(), ConfigError> {
    if cert_file.is_empty() {
        return Err(ConfigError::Validation(
            "TLS cert_file must not be empty".into(),
        ));
    }
    if key_file.is_empty() {
        return Err(ConfigError::Validation(
            "TLS key_file must not be empty".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
        let config: Config = toml::from_str(toml_str).unwrap();
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
        let config: Config = toml::from_str(toml_str).unwrap();
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
        let config: Config = toml::from_str(toml_str).unwrap();
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
        let config: Config = toml::from_str(toml_str).unwrap();
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
        let config: Config = toml::from_str(toml_str).unwrap();
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
        let config: Config = toml::from_str(toml_str).unwrap();
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
        let config: Config = toml::from_str(toml_str).unwrap();
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
        let config: Config = toml::from_str(toml_str).unwrap();
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
        let config: Config = toml::from_str(toml_str).unwrap();
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
        let config = Config {
            server: ServerConfig {
                default_timeout_ms: 5000,
                graceful_shutdown_ms: 10_000,
                max_concurrent: 256,
            },
            listeners: ListenersConfig {
                udp: Some(UdpListenerConfig {
                    enabled: true,
                    listen: "0.0.0.0:5353".into(),
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
            },
            cache: CacheConfig::default(),
            resolver: ResolverConfig::default(),
        };

        let toml_str = toml::to_string(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
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
        let config: Config = toml::from_str(toml_str).unwrap();
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
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.validate().is_err());
    }
}
