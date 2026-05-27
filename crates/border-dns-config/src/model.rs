//! Configuration model for BorderDNS runtime.

use serde::Deserialize;
use serde::Serialize;

use crate::error::ConfigError;

/// Top-level BorderDNS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server configuration (listeners, concurrency, timeouts).
    pub server: ServerConfig,
    /// Upstream resolver configuration.
    pub upstreams: UpstreamConfig,
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
        if self.server.listen.is_empty() {
            return Err(ConfigError::Validation(
                "at least one listener address is required".into(),
            ));
        }
        if self.upstreams.default.is_empty() {
            return Err(ConfigError::Validation(
                "at least one default upstream is required".into(),
            ));
        }
        for addr in &self.server.listen {
            addr.parse::<ListenerAddr>().map_err(|e| {
                ConfigError::Validation(format!("invalid listen address '{addr}': {e}"))
            })?;
        }
        for server in &self.upstreams.default {
            server.validate()?;
        }
        Ok(())
    }
}

/// Server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Listener addresses (e.g., "udp://0.0.0.0:5353", "tcp://0.0.0.0:5353").
    pub listen: Vec<String>,
    /// Maximum concurrent requests (default: 1024).
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,
    /// Request timeout in seconds (default: 5).
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: vec!["udp://0.0.0.0:5353".into(), "tcp://0.0.0.0:5353".into()],
            max_concurrent: default_max_concurrent(),
            request_timeout_secs: default_request_timeout(),
        }
    }
}

/// Upstream resolver configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    /// Default upstream servers.
    pub default: Vec<UpstreamServer>,
}

/// A single upstream DNS server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamServer {
    /// Address in "host:port" format.
    pub addr: String,
    /// Transport protocol.
    #[serde(default = "default_protocol")]
    pub protocol: DnsProtocol,
    /// Timeout in seconds (default: 3).
    #[serde(default = "default_upstream_timeout")]
    pub timeout_secs: u64,
}

impl UpstreamServer {
    /// Validate the upstream server configuration.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::Validation` if the address is invalid.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.addr.is_empty() {
            return Err(ConfigError::Validation(
                "upstream address must not be empty".into(),
            ));
        }
        // Basic host:port validation.
        if !self.addr.contains(':') {
            return Err(ConfigError::Validation(format!(
                "upstream address '{}' must be in 'host:port' format",
                self.addr
            )));
        }
        Ok(())
    }
}

/// DNS transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsProtocol {
    /// UDP DNS (RFC 1035).
    Udp,
    /// TCP DNS (RFC 7766).
    Tcp,
}

impl Default for DnsProtocol {
    fn default() -> Self {
        Self::Udp
    }
}

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

/// Resolver configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverConfig {
    /// Resolver location hint.
    #[serde(default = "default_location")]
    pub location: String,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            location: default_location(),
        }
    }
}

/// Listener address (e.g., "udp://0.0.0.0:5353").
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

// ─── Default value functions ──────────────────────────────────────────

fn default_max_concurrent() -> usize {
    1024
}

fn default_request_timeout() -> u64 {
    5
}

fn default_protocol() -> DnsProtocol {
    DnsProtocol::Udp
}

fn default_upstream_timeout() -> u64 {
    3
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

fn default_location() -> String {
    "unknown".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_listener_addr_parse_udp() {
        let addr: ListenerAddr = "udp://0.0.0.0:5353".parse().unwrap();
        assert_eq!(addr.protocol, DnsProtocol::Udp);
        assert_eq!(addr.addr, "0.0.0.0:5353");
    }

    #[test]
    fn test_listener_addr_parse_tcp() {
        let addr: ListenerAddr = "tcp://127.0.0.1:53".parse().unwrap();
        assert_eq!(addr.protocol, DnsProtocol::Tcp);
        assert_eq!(addr.addr, "127.0.0.1:53");
    }

    #[test]
    fn test_listener_addr_parse_no_prefix() {
        let result = "0.0.0.0:5353".parse::<ListenerAddr>();
        assert!(result.is_err());
    }

    #[test]
    fn test_upstream_server_validate_empty() {
        let server = UpstreamServer {
            addr: String::new(),
            protocol: DnsProtocol::Udp,
            timeout_secs: 3,
        };
        assert!(server.validate().is_err());
    }

    #[test]
    fn test_upstream_server_validate_no_port() {
        let server = UpstreamServer {
            addr: "223.5.5.5".into(),
            protocol: DnsProtocol::Udp,
            timeout_secs: 3,
        };
        assert!(server.validate().is_err());
    }

    #[test]
    fn test_upstream_server_validate_ok() {
        let server = UpstreamServer {
            addr: "223.5.5.5:53".into(),
            protocol: DnsProtocol::Udp,
            timeout_secs: 3,
        };
        assert!(server.validate().is_ok());
    }

    #[test]
    fn test_cache_config_defaults() {
        let config = CacheConfig::default();
        assert_eq!(config.max_entries, 4096);
        assert_eq!(config.min_ttl_secs, 5);
        assert_eq!(config.max_ttl_secs, 86_400);
    }

    #[test]
    fn test_config_serialize_roundtrip() {
        let config = Config {
            server: ServerConfig {
                listen: vec!["udp://0.0.0.0:5353".into()],
                max_concurrent: 512,
                request_timeout_secs: 10,
            },
            upstreams: UpstreamConfig {
                default: vec![UpstreamServer {
                    addr: "223.5.5.5:53".into(),
                    protocol: DnsProtocol::Udp,
                    timeout_secs: 3,
                }],
            },
            cache: CacheConfig::default(),
            resolver: ResolverConfig::default(),
        };

        let toml_str = toml::to_string(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.server.max_concurrent, 512);
        assert_eq!(parsed.upstreams.default.len(), 1);
    }
}
