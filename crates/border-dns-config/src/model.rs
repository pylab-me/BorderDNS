//! Configuration model for BorderDNS runtime.
//!
//! Sprint 1-1: Supports named listeners for UDP, TCP, DoT, DoH, DoQ, DoJ
//! with per-listener TLS certificate configuration and expanded upstream
//! transport types.

use std::collections::HashMap;

use serde::Deserialize;
use serde::Serialize;

use crate::error::ConfigError;

// ─── Top-level config ─────────────────────────────────────────────

/// Top-level BorderDNS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
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
    /// Third-party observation configuration.
    #[serde(default)]
    pub third_party: ThirdPartyConfig,
    /// Hosts override configuration.
    #[serde(default)]
    pub hosts: HostsConfig,
    /// Domain block configuration.
    #[serde(default)]
    pub block: BlockConfig,
    /// Blackhole HTTP acceptor configuration.
    #[serde(default)]
    pub blackhole: BlackholeConfig,
}

impl RuntimeConfig {
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
        //
        // Route-aware mode: `bootstrap` must be non-empty (china/foreign optional).
        // Simple mode: `default` must be non-empty.
        // At least one of these two must be present.
        if self.upstreams.bootstrap.is_empty() && self.upstreams.default.is_empty() {
            return Err(ConfigError::Validation(
                "no upstream servers configured; please configure `bootstrap` (route-aware mode) \
                 or `default` (simple mode) under [upstreams]"
                    .into(),
            ));
        }
        for server in &self.upstreams.bootstrap {
            server.validate()?;
        }
        for server in &self.upstreams.default {
            server.validate()?;
        }
        for server in &self.upstreams.china {
            server.validate()?;
        }
        for server in &self.upstreams.foreign {
            server.validate()?;
        }

        // Validate block config IPs.
        if self.block.enabled {
            if self
                .block
                .blackhole_ipv4
                .parse::<std::net::Ipv4Addr>()
                .is_err()
            {
                return Err(ConfigError::Validation(format!(
                    "block.blackhole_ipv4 '{}' is not a valid IPv4 address",
                    self.block.blackhole_ipv4
                )));
            }
            if self
                .block
                .blackhole_ipv6
                .parse::<std::net::Ipv6Addr>()
                .is_err()
            {
                return Err(ConfigError::Validation(format!(
                    "block.blackhole_ipv6 '{}' is not a valid IPv6 address",
                    self.block.blackhole_ipv6
                )));
            }
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
    /// IPv6-only mode.
    /// - `None` (default): dual-stack — `[::]` accepts both IPv4 and IPv6.
    /// - `Some(true)`: IPv6-only — `[::]` accepts IPv6 only.
    /// - `Some(false)`: same as `None` (dual-stack).
    /// Ignored when `listen` is an IPv4 address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_only: Option<bool>,
}

impl Default for UdpListenerConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            listen: default_udp_listen(),
            ipv6_only: None,
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
    /// IPv6-only mode. See [`UdpListenerConfig::ipv6_only`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_only: Option<bool>,
}

impl Default for TcpListenerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_tcp_listen(),
            ipv6_only: None,
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
    /// IPv6-only mode. See [`UdpListenerConfig::ipv6_only`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_only: Option<bool>,
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
    /// IPv6-only mode. See [`UdpListenerConfig::ipv6_only`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_only: Option<bool>,
}

// ─── Upstream config ──────────────────────────────────────────────

/// Upstream resolver group configuration.
///
/// Supports named upstream groups: `bootstrap`, `default`, `china`, `foreign`.
///
/// - **Route-aware mode**: configure `bootstrap` (required) + optional `china`/`foreign`.
/// - **Simple mode**: configure `default` (no route governance).
///
/// At least one of `bootstrap` or `default` must be non-empty for the
/// configuration to be valid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamGroupConfig {
    /// Bootstrap upstream servers (used for initial / fallback resolution
    /// in route-aware mode).
    #[serde(default)]
    pub bootstrap: Vec<UpstreamServer>,
    /// Default upstream servers (simple mode, no route governance).
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
    /// Priority: route-specific group → bootstrap → default.
    #[must_use]
    pub fn for_route(&self, route: dns_types::Route) -> &[UpstreamServer] {
        let group = match route {
            dns_types::Route::China => &self.china,
            dns_types::Route::Foreign => &self.foreign,
            dns_types::Route::Bootstrap | dns_types::Route::Fallback => &self.bootstrap,
        };
        if !group.is_empty() {
            return group;
        }
        // Fallback chain: bootstrap → default.
        if !self.bootstrap.is_empty() {
            &self.bootstrap
        } else {
            &self.default
        }
    }

    /// Get the upstream servers for Sprint 1 (no route governance).
    ///
    /// Returns `default` if non-empty, otherwise falls back to `bootstrap`.
    #[must_use]
    pub fn default_upstreams(&self) -> &[UpstreamServer] {
        if !self.default.is_empty() {
            &self.default
        } else {
            &self.bootstrap
        }
    }

    /// Whether the configuration uses route-aware mode (bootstrap is configured).
    #[must_use]
    pub fn is_route_aware(&self) -> bool {
        !self.bootstrap.is_empty()
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
    /// Enhanced TTL in seconds for china-location + china-route domains (default: 3600 = 1h).
    /// Only used when `resolver.location = "china"` and `route = China`.
    #[serde(default = "default_enhanced_ttl")]
    pub enhanced_ttl_secs: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: default_max_cache_entries(),
            min_ttl_secs: default_min_ttl(),
            max_ttl_secs: default_max_ttl(),
            negative_ttl_secs: default_negative_ttl(),
            enhanced_ttl_secs: default_enhanced_ttl(),
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

// ─── Third-party observation config ──────────────────────────────

/// Third-party observation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThirdPartyConfig {
    /// Whether third-party observation is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Third-party observer peers.
    #[serde(default)]
    pub peers: Vec<ThirdPartyPeerConfig>,
}

impl Default for ThirdPartyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            peers: Vec::new(),
        }
    }
}

/// A single third-party observer peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThirdPartyPeerConfig {
    /// Unique observer identifier (e.g., "cn-shanghai-1").
    pub id: String,
    /// Observer endpoint URL (e.g., "https://cn-shanghai-1.example.com/observe").
    pub endpoint: String,
    /// Geographic location of the observer.
    #[serde(default)]
    pub location: dns_types::ResolverLocation,
    /// Trust level hint.
    #[serde(default = "default_peer_trust_level")]
    pub trust_level: String,
}

fn default_peer_trust_level() -> String {
    "normal".into()
}

// ─── Hosts override config ────────────────────────────────────────

/// Hosts override configuration.
///
/// Allows static domain → IP overrides, similar to /etc/hosts.
/// Supports inline entries and external hosts files.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostsConfig {
    /// Whether hosts override is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Inline host entries: domain → list of IP addresses.
    ///
    /// ```toml
    /// [hosts.entries]
    /// "example.com" = ["1.2.3.4", "2.3.4.5"]
    /// ```
    #[serde(default)]
    pub entries: HashMap<String, Vec<String>>,
    /// Paths to hosts files to load (standard hosts format).
    #[serde(default)]
    pub files: Vec<String>,
    /// TTL for host override responses in seconds (default: 60).
    #[serde(default = "default_hosts_ttl")]
    pub ttl_secs: u32,
}

impl HostsConfig {
    /// Whether this config has any data.
    #[must_use]
    pub fn has_data(&self) -> bool {
        self.enabled && (!self.entries.is_empty() || !self.files.is_empty())
    }
}

fn default_hosts_ttl() -> u32 {
    60
}

// ─── Block config ─────────────────────────────────────────────────

/// Domain block configuration.
///
/// Blocks DNS requests for matching domains by returning blackhole IPs
/// or SOA negative responses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockConfig {
    /// Whether domain blocking is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Exact domain names to block (e.g., ["ads.example.com"]).
    #[serde(default)]
    pub domains: Vec<String>,
    /// Domain suffixes to block (e.g., ["doubleclick.net"]).
    /// Matches any domain ending with the suffix.
    #[serde(default)]
    pub suffixes: Vec<String>,
    /// Wildcard pattern rules (e.g., ["**.umeng.**", "*.jddebug.com"]).
    /// Supports `*` (single label glob), `**` (multi-label wildcard),
    /// and exact matches. Merged with `domains` + `suffixes`.
    #[serde(default)]
    pub patterns: Vec<String>,
    /// External rule file paths (one pattern per line, `#` = comment).
    /// Rules from all files are merged into the unified pattern trie
    /// alongside `domains` + `suffixes` + `patterns`.
    #[serde(default)]
    pub rules_files: Vec<String>,
    /// Blackhole IPv4 address returned for blocked A queries.
    #[serde(default = "default_blackhole_ipv4")]
    pub blackhole_ipv4: String,
    /// Blackhole IPv6 address returned for blocked AAAA queries.
    #[serde(default = "default_blackhole_ipv6")]
    pub blackhole_ipv6: String,
    /// QTypes to fully suppress (return SOA / empty NOERROR).
    /// E.g., ["HTTPS", "SRV"].
    #[serde(default)]
    pub suppress_qtypes: Vec<String>,
}

impl BlockConfig {
    /// Whether this config has any block rules.
    #[must_use]
    pub fn has_rules(&self) -> bool {
        self.enabled
            && (!self.domains.is_empty()
                || !self.suffixes.is_empty()
                || !self.patterns.is_empty()
                || !self.rules_files.is_empty())
    }
}

fn default_blackhole_ipv4() -> String {
    "0.0.0.0".into()
}

fn default_blackhole_ipv6() -> String {
    "::".into()
}

// ─── Blackhole HTTP config ────────────────────────────────────────

/// Blackhole HTTP acceptor configuration.
///
/// Listens on specified HTTP ports and returns 202 Accepted for all
/// requests. Used to consume HTTP traffic redirected by blackhole DNS
/// responses, preventing connection hangs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlackholeConfig {
    /// Whether the blackhole HTTP acceptor is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Listen address (default: "0.0.0.0").
    #[serde(default = "default_blackhole_listen")]
    pub listen: String,
    /// Ports to listen on (default: [80, 443]).
    #[serde(default = "default_blackhole_ports")]
    pub ports: Vec<u16>,
    /// Maximum header bytes to read before discarding (default: 32768).
    #[serde(default = "default_blackhole_max_header")]
    pub max_header_bytes: usize,
}

fn default_blackhole_listen() -> String {
    "0.0.0.0".into()
}

fn default_blackhole_ports() -> Vec<u16> {
    vec![80, 443]
}

fn default_blackhole_max_header() -> usize {
    32 * 1024
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

fn default_enhanced_ttl() -> u32 {
    3600
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
#[path = "model_tests.rs"]
mod tests;
