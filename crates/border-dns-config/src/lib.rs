//! Configuration model and validation for BorderDNS runtime.
//!
//! The configuration is TOML-based and strongly typed.
//! Runtime bootstrapping must not happen here.

mod error;
mod model;

use std::path::Path;

pub use error::ConfigError;
pub use model::CacheConfig;
pub use model::Config;
pub use model::DnsProtocol;
pub use model::DoHListenerConfig;
pub use model::DoJListenerConfig;
pub use model::DoQListenerConfig;
pub use model::ListenerAddr;
pub use model::ListenersConfig;
pub use model::ResolverConfig;
pub use model::ServerConfig;
pub use model::TcpListenerConfig;
pub use model::TlsListenerConfig;
pub use model::UdpListenerConfig;
pub use model::UpstreamGroupConfig;
pub use model::UpstreamServer;
pub use model::ThirdPartyConfig;
pub use model::ThirdPartyPeerConfig;

/// Load configuration from a TOML file.
///
/// # Errors
///
/// Returns error on file read failure, TOML parse error, or validation error.
pub fn load_from_file(path: &Path) -> Result<Config, ConfigError> {
    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    load_from_str(&content)
}

/// Load configuration from a TOML string.
///
/// # Errors
///
/// Returns error on TOML parse error or validation error.
pub fn load_from_str(s: &str) -> Result<Config, ConfigError> {
    let config: Config = toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))?;
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
