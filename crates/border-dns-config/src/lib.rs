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
pub use model::ListenerAddr;
pub use model::ResolverConfig;
pub use model::ServerConfig;
pub use model::UpstreamConfig;
pub use model::UpstreamServer;

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
mod tests {
    use super::*;

    #[test]
    fn test_default_config_roundtrip() {
        let toml_str = include_str!("../../../tests/fixtures/default.toml");
        let config = load_from_str(toml_str).unwrap();
        assert_eq!(config.server.listen.len(), 2);
        assert!(config.upstreams.default.len() >= 2);
    }

    #[test]
    fn test_minimal_config() {
        let toml_str = r#"
[server]
listen = ["udp://127.0.0.1:5353"]

[[upstreams.default]]
addr = "223.5.5.5:53"
protocol = "udp"
"#;
        let config = load_from_str(toml_str).unwrap();
        assert_eq!(config.server.listen.len(), 1);
        assert_eq!(config.upstreams.default.len(), 1);
    }

    #[test]
    fn test_empty_listen_rejected() {
        let toml_str = r#"
[server]
listen = []
"#;
        let result = load_from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_upstreams_rejected() {
        let toml_str = r#"
[server]
listen = ["udp://0.0.0.0:5353"]

[upstreams]
default = []
"#;
        let result = load_from_str(toml_str);
        assert!(result.is_err());
    }
}
