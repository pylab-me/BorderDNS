//! Error types for configuration loading and validation.

/// Errors produced by configuration operations.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Failed to read config file.
    #[error("failed to read config file '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Failed to parse TOML config.
    #[error("failed to parse config: {0}")]
    Parse(String),

    /// Configuration validation failed.
    #[error("config validation error: {0}")]
    Validation(String),
}
