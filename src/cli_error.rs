/// Unified error type for CLI operations.
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Configuration error: {0}")]
    Config(#[from] crate::config::ConfigError),

    #[error("Rehydration error: {0}")]
    Rehydration(#[from] crate::rehydration::RehydrationError),

    #[error("Dual store error: {0}")]
    DualStore(#[from] crate::dual_store::DualStoreError),

    #[error("Xberg error: {0}")]
    Xberg(#[from] xberg::XbergError),

    #[error("MCP error: {0}")]
    Mcp(#[from] rmcp::Error),

    #[error("Tantivy error: {0}")]
    Tantivy(#[from] tantivy::TantivyError),

    #[error("Configuration load error: {0}")]
    LoadConfig(String),

    #[error("Doctor check failed: {0}")]
    DoctorCheck(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Unknown transport: {0}")]
    UnknownTransport(String),

    #[error("Other error: {0}")]
    Other(String),
}

impl From<Box<dyn std::error::Error + Send + Sync + 'static>> for CliError {
    fn from(err: Box<dyn std::error::Error + Send + Sync + 'static>) -> Self {
        CliError::InvalidArgument(err.to_string())
    }
}

impl From<&str> for CliError {
    fn from(s: &str) -> Self {
        CliError::InvalidArgument(s.to_string())
    }
}

impl From<String> for CliError {
    fn from(s: String) -> Self {
        CliError::InvalidArgument(s)
    }
}

impl From<std::net::AddrParseError> for CliError {
    fn from(err: std::net::AddrParseError) -> Self {
        CliError::InvalidArgument(err.to_string())
    }
}
