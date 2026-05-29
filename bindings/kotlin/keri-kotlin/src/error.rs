use thiserror::Error;

#[derive(Debug, Error, uniffi::Error)]
pub enum KeriError {
    #[error("key provider not registered; call register_key_provider() first")]
    KeyProviderUnregistered,
    #[error("unsupported algorithm '{0}'")]
    UnsupportedAlgorithm(String),
    #[error("invalid URL '{url}': {reason}")]
    InvalidUrl { url: String, reason: String },
    #[error("network error: {0}")]
    Network(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("controller error: {0}")]
    Controller(String),
    #[error("key provider error: {0}")]
    KeyProvider(String),
    #[error("{0}")]
    Internal(String),
}

impl From<anyhow::Error> for KeriError {
    fn from(e: anyhow::Error) -> Self {
        KeriError::Internal(format!("{e:#}"))
    }
}

impl From<std::io::Error> for KeriError {
    fn from(e: std::io::Error) -> Self {
        KeriError::Storage(e.to_string())
    }
}

impl From<serde_json::Error> for KeriError {
    fn from(e: serde_json::Error) -> Self {
        KeriError::Storage(format!("json: {e}"))
    }
}

#[derive(Debug, Error, uniffi::Error)]
pub enum KeyProviderError {
    #[error("key not found: {0}")]
    NotFound(String),
    #[error("authentication failed: {0}")]
    AuthFailed(String),
    #[error("backend error: {0}")]
    Backend(String),
}
