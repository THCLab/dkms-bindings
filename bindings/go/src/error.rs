use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Null pointer encountered")]
    NullPointer,
    #[error("Invalid UTF-8 string")]
    InvalidUtf8,
    #[error("Error while parsing provided digest: {0}")]
    HashParsingError(String),
    #[error("Error while parsing provided key: {0}")]
    KeyParsingError(String),
    #[error("Error while parsing provided signature: {0}")]
    SignatureParsingError(String),
    #[error("Error while parsing provided oobi: {0}")]
    OobiParsingError(String),
    #[error("Error while parsing provided identifier: {0}")]
    IdParsingError(String),
    #[error("Error while parsing provided event")]
    EventParsingError,
    #[error("SDK error: {0}")]
    Sdk(String),
    #[error("Unexpected error: {0}")]
    Unexpected(String),
}
