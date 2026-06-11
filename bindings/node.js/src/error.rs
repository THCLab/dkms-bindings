use keri_sdk::advanced::{Error as SdkError, MechanicsError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error while parsing provided digest: {0}")]
    HashParsingError(String),
    #[error("Error while parsing provided key: {0}")]
    KeyParsingError(String),
    #[error("Error while parsing provided oobi: {0}")]
    OobiParsingError(String),
    #[error("Error while parsing provided identifier: {0}")]
    IdParsingError(String),
    #[error("Error while parsing provided event")]
    EventParsingError,
    #[error(transparent)]
    MechanicError(#[from] MechanicsError),
    #[error(transparent)]
    SdkError(#[from] SdkError),
    #[error("Unexpected error")]
    Unexpected(String),
}

impl From<Error> for napi::Error {
    fn from(value: Error) -> Self {
        Self::from_reason(value.to_string())
    }
}
