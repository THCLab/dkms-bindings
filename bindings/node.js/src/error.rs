use keri_controller::{error::ControllerError, identifier::mechanics::MechanicsError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error while parsing provided digest: {0}")]
    HashParsingError(said::error::Error),
    #[error("Error while parsing provided key: {0}")]
    KeyParsingError(keri_core::prefix::error::Error),
    #[error("Error while parsing provided key: {0}")]
    SignatureParsingError(keri_core::prefix::error::Error),
    #[error("Error while parsing provided oobi: {0}")]
    OobiParsingError(String),
    #[error("Error while parsing provided identifier: {0}")]
    IdParsingError(keri_core::prefix::error::Error),
    #[error("Error while parsing provided event")]
    EventParsingError,
    #[error(transparent)]
    MechanicError(#[from] MechanicsError),
    #[error(transparent)]
    ControllerError(#[from] ControllerError),
    #[error("Unexpected error")]
    Unexpected(String),
}

impl From<Error> for napi::Error {
    fn from(value: Error) -> Self {
        Self::from_reason(value.to_string())
    }
}
