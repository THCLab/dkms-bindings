use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Null pointer encountered")]
    NullPointer,
    #[error("Invalid UTF-8 string")]
    InvalidUtf8,
    #[error("Error while parsing provided digest: {0}")]
    HashParsingError(said::error::Error),
    #[error("Error while parsing provided key: {0}")]
    KeyParsingError(keri_core::prefix::error::Error),
    #[error("Error while parsing provided signature: {0}")]
    SignatureParsingError(keri_core::prefix::error::Error),
    #[error("Error while parsing provided oobi: {0}")]
    OobiParsingError(String),
    #[error("Error while parsing provided identifier: {0}")]
    IdParsingError(keri_core::prefix::error::Error),
    #[error("Error while parsing provided event")]
    EventParsingError,
    #[error(transparent)]
    MechanicError(#[from] keri_controller::identifier::mechanics::MechanicsError),
    #[error(transparent)]
    ControllerError(#[from] keri_controller::error::ControllerError),
    #[error("Unexpected error: {0}")]
    Unexpected(String),
}
