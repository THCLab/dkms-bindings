use base64::DecodeError;
use keri::error::Error as KeriError;
use std::string::FromUtf8Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    DynError(#[from] Box<dyn std::error::Error>),

    #[error(transparent)]
    KeriError(#[from] KeriError),

    #[error("{0}")]
    Generic(String),

    #[error(transparent)]
    Utf8Error(#[from] FromUtf8Error),

    #[error(transparent)]
    Base64Error(#[from] DecodeError),

    #[error("Database not initialized")]
    NoDatabase,

    #[error("Wrong event in argument")]
    WrongEventArgument,

    #[error("No public keys in current identifier state")]
    NoPublicKeys,

    #[error("Not enough signatures")]
    NotEnoughSignatures,

    #[error("Can't find public key matching signature")]
    KeyNotFound,
}
