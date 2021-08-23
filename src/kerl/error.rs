use keri::error::Error as KeriError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    DynError(#[from] Box<dyn std::error::Error>),

    #[error(transparent)]
    KeriError(#[from] KeriError),

    #[error("{0}")]
    Generic(String),

    #[error("Queue error")]
    QueueError,
}
