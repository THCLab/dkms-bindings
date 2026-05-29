uniffi::setup_scaffolding!("keri");

mod api;
mod error;
mod key_provider;
mod types;

pub use api::KeriMobileSdk;
pub use error::{KeriError, KeyProviderError};
pub use key_provider::{KeyProvider, PublicKey, SignatureAlgo};
pub use types::*;
