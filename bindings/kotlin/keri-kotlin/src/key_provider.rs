use std::sync::Arc;

use keri_keyprovider::{
    host::HostKeyProviderFactory, PublicKeyData, SignatureAlgorithm,
};

use crate::error::KeyProviderError;

/// Signature algorithm exposed across the FFI. Mirrors
/// `keri_keyprovider::SignatureAlgorithm` but is owned by this crate so
/// UniFFI can derive the foreign enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SignatureAlgo {
    Ed25519,
    EcdsaSecp256k1,
    EcdsaSecp256r1,
}

impl SignatureAlgo {
    pub fn to_keri(self) -> SignatureAlgorithm {
        match self {
            SignatureAlgo::Ed25519 => SignatureAlgorithm::Ed25519,
            SignatureAlgo::EcdsaSecp256k1 => SignatureAlgorithm::EcdsaSecp256k1,
            SignatureAlgo::EcdsaSecp256r1 => SignatureAlgorithm::EcdsaSecp256r1,
        }
    }

    pub fn from_keri(a: SignatureAlgorithm) -> Self {
        match a {
            SignatureAlgorithm::Ed25519 => SignatureAlgo::Ed25519,
            SignatureAlgorithm::EcdsaSecp256k1 => SignatureAlgo::EcdsaSecp256k1,
            SignatureAlgorithm::EcdsaSecp256r1 => SignatureAlgo::EcdsaSecp256r1,
        }
    }
}

/// A public key returned by the host key provider.
///
/// The algorithm field travels alongside the bytes so the Rust side never has
/// to remember which backend owns a label (the Dart binding kept an
/// out-of-band `key_state.json` for this — the Kotlin binding does not).
#[derive(Debug, Clone, uniffi::Record)]
pub struct PublicKey {
    pub bytes: Vec<u8>,
    pub algorithm: SignatureAlgo,
}

/// Host-implemented key provider. Implementations live on the Kotlin side
/// (typically an `AndroidKeystoreKeyProvider` that delegates to the platform
/// keystore + biometric prompt).
///
/// All five methods are async on the foreign side — Kotlin implements them as
/// `suspend fun`. The Rust adapter (`build_factory`) drives the foreign
/// futures synchronously inside `keri-keyprovider`'s `Fn` closures using
/// `block_in_place + Handle::current().block_on`, so this trait requires the
/// multi-threaded Tokio runtime.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait KeyProvider: Send + Sync {
    async fn create_key(
        &self,
        label: String,
        algorithm: SignatureAlgo,
    ) -> Result<PublicKey, KeyProviderError>;

    async fn open_key(&self, label: String) -> Result<PublicKey, KeyProviderError>;

    async fn sign(
        &self,
        label: String,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, KeyProviderError>;

    async fn delete_key(&self, label: String) -> Result<(), KeyProviderError>;

    async fn list_keys(&self) -> Result<Vec<String>, KeyProviderError>;
}

/// Wrap a foreign `KeyProvider` into a synchronous `HostKeyProviderFactory`
/// that the rest of the SDK can drive.
///
/// `keri-keyprovider`'s `HostKeyProviderFactory::new` wants `Fn` closures that
/// return synchronously. Each closure here blocks the current Tokio worker
/// (via `block_in_place` so other tasks can be migrated) and drives the
/// foreign future to completion on the same thread.
pub(crate) fn build_factory(provider: Arc<dyn KeyProvider>) -> HostKeyProviderFactory {
    let p_create = provider.clone();
    let p_open = provider.clone();
    let p_sign = provider.clone();
    let p_delete = provider.clone();
    let p_list = provider.clone();

    let create_fn = move |label: &str, algo: SignatureAlgorithm| -> keri_keyprovider::Result<PublicKeyData> {
        let label = label.to_string();
        let algo = SignatureAlgo::from_keri(algo);
        let provider = p_create.clone();
        let pk = block_on_provider(async move { provider.create_key(label, algo).await })
            .map_err(map_provider_err)?;
        Ok(PublicKeyData::new(pk.algorithm.to_keri(), pk.bytes))
    };

    let open_fn = move |label: &str| -> keri_keyprovider::Result<PublicKeyData> {
        let label = label.to_string();
        let provider = p_open.clone();
        let pk = block_on_provider(async move { provider.open_key(label).await })
            .map_err(map_provider_err)?;
        Ok(PublicKeyData::new(pk.algorithm.to_keri(), pk.bytes))
    };

    let sign_fn = move |label: &str, msg: &[u8]| -> keri_keyprovider::Result<Vec<u8>> {
        let label = label.to_string();
        let msg = msg.to_vec();
        let provider = p_sign.clone();
        block_on_provider(async move { provider.sign(label, msg).await })
            .map_err(map_provider_err)
    };

    let delete_fn = move |label: &str| -> keri_keyprovider::Result<()> {
        let label = label.to_string();
        let provider = p_delete.clone();
        block_on_provider(async move { provider.delete_key(label).await })
            .map_err(map_provider_err)
    };

    let list_fn = move || -> keri_keyprovider::Result<Vec<String>> {
        let provider = p_list.clone();
        block_on_provider(async move { provider.list_keys().await })
            .map_err(map_provider_err)
    };

    HostKeyProviderFactory::new(create_fn, open_fn, sign_fn, delete_fn, list_fn)
}

fn block_on_provider<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T> + Send,
    T: Send,
{
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))
}

fn map_provider_err(e: KeyProviderError) -> keri_keyprovider::KeyProviderError {
    keri_keyprovider::KeyProviderError::Other(e.to_string())
}
