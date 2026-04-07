use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use base64::Engine;

use keri_keyprovider::{
    host::HostKeyProviderFactory,
    KeyProvider, KeyProviderFactory, PublicKeyData, SignatureAlgorithm,
};
use keri_core::prefix::CesrPrimitive;

use crate::types::*;

pub struct KeriMobileSdk {
    db_path: PathBuf,
    key_factory: Option<Arc<HostKeyProviderFactory>>,
}

impl KeriMobileSdk {
    pub fn new(db_path: String) -> Result<Self> {
        Ok(Self {
            db_path: PathBuf::from(&db_path),
            key_factory: None,
        })
    }

    pub fn register_key_provider(
        &mut self,
        create_key: impl Fn(String, String) -> Result<Vec<u8>> + Send + Sync + 'static,
        open_key: impl Fn(String) -> Result<Vec<u8>> + Send + Sync + 'static,
        sign: impl Fn(String, Vec<u8>) -> Result<Vec<u8>> + Send + Sync + 'static,
        delete_key: impl Fn(String) -> Result<()> + Send + Sync + 'static,
        list_keys: impl Fn() -> Result<Vec<String>> + Send + Sync + 'static,
    ) {
        let create_fn = move |label: &str, algo: SignatureAlgorithm| {
            let algo_str = match algo {
                SignatureAlgorithm::Ed25519 => "Ed25519",
                SignatureAlgorithm::EcdsaSecp256k1 => "EcdsaSecp256k1",
            };
            let pk_bytes = create_key(label.to_string(), algo_str.to_string())
                .map_err(|e| keri_keyprovider::KeyProviderError::Other(e.to_string()))?;
            Ok(PublicKeyData::new(algo, pk_bytes))
        };

        let open_fn = move |label: &str| {
            let pk_bytes = open_key(label.to_string())
                .map_err(|e| keri_keyprovider::KeyProviderError::Other(e.to_string()))?;
            Ok(PublicKeyData::ed25519(pk_bytes))
        };

        let sign_fn = move |label: &str, msg: &[u8]| {
            sign(label.to_string(), msg.to_vec())
                .map_err(|e| keri_keyprovider::KeyProviderError::Other(e.to_string()))
        };

        let delete_fn = move |label: &str| {
            delete_key(label.to_string())
                .map_err(|e| keri_keyprovider::KeyProviderError::Other(e.to_string()))
        };

        let list_fn = move || {
            list_keys()
                .map_err(|e| keri_keyprovider::KeyProviderError::Other(e.to_string()))
        };

        self.key_factory = Some(Arc::new(HostKeyProviderFactory::new(
            create_fn, open_fn, sign_fn, delete_fn, list_fn,
        )));
    }

    fn open_store(&self) -> Result<keri_sdk::KeriStore> {
        Ok(keri_sdk::KeriStore::open(self.db_path.clone())?)
    }

    fn get_factory(&self) -> Result<Arc<HostKeyProviderFactory>> {
        self.key_factory.clone().ok_or_else(|| {
            anyhow::anyhow!("Key provider not registered. Call register_key_provider() first.")
        })
    }

    async fn get_signer(&self, alias: &str) -> Result<keri_sdk::keyprovider_adapter::KeriSigner> {
        let factory = self.get_factory()?;
        let provider = factory.open(alias).await?;
        Ok(keri_sdk::keyprovider_adapter::KeriSigner::from(provider as Arc<dyn KeyProvider>))
    }

    pub async fn create_identifier(
        &self,
        alias: String,
        config: FfiIdentifierConfig,
        next_pk_b64: String,
    ) -> Result<String> {
        let factory = self.get_factory()?;
        let provider = factory.create(&alias, SignatureAlgorithm::Ed25519).await?;

        let next_pk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&next_pk_b64)
            .map_err(|e| anyhow::anyhow!("base64 decode error: {e}"))?;
        let next_pk = keri_controller::BasicPrefix::Ed25519(
            keri_core::keys::PublicKey::new(next_pk_bytes)
        );

        let witnesses: Vec<keri_core::oobi::LocationScheme> = config
            .witness_urls
            .iter()
            .filter_map(|w| serde_json::from_str(w).ok())
            .collect();

        let watchers: Vec<keri_core::oobi::LocationScheme> = config
            .watcher_urls
            .iter()
            .filter_map(|w| serde_json::from_str(w).ok())
            .collect();

        let sdk_config = keri_sdk::types::IdentifierConfig {
            witnesses,
            witness_threshold: config.witness_threshold,
            watchers,
        };

        let signer = keri_sdk::keyprovider_adapter::KeriSigner::from(provider as Arc<dyn KeyProvider>);

        let alias_path = self.db_path.join(&alias).join("db");
        let id = keri_sdk::operations::create_identifier(
            alias_path,
            signer,
            next_pk,
            sdk_config,
        )
        .await?;

        let store = self.open_store()?;
        use keri_core::prefix::CesrPrimitive;
        store.save_id(&alias, id.id())?;

        Ok(id.id().to_str())
    }

    pub fn load_identifier(&self, alias: String) -> Result<String> {
        let store = self.open_store()?;
        let id = store.load(&alias)?;
        Ok(id.id().to_str())
    }

    pub fn list_aliases(&self) -> Result<Vec<String>> {
        let store = self.open_store()?;
        Ok(store.list_aliases()?)
    }

    pub async fn sign(
        &self,
        alias: String,
        data: Vec<u8>,
    ) -> Result<FfiSignedEnvelope> {
        let store = self.open_store()?;
        let id = store.load(&alias)?;
        let signer = self.get_signer(&alias).await?;

        let result = keri_sdk::signing::sign(&id, &signer, &data)?;
        Ok(FfiSignedEnvelope {
            payload: result.payload,
            cesr: result.cesr,
        })
    }

    pub fn verify(&self, alias: String, cesr: Vec<u8>) -> Result<FfiVerifiedPayload> {
        let store = self.open_store()?;
        let id = store.load(&alias)?;
        let result = keri_sdk::signing::verify(&id, &cesr)?;
        Ok(FfiVerifiedPayload {
            payload: result.payload,
            signer_id: result.signer_id.to_str(),
        })
    }

    pub async fn rotate_keys(
        &self,
        alias: String,
        config: FfiRotationConfig,
    ) -> Result<()> {
        let store = self.open_store()?;
        let mut id = store.load(&alias)?;
        let signer = self.get_signer(&alias).await?;

        let new_next_pk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&config.new_next_pk_b64)
            .map_err(|e| anyhow::anyhow!("base64 decode error: {e}"))?;
        let new_next_pk = keri_controller::BasicPrefix::Ed25519(
            keri_core::keys::PublicKey::new(new_next_pk_bytes)
        );

        let witness_to_add: Vec<keri_core::oobi::LocationScheme> = config
            .witness_to_add
            .iter()
            .filter_map(|w| serde_json::from_str(w).ok())
            .collect();

        let witness_to_remove: Vec<keri_controller::BasicPrefix> = config
            .witness_to_remove
            .iter()
            .filter_map(|w| w.parse().ok())
            .collect();

        let rot_config = keri_sdk::types::RotationConfig {
            new_next_pk,
            witness_to_add,
            witness_to_remove,
            witness_threshold: config.witness_threshold,
        };

        keri_sdk::operations::rotate(&mut id, signer, rot_config).await?;
        Ok(())
    }

    pub async fn incept_registry(
        &self,
        alias: String,
    ) -> Result<String> {
        let store = self.open_store()?;
        let mut id = store.load(&alias)?;
        let signer = self.get_signer(&alias).await?;

        let reg_id = keri_sdk::operations::incept_registry(&mut id, signer).await?;

        store.save_registry(&alias, &reg_id)?;

        Ok(reg_id.to_str())
    }

    pub async fn issue_credential(
        &self,
        alias: String,
        credential_said: String,
    ) -> Result<()> {
        let store = self.open_store()?;
        let mut id = store.load(&alias)?;
        let signer = self.get_signer(&alias).await?;

        let said: keri_core::actor::prelude::SelfAddressingIdentifier =
            credential_said.parse()?;

        keri_sdk::operations::issue(&mut id, signer, said).await?;
        Ok(())
    }

    pub async fn revoke_credential(
        &self,
        alias: String,
        credential_said: String,
    ) -> Result<()> {
        let store = self.open_store()?;
        let mut id = store.load(&alias)?;
        let signer = self.get_signer(&alias).await?;

        let said: keri_core::actor::prelude::SelfAddressingIdentifier =
            credential_said.parse()?;

        keri_sdk::operations::revoke(&mut id, signer, &said).await?;
        Ok(())
    }

    pub async fn check_credential(
        &self,
        alias: String,
        registry_id: String,
        credential_said: String,
    ) -> Result<FfiCredentialStatus> {
        let store = self.open_store()?;
        let id = store.load(&alias)?;
        let signer = self.get_signer(&alias).await?;

        let reg_id: keri_controller::IdentifierPrefix = registry_id.parse()?;
        let said: keri_core::actor::prelude::SelfAddressingIdentifier =
            credential_said.parse()?;

        let status = keri_sdk::tel::check_credential_status(&id, &signer, &reg_id, &said).await?;

        Ok(match status {
            keri_sdk::types::CredentialStatus::Issued => FfiCredentialStatus::Issued,
            keri_sdk::types::CredentialStatus::Revoked => FfiCredentialStatus::Revoked,
            keri_sdk::types::CredentialStatus::Unknown => FfiCredentialStatus::Unknown,
        })
    }

    pub fn get_credential_status(
        &self,
        alias: String,
        credential_said: String,
    ) -> Result<FfiCredentialStatus> {
        let store = self.open_store()?;
        let id = store.load(&alias)?;
        let said: keri_core::actor::prelude::SelfAddressingIdentifier =
            credential_said.parse()?;

        let status = keri_sdk::tel::get_credential_status(&id, &said)?;
        Ok(match status {
            keri_sdk::types::CredentialStatus::Issued => FfiCredentialStatus::Issued,
            keri_sdk::types::CredentialStatus::Revoked => FfiCredentialStatus::Revoked,
            keri_sdk::types::CredentialStatus::Unknown => FfiCredentialStatus::Unknown,
        })
    }
}
