use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use keri_core::prefix::CesrPrimitive;
use keri_keyprovider::{host::HostKeyProviderFactory, KeyProvider as KeriKp, KeyProviderFactory};

use crate::error::KeriError;
use crate::key_provider::{build_factory, KeyProvider, SignatureAlgo};
use crate::types::*;

/// Per-alias keystore-label bookkeeping. Lives next to the KeriStore DB
/// (in `<db_path>/<alias>/key_state.json`). Tracks the current/next key
/// labels so signing and rotation pick the correct host-side secret after
/// rotations have caused labels to diverge from the human-facing alias.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyState {
    current_label: String,
    next_label: String,
    version: u32,
}

async fn resolve_location_scheme(url: &str) -> Result<keri_core::oobi::LocationScheme, KeriError> {
    let base = url::Url::parse(url).map_err(|e| KeriError::InvalidUrl {
        url: url.to_string(),
        reason: e.to_string(),
    })?;
    let introduce = base.join("introduce").map_err(|e| KeriError::InvalidUrl {
        url: url.to_string(),
        reason: format!("join: {e}"),
    })?;
    let resp = reqwest::get(introduce)
        .await
        .map_err(|e| KeriError::Network(format!("GET introduce: {e}")))?;
    resp.json::<keri_core::oobi::LocationScheme>()
        .await
        .map_err(|e| KeriError::Network(format!("invalid LocationScheme from '{url}': {e}")))
}

fn basic_prefix_for(
    algo: SignatureAlgo,
    pk_bytes: Vec<u8>,
    transferable: bool,
) -> keri_controller::BasicPrefix {
    let pk = keri_core::keys::PublicKey::new(pk_bytes);
    use keri_keyprovider::SignatureAlgorithm as A;
    match (algo.to_keri(), transferable) {
        (A::Ed25519, true) => keri_controller::BasicPrefix::Ed25519(pk),
        (A::Ed25519, false) => keri_controller::BasicPrefix::Ed25519NT(pk),
        (A::EcdsaSecp256k1, true) => keri_controller::BasicPrefix::ECDSAsecp256k1(pk),
        (A::EcdsaSecp256k1, false) => keri_controller::BasicPrefix::ECDSAsecp256k1NT(pk),
        (A::EcdsaSecp256r1, true) => keri_controller::BasicPrefix::ECDSA256r1(pk),
        (A::EcdsaSecp256r1, false) => keri_controller::BasicPrefix::ECDSA256r1NT(pk),
    }
}

fn signer_algorithm(a: SignatureAlgo) -> keri_core::signer::SignerAlgorithm {
    match a {
        SignatureAlgo::Ed25519 => keri_core::signer::SignerAlgorithm::Ed25519,
        SignatureAlgo::EcdsaSecp256k1 => keri_core::signer::SignerAlgorithm::EcdsaSecp256k1,
        SignatureAlgo::EcdsaSecp256r1 => keri_core::signer::SignerAlgorithm::EcdsaSecp256r1,
    }
}

/// Top-level mobile SDK object. One instance per app process.
#[derive(uniffi::Object)]
pub struct KeriMobileSdk {
    db_path: PathBuf,
    key_factory: OnceLock<Arc<HostKeyProviderFactory>>,
    store: Mutex<Option<Arc<keri_sdk::KeriStore>>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl KeriMobileSdk {
    #[uniffi::constructor]
    pub fn new(db_path: String) -> Result<Arc<Self>, KeriError> {
        Ok(Arc::new(Self {
            db_path: PathBuf::from(&db_path),
            key_factory: OnceLock::new(),
            store: Mutex::new(None),
        }))
    }

    /// Register the host-side key provider. Must be called before any
    /// identifier operation. Idempotent failure: second call returns an
    /// error rather than silently replacing the provider.
    pub fn register_key_provider(
        &self,
        provider: Arc<dyn KeyProvider>,
    ) -> Result<(), KeriError> {
        let factory = build_factory(provider);
        self.key_factory
            .set(Arc::new(factory))
            .map_err(|_| KeriError::Internal("key provider already registered".into()))
    }

    /// Drop the cached `KeriStore` (releasing the redb flock) and recursively
    /// delete `db_path`. The host's keystore is wiped separately.
    pub fn wipe(&self) -> Result<(), KeriError> {
        {
            let mut guard = self.store.lock().unwrap();
            *guard = None;
        }
        if self.db_path.exists() {
            std::fs::remove_dir_all(&self.db_path)?;
        }
        Ok(())
    }

    pub async fn create_identifier(
        &self,
        alias: String,
        config: FfiIdentifierConfig,
    ) -> Result<String, KeriError> {
        let factory = self.factory()?;
        let algo = config.algorithm;
        let current_label = format!("{alias}_v1");
        let next_label = format!("{alias}_v2");

        let current_provider = factory.create(&current_label, algo.to_keri()).await
            .map_err(|e| KeriError::KeyProvider(e.to_string()))?;
        let next_provider = factory.create(&next_label, algo.to_keri()).await
            .map_err(|e| KeriError::KeyProvider(e.to_string()))?;

        let next_pk =
            basic_prefix_for(algo, next_provider.public_key().bytes.clone(), false);

        let witnesses = futures::future::try_join_all(
            config.witness_urls.iter().map(|u| resolve_location_scheme(u)),
        )
        .await?;

        let watchers = futures::future::try_join_all(
            config.watcher_urls.iter().map(|u| resolve_location_scheme(u)),
        )
        .await?;

        let sdk_config = keri_sdk::types::IdentifierConfig {
            witnesses,
            witness_threshold: config.witness_threshold,
            watchers,
            algorithm: signer_algorithm(algo),
        };

        let store = self.open_store()?;
        let (id, _signer) = store
            .create_with_provider(
                &alias,
                current_provider as Arc<dyn KeriKp>,
                next_pk,
                sdk_config,
            )
            .await
            .map_err(|e| KeriError::Controller(e.to_string()))?;

        store
            .save_id(&alias, id.id())
            .map_err(|e| KeriError::Storage(e.to_string()))?;
        self.save_key_state(
            &alias,
            &KeyState {
                current_label,
                next_label,
                version: 1,
            },
        )?;

        Ok(id.id().to_str())
    }

    pub fn load_identifier(&self, alias: String) -> Result<String, KeriError> {
        let store = self.open_store()?;
        let id = store.load(&alias).map_err(|e| KeriError::Storage(e.to_string()))?;
        Ok(id.id().to_str())
    }

    pub fn list_aliases(&self) -> Result<Vec<String>, KeriError> {
        let store = self.open_store()?;
        store.list_aliases().map_err(|e| KeriError::Storage(e.to_string()))
    }

    pub async fn sign(
        &self,
        alias: String,
        data: Vec<u8>,
    ) -> Result<FfiSignedEnvelope, KeriError> {
        let store = self.open_store()?;
        let id = store.load(&alias).map_err(|e| KeriError::Storage(e.to_string()))?;
        let signer = self.get_signer(&alias).await?;

        let result = keri_sdk::signing::sign(&id, &signer, &data)
            .map_err(|e| KeriError::Controller(e.to_string()))?;
        Ok(FfiSignedEnvelope {
            payload: result.payload,
            cesr: result.cesr,
        })
    }

    pub fn verify(
        &self,
        alias: String,
        cesr: Vec<u8>,
    ) -> Result<FfiVerifiedPayload, KeriError> {
        let store = self.open_store()?;
        let id = store.load(&alias).map_err(|e| KeriError::Storage(e.to_string()))?;
        let result = keri_sdk::signing::verify(&id, &cesr)
            .map_err(|e| KeriError::Controller(e.to_string()))?;
        Ok(FfiVerifiedPayload {
            payload: result.payload,
            signer_id: result.signer_id.to_str(),
        })
    }

    pub async fn rotate_keys(
        &self,
        alias: String,
        config: FfiRotationConfig,
    ) -> Result<(), KeriError> {
        let factory = self.factory()?;
        let store = self.open_store()?;
        let mut id = store.load(&alias).map_err(|e| KeriError::Storage(e.to_string()))?;
        let mut state = self.load_key_state(&alias)?;

        let new_current_provider = factory
            .open(&state.next_label)
            .await
            .map_err(|e| KeriError::KeyProvider(e.to_string()))?;
        let algo = SignatureAlgo::from_keri(new_current_provider.public_key().algorithm);
        let signer = keri_sdk::keyprovider_adapter::KeriSigner::from(
            new_current_provider as Arc<dyn KeriKp>,
        );

        let new_next_label = format!("{alias}_v{}", state.version + 2);
        let new_next_provider = factory
            .create(&new_next_label, algo.to_keri())
            .await
            .map_err(|e| KeriError::KeyProvider(e.to_string()))?;
        let new_next_pk =
            basic_prefix_for(algo, new_next_provider.public_key().bytes.clone(), false);

        let witness_to_add = futures::future::try_join_all(
            config
                .witness_to_add
                .iter()
                .map(|u| resolve_location_scheme(u)),
        )
        .await?;

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

        keri_sdk::operations::rotate(&mut id, signer, rot_config)
            .await
            .map_err(|e| KeriError::Controller(e.to_string()))?;

        let previous_current =
            std::mem::replace(&mut state.current_label, state.next_label.clone());
        state.next_label = new_next_label;
        state.version += 1;
        self.save_key_state(&alias, &state)?;

        let _ = factory.delete(&previous_current).await;
        Ok(())
    }

    pub async fn incept_registry(&self, alias: String) -> Result<String, KeriError> {
        let store = self.open_store()?;
        let mut id = store.load(&alias).map_err(|e| KeriError::Storage(e.to_string()))?;
        let signer = self.get_signer(&alias).await?;

        let reg_id = keri_sdk::operations::incept_registry(&mut id, signer)
            .await
            .map_err(|e| KeriError::Controller(e.to_string()))?;
        store
            .save_registry(&alias, &reg_id)
            .map_err(|e| KeriError::Storage(e.to_string()))?;
        Ok(reg_id.to_str())
    }

    pub async fn issue_credential(
        &self,
        alias: String,
        credential_said: String,
    ) -> Result<(), KeriError> {
        let store = self.open_store()?;
        let mut id = store.load(&alias).map_err(|e| KeriError::Storage(e.to_string()))?;
        let signer = self.get_signer(&alias).await?;

        let said: keri_core::actor::prelude::SelfAddressingIdentifier =
            credential_said
                .parse()
                .map_err(|e| KeriError::Internal(format!("{e}")))?;
        keri_sdk::operations::issue(&mut id, signer, said)
            .await
            .map_err(|e| KeriError::Controller(e.to_string()))
    }

    pub async fn revoke_credential(
        &self,
        alias: String,
        credential_said: String,
    ) -> Result<(), KeriError> {
        let store = self.open_store()?;
        let mut id = store.load(&alias).map_err(|e| KeriError::Storage(e.to_string()))?;
        let signer = self.get_signer(&alias).await?;

        let said: keri_core::actor::prelude::SelfAddressingIdentifier =
            credential_said
                .parse()
                .map_err(|e| KeriError::Internal(format!("{e}")))?;
        keri_sdk::operations::revoke(&mut id, signer, &said)
            .await
            .map_err(|e| KeriError::Controller(e.to_string()))
    }

    pub async fn check_credential(
        &self,
        alias: String,
        registry_id: String,
        credential_said: String,
    ) -> Result<FfiCredentialStatus, KeriError> {
        let store = self.open_store()?;
        let id = store.load(&alias).map_err(|e| KeriError::Storage(e.to_string()))?;
        let signer = self.get_signer(&alias).await?;

        let reg_id: keri_controller::IdentifierPrefix = registry_id
            .parse()
            .map_err(|e| KeriError::Internal(format!("{e}")))?;
        let said: keri_core::actor::prelude::SelfAddressingIdentifier =
            credential_said
                .parse()
                .map_err(|e| KeriError::Internal(format!("{e}")))?;

        let status = keri_sdk::tel::check_credential_status(&id, &signer, &reg_id, &said)
            .await
            .map_err(|e| KeriError::Controller(e.to_string()))?;
        Ok(map_status(status))
    }

    pub fn get_credential_status(
        &self,
        alias: String,
        credential_said: String,
    ) -> Result<FfiCredentialStatus, KeriError> {
        let store = self.open_store()?;
        let id = store.load(&alias).map_err(|e| KeriError::Storage(e.to_string()))?;
        let said: keri_core::actor::prelude::SelfAddressingIdentifier =
            credential_said
                .parse()
                .map_err(|e| KeriError::Internal(format!("{e}")))?;
        let status = keri_sdk::tel::get_credential_status(&id, &said)
            .map_err(|e| KeriError::Controller(e.to_string()))?;
        Ok(map_status(status))
    }

    /// Ingest a delegator's KEL CESR stream into `alias`'s local
    /// store. The mobile join-by-QR flow calls this with the primary
    /// device's KEL bytes carried inside the invite payload, so the
    /// delegator's seal can be validated locally without a witness
    /// or watcher round-trip.
    ///
    /// Idempotent — calling twice with the same stream is a no-op.
    pub async fn import_delegator_kel(
        &self,
        alias: String,
        kel_cesr: String,
    ) -> Result<(), KeriError> {
        use keri_core::actor::parse_notice_stream;
        let store = self.open_store()?;
        let id = store
            .load(&alias)
            .map_err(|e| KeriError::Storage(e.to_string()))?;
        let notices = parse_notice_stream(kel_cesr.as_bytes())
            .map_err(|e| KeriError::Internal(format!("parse delegator KEL: {e}")))?;
        for notice in &notices {
            id.save_notice(notice)
                .map_err(|e| KeriError::Controller(e.to_string()))?;
        }
        Ok(())
    }

    /// Build a delegated-AID inception event ('dip') under `alias`
    /// delegated by `config.delegator_aid`. Persists the alias →
    /// delegated_prefix and alias → delegator mapping. Returns the
    /// delegated AID and the dip CESR ready for out-of-band transport
    /// to the delegator.
    ///
    /// After the delegator returns the signed delegating `ixn`, call
    /// `finalize_delegation` to attach the seal to the local KEL.
    pub async fn request_delegation(
        &self,
        alias: String,
        config: FfiDelegationConfig,
    ) -> Result<FfiDelegationRequest, KeriError> {
        let factory = self.factory()?;
        let algo = config.algorithm;
        let current_label = format!("{alias}_v1");
        let next_label = format!("{alias}_v2");

        let current_provider = factory
            .create(&current_label, algo.to_keri())
            .await
            .map_err(|e| KeriError::KeyProvider(e.to_string()))?;
        let next_provider = factory
            .create(&next_label, algo.to_keri())
            .await
            .map_err(|e| KeriError::KeyProvider(e.to_string()))?;

        let next_pk =
            basic_prefix_for(algo, next_provider.public_key().bytes.clone(), false);

        let witnesses = futures::future::try_join_all(
            config.witness_urls.iter().map(|u| resolve_location_scheme(u)),
        )
        .await?;

        let delegator: keri_controller::IdentifierPrefix = config
            .delegator_aid
            .parse()
            .map_err(|e| KeriError::Internal(format!("invalid delegator AID: {e}")))?;

        let delegation_config = keri_sdk::types::DelegationConfig {
            delegator: delegator.clone(),
            witnesses,
            witness_threshold: config.witness_threshold,
            watchers: vec![],
            algorithm: signer_algorithm(algo),
        };

        // build_delegation_request opens its own Controller against
        // this path. After it returns, that Controller drops and
        // KeriStore::load can reopen the same redb on subsequent
        // calls under the same alias.
        let alias_dir = self.db_path.join(&alias);
        std::fs::create_dir_all(&alias_dir)?;
        let alias_db = alias_dir.join("db");

        let signer: Arc<dyn KeriKp> = current_provider.clone();
        let (temp_id, delegated_prefix, dip_cesr) =
            keri_sdk::operations::build_delegation_request(
                alias_db,
                signer,
                next_pk,
                delegation_config,
            )
            .await
            .map_err(|e| KeriError::Controller(e.to_string()))?;

        let store = self.open_store()?;
        store
            .save_id(&alias, temp_id.id())
            .map_err(|e| KeriError::Storage(e.to_string()))?;
        store
            .save_delegator(&alias, &delegator)
            .map_err(|e| KeriError::Storage(e.to_string()))?;
        self.save_key_state(
            &alias,
            &KeyState {
                current_label,
                next_label,
                version: 1,
            },
        )?;

        Ok(FfiDelegationRequest {
            delegated_aid: delegated_prefix.to_str(),
            dip_cesr,
        })
    }

    /// Atomic version of `request_delegation` + `import_delegator_kel`.
    ///
    /// In the mobile QR-pairing flow these two calls happen
    /// back-to-back, and routing them through two separate FFI
    /// invocations races on the redb lock: `request_delegation`'s
    /// temporary Identifier owns the redb at `<alias>/db`, returns
    /// across the FFI boundary, and the very next call
    /// (`import_delegator_kel`) goes back through KeriStore::load
    /// which constructs a fresh Controller for the same path —
    /// before redb's in-process registry has registered the previous
    /// Database as closed.
    ///
    /// This combined entry-point keeps a single live Identifier
    /// across both operations: build the delegation request, save
    /// the delegator KEL notices through the same `temp_id`, then
    /// persist the alias mapping. One Controller, no reopen.
    pub async fn request_delegation_with_kel(
        &self,
        alias: String,
        config: FfiDelegationConfig,
        delegator_kel_cesr: String,
    ) -> Result<FfiDelegationRequest, KeriError> {
        let factory = self.factory()?;
        let algo = config.algorithm;
        let current_label = format!("{alias}_v1");
        let next_label = format!("{alias}_v2");

        let current_provider = factory
            .create(&current_label, algo.to_keri())
            .await
            .map_err(|e| KeriError::KeyProvider(e.to_string()))?;
        let next_provider = factory
            .create(&next_label, algo.to_keri())
            .await
            .map_err(|e| KeriError::KeyProvider(e.to_string()))?;

        let next_pk =
            basic_prefix_for(algo, next_provider.public_key().bytes.clone(), false);

        let witnesses = futures::future::try_join_all(
            config.witness_urls.iter().map(|u| resolve_location_scheme(u)),
        )
        .await?;

        let delegator: keri_controller::IdentifierPrefix = config
            .delegator_aid
            .parse()
            .map_err(|e| KeriError::Internal(format!("invalid delegator AID: {e}")))?;

        let delegation_config = keri_sdk::types::DelegationConfig {
            delegator: delegator.clone(),
            witnesses,
            witness_threshold: config.witness_threshold,
            watchers: vec![],
            algorithm: signer_algorithm(algo),
        };

        let alias_dir = self.db_path.join(&alias);
        std::fs::create_dir_all(&alias_dir)?;
        let alias_db = alias_dir.join("db");

        let signer: Arc<dyn KeriKp> = current_provider.clone();
        let (temp_id, delegated_prefix, dip_cesr) =
            keri_sdk::operations::build_delegation_request(
                alias_db,
                signer,
                next_pk,
                delegation_config,
            )
            .await
            .map_err(|e| KeriError::Controller(e.to_string()))?;

        // Save the delegator KEL through the still-alive temp_id so
        // the redb stays open under one controller for both phases.
        if !delegator_kel_cesr.is_empty() {
            use keri_core::actor::parse_notice_stream;
            let notices = parse_notice_stream(delegator_kel_cesr.as_bytes())
                .map_err(|e| KeriError::Internal(format!("parse delegator KEL: {e}")))?;
            for notice in &notices {
                temp_id
                    .save_notice(notice)
                    .map_err(|e| KeriError::Controller(e.to_string()))?;
            }
        }

        // Flat-file alias persistence — no redb touch on the same path.
        let store = self.open_store()?;
        store
            .save_id(&alias, temp_id.id())
            .map_err(|e| KeriError::Storage(e.to_string()))?;
        store
            .save_delegator(&alias, &delegator)
            .map_err(|e| KeriError::Storage(e.to_string()))?;
        self.save_key_state(
            &alias,
            &KeyState {
                current_label,
                next_label,
                version: 1,
            },
        )?;

        Ok(FfiDelegationRequest {
            delegated_aid: delegated_prefix.to_str(),
            dip_cesr,
        })
    }

    /// Apply the delegator's signed `ixn` (CESR) to `alias`'s
    /// previously-escrowed `dip`, completing the delegated AID's
    /// KEL. The delegator's own KEL must already be present in the
    /// local store (call `import_delegator_kel` first).
    pub async fn finalize_delegation(
        &self,
        alias: String,
        delegator_seal_cesr: String,
    ) -> Result<(), KeriError> {
        let store = self.open_store()?;
        let id = store
            .load(&alias)
            .map_err(|e| KeriError::Storage(e.to_string()))?;
        keri_sdk::operations::finalize_delegation_with_seal(&id, &delegator_seal_cesr)
            .await
            .map_err(|e| KeriError::Controller(e.to_string()))
    }

    pub fn show_kel(&self, alias: String) -> Result<String, KeriError> {
        let store = self.open_store()?;
        let id = store.load(&alias).map_err(|e| KeriError::Storage(e.to_string()))?;

        let aid = id.id().to_str();
        let state_present = id.find_state(id.id()).is_ok();
        let notices = id.get_kel(id.id()).unwrap_or_default();
        let kel_text = notices
            .iter()
            .map(|n| format!("{n:?}"))
            .collect::<Vec<_>>()
            .join("\n---\n");
        let key_state_repr = std::fs::read_to_string(self.key_state_path(&alias))
            .unwrap_or_else(|e| format!("<error reading key_state.json: {e}>"));
        Ok(format!(
            "alias: {alias}\n\
             AID: {aid}\n\
             state present: {state_present}\n\
             events: {}\n\
             key_state.json:\n{key_state_repr}\n\
             ---KEL---\n{kel_text}",
            notices.len(),
        ))
    }
}

impl KeriMobileSdk {
    fn factory(&self) -> Result<Arc<HostKeyProviderFactory>, KeriError> {
        self.key_factory
            .get()
            .cloned()
            .ok_or(KeriError::KeyProviderUnregistered)
    }

    fn open_store(&self) -> Result<Arc<keri_sdk::KeriStore>, KeriError> {
        let mut guard = self.store.lock().unwrap();
        if let Some(s) = guard.as_ref() {
            return Ok(s.clone());
        }
        let s = Arc::new(
            keri_sdk::KeriStore::open(self.db_path.clone())
                .map_err(|e| KeriError::Storage(e.to_string()))?,
        );
        *guard = Some(s.clone());
        Ok(s)
    }

    fn key_state_path(&self, alias: &str) -> PathBuf {
        self.db_path.join(alias).join("key_state.json")
    }

    fn save_key_state(&self, alias: &str, state: &KeyState) -> Result<(), KeriError> {
        let path = self.key_state_path(alias);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_vec_pretty(state)?)?;
        Ok(())
    }

    fn load_key_state(&self, alias: &str) -> Result<KeyState, KeriError> {
        let bytes = std::fs::read(self.key_state_path(alias))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    async fn get_signer(
        &self,
        alias: &str,
    ) -> Result<keri_sdk::keyprovider_adapter::KeriSigner, KeriError> {
        let factory = self.factory()?;
        let label = self
            .load_key_state(alias)
            .map(|s| s.current_label)
            .unwrap_or_else(|_| alias.to_string());
        let provider = factory
            .open(&label)
            .await
            .map_err(|e| KeriError::KeyProvider(e.to_string()))?;
        Ok(keri_sdk::keyprovider_adapter::KeriSigner::from(
            provider as Arc<dyn KeriKp>,
        ))
    }
}

fn map_status(s: keri_sdk::types::CredentialStatus) -> FfiCredentialStatus {
    match s {
        keri_sdk::types::CredentialStatus::Issued => FfiCredentialStatus::Issued,
        keri_sdk::types::CredentialStatus::Revoked => FfiCredentialStatus::Revoked,
        keri_sdk::types::CredentialStatus::Unknown => FfiCredentialStatus::Unknown,
    }
}
