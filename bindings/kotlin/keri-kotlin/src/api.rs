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

        // Stash the resolved LocationScheme JSON for `list_witnesses`
        // / OOBI assembly. The Identifier itself stores only the
        // BasicPrefix in its witness set; downstream consumers (e.g.
        // mesagkesto register) need the {eid, scheme, url} triple,
        // and re-resolving from the URLs each time is both slow and
        // network-flaky.
        self.save_witness_locations(&alias, &witnesses)?;
        // Same rationale for watchers — the UI needs the URL alongside
        // the EID, and only the resolution step has it.
        self.save_watcher_locations(&alias, &watchers)?;

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

        keri_sdk::operations::rotate(&mut id, signer, rot_config.clone())
            .await
            .map_err(|e| KeriError::Controller(e.to_string()))?;

        // Keep witnesses.json aligned with the new witness set so
        // `list_witnesses` (and any OOBI assembly that hangs off it)
        // reflects the rotation. Drop entries whose eid is in
        // witness_to_remove, then append the resolved add list.
        let removed_eids: std::collections::HashSet<String> = rot_config
            .witness_to_remove
            .iter()
            .map(|p| p.to_str())
            .collect();
        let mut kept: Vec<serde_json::Value> = self
            .load_witness_locations(&alias)?
            .into_iter()
            .filter(|v| {
                v.get("eid")
                    .and_then(|e| e.as_str())
                    .map(|eid| !removed_eids.contains(eid))
                    .unwrap_or(true)
            })
            .collect();
        for ws in &rot_config.witness_to_add {
            if let Ok(v) = serde_json::to_value(ws) {
                if !kept.iter().any(|existing| existing == &v) {
                    kept.push(v);
                }
            }
        }
        self.save_witness_locations_json(&alias, &kept)?;

        let previous_current =
            std::mem::replace(&mut state.current_label, state.next_label.clone());
        state.next_label = new_next_label;
        state.version += 1;
        self.save_key_state(&alias, &state)?;

        let _ = factory.delete(&previous_current).await;
        Ok(())
    }

    /// Produce a KEL rotation event on a multi-sig group AID this
    /// alias is a signing member of. Same primitive cyfron-core uses
    /// to remove a device from the group (drop its key from
    /// `new_participants`).
    ///
    /// For a 1-of-N group the acting member's signature alone is
    /// sufficient and the rotation completes in this call. For k-of-N
    /// the surviving co-signers must trigger the same rotation
    /// independently (or call `accept_multisig` on the mailbox entry
    /// produced here); witnesses collect the signatures.
    pub async fn rotate_group(
        &self,
        alias: String,
        group_aid: String,
        config: FfiGroupRotationConfig,
    ) -> Result<(), KeriError> {
        let store = self.open_store()?;
        let mut id = store
            .load(&alias)
            .map_err(|e| KeriError::Storage(e.to_string()))?;
        let signer = self.get_signer(&alias).await?;

        let group_id: keri_controller::IdentifierPrefix = group_aid
            .parse()
            .map_err(|e| KeriError::Internal(format!("invalid group AID: {e}")))?;

        let new_participants: Vec<keri_controller::IdentifierPrefix> = config
            .new_participants
            .iter()
            .map(|s| s.parse())
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| KeriError::Internal(format!("invalid participant AID: {e}")))?;

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

        let rot_config = keri_sdk::types::GroupRotationConfig {
            new_participants,
            new_signature_threshold: config.new_signature_threshold,
            new_next_threshold: config.new_next_threshold,
            witness_to_add,
            witness_to_remove,
            witness_threshold: config.witness_threshold,
        };

        keri_sdk::operations::rotate_group(&mut id, &signer, &group_id, rot_config)
            .await
            .map_err(|e| KeriError::Controller(e.to_string()))
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

        // Persist the resolved {eid, scheme, url} triples so
        // `list_witnesses` / OOBI assembly can recover them, exactly
        // as `create_identifier` does. Without this a delegated AID
        // minted with witnesses still reports an empty witness set,
        // its OOBI comes back empty, and mesagkesto register and
        // remote watcher KEL lookups both fail.
        self.save_witness_locations(&alias, &witnesses)?;

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

        // Persist the resolved {eid, scheme, url} triples so
        // `list_witnesses` / OOBI assembly can recover them, exactly
        // as `create_identifier` does. Without this a delegated AID
        // minted with witnesses still reports an empty witness set,
        // its OOBI comes back empty, and mesagkesto register and
        // remote watcher KEL lookups both fail.
        self.save_witness_locations(&alias, &witnesses)?;

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

    /// Publish a freshly-finalised delegated AID's `dip` to its
    /// witnesses so a remote watcher can later fetch the KEL.
    ///
    /// The out-of-band pairing flow (`request_delegation` +
    /// `finalize_delegation`) builds and completes the `dip` purely in
    /// the local store — it never notifies witnesses. As a result a
    /// third party resolving the delegated AID through a watcher gets
    /// `KELNotFound`. Call this after [`finalize_delegation`] (the
    /// delegator's anchoring `ixn` must already be on the shared
    /// witnesses, which the primary publishes when it approves) to push
    /// the device `dip` and pull back the witness receipts. Mirrors the
    /// desktop daemon's `publish_delegation_to_witnesses` device leg.
    ///
    /// Requires witnesses to be configured on the delegated AID (mint
    /// it with a non-empty `witness_urls`) and the delegator's KEL to
    /// be present locally (`request_delegation_with_kel` /
    /// `import_delegator_kel`).
    pub async fn publish_delegation_to_witnesses(
        &self,
        alias: String,
        delegator_aid: String,
    ) -> Result<(), KeriError> {
        let delegator: keri_controller::IdentifierPrefix = delegator_aid
            .parse()
            .map_err(|e| KeriError::Internal(format!("invalid delegator AID: {e}")))?;
        let store = self.open_store()?;
        let mut id = store
            .load(&alias)
            .map_err(|e| KeriError::Storage(e.to_string()))?;
        let signer = self.get_signer(&alias).await?;
        let delegated_prefix = id.id().clone();
        id.notify_witnesses()
            .await
            .map_err(|e| KeriError::Controller(e.to_string()))?;
        keri_sdk::operations::complete_delegation(
            &mut id,
            &signer,
            &delegated_prefix,
            &delegator,
        )
        .await
        .map_err(|e| KeriError::Controller(e.to_string()))
    }

    /// LocationScheme JSON strings for the witnesses `alias` was
    /// configured against, in creation order. Each entry is a JSON
    /// object with `{eid, scheme, url}` — the exact shape OOBI
    /// challenge assembly (mesagkesto register/authenticate)
    /// expects. Returns an empty list when the alias was created
    /// without witnesses or pre-dates this persistence pass.
    pub fn list_witnesses(&self, alias: String) -> Result<Vec<String>, KeriError> {
        Ok(self
            .load_witness_locations(&alias)?
            .iter()
            .map(|v| v.to_string())
            .collect())
    }

    /// AID prefixes of the watchers currently authorised for `alias`.
    /// Same semantics as `cyfron_core::keri::KeriController::list_watchers`
    /// so callers comparing across desktop / mobile get the same set.
    pub fn list_watchers(&self, alias: String) -> Result<Vec<String>, KeriError> {
        let store = self.open_store()?;
        let id = store
            .load(&alias)
            .map_err(|e| KeriError::Storage(e.to_string()))?;
        let watchers = id
            .watchers()
            .map_err(|e| KeriError::Controller(e.to_string()))?;
        Ok(watchers.into_iter().map(|p| p.to_str()).collect())
    }

    /// Whether `alias` has at least one authorised watcher. Used as a
    /// precondition before processing inbound traffic — without a
    /// watcher the controller has no path to fetch and verify remote
    /// KELs. Pure derivation of [`Self::list_watchers`]; surfaced as a
    /// dedicated method so callers don't pay the Vec allocation just to
    /// check non-emptiness.
    pub fn has_watcher(&self, alias: String) -> Result<bool, KeriError> {
        Ok(!self.list_watchers(alias)?.is_empty())
    }

    /// LocationScheme JSON strings for the watchers `alias` was
    /// configured against. Mirrors `list_witnesses` so the UI can show
    /// the watcher URL next to the EID without re-resolving the OOBI.
    /// Returns an empty list for aliases that pre-date watcher
    /// persistence or had no watchers at creation.
    pub fn list_watcher_locations(
        &self,
        alias: String,
    ) -> Result<Vec<String>, KeriError> {
        Ok(self
            .load_watcher_locations(&alias)?
            .iter()
            .map(|v| v.to_string())
            .collect())
    }

    /// Authorise an additional watcher for an existing `alias`. The
    /// `watcher_url` is resolved to its `LocationScheme`, the role
    /// reply is signed with the alias's current signer, and the
    /// LocationScheme is appended to the persisted list so
    /// `list_watcher_locations` reflects it on the next call.
    ///
    /// Mirrors `cyfron_core::keri::KeriController::add_watcher`.
    pub async fn add_watcher(
        &self,
        alias: String,
        watcher_url: String,
    ) -> Result<(), KeriError> {
        let location = resolve_location_scheme(&watcher_url).await?;
        let store = self.open_store()?;
        let mut id = store
            .load(&alias)
            .map_err(|e| KeriError::Storage(e.to_string()))?;
        let signer = self.get_signer(&alias).await?;
        keri_sdk::operations::add_watcher(&mut id, &signer, &location)
            .await
            .map_err(|e| KeriError::Controller(e.to_string()))?;

        let mut existing = self.load_watcher_locations(&alias)?;
        let new_val = serde_json::to_value(&location)
            .map_err(|e| KeriError::Internal(e.to_string()))?;
        if !existing.iter().any(|v| v == &new_val) {
            existing.push(new_val);
            self.save_watcher_locations_json(&alias, &existing)?;
        }
        Ok(())
    }

    /// Remove a watcher from the persisted list for `alias`. Matches
    /// the entry by `eid` (LocationScheme.eid field) and rewrites
    /// `watchers.json` without it.
    ///
    /// Config-layer remove only: KERI's `end_role_add` is not cleanly
    /// revocable from the controller side without a key rotation, so
    /// the watcher's prior authorisation reply remains in the store.
    /// In practice this is enough — the device stops querying the
    /// watcher and `list_watcher_locations` no longer surfaces it, so
    /// new OOBI assembly skips it. Mirrors the desktop daemon's
    /// `delete_watcher_handler` semantics.
    pub fn remove_watcher(
        &self,
        alias: String,
        watcher_eid: String,
    ) -> Result<(), KeriError> {
        let existing = self.load_watcher_locations(&alias)?;
        let filtered: Vec<serde_json::Value> = existing
            .into_iter()
            .filter(|v| {
                v.get("eid").and_then(|e| e.as_str()) != Some(watcher_eid.as_str())
            })
            .collect();
        self.save_watcher_locations_json(&alias, &filtered)
    }

    /// Head (sn, SAID) of the locally-stored KEL for `aid`, looked up
    /// through `via_alias`'s redb. `None` when no KEL is stored yet
    /// (e.g. the AID was never resolved by this alias's watcher).
    ///
    /// Mirrors `cyfron_core::keri::KeriController::kel_head`.
    pub fn kel_head(
        &self,
        via_alias: String,
        aid: String,
    ) -> Result<Option<FfiKelHead>, KeriError> {
        use keri_core::prefix::IdentifierPrefix;
        use std::str::FromStr;
        let store = self.open_store()?;
        let id = store
            .load(&via_alias)
            .map_err(|e| KeriError::Storage(e.to_string()))?;
        let target = IdentifierPrefix::from_str(&aid).map_err(|e| {
            KeriError::Controller(format!("invalid aid {aid}: {e}"))
        })?;
        match id.find_state(&target) {
            Ok(s) => Ok(Some(FfiKelHead {
                sn: s.sn,
                said: s.last_event_digest.said.to_str(),
            })),
            Err(_) => Ok(None),
        }
    }

    /// Pull `target_aid`'s full KEL via every watcher authorised for
    /// `via_alias`. Returns `Ok(())` only after at least one watcher
    /// has responded AND the resulting state was persisted locally —
    /// matches `cyfron_core::keri::KeriController::query_kel_for`'s
    /// "no false-positive sync" guarantee so the UI's "KEL synced"
    /// toast on desktop and mobile mean the same thing.
    pub async fn query_kel_for(
        &self,
        via_alias: String,
        target_aid: String,
    ) -> Result<(), KeriError> {
        use keri_controller::SelfSigningPrefix;
        use keri_core::prefix::IdentifierPrefix;
        use keri_sdk::operations::SigningBackend;
        use std::str::FromStr;

        let store = self.open_store()?;
        let id = store
            .load(&via_alias)
            .map_err(|e| KeriError::Storage(e.to_string()))?;
        let signer = self.get_signer(&via_alias).await?;
        let target = IdentifierPrefix::from_str(&target_aid).map_err(|e| {
            KeriError::Controller(format!("invalid target aid {target_aid}: {e}"))
        })?;

        let watchers = id
            .watchers()
            .map_err(|e| KeriError::Controller(e.to_string()))?;
        if watchers.is_empty() {
            return Err(KeriError::Controller(format!(
                "alias {via_alias} has no watcher configured; cannot fetch KEL for {target_aid}"
            )));
        }

        let mut queries = Vec::with_capacity(watchers.len());
        for watcher in watchers {
            let qry = id.query_full_log(&target, watcher).map_err(|e| {
                KeriError::Controller(format!("query_full_log failed: {e}"))
            })?;
            let encoded = qry
                .encode()
                .map_err(|e| KeriError::Controller(e.to_string()))?;
            let sig_bytes = signer
                .sign_data(&encoded)
                .map_err(|e| KeriError::Controller(format!("sign_data: {e}")))?;
            queries.push((qry, SelfSigningPrefix::Ed25519Sha512(sig_bytes)));
        }

        let total = queries.len();
        let (_resp, errs) = id.finalize_query(queries).await;
        if errs.len() >= total {
            return Err(KeriError::Controller(format!(
                "no watcher returned a KEL for {target_aid}: {errs:?}"
            )));
        }
        if id.inner().known_events.find_kel(&target).is_none() {
            return Err(KeriError::Controller(format!(
                "watcher accepted but no KEL stored for {target_aid}"
            )));
        }
        Ok(())
    }

    /// Record an OOBI in `via_alias`'s local controller so the
    /// controller knows where to find the referenced peer's
    /// witnesses. This is the first half of the cyfron-style
    /// peer-onboarding pair — call [`Self::send_oobi_to_watcher`]
    /// next so a configured watcher can actually fetch the peer's
    /// KEL on demand. Either step alone is insufficient: location
    /// info without watcher delegation leaves the watcher unable
    /// to authenticate later `query_kel_for` calls.
    ///
    /// `oobi_json` accepts either of two shapes:
    ///
    ///   * `{"eid": "...", "scheme": "https", "url": "..."}` — a
    ///     LocationScheme, used for both witness OOBIs and watcher
    ///     OOBIs.
    ///   * `{"cid": "...", "eid": "...", "role": "witness"|"watcher"}` —
    ///     an EndRole binding, used to associate an AID with its
    ///     authorised end-role agent.
    ///
    /// Mirrors `cyfron_core::keri::KeriController::resolve_oobi_any`.
    pub async fn resolve_oobi(
        &self,
        via_alias: String,
        oobi_json: String,
    ) -> Result<(), KeriError> {
        use keri_controller::{EndRole, LocationScheme, Oobi};
        let oobi = parse_oobi_json(&oobi_json)?;
        let store = self.open_store()?;
        let id = store
            .load(&via_alias)
            .map_err(|e| KeriError::Storage(e.to_string()))?;
        id.resolve_oobi(&oobi)
            .await
            .map_err(|e| KeriError::Controller(e.to_string()))?;
        // Silence unused-import warnings: the parse helper covers
        // both shapes; we still want the explicit `use` for readers
        // who jump straight to this function.
        let _: Option<LocationScheme> = None;
        let _: Option<EndRole> = None;
        let _: Option<Oobi> = None;
        Ok(())
    }

    /// Push an OOBI to `via_alias`'s authorised watcher so the
    /// watcher can fetch / verify the referenced KEL on demand.
    /// [`Self::resolve_oobi`] alone only records location info in
    /// the local controller — without this step the watcher has no
    /// way to reach the peer's witnesses, and a subsequent
    /// [`Self::query_kel_for`] returns `InvalidSignature` from the
    /// watcher actor (it can't validate a KEL it never fetched).
    ///
    /// `oobi_json` accepts the same two shapes as
    /// [`Self::resolve_oobi`]. Mirrors
    /// `cyfron_core::keri::KeriController::send_oobi_to_watcher`.
    pub async fn send_oobi_to_watcher(
        &self,
        via_alias: String,
        oobi_json: String,
    ) -> Result<(), KeriError> {
        let oobi = parse_oobi_json(&oobi_json)?;
        let store = self.open_store()?;
        let id = store
            .load(&via_alias)
            .map_err(|e| KeriError::Storage(e.to_string()))?;
        let our_id = id.id().clone();
        id.send_oobi_to_watcher(&our_id, &oobi)
            .await
            .map_err(|e| KeriError::Controller(e.to_string()))?;
        Ok(())
    }

    /// Sign `json` and return the wire form mesagkesto expects:
    /// `<JSON_payload><CESR_signatures>` concatenated. Unlike
    /// [`Self::sign`], the payload is NOT wrapped in a `{"p":"…"}`
    /// envelope — the bytes the caller passed in are the payload
    /// half of the output.
    ///
    /// Mirrors `cyfron_core::keri::KeriController::sign_raw_cesr`
    /// byte-for-byte so server-side challenge/response verification
    /// handles desktop and mobile the same way.
    pub async fn sign_to_cesr(
        &self,
        alias: String,
        json: String,
    ) -> Result<String, KeriError> {
        let store = self.open_store()?;
        let id = store
            .load(&alias)
            .map_err(|e| KeriError::Storage(e.to_string()))?;
        let signer = self.get_signer(&alias).await?;
        keri_sdk::signing::sign_to_cesr(&id, &signer, &json)
            .map_err(|e| KeriError::Controller(e.to_string()))
    }

    /// Export the locally-stored KEL for `aid` as CESR bytes, looked up
    /// through `via_alias`'s redb. Returns the same byte stream that
    /// `KnownEvents::find_kel` produces — the wire form callers like
    /// `cyfron_core::keri::summarize_kel_for_cesr` parse into a
    /// human-readable summary.
    ///
    /// `via_alias` is the alias whose store is consulted first. When
    /// the target AID is the alias's own AID (or any AID a watcher
    /// query has previously resolved into it) the bytes come back
    /// immediately. For multi-sig group AIDs, the typical caller is the
    /// *member* alias that participates in the group — the group's KEL
    /// is fetched into the member's redb via prior watcher queries.
    ///
    /// Errors with a `PersistenceError` when no KEL is stored locally
    /// for `aid` under `via_alias`. Callers that want to fall back
    /// across every alias should iterate themselves; this method
    /// intentionally does not, so the caller controls which alias's
    /// signature trail it is reading.
    pub fn export_kel_cesr_for(
        &self,
        via_alias: String,
        aid: String,
    ) -> Result<Vec<u8>, KeriError> {
        use keri_core::prefix::IdentifierPrefix;
        use std::str::FromStr;
        let store = self.open_store()?;
        let id = store
            .load(&via_alias)
            .map_err(|e| KeriError::Storage(e.to_string()))?;
        let target = IdentifierPrefix::from_str(&aid).map_err(|e| {
            KeriError::Controller(format!("invalid aid {aid}: {e}"))
        })?;
        id.inner()
            .known_events
            .find_kel(&target)
            .map(|k| k.into_bytes())
            .ok_or_else(|| {
                KeriError::Storage(format!("no KEL stored for {aid} under alias {via_alias}"))
            })
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

    fn witnesses_path(&self, alias: &str) -> PathBuf {
        self.db_path.join(alias).join("witnesses.json")
    }

    fn watchers_path(&self, alias: &str) -> PathBuf {
        self.db_path.join(alias).join("watchers.json")
    }

    fn save_witness_locations(
        &self,
        alias: &str,
        witnesses: &[keri_core::oobi::LocationScheme],
    ) -> Result<(), KeriError> {
        let json_values: Vec<serde_json::Value> = witnesses
            .iter()
            .map(|w| serde_json::to_value(w).unwrap_or(serde_json::Value::Null))
            .filter(|v| !v.is_null())
            .collect();
        self.save_witness_locations_json(alias, &json_values)
    }

    fn save_witness_locations_json(
        &self,
        alias: &str,
        values: &[serde_json::Value],
    ) -> Result<(), KeriError> {
        let path = self.witnesses_path(alias);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_vec_pretty(values)?)?;
        Ok(())
    }

    fn load_witness_locations(
        &self,
        alias: &str,
    ) -> Result<Vec<serde_json::Value>, KeriError> {
        let path = self.witnesses_path(alias);
        match std::fs::read(&path) {
            Ok(bytes) if !bytes.is_empty() => Ok(serde_json::from_slice(&bytes)?),
            _ => Ok(Vec::new()),
        }
    }

    fn save_watcher_locations(
        &self,
        alias: &str,
        watchers: &[keri_core::oobi::LocationScheme],
    ) -> Result<(), KeriError> {
        let json_values: Vec<serde_json::Value> = watchers
            .iter()
            .map(|w| serde_json::to_value(w).unwrap_or(serde_json::Value::Null))
            .filter(|v| !v.is_null())
            .collect();
        self.save_watcher_locations_json(alias, &json_values)
    }

    fn save_watcher_locations_json(
        &self,
        alias: &str,
        values: &[serde_json::Value],
    ) -> Result<(), KeriError> {
        let path = self.watchers_path(alias);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_vec_pretty(values)?)?;
        Ok(())
    }

    fn load_watcher_locations(
        &self,
        alias: &str,
    ) -> Result<Vec<serde_json::Value>, KeriError> {
        let path = self.watchers_path(alias);
        match std::fs::read(&path) {
            Ok(bytes) if !bytes.is_empty() => Ok(serde_json::from_slice(&bytes)?),
            _ => Ok(Vec::new()),
        }
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

/// Parse an OOBI from JSON. Accepts either a LocationScheme
/// (`{eid, scheme, url}`) or an EndRole (`{cid, eid, role}`).
/// The shape is auto-detected by which keys are present so callers
/// can hand us either canonical OOBI form without having to know
/// the type up front. Mirrors the parsing inside
/// `cyfron-serviced::handlers::contacts::bootstrap_peer_verification`.
fn parse_oobi_json(s: &str) -> Result<keri_controller::Oobi, KeriError> {
    use keri_controller::{EndRole, LocationScheme, Oobi};
    let value: serde_json::Value = serde_json::from_str(s)
        .map_err(|e| KeriError::Controller(format!("oobi_json not JSON: {e}")))?;
    if value.get("cid").is_some() && value.get("role").is_some() {
        let er: EndRole = serde_json::from_value(value)
            .map_err(|e| KeriError::Controller(format!("oobi_json not EndRole: {e}")))?;
        Ok(Oobi::EndRole(er))
    } else if value.get("url").is_some() {
        let ls: LocationScheme = serde_json::from_value(value)
            .map_err(|e| KeriError::Controller(format!("oobi_json not LocationScheme: {e}")))?;
        Ok(Oobi::Location(ls))
    } else {
        Err(KeriError::Controller(format!(
            "oobi_json missing both 'url' (LocationScheme) and 'cid+role' (EndRole): {s}"
        )))
    }
}

fn map_status(s: keri_sdk::types::CredentialStatus) -> FfiCredentialStatus {
    match s {
        keri_sdk::types::CredentialStatus::Issued => FfiCredentialStatus::Issued,
        keri_sdk::types::CredentialStatus::Revoked => FfiCredentialStatus::Revoked,
        keri_sdk::types::CredentialStatus::Unknown => FfiCredentialStatus::Unknown,
    }
}
