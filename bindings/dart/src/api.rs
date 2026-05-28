use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use base64::Engine;
use serde::{Deserialize, Serialize};

use flutter_rust_bridge::DartFnFuture;
use keri_keyprovider::{
    host::HostKeyProviderFactory,
    KeyProvider, KeyProviderFactory, PublicKeyData, SignatureAlgorithm,
};
use keri_core::prefix::CesrPrimitive;

use crate::types::*;

/// Per-alias keystore-label bookkeeping that lives next to the KeriStore DB
/// (in `<db_path>/<alias>/key_state.json`). Rust owns it so signing and
/// rotation continue to work after the device-side labels diverge from the
/// human-friendly alias.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyState {
    current_label: String,
    next_label: String,
    version: u32,
    /// Persisted as the SignatureAlgorithm Debug string ("Ed25519",
    /// "EcdsaSecp256r1"). Default for older records is Ed25519.
    #[serde(default = "default_algorithm")]
    algorithm: String,
}

fn default_algorithm() -> String { "Ed25519".to_string() }

fn parse_algorithm(s: &str) -> Result<SignatureAlgorithm> {
    match s {
        "Ed25519" => Ok(SignatureAlgorithm::Ed25519),
        "EcdsaSecp256k1" => Ok(SignatureAlgorithm::EcdsaSecp256k1),
        "EcdsaSecp256r1" | "P256" => Ok(SignatureAlgorithm::EcdsaSecp256r1),
        other => Err(anyhow::anyhow!("unsupported algorithm '{other}'")),
    }
}

fn signer_algorithm(a: SignatureAlgorithm) -> keri_core::signer::SignerAlgorithm {
    match a {
        SignatureAlgorithm::Ed25519 => keri_core::signer::SignerAlgorithm::Ed25519,
        SignatureAlgorithm::EcdsaSecp256k1 => keri_core::signer::SignerAlgorithm::EcdsaSecp256k1,
        SignatureAlgorithm::EcdsaSecp256r1 => keri_core::signer::SignerAlgorithm::EcdsaSecp256r1,
    }
}

/// Parse `alias` out of a versioned key label (`alice_v3` → `alice`).
/// Aliases themselves may contain underscores; we only strip the final
/// `_v<digits>` segment.
fn alias_from_label(label: &str) -> &str {
    if let Some((alias, suffix)) = label.rsplit_once('_') {
        if suffix.starts_with('v') && suffix[1..].chars().all(|c| c.is_ascii_digit()) {
            return alias;
        }
    }
    label
}

/// Read the persisted `KeyState` algorithm for the alias that owns [label].
/// Falls back to Ed25519 when no state has been written yet (covers the
/// initial `factory.create` calls during identifier creation).
fn algorithm_for_label(db_path: &std::path::Path, label: &str) -> SignatureAlgorithm {
    let alias = alias_from_label(label);
    let path = db_path.join(alias).join("key_state.json");
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(state) = serde_json::from_slice::<KeyState>(&bytes) {
            if let Ok(algo) = parse_algorithm(&state.algorithm) {
                return algo;
            }
        }
    }
    SignatureAlgorithm::Ed25519
}

/// Build a `BasicPrefix` for the given algorithm.
///
/// `transferable = true` selects the rotation-capable variant
/// (Ed25519/ECDSAsecp256k1/ECDSA256r1). `false` selects the non-transferable
/// variant. Next-key commitments must use the NT variant — that is the
/// canonical CESR code KERI hashes during pre-rotation, and the SDK's
/// `operations::rotate` reveals next-keys as NT for the same reason.
fn basic_prefix_for(
    algo: SignatureAlgorithm,
    pk_bytes: Vec<u8>,
    transferable: bool,
) -> keri_controller::BasicPrefix {
    let pk = keri_core::keys::PublicKey::new(pk_bytes);
    match (algo, transferable) {
        (SignatureAlgorithm::Ed25519, true) => keri_controller::BasicPrefix::Ed25519(pk),
        (SignatureAlgorithm::Ed25519, false) => keri_controller::BasicPrefix::Ed25519NT(pk),
        (SignatureAlgorithm::EcdsaSecp256k1, true) => keri_controller::BasicPrefix::ECDSAsecp256k1(pk),
        (SignatureAlgorithm::EcdsaSecp256k1, false) => keri_controller::BasicPrefix::ECDSAsecp256k1NT(pk),
        (SignatureAlgorithm::EcdsaSecp256r1, true) => keri_controller::BasicPrefix::ECDSA256r1(pk),
        (SignatureAlgorithm::EcdsaSecp256r1, false) => keri_controller::BasicPrefix::ECDSA256r1NT(pk),
    }
}

/// Fetch a witness's `LocationScheme` introduction document.
///
/// dkms-bin uses the same convention: `GET <base_url>/introduce` returns a
/// JSON `LocationScheme` carrying the witness's EID, scheme, and reachable
/// URL.
async fn resolve_location_scheme(url: &str) -> Result<keri_core::oobi::LocationScheme> {
    let base = url::Url::parse(url)
        .map_err(|e| anyhow::anyhow!("invalid URL '{url}': {e}"))?;
    let introduce = base
        .join("introduce")
        .map_err(|e| anyhow::anyhow!("failed to build introduce URL for '{url}': {e}"))?;
    let resp = reqwest::get(introduce).await
        .map_err(|e| anyhow::anyhow!("GET introduce on '{url}' failed: {e}"))?;
    let loc = resp
        .json::<keri_core::oobi::LocationScheme>()
        .await
        .map_err(|e| anyhow::anyhow!("invalid LocationScheme from '{url}': {e}"))?;
    Ok(loc)
}

/// Runs a Dart future to completion from a synchronous Rust closure that itself
/// is invoked from inside Tokio's async runtime.
///
/// `block_in_place` tells the current worker thread it's about to block so other
/// tasks can be migrated; `Handle::current().block_on` then drives the Dart
/// future to completion on that thread. Requires the multi-threaded Tokio
/// runtime (which `flutter_rust_bridge` uses by default).
fn block_on_dart<T>(fut: DartFnFuture<T>) -> T {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(fut)
    })
}

pub struct KeriMobileSdk {
    db_path: PathBuf,
    key_factory: Option<Arc<HostKeyProviderFactory>>,
    // One KeriStore per SDK instance so its internal controller cache
    // survives across FFI calls — redb takes an exclusive flock and refuses
    // a second open at the same path, even from the same process.
    store: Mutex<Option<Arc<keri_sdk::KeriStore>>>,
}

impl KeriMobileSdk {
    pub fn new(db_path: String) -> Result<Self> {
        Ok(Self {
            db_path: PathBuf::from(&db_path),
            key_factory: None,
            store: Mutex::new(None),
        })
    }

    /// Register the host-side key provider. Each callback is a Dart async
    /// function: errors should be thrown as Dart exceptions, which propagate
    /// here as Rust errors via `flutter_rust_bridge`'s `DartFnFuture` adapter.
    pub fn register_key_provider(
        &mut self,
        create_key: impl Fn(String, String) -> DartFnFuture<Vec<u8>> + Send + Sync + 'static,
        open_key: impl Fn(String) -> DartFnFuture<Vec<u8>> + Send + Sync + 'static,
        sign: impl Fn(String, Vec<u8>) -> DartFnFuture<Vec<u8>> + Send + Sync + 'static,
        delete_key: impl Fn(String) -> DartFnFuture<()> + Send + Sync + 'static,
        list_keys: impl Fn() -> DartFnFuture<Vec<String>> + Send + Sync + 'static,
    ) {
        let create_fn = move |label: &str, algo: SignatureAlgorithm| {
            let algo_str = match algo {
                SignatureAlgorithm::Ed25519 => "Ed25519",
                SignatureAlgorithm::EcdsaSecp256k1 => "EcdsaSecp256k1",
                SignatureAlgorithm::EcdsaSecp256r1 => "EcdsaSecp256r1",
            };
            let pk_bytes = block_on_dart(create_key(label.to_string(), algo_str.to_string()));
            Ok(PublicKeyData::new(algo, pk_bytes))
        };

        let db_path_for_open = self.db_path.clone();
        let open_fn = move |label: &str| {
            let pk_bytes = block_on_dart(open_key(label.to_string()));
            let algo = algorithm_for_label(&db_path_for_open, label);
            Ok(PublicKeyData::new(algo, pk_bytes))
        };

        let sign_fn = move |label: &str, msg: &[u8]| {
            Ok(block_on_dart(sign(label.to_string(), msg.to_vec())))
        };

        let delete_fn = move |label: &str| {
            block_on_dart(delete_key(label.to_string()));
            Ok(())
        };

        let list_fn = move || {
            Ok(block_on_dart(list_keys()))
        };

        self.key_factory = Some(Arc::new(HostKeyProviderFactory::new(
            create_fn, open_fn, sign_fn, delete_fn, list_fn,
        )));
    }

    /// Drop the cached `KeriStore` (releasing the redb flock) and recursively
    /// delete `db_path`. Idempotent. The Android-side keystore is wiped
    /// separately by the host, since this struct doesn't own those secrets.
    pub fn wipe(&self) -> Result<()> {
        // Take + drop the Arc first so the inner KeriStore drops, which drops
        // every cached Controller, which releases redb's flock.
        {
            let mut guard = self.store.lock().unwrap();
            *guard = None;
        }
        if self.db_path.exists() {
            std::fs::remove_dir_all(&self.db_path).map_err(|e| {
                anyhow::anyhow!("failed to wipe db_path {:?}: {e}", self.db_path)
            })?;
        }
        Ok(())
    }

    fn open_store(&self) -> Result<Arc<keri_sdk::KeriStore>> {
        let mut guard = self.store.lock().unwrap();
        if let Some(s) = guard.as_ref() {
            return Ok(s.clone());
        }
        let s = Arc::new(keri_sdk::KeriStore::open(self.db_path.clone())?);
        *guard = Some(s.clone());
        Ok(s)
    }

    fn get_factory(&self) -> Result<Arc<HostKeyProviderFactory>> {
        self.key_factory.clone().ok_or_else(|| {
            anyhow::anyhow!("Key provider not registered. Call register_key_provider() first.")
        })
    }

    /// Open the signer for [alias] using the current key label tracked in
    /// `KeyState`. Falls back to the alias itself if no KeyState exists yet
    /// (covers identifiers created by older code paths).
    async fn get_signer(&self, alias: &str) -> Result<keri_sdk::keyprovider_adapter::KeriSigner> {
        let factory = self.get_factory()?;
        let label = self
            .load_key_state(alias)
            .map(|s| s.current_label)
            .unwrap_or_else(|_| alias.to_string());
        let provider = factory.open(&label).await?;
        Ok(keri_sdk::keyprovider_adapter::KeriSigner::from(provider as Arc<dyn KeyProvider>))
    }

    fn key_state_path(&self, alias: &str) -> PathBuf {
        self.db_path.join(alias).join("key_state.json")
    }

    fn save_key_state(&self, alias: &str, state: &KeyState) -> Result<()> {
        let path = self.key_state_path(alias);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_vec_pretty(state)?)?;
        Ok(())
    }

    fn load_key_state(&self, alias: &str) -> Result<KeyState> {
        let bytes = std::fs::read(self.key_state_path(alias))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Create a new KERI identifier. Mints the current and next signing keys
    /// in the host key provider (one `createKey` callback each), commits to
    /// the next-key, and persists the alias-to-label mapping so subsequent
    /// signs and rotations pick up the right labels.
    pub async fn create_identifier(
        &self,
        alias: String,
        config: FfiIdentifierConfig,
    ) -> Result<String> {
        let factory = self.get_factory()?;
        let algo = parse_algorithm(&config.algorithm)?;
        let current_label = format!("{alias}_v1");
        let next_label = format!("{alias}_v2");

        let current_provider = factory.create(&current_label, algo).await?;
        let next_provider = factory.create(&next_label, algo).await?;

        let next_pk = basic_prefix_for(algo, next_provider.public_key().bytes.clone(), false);

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
                current_provider as Arc<dyn KeyProvider>,
                next_pk,
                sdk_config,
            )
            .await?;

        store.save_id(&alias, id.id())?;
        self.save_key_state(
            &alias,
            &KeyState {
                current_label,
                next_label,
                version: 1,
                algorithm: config.algorithm.clone(),
            },
        )?;

        Ok(id.id().to_str())
    }

    /// Return the saved AID, the raw KEL (CESR bytes as String, lossy UTF-8),
    /// and whether the controller's storage currently has a key state record
    /// for that AID. Diagnostic helper — also useful for "show KEL" UI.
    pub fn show_kel(&self, alias: String) -> Result<String> {
        let store = self.open_store()?;
        let id = store.load(&alias)?;

        let aid = id.id().to_str();
        let state_present = id.find_state(id.id()).is_ok();
        let notices = id.get_kel(id.id()).unwrap_or_default();
        let kel_text = notices
            .iter()
            .map(|n| format!("{n:?}"))
            .collect::<Vec<_>>()
            .join("\n---\n");

        let key_state_path = self.key_state_path(&alias);
        let key_state_repr = match std::fs::read_to_string(&key_state_path) {
            Ok(s) => s,
            Err(e) => format!("<error reading {key_state_path:?}: {e}>"),
        };

        // Run algorithm_for_label for the labels we expect to exist for this
        // alias; this is exactly what the open/sign callbacks will resolve at
        // rotation time. If this disagrees with key_state.json the lookup is
        // broken.
        let resolved_v1 = format!("{:?}", algorithm_for_label(&self.db_path, &format!("{alias}_v1")));
        let resolved_v2 = format!("{:?}", algorithm_for_label(&self.db_path, &format!("{alias}_v2")));

        Ok(format!(
            "alias: {alias}\n\
             AID: {aid}\n\
             state present: {state_present}\n\
             events: {}\n\
             key_state path: {key_state_path:?}\n\
             key_state contents:\n{key_state_repr}\n\
             algorithm_for_label({alias}_v1) = {resolved_v1}\n\
             algorithm_for_label({alias}_v2) = {resolved_v2}\n\
             ---KEL---\n{kel_text}",
            notices.len(),
        ))
    }

    /// Read the bytes the host currently has for `<alias>_v2`, reconstruct
    /// the `BasicPrefix` that should match the inception's next-key commitment,
    /// and compare its Blake3 digest to the digest persisted in the KEL.
    /// Returns a multi-line string so a human can eyeball every field.
    pub async fn verify_next_binding(&self, alias: String) -> Result<String> {
        use cesrox::primitives::CesrPrimitive;

        let state = self.load_key_state(&alias)?;
        let algo = parse_algorithm(&state.algorithm)?;

        let factory = self.get_factory()?;
        let next_provider = factory.open(&state.next_label).await?;
        let next_bytes = next_provider.public_key().bytes.clone();
        let next_bp = basic_prefix_for(algo, next_bytes.clone(), false);
        let next_bp_str = next_bp.to_str();

        // Compute the digest the rotation flow would test against.
        let computed_digest = said::derivation::HashFunction::from(
            said::derivation::HashFunctionCode::Blake3_256,
        )
        .derive(next_bp_str.as_bytes());

        // Pull the committed digest out of the KEL.
        let store = self.open_store()?;
        let id = store.load(&alias)?;
        let kel_state = id.find_state(id.id())
            .map_err(|e| anyhow::anyhow!("no state for {}: {e}", id.id().to_str()))?;
        let committed = kel_state
            .current
            .next_keys_data
            .next_keys_hashes()
            .first()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("KEL has no committed next-key hash"))?;

        let bytes_hex = next_bytes.iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        Ok(format!(
            "label: {}\n\
             algorithm: {}\n\
             host bytes ({} bytes): {bytes_hex}\n\
             basic prefix: {next_bp_str}\n\
             computed Blake3 digest: {}\n\
             committed digest:      {}\n\
             match: {}",
            state.next_label,
            state.algorithm,
            next_bytes.len(),
            computed_digest.to_str(),
            committed.to_str(),
            computed_digest == committed,
        ))
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

    /// Rotate the signing keys for [alias].
    ///
    /// Mechanics: the next-key that was committed in the previous event is
    /// revealed and becomes the new current signer; we mint a fresh
    /// next-next-key via the host callback and commit to it. On success the
    /// previous current key is wiped from the host keystore.
    pub async fn rotate_keys(
        &self,
        alias: String,
        config: FfiRotationConfig,
    ) -> Result<()> {
        let factory = self.get_factory()?;
        let store = self.open_store()?;
        let mut id = store.load(&alias)?;
        let mut state = self.load_key_state(&alias)?;

        let new_current_provider = factory.open(&state.next_label).await?;
        let signer = keri_sdk::keyprovider_adapter::KeriSigner::from(
            new_current_provider as Arc<dyn KeyProvider>,
        );

        let algo = parse_algorithm(&state.algorithm)?;
        let new_next_label = format!("{alias}_v{}", state.version + 2);
        let new_next_provider = factory.create(&new_next_label, algo).await?;
        let new_next_pk = basic_prefix_for(algo, new_next_provider.public_key().bytes.clone(), false);

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

        keri_sdk::operations::rotate(&mut id, signer, rot_config).await?;

        let previous_current = std::mem::replace(&mut state.current_label, state.next_label.clone());
        state.next_label = new_next_label;
        state.version += 1;
        self.save_key_state(&alias, &state)?;

        // Best-effort wipe of the now-superseded current key. Failure here is
        // not fatal — the on-disk state already reflects the rotation.
        let _ = factory.delete(&previous_current).await;

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
