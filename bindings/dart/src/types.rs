use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiIdentifierConfig {
    pub witness_urls: Vec<String>,
    pub witness_threshold: u64,
    pub watcher_urls: Vec<String>,
    /// "Ed25519" or "EcdsaSecp256r1". Persisted in KeyState so rotation
    /// keeps the same algorithm without the caller needing to specify it.
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiRotationConfig {
    /// Plain witness base URLs to register (e.g. "https://witness1.example/").
    /// The Rust side fetches `<url>/introduce` to obtain the LocationScheme.
    pub witness_to_add: Vec<String>,
    /// Witness EIDs to remove (string-encoded BasicPrefix).
    pub witness_to_remove: Vec<String>,
    pub witness_threshold: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiDelegationConfig {
    pub delegator_id: String,
    pub witness_urls: Vec<String>,
    pub witness_threshold: u64,
    pub watcher_urls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiMultisigConfig {
    pub member_ids: Vec<String>,
    pub threshold: u64,
    pub witness_urls: Vec<String>,
    pub witness_threshold: u64,
    pub delegator_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiSignedEnvelope {
    pub payload: Vec<u8>,
    pub cesr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiVerifiedPayload {
    pub payload: Vec<u8>,
    pub signer_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FfiCredentialStatus {
    Issued,
    Revoked,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FfiPendingRequestType {
    Delegation,
    Multisig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiPendingRequest {
    pub request_type: FfiPendingRequestType,
    pub identifier_id: String,
}
