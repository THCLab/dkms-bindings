use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiIdentifierConfig {
    pub witness_urls: Vec<String>,
    pub witness_threshold: u64,
    pub watcher_urls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiRotationConfig {
    pub new_next_pk_b64: String,
    pub witness_to_add: Vec<String>,
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
