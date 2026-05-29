#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiIdentifierConfig {
    pub witness_urls: Vec<String>,
    pub witness_threshold: u64,
    pub watcher_urls: Vec<String>,
    pub algorithm: crate::key_provider::SignatureAlgo,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiRotationConfig {
    pub witness_to_add: Vec<String>,
    pub witness_to_remove: Vec<String>,
    pub witness_threshold: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSignedEnvelope {
    pub payload: Vec<u8>,
    pub cesr: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiVerifiedPayload {
    pub payload: Vec<u8>,
    pub signer_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiCredentialStatus {
    Issued,
    Revoked,
    Unknown,
}
