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

/// Inputs for `KeriMobileSdk::request_delegation`. The joiner side
/// of a device-pairing wizard uses this to ask its local key store
/// to mint a delegated AID and produce the `dip` event for
/// out-of-band transport to the delegator.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiDelegationConfig {
    /// Delegator's AID prefix (e.g. the primary device's main AID).
    pub delegator_aid: String,
    /// Witness LocationScheme URLs for the delegated AID. May be
    /// empty for fully out-of-band pairings (the cyfron QR flow does
    /// not configure witnesses on the joiner side).
    pub witness_urls: Vec<String>,
    /// k-of-N witness signing threshold for the delegated AID.
    pub witness_threshold: u64,
    /// Signing algorithm for the delegated AID's current key.
    pub algorithm: crate::key_provider::SignatureAlgo,
}

/// Returned by `KeriMobileSdk::request_delegation`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiDelegationRequest {
    /// Freshly-created delegated AID, as a string prefix.
    pub delegated_aid: String,
    /// CESR-encoded `dip` event ready to send out-of-band to the
    /// delegator. The delegator counter-signs an `ixn` anchoring
    /// this event's SAID and returns it for
    /// `finalize_delegation`.
    pub dip_cesr: String,
}
