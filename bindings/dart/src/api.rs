use std::sync::Mutex;

use flutter_rust_bridge::support::lazy_static;

use anyhow::Result;
use keriox_wrapper::kel::{
    key_prefix_from_b64, signature_prefix_from_b64, signature_prefix_from_hex, Kel, KeyDerivation,
    SignatureDerivation,
};

pub enum KeyType {
    ECDSAsecp256k1,
    Ed25519,
    Ed448,
    X25519,
    X448,
}

impl Into<KeyDerivation> for KeyType {
    fn into(self) -> KeyDerivation {
        match self {
            KeyType::ECDSAsecp256k1 => KeyDerivation::ECDSAsecp256k1NT,
            KeyType::Ed25519 => KeyDerivation::Ed25519NT,
            KeyType::Ed448 => KeyDerivation::Ed448NT,
            KeyType::X25519 => KeyDerivation::X25519,
            KeyType::X448 => KeyDerivation::X448,
        }
    }
}

pub enum SignatureType {
    Ed25519Sha512,
    ECDSAsecp256k1Sha256,
    Ed448,
}

impl Into<SignatureDerivation> for SignatureType {
    fn into(self) -> SignatureDerivation {
        match self {
            SignatureType::Ed25519Sha512 => SignatureDerivation::Ed25519Sha512,
            SignatureType::ECDSAsecp256k1Sha256 => SignatureDerivation::ECDSAsecp256k1Sha256,
            SignatureType::Ed448 => SignatureDerivation::Ed448,
        }
    }
}

pub struct PublicKey {
    pub(crate) algorithm: KeyType,
    /// base 64 string of public key
    pub(crate) key: String,
}
impl PublicKey {
    pub fn new(algorithm: KeyType, key: &str) -> Self {
        Self {
            algorithm,
            key: key.to_string(),
        }
    }
}

pub struct Signature {
    pub(crate) algorithm: SignatureType,
    /// hex string of signature
    pub(crate) key: String,
}
impl Signature {
    pub fn new(algorithm: SignatureType, key: String) -> Self {
        Self {
            algorithm,
            key: key,
        }
    }
}

lazy_static! {
    static ref KEL: Mutex<Option<Kel>> = Mutex::new(None);
}

pub struct Controller {
    pub identifier: String,
}

impl Controller {
    pub fn get_id(&self) -> String {
        self.identifier.clone()
    }
}

pub fn init_kel(input_app_dir: String) -> Result<()> {
    *KEL.lock().unwrap() = Some(Kel::init(input_app_dir));
    Ok(())
}

pub fn incept(
    public_keys: Vec<PublicKey>,
    next_pub_keys: Vec<PublicKey>,
    witnesses: Vec<String>,
    witness_threshold: u64,
) -> Result<String> {
    let icp = (*KEL.lock().unwrap()).as_ref().unwrap().incept(
        public_keys
            .into_iter()
            .map(|pk| key_prefix_from_b64(&pk.key, pk.algorithm.into()).unwrap())
            .collect(),
        next_pub_keys
            .into_iter()
            .map(|pk| key_prefix_from_b64(&pk.key, pk.algorithm.into()).unwrap())
            .collect(),
        witnesses,
        witness_threshold,
    )?;
    Ok(icp)
}

pub fn finalize_inception(event: String, signature: Signature) -> Result<Controller> {
    let controller_id = (*KEL.lock().unwrap())
        .as_ref()
        .unwrap()
        .finalize_inception(
            event,
            signature_prefix_from_hex(&signature.key, signature.algorithm.into())?,
        )?;
    Ok(Controller {
        identifier: controller_id,
    })
}

pub fn rotate(
    controller: Controller,
    current_keys: Vec<PublicKey>,
    new_next_keys: Vec<PublicKey>,
    witness_to_add: Vec<String>,
    witness_to_remove: Vec<String>,
    witness_threshold: u64,
) -> Result<String> {
    let rot = (*KEL.lock().unwrap()).as_ref().unwrap().rotate(
        controller.identifier,
        current_keys
            .into_iter()
            .map(|pk| key_prefix_from_b64(&pk.key, pk.algorithm.into()).unwrap())
            .collect(),
        new_next_keys
            .into_iter()
            .map(|pk| key_prefix_from_b64(&pk.key, pk.algorithm.into()).unwrap())
            .collect(),
        witness_to_add,
        witness_to_remove,
        witness_threshold,
    )?;
    Ok(rot)
}

pub fn finalize_event(event: String, signature: Signature) -> Result<()> {
    let signed_event = (*KEL.lock().unwrap()).as_ref().unwrap().finalize_event(
        event,
        signature_prefix_from_b64(&signature.key, signature.algorithm.into())?,
    )?;
    Ok(signed_event)
}

pub fn process_stream(stream: String) -> Result<()> {
    (*KEL.lock().unwrap()).as_ref().unwrap().process_stream(stream)?;
    
    Ok(())
}

pub fn get_kel(id: String) -> Result<String> {
    let signed_event = (*KEL.lock().unwrap()).as_ref().unwrap().get_kel(id)?;
    Ok(signed_event)
}
