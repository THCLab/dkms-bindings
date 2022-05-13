use std::sync::Mutex;

use flutter_rust_bridge::support::lazy_static;

use anyhow::Result;
use keriox_wrapper::kel::{
    key_prefix_from_b64, signature_prefix_from_hex, Kel, Basic, SelfSigning, Prefix,
};

pub enum KeyType {
    ECDSAsecp256k1,
    Ed25519,
    Ed448,
    X25519,
    X448,
}

impl Into<Basic> for KeyType {
    fn into(self) -> Basic {
        match self {
            KeyType::ECDSAsecp256k1 => Basic::ECDSAsecp256k1NT,
            KeyType::Ed25519 => Basic::Ed25519NT,
            KeyType::Ed448 => Basic::Ed448NT,
            KeyType::X25519 => Basic::X25519,
            KeyType::X448 => Basic::X448,
        }
    }
}

impl From<Basic> for KeyType {
    fn from(kd: Basic) -> Self {
        match kd {
            Basic::ECDSAsecp256k1NT => KeyType::ECDSAsecp256k1,
            Basic::ECDSAsecp256k1 => KeyType::ECDSAsecp256k1,
            Basic::Ed25519NT => KeyType::Ed25519,
            Basic::Ed25519 => KeyType::Ed25519,
            Basic::Ed448NT => KeyType::Ed448,
            Basic::Ed448 => KeyType::Ed448,
            Basic::X25519 => KeyType::X25519,
            Basic::X448 => KeyType::X448,
        }
    }
}

pub enum SignatureType {
    Ed25519Sha512,
    ECDSAsecp256k1Sha256,
    Ed448,
}

impl Into<SelfSigning> for SignatureType {
    fn into(self) -> SelfSigning {
        match self {
            SignatureType::Ed25519Sha512 => SelfSigning::Ed25519Sha512,
            SignatureType::ECDSAsecp256k1Sha256 => SelfSigning::ECDSAsecp256k1Sha256,
            SignatureType::Ed448 => SelfSigning::Ed448,
        }
    }
}

impl From<SelfSigning> for SignatureType {
    fn from(sd: SelfSigning) -> Self {
        match sd {
            SelfSigning::Ed25519Sha512 => SignatureType::Ed25519Sha512,
            SelfSigning::ECDSAsecp256k1Sha256 => SignatureType::ECDSAsecp256k1Sha256,
            SelfSigning::Ed448 => SignatureType::Ed448,
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
    *KEL.lock().unwrap() = Some(Kel::init(&input_app_dir));
    Ok(())
}

pub fn incept(
    public_keys: Vec<PublicKey>,
    next_pub_keys: Vec<PublicKey>,
    witnesses: Vec<String>,
    witness_threshold: u64,
) -> Result<String> {
    let icp = Kel::incept(
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
            vec![signature_prefix_from_hex(&signature.key, signature.algorithm.into())?],
        )?;
    Ok(Controller {
        identifier: controller_id.to_str(),
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
    let id = controller.identifier.parse().unwrap();
    let rot = (*KEL.lock().unwrap()).as_ref().unwrap().rotate(
        id,
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
        event.as_bytes(),
        vec![signature_prefix_from_hex(&signature.key, signature.algorithm.into())?],
    )?;
    Ok(signed_event)
}

pub fn process_stream(stream: String) -> Result<()> {
    (*KEL.lock().unwrap())
        .as_ref()
        .unwrap()
        .parse_and_process(stream.as_bytes())?;

    Ok(())
}

pub fn get_kel(id: String) -> Result<String> {
    let signed_event = (*KEL.lock().unwrap()).as_ref().unwrap().get_kel(id)?;
    Ok(signed_event)
}

pub struct PublicKeySignaturePair {
    pub key: PublicKey,
    pub signature: Signature,
}

/// Returns pairs: public key encoded in base64 and signature encoded in hex
pub fn parse_attachment(attachment: String) -> Result<Vec<PublicKeySignaturePair>> {
    let attachment = (*KEL.lock().unwrap())
        .as_ref()
        .unwrap()
        .parse_attachment(attachment)?;
    Ok(attachment
        .iter()
        .map(|(bp, sp)| PublicKeySignaturePair {
            key: PublicKey::new(bp.derivation.into(), &base64::encode(bp.public_key.key())),
            signature: Signature::new(sp.derivation.into(), hex::encode(sp.signature.clone())),
        })
        .collect::<Vec<_>>())
}
