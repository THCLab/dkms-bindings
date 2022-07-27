use std::{path::PathBuf, sync::Mutex, slice};

use flutter_rust_bridge::{support::lazy_static, frb};

use anyhow::{anyhow, Result};
use keri::{
    controller::{error::ControllerError, event_generator, utils::OptionalConfig},
    derivation::{basic::Basic, self_signing::SelfSigning, self_addressing::SelfAddressing},
    event_parsing::Attachment,
    oobi::{EndRole, LocationScheme, Role},
    prefix::{BasicPrefix, IdentifierPrefix, Prefix, SelfAddressingPrefix},
};

use crate::utils::{
    join_keys_and_signatures, key_prefix_from_b64, parse_attachment, signature_prefix_from_hex,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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

pub type DigestType = SelfAddressing;
#[frb(mirror(DigestType))]
pub enum _DigestType {
    Blake3_256,
    SHA3_256,
    SHA2_256,
    Blake3_512,
    SHA3_512,
    Blake2B512,
    SHA2_512,
}

#[derive(Clone)]
pub enum SignatureType {
    Ed25519Sha512,
    ECDSAsecp256k1Sha256,
    Ed448,
}

impl From<SignatureType> for SelfSigning {
    fn from(sig: SignatureType) -> Self {
         match sig {
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
    pub fn new(algorithm: KeyType, key: String) -> Self {
        Self {
            algorithm,
            key: key.to_string(),
        }
    }
}

#[derive(Clone)]
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

pub struct Config {
    pub initial_oobis: String,
}

pub fn with_initial_oobis(config: Config, oobis_json: String) -> Config {
    Config {
        initial_oobis: oobis_json,
        ..config
    }
}

impl Config {
    pub fn build(&self) -> Result<OptionalConfig> {
        let oobis: Vec<LocationScheme> = serde_json::from_str(&self.initial_oobis)
            .map_err(|_e| anyhow!("Improper location scheme structure"))?;
        Ok(OptionalConfig {
            initial_oobis: Some(oobis),
            db_path: None,
        })
    }
}

lazy_static! {
    static ref KEL: Mutex<Option<keri::controller::Controller>> = Mutex::new(None);
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Can't lock the database")]
    DatabaseLockingError,

    #[error("Controller wasn't initialized")]
    ControllerInitializationError,

    // arguments parsing errors
    #[error("Can't parse controller prefix: {0}")]
    PrefixParseError(String),

    #[error("Can't parse self addressing identifier: {0}")]
    SaiParseError(String),

    #[error("Can't parse witness identifier: {0}")]
    WitnessParseError(String),

    #[error("Can't parse oobi json: {0}")]
    OobiParseError(String),

    #[error("base64 decode error")]
    Base64Error(#[from] base64::DecodeError),

    #[error("hex decode error")]
    HexError(#[from] hex::FromHexError),

    #[error("Can't resolve oobi: {0}")]
    OobiResolvingError(String),

    #[error("Missing issuer oobi")]
    MissingIssuerOobi,

    #[error("Utils error: {0}")]
    UtilsError(String),

    #[error(transparent)]
    KelError(#[from] ControllerError),
}

#[derive(Clone)]
pub struct Controller {
    pub identifier: String,
}

impl Controller {
    pub fn get_id(&self) -> String {
        self.identifier.clone()
    }
}

pub fn init_kel(input_app_dir: String, optional_configs: Option<Config>) -> Result<bool> {
    let config = if let Some(config) = optional_configs {
        config
            .build()
            .map(|c| c.with_db_path(PathBuf::from(input_app_dir)))?
    } else {
        OptionalConfig {
            db_path: Some(PathBuf::from(input_app_dir)),
            initial_oobis: None,
        }
    };
    let is_initialized = {
        (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
            .as_ref()
            .is_some()
    };

    if !is_initialized {
        let controller = keri::controller::Controller::new(Some(config))?;
        *KEL.lock().map_err(|_e| Error::DatabaseLockingError)? = Some(controller);
    }

    Ok(true)
}

pub fn incept(
    public_keys: Vec<PublicKey>,
    next_pub_keys: Vec<PublicKey>,
    // witnesses location scheme json
    witnesses: Vec<String>,
    witness_threshold: u64,
) -> Result<String> {
    let witnesses = witnesses
        .iter()
        .map(|wit| serde_json::from_str::<LocationScheme>(wit)
        .map_err(|_e| Error::OobiParseError(wit.into())))
        .collect::<Result<Vec<_>, _>>()
        // improper json structure or improper prefix
        .map_err(|e| anyhow!(e.to_string()))?;
    let icp = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .incept(
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
    let controller_id = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .finalize_inception(
            event.as_bytes(),
            vec![signature_prefix_from_hex(
                &signature.key,
                signature.algorithm.into(),
            )?],
        )?;
    Ok(Controller {
        identifier: controller_id.to_str(),
    })
}

pub fn rotate(
    controller: Controller,
    current_keys: Vec<PublicKey>,
    new_next_keys: Vec<PublicKey>,
    // location schema json of witnesses
    witness_to_add: Vec<String>,
    // identifier of witnesses. Witness was previously added, so it's adresses
    // should be known.
    witness_to_remove: Vec<String>,
    witness_threshold: u64,
) -> Result<String> {
    let id = controller
        .identifier
        .parse()
        .map_err(|_e| Error::PrefixParseError(controller.identifier))?;
    // Parse location schema from string
    let witnesses_to_add = witness_to_add
        .iter()
        .map(|wit| {
            serde_json::from_str::<LocationScheme>(wit)
                .map_err(|_| Error::OobiParseError(wit.into()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let witnesses_to_remove = witness_to_remove
        .iter()
        .map(|wit| {
            wit.parse::<BasicPrefix>()
                .map_err(|_| Error::WitnessParseError(wit.into()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .rotate(
            id,
            current_keys
                .into_iter()
                .map(|pk| key_prefix_from_b64(&pk.key, pk.algorithm.into()))
                .collect::<Result<Vec<_>, _>>()?,
            new_next_keys
                .into_iter()
                .map(|pk| key_prefix_from_b64(&pk.key, pk.algorithm.into()))
                .collect::<Result<Vec<_>, _>>()?,
            witnesses_to_add,
            witnesses_to_remove,
            witness_threshold,
        )?)
}

pub fn anchor(controller: Controller, data: String, algo: DigestType) -> Result<String> {
    let id = controller
        .get_id()
        .parse::<IdentifierPrefix>()
        .map_err(|_e| Error::PrefixParseError(controller.get_id()))?;
    let digest = algo.derive(data.as_bytes());
    Ok((*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .anchor(id, slice::from_ref(&digest))?)
}


pub fn anchor_digest(controller: Controller, sais: Vec<String>) -> Result<String> {
    let sais = sais
        .iter()
        .map(|sai| {
            sai.parse::<SelfAddressingPrefix>()
                .map_err(|_e| Error::SaiParseError(sai.into()))
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let id = controller
        .get_id()
        .parse::<IdentifierPrefix>()
        .map_err(|_e| Error::PrefixParseError(controller.get_id()))?;
    Ok((*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .anchor(id, &sais)?)
}

pub fn add_watcher(controller: Controller, watcher_oobi: String) -> Result<String> {
    let lc: LocationScheme =
        serde_json::from_str(&watcher_oobi).map_err(|_| Error::OobiParseError(watcher_oobi))?;
    if let IdentifierPrefix::Basic(_bp) = &lc.eid {
        (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
            .as_ref()
            .ok_or(Error::ControllerInitializationError)?
            .resolve_loc_schema(&lc)?;

        let id = &controller.identifier.parse().map_err(|_e| Error::PrefixParseError(controller.get_id()))?;
        let add_watcher = event_generator::generate_end_role(id, &lc.eid, Role::Watcher, true)?;
        Ok(String::from_utf8(add_watcher.serialize()?)?)
    } else {
        Err(ControllerError::WrongWitnessPrefixError.into())
    }
}

pub fn finalize_event(identifier: Controller, event: String, signature: Signature) -> Result<bool> {
    (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .finalize_event(
            &identifier.identifier.parse()?,
            event.as_bytes(),
            vec![signature_prefix_from_hex(
                &signature.key,
                signature.algorithm.into(),
            )?],
        )?;
    Ok(true)
}

pub fn resolve_oobi(oobi_json: String) -> Result<bool> {
    let lc: LocationScheme =
        serde_json::from_str(&oobi_json).map_err(|_e| Error::OobiParseError(oobi_json))?;
    (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .resolve_loc_schema(&lc)
        .map_err(|e| Error::OobiResolvingError(e.to_string()))?;
    Ok(true)
}

fn query_by_id(controller: Controller, query_id: String) -> Result<bool> {
    (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .query(
            &controller
                .identifier
                .parse()
                .map_err(|_e| Error::PrefixParseError(controller.identifier))?,
            &query_id,
        )?;
    Ok(true)
}

pub fn query(controller: Controller, oobis_json: String) -> Result<bool> {
    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    enum Oobis {
        LocScheme(LocationScheme),
        EndRole(EndRole),
    }
    let mut issuer_id: Option<String> = None;
    let oobis = serde_json::from_str::<Vec<Oobis>>(&oobis_json)
        .map_err(|_| Error::OobiParseError(oobis_json.clone()))?;
    for oobi in oobis {
        match &oobi {
            Oobis::LocScheme(lc) => {
                (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
                    .as_ref()
                    .ok_or(Error::ControllerInitializationError)?
                    .resolve_loc_schema(&lc)?;
            }
            Oobis::EndRole(er) => issuer_id = Some(er.cid.to_str()),
        };

        (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
            .as_ref()
            .ok_or(Error::ControllerInitializationError)?
            .send_oobi_to_watcher(
                &controller
                    .identifier
                    .parse()
                    .map_err(|_| Error::PrefixParseError((&controller.identifier).into()))?,
                &serde_json::to_string(&oobi)?,
            )?;
    }
    query_by_id(controller, issuer_id.ok_or(Error::MissingIssuerOobi)?)
}

pub fn process_stream(stream: String) -> Result<bool> {
    (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .process_stream(stream.as_bytes())?;
    Ok(true)
}

pub fn get_kel(cont: Controller) -> Result<String> {
    let signed_event = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .storage
        .get_kel(
            &cont
                .identifier
                .parse()
                .map_err(|_e| Error::PrefixParseError(cont.identifier))?,
        )?
        .ok_or(Error::KelError(ControllerError::UnknownIdentifierError))?;
    Ok(String::from_utf8(signed_event).unwrap())
}

pub fn get_kel_by_str(cont_id: String) -> Result<String> {
    let signed_event = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .storage
        .get_kel(
            &cont_id
                .parse()
                .map_err(|_e| Error::PrefixParseError(cont_id))?,
        )?
        .ok_or(Error::KelError(ControllerError::UnknownIdentifierError))?;
    Ok(String::from_utf8(signed_event).unwrap())
}

pub struct PublicKeySignaturePair {
    pub key: PublicKey,
    pub signature: Signature,
}

/// Returns pairs: public key encoded in base64 and signature encoded in hex
pub fn get_current_public_key(attachment: String) -> Result<Vec<PublicKeySignaturePair>> {
    let att = parse_attachment(attachment.as_bytes())?;

    let keys = if let Attachment::SealSignaturesGroups(group) = att {
        let r = group
            .iter()
            .map(|(seal, signatures)| -> Result<Vec<_>, Error> {
                let current_keys = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
                    .as_ref()
                    .ok_or(Error::ControllerInitializationError)?
                    .storage
                    .get_keys_at_event(&seal.prefix, seal.sn, &seal.event_digest)
                    .map_err(|e| Error::UtilsError(e.to_string()))?
                    .ok_or(Error::UtilsError("Can't find event of given seal".into()))?
                    .public_keys;
                join_keys_and_signatures(current_keys, signatures)
            })
            .collect::<Result<Vec<_>, Error>>();
        Ok(r.into_iter()
            .flatten()
            .flatten()
            .map(|(bp, sp)| PublicKeySignaturePair {
                key: PublicKey::new(bp.derivation.into(), base64::encode(bp.public_key.key())),
                signature: Signature::new(sp.derivation.into(), hex::encode(sp.signature.clone())),
            })
            .collect::<Vec<_>>())
    } else {
        Err(Error::UtilsError("Wrong attachment".into()))
    };
    Ok(keys?)
}
