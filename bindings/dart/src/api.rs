use std::{
    path::PathBuf,
    slice,
    sync::{Arc, Mutex},
};

use controller::{error::ControllerError, identifier_controller::IdentifierController};
use flutter_rust_bridge::{frb, support::lazy_static};

use anyhow::{anyhow, Result};
pub use keri::keys::PublicKey as KeriPublicKey;
pub use keri::prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix};
use keri::{
    actor::{event_generator, prelude::Message},
    event_parsing::{
        codes::{basic::Basic, self_signing::SelfSigning, DerivationCode},
        message::query_message,
        Attachment, EventType,
    },
    oobi::{LocationScheme, Role},
    prefix::Prefix,
    sai::{derivation::SelfAddressing, SelfAddressingPrefix},
};
use tokio::runtime::Runtime;

use crate::utils::{
    join_keys_and_signatures, parse_attachment, parse_location_schemes, parse_witness_prefix,
};
pub use controller::utils::OptionalConfig;
use thiserror::Error;

pub type KeyType = Basic;
#[frb(mirror(KeyType))]
pub enum _KeyType {
    ECDSAsecp256k1NT,
    ECDSAsecp256k1,
    Ed25519NT,
    Ed25519,
    Ed448NT,
    Ed448,
    X25519,
    X448,
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
    Blake2B256(Vec<u8>),
    Blake2S256(Vec<u8>),
}

pub type SignatureType = SelfSigning;
#[frb(mirror(SignatureType))]
pub enum _SignatureType {
    Ed25519Sha512,
    ECDSAsecp256k1Sha256,
    Ed448,
}

pub struct PublicKey {
    pub derivation: KeyType,
    pub public_key: Vec<u8>,
}

pub fn new_public_key(kt: KeyType, key_b64: String) -> Result<PublicKey> {
    let expected_len = kt.code_len() + kt.derivative_b64_len();
    if key_b64.len() == expected_len {
        let decoded_key = base64::decode(key_b64).map_err(|e| Error::Base64Error(e))?;
        let pk = PublicKey {
            derivation: kt,
            public_key: decoded_key,
        };
        Ok(pk.into())
    } else {
        Err(Error::KeyLengthError(key_b64.len(), expected_len).into())
    }
}

pub struct Digest {
    pub derivation: DigestType,
    pub digest: Vec<u8>,
}

#[derive(Clone)]
pub struct Signature {
    pub derivation: SignatureType,
    pub signature: Vec<u8>,
}

pub fn signature_from_hex(st: SignatureType, signature: String) -> Signature {
    Signature {
        derivation: st,
        signature: hex::decode(signature)
            .map_err(|e| Error::HexError(e))
            .unwrap(),
    }
}

pub fn signature_from_b64(st: SignatureType, signature: String) -> Signature {
     Signature {
        derivation: st,
        signature: hex::decode(signature)
            .map_err(|e| Error::HexError(e))
            .unwrap(),
    }
}

#[derive(Clone)]
pub struct Identifier {
    pub id: String,
}

impl Identifier {
    pub fn new_from_str(id_str: String) -> Result<Identifier> {
        // check if it's proper string id
        id_str
            .parse::<IdentifierPrefix>()
            .map_err(|e| Error::IdentifierParseError(e.to_string()))?;
        Ok(Identifier { id: id_str })
    }

    pub fn to_str(&self) -> String {
        let ip: IdentifierPrefix = self.into();
        ip.to_str()
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
    pub(crate) fn build(&self) -> Result<OptionalConfig> {
        let oobis: Vec<LocationScheme> = serde_json::from_str(&self.initial_oobis)
            .map_err(|_e| anyhow!("Improper location scheme structure"))?;
        Ok(OptionalConfig {
            initial_oobis: Some(oobis),
            db_path: None,
        })
    }
}

lazy_static! {
    static ref KEL: Mutex<Option<Arc<controller::Controller>>> = Mutex::new(None);
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Can't lock the database")]
    DatabaseLockingError,

    #[error("Controller wasn't initialized")]
    ControllerInitializationError,

    // arguments parsing errors
    #[error("Can't parse identifier prefix: {0}")]
    IdentifierParseError(String),

    #[error("Can't parse event: {0}")]
    EventParsingError(String),

    #[error("Can't parse self addressing identifier: {0}")]
    SaiParseError(String),

    #[error("Can't parse witness identifier: {0}")]
    WitnessParseError(String),

    #[error("Can't parse oobi json: {0}")]
    OobiParseError(String),

    #[error("base64 decode error")]
    Base64Error(#[from] base64::DecodeError),

    #[error("wrong key length, got: {0}, should be {1}")]
    KeyLengthError(usize, usize),

    #[error("hex decode error")]
    HexError(#[from] hex::FromHexError),

    #[error("Can't resolve oobi: {0}")]
    OobiResolvingError(String),

    #[error("Missing issuer oobi")]
    MissingIssuerOobi,

    #[error("Utils error: {0}")]
    UtilsError(String),

    #[error("Improper event type")]
    EventTypeError,

    #[error(transparent)]
    KelError(#[from] ControllerError),
}

/// Helper function for tests. Enable to switch to use other database. Used to
/// simulate using multiple devices.
pub fn change_controller(db_path: String) -> Result<bool> {
    let config = OptionalConfig {
        db_path: Some(PathBuf::from(db_path)),
        initial_oobis: None,
    };
    let controller = controller::Controller::new(Some(config))?;

    *KEL.lock().map_err(|_e| Error::DatabaseLockingError)? = Some(Arc::new(controller));
    Ok(true)
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
        let rt = Runtime::new().unwrap();
        let controller = rt.block_on(async { controller::Controller::new(Some(config)) })?;
        *KEL.lock().map_err(|_e| Error::DatabaseLockingError)? = Some(Arc::new(controller));
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
        .map(|wit| parse_location_schemes(wit))
        .collect::<Result<Vec<_>, _>>()
        // improper json structure or improper prefix
        .map_err(|e| anyhow!(e.to_string()))?;
    let public_keys = public_keys.iter().map(|pk| pk.into()).collect();
    let next_pub_keys = next_pub_keys.iter().map(|pk| pk.into()).collect();
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .clone();
    let rt = Runtime::new().unwrap();
    let icp = controller.incept(public_keys, next_pub_keys, witnesses, witness_threshold);
    let icp = rt.block_on(async { icp.await })?;
    Ok(icp)
}

pub fn finalize_inception(event: String, signature: Signature) -> Result<Identifier> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .clone();
    let ssp = signature.into();
    let controller_id = controller.finalize_inception(event.as_bytes(), &ssp);
    let rt = Runtime::new().unwrap();
    let controller_id = rt.block_on(async { controller_id.await })?;
    println!("\ninception event: {}", event);
    println!(
        "\nController incepted id: {}",
        controller_id.clone().to_str()
    );
    Ok(Identifier::from(controller_id))
}

pub fn rotate(
    identifier: Identifier,
    current_keys: Vec<PublicKey>,
    new_next_keys: Vec<PublicKey>,
    // location schema json of witnesses
    witness_to_add: Vec<String>,
    // identifier of witnesses. Witness was previously added, so it's adresses
    // should be known.
    witness_to_remove: Vec<String>,
    witness_threshold: u64,
) -> Result<String> {
    // Parse location schema from string
    let witnesses_to_add = witness_to_add
        .iter()
        .map(|wit| parse_location_schemes(wit))
        .collect::<Result<Vec<_>, _>>()?;
    let witnesses_to_remove = witness_to_remove
        .iter()
        .map(|wit| {
            wit.parse::<BasicPrefix>()
                .map_err(|_| Error::WitnessParseError(wit.into()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let current_keys = current_keys.iter().map(|pk| pk.into()).collect();
    let new_next_keys = new_next_keys.iter().map(|pk| pk.into()).collect();
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .clone();
    let rotate_future = controller.rotate(
        identifier.into(),
        current_keys,
        new_next_keys,
        witnesses_to_add,
        witnesses_to_remove,
        witness_threshold,
    );
    let rt = Runtime::new().unwrap();
    Ok(rt.block_on(async { rotate_future.await })?)
}

pub fn anchor(identifier: Identifier, data: String, algo: DigestType) -> Result<String> {
    let dig_type: SelfAddressing = algo.into();
    let digest = dig_type.derive(data.as_bytes());
    Ok((*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .anchor(identifier.into(), slice::from_ref(&digest))?)
}

pub fn anchor_digest(identifier: Identifier, sais: Vec<String>) -> Result<String> {
    let sais = sais
        .iter()
        .map(|sai| {
            sai.parse::<SelfAddressingPrefix>()
                .map_err(|_e| Error::SaiParseError(sai.into()))
        })
        .collect::<Result<Vec<_>, Error>>()?;

    Ok((*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .anchor(identifier.into(), &sais)?)
}

pub fn add_watcher(identifier: Identifier, watcher_oobi: String) -> Result<String> {
    let lc = parse_location_schemes(&watcher_oobi)?;
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .clone();
    let resolve_future = controller.resolve_loc_schema(&lc);
    if let IdentifierPrefix::Basic(_bp) = &lc.eid {
        let rt = Runtime::new().unwrap();
        rt.block_on(async { resolve_future.await })?;

        let add_watcher =
            event_generator::generate_end_role(&identifier.into(), &lc.eid, Role::Watcher, true)?;
        Ok(String::from_utf8(add_watcher.serialize()?)?)
    } else {
        Err(ControllerError::WrongWitnessPrefixError.into())
    }
}

pub fn finalize_event(identifier: Identifier, event: String, signature: Signature) -> Result<bool> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .clone();
    let identifier_controller = IdentifierController::new(identifier.into(), controller);
    let finalize_event_future = identifier_controller.finalize_event(event.as_bytes(), signature.into());
    let rt = Runtime::new().unwrap();
    rt.block_on(async { finalize_event_future.await })?;
    Ok(true)
}

/// Struct for collecting data that need to be signed: generated event and
/// exchange messages that are needed to forward multisig request to other group
/// participants.
pub struct GroupInception {
    pub icp_event: String,
    pub exchanges: Vec<String>,
}

pub fn incept_group(
    identifier: Identifier,
    participants: Vec<Identifier>,
    signature_threshold: u64,
    initial_witnesses: Vec<String>,
    witness_threshold: u64,
) -> Result<GroupInception> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .clone();
    let initial_witnesses = initial_witnesses
        .iter()
        .map(|id| id.parse())
        .collect::<Result<_, _>>()?;
    let identifier_controller = IdentifierController::new(identifier.into(), controller);
    let (icp_to_sign, exns_to_sign) = identifier_controller.incept_group(
        participants.into_iter().map(|id| id.into()).collect(),
        signature_threshold,
        Some(initial_witnesses),
        Some(witness_threshold),
        None,
    )?;
    Ok(GroupInception {
        icp_event: icp_to_sign,
        exchanges: exns_to_sign,
    })
}

pub struct DataAndSignature {
    pub data: String,
    pub signature: Box<Signature>,
}

impl DataAndSignature {
    pub fn new(data: String, signature: Signature) -> DataAndSignature {
        Self {
            data,
            signature: Box::new(signature),
        }
    }
}

pub fn finalize_group_incept(
    identifier: Identifier,
    group_event: String,
    signature: Signature,
    to_forward: Vec<DataAndSignature>,
) -> Result<Identifier> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .clone();

    let mut identifier_controller = IdentifierController::new(identifier.into(), controller);

    let group_identifier_future = identifier_controller.finalize_group_incept(
        group_event.as_bytes(),
        signature.into(),
        to_forward
            .iter()
            .map(
                |DataAndSignature {
                     data: exn,
                     signature,
                 }| {
                    let sig_type: SelfSigning = signature.derivation.clone();
                    let sig = SelfSigningPrefix::new(sig_type, signature.signature.clone());
                    (exn.as_bytes().to_vec(), sig)
                },
            )
            .collect::<Vec<(Vec<u8>, SelfSigningPrefix)>>(),
    );

    let rt = Runtime::new().unwrap();
    let group_identifier = rt.block_on(async { group_identifier_future.await })?;
    Ok(Identifier::from(group_identifier))
}

pub fn query_mailbox(
    who_ask: Identifier,
    about_who: Identifier,
    witness: Vec<String>,
) -> Result<Vec<String>> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .clone();

    let identifier_controller = IdentifierController::new(who_ask.into(), controller);
    let witnesses: Result<Vec<_>> = witness
        .iter()
        .map(|wit| -> Result<BasicPrefix> { Ok(parse_witness_prefix(wit)?) })
        .collect();
    identifier_controller
        .query_mailbox(&about_who.into(), &witnesses?)?
        .iter()
        .map(|qry| -> Result<String> { Ok(String::from_utf8(qry.serialize()?)?) })
        .collect::<Result<Vec<_>>>()
}

#[derive(Debug)]
pub enum Action {
    MultisigRequest,
    DelegationRequest,
}

#[derive(Debug)]
pub struct ActionRequired {
    pub action: Action,
    pub data: String,
    pub additiona_data: String,
}

pub fn finalize_mailbox_query(
    identifier: Identifier,
    query_event: String,
    signature: Signature,
) -> Result<Vec<ActionRequired>> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .clone();
    let query = query_message(query_event.as_bytes())
        .map_err(|e| Error::EventParsingError(e.to_string()))?
        .1;
    let mut identifier_controller = IdentifierController::new(identifier.into(), controller);

    match query {
        EventType::Qry(ref qry) => {
            let finalize_qry_future =
                identifier_controller.finalize_mailbox_query(vec![(qry.clone(), signature.into())]);

            let rt = Runtime::new().unwrap();
            let out = rt
                .block_on(async { finalize_qry_future.await })?
                .iter()
                .map(|ar| -> Result<_> {
                    match ar {
                        controller::mailbox_updating::ActionRequired::MultisigRequest(
                            data,
                            exchanges,
                        ) => Ok(ActionRequired {
                            action: Action::MultisigRequest,
                            data: String::from_utf8(data.serialize()?)?,
                            additiona_data: String::from_utf8(exchanges.serialize()?)?,
                        }),
                        _ => {
                            todo!()
                        }
                    }
                })
                .collect();

            out
        }
        _ => Err(Error::EventTypeError.into()),
    }
}

pub fn resolve_oobi(oobi_json: String) -> Result<bool> {
    let lc = parse_location_schemes(&oobi_json)?;
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .clone();
    let resolve_future = controller.resolve_loc_schema(&lc);
    let rt = Runtime::new().unwrap();
    rt.block_on(async { resolve_future.await })
        .map_err(|e| Error::OobiResolvingError(e.to_string()))?;
    Ok(true)
}

pub fn process_stream(stream: String) -> Result<bool> {
    (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .process_stream(stream.as_bytes())?;
    Ok(true)
}

pub fn get_kel(identifier: Identifier) -> Result<String> {
    let signed_event = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .storage
        .get_kel_messages_with_receipts(&identifier.into())?
        .ok_or(Error::KelError(ControllerError::UnknownIdentifierError))?
        .into_iter()
        .map(|event| Message::Notice(event).to_cesr().unwrap())
        .flatten()
        .collect();
    Ok(String::from_utf8(signed_event)?)
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
                key: bp.into(),
                signature: sp.into(),
            })
            .collect::<Vec<_>>())
    } else {
        Err(Error::UtilsError("Wrong attachment".into()))
    };
    Ok(keys?)
}
