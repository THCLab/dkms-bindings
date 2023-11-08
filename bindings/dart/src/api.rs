use cesrox::derivation_code::DerivationCode;
pub use cesrox::primitives::codes::{
    basic::Basic as KeyType, self_signing::SelfSigning as SignatureType,
};
use controller::{
    error::ControllerError,
    identifier_controller::{IdentifierController, TelQueryEvent},
    Oobi,
};
use flutter_rust_bridge::{frb, support::lazy_static};
use keri::{event_message::cesr_adapter::parse_event_type, prefix::CesrPrimitive};
pub use said::derivation::HashFunctionCode as DigestType;
use std::{path::PathBuf, slice, sync::Mutex};

use crate::{
    state::Current,
    utils::{parse_location_schemes, parse_oobi, parse_witness_prefix},
};
use anyhow::{anyhow, Result};
use controller::config::ControllerConfig;
use keri::prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix};
use keri::{
    actor::{event_generator, prelude::Message},
    event_message::cesr_adapter::EventType,
    oobi::{LocationScheme, Role},
};
use said::{derivation::HashFunction, SelfAddressingIdentifier};
use thiserror::Error;
use tokio::runtime::Runtime;

#[frb(mirror(KeyType))]
pub enum _KeyType {
    ECDSAsecp256k1Nontrans,
    ECDSAsecp256k1,
    Ed25519Nontrans,
    Ed25519,
    Ed448Nontrans,
    Ed448,
    X25519,
    X448,
}

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

pub fn new_public_key(kt: KeyType, key_b64_url_safe: String) -> Result<PublicKey> {
    let expected_len = kt.code_size() + kt.value_size();
    if key_b64_url_safe.len() == expected_len {
        let decoded_key = base64::decode_config(key_b64_url_safe, base64::URL_SAFE)
            .map_err(Error::Base64Error)?;
        let pk = PublicKey {
            derivation: kt,
            public_key: decoded_key,
        };
        Ok(pk)
    } else {
        Err(Error::KeyLengthError(key_b64_url_safe.len(), expected_len).into())
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
        signature: hex::decode(signature).map_err(Error::HexError).unwrap(),
    }
}

pub fn signature_from_b64(st: SignatureType, signature: String) -> Signature {
    Signature {
        derivation: st,
        signature: hex::decode(signature).map_err(Error::HexError).unwrap(),
    }
}

#[derive(Clone, PartialEq, Hash, Eq)]
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

pub fn with_initial_oobis(_config: Config, oobis_json: String) -> Config {
    Config {
        initial_oobis: oobis_json,
    }
}

impl Config {
    pub(crate) fn build(&self, db_path: PathBuf) -> Result<ControllerConfig> {
        let oobis: Vec<LocationScheme> = serde_json::from_str(&self.initial_oobis)
            .map_err(|_e| anyhow!("Improper location scheme structure"))?;
        Ok(ControllerConfig {
            initial_oobis: oobis,
            db_path,
            ..Default::default()
        })
    }
}

lazy_static! {
    static ref KEL: Mutex<Option<Current>> = Mutex::new(None);
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

    #[error("Can't parse attachment json")]
    AttachmentParseError,

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
    let config = ControllerConfig {
        db_path: PathBuf::from(db_path),
        ..Default::default()
    };
    *KEL.lock().map_err(|_e| Error::DatabaseLockingError)? = Some(Current::new(config)?);
    Ok(true)
}

pub fn init_kel(input_app_dir: String, optional_configs: Option<Config>) -> Result<bool> {
    let config = if let Some(config) = optional_configs {
        config.build(PathBuf::from(input_app_dir))?
    } else {
        // Default configs
        ControllerConfig {
            db_path: PathBuf::from(input_app_dir),
            ..Default::default()
        }
    };
    let is_initialized = {
        (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
            .as_ref()
            .is_some()
    };

    if !is_initialized {
        let current = Current::new(config)?;
        *KEL.lock().map_err(|_e| Error::DatabaseLockingError)? = Some(current);
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
        .controller();
    let rt = Runtime::new().unwrap();
    let icp = controller.incept(public_keys, next_pub_keys, witnesses, witness_threshold);
    let icp = rt.block_on(icp)?;
    Ok(icp)
}

pub fn finalize_inception(event: String, signature: Signature) -> Result<Identifier> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .controller();
    let ssp = signature.into();
    let controller_id = controller.finalize_inception(event.as_bytes(), &ssp);
    let rt = Runtime::new().unwrap();
    let controller_id = rt.block_on(controller_id)?;
    println!("\ninception event: {}", event);
    println!("\nController incepted id: {}", controller_id.to_str());
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
        .controller();
    let rotate_future = controller.rotate(
        identifier.into(),
        current_keys,
        new_next_keys,
        witnesses_to_add,
        witnesses_to_remove,
        witness_threshold,
    );
    let rt = Runtime::new().unwrap();
    Ok(rt.block_on(rotate_future)?)
}

pub fn anchor(identifier: Identifier, data: String, algo: DigestType) -> Result<String> {
    let digest = HashFunction::from(algo).derive(data.as_bytes());
    Ok((*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .controller()
        .anchor(identifier.into(), slice::from_ref(&digest))?)
}

pub fn anchor_digest(identifier: Identifier, sais: Vec<String>) -> Result<String> {
    let sais = sais
        .iter()
        .map(|sai| {
            sai.parse::<SelfAddressingIdentifier>()
                .map_err(|_e| Error::SaiParseError(sai.into()))
        })
        .collect::<Result<Vec<_>, Error>>()?;

    Ok((*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .controller()
        .anchor(identifier.into(), &sais)?)
}

pub fn add_watcher(identifier: Identifier, watcher_oobi: String) -> Result<String> {
    let lc = parse_location_schemes(&watcher_oobi)?;
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .controller();
    let resolve_future = controller.resolve_loc_schema(&lc);
    if let IdentifierPrefix::Basic(_bp) = &lc.eid {
        let rt = Runtime::new().unwrap();
        rt.block_on(resolve_future)?;

        let add_watcher =
            event_generator::generate_end_role(&identifier.into(), &lc.eid, Role::Watcher, true)?;
        Ok(String::from_utf8(add_watcher.encode()?)?)
    } else {
        Err(ControllerError::WrongWitnessPrefixError.into())
    }
}

pub fn send_oobi_to_watcher(identifier: Identifier, oobis_json: String) -> Result<bool> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .controller();
    let identifier_controller: IdentifierPrefix = identifier.into();
    let oobi: Oobi = serde_json::from_str(&oobis_json).unwrap();
    let send_oobi_future = controller.send_oobi_to_watcher(&identifier_controller, &oobi);
    let rt = Runtime::new().unwrap();
    rt.block_on(send_oobi_future)?;
    Ok(true)
}

pub fn finalize_event(identifier: Identifier, event: String, signature: Signature) -> Result<bool> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .controller();
    let identifier_controller = IdentifierController::new(identifier.into(), controller, None);
    let finalize_event_future =
        identifier_controller.finalize_event(event.as_bytes(), signature.into());
    let rt = Runtime::new().unwrap();
    rt.block_on(finalize_event_future)?;
    Ok(true)
}

pub fn notify_witnesses(identifier: Identifier) -> Result<bool> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .controller();
    let identifier_controller = IdentifierController::new(identifier.into(), controller, None);
    let notify_future = identifier_controller.notify_witnesses();
    let rt = Runtime::new().unwrap();
    rt.block_on(notify_future)?;
    Ok(true)
}

pub fn broadcast_receipts(identifier: Identifier, witness_list: Vec<Identifier>) -> Result<bool> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .controller();
    let mut identifier_controller = IdentifierController::new(identifier.into(), controller, None);
    let wits: Vec<IdentifierPrefix> = witness_list.iter().map(|wit_id| wit_id.into()).collect();
    let broadcast_future = identifier_controller.broadcast_receipts(&wits);
    let rt = Runtime::new().unwrap();
    rt.block_on(broadcast_future)?;
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
        .controller();
    let initial_witnesses = initial_witnesses
        .iter()
        .map(|id| id.parse())
        .collect::<Result<_, _>>()?;
    let identifier_controller = IdentifierController::new(identifier.into(), controller, None);
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
        .controller();

    let mut identifier_controller = IdentifierController::new(identifier.into(), controller, None);

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
                    let sig_type: SignatureType = signature.derivation;
                    let sig = SelfSigningPrefix::new(sig_type, signature.signature.clone());
                    (exn.as_bytes().to_vec(), sig)
                },
            )
            .collect::<Vec<(Vec<u8>, SelfSigningPrefix)>>(),
    );

    let rt = Runtime::new().unwrap();
    let group_identifier = rt.block_on(group_identifier_future)?;
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
        .controller();

    let identifier_controller = IdentifierController::new(who_ask.into(), controller, None);
    let witnesses: Result<Vec<_>> = witness
        .iter()
        .map(|wit| -> Result<BasicPrefix> { Ok(parse_witness_prefix(wit)?) })
        .collect();
    identifier_controller
        .query_mailbox(&about_who.into(), &witnesses?)?
        .iter()
        .map(|qry| -> Result<String> { Ok(String::from_utf8(qry.encode()?)?) })
        .collect::<Result<Vec<_>>>()
}

pub fn query_watchers(who_ask: Identifier, about_who: Identifier) -> Result<Vec<String>> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .controller();

    let identifier_controller = IdentifierController::new(who_ask.into(), controller, None);

    identifier_controller
        .query_own_watchers(&about_who.into())?
        .iter()
        .map(|qry| -> Result<String> { Ok(String::from_utf8(qry.encode()?)?) })
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

pub fn finalize_query(
    identifier: Identifier,
    query_event: String,
    signature: Signature,
) -> Result<Vec<ActionRequired>> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .controller();

    let query =
        parse_event_type(query_event.as_bytes()).map_err(|_e| ControllerError::EventFormatError)?;

    let identifier_controller = IdentifierController::new(identifier.into(), controller, None);

    match query {
        EventType::Qry(ref qry) => {
            let finalize_qry_future =
                identifier_controller.finalize_query(vec![(qry.clone(), signature.into())]);

            let rt = Runtime::new().unwrap();
            let out = rt
                .block_on(finalize_qry_future)?
                .iter()
                .map(|ar| -> Result<_> {
                    match ar {
                        controller::mailbox_updating::ActionRequired::MultisigRequest(
                            data,
                            exchanges,
                        ) => Ok(ActionRequired {
                            action: Action::MultisigRequest,
                            data: String::from_utf8(data.encode()?)?,
                            additiona_data: String::from_utf8(exchanges.encode()?)?,
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
    let lc = parse_oobi(&oobi_json)?;
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .controller();
    let resolve_future = controller.resolve_oobi(lc);
    let rt = Runtime::new().unwrap();
    rt.block_on(resolve_future)
        .map_err(|e| Error::OobiResolvingError(e.to_string()))?;
    Ok(true)
}

pub fn process_stream(stream: String) -> Result<bool> {
    (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .controller()
        .process_stream(stream.as_bytes())?;
    Ok(true)
}

pub fn get_kel(identifier: Identifier) -> Result<String> {
    let signed_event = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .controller()
        .storage
        .get_kel_messages_with_receipts(&identifier.into())?
        .ok_or(Error::KelError(ControllerError::UnknownIdentifierError))?
        .into_iter()
        .flat_map(|event| Message::Notice(event).to_cesr().unwrap())
        .collect();
    Ok(String::from_utf8(signed_event)?)
}

pub fn to_cesr_signature(identifier: Identifier, signature: Signature) -> Result<String> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .controller();

    let identifier_controller = IdentifierController::new(identifier.into(), controller, None);
    Ok(identifier_controller.to_cesr_signature(signature.into(), 0)?)
}

pub fn sign_to_cesr(identifier: Identifier, data: String, signature: Signature) -> Result<String> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .controller();

    let identifier_controller = IdentifierController::new(identifier.into(), controller, None);
    Ok(identifier_controller.sign_to_cesr(&data, signature.into(), 0)?)
}

pub struct SplittingResult {
    pub oobis: Vec<String>,
    pub credentials: Vec<String>,
}
/// Splits parsed elements from stream into oobis to resolve and other signed
/// data.
pub fn split_oobis_and_data(stream: String) -> Result<SplittingResult> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .controller();
    let (oobis, stream) = controller.parse_cesr_stream(&stream)?;
    let oobis_str = oobis
        .into_iter()
        .map(|oobi| serde_json::to_string(&oobi).unwrap())
        .collect();

    let without_oobis = stream
        .iter()
        .map(|acdc| String::from_utf8(acdc.to_cesr().unwrap()).unwrap())
        .collect();
    Ok(SplittingResult {
        oobis: oobis_str,
        credentials: without_oobis,
    })
}

pub fn verify_from_cesr(stream: String) -> Result<bool> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .controller();
    controller.verify_from_cesr(&stream)?;
    Ok(true)
}

pub struct RegistryData {
    pub registry_id: String,
    pub ixn: String,
}

// Tel events
// Incept registry, returns ixn that anchor tel event. Need to be signed and sent do `finalize_event`.
pub fn incept_registry(identifier: Identifier) -> Result<RegistryData> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .controller();
    let registry_id = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .registry_id(&identifier)?
        .map(|id| id.parse().unwrap());

    let mut identifier_controller =
        IdentifierController::new(identifier.clone().into(), controller, registry_id);
    let (registry_id, ixn) = identifier_controller.incept_registry()?;
    (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_mut() // ref()
        .ok_or(Error::ControllerInitializationError)?
        .insert(identifier, &registry_id.to_str())?;
    let ixn = String::from_utf8(ixn).unwrap();

    Ok(RegistryData {
        registry_id: registry_id.to_str(),
        ixn,
    })
}

pub struct IssuanceData {
    pub vc_id: String,
    pub ixn: String,
}

// Issue credential, returns ixn that anchor tel event. Need to be signed and sent do `finalize_event`.
pub fn issue_credential(identifier: Identifier, credential_said: String) -> Result<IssuanceData> {
    let state = KEL.lock().map_err(|_e| Error::DatabaseLockingError)?;
    let registry_id = state
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .registry_id(&identifier)?
        .map(|id| id.parse().unwrap());
    let identifier_controller = IdentifierController::new(
        identifier.into(),
        state
            .as_ref()
            .ok_or(Error::ControllerInitializationError)?
            .controller(),
        registry_id,
    );
    let said: SelfAddressingIdentifier = credential_said
        .parse()
        .map_err(|_e| Error::SaiParseError("Can't parse digest".to_string()))?;
    let (id, ixn) = identifier_controller.issue(said)?;
    let ixn = String::from_utf8(ixn).unwrap();

    Ok(IssuanceData {
        vc_id: id.to_str(),
        ixn,
    })
}

// Revoke credential, returns ixn that anchor tel event. Need to be signed and sent do `finalize_event`.
pub fn revoke_credential(identifier: Identifier, credential_said: String) -> Result<String> {
    let state = KEL.lock().map_err(|_e| Error::DatabaseLockingError)?;
    let registry_id = state
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .registry_id(&identifier)?
        .map(|id| id.parse().unwrap());
    let identifier_controller = IdentifierController::new(
        identifier.into(),
        state
            .as_ref()
            .ok_or(Error::ControllerInitializationError)?
            .controller(),
        registry_id,
    );

    let said: SelfAddressingIdentifier = credential_said.parse()?;
    let ixn = identifier_controller.revoke(&said)?;
    let ixn = String::from_utf8(ixn).unwrap();

    Ok(ixn)
}

pub fn query_tel(
    identifier: Identifier,
    registry_id: String,
    credential_said: String,
) -> Result<String> {
    let state = KEL.lock().map_err(|_e| Error::DatabaseLockingError)?;
    let saved_registry_id = state
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .registry_id(&identifier)?
        .map(|id| id.parse().unwrap());
    let identifier_controller = IdentifierController::new(
        identifier.into(),
        state
            .as_ref()
            .ok_or(Error::ControllerInitializationError)?
            .controller(),
        saved_registry_id,
    );

    let vc_identifier: IdentifierPrefix = credential_said.parse()?;
    let registry_id: IdentifierPrefix = registry_id.parse()?;
    let query = identifier_controller.query_tel(registry_id, vc_identifier)?;
    Ok(String::from_utf8(query.encode()?).unwrap())
}

pub fn finalize_tel_query(
    identifier: Identifier,
    query_event: String,
    signature: Signature,
) -> Result<bool> {
    let state = KEL.lock().map_err(|_e| Error::DatabaseLockingError)?;
    let saved_registry_id = state
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .registry_id(&identifier)?
        .map(|id| id.parse().unwrap());
    let id: IdentifierPrefix = identifier.clone().into();
    let identifier_controller = IdentifierController::new(
        identifier.into(),
        state
            .as_ref()
            .ok_or(Error::ControllerInitializationError)?
            .controller(),
        saved_registry_id,
    );

    let query_event: TelQueryEvent =
        serde_json::from_str(&query_event).map_err(|e| Error::EventParsingError(e.to_string()))?;
    let finalize_query_future =
        identifier_controller.finalize_tel_query(&id, query_event, signature.into());
    let rt = Runtime::new().unwrap();
    rt.block_on(finalize_query_future)?;
    Ok(true)
}

pub fn get_credential_state(
    identifier: Identifier,
    credential_said: String,
) -> Result<Option<String>> {
    let state = KEL.lock().map_err(|_e| Error::DatabaseLockingError)?;
    let saved_registry_id = state
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .registry_id(&identifier)?
        .map(|id| id.parse().unwrap());
    let identifier_controller = IdentifierController::new(
        identifier.into(),
        state
            .as_ref()
            .ok_or(Error::ControllerInitializationError)?
            .controller(),
        saved_registry_id,
    );

    let state = identifier_controller
        .source
        .tel
        .get_vc_state(&credential_said.parse().unwrap())
        .unwrap();

    Ok(state.map(|st| format!("{:?}", st)))
}

pub fn notify_backers(identifier: Identifier) -> Result<bool> {
    let state = KEL.lock().map_err(|_e| Error::DatabaseLockingError)?;
    let saved_registry_id = state
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .registry_id(&identifier)?
        .map(|id| id.parse().unwrap());
    let identifier_controller = IdentifierController::new(
        identifier.into(),
        state
            .as_ref()
            .ok_or(Error::ControllerInitializationError)?
            .controller(),
        saved_registry_id,
    );
    let rt = Runtime::new().unwrap();
    rt.block_on(async { identifier_controller.notify_backers().await })?;

    Ok(true)
}

pub fn add_messagebox(identifier: Identifier, messagebox_oobi: String) -> Result<String> {
    let lc = parse_location_schemes(&messagebox_oobi)?;
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .controller();
    let resolve_future = controller.resolve_loc_schema(&lc);
    if let IdentifierPrefix::Basic(_bp) = &lc.eid {
        let rt = Runtime::new().unwrap();
        rt.block_on(resolve_future)?;

        let add_messagebox = event_generator::generate_end_role(
            &identifier.into(),
            &lc.eid,
            Role::Messagebox,
            true,
        )?;
        Ok(String::from_utf8(add_messagebox.encode()?)?)
    } else {
        Err(ControllerError::WrongWitnessPrefixError.into())
    }
}

pub fn get_messagebox(whose: String) -> Result<Vec<String>> {
    let messagebox_of: IdentifierPrefix = whose.parse()?;
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .controller();
    let locations: Result<Vec<_>, _> = controller
        .get_messagebox_location(&messagebox_of)?
        .iter()
        .map(|loc| -> Result<String, Error> {
            serde_json::to_string(loc).map_err(|e| Error::OobiParseError(e.to_string()))
        })
        .collect();
    Ok(locations?)
}
