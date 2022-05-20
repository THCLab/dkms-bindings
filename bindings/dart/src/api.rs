use std::{path::Path, sync::Mutex};

use flutter_rust_bridge::support::lazy_static;

use anyhow::{anyhow, Result};
use keriox_wrapper::{
    controller::OptionalConfig,
    kel::{Basic, BasicPrefix, IdentifierPrefix, Kel, LocationScheme, Prefix, Role, SelfSigning, EndRole},
    utils::{key_prefix_from_b64, signature_prefix_from_hex},
};
use serde::{Deserialize, Serialize};

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
    pub fn new(algorithm: KeyType, key: String) -> Self {
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

pub struct Config {
    pub initial_oobis: String,
}

pub fn initial_oobis(oobis_json: String) -> Config {
    Config {
        initial_oobis: oobis_json,
    }
}

lazy_static! {
    static ref KEL: Mutex<Option<keriox_wrapper::controller::Controller>> = Mutex::new(None);
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

pub fn init_kel(input_app_dir: String, known_oobis: Option<Config>) -> Result<()> {
    let event_db_path = vec![input_app_dir.clone(), "db".into()].join("");
    let oobi_db_path = vec![input_app_dir, "oobi_db".into()].join("");
    let config = if let Some(conf) = known_oobis {
        Some(OptionalConfig::init().set_initial_oobis(&conf.initial_oobis)?)
    } else {
        None
    };
    let controller = keriox_wrapper::controller::Controller::new(
        Path::new(&event_db_path),
        Path::new(&oobi_db_path),
        config,
    )?;

    *KEL.lock().unwrap() = Some(controller);

    Ok(())
}

pub fn incept(
    public_keys: Vec<PublicKey>,
    next_pub_keys: Vec<PublicKey>,
    witnesses: Vec<String>,
    witness_threshold: u64,
) -> Result<String> {
    let witnesses = witnesses
        .iter()
        .map(|wit| wit.parse::<BasicPrefix>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!(e.to_string()))?;
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
        .ok_or(anyhow!("There is no controller"))?
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
    witness_to_add: Vec<String>,
    witness_to_remove: Vec<String>,
    witness_threshold: u64,
) -> Result<String> {
    let id = controller.identifier.parse().unwrap();
    let witnesses_to_add = witness_to_add
        .iter()
        .map(|wit| wit.parse::<BasicPrefix>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!(e.to_string()))?;
    let witnesses_to_remove = witness_to_remove
        .iter()
        .map(|wit| wit.parse::<BasicPrefix>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!(e.to_string()))?;
    let rot = (*KEL.lock().unwrap()).as_ref().unwrap().kel.rotate(
        id,
        current_keys
            .into_iter()
            .map(|pk| key_prefix_from_b64(&pk.key, pk.algorithm.into()).unwrap())
            .collect(),
        new_next_keys
            .into_iter()
            .map(|pk| key_prefix_from_b64(&pk.key, pk.algorithm.into()).unwrap())
            .collect(),
        witnesses_to_add,
        witnesses_to_remove,
        witness_threshold,
    )?;
    Ok(rot)
}

pub fn add_watcher(controller: Controller, watcher_oobi: String) -> Result<String> {
    resolve_oobi(watcher_oobi.clone())?;
    let watcher_id = serde_json::from_str::<LocationScheme>(&watcher_oobi)?.eid;
    let id = &controller.identifier.parse()?;
    let add_watcher = (*KEL.lock().unwrap()).as_ref().unwrap().generate_end_role(
        id,
        &watcher_id,
        Role::Watcher,
        true,
    )?;
    String::from_utf8(add_watcher.serialize()?).map_err(|e| anyhow!(e.to_string()))
}

pub fn finalize_event(identifier: Controller, event: String, signature: Signature) -> Result<()> {
    let signed_event = (*KEL.lock().unwrap()).as_ref().unwrap().finalize_event(
        &identifier.identifier.parse()?,
        event.as_bytes(),
        vec![signature_prefix_from_hex(
            &signature.key,
            signature.algorithm.into(),
        )?],
    )?;
    Ok(signed_event)
}

pub fn resolve_oobi(oobi_json: String) -> Result<()> {
    let lc: LocationScheme = serde_json::from_str(&oobi_json)?;
    (*KEL.lock().unwrap())
        .as_ref()
        .unwrap()
        .resolve_loc_schema(&lc)?;
    Ok(())
}

pub fn propagate_oobi(controller: Controller, oobis_json: String) -> Result<()> {
    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    enum Oobis {
        LocScheme(LocationScheme),
        EndRole(EndRole),
    }
    match serde_json::from_str::<Vec<Oobis>>(&oobis_json) {
        Ok(oobis) => {
            for oobi in oobis {
                (*KEL.lock().unwrap())
                    .as_ref()
                    .unwrap()
                    .send_oobi_to_watcher(&controller.identifier.parse().unwrap(), &serde_json::to_string(&oobi)?)?;
            };
                Ok(())
        },
        Err(_) => Err(anyhow!("Wrong oobis format")),
    }

}

pub fn query(controller: Controller, query_id: String) -> Result<()> {
    (*KEL.lock().unwrap())
        .as_ref()
        .unwrap()
        .query(&controller.identifier.parse().unwrap(), &query_id)?;
    Ok(())
}

pub fn process_stream(stream: String) -> Result<()> {
    (*KEL.lock().unwrap())
        .as_ref()
        .unwrap()
        .kel
        .parse_and_process(stream.as_bytes())?;
    Ok(())
}

pub fn get_kel(cont: Controller) -> Result<String> {
    let signed_event = (*KEL.lock().unwrap()).as_ref().unwrap().kel.get_kel(&cont.identifier)?;
    Ok(signed_event)
}

pub fn get_kel_by_str(cont_id: String) -> Result<String> {
    let signed_event = (*KEL.lock().unwrap()).as_ref().unwrap().kel.get_kel(&cont_id)?;
    Ok(signed_event)
}

pub struct PublicKeySignaturePair {
    pub key: PublicKey,
    pub signature: Signature,
}

/// Returns pairs: public key encoded in base64 and signature encoded in hex
pub fn get_current_public_key(attachment: String) -> Result<Vec<PublicKeySignaturePair>> {
    let attachment = (*KEL.lock().unwrap())
        .as_ref()
        .unwrap()
        .kel
        .get_current_public_key(attachment)?;
    Ok(attachment
        .iter()
        .map(|(bp, sp)| PublicKeySignaturePair {
            key: PublicKey::new(bp.derivation.into(), base64::encode(bp.public_key.key())),
            signature: Signature::new(sp.derivation.into(), hex::encode(sp.signature.clone())),
        })
        .collect::<Vec<_>>())
}
