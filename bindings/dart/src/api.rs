use std::sync::Mutex;

use flutter_rust_bridge::support::lazy_static;
use keri::signer::Signer;
use rand::rngs::OsRng;

use anyhow::{Result};
use keriox_wrapper::kel::{Kel};

pub struct PublicKey(pub Vec<u8>);

#[derive(Clone)]
pub struct KeyPair {
    pub sk: Vec<u8>,
    pub pk: Vec<u8>,
}

pub fn generate_key_pair() -> KeyPair {
    let kp = ed25519_dalek::Keypair::generate(&mut OsRng {});
    let (vk, sk) = (kp.public, kp.secret);
    let pk = vk.to_bytes().to_vec();
    let sk = sk.to_bytes().to_vec();
    KeyPair { pk, sk }
}

pub fn get_public_key(kp: KeyPair) -> PublicKey {
    PublicKey(kp.pk.clone())
}

pub fn sign(kp: KeyPair, message: String) -> Result<Vec<u8>> {
    let signer = Signer::new_with_key(&kp.sk).unwrap();
    Ok(signer.sign(message.as_bytes())?)
}

lazy_static! {
    static ref KEL: Mutex<Option<Kel>> = Mutex::new(None);
}

pub struct Controller {
    pub identifier: String,
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
        public_keys.into_iter().map(|pk| pk.0).collect(),
        next_pub_keys.into_iter().map(|pk| pk.0).collect(),
        witnesses,
        witness_threshold,
    )?;
    Ok(icp)
}

pub fn finalize_inception(event: String, signature: Vec<u8>) -> Result<Controller> {
    let controller_id = (*KEL.lock().unwrap())
        .as_ref()
        .unwrap()
        .finalize_inception(event, signature)?;
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
        current_keys.into_iter().map(|pk| pk.0).collect(),
        new_next_keys.into_iter().map(|pk| pk.0).collect(),
        witness_to_add,
        witness_to_remove,
        witness_threshold,
    )?;
    Ok(rot)
}

pub fn finalize_event(event: String, signature: Vec<u8>) -> Result<()> {
    let signed_event = (*KEL.lock().unwrap())
        .as_ref()
        .unwrap()
        .finalize_event(event, signature)?;
    Ok(signed_event)
}

pub fn get_kel(id: String) -> Result<String> {
    let signed_event = (*KEL.lock().unwrap()).as_ref().unwrap().get_kel(id)?;
    Ok(signed_event)
}
