use std::sync::Arc;

use keriox_wrapper::kel::{IdentifierController, IdentifierPrefix, Kel, SelfAddressingPrefix};
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use utils::{key_config::Key, signature_config::Signature};
pub mod utils;
use napi::bindgen_prelude::ToNapiValue;

#[napi(object)]
#[derive(Debug)]
pub enum KeyType {
    ECDSAsecp256k1,
    Ed25519,
    Ed448,
    X25519,
    X448,
}

#[napi(object)]
#[derive(Debug)]
pub enum SignatureType {
    Ed25519Sha512,
    ECDSAsecp256k1Sha256,
    Ed448,
}

#[napi]
struct Controller {
    kel: Arc<Kel>,
}

#[napi]
impl Controller {
    #[napi(factory)]
    pub fn init() -> Self {
        // TODO setting database path
        let proc = Kel::init("./db");
        Controller {
            kel: Arc::new(proc),
        }
    }

    #[napi]
    pub fn finalize_inception(
        &self,
        icp_event: Buffer,
        signatures: Vec<Signature>,
    ) -> napi::Result<IdController> {
        let ssp = signatures.iter().map(|p| p.to_prefix()).collect::<Vec<_>>();
        let c = self
            .kel
            .finalize_inception(String::from_utf8(icp_event.to_vec()).unwrap(), ssp)
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
        Ok(IdController {
            controller: IdentifierController {
                id: c,
                source: self.kel.clone(),
            },
        })
    }

    #[napi]
    pub fn get_by_identifier(&self, id: String) -> napi::Result<IdController> {
        Ok(IdController::new(id.parse().unwrap(), self.kel.clone()))
    }
}

#[napi]
struct IdController {
    controller: IdentifierController,
}

#[napi]
impl IdController {
    pub fn new(id: IdentifierPrefix, kel: Arc<Kel>) -> Self {
        Self {
            controller: IdentifierController { id, source: kel },
        }
    }
    #[napi]
    pub fn get_kel(&self) -> napi::Result<String> {
        Ok(self.controller.get_kel().unwrap())
    }

    #[napi]
    pub fn rotate(&self, pks: Vec<Key>, npks: Vec<Key>) -> napi::Result<Buffer> {
        let curr_keys = pks.iter().map(|k| k.to_prefix()).collect::<Vec<_>>();
        let next_keys = npks.iter().map(|k| k.to_prefix()).collect::<Vec<_>>();
        Ok(self
            .controller
            .rotate(curr_keys, next_keys, vec![], vec![], 0)
            .unwrap()
            .as_bytes()
            .into())
    }

    #[napi]
    pub fn interact(&self, anchored_data: Vec<String>) -> napi::Result<Buffer> {
        let sais = anchored_data
            .iter()
            .map(|d| d.parse::<SelfAddressingPrefix>().unwrap())
            .collect::<Vec<_>>();
        Ok(self
            .controller
            .anchor(&sais)
            .unwrap()
            .serialize()
            .unwrap()
            .into())
    }

    #[napi]
    pub fn finalize_event(&self, event: Buffer, signatures: Vec<Signature>) -> napi::Result<()> {
        let sigs = signatures.into_iter().map(|s| s.to_prefix()).collect::<Vec<_>>();
        self.controller
            .finalize_event(&event.to_vec(), sigs)
            .map_err(|e| napi::Error::from_reason(e.to_string()))
    }
}

#[napi]
pub fn incept(pks: Vec<Key>, npks: Vec<Key>) -> Buffer {
    let curr_keys = pks.iter().map(|k| k.to_prefix()).collect::<Vec<_>>();
    let next_keys = npks.iter().map(|k| k.to_prefix()).collect::<Vec<_>>();
    let icp = Kel::incept(curr_keys, next_keys, vec![], 0)
        .map_err(|e| napi::Error::from_reason(e.to_string()))
        .unwrap();
    icp.as_bytes().into()
}
