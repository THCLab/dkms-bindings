use std::sync::Arc;

use napi::{bindgen_prelude::Buffer, tokio::sync::Mutex};
use napi_derive::napi;
pub mod utils;
use keri_controller::{controller::Controller, LocationScheme};
use utils::{configs, key_config::Key, signature_config::Signature};
mod identifier;
use identifier::JsIdentifier;

#[napi]
#[derive(Debug)]
pub enum KeyType {
    ECDSAsecp256k1,
    Ed25519,
    Ed448,
    X25519,
    X448,
}

#[napi]
#[derive(Debug)]
pub enum SignatureType {
    Ed25519Sha512,
    ECDSAsecp256k1Sha256,
    Ed448,
}

#[napi(js_name = "Controller")]
pub struct JsController {
    inner: Controller,
}

#[napi]
impl JsController {
    #[napi(constructor)]
    pub fn new(config: Option<configs::Configs>) -> Self {
        let optional_configs = config.map(|c| c.build().unwrap()).unwrap();

        let c = Controller::new(optional_configs)
            .map_err(|e| napi::Error::from_reason(e.to_string()))
            .unwrap();
        JsController { inner: c }
    }

    #[napi]
    pub async fn incept(
        &self,
        pks: Vec<Key>,
        npks: Vec<Key>,
        // witnesses location schemes jsons
        witnesses: Vec<String>,
        witness_threshold: u32,
    ) -> napi::Result<Buffer> {
        let curr_keys = pks
            .iter()
            .map(|k| k.p.to_string().parse().unwrap())
            .collect::<Vec<_>>(); //k.to_prefix()).collect::<Vec<_>>();
        let next_keys = npks
            .iter()
            .map(|k| k.p.to_string().parse().unwrap())
            .collect::<Vec<_>>(); //k.to_prefix()).collect::<Vec<_>>();
        let witnesses = witnesses
            .iter()
            .map(|wit| serde_json::from_str::<LocationScheme>(wit))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
        let icp = self
            .inner
            .incept(curr_keys, next_keys, witnesses, witness_threshold as u64)
            .await
            .map_err(|e| napi::Error::from_reason(e.to_string()))
            .unwrap();
        Ok(icp.as_bytes().into())
    }

    #[napi]
    pub fn finalize_inception(
        &self,
        icp_event: Buffer,
        signatures: Vec<Signature>,
    ) -> napi::Result<JsIdentifier> {
        let ssp = signatures.iter().map(|p| p.to_prefix()).collect::<Vec<_>>()[0].clone();
        let incepted_identifier = self
            .inner
            .finalize_incept(&icp_event, &ssp)
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
        Ok(JsIdentifier {
            inner: Arc::new(Mutex::new(incepted_identifier)),
        })
    }

    // #[napi]
    // pub fn get_by_identifier(&self, id: String) -> napi::Result<IdController> {
    //     Ok(IdController::new(
    //         id.parse().unwrap(),
    //         self.kel_data.clone(),
    //     ))
    // }
}
