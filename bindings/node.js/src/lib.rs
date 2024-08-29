use std::sync::Arc;

use crate::error::Error;
use inception_configuration::InceptionConfiguration;
use napi::{bindgen_prelude::Buffer, tokio::sync::Mutex};
use napi_derive::napi;
pub mod error;
pub mod utils;
use keri_controller::{controller::Controller, BasicPrefix, LocationScheme};
use utils::{configs, signature_config::{Signature, SignatureBuilder}};
mod identifier;
mod inception_configuration;
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
    pub fn new(config: Option<configs::Configs>) -> napi::Result<Self> {
        let optional_configs = config.map(|c| c.build().unwrap()).unwrap();

        let c = Controller::new(optional_configs).map_err(Error::ControllerError)?;
        Ok(JsController { inner: c })
    }

    #[napi]
    pub async fn incept(
        &self,
        config: &InceptionConfiguration
    ) -> napi::Result<Buffer> {
        let curr_keys = config.current_public_keys
            .iter()
            .map(|k| k.parse())
            .collect::<Result<Vec<BasicPrefix>, _>>()
            .map_err(|e| Error::KeyParsingError(e))?;
        let next_keys = config.next_public_keys
            .iter()
            .map(|k| k.parse())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Error::KeyParsingError(e))?;
        let witnesses = config.witnesses_location
            .iter()
            .map(|wit| {
                serde_json::from_str::<LocationScheme>(wit)
                    .map_err(|_| Error::OobiParsingError(wit.clone()))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let icp = self
            .inner
            .incept(curr_keys, next_keys, witnesses, config.witness_threshold as u64)
            .await
            .map_err(Error::MechanicError)?;
        Ok(icp.as_bytes().into())
    }

    #[napi]
    pub fn finalize_inception(
        &self,
        icp_event: Buffer,
        signatures: Vec<&SignatureBuilder>,
    ) -> napi::Result<JsIdentifier> {
        let ssp = signatures.iter().map(|p| p.to_prefix()).collect::<Vec<_>>()[0].clone();
        let incepted_identifier = self
            .inner
            .finalize_incept(&icp_event, &ssp)
            .map_err(Error::ControllerError)?;
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
