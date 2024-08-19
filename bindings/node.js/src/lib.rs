use std::sync::Arc;

use napi::{bindgen_prelude::{Buffer, External, Reference, SharedReference}, Env};
use napi_derive::napi;
pub mod utils;
use keri_controller::{controller::Controller, identifier::Identifier, IdentifierPrefix, LocationScheme};
use utils::{configs, key_config::Key, signature_config::Signature};

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
          .map_err(|e| napi::Error::from_reason(e.to_string())).unwrap();
      JsController {
          inner: c,
      }
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
        let curr_keys = pks.iter().map( |k| k.p.to_string().parse().unwrap()).collect::<Vec<_>>(); //k.to_prefix()).collect::<Vec<_>>();
        let next_keys = npks.iter().map(|k| k.p.to_string().parse().unwrap()).collect::<Vec<_>>();//k.to_prefix()).collect::<Vec<_>>();
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
    ) -> napi::Result<IdController> {
        let ssp = signatures.iter().map(|p| p.to_prefix()).collect::<Vec<_>>()[0].clone();
        let incepted_identifier = self
            .inner
            .finalize_incept(&icp_event.to_vec(), &ssp)
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
        Ok(IdController {inner: incepted_identifier})
    }

    // #[napi]
    // pub fn get_by_identifier(&self, id: String) -> napi::Result<IdController> {
    //     Ok(IdController::new(
    //         id.parse().unwrap(),
    //         self.kel_data.clone(),
    //     ))
    // }
}

#[napi]
pub struct IdController {
    inner: Identifier,
}

#[napi]
impl IdController {
    pub fn new(id: IdentifierPrefix, kel: Arc<keri_controller::controller::Controller>) -> Self {
        let id = Identifier::new(id, None, kel.known_events.clone(), kel.communication.clone());
        Self {
            inner: id
          }
        }
    }
    // #[napi]
    // pub fn get_kel(&self) -> napi::Result<String> {
    //     Ok(self.controller.get_kel().unwrap())
    // }

    // #[napi]
    // pub fn get_id(&self) -> napi::Result<String> {
    //     Ok(self.controller.id.to_str())
    // }

    // #[napi]
    // pub fn rotate(
    //     &self,
    //     pks: Vec<Key>,
    //     npks: Vec<Key>,
    //     // loc scheme json of witness
    //     witnesses_to_add: Vec<String>,
    //     // identifiers of witness to remove
    //     witnesses_to_remove: Vec<String>,
    //     witness_threshold: u32,
    // ) -> napi::Result<Buffer> {
    //     let curr_keys = pks.iter().map(|k| k.to_prefix()).collect::<Vec<_>>();
    //     let next_keys = npks.iter().map(|k| k.to_prefix()).collect::<Vec<_>>();
    //     let witnesses_to_add = witnesses_to_add
    //         .iter()
    //         .map(|wit| serde_json::from_str::<LocationScheme>(wit).map_err(|e| e.to_string()))
    //         .collect::<Result<Vec<_>, _>>()
    //         .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    //     let witnesses_to_remove = witnesses_to_remove
    //         .iter()
    //         .map(|wit| wit.parse::<BasicPrefix>())
    //         .collect::<Result<Vec<_>, _>>()
    //         .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    //     Ok(self
    //         .controller
    //         .rotate(
    //             curr_keys,
    //             next_keys,
    //             1,
    //             witnesses_to_add,
    //             witnesses_to_remove,
    //             witness_threshold as u64,
    //         )
    //         .unwrap()
    //         .as_bytes()
    //         .into())
    // }

    // #[napi]
    // pub fn anchor(&self, anchored_data: Vec<String>) -> napi::Result<Buffer> {
    //     let sais = anchored_data
    //         .iter()
    //         .map(|d| d.parse::<SelfAddressingPrefix>().unwrap())
    //         .collect::<Vec<_>>();
    //     Ok(self.controller.anchor(&sais).unwrap().as_bytes().into())
    // }

    // #[napi]
    // pub fn finalize_event(&self, event: Buffer, signatures: Vec<Signature>) -> napi::Result<()> {
    //     let sigs = signatures
    //         .into_iter()
    //         .map(|s| s.to_prefix())
    //         .collect::<Vec<_>>();
    //     self.controller
    //         .finalize_event(&event.to_vec(), sigs)
    //         .map_err(|e| napi::Error::from_reason(e.to_string()))
    // }

    // #[napi]
    // pub fn sign_data(&self, signature: Signature) -> napi::Result<String> {
    //     let attached_signature = AttachedSignaturePrefix {
    //         index: 0,
    //         signature: signature.to_prefix(),
    //     };

    //     let event_seal = self
    //         .controller
    //         .get_last_establishment_event_seal()
    //         .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    //     let att = Attachment::SealSignaturesGroups(vec![(event_seal, vec![attached_signature])]);
    //     Ok(att.to_cesr())
    // }
// }

// #[napi]
// pub fn incept(
//     pks: Vec<Key>,
//     npks: Vec<Key>,
//     witnesses: Vec<String>,
//     witness_threshold: u32,
// ) -> napi::Result<Buffer> {
//     let curr_keys = pks.iter().map(|k| k.to_prefix()).collect::<Vec<_>>();
//     let next_keys = npks.iter().map(|k| k.to_prefix()).collect::<Vec<_>>();
//     let witnesses = witnesses
//         .iter()
//         .map(|wit| wit.parse::<BasicPrefix>().map_err(|e| e.to_string()))
//         .collect::<Result<Vec<_>, _>>()
//         .map_err(|e| napi::Error::from_reason(e.to_string()))?;
//     let icp = event_generator::incept(curr_keys, next_keys, witnesses, witness_threshold as u64)
//         .map_err(|e| napi::Error::from_reason(e.to_string()))
//         .unwrap();
//     Ok(icp.as_bytes().into())
// }