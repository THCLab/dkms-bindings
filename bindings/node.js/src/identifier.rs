use std::{iter::zip, str::FromStr, sync::Arc};

use crate::Signature;
use keri_controller::{identifier::Identifier, SelfSigningPrefix};
use keri_core::actor::prelude::Message;
use napi::{bindgen_prelude::Buffer, tokio::sync::Mutex};
use napi_derive::napi;

#[napi]
pub struct JsIdentifier {
    pub(crate) inner: Arc<Mutex<Identifier>>,
}

#[napi]
impl JsIdentifier {
    // pub fn new(id: IdentifierPrefix, kel: Arc<keri_controller::controller::Controller>) -> Self {
    //     let id = Identifier::new(id, None, kel.known_events.clone(), kel.communication.clone());
    //     Self {
    //         inner: id
    //       }
    //     }
    // }
    #[napi]
    pub async fn get_kel(&self) -> napi::Result<String> {
        let inner = self.inner.lock().await;
        let kel = inner.get_own_kel().unwrap();
        let kel_str = kel
            .into_iter()
            .map(|event| String::from_utf8(Message::Notice(event).to_cesr().unwrap()).unwrap())
            .fold(String::new(), |a, b| a + &b + "\n");
        Ok(kel_str)
    }

    #[napi]
    pub async fn get_id(&self) -> napi::Result<String> {
        let inner = self.inner.lock().await;
        Ok(inner.id().to_string())
    }

    #[napi]
    pub async fn notify_witness(&self) -> napi::Result<()> {
        let mut inner = self.inner.lock().await;
        inner.notify_witnesses().await.unwrap();
        Ok(())
    }

    #[napi]
    pub async fn query_mailbox(&self) -> napi::Result<Vec<Buffer>> {
        let inner = self.inner.lock().await;
        let id = inner.id();
        let witnesses = inner.witnesses().collect::<Vec<_>>();
        let kel = inner.query_mailbox(id, &witnesses).unwrap(); // .get_own_kel().unwrap();
        let kel_str = kel
            .into_iter()
            .map(|event| Buffer::from(event.encode().unwrap()))
            .collect::<Vec<_>>();
        Ok(kel_str)
    }

    #[napi]
    pub async fn finalize_query_mailbox(
        &self,
        qries: Vec<Buffer>,
        signatures: Vec<Signature>,
    ) -> napi::Result<()> {
        let mut inner = self.inner.lock().await;
        let qries_and_sigs = zip(qries, signatures).map(|(qry, sig)| {
            (
                serde_json::from_slice(&qry).unwrap(),
                SelfSigningPrefix::from_str(&sig.p).unwrap(),
            )
        });
        inner
            .finalize_query_mailbox(qries_and_sigs.collect())
            .await
            .unwrap();

        Ok(())
    }

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
}
