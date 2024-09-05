use std::{iter::zip, sync::Arc};

use crate::{
    error::Error,
    utils::tel_utils::{IssuanceData, RegistryInceptionData},
    Signature,
};
use keri_controller::{
    error::ControllerError, identifier::Identifier, BasicPrefix, EndRole, IdentifierPrefix, LocationScheme, Oobi, TelState
};
use keri_core::{actor::prelude::Message, event::sections::seal::EventSeal, processor::validator::VerificationError};
use napi::{bindgen_prelude::Buffer, tokio::sync::Mutex};
use napi_derive::napi;
use said::{
    derivation::{HashFunction, HashFunctionCode},
    SelfAddressingIdentifier,
};

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
        let kel = inner.get_own_kel();
        let kel_str = match kel {
            Some(kel) => kel
                .into_iter()
                .map(|event| String::from_utf8(Message::Notice(event).to_cesr().unwrap()).unwrap())
                .fold(String::new(), |a, b| a + &b + "\n"),
            None => "KEL not found".to_string(),
        };
        Ok(kel_str)
    }

    #[napi]
    pub async fn find_state(&self, about_id: String) -> napi::Result<String> {
        let inner = self.inner.lock().await;
        let about_who: IdentifierPrefix = about_id.parse().map_err(Error::IdParsingError)?;
        let state = inner.find_state(&about_who).map_err(Error::MechanicError)?;
        Ok(format!("{:?}", state))
    }

    #[napi]
    pub async fn get_id(&self) -> napi::Result<String> {
        let inner = self.inner.lock().await;
        Ok(inner.id().to_string())
    }

    #[napi]
    pub async fn notify_witness(&self) -> napi::Result<()> {
        let mut inner = self.inner.lock().await;
        inner
            .notify_witnesses()
            .await
            .map_err(Error::MechanicError)?;
        Ok(())
    }

    #[napi]
    pub async fn query_mailbox(&self) -> napi::Result<Vec<Buffer>> {
        let inner = self.inner.lock().await;
        let id = inner.id();
        let witnesses = inner.witnesses().collect::<Vec<_>>();
        let kel = inner
            .query_mailbox(id, &witnesses)
            .map_err(Error::ControllerError)?;
        let kel_str = kel
            .into_iter()
            .map(|event| {
                let encoded = event
                    .encode()
                    .map_err(|e| Error::Unexpected(e.to_string()))?;
                Ok(Buffer::from(encoded))
            })
            .collect::<Result<Vec<_>, Error>>();
        Ok(kel_str?)
    }

    #[napi]
    pub async fn finalize_query_mailbox(
        &self,
        queries: Vec<Buffer>,
        signatures: Vec<&Signature>,
    ) -> napi::Result<()> {
        let mut inner = self.inner.lock().await;
        let qries_and_sigs = zip(queries, signatures)
            .map(|(qry, sig)| {
                Ok((
                    serde_json::from_slice(&qry).map_err(|_| Error::EventParsingError)?,
                    sig.to_prefix(),
                ))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        inner
            .finalize_query_mailbox(qries_and_sigs)
            .await
            .map_err(Error::MechanicError)?;

        Ok(())
    }

    // #[napi]
    // pub async fn rotate(
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
    //     let id = self.inner.lock().await;
    //     Ok(id
    //         .rotate(
    //             curr_keys,
    //             next_keys,
    //             1,
    //             witnesses_to_add,
    //             witnesses_to_remove,
    //             witness_threshold as u64,
    //         )
    //         .await
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

    #[napi]
    pub async fn incept_registry(&self) -> napi::Result<RegistryInceptionData> {
        let mut id = self.inner.lock().await;
        let (registry_id, vcp) = id.incept_registry().map_err(Error::ControllerError)?;

        Ok(RegistryInceptionData {
            ixn: vcp.into(),
            registry_id: registry_id.to_string(),
        })
    }

    #[napi]
    pub async fn finalize_incept_registry(
        &self,
        event: Buffer,
        signature: &Signature,
    ) -> napi::Result<()> {
        let mut id = self.inner.lock().await;
        id.finalize_incept_registry(&event, signature.to_prefix())
            .await
            .map_err(Error::MechanicError)?;

        Ok(())
    }

    #[napi]
    pub async fn issue(&self, vc: Buffer) -> napi::Result<IssuanceData> {
        let said = HashFunction::from(HashFunctionCode::Blake3_256).derive(&vc);
        let id = self.inner.lock().await;
        let (vc_hash, iss) = id.issue(said).map_err(Error::ControllerError)?;

        Ok(IssuanceData {
            ixn: iss.into(),
            vc_hash: vc_hash.to_string(),
        })
    }

    #[napi]
    pub async fn finalize_issue(&self, event: Buffer, signature: &Signature) -> napi::Result<()> {
        let mut id = self.inner.lock().await;
        id.finalize_issue(&event, signature.to_prefix())
            .await
            .map_err(Error::MechanicError)?;

        Ok(())
    }

    #[napi]
    pub async fn revoke(&self, vc_hash: String) -> napi::Result<Buffer> {
        let id = self.inner.lock().await;
        let ixn = id
            .revoke(&vc_hash.parse().map_err(|e| Error::HashParsingError(e))?)
            .map_err(Error::ControllerError)?;

        Ok(ixn.into())
    }

    #[napi]
    pub async fn finalize_revoke(&self, event: Buffer, signature: &Signature) -> napi::Result<()> {
        let mut id = self.inner.lock().await;
        id.finalize_revoke(&event, signature.to_prefix())
            .await
            .map_err(Error::MechanicError)?;

        Ok(())
    }

    #[napi]
    pub async fn notify_backers(&self) -> napi::Result<()> {
        let id = self.inner.lock().await;
        id.notify_backers().await.map_err(Error::MechanicError)?;

        Ok(())
    }

    #[napi]
    pub async fn add_watcher(&self, watcher_oobi: String) -> napi::Result<Buffer> {
        let oobi: LocationScheme = serde_json::from_str(&watcher_oobi)
            .map_err(|_| Error::OobiParsingError(watcher_oobi.clone()))?;

        let watcher_id = oobi.eid.clone();
        let id = self.inner.lock().await;

        id.resolve_oobi(&Oobi::Location(oobi))
            .await
            .map_err(Error::MechanicError)?;
        Ok(id
            .add_watcher(watcher_id)
            .map_err(Error::MechanicError)?
            .as_bytes()
            .into())
    }

    #[napi]
    pub async fn finalize_add_watcher(
        &self,
        event: Buffer,
        signature: &Signature,
    ) -> napi::Result<()> {
        let id = self.inner.lock().await;
        id.finalize_add_watcher(&event, signature.to_prefix())
            .await
            .map_err(Error::MechanicError)?;

        Ok(())
    }

    #[napi]
    pub async fn query_kel(
        &self,
        about_id: String,
        sn: u32,
        digest: String,
    ) -> napi::Result<Vec<Buffer>> {
        let id = self.inner.lock().await;
        let about_id = about_id.parse().map_err(Error::IdParsingError)?;
        let seal = EventSeal {
            prefix: about_id,
            sn: sn.into(),
            event_digest: digest.parse().map_err(Error::HashParsingError)?,
        };
        Ok(id
            .query_watchers(&seal)
            .map_err(Error::ControllerError)?
            .into_iter()
            .map(|qry| {
                Ok(Buffer::from(
                    qry.encode().map_err(|e| Error::Unexpected(e.to_string()))?,
                ))
            })
            .collect::<Result<Vec<_>, Error>>()?)
    }

    #[napi]
    pub async fn finalize_query_kel(
        &self,
        qries: Vec<Buffer>,
        signatures: Vec<&Signature>,
    ) -> napi::Result<bool> {
        let inner = self.inner.lock().await;
        let qries_and_sigs = zip(qries, signatures)
            .map(|(qry, sig)| {
                Ok((
                    serde_json::from_slice(&qry).map_err(|_| Error::EventParsingError)?,
                    sig.to_prefix(),
                ))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let (res, _err) = inner.finalize_query(qries_and_sigs).await;

        Ok(match res {
            keri_controller::identifier::query::QueryResponse::Updates => true,
            keri_controller::identifier::query::QueryResponse::NoUpdates => false,
        })
    }

    #[napi]
    pub async fn query_full_kel(&self, about_id: String) -> napi::Result<Vec<Buffer>> {
        let id = self.inner.lock().await;
        let about_id = &about_id.parse().map_err(Error::IdParsingError)?;
        let watchers = id.watchers().map_err(Error::ControllerError)?;
        let mut qries = vec![];
        for watcher in watchers {
            let qry = id
                .query_full_log(about_id, watcher)
                .map_err(Error::ControllerError)?
                .encode()
                .unwrap();
            qries.push(Buffer::from(qry));
        }
        Ok(qries)
    }

    #[napi]
    pub async fn vc_state(&self, digest: String) -> napi::Result<Option<VcState>> {
        let id = self.inner.lock().await;
        let vc_hash: SelfAddressingIdentifier = digest.parse().map_err(Error::HashParsingError)?;
        let out = id.find_vc_state(&vc_hash).map_err(Error::ControllerError)?;

        Ok(out.map(|st| match st {
            TelState::Issued(_) => VcState::Issued,
            TelState::Revoked => VcState::Revoked,
            TelState::NotIssued => VcState::NotIssued,
        }))
    }

    #[napi]
    pub async fn send_oobi_to_watcher(&self, oobi: String) -> napi::Result<()> {
        let id = self.inner.lock().await;
        let oobi: Oobi =
            serde_json::from_str(&oobi).map_err(|_e| Error::OobiParsingError(oobi.to_string()))?;
        id.send_oobi_to_watcher(id.id(), &oobi)
            .await
            .map_err(Error::ControllerError)?;

        Ok(())
    }

    #[napi]
    pub async fn query_tel(&self, registry_id: String, vc_id: String) -> napi::Result<Buffer> {
        let id = self.inner.lock().await;
        let reg_id = registry_id.parse().map_err(Error::IdParsingError)?;
        let vc_id = vc_id.parse().map_err(Error::IdParsingError)?;
        let qry = id
            .query_tel(reg_id, vc_id)
            .map_err(Error::ControllerError)?;

        Ok(qry.encode().unwrap().into())
    }

    #[napi]
    pub async fn finalize_query_tel(
        &self,
        event: Buffer,
        signature: &Signature,
    ) -> napi::Result<()> {
        let id = self.inner.lock().await;
        let qry: teliox::query::TelQueryEvent =
            serde_json::from_slice(&event).map_err(|_| Error::EventParsingError)?;
        id.finalize_query_tel(qry, signature.to_prefix())
            .await
            .map_err(Error::MechanicError)?;

        Ok(())
    }

    #[napi]
    pub async fn oobi(&self) -> napi::Result<Vec<String>> {
        let locked_id = self.inner.lock().await;
        let filter_locations = |identifiers: &[BasicPrefix]| -> Vec<Oobi> {
            identifiers
                .into_iter()
                .flat_map(|id| {
                    locked_id
                        .get_location(&IdentifierPrefix::Basic(id.clone()))
                        .unwrap()
                })
                .map(Oobi::Location)
                .collect()
        };

        let witnesses = locked_id.witnesses().collect::<Vec<_>>();
        let locations = filter_locations(&witnesses);
        let witnesses_oobi = witnesses.iter().map(|cid| {
            Oobi::EndRole(EndRole {
                eid: IdentifierPrefix::Basic(cid.clone()),
                role: keri_core::oobi::Role::Witness,
                cid: locked_id.id().clone(),
            })
        });
        let oobis: Vec<String> = locations
            .into_iter()
            .chain(witnesses_oobi)
            .map(|oobi| serde_json::to_string(&oobi).unwrap())
            .collect();
        Ok(oobis)
    }

    #[napi]
    pub async fn registry_id_oobi(&self) -> Option<Vec<String>> {
        let locked_id = self.inner.lock().await;

        let registry_id = locked_id.registry_id().map(|registry_id| {
            locked_id
                .witnesses()
                .map(|witness| {
                    Oobi::EndRole(EndRole {
                        cid: registry_id.clone(),
                        role: keri_core::oobi::Role::Witness,
                        eid: IdentifierPrefix::Basic(witness),
                    })
                })
                .map(|oobi| serde_json::to_string(&oobi).unwrap())
                .collect()
        });
        registry_id
    }

    #[napi]
    pub async fn registry_id(&self) -> Option<String> {
        let locked_id = self.inner.lock().await;

        let registry_id = locked_id.registry_id().map(|id| id.to_string());
        registry_id
    }

    #[napi]
    pub async fn sign(&self, input: String, signatures: Vec<&Signature>) -> Option<String> {
        let locked_id = self.inner.lock().await;
        let stream = locked_id
            .sign_to_cesr(
                &input,
                &signatures
                    .into_iter()
                    .map(|s| s.to_prefix())
                    .collect::<Vec<_>>(),
            )
            .unwrap();

        Some(stream)
    }

    #[napi]
    pub async fn verify(&self, stream: String) -> napi::Result<bool> {
        let locked_id = self.inner.lock().await;
        let verification_result = locked_id
            .verify_from_cesr(&stream);
        match verification_result {
            Ok(_) => Ok(true),
            Err(ControllerError::FaultySignature) => { Ok(false)}
            Err(ControllerError::VerificationError(errors)) => {
                if errors.iter().any(|(reason, _)| matches!(reason, VerificationError::VerificationFailure)) {
                    Ok(false)
                } else {
                    Err(Error::ControllerError(keri_controller::error::ControllerError::VerificationError(errors)))?
                }
            },
            Err(e) => Err(Error::ControllerError(e))?,
        }
    }
}

#[napi]
pub enum VcState {
    Issued,
    Revoked,
    NotIssued,
}
