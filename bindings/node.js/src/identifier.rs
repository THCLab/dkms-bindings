use std::{iter::zip, sync::Arc};

use crate::{
    error::Error,
    utils::{
        rotation_configuration::RotationConfiguration,
        tel_utils::{IssuanceData, RegistryInceptionData},
    },
    Signature,
};
use keri_sdk::advanced::{
    BasicPrefix, EndRole, EventSeal, HashFunction, HashFunctionCode, Identifier, IdentifierPrefix,
    LocationScheme, Oobi, QueryResponse, Role, SelfAddressingIdentifier, TelQueryEvent, TelState,
    VerificationIssue,
};
use napi::{bindgen_prelude::Buffer, tokio::sync::Mutex};
use napi_derive::napi;

#[napi]
pub struct JsIdentifier {
    pub(crate) inner: Arc<Mutex<Identifier>>,
}

#[napi]
impl JsIdentifier {
    #[napi]
    pub async fn get_kel(&self) -> napi::Result<String> {
        let inner = self.inner.lock().await;
        let kel_str = match inner.get_own_kel_cesr() {
            Some(res) => res.map_err(Error::SdkError)?,
            None => "KEL not found".to_string(),
        };
        Ok(kel_str)
    }

    #[napi]
    pub async fn find_state(&self, about_id: String) -> napi::Result<String> {
        let inner = self.inner.lock().await;
        let about_who: IdentifierPrefix = about_id
            .parse::<IdentifierPrefix>()
            .map_err(|e| Error::IdParsingError(e.to_string()))?;
        let state = inner.find_state(&about_who).map_err(Error::SdkError)?;
        Ok(serde_json::to_string(&state).unwrap())
    }

    #[napi]
    pub async fn get_id(&self) -> napi::Result<String> {
        let inner = self.inner.lock().await;
        Ok(inner.id().to_string())
    }

    #[napi]
    pub async fn notify_witness(&self) -> napi::Result<()> {
        let mut inner = self.inner.lock().await;
        inner.notify_witnesses().await.map_err(Error::SdkError)?;
        Ok(())
    }

    #[napi]
    pub async fn query_mailbox(&self) -> napi::Result<Vec<Buffer>> {
        let inner = self.inner.lock().await;
        let witnesses = inner.witnesses();
        let kel = inner
            .query_mailbox(inner.id(), &witnesses)
            .map_err(Error::SdkError)?;
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
            .map_err(Error::SdkError)?;

        Ok(())
    }

    #[napi]
    pub async fn rotate(&self, config: &RotationConfiguration) -> napi::Result<Buffer> {
        let curr_keys = config
            .current_public_keys
            .iter()
            .map(|k| k.parse())
            .collect::<Result<Vec<BasicPrefix>, _>>()
            .map_err(|e| Error::KeyParsingError(e.to_string()))?;
        let next_keys = config
            .next_public_keys
            .iter()
            .map(|k| k.parse())
            .collect::<Result<Vec<BasicPrefix>, _>>()
            .map_err(|e| Error::KeyParsingError(e.to_string()))?;
        let witnesses_to_add = config
            .witnesses_to_add
            .iter()
            .map(|wit| {
                serde_json::from_str::<LocationScheme>(wit)
                    .map_err(|_| Error::OobiParsingError(wit.clone()))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let witnesses_to_remove = config
            .witnesses_to_remove
            .iter()
            .map(|wit| wit.parse::<BasicPrefix>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
        let id = self.inner.lock().await;
        Ok(id
            .rotate(
                curr_keys,
                next_keys,
                1,
                witnesses_to_add,
                witnesses_to_remove,
                config.witness_threshold as u64,
            )
            .await
            .map_err(Error::SdkError)?
            .as_bytes()
            .into())
    }

    #[napi]
    pub async fn finalize_rotation(
        &self,
        rot_event: Buffer,
        signature: &Signature,
    ) -> napi::Result<()> {
        let mut id = self.inner.lock().await;

        let ssp = signature.to_prefix();
        id.finalize_rotate(&rot_event, ssp)
            .await
            .map_err(Error::SdkError)?;
        Ok(())
    }

    #[napi]
    pub async fn incept_registry(&self) -> napi::Result<RegistryInceptionData> {
        let mut id = self.inner.lock().await;
        let (registry_id, vcp) = id.incept_registry().map_err(Error::SdkError)?;

        Ok(RegistryInceptionData {
            ixn: vcp.encode().unwrap().into(),
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
            .map_err(Error::SdkError)?;

        Ok(())
    }

    #[napi]
    pub async fn issue(&self, vc: Buffer) -> napi::Result<IssuanceData> {
        let said = HashFunction::from(HashFunctionCode::Blake3_256).derive(&vc);
        let id = self.inner.lock().await;
        let (vc_hash, iss) = id.issue(said).map_err(Error::SdkError)?;

        Ok(IssuanceData {
            ixn: iss.encode().unwrap().into(),
            vc_hash: vc_hash.to_string(),
        })
    }

    #[napi]
    pub async fn finalize_issue(&self, event: Buffer, signature: &Signature) -> napi::Result<()> {
        let mut id = self.inner.lock().await;
        id.finalize_issue(&event, signature.to_prefix())
            .await
            .map_err(Error::SdkError)?;

        Ok(())
    }

    #[napi]
    pub async fn revoke(&self, vc_hash: String) -> napi::Result<Buffer> {
        let id = self.inner.lock().await;
        let ixn = id
            .revoke(
                &vc_hash
                    .parse::<SelfAddressingIdentifier>()
                    .map_err(|e| Error::HashParsingError(e.to_string()))?,
            )
            .map_err(Error::SdkError)?;

        Ok(ixn.into())
    }

    #[napi]
    pub async fn finalize_revoke(&self, event: Buffer, signature: &Signature) -> napi::Result<()> {
        let mut id = self.inner.lock().await;
        id.finalize_revoke(&event, signature.to_prefix())
            .await
            .map_err(Error::SdkError)?;

        Ok(())
    }

    #[napi]
    pub async fn notify_backers(&self) -> napi::Result<()> {
        let id = self.inner.lock().await;
        id.notify_backers().await.map_err(Error::SdkError)?;

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
            .map_err(Error::SdkError)?;
        Ok(id
            .add_watcher(watcher_id)
            .map_err(Error::SdkError)?
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
            .map_err(Error::SdkError)?;

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
        let about_id = about_id
            .parse::<IdentifierPrefix>()
            .map_err(|e| Error::IdParsingError(e.to_string()))?;
        let seal = EventSeal::new(
            about_id,
            sn.into(),
            digest
                .parse::<SelfAddressingIdentifier>()
                .map_err(|e| Error::HashParsingError(e.to_string()))?,
        );
        Ok(id
            .query_watchers(&seal)
            .map_err(Error::SdkError)?
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
            QueryResponse::Updates => true,
            QueryResponse::NoUpdates => false,
        })
    }

    #[napi]
    pub async fn query_full_kel(&self, about_id: String) -> napi::Result<Vec<Buffer>> {
        let id = self.inner.lock().await;
        let about_id = &about_id
            .parse::<IdentifierPrefix>()
            .map_err(|e| Error::IdParsingError(e.to_string()))?;
        let watchers = id.watchers().map_err(Error::SdkError)?;
        let mut qries = vec![];
        for watcher in watchers {
            let qry = id
                .query_full_log(about_id, watcher)
                .map_err(Error::SdkError)?
                .encode()
                .unwrap();
            qries.push(Buffer::from(qry));
        }
        Ok(qries)
    }

    #[napi]
    pub async fn vc_state(&self, digest: String) -> napi::Result<Option<VcState>> {
        let id = self.inner.lock().await;
        let vc_hash: SelfAddressingIdentifier = digest
            .parse::<SelfAddressingIdentifier>()
            .map_err(|e| Error::HashParsingError(e.to_string()))?;
        let out = id.find_vc_state(&vc_hash).map_err(Error::SdkError)?;

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
            .map_err(Error::SdkError)?;

        Ok(())
    }

    #[napi]
    pub async fn query_tel(&self, registry_id: String, vc_id: String) -> napi::Result<Buffer> {
        let id = self.inner.lock().await;
        let reg_id = registry_id
            .parse::<IdentifierPrefix>()
            .map_err(|e| Error::IdParsingError(e.to_string()))?;
        let vc_id = vc_id
            .parse::<IdentifierPrefix>()
            .map_err(|e| Error::IdParsingError(e.to_string()))?;
        let qry = id.query_tel(reg_id, vc_id).map_err(Error::SdkError)?;

        Ok(qry.encode().unwrap().into())
    }

    #[napi]
    pub async fn finalize_query_tel(
        &self,
        event: Buffer,
        signature: &Signature,
    ) -> napi::Result<()> {
        let id = self.inner.lock().await;
        let qry: TelQueryEvent =
            serde_json::from_slice(&event).map_err(|_| Error::EventParsingError)?;
        id.finalize_query_tel(qry, signature.to_prefix())
            .await
            .map_err(Error::SdkError)?;

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

        let witnesses = locked_id.witnesses();
        let locations = filter_locations(&witnesses);
        let witnesses_oobi = witnesses.iter().map(|cid| {
            Oobi::EndRole(EndRole {
                eid: IdentifierPrefix::Basic(cid.clone()),
                role: Role::Witness,
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
                .into_iter()
                .map(|witness| {
                    Oobi::EndRole(EndRole {
                        cid: registry_id.clone(),
                        role: Role::Witness,
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
    pub async fn sign(
        &self,
        input: String,
        signatures: Vec<&Signature>,
    ) -> napi::Result<Option<String>> {
        let locked_id = self.inner.lock().await;
        let stream = locked_id
            .sign_to_cesr(
                &input,
                &signatures
                    .into_iter()
                    .map(|s| s.to_prefix())
                    .collect::<Vec<_>>(),
            )
            .map_err(Error::SdkError)?;

        Ok(Some(stream))
    }

    #[napi]
    pub async fn verify(&self, stream: String) -> napi::Result<bool> {
        let locked_id = self.inner.lock().await;
        match locked_id.verify_from_cesr_detailed(stream.as_bytes()) {
            Ok(()) => Ok(true),
            Err(issues) => {
                if issues
                    .iter()
                    .any(|issue| matches!(issue, VerificationIssue::SignatureInvalid))
                {
                    Ok(false)
                } else {
                    Err(Error::Unexpected(
                        issues
                            .iter()
                            .map(|issue| issue.to_string())
                            .collect::<Vec<_>>()
                            .join("; "),
                    ))?
                }
            }
        }
    }
}

#[napi]
pub enum VcState {
    Issued,
    Revoked,
    NotIssued,
}
