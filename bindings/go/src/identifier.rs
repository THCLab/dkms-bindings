use crate::error::Error;
use crate::rotation_configuration::RotationConfiguration;
// All KERI/SAID types come from keri-sdk's re-exports so they unify with the
// SDK's own said (0.5.x) — NOT this crate's direct `said` (0.4.x, used only by
// acdc_build).
use keri_sdk::advanced::raw::keri_core::event::event_data::EventData;
use keri_sdk::advanced::raw::keri_core::event::sections::seal::{DigestSeal, Seal};
use keri_sdk::advanced::raw::keri_core::event_message::signed_event_message::Notice;
use keri_sdk::advanced::raw::keri_core::query::{mailbox::MailboxQuery, query_event::QueryEvent};
use keri_sdk::advanced::{
    BasicPrefix, EndRole, HashFunction, HashFunctionCode, Identifier as SdkIdentifier,
    IdentifierPrefix, LocationScheme, Oobi, QueryResponse, Role, SelfAddressingIdentifier,
    SelfSigningPrefix, TelQueryEvent, TelState, VerificationIssue,
};

fn sdk_err<E: std::fmt::Display>(e: E) -> Error {
    Error::Sdk(e.to_string())
}

pub struct Identifier {
    pub inner: SdkIdentifier,
}

impl Identifier {
    pub fn get_kel(&self) -> Result<String, Error> {
        match self.inner.get_own_kel_cesr() {
            Some(Ok(kel)) => Ok(kel),
            Some(Err(e)) => Err(sdk_err(e)),
            None => Ok("KEL not found".to_string()),
        }
    }

    pub async fn rotate(&self, config: &RotationConfiguration) -> Result<Vec<u8>, Error> {
        let curr_keys = config
            .current_public_keys
            .iter()
            .map(|k| k.parse())
            .collect::<Result<Vec<BasicPrefix>, _>>()
            .map_err(|e| Error::KeyParsingError(format!("{e}")))?;

        let next_keys = config
            .next_public_keys
            .iter()
            .map(|k| k.parse())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Error::KeyParsingError(format!("{e}")))?;

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
            .map_err(|e| Error::KeyParsingError(format!("{e}")))?;

        let rot = self
            .inner
            .rotate(
                curr_keys,
                next_keys,
                // new_next_threshold — the SDK makes this explicit; the
                // single-key default matches the previous behaviour.
                1,
                witnesses_to_add,
                witnesses_to_remove,
                config.witness_threshold as u64,
            )
            .await
            .map_err(sdk_err)?;

        Ok(rot.as_bytes().to_vec())
    }

    pub async fn finalize_rotation(
        &mut self,
        rot_event: &[u8],
        signature: &SelfSigningPrefix,
    ) -> Result<(), Error> {
        self.inner
            .finalize_rotate(rot_event, signature.clone())
            .await
            .map_err(sdk_err)
    }

    pub async fn notify_witnesses(&mut self) -> Result<(), Error> {
        // The SDK returns the number of events sent; the FFI contract only
        // cares about success.
        self.inner.notify_witnesses().await.map_err(sdk_err)?;
        Ok(())
    }

    pub async fn query_mailbox(&self) -> Result<Vec<Vec<u8>>, Error> {
        let id = self.inner.id().clone();
        let witnesses = self.inner.witnesses();
        let queries = self
            .inner
            .query_mailbox(&id, &witnesses)
            .map_err(sdk_err)?;
        queries
            .into_iter()
            .map(|q| q.encode().map_err(sdk_err))
            .collect()
    }

    pub async fn finalize_query_mailbox(
        &mut self,
        queries: Vec<Vec<u8>>,
        signatures: Vec<SelfSigningPrefix>,
    ) -> Result<(), Error> {
        let qries_and_sigs = queries
            .into_iter()
            .zip(signatures)
            .map(|(qry, sig)| {
                let parsed: MailboxQuery =
                    serde_json::from_slice(&qry).map_err(|_| Error::EventParsingError)?;
                Ok((parsed, sig))
            })
            .collect::<Result<Vec<_>, Error>>()?;

        self.inner
            .finalize_query_mailbox(qries_and_sigs)
            .await
            .map_err(sdk_err)?;
        Ok(())
    }

    pub async fn incept_registry(&mut self) -> Result<(String, Vec<u8>), Error> {
        let (registry_id, vcp) = self.inner.incept_registry().map_err(sdk_err)?;
        Ok((registry_id.to_string(), vcp.encode().map_err(sdk_err)?))
    }

    pub async fn finalize_incept_registry(
        &mut self,
        event: &[u8],
        signature: SelfSigningPrefix,
    ) -> Result<(), Error> {
        self.inner
            .finalize_incept_registry(event, signature)
            .await
            .map_err(sdk_err)
    }

    pub fn issue(&self, vc: &[u8]) -> Result<(String, Vec<u8>), Error> {
        let said = HashFunction::from(HashFunctionCode::Blake3_256).derive(vc);
        let (vc_id, iss) = self.inner.issue(said).map_err(sdk_err)?;
        Ok((vc_id.to_string(), iss.encode().map_err(sdk_err)?))
    }

    pub async fn finalize_issue(
        &mut self,
        event: &[u8],
        signature: SelfSigningPrefix,
    ) -> Result<(), Error> {
        self.inner
            .finalize_issue(event, signature)
            .await
            .map_err(sdk_err)
    }

    pub fn revoke(&self, vc_hash: &str) -> Result<Vec<u8>, Error> {
        let sai: SelfAddressingIdentifier = vc_hash.parse().map_err(|e| Error::HashParsingError(format!("{e}")))?;
        self.inner.revoke(&sai).map_err(sdk_err)
    }

    pub async fn finalize_revoke(
        &mut self,
        event: &[u8],
        signature: SelfSigningPrefix,
    ) -> Result<(), Error> {
        self.inner
            .finalize_revoke(event, signature)
            .await
            .map_err(sdk_err)
    }

    pub async fn notify_backers(&self) -> Result<(), Error> {
        self.inner.notify_backers().await.map_err(sdk_err)
    }

    pub async fn add_watcher(&self, watcher_oobi: &str) -> Result<Vec<u8>, Error> {
        let oobi: LocationScheme = serde_json::from_str(watcher_oobi)
            .map_err(|_| Error::OobiParsingError(watcher_oobi.to_string()))?;

        let watcher_id = oobi.eid.clone();

        self.inner
            .resolve_oobi(&Oobi::Location(oobi))
            .await
            .map_err(sdk_err)?;

        Ok(self
            .inner
            .add_watcher(watcher_id)
            .map_err(sdk_err)?
            .as_bytes()
            .to_vec())
    }

    pub async fn finalize_add_watcher(
        &self,
        event: &[u8],
        signature: SelfSigningPrefix,
    ) -> Result<(), Error> {
        self.inner
            .finalize_add_watcher(event, signature)
            .await
            .map_err(sdk_err)
    }

    pub async fn finalize_query_kel(
        &self,
        queries: Vec<Vec<u8>>,
        signatures: Vec<SelfSigningPrefix>,
    ) -> Result<bool, Error> {
        let qries_and_sigs = queries
            .into_iter()
            .zip(signatures)
            .map(|(qry, sig)| {
                let parsed: QueryEvent =
                    serde_json::from_slice(&qry).map_err(|_| Error::EventParsingError)?;
                Ok((parsed, sig))
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let (res, _err) = self.inner.finalize_query(qries_and_sigs).await;

        Ok(matches!(res, QueryResponse::Updates))
    }

    pub fn query_full_kel(&self, about_id: &str) -> Result<Vec<Vec<u8>>, Error> {
        let about_id: IdentifierPrefix = about_id.parse().map_err(|e| Error::IdParsingError(format!("{e}")))?;
        let watchers = self.inner.watchers().map_err(sdk_err)?;
        let mut qries = vec![];
        for watcher in watchers {
            let qry = self
                .inner
                .query_full_log(&about_id, watcher)
                .map_err(sdk_err)?
                .encode()
                .map_err(sdk_err)?;
            qries.push(qry);
        }
        Ok(qries)
    }

    pub fn vc_state(&self, digest: &str) -> Result<Option<VcState>, Error> {
        let vc_hash: SelfAddressingIdentifier = digest.parse().map_err(|e| Error::HashParsingError(format!("{e}")))?;
        let out = self.inner.find_vc_state(&vc_hash).map_err(sdk_err)?;

        Ok(out.map(|st| match st {
            TelState::Issued(_) => VcState::Issued,
            TelState::Revoked => VcState::Revoked,
            TelState::NotIssued => VcState::NotIssued,
        }))
    }

    pub async fn send_oobi_to_watcher(&self, oobi: &str) -> Result<(), Error> {
        let oobi: Oobi =
            serde_json::from_str(oobi).map_err(|_| Error::OobiParsingError(oobi.to_string()))?;
        self.inner
            .send_oobi_to_watcher(self.inner.id(), &oobi)
            .await
            .map_err(sdk_err)
    }

    pub fn query_tel(&self, registry_id: &str, vc_id: &str) -> Result<Vec<u8>, Error> {
        let reg_id: IdentifierPrefix = registry_id.parse().map_err(|e| Error::IdParsingError(format!("{e}")))?;
        let vc_id: IdentifierPrefix = vc_id.parse().map_err(|e| Error::IdParsingError(format!("{e}")))?;
        let qry = self.inner.query_tel(reg_id, vc_id).map_err(sdk_err)?;
        qry.encode().map_err(sdk_err)
    }

    pub async fn finalize_query_tel(
        &self,
        event: &[u8],
        signature: SelfSigningPrefix,
    ) -> Result<(), Error> {
        let qry: TelQueryEvent =
            serde_json::from_slice(event).map_err(|_| Error::EventParsingError)?;
        self.inner
            .finalize_query_tel(qry, signature)
            .await
            .map_err(sdk_err)
    }

    pub fn oobi(&self) -> Result<Vec<String>, Error> {
        let witnesses = self.inner.witnesses();

        let mut oobis: Vec<String> = vec![];
        for witness in &witnesses {
            let locations = self
                .inner
                .get_location(&IdentifierPrefix::Basic(witness.clone()))
                .map_err(sdk_err)?;
            for location in locations {
                oobis.push(serde_json::to_string(&Oobi::Location(location)).unwrap());
            }
        }
        for witness in &witnesses {
            let end_role = Oobi::EndRole(EndRole {
                eid: IdentifierPrefix::Basic(witness.clone()),
                role: Role::Witness,
                cid: self.inner.id().clone(),
            });
            oobis.push(serde_json::to_string(&end_role).unwrap());
        }
        Ok(oobis)
    }

    pub fn registry_id_oobi(&self) -> Option<Vec<String>> {
        self.inner.registry_id().map(|registry_id| {
            self.inner
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
        })
    }

    pub fn registry_id(&self) -> Option<String> {
        self.inner.registry_id().map(|id| id.to_string())
    }

    pub async fn sign(
        &self,
        input: &str,
        signature: &SelfSigningPrefix,
    ) -> Result<Option<String>, Error> {
        let stream = self
            .inner
            .sign_to_cesr(input, &[signature.clone()])
            .map_err(sdk_err)?;
        Ok(Some(stream))
    }

    pub async fn verify(&self, stream: &str) -> Result<bool, Error> {
        match self.inner.verify_from_cesr_detailed(stream.as_bytes()) {
            Ok(()) => Ok(true),
            Err(issues) => {
                if issues
                    .iter()
                    .any(|issue| matches!(issue, VerificationIssue::SignatureInvalid))
                {
                    Ok(false)
                } else {
                    Err(Error::Unexpected(format!("{:?}", issues)))
                }
            }
        }
    }

    /// generate an interaction (`ixn`) event that anchors the digest (SAID) of
    /// `payload` into the KEL. Returns the unsigned event bytes to be signed.
    ///
    /// Only the Blake3-256 digest is committed to the KEL — never the payload
    /// itself. Verification is byte-exact, so callers must anchor and later
    /// verify the same canonical bytes.
    pub fn anchor(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let said = HashFunction::from(HashFunctionCode::Blake3_256).derive(payload);
        let ixn = self.inner.anchor(&[said]).map_err(sdk_err)?;
        Ok(ixn.into_bytes())
    }

    /// finalize an anchor (interaction) event (sign + save + queue for witness
    /// notification).
    pub async fn finalize_anchor(
        &mut self,
        event: &[u8],
        signature: SelfSigningPrefix,
    ) -> Result<(), Error> {
        self.inner
            .finalize_anchor(event, signature)
            .await
            .map_err(sdk_err)
    }

    /// report whether the digest (SAID) of `payload` has been anchored in one
    /// of the identifier's interaction events.
    ///
    /// This inspects the identifier's *accepted* KEL — events that have
    /// gathered the required witness receipts. For an identifier with a
    /// non-zero witness threshold, an anchor becomes visible here only after
    /// `finalize_anchor` **and** witness notification + receipt collection;
    /// until then the `ixn` sits in partially-witnessed escrow. A `false`
    /// result therefore means "not present in the accepted KEL", which for a
    /// witnessed identifier can mean "not yet witnessed" rather than "never
    /// anchored". An identifier with no accepted KEL at all returns an error
    /// (not `false`), so the caller can distinguish "unknown" from "absent".
    pub fn verify_anchor(&self, payload: &[u8]) -> Result<bool, Error> {
        let said = HashFunction::from(HashFunctionCode::Blake3_256).derive(payload);
        let target = Seal::Digest(DigestSeal::new(said));

        let kel = self
            .inner
            .get_own_kel()
            .ok_or_else(|| Error::Unexpected("identifier has no accepted KEL".to_string()))?;
        for notice in kel {
            if let Notice::Event(sem) = notice {
                if let EventData::Ixn(ixn) = sem.event_message.data.get_event_data() {
                    if ixn.data.iter().any(|seal| *seal == target) {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum VcState {
    Issued,
    Revoked,
    NotIssued,
}
