use crate::error::Error;
use crate::rotation_configuration::RotationConfiguration;
use keri_controller::{
    controller::PostgresIdentifier, BasicPrefix, IdentifierPrefix, LocationScheme, Oobi,
};
use keri_core::{actor::prelude::Message, event::sections::seal::EventSeal};

pub struct Identifier {
    pub inner: PostgresIdentifier,
}

impl Identifier {
    pub fn get_kel(&self) -> Result<String, Error> {
        let kel = self.inner.get_own_kel();
        let kel_str = match kel {
            Some(kel) => kel
                .into_iter()
                .map(|event| String::from_utf8(Message::Notice(event).to_cesr().unwrap()).unwrap())
                .fold(String::new(), |a, b| a + &b + "\n"),
            None => "KEL not found".to_string(),
        };
        Ok(kel_str)
    }

    pub fn find_state(&self, about_id: &str) -> Result<String, Error> {
        let about_who: IdentifierPrefix = about_id.parse().map_err(Error::IdParsingError)?;
        let state = self
            .inner
            .find_state(&about_who)
            .map_err(Error::MechanicError)?;
        Ok(serde_json::to_string(&state).unwrap())
    }

    pub async fn rotate(&self, config: &RotationConfiguration) -> Result<Vec<u8>, Error> {
        let curr_keys = config
            .current_public_keys
            .iter()
            .map(|k| k.parse())
            .collect::<Result<Vec<BasicPrefix>, _>>()
            .map_err(Error::KeyParsingError)?;

        let next_keys = config
            .next_public_keys
            .iter()
            .map(|k| k.parse())
            .collect::<Result<Vec<_>, _>>()
            .map_err(Error::KeyParsingError)?;

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
            .map_err(Error::KeyParsingError)?;

        let rot = self
            .inner
            .rotate(
                curr_keys,
                next_keys,
                1,
                witnesses_to_add,
                witnesses_to_remove,
                config.witness_threshold as u64,
            )
            .await
            .map_err(Error::MechanicError)?;

        Ok(rot.as_bytes().to_vec())
    }

    pub async fn finalize_rotation(
        &mut self,
        rot_event: &[u8],
        signature: &keri_controller::SelfSigningPrefix,
    ) -> Result<(), Error> {
        self.inner
            .finalize_rotate(rot_event, signature.clone())
            .await
            .map_err(Error::MechanicError)?;
        Ok(())
    }

    pub async fn notify_witnesses(&mut self) -> Result<(), Error> {
        self.inner
            .notify_witnesses()
            .await
            .map_err(Error::MechanicError)?;
        Ok(())
    }

    pub async fn query_mailbox(&self) -> Result<Vec<Vec<u8>>, Error> {
        let id = self.inner.id();
        let witnesses = self.inner.witnesses().collect::<Vec<_>>();
        let kel = self
            .inner
            .query_mailbox(id, &witnesses)
            .map_err(Error::ControllerError)?;
        let kel_bytes = kel
            .into_iter()
            .map(|event| event.encode().map_err(|e| Error::Unexpected(e.to_string())))
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(kel_bytes)
    }

    pub async fn finalize_query_mailbox(
        &mut self,
        queries: Vec<Vec<u8>>,
        signatures: Vec<keri_controller::SelfSigningPrefix>,
    ) -> Result<(), Error> {
        let qries_and_sigs = queries
            .into_iter()
            .zip(signatures)
            .map(|(qry, sig)| {
                Ok((
                    serde_json::from_slice(&qry).map_err(|_| Error::EventParsingError)?,
                    sig,
                ))
            })
            .collect::<Result<Vec<_>, Error>>()?;

        self.inner
            .finalize_query_mailbox(qries_and_sigs)
            .await
            .map_err(Error::ControllerError)?;

        Ok(())
    }

    pub async fn incept_registry(&mut self) -> Result<(String, Vec<u8>), Error> {
        let (registry_id, vcp) = self
            .inner
            .incept_registry()
            .map_err(Error::ControllerError)?;

        Ok((registry_id.to_string(), vcp.encode().unwrap()))
    }

    pub async fn finalize_incept_registry(
        &mut self,
        event: &[u8],
        signature: keri_controller::SelfSigningPrefix,
    ) -> Result<(), Error> {
        self.inner
            .finalize_incept_registry(event, signature)
            .await
            .map_err(Error::MechanicError)?;

        Ok(())
    }

    pub fn issue(&self, vc: &[u8]) -> Result<(String, Vec<u8>), Error> {
        use said::derivation::{HashFunction, HashFunctionCode};
        let said = HashFunction::from(HashFunctionCode::Blake3_256).derive(vc);
        let (vc_hash, iss) = self.inner.issue(said).map_err(Error::ControllerError)?;

        Ok((vc_hash.to_string(), iss.encode().unwrap()))
    }

    pub async fn finalize_issue(
        &mut self,
        event: &[u8],
        signature: keri_controller::SelfSigningPrefix,
    ) -> Result<(), Error> {
        self.inner
            .finalize_issue(event, signature)
            .await
            .map_err(Error::MechanicError)?;

        Ok(())
    }

    pub fn revoke(&self, vc_hash: &str) -> Result<Vec<u8>, Error> {
        let ixn = self
            .inner
            .revoke(&vc_hash.parse().map_err(Error::HashParsingError)?)
            .map_err(Error::ControllerError)?;

        Ok(ixn)
    }

    pub async fn finalize_revoke(
        &mut self,
        event: &[u8],
        signature: keri_controller::SelfSigningPrefix,
    ) -> Result<(), Error> {
        self.inner
            .finalize_revoke(event, signature)
            .await
            .map_err(Error::MechanicError)?;

        Ok(())
    }

    pub async fn notify_backers(&self) -> Result<(), Error> {
        self.inner
            .notify_backers()
            .await
            .map_err(Error::MechanicError)?;

        Ok(())
    }

    pub async fn add_watcher(&self, watcher_oobi: &str) -> Result<Vec<u8>, Error> {
        let oobi: LocationScheme = serde_json::from_str(watcher_oobi)
            .map_err(|_| Error::OobiParsingError(watcher_oobi.to_string()))?;

        let watcher_id = oobi.eid.clone();

        self.inner
            .resolve_oobi(&Oobi::Location(oobi))
            .await
            .map_err(Error::MechanicError)?;

        Ok(self
            .inner
            .add_watcher(watcher_id)
            .map_err(Error::MechanicError)?
            .as_bytes()
            .to_vec())
    }

    pub async fn finalize_add_watcher(
        &self,
        event: &[u8],
        signature: keri_controller::SelfSigningPrefix,
    ) -> Result<(), Error> {
        self.inner
            .finalize_add_watcher(event, signature)
            .await
            .map_err(Error::MechanicError)?;

        Ok(())
    }

    pub fn query_kel(&self, about_id: &str, sn: u32, digest: &str) -> Result<Vec<Vec<u8>>, Error> {
        let about_id = about_id.parse().map_err(Error::IdParsingError)?;
        let seal = EventSeal::new(
            about_id,
            sn.into(),
            digest.parse().map_err(Error::HashParsingError)?,
        );
        Ok(self
            .inner
            .query_watchers(&seal)
            .map_err(Error::ControllerError)?
            .into_iter()
            .map(|qry| qry.encode().map_err(|e| Error::Unexpected(e.to_string())))
            .collect::<Result<Vec<_>, Error>>()?)
    }

    pub async fn finalize_query_kel(
        &self,
        queries: Vec<Vec<u8>>,
        signatures: Vec<keri_controller::SelfSigningPrefix>,
    ) -> Result<bool, Error> {
        let qries_and_sigs = queries
            .into_iter()
            .zip(signatures)
            .map(|(qry, sig)| {
                Ok((
                    serde_json::from_slice(&qry).map_err(|_| Error::EventParsingError)?,
                    sig,
                ))
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let (res, _err) = self.inner.finalize_query(qries_and_sigs).await;

        Ok(matches!(
            res,
            keri_controller::identifier::query::QueryResponse::Updates
        ))
    }

    pub fn query_full_kel(&self, about_id: &str) -> Result<Vec<Vec<u8>>, Error> {
        let about_id = &about_id.parse().map_err(Error::IdParsingError)?;
        let watchers = self.inner.watchers().map_err(Error::ControllerError)?;
        let mut qries = vec![];
        for watcher in watchers {
            let qry = self
                .inner
                .query_full_log(about_id, watcher)
                .map_err(Error::ControllerError)?
                .encode()
                .unwrap();
            qries.push(qry);
        }
        Ok(qries)
    }

    pub fn vc_state(&self, digest: &str) -> Result<Option<VcState>, Error> {
        use keri_controller::TelState;
        use said::SelfAddressingIdentifier;

        let vc_hash: SelfAddressingIdentifier = digest.parse().map_err(Error::HashParsingError)?;
        let out = self
            .inner
            .find_vc_state(&vc_hash)
            .map_err(Error::ControllerError)?;

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
            .map_err(Error::ControllerError)?;

        Ok(())
    }

    pub fn query_tel(&self, registry_id: &str, vc_id: &str) -> Result<Vec<u8>, Error> {
        let reg_id = registry_id.parse().map_err(Error::IdParsingError)?;
        let vc_id = vc_id.parse().map_err(Error::IdParsingError)?;
        let qry = self
            .inner
            .query_tel(reg_id, vc_id)
            .map_err(Error::ControllerError)?;

        Ok(qry.encode().unwrap())
    }

    pub async fn finalize_query_tel(
        &self,
        event: &[u8],
        signature: keri_controller::SelfSigningPrefix,
    ) -> Result<(), Error> {
        let qry: teliox::query::TelQueryEvent =
            serde_json::from_slice(event).map_err(|_| Error::EventParsingError)?;
        self.inner
            .finalize_query_tel(qry, signature)
            .await
            .map_err(Error::MechanicError)?;

        Ok(())
    }

    pub fn oobi(&self) -> Result<Vec<String>, Error> {
        use keri_core::oobi::Role;

        let filter_locations = |identifiers: &[BasicPrefix]| -> Vec<Oobi> {
            identifiers
                .iter()
                .flat_map(|id| {
                    self.inner
                        .get_location(&IdentifierPrefix::Basic(id.clone()))
                        .unwrap()
                })
                .map(Oobi::Location)
                .collect()
        };

        let witnesses = self.inner.witnesses().collect::<Vec<_>>();
        let locations = filter_locations(&witnesses);
        let witnesses_oobi = witnesses.iter().map(|cid| {
            Oobi::EndRole(keri_controller::EndRole {
                eid: IdentifierPrefix::Basic(cid.clone()),
                role: Role::Witness,
                cid: self.inner.id().clone(),
            })
        });
        let oobis: Vec<String> = locations
            .into_iter()
            .chain(witnesses_oobi)
            .map(|oobi| serde_json::to_string(&oobi).unwrap())
            .collect();
        Ok(oobis)
    }

    pub fn registry_id_oobi(&self) -> Option<Vec<String>> {
        use keri_core::oobi::Role;

        self.inner.registry_id().map(|registry_id| {
            self.inner
                .witnesses()
                .map(|witness| {
                    Oobi::EndRole(keri_controller::EndRole {
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
        signature: &keri_controller::SelfSigningPrefix,
    ) -> Result<Option<String>, Error> {
        let stream = self
            .inner
            .sign_to_cesr(input, &vec![signature.clone()])
            .map_err(Error::ControllerError)?;

        Ok(Some(stream))
    }

    pub async fn verify(&self, stream: &str) -> Result<bool, Error> {
        use keri_controller::error::ControllerError;
        use keri_core::processor::validator::VerificationError;

        let verification_result = self.inner.verify_from_cesr(stream.as_bytes());
        match verification_result {
            Ok(_) => Ok(true),
            Err(ControllerError::FaultySignature) => Ok(false),
            Err(ControllerError::VerificationError(errors)) => {
                if errors
                    .iter()
                    .any(|(reason, _)| matches!(reason, VerificationError::VerificationFailure))
                {
                    Ok(false)
                } else {
                    Err(Error::ControllerError(
                        keri_controller::error::ControllerError::VerificationError(errors),
                    ))
                }
            }
            Err(e) => Err(Error::ControllerError(e)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum VcState {
    Issued,
    Revoked,
    NotIssued,
}
