use keri::{
    derivation::{basic::Basic, self_signing::SelfSigning},
    event_parsing::attachment::attachment,
    keys::PublicKey as KeriPK,
    prefix::{AttachedSignaturePrefix, BasicPrefix, SelfSigningPrefix},
    processor::event_storage::EventStorage,
};

use crate::kel::KelError;

pub fn key_prefix_from_b64(key: &str, derivation: Basic) -> Result<BasicPrefix, KelError> {
    let key = KeriPK::new(base64::decode(key)?);
    Ok(derivation.derive(key))
}

pub fn signature_prefix_from_b64(
    sig: &str,
    derivation: SelfSigning,
) -> Result<SelfSigningPrefix, KelError> {
    let sig = base64::decode(sig).unwrap();
    Ok(derivation.derive(sig))
}

pub fn signature_prefix_from_hex(
    sig_hex: &str,
    derivation: SelfSigning,
) -> Result<SelfSigningPrefix, KelError> {
    let sig = hex::decode(sig_hex)?;
    Ok(derivation.derive(sig))
}

// helper functions for parsing attached signatures
fn join_keys_and_signatures(
    current_keys: Vec<BasicPrefix>,
    signatures: &[AttachedSignaturePrefix],
) -> Result<Vec<(BasicPrefix, SelfSigningPrefix)>, KelError> {
    let ss: Result<Vec<(_, _)>, KelError> = signatures
        .iter()
        .map(|s| -> Result<_, _> {
            Ok((
                current_keys
                    .get(s.index as usize)
                    .ok_or_else(|| KelError::GeneralError("Missing signature index".into()))?
                    .to_owned(),
                s.signature.clone(),
            ))
        })
        .collect();
    ss
}

pub fn get_current_public_key(
    storage: EventStorage,
    stream: &str,
) -> Result<Vec<(BasicPrefix, SelfSigningPrefix)>, KelError> {
    let (_rest, att1) =
        attachment(stream.as_bytes()).map_err(|e| KelError::ParseEventError(e.to_string()))?;
    if let keri::event_parsing::Attachment::SealSignaturesGroups(group) = att1 {
        let r = group
            .iter()
            .map(|(seal, signatures)| -> Result<Vec<_>, KelError> {
                // let event = storage
                //     .get_event_at_sn(&seal.prefix, seal.sn)?
                //     .ok_or_else(|| KelError::MissingEventError)?;
                // //check digests
                // if event.signed_event_message.event_message.event.get_digest()
                //     != seal.event_digest
                // {
                //     return Err(KelError::GeneralError("Event digests doesn't match".into()));
                // };
                let current_keys = storage
                    .compute_state_at_sn(&seal.prefix, seal.sn)?
                    .ok_or_else(|| KelError::GeneralError("No state".into()))?
                    .current
                    .public_keys;
                join_keys_and_signatures(current_keys, signatures)
            })
            .collect::<Result<Vec<_>, KelError>>();
        Ok(r.into_iter()
            .flatten()
            .flatten()
            .collect::<Vec<(BasicPrefix, SelfSigningPrefix)>>())

        // r
    } else {
        Err(KelError::GeneralError("Wrong attachment".into()))
    }
}
