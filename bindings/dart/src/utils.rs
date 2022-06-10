use keriox_wrapper::kel::{
    AttachedSignaturePrefix, Basic, BasicPrefix, PublicKey as KeriPK, SelfSigning,
    SelfSigningPrefix,
};

use crate::api::Error;

pub fn key_prefix_from_b64(key: &str, derivation: Basic) -> Result<BasicPrefix, Error> {
    let key = KeriPK::new(base64::decode(key)?);
    Ok(derivation.derive(key))
}

pub fn signature_prefix_from_b64(
    sig: &str,
    derivation: SelfSigning,
) -> Result<SelfSigningPrefix, Error> {
    let sig = base64::decode(sig).unwrap();
    Ok(derivation.derive(sig))
}

pub fn signature_prefix_from_hex(
    sig_hex: &str,
    derivation: SelfSigning,
) -> Result<SelfSigningPrefix, Error> {
    let sig = hex::decode(sig_hex)?;
    Ok(derivation.derive(sig))
}

// helper functions for parsing attached signatures
pub fn join_keys_and_signatures(
    current_keys: Vec<BasicPrefix>,
    signatures: &[AttachedSignaturePrefix],
) -> Result<Vec<(BasicPrefix, SelfSigningPrefix)>, Error> {
    signatures
        .iter()
        .map(|s| -> Result<_, _> {
            Ok((
                current_keys
                    .get(s.index as usize)
                    .ok_or_else(|| Error::UtilsError("Missing signature index".into()))?
                    .to_owned(),
                s.signature.clone(),
            ))
        })
        .collect()
}
