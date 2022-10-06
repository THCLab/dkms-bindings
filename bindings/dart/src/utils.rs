use crate::api::Error;
use controller::error::ControllerError;
use keri::{
    event_parsing::{attachment::attachment, Attachment},
    prefix::{AttachedSignaturePrefix, BasicPrefix, SelfSigningPrefix},
};

pub fn parse_attachment(stream: &[u8]) -> Result<Attachment, Error> {
    attachment(stream)
        .map_err(|_e| Error::KelError(ControllerError::AttachmentParseError))
        .map(|(_rest, att)| att)
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
