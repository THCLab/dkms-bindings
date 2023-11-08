use crate::api::{Digest, Error, PublicKey, Signature};
use controller::Oobi;
use keri::prefix::CesrPrimitive;
pub use keri::{
    oobi::LocationScheme,
    prefix::{BasicPrefix, IndexedSignature, SelfSigningPrefix},
};
use said::SelfAddressingIdentifier;

pub fn parse_location_schemes(location_str: &str) -> Result<LocationScheme, Error> {
    serde_json::from_str::<LocationScheme>(location_str)
        .map_err(|_| Error::OobiParseError(location_str.into()))
}

pub fn parse_oobi(location_str: &str) -> Result<Oobi, Error> {
    serde_json::from_str::<Oobi>(location_str)
        .map_err(|_| Error::OobiParseError(location_str.into()))
}

pub fn parse_witness_prefix(wit_str: &str) -> Result<BasicPrefix, Error> {
    let parsed_prefix = wit_str
        .parse::<BasicPrefix>()
        .map_err(|_| Error::IdentifierParseError("Can't parse witness prefix".into()))?;
    if !parsed_prefix.is_transferable() {
        Ok(parsed_prefix)
    } else {
        Err(Error::IdentifierParseError(
            "Witness identifier must be nontransferable".into(),
        ))
    }
}

impl From<Signature> for SelfSigningPrefix {
    fn from(val: Signature) -> Self {
        SelfSigningPrefix::new(val.derivation, val.signature)
    }
}

impl From<Digest> for SelfAddressingIdentifier {
    fn from(val: Digest) -> Self {
        SelfAddressingIdentifier::new(val.derivation.into(), val.digest)
    }
}

impl From<PublicKey> for BasicPrefix {
    fn from(val: PublicKey) -> Self {
        BasicPrefix::new(val.derivation, keri::keys::PublicKey::new(val.public_key))
    }
}

impl From<SelfSigningPrefix> for Signature {
    fn from(ssp: SelfSigningPrefix) -> Self {
        Signature {
            derivation: ssp.get_code(),
            signature: ssp.derivative(),
        }
    }
}

#[test]
pub fn test_parse_witness_prefix() -> Result<(), Error> {
    let witness_id = "BKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ";
    let wrong_witness_id = "DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ";
    let id = parse_witness_prefix(witness_id);
    let wrong_id = parse_witness_prefix(wrong_witness_id);
    assert!(id.is_ok());
    assert!(wrong_id.is_err());
    assert!(matches!(wrong_id, Err(Error::IdentifierParseError(_))));

    Ok(())
}
