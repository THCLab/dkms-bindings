use keri::{
    derivation::self_signing::SelfSigning,
    prefix::{Prefix, SelfSigningPrefix},
};
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

use crate::SignatureType;

impl Into<SelfSigning> for SignatureType {
    fn into(self) -> SelfSigning {
        match self {
            SignatureType::Ed25519Sha512 => SelfSigning::Ed25519Sha512,
            SignatureType::ECDSAsecp256k1Sha256 => SelfSigning::ECDSAsecp256k1Sha256,
            SignatureType::Ed448 => SelfSigning::Ed448,
        }
    }
}

impl From<SelfSigning> for SignatureType {
    fn from(sd: SelfSigning) -> Self {
        match sd {
            SelfSigning::Ed25519Sha512 => SignatureType::Ed25519Sha512,
            SelfSigning::ECDSAsecp256k1Sha256 => SignatureType::ECDSAsecp256k1Sha256,
            SelfSigning::Ed448 => SignatureType::Ed448,
        }
    }
}

#[napi]
pub struct SignatureBuilder {
    pub prefix: String,
}
#[napi]
impl SignatureBuilder {
    #[napi(constructor)]
    pub fn new(algorithm: SignatureType, signature: Buffer) -> Self {
        let d: SelfSigning = algorithm.into();
        let pref = d.derive(signature.to_vec());
        Self {
            prefix: pref.to_str(),
        }
    }

    #[napi]
    pub fn get_signature(&self) -> Signature {
        Signature {
            p: self.prefix.clone(),
        }
    }
}

#[napi(object)]
pub struct Signature {
    pub p: String,
}

impl Signature {
    pub fn to_prefix(&self) -> SelfSigningPrefix {
        self.p.parse().unwrap()
    }
}
