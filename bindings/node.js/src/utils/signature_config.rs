use cesrox::primitives::codes::self_signing::SelfSigning;
use keri_controller::CesrPrimitive;
use keri_controller::SelfSigningPrefix;
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
pub struct Signature {
    pub prefix: String,
}
#[napi]
impl Signature {
    #[napi(constructor)]
    pub fn new(algorithm: SignatureType, signature: Buffer) -> Self {
        let d: SelfSigning = algorithm.into();
        let ss = SelfSigningPrefix::new(d, signature.to_vec());
        Self {
            prefix: ss.to_str(),
        }
    }

    pub fn to_prefix(&self) -> keri_controller::SelfSigningPrefix {
        self.prefix.parse().unwrap()
    }
}
