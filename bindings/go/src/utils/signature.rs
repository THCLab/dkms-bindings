use crate::error::Error;
use cesrox::primitives::codes::self_signing::SelfSigning;
use keri_sdk::advanced::{CesrPrimitive, SelfSigningPrefix};

#[derive(Debug, Clone, Copy)]
pub enum SignatureType {
    Ed25519Sha512 = 0,
    ECDSAsecp256k1Sha256 = 1,
    Ed448 = 2,
}

impl From<u32> for SignatureType {
    fn from(value: u32) -> Self {
        match value {
            0 => SignatureType::Ed25519Sha512,
            1 => SignatureType::ECDSAsecp256k1Sha256,
            2 => SignatureType::Ed448,
            _ => SignatureType::Ed25519Sha512, // default
        }
    }
}

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
            // NIST P-256 ECDSA has no dedicated SignatureType; report it as the
            // nearest ECDSA option (convenience reverse mapping only).
            SelfSigning::ECDSA256r1Sha256 => SignatureType::ECDSAsecp256k1Sha256,
        }
    }
}

pub struct Signature {
    prefix: String,
}

impl Signature {
    pub fn new(algorithm: u32, signature: Vec<u8>) -> Result<Self, Error> {
        let sig_type: SignatureType = algorithm.into();
        let d: SelfSigning = sig_type.into();
        let ss = SelfSigningPrefix::new(d, signature);
        Ok(Self {
            prefix: ss.to_str(),
        })
    }

    pub fn from_string(prefix: &str) -> Result<Self, Error> {
        // Validate that it's a valid prefix
        let _: SelfSigningPrefix = prefix
            .parse()
            .map_err(|e| Error::SignatureParsingError(format!("{e}")))?;
        Ok(Self {
            prefix: prefix.to_string(),
        })
    }

    pub fn to_string(&self) -> String {
        self.prefix.clone()
    }

    pub fn to_prefix(&self) -> SelfSigningPrefix {
        self.prefix.parse().unwrap()
    }
}
