use crate::error::Error;
use cesrox::primitives::codes::basic::Basic;
use keri_sdk::advanced::raw::keri_core::keys::PublicKey as KeriPublicKey;
use keri_sdk::advanced::{BasicPrefix, CesrPrimitive};

#[derive(Debug, Clone, Copy)]
pub enum KeyType {
    ECDSAsecp256k1 = 0,
    Ed25519 = 1,
    Ed448 = 2,
    X25519 = 3,
    X448 = 4,
}

impl From<u32> for KeyType {
    fn from(value: u32) -> Self {
        match value {
            0 => KeyType::ECDSAsecp256k1,
            1 => KeyType::Ed25519,
            2 => KeyType::Ed448,
            3 => KeyType::X25519,
            4 => KeyType::X448,
            _ => KeyType::Ed25519, // default
        }
    }
}

impl Into<Basic> for KeyType {
    fn into(self) -> Basic {
        match self {
            KeyType::ECDSAsecp256k1 => Basic::ECDSAsecp256k1Nontrans,
            KeyType::Ed25519 => Basic::Ed25519Nontrans,
            KeyType::Ed448 => Basic::Ed448Nontrans,
            KeyType::X25519 => Basic::X25519,
            KeyType::X448 => Basic::X448,
        }
    }
}

impl From<Basic> for KeyType {
    fn from(kd: Basic) -> Self {
        match kd {
            Basic::ECDSAsecp256k1Nontrans => KeyType::ECDSAsecp256k1,
            Basic::ECDSAsecp256k1 => KeyType::ECDSAsecp256k1,
            Basic::Ed25519Nontrans => KeyType::Ed25519,
            Basic::Ed25519 => KeyType::Ed25519,
            Basic::Ed448Nontrans => KeyType::Ed448,
            Basic::Ed448 => KeyType::Ed448,
            Basic::X25519 => KeyType::X25519,
            Basic::X448 => KeyType::X448,
            // NIST P-256 has no dedicated KeyType; report it as the nearest
            // ECDSA option. This reverse mapping is a convenience only — key
            // creation uses the forward `Into<Basic>` direction.
            Basic::ECDSA256r1Nontrans | Basic::ECDSA256r1 => KeyType::ECDSAsecp256k1,
        }
    }
}

pub struct PublicKey {
    prefix: String,
}

impl PublicKey {
    pub fn new(algorithm: u32, key: Vec<u8>) -> Result<Self, Error> {
        let key_type: KeyType = algorithm.into();
        let d: Basic = key_type.into();
        let keys = KeriPublicKey::new(key);
        let pref = BasicPrefix::new(d, keys);
        Ok(Self {
            prefix: pref.to_str(),
        })
    }

    pub fn to_string(&self) -> String {
        self.prefix.clone()
    }
}
