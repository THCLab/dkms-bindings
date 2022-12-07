use keri::event_parsing::codes::basic::Basic;
use keri::event_parsing::primitives::CesrPrimitive;
use keri::keys::PublicKey as KeriPublicKey;
use keri::prefix::{BasicPrefix, IdentifierPrefix};

use crate::api::{Identifier, PublicKey};

impl From<IdentifierPrefix> for Identifier {
    fn from(id: IdentifierPrefix) -> Self {
        Identifier { id: id.to_str() }
    }
}

impl Into<IdentifierPrefix> for &Identifier {
    fn into(self) -> IdentifierPrefix {
        self.id.parse::<IdentifierPrefix>().unwrap()
    }
}
impl Into<IdentifierPrefix> for Identifier {
    fn into(self) -> IdentifierPrefix {
        self.id.parse::<IdentifierPrefix>().unwrap()
    }
}

impl From<BasicPrefix> for PublicKey {
    fn from(bp: BasicPrefix) -> Self {
        let code = match bp {
            BasicPrefix::ECDSAsecp256k1NT(_) => Basic::ECDSAsecp256k1NT,
            BasicPrefix::ECDSAsecp256k1(_) => Basic::ECDSAsecp256k1,
            BasicPrefix::Ed25519NT(_) => Basic::Ed25519NT,
            BasicPrefix::Ed25519(_) => Basic::Ed25519,
            BasicPrefix::Ed448NT(_) => Basic::Ed25519NT,
            BasicPrefix::Ed448(_) => Basic::Ed448,
            BasicPrefix::X25519(_) => Basic::X25519,
            BasicPrefix::X448(_) => Basic::X448,
        };
        PublicKey {
            public_key: bp.derivative(),
            derivation: code,
        }
    }
}

impl From<&PublicKey> for BasicPrefix {
    fn from(pk: &PublicKey) -> Self {
        BasicPrefix::new(pk.derivation, KeriPublicKey::new(pk.public_key.clone()))
    }
}
