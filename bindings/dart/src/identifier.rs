use keri::keys::PublicKey as KeriPublicKey;
use keri::prefix::{BasicPrefix, IdentifierPrefix, Prefix};

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
        PublicKey {
            public_key: bp.public_key.key(),
            derivation: bp.derivation,
        }
    }
}

impl From<&PublicKey> for BasicPrefix {
    fn from(pk: &PublicKey) -> Self {
        BasicPrefix {
            derivation: pk.derivation,
            public_key: KeriPublicKey::new(pk.public_key.clone()),
        }
    }
}
