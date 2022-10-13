use keri::prefix::{IdentifierPrefix, Prefix};

use crate::api::Identifier;

impl From<IdentifierPrefix> for Identifier {
    fn from(id: IdentifierPrefix) -> Self {
        Identifier {id: id.to_str()}
}
}

impl Into<IdentifierPrefix> for Identifier {
    fn into(self) -> IdentifierPrefix {
        self.id.parse::<IdentifierPrefix>().unwrap()
    }
}
