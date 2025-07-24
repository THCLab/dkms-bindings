use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use said::SelfAddressingIdentifier;
use keri_core::{database::SequencedEventDatabase, prefix::IdentifierPrefix};
use cesrox::primitives::CesrPrimitive;

use super::InMemoryDbError;

pub struct InMemorySnDatabase {
    data: RwLock<HashMap<(String, u64), Vec<SelfAddressingIdentifier>>>,
}

impl Default for InMemorySnDatabase {
    fn default() -> Self {
        Self::new(Arc::new(()), "default").unwrap()
    }
}

impl SequencedEventDatabase for InMemorySnDatabase {
    type DatabaseType = ();
    type Error = InMemoryDbError;
    type DigestIter = Box<dyn Iterator<Item = SelfAddressingIdentifier>>;

    fn new(
        _db: Arc<Self::DatabaseType>,
        _table_name: &'static str,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Self {
            data: RwLock::new(HashMap::new()),
        })
    }

    fn insert(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        digest: &SelfAddressingIdentifier,
    ) -> Result<(), Self::Error> {
        let mut data = self.data.write().unwrap();
        let key = (id.to_str(), sn);
        data.entry(key)
            .or_default()
            .push(digest.clone());
        Ok(())
    }

    fn get(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Self::DigestIter, Self::Error> {
        let data = self.data.read().unwrap();
        let key = (id.to_str(), sn);

        if let Some(digests) = data.get(&key) {
            Ok(Box::new(digests.clone().into_iter()))
        } else {
            Ok(Box::new(std::iter::empty()))
        }
    }

    fn get_greater_than(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Self::DigestIter, Self::Error> {
        let data = self.data.read().unwrap();
        let id_str = id.to_str();

        let mut result = Vec::new();
        for ((prefix, seq), digests) in data.iter() {
            if prefix == &id_str && *seq >= sn {
                result.extend(digests.clone());
            }
        }

        Ok(Box::new(result.into_iter()))
    }

    fn remove(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        digest: &SelfAddressingIdentifier,
    ) -> Result<(), Self::Error> {
        let mut data = self.data.write().unwrap();
        let key = (id.to_str(), sn);

        if let Some(digests) = data.get_mut(&key) {
            digests.retain(|d| d != digest);
            if digests.is_empty() {
                data.remove(&key);
            }
            Ok(())
        } else {
            Err(InMemoryDbError::NotFound(format!("{:?} at sn {}", id, sn)))
        }
    }
}
