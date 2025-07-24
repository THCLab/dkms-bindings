use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use said::SelfAddressingIdentifier;

use keri_core::{
    database::EscrowDatabase,
    database::LogDatabase,
    event::KeyEvent,
    event_message::{msg::KeriEvent, signed_event_message::SignedEventMessage},
    prefix::IdentifierPrefix,
};

use super::InMemoryDbError;

pub struct InMemoryEscrowDatabase {
    sn_db: Arc<dyn keri_core::database::SequencedEventDatabase<
        DatabaseType = (), 
        Error = InMemoryDbError,
        DigestIter = Box<dyn Iterator<Item = SelfAddressingIdentifier>>,
    >>,
    log: Arc<super::logging::InMemoryLogDatabase>,
    events: RwLock<HashMap<SelfAddressingIdentifier, SignedEventMessage>>,
}

impl EscrowDatabase for InMemoryEscrowDatabase {
    type EscrowDatabaseType = ();
    type LogDatabaseType = super::logging::InMemoryLogDatabase;
    type Error = InMemoryDbError;
    type EventIter = Box<dyn Iterator<Item = SignedEventMessage>>;

    fn new(
        sn_db: Arc<dyn keri_core::database::SequencedEventDatabase<
            DatabaseType = (), 
            Error = InMemoryDbError,
            DigestIter = Box<dyn Iterator<Item = SelfAddressingIdentifier>>,
        >>, 
        log: Arc<super::logging::InMemoryLogDatabase>
    ) -> Self {
        Self {
            sn_db,
            log,
            events: RwLock::new(HashMap::new()),
        }
    }

    fn save_digest(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        event_digest: &SelfAddressingIdentifier,
    ) -> Result<(), Self::Error> {
        self.sn_db.insert(id, sn, event_digest)
    }

    fn insert(&self, event: &SignedEventMessage) -> Result<(), Self::Error> {
        let said = event.event_message.digest().unwrap();
        let id = event.event_message.data.get_prefix();
        let sn = event.event_message.data.sn;
        
        self.log.log_event_with_new_transaction(event)?;
        self.events.write().unwrap().insert(said.clone(), event.clone());
        self.sn_db.insert(&id, sn, &said)
    }

    fn insert_key_value(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        event: &SignedEventMessage,
    ) -> Result<(), Self::Error> {
        let said = event.event_message.digest().unwrap();
        
        self.log.log_event_with_new_transaction(event)?;
        self.events.write().unwrap().insert(said.clone(), event.clone());
        self.sn_db.insert(id, sn, &said)
    }

    fn get(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Self::EventIter, Self::Error> {
        let digests = self.sn_db.get(identifier, sn)?;
        let events = self.events.read().unwrap();
        
        let events_cloned = events.clone();
        let events_iter = digests.filter_map(move |digest| {
            events_cloned.get(&digest).cloned()
        });
        
        Ok(Box::new(events_iter))
    }

    fn get_from_sn(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Self::EventIter, Self::Error> {
        let digests = self.sn_db.get_greater_than(identifier, sn)?;
        let events = self.events.read().unwrap();
        
        let events_cloned = events.clone();
        let events_iter = digests.filter_map(move |digest| {
            events_cloned.get(&digest).cloned()
        });
        
        Ok(Box::new(events_iter))
    }

    fn remove(&self, event: &KeriEvent<KeyEvent>) {
        let said = event.digest().unwrap();
        let id = event.data.get_prefix();
        let sn = event.data.sn;
        
        self.sn_db.remove(&id, sn, &said).ok();
        self.events.write().unwrap().remove(&said);
    }

    fn contains(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        digest: &SelfAddressingIdentifier,
    ) -> Result<bool, Self::Error> {
        let mut digests = self.sn_db.get(id, sn)?;
        let result: bool = digests.any(|d| &d == digest);
        Ok(result)
    }
}
