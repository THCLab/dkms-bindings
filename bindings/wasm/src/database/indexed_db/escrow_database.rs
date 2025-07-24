use std::sync::Arc;

use keri_sdk::database::SequencedEventDatabase;
use said::SelfAddressingIdentifier;

use keri_core::{
    database::EscrowDatabase,
    database::LogDatabase,
    event::KeyEvent,
    event_message::{msg::KeriEvent, signed_event_message::SignedEventMessage},
    prefix::IdentifierPrefix,
};

use super::IndexedDbError;

pub struct IndexedDbEscrowDatabase {
    escrow: Arc<
        dyn SequencedEventDatabase<
            DatabaseType = (),
            Error = IndexedDbError,
            DigestIter = Box<dyn Iterator<Item = said::SelfAddressingIdentifier>>,
        >,
    >,
    log: Arc<super::logging::IndexedDbLogDatabase>,
}

// SAFETY: In WebAssembly context, there's no true threading, so these are safe
unsafe impl Send for IndexedDbEscrowDatabase {}
unsafe impl Sync for IndexedDbEscrowDatabase {}

impl EscrowDatabase for IndexedDbEscrowDatabase {
    type EscrowDatabaseType = ();
    type LogDatabaseType = super::logging::IndexedDbLogDatabase;
    type Error = IndexedDbError;
    type EventIter = Box<dyn Iterator<Item = SignedEventMessage>>;

    fn new(
        escrow: Arc<
            dyn SequencedEventDatabase<
                DatabaseType = Self::EscrowDatabaseType,
                Error = Self::Error,
                DigestIter = Box<dyn Iterator<Item = said::SelfAddressingIdentifier>>,
            >,
        >,
        log: Arc<Self::LogDatabaseType>,
    ) -> Self
    where
        Self: Sized,
    {
        Self { escrow, log }
    }

    fn save_digest(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        event_digest: &SelfAddressingIdentifier,
    ) -> Result<(), Self::Error> {
        self.escrow.insert(id, sn, event_digest)?;

        Ok(())
    }

    fn insert(&self, event: &SignedEventMessage) -> Result<(), Self::Error> {
        self.log
            .log_event_with_new_transaction(event)?;
        let said = event.event_message.digest().unwrap();
        let id = event.event_message.data.get_prefix();
        let sn = event.event_message.data.sn;
        self.escrow.insert(&id, sn, &said)?;

        Ok(())
    }

    fn insert_key_value(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        event: &SignedEventMessage,
    ) -> Result<(), Self::Error> {
        self.log
            .log_event_with_new_transaction(event)?;
        let said = event.event_message.digest().unwrap();

        self.escrow.insert(id, sn, &said)?;

        Ok(())
    }

    fn get(&self, identifier: &IdentifierPrefix, sn: u64) -> Result<Self::EventIter, Self::Error> {
        let saids = self.escrow.get(identifier, sn)?;
        let saids_vec: Vec<_> = saids.collect();

        let log = Arc::clone(&self.log);

        let events = saids_vec.into_iter().filter_map(move |said| {
            log.get_signed_event(&said)
                .ok()
                .flatten()
                .map(|el| el.signed_event_message)
        });

        Ok(Box::new(events))
    }

    fn get_from_sn(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Self::EventIter, Self::Error> {
        let saids = self.escrow.get_greater_than(identifier, sn)?;
        let saids_vec: Vec<_> = saids.collect();

        let log = Arc::clone(&self.log);

        let events = saids_vec.into_iter().filter_map(move |said| {
            log.get_signed_event(&said)
                .ok()
                .flatten()
                .map(|el| el.signed_event_message)
        });

        Ok(Box::new(events))
    }

    fn remove(&self, event: &KeriEvent<KeyEvent>) {
        let said = event.digest().unwrap();
        let id = event.data.get_prefix();
        let sn = event.data.sn;
        self.escrow.remove(&id, sn, &said).unwrap();
    }

    fn contains(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        digest: &SelfAddressingIdentifier,
    ) -> Result<bool, Self::Error> {
        Ok(self
            .escrow
            .get(id, sn)?
            .any(|said| &said == digest))
    }
}
