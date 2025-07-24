use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use keri_sdk::TelEventDatabase;
use said::SelfAddressingIdentifier;
use teliox::event::{verifiable_event::VerifiableEvent, Event};

use keri_core::{
    database::SequencedEventDatabase,
    event::KeyEvent,
    event_message::{
        msg::KeriEvent,
        signed_event_message::{
            SignedEventMessage, SignedNontransferableReceipt,
            SignedTransferableReceipt,
        },
    },
    prefix::IdentifierPrefix,
    state::IdentifierState,
};

use keri_core::database::{
    timestamped, EscrowCreator, EscrowDatabase, EventDatabase, QueryParameters,
};

use cesrox::primitives::CesrPrimitive;

pub mod logging;
use keri_core::database::LogDatabase;
use logging::InMemoryLogDatabase;

pub mod escrow_database;
pub mod sn_database;

use escrow_database::InMemoryEscrowDatabase;
use sn_database::InMemorySnDatabase;

impl EscrowCreator for InMemoryDatabase {
    type EscrowDatabaseType = InMemoryEscrowDatabase;

    fn create_escrow_db(
        &self,
        _table_name: &'static str,
    ) -> Self::EscrowDatabaseType {
        InMemoryEscrowDatabase::new(
            Arc::new(
                InMemorySnDatabase::new(Arc::new(()), _table_name).unwrap(),
            ),
            self.log_db.clone(),
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InMemoryDbError {
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Already saved: {0}")]
    AlreadySaved(SelfAddressingIdentifier),
    #[error("Event not found")]
    MissingDigest,
    #[error("Lock error")]
    LockError,
}

/// In-memory implementation of the event database
pub struct InMemoryDatabase {
    kels: RwLock<HashMap<(String, u64), SelfAddressingIdentifier>>,
    key_states: RwLock<HashMap<String, IdentifierState>>,
    events: RwLock<
        HashMap<
            SelfAddressingIdentifier,
            timestamped::TimestampedSignedEventMessage,
        >,
    >,
    trans_receipts: RwLock<
        HashMap<
            SelfAddressingIdentifier,
            Vec<keri_core::event_message::signature::Transferable>,
        >,
    >,
    nontrans_receipts: RwLock<
        HashMap<
            SelfAddressingIdentifier,
            Vec<keri_core::event_message::signature::Nontransferable>,
        >,
    >,
    log_db: Arc<InMemoryLogDatabase>,
    tel_events: RwLock<HashMap<IdentifierPrefix, Vec<VerifiableEvent>>>,
    management_events: RwLock<HashMap<IdentifierPrefix, Vec<VerifiableEvent>>>,
}

impl InMemoryDatabase {
    pub fn new() -> Self {
        Self {
            kels: RwLock::new(HashMap::new()),
            key_states: RwLock::new(HashMap::new()),
            events: RwLock::new(HashMap::new()),
            trans_receipts: RwLock::new(HashMap::new()),
            nontrans_receipts: RwLock::new(HashMap::new()),
            log_db: Arc::new(InMemoryLogDatabase::new(Arc::new(())).unwrap()),
            tel_events: RwLock::new(HashMap::new()),
            management_events: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl EventDatabase for InMemoryDatabase {
    type Error = InMemoryDbError;
    type LogDatabaseType = InMemoryLogDatabase;

    fn get_log_db(&self) -> Arc<Self::LogDatabaseType> {
        self.log_db.clone()
    }

    fn add_kel_finalized_event(
        &self,
        signed_event: SignedEventMessage,
        id: &IdentifierPrefix,
    ) -> Result<(), Self::Error> {
        let event = &signed_event.event_message;
        let digest = event.digest().unwrap();
        let id_str = id.to_str();
        let sn = event.data.sn;

        // Update key state
        let mut key_states = self.key_states.write().unwrap();
        let mut key_state =
            key_states.get(&id_str).cloned().unwrap_or_default();
        key_state = key_state
            .apply(event)
            .map_err(|_| InMemoryDbError::AlreadySaved(digest.clone()))?;
        key_states.insert(id_str.clone(), key_state);

        // Save to KEL
        self.kels
            .write()
            .unwrap()
            .insert((id_str, sn), digest.clone());

        self.log_db.log_event_with_new_transaction(&signed_event)?;

        // Save event
        self.events.write().unwrap().insert(
            digest,
            timestamped::TimestampedSignedEventMessage::new(signed_event),
        );

        Ok(())
    }

    fn add_receipt_t(
        &self,
        receipt: SignedTransferableReceipt,
        _id: &IdentifierPrefix,
    ) -> Result<(), Self::Error> {
        let digest = receipt.body.receipted_event_digest;
        let transferable =
            keri_core::event_message::signature::Transferable::Seal(
                receipt.validator_seal,
                receipt.signatures,
            );

        let mut receipts = self.trans_receipts.write().unwrap();
        receipts.entry(digest).or_default().push(transferable);

        Ok(())
    }

    fn add_receipt_nt(
        &self,
        receipt: SignedNontransferableReceipt,
        _id: &IdentifierPrefix,
    ) -> Result<(), Self::Error> {
        let digest = receipt.body.receipted_event_digest;

        let mut receipts = self.nontrans_receipts.write().unwrap();
        receipts
            .entry(digest)
            .or_default()
            .extend(receipt.signatures);

        Ok(())
    }

    fn get_key_state(&self, id: &IdentifierPrefix) -> Option<IdentifierState> {
        self.key_states.read().unwrap().get(&id.to_str()).cloned()
    }

    fn get_kel_finalized_events(
        &self,
        params: QueryParameters,
    ) -> Option<
        impl DoubleEndedIterator<Item = timestamped::TimestampedSignedEventMessage>,
    > {
        match params {
            QueryParameters::BySn { id, sn } => {
                let key = (id.to_str(), sn);
                let kels = self.kels.read().unwrap();
                let events = self.events.read().unwrap();

                kels.get(&key)
                    .and_then(|digest| events.get(digest))
                    .cloned()
                    .map(|event| vec![event].into_iter())
            }
            QueryParameters::Range { id, start, limit } => {
                let id_str = id.to_str();
                let kels = self.kels.read().unwrap();
                let events = self.events.read().unwrap();

                let mut result = Vec::new();
                for sn in start..(start + limit) {
                    if let Some(digest) = kels.get(&(id_str.clone(), sn)) {
                        if let Some(event) = events.get(digest) {
                            result.push(event.clone());
                        }
                    }
                }

                if result.is_empty() {
                    None
                } else {
                    Some(result.into_iter())
                }
            }
            QueryParameters::All { id } => {
                let id_str = id.to_str();
                let kels = self.kels.read().unwrap();
                let events = self.events.read().unwrap();

                let mut result = Vec::new();
                for ((prefix, _), digest) in kels.iter() {
                    if prefix == &id_str {
                        if let Some(event) = events.get(digest) {
                            result.push(event.clone());
                        }
                    }
                }

                if result.is_empty() {
                    None
                } else {
                    Some(result.into_iter())
                }
            }
        }
    }

    fn get_receipts_t(
        &self,
        params: QueryParameters,
    ) -> Option<
        impl DoubleEndedIterator<
            Item = keri_core::event_message::signature::Transferable,
        >,
    > {
        match params {
            QueryParameters::BySn { id, sn } => {
                let key = (id.to_str(), sn);
                let kels = self.kels.read().unwrap();
                let receipts = self.trans_receipts.read().unwrap();

                kels.get(&key)
                    .and_then(|digest| receipts.get(digest))
                    .cloned()
                    .map(|r| r.into_iter())
            }
            _ => None,
        }
    }

    fn get_receipts_nt(
        &self,
        params: QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = SignedNontransferableReceipt>>
    {
        match params {
            QueryParameters::BySn { id: _, sn: _ } => Some(vec![].into_iter()),
            _ => None,
        }
    }

    fn accept_to_kel(
        &self,
        event: &KeriEvent<KeyEvent>,
    ) -> Result<(), Self::Error> {
        let digest = event.digest().unwrap();
        let id_str = event.data.get_prefix().to_str();
        let sn = event.data.sn;

        // Update key state
        let mut key_states = self.key_states.write().unwrap();
        let mut key_state =
            key_states.get(&id_str).cloned().unwrap_or_default();
        key_state = key_state
            .apply(event)
            .map_err(|_| InMemoryDbError::AlreadySaved(digest.clone()))?;
        key_states.insert(id_str.clone(), key_state);

        // Save to KEL
        self.kels.write().unwrap().insert((id_str, sn), digest);

        Ok(())
    }

    fn save_reply(
        &self,
        _reply: keri_core::query::reply_event::SignedReply,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
    fn get_reply(
        &self,
        _id: &IdentifierPrefix,
        _from_who: &IdentifierPrefix,
    ) -> Option<keri_core::query::reply_event::SignedReply> {
        None
    }
}

impl TelEventDatabase for InMemoryDatabase {
    fn new(
        _path: impl AsRef<std::path::Path>,
    ) -> Result<Self, teliox::error::Error>
    where
        Self: Sized,
    {
        Ok(Self::new())
    }

    fn add_new_event(
        &self,
        event: VerifiableEvent,
        id: &IdentifierPrefix,
    ) -> Result<(), teliox::error::Error> {
        match event.event {
            Event::Vc(_) => {
                let mut events_map = self
                    .tel_events
                    .write()
                    .map_err(|_| teliox::error::Error::RwLockingError)?;
                events_map
                    .entry(id.clone())
                    .or_insert_with(Vec::new)
                    .push(event);
            }
            Event::Management(_) => {
                let mut events_map = self
                    .management_events
                    .write()
                    .map_err(|_| teliox::error::Error::RwLockingError)?;
                events_map
                    .entry(id.clone())
                    .or_insert_with(Vec::new)
                    .push(event);
            }
        }
        Ok(())
    }

    fn get_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = VerifiableEvent>> {
        let events_map = self.tel_events.read().ok()?;
        events_map.get(id).map(|events| events.clone().into_iter())
    }

    fn get_management_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = VerifiableEvent>> {
        let events_map = self.management_events.read().ok()?;
        events_map.get(id).map(|events| events.clone().into_iter())
    }
}
