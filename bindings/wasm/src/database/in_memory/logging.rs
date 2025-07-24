use keri_core::database::LogDatabase;
use super::InMemoryDbError;
use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use keri_core::event_message::signature::{Nontransferable, Transferable};
use keri_core::event::KeyEvent;
use keri_core::event_message::msg::KeriEvent;
use keri_core::event_message::signed_event_message::{ SignedEventMessage, SignedNontransferableReceipt };
use keri_core::database::timestamped::TimestampedSignedEventMessage;
use keri_core::prefix::IndexedSignature;
use said::SelfAddressingIdentifier;

pub struct InMemoryLogDatabase {
    events: RwLock<HashMap<String, TimestampedSignedEventMessage>>,
    signatures: RwLock<HashMap<String, Vec<IndexedSignature>>>,
    nontrans_receipts: RwLock<HashMap<String, Vec<Nontransferable>>>,
    trans_receipts: RwLock<HashMap<String, Vec<Transferable>>>,
}

impl LogDatabase<'_> for InMemoryLogDatabase {
    type DatabaseType = ();
    type Error = InMemoryDbError;
    type TransactionType = ();

    fn new(_db: Arc<Self::DatabaseType>) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Self {
            events: RwLock::new(HashMap::new()),
            signatures: RwLock::new(HashMap::new()),
            nontrans_receipts: RwLock::new(HashMap::new()),
            trans_receipts: RwLock::new(HashMap::new()),
        })
    }

    fn log_event(
        &self,
        _txn: &Self::TransactionType,
        signed_event: &SignedEventMessage,
    ) -> Result<(), Self::Error> {
        self.log_event_with_new_transaction(signed_event)
    }

    fn log_event_with_new_transaction(
        &self,
        signed_event: &SignedEventMessage,
    ) -> Result<(), Self::Error> {
        let digest = signed_event
            .event_message
            .digest()
            .map_err(|_| InMemoryDbError::MissingDigest)?;
        
        let said_str = digest.to_string();
        
        // Store the event
        self.events
            .write()
            .map_err(|_| InMemoryDbError::LockError)?
            .insert(said_str.clone(), TimestampedSignedEventMessage::new(signed_event.clone()));
        
        // Store the signatures
        self.signatures
            .write()
            .map_err(|_| InMemoryDbError::LockError)?
            .insert(said_str.clone(), signed_event.signatures.clone());

        // Store the witness receipts if present
        if let Some(receipts) = &signed_event.witness_receipts {
            self.nontrans_receipts
                .write()
                .map_err(|_| InMemoryDbError::LockError)?
                .insert(said_str.clone(), receipts.clone());
        }

        log::debug!("Logged event with SAID: {}", said_str);
        Ok(())
    }

    fn log_receipt(
        &self,
        _txn: &Self::TransactionType,
        signed_receipt: &SignedNontransferableReceipt,
    ) -> Result<(), Self::Error> {
        self.log_receipt_with_new_transaction(signed_receipt)
    }

    fn log_receipt_with_new_transaction(
        &self,
        signed_receipt: &SignedNontransferableReceipt,
    ) -> Result<(), Self::Error> {
        let digest = &signed_receipt.body.receipted_event_digest;
        let said_str = digest.to_string();
        
        let mut receipts_map = self.nontrans_receipts
            .write()
            .map_err(|_| InMemoryDbError::LockError)?;
        
        // Get existing receipts or create new vector
        let receipts = receipts_map.entry(said_str.clone()).or_insert_with(Vec::new);
        
        // Add new receipts
        for receipt in &signed_receipt.signatures {
            if !receipts.contains(receipt) {
                receipts.push(receipt.clone());
            }
        }
        
        log::debug!("Logged receipt for SAID: {}", said_str);
        Ok(())
    }

    fn get_signed_event(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<Option<TimestampedSignedEventMessage>, Self::Error> {
        let events = self.events
            .read()
            .map_err(|_| InMemoryDbError::LockError)?;
        
        let r = events.get(&said.to_string()).cloned();
        Ok(r)
    }

    fn get_event(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<Option<KeriEvent<KeyEvent>>, Self::Error> {
        let events = self.events
            .read()
            .map_err(|_| InMemoryDbError::LockError)?;
            
        match events.get(&said.to_string()) {
            Some(signed_event) => Ok(Some(signed_event.signed_event_message.event_message.clone())),
            None => Ok(None),
        }
    }

    fn get_signatures(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<Option<impl Iterator<Item = IndexedSignature>>, Self::Error> {
        let signatures = self.signatures
            .read()
            .map_err(|_| InMemoryDbError::LockError)?;
            
        match signatures.get(&said.to_string()) {
            Some(sigs) => Ok(Some(sigs.clone().into_iter())),
            None => Ok(None),
        }
    }

    fn get_nontrans_couplets(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<Option<impl Iterator<Item = Nontransferable>>, Self::Error> {
        let receipts = self.nontrans_receipts
            .read()
            .map_err(|_| InMemoryDbError::LockError)?;
            
        match receipts.get(&said.to_string()) {
            Some(receipts) => Ok(Some(receipts.clone().into_iter())),
            None => Ok(None),
        }
    }

    fn get_trans_receipts(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<impl DoubleEndedIterator<Item = Transferable>, Self::Error> {
        let receipts = self.trans_receipts
            .read()
            .map_err(|_| InMemoryDbError::LockError)?;
            
        match receipts.get(&said.to_string()) {
            Some(receipts) => Ok(receipts.clone().into_iter()),
            None => Ok(Vec::new().into_iter()),
        }
    }

    fn remove_nontrans_receipt(
        &self,
        _txn_mode: &Self::TransactionType,
        said: &SelfAddressingIdentifier,
        nontrans: impl IntoIterator<Item = Nontransferable>,
    ) -> Result<(), Self::Error> {
        let said_str = said.to_string();
        let mut receipts_map = self.nontrans_receipts
            .write()
            .map_err(|_| InMemoryDbError::LockError)?;
        
        if let Some(receipts) = receipts_map.get_mut(&said_str) {
            let receipts_to_remove: Vec<Nontransferable> = nontrans.into_iter().collect();
            receipts.retain(|r| !receipts_to_remove.contains(r));
        }
        
        Ok(())
    }

    fn remove_nontrans_receipt_with_new_transaction(
        &self,
        said: &SelfAddressingIdentifier,
        nontrans: impl IntoIterator<Item = Nontransferable>,
    ) -> Result<(), Self::Error> {
        self.remove_nontrans_receipt(&(), said, nontrans)
    }
}
