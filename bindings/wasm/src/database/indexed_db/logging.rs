use keri_core::database::LogDatabase;

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

use super::IndexedDbError;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;
use std::collections::HashMap;
use keri_core::event_message::signature::{Nontransferable, Transferable};
use keri_core::event::KeyEvent;
use keri_core::event_message::msg::KeriEvent;
use keri_core::event_message::signed_event_message::{ SignedEventMessage, SignedNontransferableReceipt };
use keri_core::database::timestamped::TimestampedSignedEventMessage;
use keri_core::prefix::IndexedSignature;
use said::SelfAddressingIdentifier;

const DB_NAME: &str = "log_db";

pub struct IndexedDbLogDatabase {
    db_ref: Rc<RefCell<Option<web_sys::IdbDatabase>>>,
    events: Rc<RefCell<HashMap<String, TimestampedSignedEventMessage>>>,
    signatures: Rc<RefCell<HashMap<String, Vec<IndexedSignature>>>>,
    trans_receipts: Rc<RefCell<HashMap<String, Vec<Transferable>>>>,
    nontrans_receipts: Rc<RefCell<HashMap<String, Vec<Nontransferable>>>>,
    pending_operations: Rc<RefCell<Vec<PendingOperation>>>,
    flush_in_progress: Rc<Cell<bool>>,
}

// SAFETY: In WebAssembly context, there's no true threading, so these are safe
unsafe impl Send for IndexedDbLogDatabase {}
unsafe impl Sync for IndexedDbLogDatabase {}

enum PendingOperation {
    StoreEvent {
        said: String, 
        event: Box<TimestampedSignedEventMessage>,
        signatures: Vec<IndexedSignature>,
    },
    StoreNontransReceipt { said: String, receipts: Vec<Nontransferable> },
    StoreTransReceipt { said: String, receipts: Vec<Transferable> },
    RemoveReceipt {
        said: String,
        remaining_receipts: Vec<Nontransferable>,
    },
}

impl IndexedDbLogDatabase {
    fn init_db(&mut self) {
        let window = web_sys::window().expect("should have a window");
        
        // Get IndexedDB factory
        if let Ok(Some(factory)) = window.indexed_db() {
            let db_ref = self.db_ref.clone();
            let events = self.events.clone();
            let signatures = self.signatures.clone();
            let trans_receipts = self.trans_receipts.clone();
            let nontrans_receipts = self.nontrans_receipts.clone();
            let pending_operations = self.pending_operations.clone();
            let flush_in_progress = self.flush_in_progress.clone();

            // Open database
            if let Ok(request) = factory.open(DB_NAME) {
                // Handle database upgrade needed (first time opening)
                let upgrade_needed_cb = Closure::wrap(Box::new(move |event: web_sys::IdbVersionChangeEvent| {
                    if let Some(db) = event.target()
                        .and_then(|t| t.dyn_into::<web_sys::IdbOpenDbRequest>().ok())
                        .and_then(|r| r.result().ok())
                        .and_then(|r| r.dyn_into::<web_sys::IdbDatabase>().ok()) 
                    {
                        // Create stores for log database
                        let _ = db.create_object_store("events");
                        let _ = db.create_object_store("trans_receipts");
                        let _ = db.create_object_store("nontrans_receipts");
                    }
                }) as Box<dyn FnMut(_)>);

                request.set_onupgradeneeded(Some(upgrade_needed_cb.as_ref().unchecked_ref()));
                upgrade_needed_cb.forget();

                // Handle successful open
                let success_cb = Closure::wrap(Box::new(move |event: web_sys::Event| {
                    if let Some(db) = event.target()
                        .and_then(|t| t.dyn_into::<web_sys::IdbOpenDbRequest>().ok())
                        .and_then(|r| r.result().ok())
                        .and_then(|r| r.dyn_into::<web_sys::IdbDatabase>().ok())
                    {
                        *db_ref.borrow_mut() = Some(db.clone());

                        // Load data from IndexedDB
                        load_events(&db, events.clone());
                        load_signatures(&db, signatures.clone());
                        load_trans_receipts(&db, trans_receipts.clone());
                        load_nontrans_receipts(&db, nontrans_receipts.clone());

                        // Set up background flush
                        setup_background_flush(db, pending_operations.clone(), flush_in_progress.clone());
                    }
                }) as Box<dyn FnMut(_)>);

                request.set_onsuccess(Some(success_cb.as_ref().unchecked_ref()));
                success_cb.forget();

                // Handle errors
                let error_cb = Closure::wrap(Box::new(|event: web_sys::Event| {
                    log::error!("Failed to open IndexedDB Log Database: {:?}", event);
                }) as Box<dyn FnMut(_)>);

                request.set_onerror(Some(error_cb.as_ref().unchecked_ref()));
                error_cb.forget();
            }
        }
    }
}

impl LogDatabase<'_> for IndexedDbLogDatabase {
    type DatabaseType = ();
    type Error = IndexedDbError;
    type TransactionType = ();

    fn new(_db: Arc<Self::DatabaseType>) -> Result<Self, IndexedDbError> {
        let db_ref = Rc::new(RefCell::new(None));
        let events = Rc::new(RefCell::new(HashMap::new()));
        let signatures = Rc::new(RefCell::new(HashMap::new()));
        let trans_receipts = Rc::new(RefCell::new(HashMap::new()));
        let nontrans_receipts = Rc::new(RefCell::new(HashMap::new()));
        let pending_operations = Rc::new(RefCell::new(Vec::new()));
        let flush_in_progress = Rc::new(Cell::new(false));

        let mut db = Self {
            db_ref,
            events,
            signatures,
            trans_receipts,
            nontrans_receipts,
            pending_operations,
            flush_in_progress,
        };

        db.init_db();

        Ok(db)
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
            .map_err(|_| IndexedDbError::MissingDigest)?;

        let said_str = digest.to_string();
        
        // Store the event in memory
        let timestamped_event = TimestampedSignedEventMessage::new(signed_event.clone());
        self.events
            .borrow_mut()
            .insert(said_str.clone(), timestamped_event.clone());

        // Store the signatures
        self.signatures
            .borrow_mut()
            .insert(said_str.clone(), signed_event.signatures.clone());

        // Store the witness receipts if present
        if let Some(receipts) = &signed_event.witness_receipts {
            self.nontrans_receipts
                .borrow_mut()
                .insert(said_str.clone(), receipts.clone());
        }

        // Queue for IndexedDB persistence
        let mut pending = self.pending_operations.borrow_mut();
        pending.push(PendingOperation::StoreEvent {
            said: said_str.clone(),
            event: Box::new(timestamped_event),
            signatures: signed_event.signatures.clone(),
        });

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
            .borrow_mut();
        
        // Get existing receipts or create new vector
        let receipts = receipts_map.entry(said_str.clone()).or_default();

        // Add new receipts that aren't already present
        let mut new_receipts = Vec::new();
        for receipt in &signed_receipt.signatures {
            if !receipts.contains(receipt) {
                receipts.push(receipt.clone());
                new_receipts.push(receipt.clone());
            }
        }

        if !new_receipts.is_empty() {
            // Queue for IndexedDB persistence
            let mut pending = self.pending_operations.borrow_mut();
            pending.push(PendingOperation::StoreNontransReceipt {
                said: said_str.clone(),
                receipts: new_receipts,
            });
        }

        Ok(())
    }

    fn get_signed_event(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<Option<TimestampedSignedEventMessage>, Self::Error> {
        let events = self.events.borrow();

        let r = events.get(&said.to_string()).cloned();
        Ok(r)
    }

    fn get_event(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<Option<KeriEvent<KeyEvent>>, Self::Error> {
        let events = self.events.borrow();

        match events.get(&said.to_string()) {
            Some(signed_event) => Ok(Some(signed_event.signed_event_message.event_message.clone())),
            None => Ok(None),
        }
    }

    fn get_signatures(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<Option<impl Iterator<Item = IndexedSignature>>, Self::Error> {
        let signatures = self.signatures.borrow();

        match signatures.get(&said.to_string()) {
            Some(sigs) => Ok(Some(sigs.clone().into_iter())),
            None => Ok(None),
        }
    }

    fn get_nontrans_couplets(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<Option<impl Iterator<Item = Nontransferable>>, Self::Error> {
        let receipts = self.nontrans_receipts.borrow();

        match receipts.get(&said.to_string()) {
            Some(receipts) => Ok(Some(receipts.clone().into_iter())),
            None => Ok(None),
        }
    }

    fn get_trans_receipts(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<impl DoubleEndedIterator<Item = Transferable>, Self::Error> {
        let receipts = self.trans_receipts.borrow();

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
        let mut receipts_map = self.nontrans_receipts.borrow_mut();

        if let Some(receipts) = receipts_map.get_mut(&said_str) {
            let receipts_to_remove: Vec<Nontransferable> = nontrans.into_iter().collect();
            receipts.retain(|r| !receipts_to_remove.contains(r));

            // Queue for IndexedDB persistence - include the REMAINING receipts after removal
            let mut pending = self.pending_operations.borrow_mut();
            pending.push(PendingOperation::RemoveReceipt {
                said: said_str,
                remaining_receipts: receipts.clone(),
            });
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

impl IndexedDbLogDatabase {
    // Insert transferable receipts
    pub fn insert_trans_receipt(
        &self, 
        said: &SelfAddressingIdentifier, 
        receipts: &[Transferable]
    ) -> Result<(), IndexedDbError> {
        let said_str = said.to_string();
        let mut receipts_map = self.trans_receipts.borrow_mut();

        // Get existing receipts or create new vector
        let existing_receipts = receipts_map.entry(said_str.clone()).or_default();

        // Add new receipts that aren't already present
        let mut new_receipts = Vec::new();
        for receipt in receipts {
            if !existing_receipts.contains(receipt) {
                existing_receipts.push(receipt.clone());
                new_receipts.push(receipt.clone());
            }
        }

        // Queue for IndexedDB persistence if we have new receipts
        if !new_receipts.is_empty() {
            let mut pending = self.pending_operations.borrow_mut();
            pending.push(PendingOperation::StoreTransReceipt {
                said: said_str,
                receipts: new_receipts,
            });
        }

        Ok(())
    }

    // Insert non-transferable receipts
    pub fn insert_nontrans_receipt(
        &self,
        said: &SelfAddressingIdentifier,
        receipts: &[Nontransferable]
    ) -> Result<(), IndexedDbError> {
        let said_str = said.to_string();
        let mut receipts_map = self.nontrans_receipts.borrow_mut();

        // Get existing receipts or create new vector
        let existing_receipts = receipts_map.entry(said_str.clone()).or_default();

        // Add new receipts that aren't already present
        let mut new_receipts = Vec::new();
        for receipt in receipts {
            if !existing_receipts.contains(receipt) {
                existing_receipts.push(receipt.clone());
                new_receipts.push(receipt.clone());
            }
        }

        // Queue for IndexedDB persistence
        if !new_receipts.is_empty() {
            let mut pending = self.pending_operations.borrow_mut();
            pending.push(PendingOperation::StoreNontransReceipt {
                said: said_str.clone(),
                receipts: new_receipts,
            });
        }

        Ok(())
    }

    pub fn get_nontrans_couplets_by_key(
        &self,
        key_prefix: &SelfAddressingIdentifier
    ) -> Result<Option<impl Iterator<Item = Nontransferable>>, IndexedDbError> {
        let key_str = key_prefix.to_string();
        let receipts_map = self.nontrans_receipts.borrow();

        if let Some(receipts) = receipts_map.get(&key_str) {
            if receipts.is_empty() {
                Ok(None)
            } else {
                // Return cloned receipts
                Ok(Some(receipts.clone().into_iter()))
            }
        } else {
            Ok(None)
        }
    }
}

// Helper function to flush pending operations to IndexedDB
fn flush_pending_operations(
    db: &web_sys::IdbDatabase,
    operations: &Vec<PendingOperation>,
) {
    for op in operations {
        match op {
            PendingOperation::StoreEvent { said, event, signatures } => {
                // Store event
                if let Ok(transaction) = db.transaction_with_str_and_mode(
                    "events",
                    web_sys::IdbTransactionMode::Readwrite,
                ) {
                    if let Ok(store) = transaction.object_store("events") {
                        // Convert event to JsValue
                        let value = js_sys::Object::new();
                        let _ = js_sys::Reflect::set(&value, &"said".into(), &said.clone().into());
                        let _ = js_sys::Reflect::set(
                            &value,
                            &"event".into(),
                            &JsValue::from_str(&format!("{:?}", serde_cbor::to_vec(&event).unwrap())),
                        );

                        if let Err(e) = store.put_with_key(&value, &said.into()) {
                            log::error!("Failed to store event in IndexedDB: {:?}", e);
                        }
                    }
                }

                // Store signatures
                if let Ok(transaction) = db.transaction_with_str_and_mode(
                    "signatures",
                    web_sys::IdbTransactionMode::Readwrite,
                ) {
                    if let Ok(store) = transaction.object_store("signatures") {
                        let value = js_sys::Object::new();
                        let _ = js_sys::Reflect::set(&value, &"said".into(), &said.into());
                        let _ = js_sys::Reflect::set(
                            &value,
                            &"signatures".into(),
                            &JsValue::from_str(&serde_json::to_string(&signatures).unwrap_or_default()),
                        );

                        if let Err(e) = store.put_with_key(&value, &said.into()) {
                            log::error!("Failed to store signatures in IndexedDB: {:?}", e);
                        }
                    }
                }
            },
            PendingOperation::StoreNontransReceipt { said, receipts } => {
                if let Ok(transaction) = db.transaction_with_str_and_mode(
                    "nontrans_receipts",
                    web_sys::IdbTransactionMode::Readwrite,
                ) {
                    if let Ok(store) = transaction.object_store("nontrans_receipts") {
                        // Trust our in-memory representation and just update the database
                        // This works because we load all data at startup and keep it in sync
                        let value = js_sys::Object::new();
                        let _ = js_sys::Reflect::set(&value, &"said".into(), &said.into());
                        let _ = js_sys::Reflect::set(
                            &value,
                            &"receipts".into(),
                            &JsValue::from_str(&serde_json::to_string(&receipts).unwrap_or_default()),
                        );

                        if let Err(e) = store.put_with_key(&value, &said.into()) {
                            log::error!("Failed to store receipts in IndexedDB: {:?}", e);
                        }
                    }
                }
            },
            PendingOperation::StoreTransReceipt { said, receipts } => {
                if let Ok(transaction) = db.transaction_with_str_and_mode(
                    "trans_receipts",
                    web_sys::IdbTransactionMode::Readwrite,
                ) {
                    if let Ok(store) = transaction.object_store("trans_receipts") {
                        // Trust our in-memory representation and just update the database
                        // This works because we load all data at startup and keep it in sync
                        let value = js_sys::Object::new();
                        let _ = js_sys::Reflect::set(&value, &"said".into(), &said.into());
                        let _ = js_sys::Reflect::set(
                            &value,
                            &"receipts".into(),
                            &JsValue::from_str(&serde_json::to_string(&receipts).unwrap_or_default()),
                        );

                        if let Err(e) = store.put_with_key(&value, &said.into()) {
                            log::error!("Failed to store transferable receipts in IndexedDB: {:?}", e);
                        }
                    }
                }
            },
            PendingOperation::RemoveReceipt { said, remaining_receipts } => {
                if let Ok(transaction) = db.transaction_with_str_and_mode(
                    "nontrans_receipts",
                    web_sys::IdbTransactionMode::Readwrite,
                ) {
                    if let Ok(store) = transaction.object_store("nontrans_receipts") {
                        // We already have the remaining receipts, so we can just update/delete
                        if remaining_receipts.is_empty() {
                            // Delete the entire entry if no receipts remain
                            if let Err(e) = store.delete(&said.into()) {
                                log::error!("Failed to delete receipts from IndexedDB: {:?}", e);
                            }
                        } else {
                            // Update with remaining receipts
                            let value = js_sys::Object::new();
                            let _ = js_sys::Reflect::set(&value, &"said".into(), &said.into());
                            let _ = js_sys::Reflect::set(
                                &value,
                                &"receipts".into(),
                                &JsValue::from_str(&serde_json::to_string(&remaining_receipts).unwrap_or_default()),
                            );

                            if let Err(e) = store.put_with_key(&value, &said.into()) {
                                log::error!("Failed to update receipts in IndexedDB: {:?}", e);
                            }
                        }
                    }
                }
            }
        }
    }
}

// Helper function to load events from IndexedDB
fn load_events(db: &web_sys::IdbDatabase, events: Rc<RefCell<HashMap<String, TimestampedSignedEventMessage>>>) {
    if let Ok(transaction) = db.transaction_with_str_and_mode(
        "events",
        web_sys::IdbTransactionMode::Readwrite,
    ) {
        if let Ok(store) = transaction.object_store("events") {
            if let Ok(request) = store.get_all() {
                let callback = Closure::wrap(Box::new(move |event: web_sys::Event| {
                    if let Some(result) = event.target()
                        .and_then(|t| t.dyn_into::<web_sys::IdbRequest>().ok())
                        .and_then(|r| r.result().ok())
                    {
                        if let Ok(array) = result.dyn_into::<js_sys::Array>() {
                            let mut events_map = events.borrow_mut();
                            for i in 0..array.length() {
                                if let Ok(item) = array.get(i).dyn_into::<js_sys::Object>() {
                                    if let (Some(said), Some(event_str)) = (
                                        js_sys::Reflect::get(&item, &"said".into())
                                            .ok()
                                            .and_then(|v| v.as_string()),
                                        js_sys::Reflect::get(&item, &"event".into())
                                            .ok()
                                            .and_then(|v| v.as_string()),
                                    ) {
                                        let mut ev_vec: Vec<u8> = vec![];
                                        let mut ev_str = event_str.clone();
                                        ev_str.remove(0);
                                        ev_str.pop();
                                        for e in ev_str.split(", ") {
                                            ev_vec.push(e.parse().unwrap());
                                        }
                                        if let Ok(event) = serde_cbor::from_slice::<TimestampedSignedEventMessage>(&ev_vec) {
                                            // let mut events_mut = events.borrow_mut();
                                            events_map.insert(said, event);
                                        } else {
                                            log::warn!("Failed to parse event: {}", event_str);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }) as Box<dyn FnMut(_)>);

                request.set_onsuccess(Some(callback.as_ref().unchecked_ref()));
                callback.forget();
            }
        }
    }
}

fn load_signatures(db: &web_sys::IdbDatabase, signatures: Rc<RefCell<HashMap<String, Vec<IndexedSignature>>>>) {
    if let Ok(transaction) = db.transaction_with_str_and_mode(
        "signatures",
        web_sys::IdbTransactionMode::Readwrite,
    ) {
        if let Ok(store) = transaction.object_store("signatures") {
            if let Ok(request) = store.get_all() {
                let callback = Closure::wrap(Box::new(move |event: web_sys::Event| {
                    if let Some(result) = event.target()
                        .and_then(|t| t.dyn_into::<web_sys::IdbRequest>().ok())
                        .and_then(|r| r.result().ok())
                    {
                        if let Ok(array) = result.dyn_into::<js_sys::Array>() {
                            let mut sigs_map = signatures.borrow_mut();
                            for i in 0..array.length() {
                                if let Ok(item) = array.get(i).dyn_into::<js_sys::Object>() {
                                    if let (Ok(digest), Ok(sigs_json)) = (
                                        js_sys::Reflect::get(&item, &"digest".into()),
                                        js_sys::Reflect::get(&item, &"signatures".into())
                                    ) {
                                        if let (Some(digest_str), Some(sigs_str)) = (
                                            digest.as_string(),
                                            sigs_json.as_string()
                                        ) {
                                            if let Ok(sig_data) = serde_json::from_str::<Vec<IndexedSignature>>(&sigs_str) {
                                                sigs_map.insert(digest_str, sig_data);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }) as Box<dyn FnMut(_)>);

                request.set_onsuccess(Some(callback.as_ref().unchecked_ref()));
                callback.forget();
            }
        }
    }
}

// Helper function to load transferable receipts from IndexedDB
fn load_trans_receipts(db: &web_sys::IdbDatabase, receipts: Rc<RefCell<std::collections::HashMap<String, Vec<Transferable>>>>) {
    if let Ok(transaction) = db.transaction_with_str_and_mode(
        "trans_receipts",
        web_sys::IdbTransactionMode::Readwrite,
    ) {
        if let Ok(store) = transaction.object_store("trans_receipts") {
            if let Ok(request) = store.get_all() {
                let callback = Closure::wrap(Box::new(move |event: web_sys::Event| {
                    if let Some(result) = event.target()
                        .and_then(|t| t.dyn_into::<web_sys::IdbRequest>().ok())
                        .and_then(|r| r.result().ok())
                    {
                        if let Ok(array) = result.dyn_into::<js_sys::Array>() {
                            let mut receipts_map = receipts.borrow_mut();
                            for i in 0..array.length() {
                                if let Ok(item) = array.get(i).dyn_into::<js_sys::Object>() {
                                    if let (Ok(digest), Ok(receipts_json)) = (
                                        js_sys::Reflect::get(&item, &"digest".into()),
                                        js_sys::Reflect::get(&item, &"receipts".into())
                                    ) {
                                        if let (Some(digest_str), Some(receipts_str)) = (
                                            digest.as_string(),
                                            receipts_json.as_string()
                                        ) {
                                            if let Ok(trans_receipts) = serde_json::from_str::<Vec<Transferable>>(&receipts_str) {
                                                receipts_map.insert(digest_str, trans_receipts);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }) as Box<dyn FnMut(_)>);

                request.set_onsuccess(Some(callback.as_ref().unchecked_ref()));
                callback.forget();
            }
        }
    }
}

// Helper function to load non-transferable receipts from IndexedDB
fn load_nontrans_receipts(db: &web_sys::IdbDatabase, receipts: Rc<RefCell<HashMap<String, Vec<Nontransferable>>>>) {
    if let Ok(transaction) = db.transaction_with_str_and_mode(
        "nontrans_receipts",
        web_sys::IdbTransactionMode::Readwrite,
    ) {
        if let Ok(store) = transaction.object_store("nontrans_receipts") {
            if let Ok(request) = store.get_all() {
                let callback = Closure::wrap(Box::new(move |event: web_sys::Event| {
                    if let Some(result) = event.target()
                        .and_then(|t| t.dyn_into::<web_sys::IdbRequest>().ok())
                        .and_then(|r| r.result().ok())
                    {
                        if let Ok(array) = result.dyn_into::<js_sys::Array>() {
                            let mut receipts_map = receipts.borrow_mut();
                            for i in 0..array.length() {
                                if let Ok(item) = array.get(i).dyn_into::<js_sys::Object>() {
                                    if let (Ok(digest), Ok(receipts_json)) = (
                                        js_sys::Reflect::get(&item, &"digest".into()),
                                        js_sys::Reflect::get(&item, &"receipts".into())
                                    ) {
                                        if let (Some(digest_str), Some(receipts_str)) = (
                                            digest.as_string(),
                                            receipts_json.as_string()
                                        ) {
                                            if let Ok(nontrans_receipts) = serde_json::from_str::<Vec<Nontransferable>>(&receipts_str) {
                                                receipts_map.insert(digest_str, nontrans_receipts);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }) as Box<dyn FnMut(_)>);

                request.set_onsuccess(Some(callback.as_ref().unchecked_ref()));
                callback.forget();
            }
        }
    }
}

// Set up background flush for IndexedDB
fn setup_background_flush(
    db: web_sys::IdbDatabase,
    pending_ops: Rc<RefCell<Vec<PendingOperation>>>,
    flush_flag: Rc<Cell<bool>>
) {
    // Create interval function
    let interval_callback = Closure::wrap(Box::new(move || {
        if !flush_flag.get() {
            flush_flag.set(true);

            spawn_local({
                let db = db.clone();
                let pending = pending_ops.clone();
                let flag = flush_flag.clone();

                async move {
                    // Get operations to process
                    let ops_to_flush = {
                        let mut pending_borrow = pending.borrow_mut();
                        if pending_borrow.is_empty() {
                            Vec::new()
                        } else {
                            pending_borrow.drain(..).collect::<Vec<_>>()
                        }
                    };

                    // Process operations
                    if !ops_to_flush.is_empty() {
                        flush_pending_operations(&db, &ops_to_flush);
                    }

                    flag.set(false);
                }
            });
        }
    }) as Box<dyn FnMut()>);

    // Set up interval
    let window = web_sys::window().unwrap();
    let _ = window.set_interval_with_callback_and_timeout_and_arguments_0(
        interval_callback.as_ref().unchecked_ref(),
        1000
    );

    interval_callback.forget();
}
