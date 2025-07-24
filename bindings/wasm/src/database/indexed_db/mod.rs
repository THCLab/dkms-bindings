pub mod escrow_database;
pub mod sn_database;
pub mod logging;

use std::sync::Arc;
use std::rc::Rc;
use std::cell::{RefCell, Cell};
use keri_core::event::receipt::Receipt;
use keri_core::oobi::{LocationScheme, Scheme};
use keri_core::prefix::SeedPrefix;
use keri_sdk::TelEventDatabase;
use said::sad::SerializationFormats;
use teliox::event::verifiable_event::VerifiableEvent;
use teliox::event::Event;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

use keri_core::{
    event::KeyEvent,
    event_message::{
        msg::KeriEvent,
        signature::Transferable,
        signed_event_message::{
            SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt,
        },
    },
    prefix::IdentifierPrefix,
    state::IdentifierState,
};

use keri_core::database::{timestamped, EscrowCreator, EscrowDatabase, EventDatabase, QueryParameters, LogDatabase, SequencedEventDatabase};
use escrow_database::IndexedDbEscrowDatabase;
use logging::IndexedDbLogDatabase;
use sn_database::IndexedDbSnDatabase;
use said::SelfAddressingIdentifier;

#[derive(Debug, thiserror::Error)]
pub enum IndexedDbError {
    #[error("Failed to save to database")]
    DatabaseSaveFailed(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Event not found")]
    MissingDigest,
    #[error("Lock error")]
    LockError,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Failed to encode")]
    EncodingFailed(String),
    #[error("Failed to decode")]
    DecodingFailed(String),
    #[error("Key format error")]
    KeyFormatError,
}

#[derive(Debug, Clone)]
pub struct IdentifierRecord {
    pub said: IdentifierPrefix,
    pub seed: SeedPrefix,
    pub watcher_oobi: Option<LocationScheme>,
}

pub struct IndexedDbDatabase {
    log_db: Arc<IndexedDbLogDatabase>,
    key_states: Rc<RefCell<std::collections::HashMap<String, IdentifierState>>>,
    kels: Rc<RefCell<std::collections::HashMap<(String, u64), SelfAddressingIdentifier>>>,
    pending_operations: Rc<RefCell<Vec<PendingDbOperation>>>,
    flush_in_progress: Rc<Cell<bool>>,
    tel_events: Rc<RefCell<std::collections::HashMap<IdentifierPrefix, Vec<VerifiableEvent>>>>,
    management_events: Rc<RefCell<std::collections::HashMap<IdentifierPrefix, Vec<VerifiableEvent>>>>,
    identifiers: Rc<RefCell<std::collections::HashMap<String, IdentifierRecord>>>,
}

enum PendingDbOperation {
    SaveKeyState { id: String, state: IdentifierState },
    SaveKel { id: String, sn: u64, digest: SelfAddressingIdentifier },
    SaveTelEvent { id: IdentifierPrefix, event: VerifiableEvent },
    SaveManagementEvent { id: IdentifierPrefix, event: VerifiableEvent },
    SaveIdentifier { alias: String, said: IdentifierPrefix, seed: SeedPrefix },
    RemoveIdentifier { alias: String },
    AddWatcher { alias: String, watcher_oobi: LocationScheme },
}

// SAFETY: In WebAssembly context, there's no true threading, so these are safe
unsafe impl Send for IndexedDbDatabase {}
unsafe impl Sync for IndexedDbDatabase {}

impl Default for IndexedDbDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl IndexedDbDatabase {
    pub fn get_identifiers(&self) -> Vec<(String, IdentifierRecord)> {
        self.identifiers.borrow().iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    pub fn get_identifier(&self, alias: &str) -> Option<IdentifierRecord> {
        self.identifiers.borrow().get(alias).cloned()
    }

    pub fn new() -> Self {
        let log_db = Arc::new(IndexedDbLogDatabase::new(Arc::new(())).unwrap());
        let key_states = Rc::new(RefCell::new(std::collections::HashMap::new()));
        let kels = Rc::new(RefCell::new(std::collections::HashMap::new()));
        let pending_operations = Rc::new(RefCell::new(Vec::new()));
        let flush_in_progress = Rc::new(Cell::new(false));
        let tel_events = Rc::new(RefCell::new(std::collections::HashMap::new()));
        let management_events = Rc::new(RefCell::new(std::collections::HashMap::new()));
        let identifiers = Rc::new(RefCell::new(std::collections::HashMap::new()));
        
        let mut db = Self {
            log_db,
            key_states,
            kels,
            pending_operations,
            flush_in_progress,
            tel_events,
            management_events,
            identifiers,
        };
        
        db.init_db("keri_indexed_db");
        
        db
    }
    
    fn init_db(&mut self, db_name: &str) {
        let window = web_sys::window().expect("should have a window");
        
        // Get IndexedDB factory
        if let Ok(Some(factory)) = window.indexed_db() {
            let pending_ops = self.pending_operations.clone();
            let flush_flag = self.flush_in_progress.clone();
            let key_states = self.key_states.clone();
            let kels = self.kels.clone();
            let tel_events = self.tel_events.clone();
            let management_events = self.management_events.clone();
            let identifiers = self.identifiers.clone();
            
            // Open database
            if let Ok(request) = factory.open(db_name) {
                // Handle database upgrade needed (first time opening)
                let upgrade_needed_cb = Closure::wrap(Box::new(move |event: web_sys::IdbVersionChangeEvent| {
                    if let Some(db) = event.target()
                        .and_then(|t| t.dyn_into::<web_sys::IdbOpenDbRequest>().ok())
                        .and_then(|r| r.result().ok())
                        .and_then(|r| r.dyn_into::<web_sys::IdbDatabase>().ok()) 
                    {
                        // Create stores similar to redb tables
                        let _ = db.create_object_store("kels");
                        let _ = db.create_object_store("key_states");
                        let _ = db.create_object_store("tel_events");
                        let _ = db.create_object_store("management_events");
                        let _ = db.create_object_store("identifiers");
                    }
                }) as Box<dyn FnMut(_)>);
                
                request.set_onupgradeneeded(Some(upgrade_needed_cb.as_ref().unchecked_ref()));
                upgrade_needed_cb.forget();
                
                // Handle successful open
                let success_cb = {
                    let this_db = Rc::new(RefCell::new(None::<web_sys::IdbDatabase>));
                    let this_db_clone = this_db.clone();
                    
                    Closure::wrap(Box::new(move |event: web_sys::Event| {
                        if let Some(db) = event.target()
                            .and_then(|t| t.dyn_into::<web_sys::IdbOpenDbRequest>().ok())
                            .and_then(|r| r.result().ok())
                            .and_then(|r| r.dyn_into::<web_sys::IdbDatabase>().ok()) 
                        {
                            *this_db_clone.borrow_mut() = Some(db.clone());
                            
                            // Load key states and kels from IndexedDB
                            load_key_states(&db, key_states.clone());
                            load_kels(&db, kels.clone());
                            load_tel_events(&db, tel_events.clone());
                            load_management_events(&db, management_events.clone());
                            load_identifiers(&db, identifiers.clone());
                            
                            // Set up background flush
                            setup_background_flush(db, pending_ops.clone(), flush_flag.clone());
                        }
                    }) as Box<dyn FnMut(_)>)
                };
                
                request.set_onsuccess(Some(success_cb.as_ref().unchecked_ref()));
                success_cb.forget();
                
                // Handle errors
                let error_cb = Closure::wrap(Box::new(|event: web_sys::Event| {
                    log::error!("Failed to open IndexedDB: {:?}", event);
                }) as Box<dyn FnMut(_)>);
                
                request.set_onerror(Some(error_cb.as_ref().unchecked_ref()));
                error_cb.forget();
            }
        }
    }

    pub fn add_identifier(&self, alias: &str, said: &IdentifierPrefix, seed: &SeedPrefix) -> Result<(), IndexedDbError> {
        let record = IdentifierRecord {
            said: said.clone(),
            seed: seed.clone(),
            watcher_oobi: None,
        };

        self.identifiers.borrow_mut().insert(alias.to_string(), record);
        self.pending_operations.borrow_mut().push(PendingDbOperation::SaveIdentifier {
            alias: alias.to_string(),
            said: said.clone(),
            seed: seed.clone()
        });

        Ok(())
    }

    pub fn update_identifier_watcher(&self, alias: &str, watcher_oobi: LocationScheme) -> Result<(), IndexedDbError> {
        if let Some(record) = self.identifiers.borrow_mut().get_mut(alias) {
            record.watcher_oobi = Some(watcher_oobi.clone());
            self.pending_operations.borrow_mut().push(PendingDbOperation::AddWatcher {
                alias: alias.to_string(),
                watcher_oobi: watcher_oobi.clone()
            });
            Ok(())
        } else {
            Err(IndexedDbError::NotFound(format!("Identifier with alias {} not found", alias)))
        }
    }

    pub fn update_identifier_alias(&self, old_alias: &str, new_alias: &str) -> Result<(), IndexedDbError> {
        let mut identifiers = self.identifiers.borrow_mut();
        if let Some(record) = identifiers.remove(old_alias) {
            identifiers.insert(new_alias.to_string(), record.clone());
            self.pending_operations.borrow_mut().push(PendingDbOperation::SaveIdentifier {
                alias: new_alias.to_string(),
                said: record.said.clone(),
                seed: record.seed.clone()
            });
            self.pending_operations.borrow_mut().push(PendingDbOperation::RemoveIdentifier {
                alias: old_alias.to_string(),
            });
            Ok(())
        } else {
            Err(IndexedDbError::NotFound(format!("Identifier with alias {} not found", old_alias)))
        }
    }
}

// Helper function to load key states from IndexedDB
fn load_key_states(db: &web_sys::IdbDatabase, key_states: Rc<RefCell<std::collections::HashMap<String, IdentifierState>>>) {
    if let Ok(transaction) = db.transaction_with_str_and_mode(
        "key_states",
        web_sys::IdbTransactionMode::Readwrite,
    ) {
        if let Ok(store) = transaction.object_store("key_states") {
            if let Ok(request) = store.get_all() {
                let callback = Closure::wrap(Box::new(move |event: web_sys::Event| {
                    if let Some(result) = event.target()
                        .and_then(|t| t.dyn_into::<web_sys::IdbRequest>().ok())
                        .and_then(|r| r.result().ok())
                    {
                        if let Ok(array) = result.dyn_into::<js_sys::Array>() {
                            let mut states = key_states.borrow_mut();
                            for i in 0..array.length() {
                                if let Ok(item) = array.get(i).dyn_into::<js_sys::Object>() {
                                    if let (Ok(id), Ok(state_bytes)) = (
                                        js_sys::Reflect::get(&item, &"id".into()),
                                        js_sys::Reflect::get(&item, &"state".into())
                                    ) {
                                        if let (Some(id_str), Some(state_str)) = (
                                            id.as_string(),
                                            state_bytes.as_string()
                                        ) {
                                            if let Ok(state) = serde_json::from_str::<IdentifierState>(&state_str) {
                                                states.insert(id_str, state);
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

// Helper function to load KELs from IndexedDB
fn load_kels(db: &web_sys::IdbDatabase, kels: Rc<RefCell<std::collections::HashMap<(String, u64), SelfAddressingIdentifier>>>) {
    if let Ok(transaction) = db.transaction_with_str_and_mode(
        "kels",
        web_sys::IdbTransactionMode::Readwrite,
    ) {
        if let Ok(store) = transaction.object_store("kels") {
            if let Ok(request) = store.get_all() {
                let callback = Closure::wrap(Box::new(move |event: web_sys::Event| {
                    if let Some(result) = event.target()
                        .and_then(|t| t.dyn_into::<web_sys::IdbRequest>().ok())
                        .and_then(|r| r.result().ok())
                    {
                        if let Ok(array) = result.dyn_into::<js_sys::Array>() {
                            let mut kel_map = kels.borrow_mut();
                            for i in 0..array.length() {
                                if let Ok(item) = array.get(i).dyn_into::<js_sys::Object>() {
                                    if let (Ok(id), Ok(sn), Ok(digest)) = (
                                        js_sys::Reflect::get(&item, &"id".into()),
                                        js_sys::Reflect::get(&item, &"sn".into()),
                                        js_sys::Reflect::get(&item, &"digest".into())
                                    ) {
                                        if let (Some(id_str), Some(sn_num), Some(digest_str)) = (
                                            id.as_string(),
                                            sn.as_f64().map(|n| n as u64),
                                            digest.as_string()
                                        ) {
                                            if let Ok(said) = digest_str.parse::<SelfAddressingIdentifier>() {
                                                kel_map.insert((id_str, sn_num), said);
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

// Helper function to load TEL events from IndexedDB
fn load_tel_events(db: &web_sys::IdbDatabase, tel_events: Rc<RefCell<std::collections::HashMap<IdentifierPrefix, Vec<VerifiableEvent>>>>) {
    if let Ok(transaction) = db.transaction_with_str_and_mode(
        "tel_events",
        web_sys::IdbTransactionMode::Readwrite,
    ) {
        if let Ok(store) = transaction.object_store("tel_events") {
            if let Ok(request) = store.get_all() {
                let callback = Closure::wrap(Box::new(move |event: web_sys::Event| {
                    if let Some(result) = event.target()
                        .and_then(|t| t.dyn_into::<web_sys::IdbRequest>().ok())
                        .and_then(|r| r.result().ok())
                    {
                        if let Ok(array) = result.dyn_into::<js_sys::Array>() {
                            let mut events_map = tel_events.borrow_mut();
                            for i in 0..array.length() {
                                if let Ok(item) = array.get(i).dyn_into::<js_sys::Object>() {
                                    if let (Ok(id), Ok(event_json)) = (
                                        js_sys::Reflect::get(&item, &"id".into()),
                                        js_sys::Reflect::get(&item, &"event".into())
                                    ) {
                                        if let (Some(id_str), Some(event_str)) = (
                                            id.as_string(),
                                            event_json.as_string()
                                        ) {
                                            if let (Ok(prefix), Ok(event)) = (
                                                id_str.parse::<IdentifierPrefix>(),
                                                serde_json::from_str::<VerifiableEvent>(&event_str)
                                            ) {
                                                events_map.entry(prefix)
                                                    .or_default()
                                                    .push(event);
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

// Helper function to load management events from IndexedDB
fn load_management_events(db: &web_sys::IdbDatabase, management_events: Rc<RefCell<std::collections::HashMap<IdentifierPrefix, Vec<VerifiableEvent>>>>) {
    if let Ok(transaction) = db.transaction_with_str_and_mode(
        "management_events",
        web_sys::IdbTransactionMode::Readwrite,
    ) {
        if let Ok(store) = transaction.object_store("management_events") {
            if let Ok(request) = store.get_all() {
                let callback = Closure::wrap(Box::new(move |event: web_sys::Event| {
                    if let Some(result) = event.target()
                        .and_then(|t| t.dyn_into::<web_sys::IdbRequest>().ok())
                        .and_then(|r| r.result().ok())
                    {
                        if let Ok(array) = result.dyn_into::<js_sys::Array>() {
                            let mut events_map = management_events.borrow_mut();
                            for i in 0..array.length() {
                                if let Ok(item) = array.get(i).dyn_into::<js_sys::Object>() {
                                    if let (Ok(id), Ok(event_json)) = (
                                        js_sys::Reflect::get(&item, &"id".into()),
                                        js_sys::Reflect::get(&item, &"event".into())
                                    ) {
                                        if let (Some(id_str), Some(event_str)) = (
                                            id.as_string(),
                                            event_json.as_string()
                                        ) {
                                            if let (Ok(prefix), Ok(event)) = (
                                                id_str.parse::<IdentifierPrefix>(),
                                                serde_json::from_str::<VerifiableEvent>(&event_str)
                                            ) {
                                                events_map.entry(prefix)
                                                    .or_default()
                                                    .push(event);
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

fn load_identifiers(db: &web_sys::IdbDatabase, identifiers: Rc<RefCell<std::collections::HashMap<String, IdentifierRecord>>>) {
    if let Ok(transaction) = db.transaction_with_str_and_mode(
        "identifiers",
        web_sys::IdbTransactionMode::Readwrite,
    ) {
        if let Ok(store) = transaction.object_store("identifiers") {
            if let Ok(request) = store.open_cursor() {
                let callback = Closure::wrap(Box::new(move |event: web_sys::Event| {
                    if let Some(cursor_result) = event.target()
                        .and_then(|t| t.dyn_into::<web_sys::IdbRequest>().ok())
                        .and_then(|r| r.result().ok())
                    {
                        // If we have a cursor
                        if !cursor_result.is_undefined() {
                            if let Ok(cursor) = cursor_result.dyn_into::<web_sys::IdbCursorWithValue>() {
                                let key = cursor.key().ok()
                                    .and_then(|k| k.as_string())
                                    .unwrap_or_default();
                                let item = cursor.value().unwrap();

                                if let (Ok(said), Ok(seed), watcher_url, watcher_eid, watcher_scheme) = (
                                    js_sys::Reflect::get(&item, &"said".into()),
                                    js_sys::Reflect::get(&item, &"seed".into()),
                                    js_sys::Reflect::get(&item, &"watcher_url".into()),
                                    js_sys::Reflect::get(&item, &"watcher_eid".into()),
                                    js_sys::Reflect::get(&item, &"watcher_scheme".into())
                                ) {
                                    if let (Some(said_str), Some(seed_str)) = (
                                        said.as_string(),
                                        seed.as_string()
                                    ) {
                                        if let (Ok(prefix), Ok(seed)) = (
                                            said_str.parse::<IdentifierPrefix>(),
                                            seed_str.parse::<SeedPrefix>(),
                                        ) {
                                            let mut watcher_oobi = None;
                                            if let (Ok(watcher_url), Ok(watcher_eid), Ok(watcher_scheme)) = (watcher_url, watcher_eid, watcher_scheme) {
                                                if let (Some(url_str), Some(eid_str), Some(scheme_str)) = (
                                                    watcher_url.as_string(),
                                                    watcher_eid.as_string(),
                                                    watcher_scheme.as_string()
                                                ) {
                                                    if let (Ok(url), Ok(eid), Ok(scheme)) = (
                                                        url::Url::parse(&url_str),
                                                        eid_str.parse::<IdentifierPrefix>(),
                                                        scheme_str.parse::<Scheme>()
                                                    ) {
                                                        watcher_oobi = Some(LocationScheme::new(eid, scheme, url));
                                                    }
                                                }
                                            }

                                            let id = IdentifierRecord {
                                                said: prefix,
                                                seed,
                                                watcher_oobi,
                                            };

                                            identifiers.borrow_mut().insert(key, id);
                                        }
                                    }
                                }

                                if let Err(e) = cursor.continue_() {
                                    log::error!("Error continuing cursor: {:?}", e);
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
    pending_ops: Rc<RefCell<Vec<PendingDbOperation>>>,
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
                        // Handle key state operations
                        let key_state_ops: Vec<_> = ops_to_flush.iter().filter_map(|op| {
                            if let PendingDbOperation::SaveKeyState { id, state } = op {
                                Some((id.clone(), state.clone()))
                            } else {
                                None
                            }
                        }).collect();
                        
                        if !key_state_ops.is_empty() && db.transaction_with_str_and_mode("key_states", web_sys::IdbTransactionMode::Readwrite).is_ok() {
                            let transaction = db.transaction_with_str_and_mode("key_states", web_sys::IdbTransactionMode::Readwrite).unwrap();
                            if let Ok(store) = transaction.object_store("key_states") {
                                for (id, state) in key_state_ops {
                                    let value = js_sys::Object::new();
                                    js_sys::Reflect::set(&value, &"id".into(), &id.clone().into()).unwrap();
                                    

                                    // Serialize state to JSON string
                                    if let Ok(state_json) = serde_json::to_string(&state) {
                                        js_sys::Reflect::set(&value, &"state".into(), &state_json.into()).unwrap();
                                        
                                        if let Err(e) = store.put_with_key(&value, &id.into()) {
                                            log::error!("Failed to store key state in IndexedDB: {:?}", e);
                                        }
                                    }
                                }
                            }
                        }
                        
                        // Handle KEL operations
                        let kel_ops: Vec<_> = ops_to_flush.iter().filter_map(|op| {
                            match op {
                                PendingDbOperation::SaveKel { id, sn, digest } => {
                                    Some(("save", id.clone(), *sn, digest.clone()))
                                }
                                _ => None
                            }
                        }).collect();
                        
                        if !kel_ops.is_empty() && db.transaction_with_str_and_mode("kels", web_sys::IdbTransactionMode::Readwrite).is_ok() {
                            let transaction = db.transaction_with_str_and_mode("kels", web_sys::IdbTransactionMode::Readwrite).unwrap();
                            if let Ok(store) = transaction.object_store("kels") {
                                for (op_type, id, sn, digest) in kel_ops {
                                    let key = format!("{}:{}", id, sn);
                                    
                                    if op_type == "save" {
                                        let value = js_sys::Object::new();
                                        js_sys::Reflect::set(&value, &"id".into(), &id.into()).unwrap();
                                        js_sys::Reflect::set(&value, &"sn".into(), &(sn as f64).into()).unwrap();
                                        js_sys::Reflect::set(&value, &"digest".into(), &digest.to_string().into()).unwrap();
                                        
                                        if let Err(e) = store.put_with_key(&value, &key.into()) {
                                            log::error!("Failed to store KEL in IndexedDB: {:?}", e);
                                        }
                                    } else if let Err(e) = store.delete(&key.into()) {
                                        log::error!("Failed to remove KEL from IndexedDB: {:?}", e);
                                    }
                                }
                            }
                        }

                        // Handle TEL event operations
                        let tel_ops: Vec<_> = ops_to_flush.iter().filter_map(|op| {
                            if let PendingDbOperation::SaveTelEvent { id, event } = op {
                                Some((id.clone(), event.clone()))
                            } else {
                                None
                            }
                        }).collect();

                        if !tel_ops.is_empty() && db.transaction_with_str_and_mode("tel_events", web_sys::IdbTransactionMode::Readwrite).is_ok() {
                            let transaction = db.transaction_with_str_and_mode("tel_events", web_sys::IdbTransactionMode::Readwrite).unwrap();
                            if let Ok(store) = transaction.object_store("tel_events") {
                                for (id, event) in tel_ops {
                                    let key = id.to_string();
                                    let value = js_sys::Object::new();
                                    js_sys::Reflect::set(&value, &"id".into(), &key.clone().into()).unwrap();
                                    
                                    // Serialize event to JSON string
                                    if let Ok(event_json) = serde_json::to_string(&event) {
                                        js_sys::Reflect::set(&value, &"event".into(), &event_json.into()).unwrap();
                                        
                                        if let Err(e) = store.put_with_key(&value, &key.into()) {
                                            log::error!("Failed to store TEL event in IndexedDB: {:?}", e);
                                        }
                                    }
                                }
                            }
                        }
                        
                        // Handle management event operations
                        let mgmt_ops: Vec<_> = ops_to_flush.iter().filter_map(|op| {
                            if let PendingDbOperation::SaveManagementEvent { id, event } = op {
                                Some((id.clone(), event.clone()))
                            } else {
                                None
                            }
                        }).collect();

                        if !mgmt_ops.is_empty() && db.transaction_with_str_and_mode("management_events", web_sys::IdbTransactionMode::Readwrite).is_ok() {
                            let transaction = db.transaction_with_str_and_mode("management_events", web_sys::IdbTransactionMode::Readwrite).unwrap();
                            if let Ok(store) = transaction.object_store("management_events") {
                                for (id, event) in mgmt_ops {
                                    let key = id.to_string();
                                    let value = js_sys::Object::new();
                                    js_sys::Reflect::set(&value, &"id".into(), &key.clone().into()).unwrap();
                                    
                                    // Serialize event to JSON string
                                    if let Ok(event_json) = serde_json::to_string(&event) {
                                        js_sys::Reflect::set(&value, &"event".into(), &event_json.into()).unwrap();
                                        
                                        if let Err(e) = store.put_with_key(&value, &key.into()) {
                                            log::error!("Failed to store management event in IndexedDB: {:?}", e);
                                        }
                                    }
                                }
                            }
                        }

                        // Handle identifiers event operations
                        let id_ops: Vec<_> = ops_to_flush.iter().filter_map(|op| {
                            if let PendingDbOperation::SaveIdentifier { alias, said, seed } = op {
                                Some((alias.clone(), said.clone(), seed.clone()))
                            } else {
                                None
                            }
                        }).collect();

                        if !id_ops.is_empty() && db.transaction_with_str_and_mode("identifiers", web_sys::IdbTransactionMode::Readwrite).is_ok() {
                            let transaction = db.transaction_with_str_and_mode("identifiers", web_sys::IdbTransactionMode::Readwrite).unwrap();
                            if let Ok(store) = transaction.object_store("identifiers") {
                                for (alias, said, seed) in id_ops {
                                    let value = js_sys::Object::new();

                                    let key = alias.to_string();
                                    let said = said.to_string();
                                    js_sys::Reflect::set(&value, &"said".into(), &said.clone().into()).unwrap();
                                    let seed_str = serde_json::to_string(&seed).unwrap();
                                    if let serde_json::Value::String(seed) = serde_json::from_str(&seed_str).unwrap() {
                                        js_sys::Reflect::set(&value, &"seed".into(), &seed.clone().into()).unwrap();
                                    }
                                    if let Err(e) = store.put_with_key(&value, &key.into()) {
                                        log::error!("Failed to store management event in IndexedDB: {:?}", e);
                                    }
                                }
                            }
                        }

                        let id_alias_ops: Vec<_> = ops_to_flush.iter().filter_map(|op| {
                            if let PendingDbOperation::RemoveIdentifier { alias } = op {
                                Some(alias.clone())
                            } else {
                                None
                            }
                        }).collect();

                        if !id_alias_ops.is_empty() && db.transaction_with_str_and_mode("identifiers", web_sys::IdbTransactionMode::Readwrite).is_ok() {
                            let transaction = db.transaction_with_str_and_mode("identifiers", web_sys::IdbTransactionMode::Readwrite).unwrap();
                            if let Ok(store) = transaction.object_store("identifiers") {
                                for alias in id_alias_ops {
                                    if let Err(e) = store.delete(&alias.into()) {
                                        log::error!("Failed to delete old identifier alias in IndexedDB: {:?}", e);
                                    }
                                }
                            }
                        }

                        let id_watcher_ops: Vec<_> = ops_to_flush.iter().filter_map(|op| {
                            if let PendingDbOperation::AddWatcher { alias, watcher_oobi } = op {
                                Some((alias.clone(), watcher_oobi.clone()))
                            } else {
                                None
                            }
                        }).collect();

                        if !id_watcher_ops.is_empty() && db.transaction_with_str_and_mode("identifiers", web_sys::IdbTransactionMode::Readwrite).is_ok() {
                            if let Ok(transaction) = db.transaction_with_str_and_mode("identifiers", web_sys::IdbTransactionMode::Readwrite) {
                                for (alias, watcher_oobi) in id_watcher_ops {
                                    if let Ok(store) = transaction.object_store("identifiers") {
                                        // First get the existing record
                                        let request = store.get(&alias.clone().into());
                                        let alias_clone = alias.clone();
                                        let on_success = Closure::wrap(Box::new(move |event: web_sys::Event| {
                                            if let Some(result) = event.target()
                                                .and_then(|t| t.dyn_into::<web_sys::IdbRequest>().ok())
                                                .and_then(|r| r.result().ok())
                                            {
                                                // If we have an existing record
                                                if !result.is_undefined() {
                                                    if let Ok(item) = result.dyn_into::<js_sys::Object>() {
                                                        // Update the watcher_url field
                                                        js_sys::Reflect::set(&item, &"watcher_url".into(), &watcher_oobi.url.to_string().clone().into()).unwrap_or_else(|_| {
                                                            log::error!("Failed to set watcher_url property");
                                                            false
                                                        });
                                                        js_sys::Reflect::set(&item, &"watcher_eid".into(), &watcher_oobi.eid.to_string().clone().into()).unwrap_or_else(|_| {
                                                            log::error!("Failed to set watcher_eid property");
                                                            false
                                                        });
                                                        if let serde_json::Value::String(scheme_str) = serde_json::to_value(&watcher_oobi.scheme).unwrap() {
                                                            js_sys::Reflect::set(&item, &"watcher_scheme".into(), &scheme_str.clone().into()).unwrap_or_else(|_| {
                                                                log::error!("Failed to set watcher_scheme property");
                                                                false
                                                            });
                                                        }
                                                        // Put it back in the store
                                                        let transaction = store.transaction();
                                                        if let Ok(store_again) = transaction.object_store("identifiers") {
                                                            let key_for_put = alias_clone.clone();
                                                            if let Err(e) = store_again.put_with_key(&item, &key_for_put.into()) {
                                                                log::error!("Failed to update identifier watcher URL in IndexedDB: {:?}", e);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }) as Box<dyn FnMut(_)>);

                                        request.unwrap().set_onsuccess(Some(on_success.as_ref().unchecked_ref()));
                                        on_success.forget();
                                    }
                                }
                            }
                        }
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

impl EventDatabase for IndexedDbDatabase {
    type Error = IndexedDbError;
    type LogDatabaseType = IndexedDbLogDatabase;

    fn get_log_db(&self) -> Arc<Self::LogDatabaseType> {
        self.log_db.clone()
    }

    fn add_kel_finalized_event(
        &self,
        signed_event: SignedEventMessage,
        _id: &IdentifierPrefix,
    ) -> Result<(), Self::Error> {
        self.update_key_state(&signed_event.event_message)?;
        self.log_db.log_event_with_new_transaction(&signed_event)?;
        self.save_to_kel(&signed_event.event_message)?;
        
        Ok(())
    }

    fn add_receipt_t(
        &self,
        receipt: SignedTransferableReceipt,
        _id: &IdentifierPrefix,
    ) -> Result<(), Self::Error> {
        let digest = receipt.body.receipted_event_digest;
        let transferable = Transferable::Seal(receipt.validator_seal, receipt.signatures);
        self.log_db.insert_trans_receipt(&digest, &[transferable])
    }

    fn add_receipt_nt(
        &self,
        receipt: SignedNontransferableReceipt,
        _id: &IdentifierPrefix,
    ) -> Result<(), Self::Error> {
        let receipted_event_digest = receipt.body.receipted_event_digest;
        let receipts = receipt.signatures;
        self.log_db.insert_nontrans_receipt(&receipted_event_digest, &receipts)
    }

    fn get_key_state(&self, id: &IdentifierPrefix) -> Option<IdentifierState> {
        let key = id.to_string();
        self.key_states.borrow().get(&key).cloned()
    }

    fn get_kel_finalized_events(
        &self,
        params: QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = timestamped::TimestampedSignedEventMessage>> {
        match params {
            QueryParameters::BySn { id, sn } => {
                self.get_kel(&id, sn, 1)
                    .map(|events| events.into_iter())
            }
            QueryParameters::Range { id, start, limit } => {
                self.get_kel(&id, start, limit)
                    .map(|events| events.into_iter())
            }
            QueryParameters::All { id } => {
                self.get_full_kel(id)
                    .map(|events| events.into_iter())
            }
        }
    }

    fn get_receipts_t(
        &self,
        params: QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = Transferable>> {
        match params {
            QueryParameters::BySn { id, sn } => {
                let key = id.to_string();
                let digest = self.kels.borrow().get(&(key, sn)).cloned()?;
                let receipts = self.log_db.get_trans_receipts(&digest).ok()?;
                Some(receipts.collect::<Vec<_>>().into_iter())
            }
            QueryParameters::Range {..} | QueryParameters::All {..} => {
                // For simplicity, not implementing range/all queries for receipts
                None
            }
        }
    }

    fn get_receipts_nt(
        &self,
        params: QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = SignedNontransferableReceipt>> {
        match params {
            QueryParameters::BySn { id, sn } => self
                .get_nontrans_receipts_range(&id.to_string(), sn, 1)
                .ok()
                .map(|e| e.into_iter()),
            QueryParameters::Range { id, start, limit } => self
                .get_nontrans_receipts_range(&id.to_string(), start, limit)
                .ok()
                .map(|e| e.into_iter()),
            QueryParameters::All { id } => self
                .get_nontrans_receipts_range(&id.to_string(), 0, u64::MAX)
                .ok()
                .map(|e| e.into_iter()),
        }
    }

    fn accept_to_kel(&self, event: &KeriEvent<KeyEvent>) -> Result<(), Self::Error> {
        self.save_to_kel(event)?;
        self.update_key_state(event)?;
        Ok(())
    }

    fn save_reply(&self, _reply: keri_core::query::reply_event::SignedReply) -> Result<(), Self::Error> {
        // Not implemented for WASM yet
        Ok(())
    }

    fn get_reply(&self, _id: &IdentifierPrefix, _from_who: &IdentifierPrefix) -> Option<keri_core::query::reply_event::SignedReply> {
        // Not implemented for WASM yet
        None
    }
}

// Helper methods for IndexedDbDatabase
impl IndexedDbDatabase {
    fn save_to_kel(&self, event: &KeriEvent<KeyEvent>) -> Result<(), IndexedDbError> {
        let digest = event.digest()
            .map_err(|_| IndexedDbError::EncodingFailed("Could not get event digest".to_string()))?;
        
        let id = event.data.prefix.to_string();
        let sn = event.data.sn;
        
        // Save to in-memory map
        self.kels.borrow_mut().insert((id.clone(), sn), digest.clone());
        
        // Queue for persistence
        self.pending_operations.borrow_mut().push(PendingDbOperation::SaveKel { 
            id, 
            sn, 
            digest 
        });
        
        Ok(())
    }
    
    fn update_key_state(&self, event: &KeriEvent<KeyEvent>) -> Result<(), IndexedDbError> {
        let id = event.data.prefix.to_string();
        
        // Get current state or default
        let key_state = self.key_states.borrow()
            .get(&id)
            .cloned()
            .unwrap_or_default();
        
        // Apply event to state
        let updated_state = key_state.apply(event)
            .map_err(|_| IndexedDbError::DatabaseSaveFailed("Failed to apply event to key state".to_string()))?;
        
        // Save updated state
        self.key_states.borrow_mut().insert(id.clone(), updated_state.clone());
        
        // Queue for persistence
        self.pending_operations.borrow_mut().push(PendingDbOperation::SaveKeyState { 
            id, 
            state: updated_state 
        });
        
        Ok(())
    }
    
    #[allow(dead_code)]
    fn get_event_digest(&self, id: &IdentifierPrefix, sn: u64) -> Option<SelfAddressingIdentifier> {
        let key = id.to_string();
        self.kels.borrow().get(&(key, sn)).cloned()
    }
    
    fn get_kel(&self, id: &IdentifierPrefix, from: u64, limit: u64) -> Option<Vec<timestamped::TimestampedSignedEventMessage>> {
        let id_str = id.to_string();
        let mut events = Vec::new();
        
        for sn in from..(from + limit) {
            if let Some(digest) = self.kels.borrow().get(&(id_str.clone(), sn)) {
                if let Ok(Some(event)) = self.log_db.get_signed_event(digest) {
                    events.push(event);
                }
            } else {
                break;
            }
        }
        
        if events.is_empty() {
            None
        } else {
            Some(events)
        }
    }
    
    fn get_full_kel(&self, id: &IdentifierPrefix) -> Option<Vec<timestamped::TimestampedSignedEventMessage>> {
        let id_str = id.to_string();
        let mut events = Vec::new();
        let mut sn = 0;
        
        // Find all events for this identifier
        while let Some(digest) = self.kels.borrow().get(&(id_str.clone(), sn)) {
            if let Ok(Some(event)) = self.log_db.get_signed_event(digest) {
                events.push(event);
                sn += 1;
            } else {
                break;
            }
        };
        
        if events.is_empty() {
            None
        } else {
            Some(events)
        }
    }

    fn get_nontrans_receipts_range(
        &self,
        id: &str,
        start: u64,
        limit: u64,
    ) -> Result<Vec<SignedNontransferableReceipt>, IndexedDbError> {
        // Get all sequence numbers in the range for this identifier
        let mut receipts = Vec::new();
        let kels_map = self.kels.borrow();
        
        // Collect sequence numbers first to make iteration easier
        let mut sequence_numbers = Vec::new();
        for sn in start..(start + limit) {
            if kels_map.contains_key(&(id.to_string(), sn)) {
                sequence_numbers.push(sn);
            }
        }
        
        // Create receipts for each event in the range
        for sn in sequence_numbers {
            if let Some(said) = kels_map.get(&(id.to_string(), sn)) {
                // Get non-transferable couplets for this digest
                if let Ok(nontrans) = self.log_db.get_nontrans_couplets_by_key(said) {
                    // Parse identifier
                    if let Ok(identifier) = id.parse::<IdentifierPrefix>() {
                        // Create receipt
                        let rct = Receipt::new(SerializationFormats::JSON, said.clone(), identifier, start);
                        
                        // Create signed receipt with signatures
                        let signatures = nontrans
                            .unwrap()
                            .collect();
                        
                        let signed_receipt = SignedNontransferableReceipt {
                            body: rct,
                            signatures,
                        };
                        
                        receipts.push(signed_receipt);
                    }
                }
            }
        }
        
        Ok(receipts)
    }
}

impl EscrowCreator for IndexedDbDatabase {
    type EscrowDatabaseType = IndexedDbEscrowDatabase;

    fn create_escrow_db(&self, table_name: &'static str) -> Self::EscrowDatabaseType {
        
        IndexedDbEscrowDatabase::new(
            Arc::new(IndexedDbSnDatabase::new(Arc::new(()), table_name).unwrap()),
            self.log_db.clone(),
        )
    }
}

impl TelEventDatabase for IndexedDbDatabase {
    fn new(_path: impl AsRef<std::path::Path>) -> Result<Self, teliox::error::Error>
    where
        Self: Sized,
    {
        Ok(Self::new())
    }

    fn add_new_event(&self, event: VerifiableEvent, id: &IdentifierPrefix) -> Result<(), teliox::error::Error> {
        match event.event {
            Event::Vc(_) => {
                self.tel_events.borrow_mut()
                    .entry(id.clone())
                    .or_default()
                    .push(event.clone());
                
                self.pending_operations.borrow_mut()
                    .push(PendingDbOperation::SaveTelEvent { 
                        id: id.clone(), 
                        event: event.clone()
                    });
            },
            Event::Management(_) => {
                self.management_events.borrow_mut()
                    .entry(id.clone())
                    .or_default()
                    .push(event.clone());
                
                self.pending_operations.borrow_mut()
                    .push(PendingDbOperation::SaveManagementEvent { 
                        id: id.clone(), 
                        event: event.clone()
                    });
            },
        }
        
        Ok(())
    }

    fn get_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = VerifiableEvent>> {
        if let Some(events) = self.tel_events.borrow().get(id) {
            return Some(events.clone().into_iter());
        }

        None
    }

    fn get_management_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = VerifiableEvent>> {
        if let Some(events) = self.management_events.borrow().get(id) {
            return Some(events.clone().into_iter());
        }
        
        None
    }
}
