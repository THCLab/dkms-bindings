use cesrox::primitives::CesrPrimitive;
use keri_core::{database::SequencedEventDatabase, prefix::IdentifierPrefix};
use said::SelfAddressingIdentifier;
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    rc::Rc,
    sync::{
        Arc, RwLock,
    },
};

use std::str::FromStr;

use super::IndexedDbError;

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

use web_sys::{
    IdbDatabase, IdbOpenDbRequest,
};

// SAFETY: In WebAssembly context, there's no true threading, so these are safe
unsafe impl Send for IndexedDbSnDatabase {}
unsafe impl Sync for IndexedDbSnDatabase {}

pub struct IndexedDbSnDatabase {
    data: RwLock<HashMap<(String, u64), Vec<SelfAddressingIdentifier>>>,
    pending_operations: Rc<RefCell<Vec<PendingOperation>>>,
}

enum PendingOperation {
    Insert {
        id_str: String,
        sn: u64,
        digest: SelfAddressingIdentifier,
    },
    Remove {
        id_str: String,
        sn: u64,
    },
}

impl SequencedEventDatabase for IndexedDbSnDatabase {
    type DatabaseType = ();
    type Error = IndexedDbError;
    type DigestIter = Box<dyn Iterator<Item = SelfAddressingIdentifier>>;

    fn new(
        _db: Arc<Self::DatabaseType>,
        table_name: &'static str,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let pending_operations = Rc::new(RefCell::new(Vec::new()));
        let flush_in_progress = Rc::new(Cell::new(false));

        // Create database instance
        let window =
            web_sys::window().expect("should have a window in this context");
        let factory = match window.indexed_db() {
            Ok(Some(factory)) => factory,
            Ok(None) => {
                log::error!("IndexedDB not available");
                return Ok(Self {
                    data: RwLock::new(HashMap::new()),
                    pending_operations,
                });
            }
            Err(e) => {
                log::error!("Failed to get IndexedDB: {:?}", e);
                return Ok(Self {
                    data: RwLock::new(HashMap::new()),
                    pending_operations,
                });
            }
        };

        let db_name = table_name.to_string();
        let pending_ops_clone = pending_operations.clone();
        let flush_flag = flush_in_progress.clone();

        // Initialize database asynchronously
        match factory.open(&db_name) {
            Ok(open_request) => {
                let upgrade_needed_cb = Closure::wrap(Box::new(
                    move |event: web_sys::IdbVersionChangeEvent| {
                        let target = event.target().unwrap();
                        let request =
                            target.dyn_into::<IdbOpenDbRequest>().unwrap();
                        if let Some(db) = request
                            .result()
                            .ok()
                            .and_then(|res| res.dyn_into::<IdbDatabase>().ok())
                        {
                            // Create object store with keyPath configuration
                            let mut params =
                                web_sys::IdbObjectStoreParameters::new();
                            params.key_path(Some(&JsValue::from_str("key")));

                            if let Err(e) = db
                                .create_object_store_with_optional_parameters(
                                    "events", &params,
                                )
                            {
                                log::error!(
                                    "Failed to create events store: {:?}",
                                    e
                                );
                            }
                        }
                    },
                )
                    as Box<dyn FnMut(_)>);

                open_request.set_onupgradeneeded(Some(
                    upgrade_needed_cb.as_ref().unchecked_ref(),
                ));
                upgrade_needed_cb.forget();

                let data_clone = Rc::new(RefCell::new(HashMap::new()));

                // Handle database initialization
                let success_cb = Closure::wrap(Box::new(
                    move |event: web_sys::Event| {
                        let target = event.target().unwrap();
                        let request =
                            target.dyn_into::<IdbOpenDbRequest>().unwrap();
                        if let Ok(db) = request
                            .result()
                            .and_then(|res| res.dyn_into::<IdbDatabase>())
                        {
                            // Load existing data from IndexedDB
                            let db_for_load = db.clone();
                            let data_weak = Rc::downgrade(&data_clone);
                            spawn_local(async move {
                                if let Some(data_ref) = data_weak.upgrade() {
                                    load_existing_data(&db_for_load, data_ref)
                                        .await;
                                }
                            });

                            // Start background persistence process
                            let db_clone = db.clone();
                            let pending_ops = pending_ops_clone.clone();
                            let flush_flag = flush_flag.clone();

                            // Schedule periodic persistence
                            let interval_callback =
                                Closure::wrap(Box::new(move || {
                                    let db = db_clone.clone();
                                    let pending = pending_ops.clone();
                                    let flag = flush_flag.clone();

                                    if !flag.get() {
                                        flag.set(true);

                                        spawn_local({
                                            let pending = pending.clone();
                                            let flag = flag.clone();

                                            async move {
                                                let ops_to_flush = {
                                                    let mut pending_borrow =
                                                        pending.borrow_mut();
                                                    if pending_borrow.is_empty()
                                                    {
                                                        Vec::new()
                                                    } else {
                                                        pending_borrow
                                                            .drain(..)
                                                            .collect()
                                                    }
                                                };

                                                if !ops_to_flush.is_empty() {
                                                    flush_pending_operations(
                                                        &db,
                                                        ops_to_flush,
                                                    )
                                                    .await;
                                                }

                                                flag.set(false);
                                            }
                                        });
                                    }
                                })
                                    as Box<dyn FnMut()>);

                            // Set up interval using JavaScript
                            let interval_fn = interval_callback
                                .as_ref()
                                .unchecked_ref::<js_sys::Function>(
                            );
                            let _interval_id = window.set_interval_with_callback_and_timeout_and_arguments_0(
                            interval_fn,
                            1000
                        ).expect("should be able to set interval");
                            interval_callback.forget(); // Prevent closure from being dropped
                        }
                    },
                )
                    as Box<dyn FnMut(_)>);

                open_request
                    .set_onsuccess(Some(success_cb.as_ref().unchecked_ref()));
                success_cb.forget();

                // Handle errors
                let error_cb =
                    Closure::wrap(Box::new(|event: web_sys::Event| {
                        log::error!("Failed to open IndexedDB: {:?}", event);
                    }) as Box<dyn FnMut(_)>);

                open_request
                    .set_onerror(Some(error_cb.as_ref().unchecked_ref()));
                error_cb.forget();
            }
            Err(e) => {
                log::error!("Failed to create open request: {:?}", e);
            }
        }

        Ok(Self {
            data: RwLock::new(HashMap::new()),
            pending_operations,
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
        data.entry(key.clone()).or_default().push(digest.clone());

        let mut pending = self.pending_operations.borrow_mut();
        pending.push(PendingOperation::Insert {
            id_str: key.0,
            sn: key.1,
            digest: digest.clone(),
        });

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

            // Queue the remove operation for IndexedDB
            let mut pending = self.pending_operations.borrow_mut();
            pending.push(PendingOperation::Remove {
                id_str: key.0.clone(),
                sn: key.1,
            });

            if digests.is_empty() {
                data.remove(&key);
            }
            Ok(())
        } else {
            Err(IndexedDbError::NotFound(format!("{:?} at sn {}", id, sn)))
        }
    }
}

// Helper function to flush pending operations to IndexedDB
async fn flush_pending_operations(
    db: &IdbDatabase,
    operations: Vec<PendingOperation>,
) {
    if let Ok(transaction) = db.transaction_with_str_and_mode(
        "events",
        web_sys::IdbTransactionMode::Readwrite,
    ) {
        if let Ok(store) = transaction.object_store("events") {
            for op in operations {
                match op {
                    PendingOperation::Insert { id_str, sn, digest } => {
                        let key = format!("{}:{}", id_str, sn);
                        let value = js_sys::Object::new();
                        let _ = js_sys::Reflect::set(
                            &value,
                            &"key".into(),
                            &key.into(),
                        );
                        let _ = js_sys::Reflect::set(
                            &value,
                            &"id".into(),
                            &id_str.into(),
                        );
                        let _ = js_sys::Reflect::set(
                            &value,
                            &"sn".into(),
                            &sn.into(),
                        );
                        let _ = js_sys::Reflect::set(
                            &value,
                            &"digest".into(),
                            &digest.to_str().into(),
                        );

                        if let Err(e) = store.put(&value) {
                            log::error!(
                                "Failed to store event in IndexedDB: {:?}",
                                e
                            );
                        }
                    }
                    PendingOperation::Remove { id_str, sn } => {
                        let key = format!("{}:{}", id_str, sn);
                        if let Err(e) = store.delete(&key.into()) {
                            log::error!(
                                "Failed to remove event from IndexedDB: {:?}",
                                e
                            );
                        }
                    }
                }
            }
        }
    }
}

async fn load_existing_data(
    db: &IdbDatabase,
    data: Rc<RefCell<HashMap<(String, u64), Vec<SelfAddressingIdentifier>>>>,
) {
    if let Ok(transaction) = db.transaction_with_str_and_mode(
        "events",
        web_sys::IdbTransactionMode::Readonly,
    ) {
        if let Ok(store) = transaction.object_store("events") {
            // Use a cursor to iterate through all objects in the store
            let request = match store.open_cursor() {
                Ok(request) => request,
                Err(e) => {
                    log::error!("Failed to open cursor: {:?}", e);
                    return;
                }
            };

            // Set up callbacks for cursor iteration
            let cursor_success = Closure::wrap(Box::new(
                move |event: web_sys::Event| {
                    let target =
                        event.target().expect("event should have target");
                    let request = target
                        .dyn_into::<web_sys::IdbRequest>()
                        .expect("target should be IdbRequest");

                    if let Ok(cursor_val) = request.result() {
                        if !cursor_val.is_null() {
                            if let Ok(cursor) = cursor_val
                                .dyn_into::<web_sys::IdbCursorWithValue>(
                            ) {
                                if let Ok(value) = cursor.value() {
                                    // Extract data from the stored object
                                    if let (
                                        Some(id),
                                        Some(sn),
                                        Some(digest_str),
                                    ) = (
                                        js_sys::Reflect::get(
                                            &value,
                                            &"id".into(),
                                        )
                                        .ok()
                                        .and_then(|v| v.as_string()),
                                        js_sys::Reflect::get(
                                            &value,
                                            &"sn".into(),
                                        )
                                        .ok()
                                        .and_then(|v| {
                                            if !v.is_bigint() {
                                                return None;
                                            }
                                            let bingint = v
                                                .dyn_into::<js_sys::BigInt>()
                                                .ok()?;
                                            bingint.to_string(10).ok().and_then(
                                                |s| {
                                                    s.as_string()
                                                        .unwrap()
                                                        .parse::<u64>()
                                                        .ok()
                                                },
                                            )
                                        }),
                                        js_sys::Reflect::get(
                                            &value,
                                            &"digest".into(),
                                        )
                                        .ok()
                                        .and_then(|v| v.as_string()),
                                    ) {
                                        if let Ok(digest) =
                                            SelfAddressingIdentifier::from_str(
                                                &digest_str,
                                            )
                                        {
                                            let mut data_mut =
                                                data.borrow_mut();
                                            data_mut
                                                .entry((id, sn))
                                                .or_default()
                                                .push(digest);
                                        } else {
                                            log::warn!(
                                                "Failed to parse digest: {}",
                                                digest_str
                                            );
                                        }
                                    } else {
                                        log::warn!(
                                            "Stored object missing required fields"
                                        );
                                    }
                                }

                                // Move to next record
                                if let Err(e) = cursor.continue_() {
                                    log::error!(
                                        "Error continuing cursor: {:?}",
                                        e
                                    );
                                }
                            }
                        }
                    } else {
                        log::error!("Failed to get cursor from result");
                    }
                },
            )
                as Box<dyn FnMut(_)>);

            let cursor_error =
                Closure::wrap(Box::new(move |event: web_sys::Event| {
                    log::error!("Error in IndexedDB cursor: {:?}", event);
                }) as Box<dyn FnMut(_)>);

            // Set callbacks
            request
                .set_onsuccess(Some(cursor_success.as_ref().unchecked_ref()));
            request.set_onerror(Some(cursor_error.as_ref().unchecked_ref()));

            // Keep closures alive
            cursor_success.forget();
            cursor_error.forget();
        }
    }
}
