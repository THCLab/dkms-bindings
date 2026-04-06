use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Arc, OnceLock};

mod error;
mod identifier;
mod inception_configuration;
mod rotation_configuration;
mod utils;

use error::Error;
use identifier::Identifier;
use inception_configuration::InceptionConfiguration;
use keri_controller::{controller::PostgresController, BasicPrefix, LocationScheme};
use rotation_configuration::RotationConfiguration;
use utils::{key::PublicKey, signature::Signature};

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn rt() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Runtime::new().expect("tokio runtime init failed")
    })
}

// Helper function to convert C string to Rust String
unsafe fn c_str_to_string(c_str: *const c_char) -> Result<String, Error> {
    if c_str.is_null() {
        return Err(Error::NullPointer);
    }
    CStr::from_ptr(c_str)
        .to_str()
        .map(|s| s.to_string())
        .map_err(|_| Error::InvalidUtf8)
}

// Helper function to convert Rust String to C string
fn string_to_c_str(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// Helper function to convert byte slice to C buffer
fn bytes_to_c_buffer(data: Vec<u8>) -> *mut u8 {
    let mut boxed = data.into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    std::mem::forget(boxed);
    ptr
}

// Opaque pointer types for Go
pub struct CController {
    inner: PostgresController,
}

pub struct CIdentifier {
    inner: Arc<std::sync::Mutex<Identifier>>,
}

pub struct CInceptionConfig {
    inner: InceptionConfiguration,
}

pub struct CRotationConfig {
    inner: RotationConfiguration,
}

// Controller functions
#[no_mangle]
pub extern "C" fn controller_new_postgres(
    db_url: *const c_char,
    initial_oobis: *const c_char,
) -> *mut CController {
    unsafe {
        let db_url_str = match c_str_to_string(db_url) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };

        let initial_oobis_str = if initial_oobis.is_null() {
            None
        } else {
            c_str_to_string(initial_oobis).ok()
        };

        let mut config = keri_controller::config::ControllerConfig::default();
        if let Some(oobis) = initial_oobis_str {
            if let Ok(location) = serde_json::from_str::<LocationScheme>(&oobis) {
                config.initial_oobis = vec![location];
            }
        }

        match rt().block_on(PostgresController::new_postgres(&db_url_str, config)) {
            Ok(controller) => Box::into_raw(Box::new(CController { inner: controller })),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

#[no_mangle]
pub extern "C" fn controller_free(controller: *mut CController) {
    if !controller.is_null() {
        unsafe {
            let _ = Box::from_raw(controller);
        }
    }
}

#[no_mangle]
pub extern "C" fn controller_incept(
    controller: *mut CController,
    config: *mut CInceptionConfig,
    out_len: *mut usize,
) -> *mut u8 {
    if controller.is_null() || config.is_null() || out_len.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        let ctrl = &(*controller).inner;
        let cfg = &(*config).inner;

        let rt = rt();

        let result = rt.block_on(async {
            let curr_keys = cfg
                .current_public_keys
                .iter()
                .map(|k| k.parse::<BasicPrefix>())
                .collect::<Result<Vec<_>, _>>()
                .ok()?;

            let next_keys = cfg
                .next_public_keys
                .iter()
                .map(|k| k.parse::<BasicPrefix>())
                .collect::<Result<Vec<_>, _>>()
                .ok()?;

            let witnesses = cfg
                .witnesses_location
                .iter()
                .map(|wit| serde_json::from_str::<LocationScheme>(wit).ok())
                .collect::<Option<Vec<_>>>()?;

            ctrl.incept(
                curr_keys,
                next_keys,
                witnesses,
                cfg.witness_threshold as u64,
            )
            .await
            .ok()
        });

        match result {
            Some(icp) => {
                let bytes = icp.as_bytes().to_vec();
                *out_len = bytes.len();
                bytes_to_c_buffer(bytes)
            }
            None => std::ptr::null_mut(),
        }
    }
}

#[no_mangle]
pub extern "C" fn controller_finalize_inception(
    controller: *mut CController,
    icp_event: *const u8,
    icp_event_len: usize,
    signature: *const c_char,
) -> *mut CIdentifier {
    if controller.is_null() || icp_event.is_null() || signature.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        let ctrl = &(*controller).inner;
        let event_slice = std::slice::from_raw_parts(icp_event, icp_event_len);

        let sig_str = match c_str_to_string(signature) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };

        let sig = match Signature::from_string(&sig_str) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };

        match ctrl.finalize_incept(event_slice, &sig.to_prefix()) {
            Ok(identifier) => Box::into_raw(Box::new(CIdentifier {
                inner: Arc::new(std::sync::Mutex::new(Identifier { inner: identifier })),
            })),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

// InceptionConfiguration functions
#[no_mangle]
pub extern "C" fn inception_config_new() -> *mut CInceptionConfig {
    Box::into_raw(Box::new(CInceptionConfig {
        inner: InceptionConfiguration::new(),
    }))
}

#[no_mangle]
pub extern "C" fn inception_config_free(config: *mut CInceptionConfig) {
    if !config.is_null() {
        unsafe {
            let _ = Box::from_raw(config);
        }
    }
}

#[no_mangle]
pub extern "C" fn inception_config_add_current_key(
    config: *mut CInceptionConfig,
    key: *const c_char,
) {
    if config.is_null() || key.is_null() {
        return;
    }
    unsafe {
        if let Ok(key_str) = c_str_to_string(key) {
            (*config).inner.current_public_keys.push(key_str);
        }
    }
}

#[no_mangle]
pub extern "C" fn inception_config_add_next_key(config: *mut CInceptionConfig, key: *const c_char) {
    if config.is_null() || key.is_null() {
        return;
    }
    unsafe {
        if let Ok(key_str) = c_str_to_string(key) {
            (*config).inner.next_public_keys.push(key_str);
        }
    }
}

#[no_mangle]
pub extern "C" fn inception_config_add_witness(
    config: *mut CInceptionConfig,
    witness_oobi: *const c_char,
) {
    if config.is_null() || witness_oobi.is_null() {
        return;
    }
    unsafe {
        if let Ok(oobi_str) = c_str_to_string(witness_oobi) {
            (*config).inner.witnesses_location.push(oobi_str);
        }
    }
}

#[no_mangle]
pub extern "C" fn inception_config_set_witness_threshold(
    config: *mut CInceptionConfig,
    threshold: u32,
) {
    if !config.is_null() {
        unsafe {
            (*config).inner.witness_threshold = threshold;
        }
    }
}

// RotationConfiguration functions
#[no_mangle]
pub extern "C" fn rotation_config_new() -> *mut CRotationConfig {
    Box::into_raw(Box::new(CRotationConfig {
        inner: RotationConfiguration::new(),
    }))
}

#[no_mangle]
pub extern "C" fn rotation_config_free(config: *mut CRotationConfig) {
    if !config.is_null() {
        unsafe {
            let _ = Box::from_raw(config);
        }
    }
}

#[no_mangle]
pub extern "C" fn rotation_config_add_current_key(
    config: *mut CRotationConfig,
    key: *const c_char,
) {
    if config.is_null() || key.is_null() {
        return;
    }

    unsafe {
        if let Ok(key_str) = c_str_to_string(key) {
            (*config).inner.current_public_keys.push(key_str);
        }
    }
}

#[no_mangle]
pub extern "C" fn rotation_config_add_next_key(config: *mut CRotationConfig, key: *const c_char) {
    if config.is_null() || key.is_null() {
        return;
    }

    unsafe {
        if let Ok(key_str) = c_str_to_string(key) {
            (*config).inner.next_public_keys.push(key_str);
        }
    }
}

#[no_mangle]
pub extern "C" fn rotation_config_add_witness_to_add(
    config: *mut CRotationConfig,
    witness_oobi: *const c_char,
) {
    if config.is_null() || witness_oobi.is_null() {
        return;
    }

    unsafe {
        if let Ok(witness_str) = c_str_to_string(witness_oobi) {
            (*config).inner.witnesses_to_add.push(witness_str);
        }
    }
}

#[no_mangle]
pub extern "C" fn rotation_config_add_witness_to_remove(
    config: *mut CRotationConfig,
    witness_id: *const c_char,
) {
    if config.is_null() || witness_id.is_null() {
        return;
    }

    unsafe {
        if let Ok(witness_str) = c_str_to_string(witness_id) {
            (*config).inner.witnesses_to_remove.push(witness_str);
        }
    }
}

#[no_mangle]
pub extern "C" fn rotation_config_set_witness_threshold(
    config: *mut CRotationConfig,
    threshold: u32,
) {
    if config.is_null() {
        return;
    }

    unsafe {
        (*config).inner.witness_threshold = threshold;
    }
}

// Identifier functions
#[no_mangle]
pub extern "C" fn identifier_free(identifier: *mut CIdentifier) {
    if !identifier.is_null() {
        unsafe {
            let _ = Box::from_raw(identifier);
        }
    }
}

#[no_mangle]
pub extern "C" fn identifier_get_id(identifier: *mut CIdentifier) -> *mut c_char {
    if identifier.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        let locked = (*identifier).inner.lock().unwrap();
        let id_str = locked.inner.id().to_string();
        string_to_c_str(id_str)
    }
}

#[no_mangle]
pub extern "C" fn identifier_get_kel(identifier: *mut CIdentifier) -> *mut c_char {
    if identifier.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        let locked = (*identifier).inner.lock().unwrap();
        match locked.get_kel() {
            Ok(kel_str) => string_to_c_str(kel_str),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

#[no_mangle]
pub extern "C" fn identifier_rotate(
    identifier: *mut CIdentifier,
    config: *mut CRotationConfig,
    out_len: *mut usize,
) -> *mut u8 {
    if identifier.is_null() || config.is_null() || out_len.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        let rt = rt();

        let locked = (*identifier).inner.lock().unwrap();
        let cfg = &(*config).inner;

        let result = rt.block_on(async { locked.rotate(cfg).await.ok() });

        match result {
            Some(bytes) => {
                *out_len = bytes.len();
                bytes_to_c_buffer(bytes)
            }
            None => std::ptr::null_mut(),
        }
    }
}

#[no_mangle]
pub extern "C" fn identifier_finalize_rotation(
    identifier: *mut CIdentifier,
    rot_event: *const u8,
    rot_event_len: usize,
    signature: *const c_char,
) -> bool {
    if identifier.is_null() || rot_event.is_null() || signature.is_null() {
        return false;
    }

    unsafe {
        let rt = rt();

        let mut locked = (*identifier).inner.lock().unwrap();
        let event_slice = std::slice::from_raw_parts(rot_event, rot_event_len);

        let sig_str = match c_str_to_string(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let sig = match Signature::from_string(&sig_str) {
            Ok(s) => s,
            Err(_) => return false,
        };

        rt.block_on(async {
            locked
                .finalize_rotation(event_slice, &sig.to_prefix())
                .await
                .is_ok()
        })
    }
}

#[no_mangle]
pub extern "C" fn identifier_notify_witnesses(identifier: *mut CIdentifier) -> bool {
    if identifier.is_null() {
        return false;
    }

    unsafe {
        let rt = rt();

        let mut locked = (*identifier).inner.lock().unwrap();

        rt.block_on(async { locked.notify_witnesses().await.is_ok() })
    }
}

/// Queries the mailbox of each witness for pending receipts.
/// Returns a JSON array of base64-encoded query event bytes, one per witness.
/// Returns null on error.
#[no_mangle]
pub extern "C" fn identifier_query_mailbox(identifier: *mut CIdentifier) -> *mut c_char {
    if identifier.is_null() {
        return std::ptr::null_mut();
    }
    unsafe {
        let locked = (*identifier).inner.lock().unwrap();
        match rt().block_on(locked.query_mailbox()) {
            Ok(events) => {
                let encoded: Vec<String> = events
                    .into_iter()
                    .map(|e| base64::encode(&e))
                    .collect();
                match serde_json::to_string(&encoded) {
                    Ok(s) => string_to_c_str(s),
                    Err(_) => std::ptr::null_mut(),
                }
            }
            Err(_) => std::ptr::null_mut(),
        }
    }
}

/// Finalizes mailbox queries by processing the receipts.
/// `queries_b64_json`: JSON array of base64-encoded query events (from `identifier_query_mailbox`).
/// `signatures_json`: JSON array of signature strings, one per query.
/// Returns true on success.
#[no_mangle]
pub extern "C" fn identifier_finalize_query_mailbox(
    identifier: *mut CIdentifier,
    queries_b64_json: *const c_char,
    signatures_json: *const c_char,
) -> bool {
    if identifier.is_null() {
        return false;
    }
    unsafe {
        let queries_str = match c_str_to_string(queries_b64_json) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let sigs_str = match c_str_to_string(signatures_json) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let b64_queries: Vec<String> = match serde_json::from_str(&queries_str) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let sig_strs: Vec<String> = match serde_json::from_str(&sigs_str) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let queries: Vec<Vec<u8>> = match b64_queries
            .iter()
            .map(|s| base64::decode(s).map_err(|_| ()))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(v) => v,
            Err(_) => return false,
        };
        let sigs: Vec<keri_controller::SelfSigningPrefix> = match sig_strs
            .iter()
            .map(|s| s.parse().map_err(|_| ()))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(v) => v,
            Err(_) => return false,
        };
        let mut locked = (*identifier).inner.lock().unwrap();
        match rt().block_on(locked.finalize_query_mailbox(queries, sigs)) {
            Ok(_) => true,
            Err(e) => {
                eprintln!("[finalize_query_mailbox] error: {:?}", e);
                false
            }
        }
    }
}

// Utility functions
#[no_mangle]
pub extern "C" fn public_key_new(
    algorithm: u32,
    key_data: *const u8,
    key_len: usize,
) -> *mut c_char {
    if key_data.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        let key_bytes = std::slice::from_raw_parts(key_data, key_len);
        match PublicKey::new(algorithm, key_bytes.to_vec()) {
            Ok(pk) => string_to_c_str(pk.to_string()),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

#[no_mangle]
pub extern "C" fn signature_new(
    algorithm: u32,
    sig_data: *const u8,
    sig_len: usize,
) -> *mut c_char {
    if sig_data.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        let sig_bytes = std::slice::from_raw_parts(sig_data, sig_len);
        match Signature::new(algorithm, sig_bytes.to_vec()) {
            Ok(sig) => string_to_c_str(sig.to_string()),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

#[no_mangle]
pub extern "C" fn free_buffer(data: *mut u8, len: usize) {
    if !data.is_null() && len > 0 {
        unsafe {
            let _ = Vec::from_raw_parts(data, len, len);
        }
    }
}

#[no_mangle]
pub extern "C" fn identifier_sign(
    identifier: *mut CIdentifier,
    input: *const c_char,
    signature: *const c_char,
) -> *mut c_char {
    if identifier.is_null() || input.is_null() || signature.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        let rt = rt();

        let locked = (*identifier).inner.lock().unwrap();

        let input_str = match c_str_to_string(input) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };

        let sig_str = match c_str_to_string(signature) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };

        let sig = match Signature::from_string(&sig_str) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };

        let result = rt.block_on(async { locked.sign(&input_str, &sig.to_prefix()).await });

        match result {
            Ok(Some(stream)) => string_to_c_str(stream),
            _ => std::ptr::null_mut(),
        }
    }
}

#[no_mangle]
pub extern "C" fn identifier_verify(identifier: *mut CIdentifier, stream: *const c_char) -> i32 {
    if identifier.is_null() || stream.is_null() {
        return -1;
    }

    unsafe {
        let rt = rt();

        let locked = (*identifier).inner.lock().unwrap();

        let stream_str = match c_str_to_string(stream) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let result = rt.block_on(async { locked.verify(&stream_str).await });

        match result {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(_) => -1,
        }
    }
}

// VC (Verifiable Credential) functions

#[no_mangle]
pub extern "C" fn identifier_incept_registry(
    identifier: *mut CIdentifier,
    out_registry_id: *mut *mut c_char,
    out_len: *mut usize,
) -> *mut u8 {
    if identifier.is_null() || out_registry_id.is_null() || out_len.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        let rt = rt();

        let mut locked = (*identifier).inner.lock().unwrap();

        let result = rt.block_on(async { locked.incept_registry().await });

        match result {
            Ok((registry_id, vcp_bytes)) => {
                *out_registry_id = string_to_c_str(registry_id);
                *out_len = vcp_bytes.len();
                bytes_to_c_buffer(vcp_bytes)
            }
            Err(_) => std::ptr::null_mut(),
        }
    }
}

#[no_mangle]
pub extern "C" fn identifier_finalize_incept_registry(
    identifier: *mut CIdentifier,
    event: *const u8,
    event_len: usize,
    signature: *const c_char,
) -> bool {
    if identifier.is_null() || event.is_null() || signature.is_null() {
        return false;
    }

    unsafe {
        let rt = rt();

        let mut locked = (*identifier).inner.lock().unwrap();
        let event_slice = std::slice::from_raw_parts(event, event_len);

        let sig_str = match c_str_to_string(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let sig = match Signature::from_string(&sig_str) {
            Ok(s) => s,
            Err(_) => return false,
        };

        rt.block_on(async {
            locked
                .finalize_incept_registry(event_slice, sig.to_prefix())
                .await
                .is_ok()
        })
    }
}

#[no_mangle]
pub extern "C" fn identifier_issue(
    identifier: *mut CIdentifier,
    vc: *const u8,
    vc_len: usize,
    out_vc_hash: *mut *mut c_char,
    out_len: *mut usize,
) -> *mut u8 {
    if identifier.is_null() || vc.is_null() || out_vc_hash.is_null() || out_len.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        let locked = (*identifier).inner.lock().unwrap();
        let vc_slice = std::slice::from_raw_parts(vc, vc_len);

        match locked.issue(vc_slice) {
            Ok((vc_hash, iss_bytes)) => {
                *out_vc_hash = string_to_c_str(vc_hash);
                *out_len = iss_bytes.len();
                bytes_to_c_buffer(iss_bytes)
            }
            Err(_) => std::ptr::null_mut(),
        }
    }
}

#[no_mangle]
pub extern "C" fn identifier_finalize_issue(
    identifier: *mut CIdentifier,
    event: *const u8,
    event_len: usize,
    signature: *const c_char,
) -> bool {
    if identifier.is_null() || event.is_null() || signature.is_null() {
        return false;
    }

    unsafe {
        let rt = rt();

        let mut locked = (*identifier).inner.lock().unwrap();
        let event_slice = std::slice::from_raw_parts(event, event_len);

        let sig_str = match c_str_to_string(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let sig = match Signature::from_string(&sig_str) {
            Ok(s) => s,
            Err(_) => return false,
        };

        rt.block_on(async {
            locked
                .finalize_issue(event_slice, sig.to_prefix())
                .await
                .is_ok()
        })
    }
}

#[no_mangle]
pub extern "C" fn identifier_revoke(
    identifier: *mut CIdentifier,
    vc_hash: *const c_char,
    out_len: *mut usize,
) -> *mut u8 {
    if identifier.is_null() || vc_hash.is_null() || out_len.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        let locked = (*identifier).inner.lock().unwrap();

        let vc_hash_str = match c_str_to_string(vc_hash) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };

        match locked.revoke(&vc_hash_str) {
            Ok(ixn_bytes) => {
                *out_len = ixn_bytes.len();
                bytes_to_c_buffer(ixn_bytes)
            }
            Err(_) => std::ptr::null_mut(),
        }
    }
}

#[no_mangle]
pub extern "C" fn identifier_finalize_revoke(
    identifier: *mut CIdentifier,
    event: *const u8,
    event_len: usize,
    signature: *const c_char,
) -> bool {
    if identifier.is_null() || event.is_null() || signature.is_null() {
        return false;
    }

    unsafe {
        let rt = rt();

        let mut locked = (*identifier).inner.lock().unwrap();
        let event_slice = std::slice::from_raw_parts(event, event_len);

        let sig_str = match c_str_to_string(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let sig = match Signature::from_string(&sig_str) {
            Ok(s) => s,
            Err(_) => return false,
        };

        rt.block_on(async {
            locked
                .finalize_revoke(event_slice, sig.to_prefix())
                .await
                .is_ok()
        })
    }
}

#[no_mangle]
pub extern "C" fn identifier_notify_backers(identifier: *mut CIdentifier) -> bool {
    if identifier.is_null() {
        return false;
    }

    unsafe {
        let rt = rt();

        let locked = (*identifier).inner.lock().unwrap();

        rt.block_on(async { locked.notify_backers().await.is_ok() })
    }
}

#[no_mangle]
pub extern "C" fn identifier_vc_state(identifier: *mut CIdentifier, digest: *const c_char) -> i32 {
    if identifier.is_null() || digest.is_null() {
        return -1;
    }

    unsafe {
        let locked = (*identifier).inner.lock().unwrap();

        let digest_str = match c_str_to_string(digest) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        match locked.vc_state(&digest_str) {
            Ok(Some(state)) => match state {
                identifier::VcState::Issued => 0,
                identifier::VcState::Revoked => 1,
                identifier::VcState::NotIssued => 2,
            },
            Ok(None) => -1,
            Err(_) => -1,
        }
    }
}

#[no_mangle]
pub extern "C" fn identifier_query_tel(
    identifier: *mut CIdentifier,
    registry_id: *const c_char,
    vc_id: *const c_char,
    out_len: *mut usize,
) -> *mut u8 {
    if identifier.is_null() || registry_id.is_null() || vc_id.is_null() || out_len.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        let locked = (*identifier).inner.lock().unwrap();

        let registry_id_str = match c_str_to_string(registry_id) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };

        let vc_id_str = match c_str_to_string(vc_id) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };

        match locked.query_tel(&registry_id_str, &vc_id_str) {
            Ok(qry_bytes) => {
                *out_len = qry_bytes.len();
                bytes_to_c_buffer(qry_bytes)
            }
            Err(_) => std::ptr::null_mut(),
        }
    }
}

#[no_mangle]
pub extern "C" fn identifier_finalize_query_tel(
    identifier: *mut CIdentifier,
    event: *const u8,
    event_len: usize,
    signature: *const c_char,
) -> bool {
    if identifier.is_null() || event.is_null() || signature.is_null() {
        return false;
    }

    unsafe {
        let rt = rt();

        let locked = (*identifier).inner.lock().unwrap();
        let event_slice = std::slice::from_raw_parts(event, event_len);

        let sig_str = match c_str_to_string(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let sig = match Signature::from_string(&sig_str) {
            Ok(s) => s,
            Err(_) => return false,
        };

        rt.block_on(async {
            locked
                .finalize_query_tel(event_slice, sig.to_prefix())
                .await
                .is_ok()
        })
    }
}

#[no_mangle]
pub extern "C" fn identifier_registry_id(identifier: *mut CIdentifier) -> *mut c_char {
    if identifier.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        let locked = (*identifier).inner.lock().unwrap();
        match locked.registry_id() {
            Some(id) => string_to_c_str(id),
            None => std::ptr::null_mut(),
        }
    }
}

/// Build a proper ACDC attestation and return its JSON encoding.
///
/// Parameters:
///   - issuer_id:     KERI identifier of the issuer (AID)
///   - holder_id:     KERI identifier of the credential subject/holder (AID); may be null for untargeted credentials
///   - registry_id:   SAID of the credential registry
///   - schema_said:   SAID of the credential schema
///   - attrs_json:    JSON object string of credential claims, e.g. `{"name":"Alice","age":30}`
///   - out_said:      output parameter — caller-owned C string with the SAID of the built ACDC
///
/// Returns the ACDC JSON as a caller-owned C string, or null on error.
/// Both returned strings must be freed with `free_string`.
#[no_mangle]
pub extern "C" fn acdc_build(
    issuer_id: *const c_char,
    holder_id: *const c_char,
    registry_id: *const c_char,
    schema_said: *const c_char,
    attrs_json: *const c_char,
    out_said: *mut *mut c_char,
) -> *mut c_char {
    use acdc::attributes::InlineAttributes;
    use acdc::Attestation;
    use said::{
        derivation::HashFunctionCode,
        version::{format::SerializationFormats, Encode},
    };

    unsafe {
        let issuer = match c_str_to_string(issuer_id) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };
        let registry = match c_str_to_string(registry_id) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };
        let schema = match c_str_to_string(schema_said) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };
        let attrs_str = match c_str_to_string(attrs_json) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };

        let attrs: InlineAttributes = match attrs_str.parse() {
            Ok(a) => a,
            Err(_) => return std::ptr::null_mut(),
        };

        let attestation = if holder_id.is_null() {
            Attestation::new_public_untargeted(
                &issuer,
                registry,
                schema,
                attrs,
                &SerializationFormats::JSON,
                &HashFunctionCode::Blake3_256,
            )
        } else {
            let holder = match c_str_to_string(holder_id) {
                Ok(s) => s,
                Err(_) => return std::ptr::null_mut(),
            };
            Attestation::new_public_targeted(
                &issuer,
                &holder,
                registry,
                schema,
                attrs,
                &SerializationFormats::JSON,
                &HashFunctionCode::Blake3_256,
            )
        };

        // Write the SAID to the output parameter
        if !out_said.is_null() {
            let said_str = match &attestation.digest {
                Some(d) => d.to_string(),
                None => return std::ptr::null_mut(),
            };
            *out_said = string_to_c_str(said_str);
        }

        // Encode and return the full ACDC JSON
        match attestation.encode(&HashFunctionCode::Blake3_256, &SerializationFormats::JSON) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(s) => string_to_c_str(s),
                Err(_) => std::ptr::null_mut(),
            },
            Err(_) => std::ptr::null_mut(),
        }
    }
}

/// Returns the identifier's OOBIs as a newline-separated string of JSON OOBI objects.
/// The caller must free the returned string with `free_string`.
#[no_mangle]
pub extern "C" fn identifier_oobi(identifier: *mut CIdentifier) -> *mut c_char {
    unsafe {
        let locked = (*identifier).inner.lock().unwrap();
        match locked.oobi() {
            Ok(oobis) => string_to_c_str(oobis.join("\n")),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

/// Returns the registry's OOBIs as a newline-separated string of JSON OOBI objects,
/// or null if no registry has been incepted.
/// The caller must free the returned string with `free_string`.
#[no_mangle]
pub extern "C" fn identifier_registry_id_oobi(identifier: *mut CIdentifier) -> *mut c_char {
    unsafe {
        let locked = (*identifier).inner.lock().unwrap();
        match locked.registry_id_oobi() {
            Some(oobis) => string_to_c_str(oobis.join("\n")),
            None => std::ptr::null_mut(),
        }
    }
}

/// Resolves the watcher's OOBI and produces an add-watcher event.
/// Returns the event bytes; `out_len` is set to the byte count.
/// Returns null on error. The caller must free with `free_buffer`.
#[no_mangle]
pub extern "C" fn identifier_add_watcher(
    identifier: *mut CIdentifier,
    watcher_oobi: *const c_char,
    out_len: *mut usize,
) -> *mut u8 {
    unsafe {
        let watcher_str = match c_str_to_string(watcher_oobi) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };
        let locked = (*identifier).inner.lock().unwrap();
        match rt().block_on(locked.add_watcher(&watcher_str)) {
            Ok(event) => {
                *out_len = event.len();
                bytes_to_c_buffer(event)
            }
            Err(_) => std::ptr::null_mut(),
        }
    }
}

/// Finalizes adding a watcher using the signed add-watcher event.
/// Returns true on success.
#[no_mangle]
pub extern "C" fn identifier_finalize_add_watcher(
    identifier: *mut CIdentifier,
    event: *const u8,
    event_len: usize,
    signature: *const c_char,
) -> bool {
    unsafe {
        let event_slice = std::slice::from_raw_parts(event, event_len);
        let sig_str = match c_str_to_string(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let sig = match sig_str.parse::<keri_controller::SelfSigningPrefix>() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let locked = (*identifier).inner.lock().unwrap();
        rt().block_on(locked.finalize_add_watcher(event_slice, sig)).is_ok()
    }
}

/// Sends an OOBI (location or end-role) to the identifier's watcher.
/// Returns true on success.
#[no_mangle]
pub extern "C" fn identifier_send_oobi_to_watcher(
    identifier: *mut CIdentifier,
    oobi: *const c_char,
) -> bool {
    unsafe {
        let oobi_str = match c_str_to_string(oobi) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let locked = (*identifier).inner.lock().unwrap();
        rt().block_on(locked.send_oobi_to_watcher(&oobi_str)).is_ok()
    }
}

/// Produces KEL query messages for all of the identifier's watchers, asking about `about_id`.
/// Returns a JSON array string of base64-encoded query event bytes, e.g. `["AAAA...","BBBB..."]`.
/// The caller must free with `free_string`.
#[no_mangle]
pub extern "C" fn identifier_query_full_kel(
    identifier: *mut CIdentifier,
    about_id: *const c_char,
) -> *mut c_char {
    unsafe {
        let about_str = match c_str_to_string(about_id) {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };
        let locked = (*identifier).inner.lock().unwrap();
        match locked.query_full_kel(&about_str) {
            Ok(queries) => {
                let encoded: Vec<String> = queries
                    .into_iter()
                    .map(|q| base64::encode(&q))
                    .collect();
                match serde_json::to_string(&encoded) {
                    Ok(s) => string_to_c_str(s),
                    Err(_) => std::ptr::null_mut(),
                }
            }
            Err(_) => std::ptr::null_mut(),
        }
    }
}

/// Finalizes KEL queries by sending them (with signatures) to the watchers.
/// `queries_b64_json`: JSON array of base64-encoded query events (from `identifier_query_full_kel`).
/// `signatures_json`: JSON array of signature strings, one per query.
/// Returns true if the watcher returned new updates.
#[no_mangle]
pub extern "C" fn identifier_finalize_query_kel(
    identifier: *mut CIdentifier,
    queries_b64_json: *const c_char,
    signatures_json: *const c_char,
) -> bool {
    unsafe {
        let queries_str = match c_str_to_string(queries_b64_json) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let sigs_str = match c_str_to_string(signatures_json) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let b64_queries: Vec<String> = match serde_json::from_str(&queries_str) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let sig_strs: Vec<String> = match serde_json::from_str(&sigs_str) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let queries: Vec<Vec<u8>> = match b64_queries.iter()
            .map(|s| base64::decode(s).map_err(|_| ()))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(v) => v,
            Err(_) => return false,
        };
        let sigs: Vec<keri_controller::SelfSigningPrefix> = match sig_strs.iter()
            .map(|s| s.parse().map_err(|_| ()))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(v) => v,
            Err(_) => return false,
        };
        let locked = (*identifier).inner.lock().unwrap();
        rt().block_on(locked.finalize_query_kel(queries, sigs))
            .unwrap_or(false)
    }
}
