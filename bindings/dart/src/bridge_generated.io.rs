use super::*;
// Section: wire functions

#[no_mangle]
pub extern "C" fn wire_new_public_key(
    port_: i64,
    kt: i32,
    key_b64_url_safe: *mut wire_uint_8_list,
) {
    wire_new_public_key_impl(port_, kt, key_b64_url_safe)
}

#[no_mangle]
pub extern "C" fn wire_signature_from_hex(port_: i64, st: i32, signature: *mut wire_uint_8_list) {
    wire_signature_from_hex_impl(port_, st, signature)
}

#[no_mangle]
pub extern "C" fn wire_signature_from_b64(port_: i64, st: i32, signature: *mut wire_uint_8_list) {
    wire_signature_from_b64_impl(port_, st, signature)
}

#[no_mangle]
pub extern "C" fn wire_with_initial_oobis(
    port_: i64,
    config: *mut wire_Config,
    oobis_json: *mut wire_uint_8_list,
) {
    wire_with_initial_oobis_impl(port_, config, oobis_json)
}

#[no_mangle]
pub extern "C" fn wire_change_controller(port_: i64, db_path: *mut wire_uint_8_list) {
    wire_change_controller_impl(port_, db_path)
}

#[no_mangle]
pub extern "C" fn wire_init_kel(
    port_: i64,
    input_app_dir: *mut wire_uint_8_list,
    optional_configs: *mut wire_Config,
) {
    wire_init_kel_impl(port_, input_app_dir, optional_configs)
}

#[no_mangle]
pub extern "C" fn wire_incept(
    port_: i64,
    public_keys: *mut wire_list_public_key,
    next_pub_keys: *mut wire_list_public_key,
    witnesses: *mut wire_StringList,
    witness_threshold: u64,
) {
    wire_incept_impl(
        port_,
        public_keys,
        next_pub_keys,
        witnesses,
        witness_threshold,
    )
}

#[no_mangle]
pub extern "C" fn wire_finalize_inception(
    port_: i64,
    event: *mut wire_uint_8_list,
    signature: *mut wire_Signature,
) {
    wire_finalize_inception_impl(port_, event, signature)
}

#[no_mangle]
pub extern "C" fn wire_rotate(
    port_: i64,
    identifier: *mut wire_Identifier,
    current_keys: *mut wire_list_public_key,
    new_next_keys: *mut wire_list_public_key,
    witness_to_add: *mut wire_StringList,
    witness_to_remove: *mut wire_StringList,
    witness_threshold: u64,
) {
    wire_rotate_impl(
        port_,
        identifier,
        current_keys,
        new_next_keys,
        witness_to_add,
        witness_to_remove,
        witness_threshold,
    )
}

#[no_mangle]
pub extern "C" fn wire_anchor(
    port_: i64,
    identifier: *mut wire_Identifier,
    data: *mut wire_uint_8_list,
    algo: *mut wire_DigestType,
) {
    wire_anchor_impl(port_, identifier, data, algo)
}

#[no_mangle]
pub extern "C" fn wire_anchor_digest(
    port_: i64,
    identifier: *mut wire_Identifier,
    sais: *mut wire_StringList,
) {
    wire_anchor_digest_impl(port_, identifier, sais)
}

#[no_mangle]
pub extern "C" fn wire_add_watcher(
    port_: i64,
    identifier: *mut wire_Identifier,
    watcher_oobi: *mut wire_uint_8_list,
) {
    wire_add_watcher_impl(port_, identifier, watcher_oobi)
}

#[no_mangle]
pub extern "C" fn wire_send_oobi_to_watcher(
    port_: i64,
    identifier: *mut wire_Identifier,
    oobis_json: *mut wire_uint_8_list,
) {
    wire_send_oobi_to_watcher_impl(port_, identifier, oobis_json)
}

#[no_mangle]
pub extern "C" fn wire_finalize_event(
    port_: i64,
    identifier: *mut wire_Identifier,
    event: *mut wire_uint_8_list,
    signature: *mut wire_Signature,
) {
    wire_finalize_event_impl(port_, identifier, event, signature)
}

#[no_mangle]
pub extern "C" fn wire_notify_witnesses(port_: i64, identifier: *mut wire_Identifier) {
    wire_notify_witnesses_impl(port_, identifier)
}

#[no_mangle]
pub extern "C" fn wire_broadcast_receipts(
    port_: i64,
    identifier: *mut wire_Identifier,
    witness_list: *mut wire_list_identifier,
) {
    wire_broadcast_receipts_impl(port_, identifier, witness_list)
}

#[no_mangle]
pub extern "C" fn wire_incept_group(
    port_: i64,
    identifier: *mut wire_Identifier,
    participants: *mut wire_list_identifier,
    signature_threshold: u64,
    initial_witnesses: *mut wire_StringList,
    witness_threshold: u64,
) {
    wire_incept_group_impl(
        port_,
        identifier,
        participants,
        signature_threshold,
        initial_witnesses,
        witness_threshold,
    )
}

#[no_mangle]
pub extern "C" fn wire_finalize_group_incept(
    port_: i64,
    identifier: *mut wire_Identifier,
    group_event: *mut wire_uint_8_list,
    signature: *mut wire_Signature,
    to_forward: *mut wire_list_data_and_signature,
) {
    wire_finalize_group_incept_impl(port_, identifier, group_event, signature, to_forward)
}

#[no_mangle]
pub extern "C" fn wire_query_mailbox(
    port_: i64,
    who_ask: *mut wire_Identifier,
    about_who: *mut wire_Identifier,
    witness: *mut wire_StringList,
) {
    wire_query_mailbox_impl(port_, who_ask, about_who, witness)
}

#[no_mangle]
pub extern "C" fn wire_query_watchers(
    port_: i64,
    who_ask: *mut wire_Identifier,
    about_who: *mut wire_Identifier,
) {
    wire_query_watchers_impl(port_, who_ask, about_who)
}

#[no_mangle]
pub extern "C" fn wire_finalize_query(
    port_: i64,
    identifier: *mut wire_Identifier,
    query_event: *mut wire_uint_8_list,
    signature: *mut wire_Signature,
) {
    wire_finalize_query_impl(port_, identifier, query_event, signature)
}

#[no_mangle]
pub extern "C" fn wire_resolve_oobi(port_: i64, oobi_json: *mut wire_uint_8_list) {
    wire_resolve_oobi_impl(port_, oobi_json)
}

#[no_mangle]
pub extern "C" fn wire_process_stream(port_: i64, stream: *mut wire_uint_8_list) {
    wire_process_stream_impl(port_, stream)
}

#[no_mangle]
pub extern "C" fn wire_get_kel(port_: i64, identifier: *mut wire_Identifier) {
    wire_get_kel_impl(port_, identifier)
}

#[no_mangle]
pub extern "C" fn wire_to_cesr_signature(
    port_: i64,
    identifier: *mut wire_Identifier,
    signature: *mut wire_Signature,
) {
    wire_to_cesr_signature_impl(port_, identifier, signature)
}

#[no_mangle]
pub extern "C" fn wire_sign_to_cesr(
    port_: i64,
    identifier: *mut wire_Identifier,
    data: *mut wire_uint_8_list,
    signature: *mut wire_Signature,
) {
    wire_sign_to_cesr_impl(port_, identifier, data, signature)
}

#[no_mangle]
pub extern "C" fn wire_split_oobis_and_data(port_: i64, stream: *mut wire_uint_8_list) {
    wire_split_oobis_and_data_impl(port_, stream)
}

#[no_mangle]
pub extern "C" fn wire_verify_from_cesr(port_: i64, stream: *mut wire_uint_8_list) {
    wire_verify_from_cesr_impl(port_, stream)
}

#[no_mangle]
pub extern "C" fn wire_incept_registry(port_: i64, identifier: *mut wire_Identifier) {
    wire_incept_registry_impl(port_, identifier)
}

#[no_mangle]
pub extern "C" fn wire_issue_credential(
    port_: i64,
    identifier: *mut wire_Identifier,
    credential: *mut wire_uint_8_list,
) {
    wire_issue_credential_impl(port_, identifier, credential)
}

#[no_mangle]
pub extern "C" fn wire_revoke_credential(
    port_: i64,
    identifier: *mut wire_Identifier,
    credential_said: *mut wire_uint_8_list,
) {
    wire_revoke_credential_impl(port_, identifier, credential_said)
}

#[no_mangle]
pub extern "C" fn wire_query_tel(
    port_: i64,
    identifier: *mut wire_Identifier,
    registry_id: *mut wire_uint_8_list,
    credential_said: *mut wire_uint_8_list,
) {
    wire_query_tel_impl(port_, identifier, registry_id, credential_said)
}

#[no_mangle]
pub extern "C" fn wire_finalize_tel_query(
    port_: i64,
    identifier: *mut wire_Identifier,
    query_event: *mut wire_uint_8_list,
    signature: *mut wire_Signature,
) {
    wire_finalize_tel_query_impl(port_, identifier, query_event, signature)
}

#[no_mangle]
pub extern "C" fn wire_get_credential_state(
    port_: i64,
    identifier: *mut wire_Identifier,
    credential_said: *mut wire_uint_8_list,
) {
    wire_get_credential_state_impl(port_, identifier, credential_said)
}

#[no_mangle]
pub extern "C" fn wire_notify_backers(port_: i64, identifier: *mut wire_Identifier) {
    wire_notify_backers_impl(port_, identifier)
}

#[no_mangle]
pub extern "C" fn wire_add_messagebox(
    port_: i64,
    identifier: *mut wire_Identifier,
    messagebox_oobi: *mut wire_uint_8_list,
) {
    wire_add_messagebox_impl(port_, identifier, messagebox_oobi)
}

#[no_mangle]
pub extern "C" fn wire_get_messagebox(port_: i64, whose: *mut wire_uint_8_list) {
    wire_get_messagebox_impl(port_, whose)
}

#[no_mangle]
pub extern "C" fn wire_new_from_str__static_method__Identifier(
    port_: i64,
    id_str: *mut wire_uint_8_list,
) {
    wire_new_from_str__static_method__Identifier_impl(port_, id_str)
}

#[no_mangle]
pub extern "C" fn wire_to_str__method__Identifier(port_: i64, that: *mut wire_Identifier) {
    wire_to_str__method__Identifier_impl(port_, that)
}

#[no_mangle]
pub extern "C" fn wire_new__static_method__DataAndSignature(
    port_: i64,
    data: *mut wire_uint_8_list,
    signature: *mut wire_Signature,
) {
    wire_new__static_method__DataAndSignature_impl(port_, data, signature)
}

// Section: allocate functions

#[no_mangle]
pub extern "C" fn new_StringList_0(len: i32) -> *mut wire_StringList {
    let wrap = wire_StringList {
        ptr: support::new_leak_vec_ptr(<*mut wire_uint_8_list>::new_with_null_ptr(), len),
        len,
    };
    support::new_leak_box_ptr(wrap)
}

#[no_mangle]
pub extern "C" fn new_box_autoadd_config_0() -> *mut wire_Config {
    support::new_leak_box_ptr(wire_Config::new_with_null_ptr())
}

#[no_mangle]
pub extern "C" fn new_box_autoadd_digest_type_0() -> *mut wire_DigestType {
    support::new_leak_box_ptr(wire_DigestType::new_with_null_ptr())
}

#[no_mangle]
pub extern "C" fn new_box_autoadd_identifier_0() -> *mut wire_Identifier {
    support::new_leak_box_ptr(wire_Identifier::new_with_null_ptr())
}

#[no_mangle]
pub extern "C" fn new_box_autoadd_signature_0() -> *mut wire_Signature {
    support::new_leak_box_ptr(wire_Signature::new_with_null_ptr())
}

#[no_mangle]
pub extern "C" fn new_box_signature_0() -> *mut wire_Signature {
    support::new_leak_box_ptr(wire_Signature::new_with_null_ptr())
}

#[no_mangle]
pub extern "C" fn new_list_data_and_signature_0(len: i32) -> *mut wire_list_data_and_signature {
    let wrap = wire_list_data_and_signature {
        ptr: support::new_leak_vec_ptr(<wire_DataAndSignature>::new_with_null_ptr(), len),
        len,
    };
    support::new_leak_box_ptr(wrap)
}

#[no_mangle]
pub extern "C" fn new_list_identifier_0(len: i32) -> *mut wire_list_identifier {
    let wrap = wire_list_identifier {
        ptr: support::new_leak_vec_ptr(<wire_Identifier>::new_with_null_ptr(), len),
        len,
    };
    support::new_leak_box_ptr(wrap)
}

#[no_mangle]
pub extern "C" fn new_list_public_key_0(len: i32) -> *mut wire_list_public_key {
    let wrap = wire_list_public_key {
        ptr: support::new_leak_vec_ptr(<wire_PublicKey>::new_with_null_ptr(), len),
        len,
    };
    support::new_leak_box_ptr(wrap)
}

#[no_mangle]
pub extern "C" fn new_uint_8_list_0(len: i32) -> *mut wire_uint_8_list {
    let ans = wire_uint_8_list {
        ptr: support::new_leak_vec_ptr(Default::default(), len),
        len,
    };
    support::new_leak_box_ptr(ans)
}

// Section: related functions

// Section: impl Wire2Api

impl Wire2Api<String> for *mut wire_uint_8_list {
    fn wire2api(self) -> String {
        let vec: Vec<u8> = self.wire2api();
        String::from_utf8_lossy(&vec).into_owned()
    }
}
impl Wire2Api<Vec<String>> for *mut wire_StringList {
    fn wire2api(self) -> Vec<String> {
        let vec = unsafe {
            let wrap = support::box_from_leak_ptr(self);
            support::vec_from_leak_ptr(wrap.ptr, wrap.len)
        };
        vec.into_iter().map(Wire2Api::wire2api).collect()
    }
}
impl Wire2Api<Config> for *mut wire_Config {
    fn wire2api(self) -> Config {
        let wrap = unsafe { support::box_from_leak_ptr(self) };
        Wire2Api::<Config>::wire2api(*wrap).into()
    }
}
impl Wire2Api<DigestType> for *mut wire_DigestType {
    fn wire2api(self) -> DigestType {
        let wrap = unsafe { support::box_from_leak_ptr(self) };
        Wire2Api::<DigestType>::wire2api(*wrap).into()
    }
}
impl Wire2Api<Identifier> for *mut wire_Identifier {
    fn wire2api(self) -> Identifier {
        let wrap = unsafe { support::box_from_leak_ptr(self) };
        Wire2Api::<Identifier>::wire2api(*wrap).into()
    }
}
impl Wire2Api<Signature> for *mut wire_Signature {
    fn wire2api(self) -> Signature {
        let wrap = unsafe { support::box_from_leak_ptr(self) };
        Wire2Api::<Signature>::wire2api(*wrap).into()
    }
}
impl Wire2Api<Box<Signature>> for *mut wire_Signature {
    fn wire2api(self) -> Box<Signature> {
        let wrap = unsafe { support::box_from_leak_ptr(self) };
        Wire2Api::<Signature>::wire2api(*wrap).into()
    }
}
impl Wire2Api<Config> for wire_Config {
    fn wire2api(self) -> Config {
        Config {
            initial_oobis: self.initial_oobis.wire2api(),
        }
    }
}
impl Wire2Api<DataAndSignature> for wire_DataAndSignature {
    fn wire2api(self) -> DataAndSignature {
        DataAndSignature {
            data: self.data.wire2api(),
            signature: self.signature.wire2api(),
        }
    }
}
impl Wire2Api<DigestType> for wire_DigestType {
    fn wire2api(self) -> DigestType {
        match self.tag {
            0 => DigestType::Blake3_256,
            1 => DigestType::SHA3_256,
            2 => DigestType::SHA2_256,
            3 => DigestType::Blake3_512,
            4 => DigestType::SHA3_512,
            5 => DigestType::Blake2B512,
            6 => DigestType::SHA2_512,
            7 => unsafe {
                let ans = support::box_from_leak_ptr(self.kind);
                let ans = support::box_from_leak_ptr(ans.Blake2B256);
                DigestType::Blake2B256(ans.field0.wire2api())
            },
            8 => unsafe {
                let ans = support::box_from_leak_ptr(self.kind);
                let ans = support::box_from_leak_ptr(ans.Blake2S256);
                DigestType::Blake2S256(ans.field0.wire2api())
            },
            _ => unreachable!(),
        }
    }
}

impl Wire2Api<Identifier> for wire_Identifier {
    fn wire2api(self) -> Identifier {
        Identifier {
            id: self.id.wire2api(),
        }
    }
}

impl Wire2Api<Vec<DataAndSignature>> for *mut wire_list_data_and_signature {
    fn wire2api(self) -> Vec<DataAndSignature> {
        let vec = unsafe {
            let wrap = support::box_from_leak_ptr(self);
            support::vec_from_leak_ptr(wrap.ptr, wrap.len)
        };
        vec.into_iter().map(Wire2Api::wire2api).collect()
    }
}
impl Wire2Api<Vec<Identifier>> for *mut wire_list_identifier {
    fn wire2api(self) -> Vec<Identifier> {
        let vec = unsafe {
            let wrap = support::box_from_leak_ptr(self);
            support::vec_from_leak_ptr(wrap.ptr, wrap.len)
        };
        vec.into_iter().map(Wire2Api::wire2api).collect()
    }
}
impl Wire2Api<Vec<PublicKey>> for *mut wire_list_public_key {
    fn wire2api(self) -> Vec<PublicKey> {
        let vec = unsafe {
            let wrap = support::box_from_leak_ptr(self);
            support::vec_from_leak_ptr(wrap.ptr, wrap.len)
        };
        vec.into_iter().map(Wire2Api::wire2api).collect()
    }
}

impl Wire2Api<PublicKey> for wire_PublicKey {
    fn wire2api(self) -> PublicKey {
        PublicKey {
            derivation: self.derivation.wire2api(),
            public_key: self.public_key.wire2api(),
        }
    }
}
impl Wire2Api<Signature> for wire_Signature {
    fn wire2api(self) -> Signature {
        Signature {
            derivation: self.derivation.wire2api(),
            signature: self.signature.wire2api(),
        }
    }
}

impl Wire2Api<Vec<u8>> for *mut wire_uint_8_list {
    fn wire2api(self) -> Vec<u8> {
        unsafe {
            let wrap = support::box_from_leak_ptr(self);
            support::vec_from_leak_ptr(wrap.ptr, wrap.len)
        }
    }
}
// Section: wire structs

#[repr(C)]
#[derive(Clone)]
pub struct wire_StringList {
    ptr: *mut *mut wire_uint_8_list,
    len: i32,
}

#[repr(C)]
#[derive(Clone)]
pub struct wire_Config {
    initial_oobis: *mut wire_uint_8_list,
}

#[repr(C)]
#[derive(Clone)]
pub struct wire_DataAndSignature {
    data: *mut wire_uint_8_list,
    signature: *mut wire_Signature,
}

#[repr(C)]
#[derive(Clone)]
pub struct wire_Identifier {
    id: *mut wire_uint_8_list,
}

#[repr(C)]
#[derive(Clone)]
pub struct wire_list_data_and_signature {
    ptr: *mut wire_DataAndSignature,
    len: i32,
}

#[repr(C)]
#[derive(Clone)]
pub struct wire_list_identifier {
    ptr: *mut wire_Identifier,
    len: i32,
}

#[repr(C)]
#[derive(Clone)]
pub struct wire_list_public_key {
    ptr: *mut wire_PublicKey,
    len: i32,
}

#[repr(C)]
#[derive(Clone)]
pub struct wire_PublicKey {
    derivation: i32,
    public_key: *mut wire_uint_8_list,
}

#[repr(C)]
#[derive(Clone)]
pub struct wire_Signature {
    derivation: i32,
    signature: *mut wire_uint_8_list,
}

#[repr(C)]
#[derive(Clone)]
pub struct wire_uint_8_list {
    ptr: *mut u8,
    len: i32,
}

#[repr(C)]
#[derive(Clone)]
pub struct wire_DigestType {
    tag: i32,
    kind: *mut DigestTypeKind,
}

#[repr(C)]
pub union DigestTypeKind {
    Blake3_256: *mut wire_DigestType_Blake3_256,
    SHA3_256: *mut wire_DigestType_SHA3_256,
    SHA2_256: *mut wire_DigestType_SHA2_256,
    Blake3_512: *mut wire_DigestType_Blake3_512,
    SHA3_512: *mut wire_DigestType_SHA3_512,
    Blake2B512: *mut wire_DigestType_Blake2B512,
    SHA2_512: *mut wire_DigestType_SHA2_512,
    Blake2B256: *mut wire_DigestType_Blake2B256,
    Blake2S256: *mut wire_DigestType_Blake2S256,
}

#[repr(C)]
#[derive(Clone)]
pub struct wire_DigestType_Blake3_256 {}

#[repr(C)]
#[derive(Clone)]
pub struct wire_DigestType_SHA3_256 {}

#[repr(C)]
#[derive(Clone)]
pub struct wire_DigestType_SHA2_256 {}

#[repr(C)]
#[derive(Clone)]
pub struct wire_DigestType_Blake3_512 {}

#[repr(C)]
#[derive(Clone)]
pub struct wire_DigestType_SHA3_512 {}

#[repr(C)]
#[derive(Clone)]
pub struct wire_DigestType_Blake2B512 {}

#[repr(C)]
#[derive(Clone)]
pub struct wire_DigestType_SHA2_512 {}

#[repr(C)]
#[derive(Clone)]
pub struct wire_DigestType_Blake2B256 {
    field0: *mut wire_uint_8_list,
}

#[repr(C)]
#[derive(Clone)]
pub struct wire_DigestType_Blake2S256 {
    field0: *mut wire_uint_8_list,
}

// Section: impl NewWithNullPtr

pub trait NewWithNullPtr {
    fn new_with_null_ptr() -> Self;
}

impl<T> NewWithNullPtr for *mut T {
    fn new_with_null_ptr() -> Self {
        std::ptr::null_mut()
    }
}

impl NewWithNullPtr for wire_Config {
    fn new_with_null_ptr() -> Self {
        Self {
            initial_oobis: core::ptr::null_mut(),
        }
    }
}

impl Default for wire_Config {
    fn default() -> Self {
        Self::new_with_null_ptr()
    }
}

impl NewWithNullPtr for wire_DataAndSignature {
    fn new_with_null_ptr() -> Self {
        Self {
            data: core::ptr::null_mut(),
            signature: core::ptr::null_mut(),
        }
    }
}

impl Default for wire_DataAndSignature {
    fn default() -> Self {
        Self::new_with_null_ptr()
    }
}

impl Default for wire_DigestType {
    fn default() -> Self {
        Self::new_with_null_ptr()
    }
}

impl NewWithNullPtr for wire_DigestType {
    fn new_with_null_ptr() -> Self {
        Self {
            tag: -1,
            kind: core::ptr::null_mut(),
        }
    }
}

#[no_mangle]
pub extern "C" fn inflate_DigestType_Blake2B256() -> *mut DigestTypeKind {
    support::new_leak_box_ptr(DigestTypeKind {
        Blake2B256: support::new_leak_box_ptr(wire_DigestType_Blake2B256 {
            field0: core::ptr::null_mut(),
        }),
    })
}

#[no_mangle]
pub extern "C" fn inflate_DigestType_Blake2S256() -> *mut DigestTypeKind {
    support::new_leak_box_ptr(DigestTypeKind {
        Blake2S256: support::new_leak_box_ptr(wire_DigestType_Blake2S256 {
            field0: core::ptr::null_mut(),
        }),
    })
}

impl NewWithNullPtr for wire_Identifier {
    fn new_with_null_ptr() -> Self {
        Self {
            id: core::ptr::null_mut(),
        }
    }
}

impl Default for wire_Identifier {
    fn default() -> Self {
        Self::new_with_null_ptr()
    }
}

impl NewWithNullPtr for wire_PublicKey {
    fn new_with_null_ptr() -> Self {
        Self {
            derivation: Default::default(),
            public_key: core::ptr::null_mut(),
        }
    }
}

impl Default for wire_PublicKey {
    fn default() -> Self {
        Self::new_with_null_ptr()
    }
}

impl NewWithNullPtr for wire_Signature {
    fn new_with_null_ptr() -> Self {
        Self {
            derivation: Default::default(),
            signature: core::ptr::null_mut(),
        }
    }
}

impl Default for wire_Signature {
    fn default() -> Self {
        Self::new_with_null_ptr()
    }
}

// Section: sync execution mode utility

#[no_mangle]
pub extern "C" fn free_WireSyncReturn(ptr: support::WireSyncReturn) {
    unsafe {
        let _ = support::box_from_leak_ptr(ptr);
    };
}
