#![allow(
    non_camel_case_types,
    unused,
    clippy::redundant_closure,
    clippy::useless_conversion,
    clippy::unit_arg,
    clippy::double_parens,
    non_snake_case,
    clippy::too_many_arguments
)]
// AUTO GENERATED FILE, DO NOT EDIT.
// Generated by `flutter_rust_bridge`@ 1.49.0.

use crate::api::*;
use core::panic::UnwindSafe;
use flutter_rust_bridge::*;

// Section: imports

// Section: wire functions

fn wire_new_public_key_impl(
    port_: MessagePort,
    kt: impl Wire2Api<KeyType> + UnwindSafe,
    key_b64: impl Wire2Api<String> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "new_public_key",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_kt = kt.wire2api();
            let api_key_b64 = key_b64.wire2api();
            move |task_callback| Ok(mirror_PublicKey(new_public_key(api_kt, api_key_b64)))
        },
    )
}
fn wire_signature_from_hex_impl(
    port_: MessagePort,
    st: impl Wire2Api<SignatureType> + UnwindSafe,
    signature: impl Wire2Api<String> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "signature_from_hex",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_st = st.wire2api();
            let api_signature = signature.wire2api();
            move |task_callback| Ok(mirror_Signature(signature_from_hex(api_st, api_signature)))
        },
    )
}
fn wire_signature_from_b64_impl(
    port_: MessagePort,
    st: impl Wire2Api<SignatureType> + UnwindSafe,
    signature: impl Wire2Api<String> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "signature_from_b64",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_st = st.wire2api();
            let api_signature = signature.wire2api();
            move |task_callback| Ok(mirror_Signature(signature_from_b64(api_st, api_signature)))
        },
    )
}
fn wire_identifier_from_str_impl(port_: MessagePort, id_str: impl Wire2Api<String> + UnwindSafe) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "identifier_from_str",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_id_str = id_str.wire2api();
            move |task_callback| identifier_from_str(api_id_str)
        },
    )
}
fn wire_identifier_to_str_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "identifier_to_str",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            move |task_callback| Ok(identifier_to_str(api_identifier))
        },
    )
}
fn wire_with_initial_oobis_impl(
    port_: MessagePort,
    config: impl Wire2Api<Config> + UnwindSafe,
    oobis_json: impl Wire2Api<String> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "with_initial_oobis",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_config = config.wire2api();
            let api_oobis_json = oobis_json.wire2api();
            move |task_callback| Ok(with_initial_oobis(api_config, api_oobis_json))
        },
    )
}
fn wire_init_kel_impl(
    port_: MessagePort,
    input_app_dir: impl Wire2Api<String> + UnwindSafe,
    optional_configs: impl Wire2Api<Option<Config>> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "init_kel",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_input_app_dir = input_app_dir.wire2api();
            let api_optional_configs = optional_configs.wire2api();
            move |task_callback| init_kel(api_input_app_dir, api_optional_configs)
        },
    )
}
fn wire_incept_impl(
    port_: MessagePort,
    public_keys: impl Wire2Api<Vec<PublicKey>> + UnwindSafe,
    next_pub_keys: impl Wire2Api<Vec<PublicKey>> + UnwindSafe,
    witnesses: impl Wire2Api<Vec<String>> + UnwindSafe,
    witness_threshold: impl Wire2Api<u64> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "incept",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_public_keys = public_keys.wire2api();
            let api_next_pub_keys = next_pub_keys.wire2api();
            let api_witnesses = witnesses.wire2api();
            let api_witness_threshold = witness_threshold.wire2api();
            move |task_callback| {
                incept(
                    api_public_keys,
                    api_next_pub_keys,
                    api_witnesses,
                    api_witness_threshold,
                )
            }
        },
    )
}
fn wire_finalize_inception_impl(
    port_: MessagePort,
    event: impl Wire2Api<String> + UnwindSafe,
    signature: impl Wire2Api<Signature> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "finalize_inception",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_event = event.wire2api();
            let api_signature = signature.wire2api();
            move |task_callback| finalize_inception(api_event, api_signature)
        },
    )
}
fn wire_rotate_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    current_keys: impl Wire2Api<Vec<PublicKey>> + UnwindSafe,
    new_next_keys: impl Wire2Api<Vec<PublicKey>> + UnwindSafe,
    witness_to_add: impl Wire2Api<Vec<String>> + UnwindSafe,
    witness_to_remove: impl Wire2Api<Vec<String>> + UnwindSafe,
    witness_threshold: impl Wire2Api<u64> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "rotate",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_current_keys = current_keys.wire2api();
            let api_new_next_keys = new_next_keys.wire2api();
            let api_witness_to_add = witness_to_add.wire2api();
            let api_witness_to_remove = witness_to_remove.wire2api();
            let api_witness_threshold = witness_threshold.wire2api();
            move |task_callback| {
                rotate(
                    api_identifier,
                    api_current_keys,
                    api_new_next_keys,
                    api_witness_to_add,
                    api_witness_to_remove,
                    api_witness_threshold,
                )
            }
        },
    )
}
fn wire_anchor_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    data: impl Wire2Api<String> + UnwindSafe,
    algo: impl Wire2Api<DigestType> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "anchor",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_data = data.wire2api();
            let api_algo = algo.wire2api();
            move |task_callback| anchor(api_identifier, api_data, api_algo)
        },
    )
}
fn wire_anchor_digest_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    sais: impl Wire2Api<Vec<String>> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "anchor_digest",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_sais = sais.wire2api();
            move |task_callback| anchor_digest(api_identifier, api_sais)
        },
    )
}
fn wire_add_watcher_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    watcher_oobi: impl Wire2Api<String> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "add_watcher",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_watcher_oobi = watcher_oobi.wire2api();
            move |task_callback| add_watcher(api_identifier, api_watcher_oobi)
        },
    )
}
fn wire_finalize_event_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    event: impl Wire2Api<String> + UnwindSafe,
    signature: impl Wire2Api<Signature> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "finalize_event",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_event = event.wire2api();
            let api_signature = signature.wire2api();
            move |task_callback| finalize_event(api_identifier, api_event, api_signature)
        },
    )
}
fn wire_incept_group_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    participants: impl Wire2Api<Vec<Identifier>> + UnwindSafe,
    signature_threshold: impl Wire2Api<u64> + UnwindSafe,
    initial_witnesses: impl Wire2Api<Vec<String>> + UnwindSafe,
    witness_threshold: impl Wire2Api<u64> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "incept_group",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_participants = participants.wire2api();
            let api_signature_threshold = signature_threshold.wire2api();
            let api_initial_witnesses = initial_witnesses.wire2api();
            let api_witness_threshold = witness_threshold.wire2api();
            move |task_callback| {
                incept_group(
                    api_identifier,
                    api_participants,
                    api_signature_threshold,
                    api_initial_witnesses,
                    api_witness_threshold,
                )
            }
        },
    )
}
fn wire_finalize_group_incept_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    group_event: impl Wire2Api<String> + UnwindSafe,
    signature: impl Wire2Api<Signature> + UnwindSafe,
    to_forward: impl Wire2Api<Vec<DataAndSignature>> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "finalize_group_incept",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_group_event = group_event.wire2api();
            let api_signature = signature.wire2api();
            let api_to_forward = to_forward.wire2api();
            move |task_callback| {
                finalize_group_incept(
                    api_identifier,
                    api_group_event,
                    api_signature,
                    api_to_forward,
                )
            }
        },
    )
}
fn wire_query_mailbox_impl(
    port_: MessagePort,
    who_ask: impl Wire2Api<Identifier> + UnwindSafe,
    about_who: impl Wire2Api<Identifier> + UnwindSafe,
    witness: impl Wire2Api<Vec<String>> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "query_mailbox",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_who_ask = who_ask.wire2api();
            let api_about_who = about_who.wire2api();
            let api_witness = witness.wire2api();
            move |task_callback| query_mailbox(api_who_ask, api_about_who, api_witness)
        },
    )
}
fn wire_finalize_mailbox_query_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    query_event: impl Wire2Api<String> + UnwindSafe,
    signature: impl Wire2Api<Signature> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "finalize_mailbox_query",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_query_event = query_event.wire2api();
            let api_signature = signature.wire2api();
            move |task_callback| {
                finalize_mailbox_query(api_identifier, api_query_event, api_signature)
            }
        },
    )
}
fn wire_resolve_oobi_impl(port_: MessagePort, oobi_json: impl Wire2Api<String> + UnwindSafe) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "resolve_oobi",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_oobi_json = oobi_json.wire2api();
            move |task_callback| resolve_oobi(api_oobi_json)
        },
    )
}
fn wire_query_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    oobis_json: impl Wire2Api<String> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "query",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_oobis_json = oobis_json.wire2api();
            move |task_callback| query(api_identifier, api_oobis_json)
        },
    )
}
fn wire_process_stream_impl(port_: MessagePort, stream: impl Wire2Api<String> + UnwindSafe) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "process_stream",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_stream = stream.wire2api();
            move |task_callback| process_stream(api_stream)
        },
    )
}
fn wire_get_kel_impl(port_: MessagePort, identifier: impl Wire2Api<Identifier> + UnwindSafe) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "get_kel",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            move |task_callback| get_kel(api_identifier)
        },
    )
}
fn wire_get_current_public_key_impl(
    port_: MessagePort,
    attachment: impl Wire2Api<String> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "get_current_public_key",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_attachment = attachment.wire2api();
            move |task_callback| get_current_public_key(api_attachment)
        },
    )
}
fn wire_new__static_method__DataAndSignature_impl(
    port_: MessagePort,
    data: impl Wire2Api<String> + UnwindSafe,
    signature: impl Wire2Api<Signature> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "new__static_method__DataAndSignature",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_data = data.wire2api();
            let api_signature = signature.wire2api();
            move |task_callback| Ok(DataAndSignature::new(api_data, api_signature))
        },
    )
}
// Section: wrapper structs

#[derive(Clone)]
struct mirror_KeriPublicKey(KeriPublicKey);

#[derive(Clone)]
struct mirror_KeyType(KeyType);

#[derive(Clone)]
struct mirror_PublicKey(PublicKey);

#[derive(Clone)]
struct mirror_Signature(Signature);

#[derive(Clone)]
struct mirror_SignatureType(SignatureType);

// Section: static checks

const _: fn() = || {
    {
        let KeriPublicKey = None::<KeriPublicKey>.unwrap();
        let _: Vec<u8> = KeriPublicKey.public_key;
    }
    match None::<KeyType>.unwrap() {
        KeyType::ECDSAsecp256k1NT => {}
        KeyType::ECDSAsecp256k1 => {}
        KeyType::Ed25519NT => {}
        KeyType::Ed25519 => {}
        KeyType::Ed448NT => {}
        KeyType::Ed448 => {}
        KeyType::X25519 => {}
        KeyType::X448 => {}
    }
    {
        let PublicKey = None::<PublicKey>.unwrap();
        let _: KeyType = PublicKey.derivation;
        let _: KeriPublicKey = PublicKey.public_key;
    }
    {
        let Signature = None::<Signature>.unwrap();
        let _: SignatureType = Signature.derivation;
        let _: Vec<u8> = Signature.signature;
    }
    match None::<SignatureType>.unwrap() {
        SignatureType::Ed25519Sha512 => {}
        SignatureType::ECDSAsecp256k1Sha256 => {}
        SignatureType::Ed448 => {}
    }
};
// Section: allocate functions

// Section: impl Wire2Api

pub trait Wire2Api<T> {
    fn wire2api(self) -> T;
}

impl<T, S> Wire2Api<Option<T>> for *mut S
where
    *mut S: Wire2Api<T>,
{
    fn wire2api(self) -> Option<T> {
        (!self.is_null()).then(|| self.wire2api())
    }
}

impl Wire2Api<i32> for i32 {
    fn wire2api(self) -> i32 {
        self
    }
}

impl Wire2Api<KeyType> for i32 {
    fn wire2api(self) -> KeyType {
        match self {
            0 => KeyType::ECDSAsecp256k1NT,
            1 => KeyType::ECDSAsecp256k1,
            2 => KeyType::Ed25519NT,
            3 => KeyType::Ed25519,
            4 => KeyType::Ed448NT,
            5 => KeyType::Ed448,
            6 => KeyType::X25519,
            7 => KeyType::X448,
            _ => unreachable!("Invalid variant for KeyType: {}", self),
        }
    }
}

impl Wire2Api<SignatureType> for i32 {
    fn wire2api(self) -> SignatureType {
        match self {
            0 => SignatureType::Ed25519Sha512,
            1 => SignatureType::ECDSAsecp256k1Sha256,
            2 => SignatureType::Ed448,
            _ => unreachable!("Invalid variant for SignatureType: {}", self),
        }
    }
}
impl Wire2Api<u64> for u64 {
    fn wire2api(self) -> u64 {
        self
    }
}
impl Wire2Api<u8> for u8 {
    fn wire2api(self) -> u8 {
        self
    }
}

// Section: impl IntoDart

impl support::IntoDart for Action {
    fn into_dart(self) -> support::DartAbi {
        match self {
            Self::MultisigRequest => 0,
            Self::DelegationRequest => 1,
        }
        .into_dart()
    }
}
impl support::IntoDart for ActionRequired {
    fn into_dart(self) -> support::DartAbi {
        vec![
            self.action.into_dart(),
            self.data.into_dart(),
            self.additiona_data.into_dart(),
        ]
        .into_dart()
    }
}
impl support::IntoDartExceptPrimitive for ActionRequired {}

impl support::IntoDart for Config {
    fn into_dart(self) -> support::DartAbi {
        vec![self.initial_oobis.into_dart()].into_dart()
    }
}
impl support::IntoDartExceptPrimitive for Config {}

impl support::IntoDart for DataAndSignature {
    fn into_dart(self) -> support::DartAbi {
        vec![
            self.data.into_dart(),
            mirror_Signature((*self.signature)).into_dart(),
        ]
        .into_dart()
    }
}
impl support::IntoDartExceptPrimitive for DataAndSignature {}

impl support::IntoDart for GroupInception {
    fn into_dart(self) -> support::DartAbi {
        vec![self.icp_event.into_dart(), self.exchanges.into_dart()].into_dart()
    }
}
impl support::IntoDartExceptPrimitive for GroupInception {}

impl support::IntoDart for Identifier {
    fn into_dart(self) -> support::DartAbi {
        vec![self.id.into_dart()].into_dart()
    }
}
impl support::IntoDartExceptPrimitive for Identifier {}

impl support::IntoDart for mirror_KeriPublicKey {
    fn into_dart(self) -> support::DartAbi {
        vec![self.0.public_key.into_dart()].into_dart()
    }
}
impl support::IntoDartExceptPrimitive for mirror_KeriPublicKey {}

impl support::IntoDart for mirror_KeyType {
    fn into_dart(self) -> support::DartAbi {
        match self.0 {
            KeyType::ECDSAsecp256k1NT => 0,
            KeyType::ECDSAsecp256k1 => 1,
            KeyType::Ed25519NT => 2,
            KeyType::Ed25519 => 3,
            KeyType::Ed448NT => 4,
            KeyType::Ed448 => 5,
            KeyType::X25519 => 6,
            KeyType::X448 => 7,
        }
        .into_dart()
    }
}

impl support::IntoDart for mirror_PublicKey {
    fn into_dart(self) -> support::DartAbi {
        vec![
            mirror_KeyType(self.0.derivation).into_dart(),
            mirror_KeriPublicKey(self.0.public_key).into_dart(),
        ]
        .into_dart()
    }
}
impl support::IntoDartExceptPrimitive for mirror_PublicKey {}

impl support::IntoDart for PublicKeySignaturePair {
    fn into_dart(self) -> support::DartAbi {
        vec![
            mirror_PublicKey(self.key).into_dart(),
            mirror_Signature(self.signature).into_dart(),
        ]
        .into_dart()
    }
}
impl support::IntoDartExceptPrimitive for PublicKeySignaturePair {}

impl support::IntoDart for mirror_Signature {
    fn into_dart(self) -> support::DartAbi {
        vec![
            mirror_SignatureType(self.0.derivation).into_dart(),
            self.0.signature.into_dart(),
        ]
        .into_dart()
    }
}
impl support::IntoDartExceptPrimitive for mirror_Signature {}

impl support::IntoDart for mirror_SignatureType {
    fn into_dart(self) -> support::DartAbi {
        match self.0 {
            SignatureType::Ed25519Sha512 => 0,
            SignatureType::ECDSAsecp256k1Sha256 => 1,
            SignatureType::Ed448 => 2,
        }
        .into_dart()
    }
}

// Section: executor

support::lazy_static! {
    pub static ref FLUTTER_RUST_BRIDGE_HANDLER: support::DefaultHandler = Default::default();
}

#[cfg(not(target_family = "wasm"))]
#[path = "bridge_generated.io.rs"]
mod io;
#[cfg(not(target_family = "wasm"))]
pub use io::*;
