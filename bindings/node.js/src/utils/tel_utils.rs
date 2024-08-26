use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

#[napi]
pub struct RegistryInceptionData {
    pub ixn: Buffer,
    pub registry_id: String,
}

#[napi]
pub struct IssuanceData {
    pub ixn: Buffer,
    pub vc_hash: String,
}
