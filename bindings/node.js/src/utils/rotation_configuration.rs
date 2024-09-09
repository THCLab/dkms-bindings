use keri_controller::LocationScheme;
use napi_derive::napi;

use crate::utils::key_config::JsPublicKey;

#[napi]
pub struct RotationConfiguration {
    pub current_public_keys: Vec<String>,
    pub next_public_keys: Vec<String>,
    // witnesses location schemes json
    pub witnesses_to_add: Vec<String>,
    // identifiers of witnesses to remove
    pub witnesses_to_remove: Vec<String>,
    pub witness_threshold: u32,
}

#[napi]
impl RotationConfiguration {
    #[napi(constructor)]
    pub fn new() -> Self {
        RotationConfiguration {
            current_public_keys: vec![],
            next_public_keys: vec![],
            witnesses_to_add: vec![],
            witnesses_to_remove: vec![],
            witness_threshold: 0,
        }
    }

    #[napi]
    pub fn with_current_keys(&self, keys: Vec<&JsPublicKey>) -> RotationConfiguration {
        let keys_str = keys.into_iter().map(|k| k.get_key().p).collect();
        RotationConfiguration {
            current_public_keys: keys_str,
            next_public_keys: self.next_public_keys.clone(),
            witnesses_to_add: self.witnesses_to_add.clone(),
            witnesses_to_remove: self.witnesses_to_remove.clone(),
            witness_threshold: self.witness_threshold.clone(),
        }
    }

    #[napi]
    pub fn with_next_keys(&mut self, keys: Vec<&JsPublicKey>) -> RotationConfiguration {
        let keys_str = keys.into_iter().map(|k| k.get_key().p).collect();
        RotationConfiguration {
            current_public_keys: self.current_public_keys.clone(),
            next_public_keys: keys_str,
            witnesses_to_add: self.witnesses_to_add.clone(),
            witnesses_to_remove: self.witnesses_to_remove.clone(),
            witness_threshold: self.witness_threshold.clone(),
        }
    }

    #[napi]
    pub fn with_witness_to_add(&mut self, locations: Vec<String>) -> RotationConfiguration {
        let _lc: Vec<LocationScheme> = locations
            .iter()
            .map(|l| serde_json::from_str::<LocationScheme>(&l).unwrap())
            .collect();
        RotationConfiguration {
            current_public_keys: self.current_public_keys.clone(),
            next_public_keys: self.next_public_keys.clone(),
            witnesses_to_add: locations,
            witnesses_to_remove: self.witnesses_to_remove.clone(),
            witness_threshold: self.witness_threshold.clone(),
        }
    }

    #[napi]
    pub fn with_witness_to_remove(&mut self, witness_ids: Vec<String>) -> RotationConfiguration {
        RotationConfiguration {
            current_public_keys: self.current_public_keys.clone(),
            next_public_keys: self.next_public_keys.clone(),
            witnesses_to_add: self.witnesses_to_add.clone(),
            witnesses_to_remove: witness_ids,
            witness_threshold: self.witness_threshold.clone(),
        }
    }

    #[napi]
    pub fn with_witness_threshold(&mut self, threshold: u32) -> RotationConfiguration {
        RotationConfiguration {
            current_public_keys: self.current_public_keys.clone(),
            next_public_keys: self.next_public_keys.clone(),
            witnesses_to_add: self.witnesses_to_add.clone(),
            witnesses_to_remove: self.witnesses_to_remove.clone(),
            witness_threshold: threshold,
        }
    }
}
