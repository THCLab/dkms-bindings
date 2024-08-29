use keri_controller::LocationScheme;
use napi_derive::napi;

use crate::utils::key_config::JsPublicKey;

#[napi]
pub struct InceptionConfiguration {
    pub current_public_keys: Vec<String>,
    pub next_public_keys: Vec<String>,
    // witnesses location schemes jsons
    pub witnesses_location: Vec<String>,
    pub witness_threshold: u32,
}

#[napi]
impl InceptionConfiguration {
    #[napi(constructor)]
    pub fn new() -> Self {
        InceptionConfiguration {
            current_public_keys: vec![],
            next_public_keys: vec![],
            witnesses_location: vec![],
            witness_threshold: 0,
        }
    }

    #[napi]
	pub fn with_current_keys(&self, keys: Vec<&JsPublicKey>) -> InceptionConfiguration {
		let keys_str = keys.into_iter().map(|k| k.get_key().p).collect();
		InceptionConfiguration {
			current_public_keys: keys_str,
			next_public_keys: self.next_public_keys.clone(),
            witnesses_location: self.witnesses_location.clone(),
			witness_threshold: self.witness_threshold.clone()
		}
	}

	#[napi]
	pub fn with_next_keys(&mut self, keys: Vec<&JsPublicKey>) -> InceptionConfiguration {
		let keys_str = keys.into_iter().map(|k| k.get_key().p).collect();
		InceptionConfiguration {
			current_public_keys: self.current_public_keys.clone(),
			next_public_keys: keys_str,
            witnesses_location: self.witnesses_location.clone(),
			witness_threshold: self.witness_threshold.clone()
		}
	}

	#[napi]
	pub fn with_witness(&mut self, locations: Vec<String>) -> InceptionConfiguration {
		let _lc: Vec<LocationScheme> = locations.iter().map(|l| {
			serde_json::from_str::<LocationScheme>(&l).unwrap()
		}).collect();
		InceptionConfiguration {
			current_public_keys: self.current_public_keys.clone(),
			next_public_keys: self.next_public_keys.clone(),
            witnesses_location: locations,
			witness_threshold: self.witness_threshold.clone()
		}
	}

	#[napi]
	pub fn with_witness_threshold(&mut self, threshold: u32) -> InceptionConfiguration {
		InceptionConfiguration {
			current_public_keys: self.current_public_keys.clone(),
			next_public_keys: self.next_public_keys.clone(),
            witnesses_location: self.witnesses_location.clone(),
			witness_threshold: threshold
		}
	}
}