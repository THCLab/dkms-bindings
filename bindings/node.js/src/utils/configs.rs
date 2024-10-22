use std::path::PathBuf;

use keri_controller::{config::ControllerConfig, LocationScheme};
use napi_derive::napi;

#[napi(constructor)]
pub struct ConfigBuilder {
    pub db_path: Option<String>,
    pub initial_oobis: Option<String>,
}

#[napi]
impl ConfigBuilder {
    // #[napi(constructor)]
    pub fn new() -> Self {
        ConfigBuilder {
            db_path: None,
            initial_oobis: None,
        }
    }

    #[napi]
    pub fn with_initial_oobis(&self, oobis_json: String) -> ConfigBuilder {
        ConfigBuilder {
            initial_oobis: Some(oobis_json),
            db_path: self.db_path.clone(),
        }
    }

    #[napi]
    pub fn with_db_path(&self, db_path: String) -> ConfigBuilder {
        ConfigBuilder {
            db_path: Some(db_path),
            initial_oobis: self.initial_oobis.clone(),
        }
    }

    #[napi]
    pub fn build(&self) -> Configs {
        Configs {
            db_path: self.db_path.clone(),
            initial_oobis: self.initial_oobis.clone(),
        }
    }
}

#[napi(object)]
pub struct Configs {
    pub db_path: Option<String>,
    pub initial_oobis: Option<String>,
}

impl Configs {
    pub fn build(&self) -> napi::Result<ControllerConfig> {
        let oobis = if let Some(oobis) = &self.initial_oobis {
            vec![serde_json::from_str::<LocationScheme>(oobis).ok().unwrap()]
        } else {
            vec![]
        };
        let db_path = self.db_path.as_ref().map(PathBuf::from);
        let c = ControllerConfig::default();
        Ok(ControllerConfig {
            initial_oobis: oobis,
            db_path: db_path.unwrap(),
            ..c
        })
    }
}
