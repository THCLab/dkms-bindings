use std::path::PathBuf;

use keri::controller::utils::OptionalConfig;
use napi_derive::napi;

#[napi]
pub struct ConfigBuilder {
    pub db_path: Option<String>,
    pub initial_oobis: Option<String>,
}

#[napi]
impl ConfigBuilder {
    #[napi(constructor)]
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
    pub fn build(&self) -> napi::Result<OptionalConfig> {
        let oobis = if let Some(oobis) = &self.initial_oobis {
            serde_json::from_str(oobis)?
        } else {
            None
        };
        let db_path = if let Some(db_path) = &self.db_path {
            Some(PathBuf::from(db_path))
        } else {
            None
        };
        Ok(OptionalConfig {
            initial_oobis: oobis,
            db_path,
        })
    }
}
