use std::{collections::HashMap, sync::Arc};

use controller::{config::ControllerConfig, Controller};

use crate::api::Identifier;

pub struct Current {
    controller: Arc<Controller>,
    registry_map: HashMap<Identifier, String>,
}
use anyhow::Result;

impl Current {
    pub fn new(config: ControllerConfig) -> Result<Self> {
        let controller = Arc::new(controller::Controller::new(config)?);
        Ok(Self {
            controller,
            registry_map: HashMap::new(),
        })
    }

    pub fn insert(&mut self, identifier: Identifier, registry_id: String) -> Result<()> {
        self.registry_map.insert(identifier, registry_id);
        Ok(())
    }

    pub fn controller(&self) -> Arc<Controller> {
        self.controller.clone()
    }

    pub fn registry_id(&self, id: &Identifier) -> Option<String> {
        self.registry_map.get(&id).map(|e| e.clone())
    }
}
