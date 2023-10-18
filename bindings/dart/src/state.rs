use std::sync::Arc;

use controller::{config::ControllerConfig, Controller};

use crate::api::Identifier;

pub struct Current {
    controller: Arc<Controller>,
    registry_map: sled::Db,
    tree: sled::Tree,
}
use anyhow::Result;

impl Current {
    pub fn new(config: ControllerConfig) -> Result<Self> {
        let mut path = config.db_path.clone();
        path.push("registry");
        let registry_db = sled::open(path)?;
        let tree = registry_db.open_tree("registry")?;

        let controller = Arc::new(controller::Controller::new(config)?);
        Ok(Self {
            controller,
            registry_map: registry_db,
            tree,
        })
    }

    pub fn insert(&mut self, identifier: Identifier, registry_id: &str) -> Result<()> {
        self.tree.insert(identifier.to_str(), registry_id)?;
        self.registry_map.flush()?;
        Ok(())
    }

    pub fn controller(&self) -> Arc<Controller> {
        self.controller.clone()
    }

    pub fn registry_id(&self, id: &Identifier) -> Result<Option<String>> {
        Ok(match self.tree.get(id.to_str())? {
            Some(value) => Some(std::str::from_utf8(value.as_ref())?.to_string()),
            None => None,
        })
    }
}
