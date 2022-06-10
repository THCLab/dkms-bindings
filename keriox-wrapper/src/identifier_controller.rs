use std::sync::Arc;

use keri::{
    event::{
        sections::seal::{EventSeal, Seal},
        EventMessage,
    },
    event_message::key_event_message::KeyEvent,
    oobi::{LocationScheme, Role},
    prefix::{BasicPrefix, IdentifierPrefix, SelfAddressingPrefix, SelfSigningPrefix},
};

use crate::{controller::Controller, event_generator, kel::KelError};

pub struct IdentifierController {
    pub id: IdentifierPrefix,
    pub source: Arc<Controller>,
}

impl IdentifierController {
    pub fn new(id: IdentifierPrefix, kel: Arc<Controller>) -> Self {
        Self { id, source: kel }
    }

    pub fn get_kel(&self) -> Result<String, KelError> {
        self.source.events_manager.get_kel(&self.id)
    }

    pub fn rotate(
        &self,
        current_keys: Vec<BasicPrefix>,
        new_next_keys: Vec<BasicPrefix>,
        witness_to_add: Vec<LocationScheme>,
        witness_to_remove: Vec<BasicPrefix>,
        witness_threshold: u64,
    ) -> Result<String, KelError> {
        self.source.rotate(
            self.id.clone(),
            current_keys,
            new_next_keys,
            witness_to_add,
            witness_to_remove,
            witness_threshold,
        )
    }

    pub fn anchor(
        &self,
        payload: &[SelfAddressingPrefix],
    ) -> Result<EventMessage<KeyEvent>, KelError> {
        self.source.anchor(self.id.clone(), payload)
    }

    pub fn anchor_with_seal(&self, seal_list: &[Seal]) -> Result<EventMessage<KeyEvent>, KelError> {
        self.source.anchor_with_seal(self.id.clone(), seal_list)
    }

    pub fn add_watcher(&self, watcher_id: IdentifierPrefix) -> String {
        String::from_utf8(
            event_generator::generate_end_role(&self.id, &watcher_id, Role::Watcher, true)
                .unwrap()
                .serialize()
                .unwrap(),
        )
        .unwrap()
    }

    pub fn remove_watcher(&self, watcher_id: IdentifierPrefix) -> String {
        String::from_utf8(
            event_generator::generate_end_role(&self.id, &watcher_id, Role::Watcher, false)
                .unwrap()
                .serialize()
                .unwrap(),
        )
        .unwrap()
    }

    /// Check signatures, updates database and send events to watcher or witnesses.
    pub fn finalize_event(
        &self,
        event: &[u8],
        sig: Vec<SelfSigningPrefix>,
    ) -> Result<(), KelError> {
        Ok(self.source.finalize_event(&self.id, event, sig).unwrap())
    }

    pub fn get_last_establishment_event_seal(&self) -> Result<EventSeal, KelError> {
        self.source
            .events_manager
            .get_last_establishment_event_seal(&self.id)
    }
}
