use std::sync::Arc;

use keri::{
    event::{sections::seal::Seal, EventMessage},
    event_message::{key_event_message::KeyEvent},
    event_parsing::{message::key_event_message, EventType},
    oobi::Role,
    prefix::{
        BasicPrefix, IdentifierPrefix, SelfAddressingPrefix,
        SelfSigningPrefix,
    },
    processor::event_storage::EventStorage,
    query::reply_event::ReplyRoute,
};

use crate::{controller::Controller, kel::KelError};

pub struct IdentifierController {
    pub id: IdentifierPrefix,
    pub source: Arc<Controller>,
}

impl IdentifierController {
    pub fn new(id: IdentifierPrefix, kel: Arc<Controller>) -> Self {
        Self { id, source: kel }
    }

    pub fn get_kel(&self) -> Result<String, KelError> {
        let storage = EventStorage::new(self.source.kel.db.clone());
        String::from_utf8(
            storage
                .get_kel(&self.id)?
                .ok_or(KelError::UnknownIdentifierError)?,
        )
        .map_err(|e| KelError::ParseEventError(e.to_string()))
    }

    pub fn rotate(
        &self,
        current_keys: Vec<BasicPrefix>,
        new_next_keys: Vec<BasicPrefix>,
        witness_to_add: Vec<BasicPrefix>,
        witness_to_remove: Vec<BasicPrefix>,
        witness_threshold: u64,
    ) -> Result<String, KelError> {
        self.source.kel.rotate(
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
        self.source.kel.anchor(self.id.clone(), payload)
    }

    pub fn anchor_with_seal(&self, seal_list: &[Seal]) -> Result<EventMessage<KeyEvent>, KelError> {
        self.source.kel.anchor_with_seal(self.id.clone(), seal_list)
    }

    pub fn add_watcher(&self, watcher_id: IdentifierPrefix) -> String {
        String::from_utf8(
            self.source
                .generate_end_role(&self.id, &watcher_id, Role::Watcher, true)
                .unwrap()
                .serialize()
                .unwrap(),
        )
        .unwrap()
    }

    pub fn remove_watcher(&self, watcher_id: IdentifierPrefix) -> String {
        String::from_utf8(
            self.source
                .generate_end_role(&self.id, &watcher_id, Role::Watcher, false)
                .unwrap()
                .serialize()
                .unwrap(),
        )
        .unwrap()
    }

    /// Check signatures, updates database and send events to watcher or witnesses.
    pub async fn finalize_event(
        &self,
        event: &[u8],
        sig: Vec<SelfSigningPrefix>,
    ) -> Result<(), KelError> {
        let parsed_event = key_event_message(event)
            .map_err(|e| KelError::ParseEventError(e.to_string()))?
            .1;
        match parsed_event {
            EventType::KeyEvent(ke) => Ok(self
                .source
                .finalize_key_event(ke, sig)
                .await
                .unwrap_or_default()),
            EventType::Receipt(_) => todo!(),
            EventType::Qry(_) => todo!(),
            EventType::Rpy(rpy) => match rpy.get_route() {
                ReplyRoute::Ksn(_, _) => todo!(),
                ReplyRoute::LocScheme(_) => todo!(),
                ReplyRoute::EndRoleAdd(_) => {
                    Ok(self.source.finalize_add_role(&self.id, rpy, sig).await.unwrap())
                }
                ReplyRoute::EndRoleCut(_) => todo!(),
            },
        }
    }
}
