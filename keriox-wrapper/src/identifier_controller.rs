use std::sync::Arc;

use keri::{
    event::{sections::seal::Seal, EventMessage},
    event_message::{key_event_message::KeyEvent, signed_event_message::Message},
    event_parsing::{message::key_event_message, EventType},
    oobi::Role,
    prefix::{
        AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, SelfAddressingPrefix,
        SelfSigningPrefix,
    },
    processor::{event_storage::EventStorage, EventProcessor},
    query::reply_event::{ReplyRoute, SignedReply},
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
        witness_to_add: Vec<String>,
        witness_to_remove: Vec<String>,
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

    pub fn finalize_event(
        &self,
        event: &[u8],
        sig: Vec<SelfSigningPrefix>,
    ) -> Result<(), KelError> {
        let parsed_event = key_event_message(event)
            .map_err(|e| KelError::ParseEventError(e.to_string()))?
            .1;
        match parsed_event {
            keri::event_parsing::EventType::KeyEvent(ke) => {
				self.source.kel.finalize_event(ke, sig)
			},
            EventType::Receipt(_) => todo!(),
            EventType::Qry(_) => todo!(),
            EventType::Rpy(rpy) => match rpy.get_route() {
                ReplyRoute::Ksn(_, _) => todo!(),
                ReplyRoute::LocScheme(_) => todo!(),
                ReplyRoute::EndRoleAdd(_) => {
                    let sigs = sig
                        .into_iter()
                        .enumerate()
                        .map(|(i, sig)| AttachedSignaturePrefix {
                            index: i as u16,
                            signature: sig,
                        })
                        .collect();

                    let storage = EventStorage::new(self.source.kel.db.clone());
                    let signed_rpy = SignedReply::new_trans(
                        rpy,
                        storage
                            .get_last_establishment_event_seal(&self.id)
                            .unwrap()
                            .unwrap(),
                        sigs,
                    );
                    Ok(self
                        .source
                        .oobi_manager
                        .save_oobi(signed_rpy.clone())
                        .unwrap())
                }
                ReplyRoute::EndRoleCut(_) => todo!(),
            },
        }
    }
}
