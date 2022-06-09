use std::{path::PathBuf, sync::Arc};

// use anyhow::{anyhow, Result};

use crate::{
    event_generator,
    kel::{Kel, KelError},
};
use keri::{
    event::{
        event_data::EventData,
        sections::seal::{EventSeal, Seal},
        EventMessage,
    },
    event_message::{
        key_event_message::KeyEvent,
        signed_event_message::{Message, SignedEventMessage},
        Digestible,
    },
    event_parsing::{
        message::{event_message, key_event_message},
        EventType, SignedEventData,
    },
    oobi::{LocationScheme, OobiManager, Role, Scheme},
    prefix::{
        AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, SelfAddressingPrefix,
        SelfSigningPrefix,
    },
    processor::notification::JustNotification,
    query::reply_event::{ReplyEvent, ReplyRoute, SignedReply},
};

pub enum Topic {
    Oobi(Vec<u8>),
    Query(String),
    Process(Vec<u8>),
}

pub struct OptionalConfig {
    pub db_path: Option<PathBuf>,
    pub initial_oobis: Option<Vec<LocationScheme>>,
}

impl OptionalConfig {
    pub fn init() -> Self {
        Self {
            db_path: None,
            initial_oobis: None,
        }
    }

    pub fn with_initial_oobis(self, oobis: Vec<LocationScheme>) -> Self {
        Self {
            initial_oobis: Some(oobis),
            ..self
        }
    }
    pub fn with_db_path(self, db_path: PathBuf) -> Self {
        Self {
            db_path: Some(db_path),
            ..self
        }
    }
}

pub struct Controller {
    pub events_manager: Kel,
    oobi_manager: Arc<OobiManager>,
}
impl Controller {
    pub fn new(configs: Option<OptionalConfig>) -> Result<Self, KelError> {
        let (db_dir_path, initial_oobis) = match configs {
            Some(OptionalConfig {
                db_path,
                initial_oobis,
            }) => (db_path.unwrap_or(PathBuf::from("./db")), initial_oobis),
            None => (PathBuf::from("./db"), None),
        };

        let mut events_db = db_dir_path.clone();
        events_db.push("events");
        let mut oobis_db = db_dir_path.clone();
        oobis_db.push("oobis");

        let mut events_manager = Kel::init(
            events_db
                .to_str()
                .ok_or(KelError::DatabaseError("Improper path".into()))?,
        )?;
        let oobi_manager = Arc::new(OobiManager::new(&oobis_db));
        // TODO oobi manager should be independent of event manager
        events_manager.register_observer(oobi_manager.clone(), vec![JustNotification::GotOobi]);

        let controller = Self {
            events_manager,
            oobi_manager: oobi_manager.clone(),
        };

        if let Some(initial_oobis) = initial_oobis {
            controller.setup_witnesses(&initial_oobis)?;
        }

        Ok(controller)
    }

    pub fn setup_witnesses(&self, oobis: &[LocationScheme]) -> Result<(), KelError> {
        oobis
            .iter()
            .try_for_each(|lc| self.resolve_loc_schema(lc))?;
        Ok(())
    }

    /// Make http request to get identifier's endpoints information.
    pub fn resolve_loc_schema(&self, lc: &LocationScheme) -> Result<(), KelError> {
        let url = format!("{}oobi/{}", lc.url, lc.eid);
        let oobis = reqwest::blocking::get(url)
            .map_err(|e| KelError::CommunicationError(e.to_string()))?
            .text()
            .map_err(|e| KelError::CommunicationError(e.to_string()))?;

        self.events_manager.parse_and_process(oobis.as_bytes())
    }

    fn get_watchers(&self, id: &IdentifierPrefix) -> Result<Vec<IdentifierPrefix>, KelError> {
        Ok(self
            .oobi_manager
            .get_end_role(id, Role::Watcher)?
            .ok_or_else(|| KelError::UnknownIdentifierError)?
            .into_iter()
            .filter_map(|r| {
                if let ReplyRoute::EndRoleAdd(adds) = r.reply.get_route() {
                    Some(adds.eid)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>())
    }

    /// Sends identifier's endpoint information to identifiers's watchers.
    // TODO use stream instead of json
    pub fn send_oobi_to_watcher(
        &self,
        id: &IdentifierPrefix,
        end_role_json: &str,
    ) -> Result<(), KelError> {
        for watcher in self.get_watchers(id)?.iter() {
            self.send_to(
                &watcher,
                Scheme::Http,
                Topic::Oobi(end_role_json.as_bytes().to_vec()),
            )?;
        }

        Ok(())
    }

    /// Query watcher (TODO randomly chosen, for now asks first found watcher)
    /// about id kel and updates local kel.
    pub fn query(&self, id: &IdentifierPrefix, query_id: &str) -> Result<(), KelError> {
        let watchers = self.get_watchers(id)?;
        // TODO choose random watcher id?
        // TODO we assume that we get the answer immediately which is not always true
        let kel = self.send_to(&watchers[0], Scheme::Http, Topic::Query(query_id.into()))?;

        self.events_manager.parse_and_process(kel.as_bytes())?;
        Ok(())
    }

    /// Returns identifier contact information.
    pub fn get_loc_schemas(&self, id: &IdentifierPrefix) -> Result<Vec<LocationScheme>, KelError> {
        Ok(self
            .oobi_manager
            .get_loc_scheme(id)?
            .ok_or_else(|| KelError::UnknownIdentifierError)?
            .iter()
            .filter_map(|lc| {
                if let ReplyRoute::LocScheme(loc_scheme) = lc.get_route() {
                    Ok(loc_scheme)
                } else {
                    Err(KelError::GeneralError("Wrong route type".into()))
                }
                .ok()
            })
            .collect())
    }

    pub fn send_to(
        &self,
        watcher_id: &IdentifierPrefix,
        schema: Scheme,
        topic: Topic,
    ) -> Result<String, KelError> {
        let addresses = self.get_loc_schemas(&watcher_id)?;
        match addresses
            .iter()
            // TODO It uses first found address that match schema
            .find(|loc| loc.scheme == schema)
            .map(|lc| &lc.url)
        {
            Some(address) => match schema {
                Scheme::Http => {
                    let client = reqwest::blocking::Client::new();
                    let response = match topic {
                        Topic::Oobi(oobi_json) => client
                            .post(format!("{}resolve", address))
                            .body(oobi_json)
                            .send()
                            .map_err(|e| KelError::GeneralError(e.to_string()))?
                            .text()
                            .map_err(|e| KelError::GeneralError(e.to_string()))?,
                        Topic::Query(id) => client
                            .get(format!("{}query/{}", address, id))
                            .send()
                            .map_err(|e| KelError::GeneralError(e.to_string()))?
                            .text()
                            .map_err(|e| KelError::GeneralError(e.to_string()))?,
                        Topic::Process(to_process) => client
                            .post(format!("{}process", address))
                            .body(to_process)
                            .send()
                            .map_err(|e| KelError::GeneralError(e.to_string()))?
                            .text()
                            .map_err(|e| KelError::GeneralError(e.to_string()))?,
                    };

                    Ok(response)
                }
                Scheme::Tcp => {
                    todo!()
                }
            },
            _ => Err(KelError::GeneralError(format!(
                "No address for scheme {:?}",
                schema
            ))),
        }
    }

    /// Publish key event to witnesses
    ///
    ///  1. send it to all witnesses
    ///  2. collect witness receipts and process them
    ///  3. get processed receipts from db and send it to all witnesses
    pub fn publish(
        &self,
        witness_prefixes: &[BasicPrefix],
        message: &SignedEventMessage,
    ) -> Result<(), KelError> {
        let msg = SignedEventData::from(message).to_cesr()?;
        let collected_receipts = witness_prefixes
            .iter()
            .map(|prefix| {
                self.send_to(
                    &IdentifierPrefix::Basic(prefix.clone()),
                    Scheme::Http,
                    Topic::Process(msg.clone()),
                )
            })
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .join("");

        // Kel should be empty because event is not fully witnessed
        // assert!(self.kel.get_kel(self.kel.prefix()).unwrap().is_none());

        // process collected receipts
        self.events_manager
            .parse_and_process(collected_receipts.as_bytes())?;

        // Now event is fully witnessed
        // assert!(self.kel.get_kel(self.kel.prefix()).unwrap().is_some());

        // Get processed receipts from database to send all of them to witnesses. It
        // will return one receipt with all witness signatures as one attachment,
        // not three separate receipts as in `collected_receipts`.
        let rcts_from_db = self.events_manager.get_receipts_of_event(EventSeal {
            prefix: message.event_message.event.get_prefix(),
            sn: message.event_message.event.get_sn(),
            event_digest: message.event_message.event.get_digest(),
        })?;

        match rcts_from_db {
            Some(receipts) => {
                let serialized_receipts = SignedEventData::from(receipts).to_cesr()?;
                // send receipts to all witnesses
                witness_prefixes
                    .iter()
                    .try_for_each(|prefix| -> Result<_, KelError> {
                        self.send_to(
                            &IdentifierPrefix::Basic(prefix.clone()),
                            Scheme::Http,
                            Topic::Process(serialized_receipts.clone()),
                        )?;
                        Ok(())
                    })?;
            }
            None => (),
        };

        Ok(())
    }

    pub fn incept(
        &self,
        public_keys: Vec<BasicPrefix>,
        next_pub_keys: Vec<BasicPrefix>,
        witnesses: Vec<LocationScheme>,
        witness_threshold: u64,
    ) -> Result<String, KelError> {
        self.setup_witnesses(&witnesses)?;
        let witnesses = witnesses
            .iter()
            .map(|wit| {
                if let IdentifierPrefix::Basic(bp) = &wit.eid {
                    Ok(bp.clone())
                } else {
                    Err(KelError::GeneralError(
                        "Improper witness prefix, should be basic prefix".into(),
                    ))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(event_generator::incept(
            public_keys,
            next_pub_keys,
            witnesses,
            witness_threshold,
        )?)
    }

    pub fn finalize_inception(
        &self,
        event: &[u8],
        sig: Vec<SelfSigningPrefix>,
    ) -> Result<IdentifierPrefix, KelError> {
        let (_, parsed_event) =
            key_event_message(&event).map_err(|e| KelError::ParseEventError(e.to_string()))?;
        match parsed_event {
            EventType::KeyEvent(ke) => {
                if let EventData::Icp(_) = &ke.event.get_event_data() {
                    self.finalize_key_event(&ke, sig)?;
                    Ok(ke.event.get_prefix())
                } else {
                    Err(KelError::ParseEventError(
                        "Wrong event type, should be inception event".into(),
                    ))
                }
            }
            _ => Err(KelError::ParseEventError(
                "Wrong event type, should be inception event".into(),
            )),
        }
    }

    pub fn rotate(
        &self,
        id: IdentifierPrefix,
        current_keys: Vec<BasicPrefix>,
        new_next_keys: Vec<BasicPrefix>,
        witness_to_add: Vec<LocationScheme>,
        witness_to_remove: Vec<BasicPrefix>,
        witness_threshold: u64,
    ) -> Result<String, KelError> {
        self.setup_witnesses(&witness_to_add)?;
        let witnesses_to_add = witness_to_add
            .iter()
            .map(|wit| {
                if let IdentifierPrefix::Basic(bp) = &wit.eid {
                    Ok(bp.clone())
                } else {
                    Err(KelError::GeneralError(
                        "Improper witness prefix, should be basic prefix".into(),
                    ))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        let state = self.events_manager.get_state_for_id(&id)?;

        Ok(event_generator::rotate(
            state,
            current_keys,
            new_next_keys,
            witnesses_to_add,
            witness_to_remove,
            witness_threshold,
        )?)
    }

    pub fn anchor(
        &self,
        id: IdentifierPrefix,
        payload: &[SelfAddressingPrefix],
    ) -> Result<EventMessage<KeyEvent>, KelError> {
        let state = self.events_manager.get_state_for_id(&id)?;
        Ok(event_generator::anchor(state, payload)?)
    }

    pub fn anchor_with_seal(
        &self,
        id: IdentifierPrefix,
        payload: &[Seal],
    ) -> Result<EventMessage<KeyEvent>, KelError> {
        let state = self.events_manager.get_state_for_id(&id)?;
        Ok(event_generator::anchor_with_seal(state, payload)?)
    }

    /// Check signatures, updates database and send events to watcher or witnesses.
    pub fn finalize_event(
        &self,
        id: &IdentifierPrefix,
        event: &[u8],
        sig: Vec<SelfSigningPrefix>,
    ) -> Result<(), KelError> {
        let parsed_event = event_message(event)
            .map_err(|e| KelError::ParseEventError(e.to_string()))?
            .1;

        match parsed_event {
            EventType::KeyEvent(ke) => Ok(self.finalize_key_event(&ke, sig)?),
            EventType::Receipt(_) => todo!(),
            EventType::Qry(_) => todo!(),
            EventType::Rpy(rpy) => match rpy.get_route() {
                ReplyRoute::EndRoleAdd(_) => Ok(self.finalize_add_role(id, rpy, sig)?),
                ReplyRoute::EndRoleCut(_) => todo!(),
                _ => Err(KelError::GeneralError("Wrong event type".into())),
            },
        }
    }

    fn finalize_key_event(
        &self,
        event: &EventMessage<KeyEvent>,
        sig: Vec<SelfSigningPrefix>,
    ) -> Result<(), KelError> {
        let sigs = sig
            .into_iter()
            .enumerate()
            .map(|(i, sig)| AttachedSignaturePrefix {
                index: i as u16,
                signature: sig,
            })
            .collect();

        let signed_message = event.sign(sigs, None, None);
        self.events_manager
            .process(&Message::Event(signed_message.clone()))?;

        let wits = match event.event.get_event_data() {
            EventData::Icp(icp) => icp.witness_config.initial_witnesses,
            EventData::Rot(rot) => {
                let wits = self
                    .events_manager
                    .get_current_witness_list(&event.event.content.prefix)?;
                wits.into_iter()
                    .filter(|w| !rot.witness_config.prune.contains(w))
                    .chain(rot.witness_config.graft.into_iter())
                    .collect::<Vec<_>>()
            }
            EventData::Ixn(_) => self
                .events_manager
                .get_current_witness_list(&event.event.content.prefix)?,
            EventData::Dip(_) => todo!(),
            EventData::Drt(_) => todo!(),
        };

        self.publish(&wits, &signed_message)
    }

    fn finalize_add_role(
        &self,
        signer_prefix: &IdentifierPrefix,
        event: ReplyEvent,
        sig: Vec<SelfSigningPrefix>,
    ) -> Result<(), KelError> {
        let sigs = sig
            .into_iter()
            .enumerate()
            .map(|(i, sig)| AttachedSignaturePrefix {
                index: i as u16,
                signature: sig,
            })
            .collect();

        let dest_prefix = match &event.event.content.data {
            ReplyRoute::Ksn(_, _) => todo!(),
            ReplyRoute::LocScheme(_) => todo!(),
            ReplyRoute::EndRoleAdd(role) => role.eid.clone(),
            ReplyRoute::EndRoleCut(role) => role.eid.clone(),
        };
        let signed_rpy = SignedReply::new_trans(
            event,
            self.events_manager
                .get_last_establishment_event_seal(signer_prefix)?,
            sigs,
        );
        self.oobi_manager.save_oobi(signed_rpy.clone()).unwrap();
        let mut kel = self
            .events_manager
            .get_kel(&signer_prefix)?
            .as_bytes()
            .to_vec();
        let end_role = SignedEventData::from(signed_rpy).to_cesr()?;
        kel.extend(end_role.iter());

        self.send_to(&dest_prefix, Scheme::Http, Topic::Process(kel))?;
        Ok(())
    }
}
