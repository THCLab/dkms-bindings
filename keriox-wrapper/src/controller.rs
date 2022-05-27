use std::{path::PathBuf, sync::Arc};

// use anyhow::{anyhow, Result};

use crate::{
    event_generator,
    kel::{Kel, KelError},
};
use keri::{
    derivation::self_addressing::SelfAddressing,
    event::{
        event_data::EventData,
        sections::seal::{EventSeal, Seal},
        EventMessage, SerializationFormats,
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
    oobi::{EndRole, LocationScheme, OobiManager, Role, Scheme},
    prefix::{
        AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, Prefix, SelfAddressingPrefix,
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
        let (initial_oobis, db_path) = if let Some(configs) = configs {
            (configs.initial_oobis, configs.db_path)
        } else {
            (None, Some(PathBuf::from("./db")))
        };

        let db_dir_path = match db_path {
            Some(db_path) => db_path,
            None => PathBuf::from("./db"),
        };

        let mut events_db = db_dir_path.clone();
        events_db.push("events");
        let mut oobis_db = db_dir_path.clone();
        oobis_db.push("oobis");

        let mut keri = Kel::init(events_db.to_str().unwrap());
        let oobi_manager = Arc::new(OobiManager::new(&oobis_db));
        keri.register_observer(oobi_manager.clone(), vec![JustNotification::GotOobi]);

        let controller = Self {
            events_manager: keri,
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
            .map_err(|e| KelError::GeneralError(e.to_string()))?
            .text()
            .map_err(|e| KelError::GeneralError(e.to_string()))?;
        println!("\n\nin resolve oobi got: {}", oobis);

        self.events_manager
            .parse_and_process(oobis.as_bytes())
            .unwrap();

        Ok(())
    }

    fn get_watchers(&self, id: &IdentifierPrefix) -> Result<Vec<IdentifierPrefix>, KelError> {
        Ok(self
            .oobi_manager
            .get_end_role(id, Role::Watcher)?
            .unwrap()
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

    /// Sends identifier's endpoint information to id's watchers.
    pub fn send_oobi_to_watcher(
        &self,
        id: &IdentifierPrefix,
        end_role_json: &str,
    ) -> Result<(), KelError> {
        self.get_watchers(id)?.iter().for_each(|watcher| {
            self.send_to(
                &watcher,
                Scheme::Http,
                Topic::Oobi(end_role_json.as_bytes().to_vec()),
            )
            .unwrap();
        });

        Ok(())
    }

    /// Query watcher (TODO randomly chosen, for now asks first found watcher)
    /// about id kel and updates local kel.
    pub fn query(&self, id: &IdentifierPrefix, query_id: &str) -> Result<(), KelError> {
        let watchers = self.get_watchers(id)?;
        // TODO choose random watcher id?
        let kel = self.send_to(&watchers[0], Scheme::Http, Topic::Query(query_id.into()))?;
        match kel {
            Some(kel) => {
                self.events_manager.parse_and_process(kel.as_bytes())?;
                Ok(())
            }
            None => Err(KelError::GeneralError(format!(
                "Can't find kel of identifier {}",
                id.to_str()
            ))),
        }
    }

    /// Returns identifier contact information.
    pub fn get_loc_schemas(&self, id: &IdentifierPrefix) -> Result<Vec<LocationScheme>, KelError> {
        Ok(self
            .oobi_manager
            .get_loc_scheme(id)?
            .unwrap()
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
    ) -> Result<Option<String>, KelError> {
        let addresses = self.get_loc_schemas(&watcher_id)?;
        match addresses
            .iter()
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
                            .unwrap()
                            .text()
                            .unwrap(),
                        Topic::Query(id) => client
                            .get(format!("{}query/{}", address, id))
                            .send()
                            .unwrap()
                            .text()
                            .unwrap(),
                        Topic::Process(to_process) => client
                            .post(format!("{}process", address))
                            .body(to_process)
                            .send()
                            .unwrap()
                            .text()
                            .unwrap(),
                    };

                    Ok(Some(response))
                }
                Scheme::Tcp => {
                    // let mut stream = TcpStream::connect(format!(
                    //     "{}:{}",
                    //     address
                    //         .host()
                    //         .ok_or(anyhow!("Wrong url, missing host {:?}", schema))?,
                    //     address
                    //         .port()
                    //         .ok_or(anyhow!("Wrong url, missing port {:?}", schema))?
                    // ))
                    // .await?;
                    // stream.write(&msg).await?;
                    // println!("Sending message to witness {}", wit_id.to_str());
                    // let mut buf = vec![];
                    // stream.read(&mut buf).await?;
                    // println!("Got response: {}", String::from_utf8(buf).unwrap());
                    // Ok(None)
                    todo!()
                }
            },
            _ => Err(KelError::GeneralError(format!(
                "No address for scheme {:?}",
                schema
            ))),
        }
    }

    /// Generate reply event used to add role to given identifier.
    pub fn generate_end_role(
        controller_id: &IdentifierPrefix,
        watcher_id: &IdentifierPrefix,
        role: Role,
        enabled: bool,
    ) -> Result<ReplyEvent, KelError> {
        let end_role = EndRole {
            cid: controller_id.clone(),
            role,
            eid: watcher_id.clone(),
        };
        let reply_route = if enabled {
            ReplyRoute::EndRoleAdd(end_role)
        } else {
            ReplyRoute::EndRoleCut(end_role)
        };
        ReplyEvent::new_reply(
            reply_route,
            SelfAddressing::Blake3_256,
            SerializationFormats::JSON,
        )
        .map_err(|e| KelError::GeneralError(e.to_string()))
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
            .fold(String::default(), |acc, res| {
                [acc, res.unwrap().unwrap()].join("")
            });

        // Kel should be empty because event is not fully witnessed
        // assert!(self.kel.get_kel(self.kel.prefix()).unwrap().is_none());

        // process collected receipts
        self.events_manager
            .parse_and_process(collected_receipts.as_bytes())
            .unwrap();

        // Now event is fully witnessed
        // assert!(self.kel.get_kel(self.kel.prefix()).unwrap().is_some());

        // Get processed receipts from database to send all of them to witnesses. It
        // will return one receipt with all witness signatures as one attachment,
        // not three separate receipts as in `collected_receipts`.
        let rcts_from_db = self
            .events_manager
            .get_receipts_of_event(EventSeal {
                prefix: message.event_message.event.get_prefix(),
                sn: message.event_message.event.get_sn(),
                event_digest: message.event_message.event.get_digest(),
            })?
            .map(|rct| SignedEventData::from(rct).to_cesr().unwrap())
            .unwrap_or_default();

        // send receipts to all witnesses
        witness_prefixes.iter().for_each(|prefix| {
            self.send_to(
                &IdentifierPrefix::Basic(prefix.clone()),
                Scheme::Http,
                Topic::Process(rcts_from_db.clone()),
            )
            .unwrap();
        });
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
            keri::event_parsing::EventType::KeyEvent(ke) => {
                let pref = ke.event.get_prefix().clone();
                if let EventData::Icp(_) = ke.event.get_event_data() {
                    self.finalize_key_event(ke, sig)?;
                }
                Ok(pref)
            }
            _ => Err(KelError::GeneralError("Wrong event type".into())),
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
        self.setup_witnesses(&witness_to_add)
            .map_err(|e| KelError::GeneralError(e.to_string()))?;
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
            .map_err(|e| KelError::GeneralError(e.to_string()))?
            .1;
        match parsed_event {
            EventType::KeyEvent(ke) => Ok(self.finalize_key_event(ke, sig).unwrap_or_default()),
            EventType::Receipt(_) => todo!(),
            EventType::Qry(_) => todo!(),
            EventType::Rpy(rpy) => match rpy.get_route() {
                ReplyRoute::EndRoleAdd(_) => Ok(self.finalize_add_role(id, rpy, sig).unwrap()),
                ReplyRoute::EndRoleCut(_) => todo!(),
                _ => Err(KelError::GeneralError("Wrong event type".into())),
            },
        }
    }

    fn finalize_key_event(
        &self,
        event: EventMessage<KeyEvent>,
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
            .process(&vec![Message::Event(signed_message.clone())])?;

        let wits = match event.event.get_event_data() {
            keri::event::event_data::EventData::Icp(icp) => icp.witness_config.initial_witnesses,
            keri::event::event_data::EventData::Rot(rot) => {
                let wits = self
                    .events_manager
                    .get_current_witness_list(&event.event.content.prefix)?;
                wits.into_iter()
                    .filter(|w| !rot.witness_config.prune.contains(w))
                    .chain(rot.witness_config.graft.into_iter())
                    .collect::<Vec<_>>()
            }
            keri::event::event_data::EventData::Ixn(_) => self
                .events_manager
                .get_current_witness_list(&event.event.content.prefix)?,
            keri::event::event_data::EventData::Dip(_) => todo!(),
            keri::event::event_data::EventData::Drt(_) => todo!(),
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
        let end_role = SignedEventData::from(signed_rpy)
            .to_cesr()
            .unwrap_or_default();
        kel.extend(end_role.iter());

        self.send_to(&dest_prefix, Scheme::Http, Topic::Process(kel))?;
        Ok(())
    }
}
