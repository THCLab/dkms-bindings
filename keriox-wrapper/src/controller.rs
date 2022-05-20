use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{anyhow, Result};

use crate::kel::Kel;
use keri::{
    derivation::self_addressing::SelfAddressing,
    event::{event_data::EventData, EventMessage, SerializationFormats},
    event_message::{
        key_event_message::KeyEvent, signed_event_message::SignedEventMessage, Digestible,
    },
    event_parsing::{
        message::{event_message, key_event_message},
        EventType, SignedEventData,
    },
    oobi::{EndRole, LocationScheme, OobiManager, Role, Scheme},
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, Prefix, SelfSigningPrefix},
    processor::{event_storage::EventStorage, notification::JustNotification},
    query::reply_event::{ReplyEvent, ReplyRoute, SignedReply},
};

pub enum Topic {
    Oobi(Vec<u8>),
    Query(String),
    Process(Vec<u8>),
}

pub struct OptionalConfig {
    pub initial_oobis: Option<String>,
}

impl OptionalConfig {
    pub fn init() -> Self {
        Self {
            initial_oobis: None,
        }
    }

    pub fn set_initial_oobis(&self, oobis_json: &str) -> Result<Self> {
        Ok(Self {
            initial_oobis: Some(oobis_json.into()),
        })
    }
}

pub struct Controller {
    pub kel: Kel,
    pub oobi_manager: Arc<OobiManager>,
}
impl Controller {
    pub fn new(
        event_db_path: &Path,
        oobi_db_path: &Path,
        configs: Option<OptionalConfig>,
    ) -> Result<Self> {
        let mut keri = Kel::init(event_db_path.to_str().unwrap());
        let oobi_manager = Arc::new(OobiManager::new(oobi_db_path));
        keri.register_observer(oobi_manager.clone(), vec![JustNotification::GotOobi]);

        let controller = Self {
            kel: keri,
            oobi_manager: oobi_manager.clone(),
        };
        if let Some(config) = configs {
            if let Some(initial_oobis) = config.initial_oobis {
                controller.setup_witnesses(&initial_oobis)?;
            }
        };

        Ok(controller)
    }

    pub fn setup_witnesses(&self, oobis_json: &str) -> Result<()> {
        let oobis: Vec<LocationScheme> = serde_json::from_str(oobis_json)?;
        oobis
            .iter()
            .try_for_each(|lc| self.resolve_loc_schema(lc))?;
        Ok(())
    }

    /// Make http request to get identifier's endpoints information.
    pub fn resolve_loc_schema(&self, lc: &LocationScheme) -> Result<()> {
        let url = format!("{}oobi/{}", lc.url, lc.eid);
        let oobis = reqwest::blocking::get(url)?.text()?;

        self.kel.parse_and_process(oobis.as_bytes()).unwrap();

        Ok(())
    }

    fn get_watchers(&self, id: &IdentifierPrefix) -> Result<Vec<IdentifierPrefix>> {
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
    pub fn resolve_end_role(&self, id: &IdentifierPrefix, end_role_json: &str) -> Result<()> {
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
    pub fn query(&self, id: &IdentifierPrefix, query_id: &str) -> Result<()> {
        let watchers = self.get_watchers(id)?;
        // TODO choose random watcher id?
        let kel = self.send_to(&watchers[0], Scheme::Http, Topic::Query(query_id.into()))?;
        match kel {
            Some(kel) => {
                self.kel.parse_and_process(kel.as_bytes())?;
                Ok(())
            }
            None => Err(anyhow!("Can't find kel of identifier {}", id.to_str())),
        }
    }

    /// Returns identifier contact information.
    pub fn get_loc_schemas(&self, id: &IdentifierPrefix) -> Result<Vec<LocationScheme>> {
        Ok(self
            .oobi_manager
            .get_loc_scheme(id)?
            .unwrap()
            .iter()
            .filter_map(|lc| {
                if let ReplyRoute::LocScheme(loc_scheme) = lc.get_route() {
                    Ok(loc_scheme)
                } else {
                    Err(anyhow!("Wrong route type"))
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
    ) -> Result<Option<String>> {
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
            _ => Err(anyhow!("No address for scheme {:?}", schema)),
        }
    }

    /// Generate reply event used to add role to given identifier.
    pub fn generate_end_role(
        &self,
        controller_id: &IdentifierPrefix,
        watcher_id: &IdentifierPrefix,
        role: Role,
        enabled: bool,
    ) -> Result<ReplyEvent> {
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
        .map_err(|e| anyhow!(e.to_string()))
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
    ) -> Result<()> {
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
        self.kel
            .parse_and_process(collected_receipts.as_bytes())
            .unwrap();

        // Now event is fully witnessed
        // assert!(self.kel.get_kel(self.kel.prefix()).unwrap().is_some());

        // Get processed receipts from database to send all of them to witnesses. It
        // will return one receipt with all witness signatures as one attachment,
        // not three separate receipts as in `collected_receipts`.
        let storage = EventStorage::new(self.kel.db.clone());
        let rcts_from_db = storage
            .get_nt_receipts(
                &message.event_message.event.get_prefix(),
                message.event_message.event.get_sn(),
                &message.event_message.event.get_digest(),
            )?
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

    pub fn finalize_inception(
        &self,
        event: &[u8],
        sig: Vec<SelfSigningPrefix>,
    ) -> Result<IdentifierPrefix> {
        let parsed_event = key_event_message(&event)
            .unwrap()
            // .map_err(|e| KelError::ParseEventError(e.to_string()))?
            .1;
        match parsed_event {
            keri::event_parsing::EventType::KeyEvent(ke) => {
                let pref = ke.event.get_prefix().clone();
                if let EventData::Icp(_) = ke.event.get_event_data() {
                    self.finalize_key_event(ke, sig)?;
                }
                Ok(pref)
            }
            _ => Err(anyhow!("Wrong event type")),
        }
    }

    /// Check signatures, updates database and send events to watcher or witnesses.
    pub fn finalize_event(
        &self,
        id: &IdentifierPrefix,
        event: &[u8],
        sig: Vec<SelfSigningPrefix>,
    ) -> Result<()> {
        let parsed_event = event_message(event).map_err(|e| anyhow!(e.to_string()))?.1;
        match parsed_event {
            EventType::KeyEvent(ke) => Ok(self.finalize_key_event(ke, sig).unwrap_or_default()),
            EventType::Receipt(_) => todo!(),
            EventType::Qry(_) => todo!(),
            EventType::Rpy(rpy) => match rpy.get_route() {
                ReplyRoute::EndRoleAdd(_) => Ok(self.finalize_add_role(id, rpy, sig).unwrap()),
                ReplyRoute::EndRoleCut(_) => todo!(),
                _ => Err(anyhow!("Wrong event type")),
            },
        }
    }

    fn finalize_key_event(
        &self,
        event: EventMessage<KeyEvent>,
        sig: Vec<SelfSigningPrefix>,
    ) -> Result<()> {
        let message = self.kel.finalize_event(&event, sig)?;

        let wits = match event.event.get_event_data() {
            keri::event::event_data::EventData::Icp(icp) => icp.witness_config.initial_witnesses,
            keri::event::event_data::EventData::Rot(rot) => {
                let wits = self
                    .kel
                    .get_current_witness_list(&event.event.content.prefix)?
                    .unwrap_or_default();
                wits.into_iter()
                    .filter(|w| !rot.witness_config.prune.contains(w))
                    .chain(rot.witness_config.graft.into_iter())
                    .collect::<Vec<_>>()
            }
            keri::event::event_data::EventData::Ixn(_) => self
                .kel
                .get_current_witness_list(&event.event.content.prefix)?
                .unwrap_or_default(),
            keri::event::event_data::EventData::Dip(_) => todo!(),
            keri::event::event_data::EventData::Drt(_) => todo!(),
        };

        self.publish(&wits, &message)
    }

    fn finalize_add_role(
        &self,
        signer_prefix: &IdentifierPrefix,
        event: ReplyEvent,
        sig: Vec<SelfSigningPrefix>,
    ) -> Result<()> {
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
        let storage = EventStorage::new(self.kel.db.clone());
        let signed_rpy = SignedReply::new_trans(
            event,
            storage
                .get_last_establishment_event_seal(signer_prefix)
                .unwrap()
                .unwrap(),
            sigs,
        );
        self.oobi_manager.save_oobi(signed_rpy.clone()).unwrap();
        let mut kel = self
            .kel
            .get_kel(&signer_prefix.to_str())?
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
