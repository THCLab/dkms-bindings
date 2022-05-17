use std::{path::Path, sync::Arc};

use anyhow::{anyhow, Result};
use async_std::{
    io::{ReadExt, WriteExt},
    net::TcpStream,
};
use futures::future::join_all;
use keri::{
    derivation::self_addressing::SelfAddressing,
    event::{event_data::EventData, EventMessage, SerializationFormats},
    event_message::{
        key_event_message::KeyEvent, signed_event_message::SignedEventMessage, Digestible,
    },
    event_parsing::{message::key_event_message, SignedEventData},
    oobi::{EndRole, LocationScheme, OobiManager, Role, Scheme},
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, Prefix, SelfSigningPrefix},
    processor::{
        event_storage::EventStorage,
        notification::JustNotification,
    },
    query::reply_event::{ReplyEvent, ReplyRoute, SignedReply},
};

use crate::kel::Kel;

pub struct Controller {
    pub kel: Kel,
    pub oobi_manager: Arc<OobiManager>,
}
impl Controller {
    pub fn new(event_db_path: &Path, oobi_db_path: &Path) -> Self {
        let mut keri = Kel::init(event_db_path.to_str().unwrap());
        let oobi_manager = Arc::new(OobiManager::new(oobi_db_path));
        keri.register_observer(oobi_manager.clone(), vec![JustNotification::GotOobi]);

        Self {
            kel: keri,
            oobi_manager: oobi_manager.clone(),
        }
    }

    pub async fn setup(&self) {
        let loc_scheme = LocationScheme::new(
            "BYSUc5ahFNbTaqesfY-6YJwzALaXSx-_Mvbs6y3I74js"
                .parse()
                .unwrap(),
            Scheme::Http,
            "http://127.0.0.1:3235".parse().unwrap(),
        );
        self.resolve(loc_scheme).await.unwrap();
        let loc_scheme = LocationScheme::new(
            "BZFIYlHDQAHxHH3TJsjMhZFbVR_knDzSc3na_VHBZSBs"
                .parse()
                .unwrap(),
            Scheme::Http,
            "http://127.0.0.1:3234".parse().unwrap(),
        );
        self.resolve(loc_scheme).await.unwrap();
        let loc_scheme = LocationScheme::new(
            "BMOaOdnrbEP-MSQE_CaL7BhGXvqvIdoHEMYcOnUAWjOE"
                .parse()
                .unwrap(),
            Scheme::Http,
            "http://127.0.0.1:3232".parse().unwrap(),
        );
        self.resolve(loc_scheme).await.unwrap();
    }

    pub async fn resolve(&self, lc: LocationScheme) -> Result<()> {
        let url = format!("{}oobi/{}", lc.url, lc.eid);
        let oobis = reqwest::get(url).await?.text().await?;
        println!("\ngot via http: {}", oobis);

        self.kel.parse_and_process(oobis.as_bytes()).unwrap();

        Ok(())
    }

    pub fn get_loc_schemas(&self, id: &IdentifierPrefix) -> Result<Vec<LocationScheme>> {
        Ok(self
            .oobi_manager
            .get_loc_scheme(id)
            .unwrap()
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

    pub async fn send_to(
        &self,
        wit_id: IdentifierPrefix,
        schema: Scheme,
        msg: Vec<u8>,
    ) -> Result<Option<String>> {
        let addresses = self.get_loc_schemas(&wit_id)?;
        match addresses
            .iter()
            .find(|loc| loc.scheme == schema)
            .map(|lc| &lc.url)
        {
            Some(address) => match schema {
                Scheme::Http => {
                    let client = reqwest::Client::new();
                    let response = client
                        .post(format!("{}process", address))
                        .body(msg)
                        .send()
                        .await?
                        .text()
                        .await?;

                    println!("\ngot response: {}", response);
                    Ok(Some(response))
                }
                Scheme::Tcp => {
                    let mut stream = TcpStream::connect(format!(
                        "{}:{}",
                        address
                            .host()
                            .ok_or(anyhow!("Wrong url, missing host {:?}", schema))?,
                        address
                            .port()
                            .ok_or(anyhow!("Wrong url, missing port {:?}", schema))?
                    ))
                    .await?;
                    stream.write(&msg).await?;
                    println!("Sending message to witness {}", wit_id.to_str());
                    let mut buf = vec![];
                    stream.read(&mut buf).await?;
                    println!("Got response: {}", String::from_utf8(buf).unwrap());
                    Ok(None)
                }
            },
            _ => Err(anyhow!("No address for scheme {:?}", schema)),
        }
    }

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

    // async fn add_watcher(&self, watcher_id: &IdentifierPrefix) -> Result<()> {
    //     let rep: SignedEventData = self
    //         .generate_end_role(watcher_id, Role::Watcher, true)?
    //         .into();
    //     self.send_to(watcher_id.clone(), Scheme::Tcp, rep.to_cesr().unwrap())
    //         .await?;
    //     Ok(())
    // }

    // async fn remove_watcher(&self, watcher_id: &IdentifierPrefix) -> Result<()> {
    //     let rep: SignedEventData = self
    //         .generate_end_role(watcher_id, Role::Watcher, false)?
    //         .into();
    //     self.send_to(watcher_id.clone(), Scheme::Tcp, rep.to_cesr().unwrap())
    //         .await?;
    //     Ok(())
    // }

    /// Publish key event to witnesses
    ///
    ///  1. send it to all witnesses
    ///  2. collect witness receipts and process them
    ///  3. get processed receipts from db and send it to all witnesses
    pub async fn publish(
        &self,
        witness_prefixes: &[BasicPrefix],
        message: &SignedEventMessage,
    ) -> Result<()> {
        let msg = SignedEventData::from(message).to_cesr().unwrap();
        let collected_receipts = join_all(witness_prefixes.iter().map(|prefix| {
            self.send_to(
                IdentifierPrefix::Basic(prefix.clone()),
                Scheme::Http,
                msg.clone(),
            )
        }))
        .await
        .into_iter()
        .fold(String::default(), |acc, res| {
            [acc, res.unwrap().unwrap()].join("")
        });

        println!(
            "\n\nreceipts in publish: {}\n\n",
            collected_receipts.clone()
        );

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
            )
            .unwrap()
            .map(|rct| SignedEventData::from(rct).to_cesr().unwrap())
            .unwrap();
        println!(
            "\nreceipts: {}",
            String::from_utf8(rcts_from_db.clone()).unwrap()
        );

        // send receipts to all witnesses
        join_all(witness_prefixes.iter().map(|prefix| {
            self.send_to(
                IdentifierPrefix::Basic(prefix.clone()),
                Scheme::Http,
                rcts_from_db.clone(),
            )
        }))
        .await;
        Ok(())
    }

    // TODO why it needs static
    pub async fn finalize_inception(
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
                    self.finalize_key_event(ke, sig).await?;
                }
                Ok(pref)
            }
            keri::event_parsing::EventType::Receipt(_) => todo!(),
            keri::event_parsing::EventType::Qry(_) => todo!(),
            keri::event_parsing::EventType::Rpy(_) => todo!(),
        }
    }

    pub async fn finalize_key_event(
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

        self.publish(&wits, &message).await
    }

    pub async fn finalize_add_role(
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
        self.send_to(
            dest_prefix,
            Scheme::Http,
            SignedEventData::from(signed_rpy)
                .to_cesr()
                .unwrap_or_default(),
        )
        .await?;
        Ok(())
    }
}
