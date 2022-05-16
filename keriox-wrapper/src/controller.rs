use std::{path::Path, sync::Arc};

use anyhow::{anyhow, Result};
use async_std::{
    io::{ReadExt, WriteExt},
    net::TcpStream,
};
use futures::future::join_all;
use keri::{
    derivation::self_addressing::SelfAddressing,
    event::SerializationFormats,
    event_message::{signed_event_message::SignedEventMessage, Digestible},
    event_parsing::SignedEventData,
    keri::Responder,
    oobi::{EndRole, LocationScheme, OobiManager, Role, Scheme},
    prefix::{BasicPrefix, IdentifierPrefix, Prefix},
    processor::{
        event_storage::EventStorage,
        notification::{JustNotification, Notification},
    },
    query::reply_event::{ReplyEvent, ReplyRoute},
};

use crate::kel::Kel;

pub struct Controller {
    pub kel: Kel,
    pub oobi_manager: Arc<OobiManager>,
    response_queue: Arc<Responder<Notification>>,
}
impl Controller {
    pub fn new(event_db_path: &Path, oobi_db_path: &Path) -> Self {
        let mut keri = Kel::init(event_db_path.to_str().unwrap());
        let oobi_manager = Arc::new(OobiManager::new(oobi_db_path));
        keri.register_observer(oobi_manager.clone(), vec![JustNotification::GotOobi]);

        let responder = Arc::new(Responder::new());
        keri.register_observer(responder.clone(), vec![JustNotification::KeyEventAdded]);

        Self {
            kel: keri,
            oobi_manager: oobi_manager.clone(),
            response_queue: responder,
        }
    }
    pub async fn resolve(&self, lc: LocationScheme) -> Result<()> {
        let url = format!("{}oobi/{}", lc.url, lc.eid);
        let oobis = reqwest::get(url).await.unwrap().text().await.unwrap();
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
                0,
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
}
