use ed25519_dalek::SigningKey;
use gloo_net::http::Request;
use js_sys::Uint8Array;
use keri_core::{
    actor::{parse_event_stream, prelude::Message},
    event_message::signed_event_message::Op,
    oobi::{LocationScheme, Oobi},
    prefix::{
        BasicPrefix, IdentifierPrefix, IndexedSignature, SeedPrefix,
        SelfSigningPrefix,
    },
    query::query_event::{SignedKelQuery, SignedQueryMessage},
    signer::Signer,
};
use keri_sdk::{Controller, Identifier};
use said::SelfAddressingIdentifier;
use teliox::state::vc_state::TelState;
use std::sync::Arc;
use url::Url;
use wasm_bindgen::prelude::*;

pub mod database;
use crate::database::indexed_db::IndexedDbDatabase as Database;

#[wasm_bindgen]
pub enum VcState {
    Issued,
    Revoked,
    NotIssued,
}

#[wasm_bindgen]
pub struct JsIdentifier {
    inner: Identifier<Database>,
    db: Arc<Database>,
    alias: String,
    signer: Arc<Signer>,
    watcher_oobi: Option<LocationScheme>,
}

impl JsIdentifier {
    pub fn new(alias: String, inner: Identifier<Database>, signer: Arc<Signer>, db: Arc<Database>, watcher_oobi: Option<LocationScheme>) -> Self {
        Self {
            inner,
            db,
            alias,
            signer,
            watcher_oobi,
        }
    }
}

#[wasm_bindgen]
impl JsIdentifier {
    pub fn get_prefix(&self) -> String {
        self.inner.get_prefix().to_string()
    }

    pub fn get_kel(&self) -> String {
        format!("{:?}", self.inner.get_own_kel().unwrap())
    }

    pub fn set_alias(&mut self, alias: String) -> Result<(), JsValue> {
        self.db.update_identifier_alias(&self.alias, &alias).map_err(|e| JsValue::from_str(&format!("Failed to update alias in DB: {}", e)))?;
        self.alias = alias;
        Ok(())
    }

    pub async fn add_watcher(&mut self, url: String) -> Result<(), JsValue> {
        let url = Url::parse(&url)
            .map_err(|e| JsValue::from_str(&format!("Invalid URL: {}", e)))?;
        let res = Request::get(url.join("introduce").unwrap().as_str())
            .send()
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let res_str = res.text().await.map_err(|e| {
            JsValue::from_str(&format!("Failed to get response: {}", e))
        })?;
        let oobi: LocationScheme =
            serde_json::from_str(&res_str).map_err(|e| {
                JsValue::from_str(&format!("Failed to parse OOBI: {}", e))
            })?;
        self.watcher_oobi = Some(oobi.clone());
        let watcher_prefix = oobi.clone().eid;

        let add_watcher_event = self
            .inner
            .add_watcher(watcher_prefix.clone())
            .map_err(|e| {
                JsValue::from_str(&format!("Failed to add watcher: {}", e))
            })?;

        let sig = SelfSigningPrefix::new(
            cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
            self.signer.sign(add_watcher_event.as_bytes()).unwrap(),
        );
        let (_, messages) = self
            .inner
            .finalize_add_watcher(add_watcher_event.as_bytes(), sig)
            .unwrap();

        for message in messages {
            let request_url: Option<String> = match message {
                Message::Notice(_) => {
                    Some(url.join("process").unwrap().to_string())
                }
                Message::Op(Op::Reply(_)) => {
                    Some(url.join("register").unwrap().to_string())
                }
                _ => {
                    log::warn!("Unsupported message type: {:?}", message);
                    None
                }
            };
            if let Some(request_url) = request_url {
                let body =
                    Uint8Array::from(message.to_cesr().unwrap().as_slice());
                let _ = Request::post(&request_url)
                    .header("Content-Type", "application/json")
                    .body(&body)
                    .unwrap()
                    .send()
                    .await
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
            }
        }

        self.db.update_identifier_watcher(
            &self.alias,
            oobi.clone(),
        ).map_err(|e| JsValue::from_str(&format!("Failed to update identifier in DB: {}", e)))?;

        Ok(())
    }

    pub fn get_watcher(&self) -> Option<String> {
        self.watcher_oobi.as_ref().map(|scheme| scheme.url.to_string())
    }
}

#[wasm_bindgen]
pub struct JsController {
    inner: Controller<Database, Database>,
    db: Arc<Database>,
}

struct KeysConfig {
    pub current: SeedPrefix,
    pub next: SeedPrefix,
}

impl Default for KeysConfig {
    fn default() -> Self {
        let current = SigningKey::generate(&mut rand::rngs::OsRng);
        let next = SigningKey::generate(&mut rand::rngs::OsRng);
        Self {
            current: SeedPrefix::RandomSeed256Ed25519(
                current.as_bytes().to_vec(),
            ),
            next: SeedPrefix::RandomSeed256Ed25519(next.as_bytes().to_vec()),
        }
    }
}

#[wasm_bindgen]
impl JsController {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<JsController, JsValue> {
        log::set_logger(&wasm_bindgen_console_logger::DEFAULT_LOGGER).unwrap();
        log::set_max_level(log::LevelFilter::Info);

        let event_database = Arc::new(Database::new());
        let tel_database = Arc::new(Database::new());
        let inner = Controller::new(event_database, tel_database);

        let identifiers_db = Arc::new(Database::new());

        Ok(Self {
            inner,
            db: identifiers_db,
        })
    }

    pub fn load_identifier(
        &self,
        alias: String,
    ) -> Result<JsIdentifier, JsValue> {
        let id_record = self
            .db
            .get_identifier(&alias)
            .ok_or_else(|| JsValue::from_str("Identifier not found"))?;

        let identifier = self
            .inner
            .load_identifier(&id_record.said)
            .map_err(|e| JsValue::from_str(&format!("Load identifier error: {}", e)))?;
        let signer = Signer::new_with_seed(&id_record.seed)
            .map_err(|e| JsValue::from_str(&format!("Signer creation error: {}", e)))?;

        Ok(JsIdentifier::new(alias, identifier, Arc::new(signer), self.db.clone(), id_record.watcher_oobi))
    }

    pub fn get_identifier_aliases(&self) -> Result<Vec<JsValue>, JsValue> {
        let aliases: Vec<JsValue> = self
            .db
            .get_identifiers()
            .iter()
            .map(|(alias, _)| JsValue::from_str(alias))
            .collect();
        Ok(aliases)
    }

    pub fn incept(&self) -> Result<JsIdentifier, JsValue> {
        let keys = KeysConfig::default();
        let (next_pub_key, _next_secret_keys) =
            match keys.next.derive_key_pair() {
                Ok(pair) => pair,
                Err(e) => {
                    return Err(JsValue::from_str(&format!(
                        "Failed to derive keys: {}",
                        e
                    )))
                }
            };

        let signer = match Signer::new_with_seed(&keys.current.clone()) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                return Err(JsValue::from_str(&format!(
                    "Failed to create signer: {}",
                    e
                )))
            }
        };

        let next_pub_keys = vec![BasicPrefix::Ed25519NT(next_pub_key)];
        let public_keys = vec![BasicPrefix::Ed25519(signer.public_key())];

        let signing_inception =
            self.inner
                .incept(public_keys, next_pub_keys)
                .map_err(|_| JsValue::from_str("Incept error"))?;
        let signature = SelfSigningPrefix::new(
            cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
            signer.sign(signing_inception.as_bytes()).unwrap(),
        );
        let signing_identifier = self
            .inner
            .finalize_incept(signing_inception.as_bytes(), &signature)
            .map_err(|_| JsValue::from_str("Finalize error"))?;

        let kel = format!("{:?}", signing_identifier.get_own_kel().unwrap());
        self.process_kel(kel)?;

        let prefix = signing_identifier.get_prefix();
        let alias = prefix.to_string();
        self.db.add_identifier(&alias, &prefix.clone(), &keys.current).map_err(|e| {
            JsValue::from_str(&format!("Failed to add identifier to DB: {}", e))
        })?;

        Ok(JsIdentifier::new(alias, signing_identifier, signer.clone(), self.db.clone(), None))
    }

    pub fn process_kel(
        &self,
        kel: String,
    ) -> Result<(), JsValue> {
        let parsed_kel: Vec<Message> = parse_event_stream(kel.as_bytes())
            .map_err(|e| {
                JsValue::from_str(&format!("Failed to parse KEL: {}", e))
            })?;
        let parsed_kel = parsed_kel
            .into_iter()
            .collect::<Vec<_>>();

        self.inner.process_kel(&parsed_kel).map_err(|e| {
            JsValue::from_str(&format!("Process events error: {}", e))
        })?;

        Ok(())
    }

    pub fn process_tel(&self, tel: String) -> Result<(), JsValue> {
        self.inner.process_tel(tel.as_bytes()).map_err(|e| {
            JsValue::from_str(&format!("Process events error: {}", e))
        })?;

        Ok(())
    }

    pub fn get_vc_state(&self, prefix: String) -> Result<VcState, JsValue> {
        let said: SelfAddressingIdentifier = prefix.parse().map_err(|e| {
            JsValue::from_str(&format!("Invalid prefix: {}", e))
        })?;

        self.inner.get_vc_state(&said)
            .map_err(|e| JsValue::from_str(&format!("Get VC state error: {}", e)))
            .map(|state| {
                match state {
                    Some(TelState::Issued(_)) => VcState::Issued,
                    Some(TelState::Revoked) => VcState::Revoked,
                    None | Some(TelState::NotIssued) => VcState::NotIssued,
                }
            })
    }

    pub async fn verify(
        &self,
        identifier: &JsIdentifier,
        oobi_array: JsValue,
        message: String,
    ) -> Result<JsValue, JsValue> {
        let oobis: Vec<Oobi> =
            serde_wasm_bindgen::from_value(oobi_array).unwrap_or(vec![]);
        let watcher_url = identifier
            .watcher_oobi
            .clone()
            .ok_or_else(|| JsValue::from_str("Watcher for identifier not set"))?
            .url;
        self.resolve_oobis(&watcher_url.to_string(), oobis.clone())
            .await
            .map_err(|e| {
                JsValue::from_str(&format!("Failed to resolve OOBIs: {:?}", e))
            })?;

        let (_rest, cesr) = cesrox::parse(message.as_bytes()).map_err(|e| {
            JsValue::from_str(&format!("Failed to parse CESR: {}", e))
        })?;
        let att: acdc::Attestation = match cesr.payload {
            cesrox::payload::Payload::JSON(items) => {
                serde_json::from_slice(&items).map_err(|_e| ()).map_err(
                    |_| JsValue::from_str("Failed to parse JSON payload"),
                )?
            }
            cesrox::payload::Payload::CBOR(items) => {
                serde_cbor::from_slice(&items).map_err(|_e| ()).map_err(
                    |_| JsValue::from_str("Failed to parse CBOR payload"),
                )?
            }
            cesrox::payload::Payload::MGPK(_items) => todo!(),
        };

        let issuer_id: IdentifierPrefix = att.issuer.parse().map_err(|e| {
            JsValue::from_str(&format!("Failed to parse issuer ID: {}", e))
        })?;

        let kel =
            self.query_kel(identifier, issuer_id).await.map_err(|e| {
                JsValue::from_str(&format!("Failed to query KEL: {:?}", e))
            })?;
        self.process_kel(kel).map_err(|e| {
            JsValue::from_str(&format!("Failed to process KEL: {:?}", e))
        })?;

        let tel =
            self.query_tel(identifier, att.clone())
                .await
                .map_err(|e| {
                    JsValue::from_str(&format!("Failed to query TEL: {:?}", e))
                })?;
        self.process_tel(tel).map_err(|e| {
            JsValue::from_str(&format!("Failed to process TEL: {:?}", e))
        })?;

        let vc_said = att.digest.unwrap();
        let vc_state = self.get_vc_state(vc_said.to_string())?;
        let result = match vc_state {
            VcState::Issued => VerificationResult {
                verified: true,
                status: "issued".to_string(),
            },
            VcState::Revoked => VerificationResult {
                verified: false,
                status: "revoked".to_string(),
            },
            VcState::NotIssued => VerificationResult {
                verified: false,
                status: "not issued".to_string(),
            },
        };

        Ok(result.into())
    }
}

impl JsController {
    async fn resolve_oobis(
        &self,
        watcher_url: &String,
        oobis: Vec<Oobi>,
    ) -> Result<(), JsValue> {
        for oobi in oobis {
            let _ = Request::post(&format!("{}resolve", watcher_url))
                .header("Content-Type", "application/json")
                .body(serde_json::to_string(&oobi).unwrap())
                .unwrap()
                .send()
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()));
        }
        Ok(())
    }

    async fn query_kel(
        &self,
        signing_id: &JsIdentifier,
        id: IdentifierPrefix,
    ) -> Result<String, JsValue> {
        let watcher_url = signing_id.watcher_oobi.clone().unwrap().url;
        let watcher_id = signing_id.watcher_oobi.clone().unwrap().eid;
        let qry = signing_id.inner.get_log_query(id, watcher_id);
        let signer = signing_id.signer.clone();

        let sig = SelfSigningPrefix::new(
            cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
            signer.sign(qry.encode().unwrap()).unwrap(),
        );
        let signatures = vec![IndexedSignature::new_both_same(sig, 0)];
        let singed_kel_qry = SignedKelQuery::new_trans(
            qry.clone(),
            signing_id.inner.get_prefix().clone(),
            signatures,
        );

        let mut delay = std::time::Duration::from_secs(1);
        let mut kel = "".to_string();
        for _i in 0..5 {
            let signed_qry =
                SignedQueryMessage::KelQuery(singed_kel_qry.clone());

            let body_msg =
                Message::Op(Op::Query(signed_qry)).to_cesr().unwrap();
            let body = js_sys::Uint8Array::from(body_msg.as_slice());
            let response =
                Request::post(watcher_url.join("query").unwrap().as_str())
                    .header("Content-Type", "application/json")
                    .body(&body)
                    .unwrap()
                    .send()
                    .await
                    .map_err(|e| {
                        JsValue::from_str(&format!(
                            "Failed to send request: {}",
                            e
                        ))
                    })?;

            let code = response.status();
            if code == 200 {
                kel = response.text().await.map_err(|e| {
                    JsValue::from_str(&format!(
                        "Failed to get response text: {}",
                        e
                    ))
                })?;
                break;
            } else {
                gloo_timers::future::TimeoutFuture::new(
                    delay.as_millis() as u32
                )
                .await;
                delay *= 2;
            }
        }

        Ok(kel)
    }

    async fn query_tel(
        &self,
        id: &JsIdentifier,
        acdc_attestation: acdc::Attestation,
    ) -> Result<String, JsValue> {
        let watcher_url = id.watcher_oobi.clone().unwrap().url;
        let vc_said = acdc_attestation.digest.unwrap();
        let registry_id: said::SelfAddressingIdentifier =
            acdc_attestation.registry_identifier.parse().unwrap();
        let signer = id.signer.clone();

        let tel_qry = id
            .inner
            .get_tel_query(
                IdentifierPrefix::SelfAddressing(registry_id.into()),
                IdentifierPrefix::SelfAddressing(vc_said.clone().into()),
            )
            .unwrap();

        let signature_tel_query = SelfSigningPrefix::new(
            cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
            signer.sign(tel_qry.encode().unwrap()).unwrap(),
        );

        let tel_query = match &id.inner.id {
            IdentifierPrefix::Basic(bp) => {
                teliox::query::SignedTelQuery::new_nontrans(
                    tel_qry.clone(),
                    bp.clone(),
                    signature_tel_query,
                )
            }
            _ => {
                let signatures =
                    vec![keri_core::prefix::IndexedSignature::new_both_same(
                        signature_tel_query,
                        0,
                    )];
                teliox::query::SignedTelQuery::new_trans(
                    tel_qry.clone(),
                    id.inner.id.clone(),
                    signatures,
                )
            }
        };

        let mut delay = std::time::Duration::from_secs(1);
        let mut tel = "".to_string();
        for _i in 0..5 {
            let body = js_sys::Uint8Array::from(
                tel_query.to_cesr().unwrap().as_slice(),
            );
            let response =
                Request::post(watcher_url.join("query/tel").unwrap().as_str())
                    .header("Content-Type", "application/json")
                    .body(&body)
                    .unwrap()
                    .send()
                    .await
                    .map_err(|e| {
                        JsValue::from_str(&format!(
                            "Failed to send request: {}",
                            e
                        ))
                    })?;

            let code = response.status();
            if code == 200 {
                tel = response.text().await.map_err(|e| {
                    JsValue::from_str(&format!(
                        "Failed to get response text: {}",
                        e
                    ))
                })?;
                break;
            } else {
                gloo_timers::future::TimeoutFuture::new(
                    delay.as_millis() as u32
                )
                .await;
                delay *= 2;
            }
        }

        Ok(tel)
    }
}

pub struct VerificationResult {
    verified: bool,
    status: String,
}

impl From<VerificationResult> for JsValue {
    fn from(val: VerificationResult) -> Self {
        let obj = js_sys::Object::new();

        js_sys::Reflect::set(&obj, &JsValue::from_str("verified"), &JsValue::from_bool(val.verified))
            .expect("setting verified failed");

        js_sys::Reflect::set(&obj, &JsValue::from_str("status"), &JsValue::from_str(&val.status))
            .expect("setting status failed");

        obj.into()
    }
}
