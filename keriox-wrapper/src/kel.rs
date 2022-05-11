use keri::{
    database::sled::SledEventDatabase,
    derivation::{basic::Basic, self_signing::SelfSigning},
    event::{
        event_data::EventData,
        sections::{threshold::SignatureThreshold}, receipt::Receipt, SerializationFormats,
    },
    event_message::{
        event_msg_builder::EventMsgBuilder, signed_event_message::{Message, SignedNontransferableReceipt}, EventTypeTag,
    },
    event_parsing::{
        attachment::attachment,
        message::{key_event_message, signed_event_stream},
    },
    keys::PublicKey as KeriPK,
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, Prefix, SelfSigningPrefix, SelfAddressingPrefix},
    processor::{event_storage::EventStorage, notification::NotificationBus, EventProcessor, escrow::default_escrow_bus},
};
use std::{path::Path, sync::Arc};
use thiserror::Error;

pub type KeyDerivation = Basic;
pub type SignatureDerivation = SelfSigning;
pub type KeyPrefix = BasicPrefix;
pub type Threshold= SignatureThreshold;
pub type PublicKey = keri::keys::PublicKey;
pub type SAI = SelfAddressingPrefix;
pub type Identifier = IdentifierPrefix;
pub type SignaturePrefix = SelfSigningPrefix;

pub fn key_prefix_from_b64(key: &str, derivation: Basic) -> Result<BasicPrefix, KelError> {
    let key = KeriPK::new(base64::decode(key).unwrap());
    Ok(derivation.derive(key))
}

pub fn signature_prefix_from_b64(
    sig: &str,
    derivation: SelfSigning,
) -> Result<SelfSigningPrefix, KelError> {
    let sig = base64::decode(sig).unwrap();
    Ok(derivation.derive(sig))
}

pub fn signature_prefix_from_hex(
    sig_hex: &str,
    derivation: SelfSigning,
) -> Result<SelfSigningPrefix, KelError> {
    let sig = hex::decode(sig_hex)?;
    Ok(derivation.derive(sig))
}

// helper functions for parsing attached signatures
fn join_keys_and_signatures(
    current_keys: Vec<BasicPrefix>,
    signatures: &[AttachedSignaturePrefix],
) -> Result<Vec<(BasicPrefix, SelfSigningPrefix)>, KelError> {
    let ss: Result<Vec<(_, _)>, KelError> = signatures
        .iter()
        .map(|s| -> Result<_, _> {
            Ok((
                current_keys
                    .get(s.index as usize)
                    .ok_or_else(|| KelError::GeneralError("Missing signature index".into()))?
                    .to_owned(),
                s.signature.clone(),
            ))
        })
        .collect();
    ss
}

pub fn parse_attachment(
    storage: EventStorage,
    stream: &str,
) -> Result<Vec<(BasicPrefix, SelfSigningPrefix)>, KelError> {
    let (_rest, att1) =
        attachment(stream.as_bytes()).map_err(|e| KelError::ParseEventError(e.to_string()))?;
    if let keri::event_parsing::Attachment::SealSignaturesGroups(group) = att1 {
        let r = group
            .iter()
            .map(|(seal, signatures)| -> Result<Vec<_>, KelError> {
                // let event = storage
                //     .get_event_at_sn(&seal.prefix, seal.sn)?
                //     .ok_or_else(|| KelError::MissingEventError)?;
                // //check digests
                // if event.signed_event_message.event_message.event.get_digest()
                //     != seal.event_digest
                // {
                //     return Err(KelError::GeneralError("Event digests doesn't match".into()));
                // };
                let current_keys = storage
                    .compute_state_at_sn(&seal.prefix, seal.sn)?
                    .ok_or_else(|| KelError::GeneralError("No state".into()))?
                    .current
                    .public_keys;
                join_keys_and_signatures(current_keys, signatures)
            })
            .collect::<Result<Vec<_>, KelError>>();
        Ok(r.into_iter()
            .flatten()
            .flatten()
            .collect::<Vec<(BasicPrefix, SelfSigningPrefix)>>())

        // r
    } else {
        Err(KelError::GeneralError("Wrong attachment".into()))
    }
}

pub struct Kel {
    db: Arc<SledEventDatabase>,
    notification_bus: NotificationBus,
}
impl Kel {

    pub fn load_kel(path: &str, id: IdentifierPrefix) -> Result<Self, keri::error::Error> {
        todo!()
    }

    pub fn init(path: &str) -> Self {
        let db = Arc::new(SledEventDatabase::new(Path::new(&path)).unwrap());
        Kel {
            db: db.clone(),
            notification_bus: default_escrow_bus(db.clone()),
        }
    }

    // todo add setting signing threshold
    pub fn incept(
        &self,
        public_keys: Vec<BasicPrefix>,
        next_pub_keys: Vec<BasicPrefix>,
        witnesses: Vec<String>,
        witness_threshold: u64,
    ) -> Result<String, KelError> {
        let witnesses = witnesses
            .iter()
            .map(|wit| wit.parse::<BasicPrefix>().map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_e| KelError::InceptionError)?;
        let pks = public_keys;
        let npks = next_pub_keys;
        let serialized_icp = EventMsgBuilder::new(EventTypeTag::Icp)
            .with_keys(pks)
            .with_next_keys(npks)
            .with_witness_list(witnesses.as_slice())
            .with_witness_threshold(&SignatureThreshold::Simple(witness_threshold))
            .build()
            .map_err(|_e| KelError::InceptionError)?
            .serialize()
            .map_err(|_e| KelError::InceptionError)?;

        let icp = String::from_utf8(serialized_icp).map_err(|_e| KelError::InceptionError)?;
        Ok(icp)
    }

    pub fn rotate(
        &self,
        identifier: String,
        current_keys: Vec<BasicPrefix>,
        new_next_keys: Vec<BasicPrefix>,
        witness_to_add: Vec<String>,
        witness_to_remove: Vec<String>,
        witness_threshold: u64,
    ) -> Result<String, KelError> {
        let identifier = identifier
            .parse::<IdentifierPrefix>()
            .map_err(|_e| KelError::RotationError)?;
        let witnesses_to_add = witness_to_add
            .iter()
            .map(|wit| wit.parse::<BasicPrefix>().map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_e| KelError::RotationError)?;
        let witnesses_to_remove = witness_to_remove
            .iter()
            .map(|wit| wit.parse::<BasicPrefix>().unwrap())
            .collect::<Vec<_>>();
        let pks = current_keys;
        let npks = new_next_keys;
        let storage = EventStorage::new(self.db.clone());
        let state = storage
            .get_state(&identifier)
            .map_err(|_e| KelError::RotationError)?
            .ok_or_else(|| format!("no state for prefix {}", identifier.to_str()))
            .map_err(|_e| KelError::RotationError)?;
        let rot = EventMsgBuilder::new(EventTypeTag::Rot)
            .with_prefix(&identifier)
            .with_sn(state.sn + 1)
            .with_previous_event(&state.last_event_digest)
            .with_keys(pks)
            .with_next_keys(npks)
            .with_witness_to_add(&witnesses_to_add)
            .with_witness_to_remove(&witnesses_to_remove)
            .with_witness_threshold(&SignatureThreshold::Simple(witness_threshold))
            .build()
            .map_err(|_e| KelError::RotationError)?
            .serialize()
            .map_err(|_e| KelError::RotationError)?;
        String::from_utf8(rot).map_err(|_e| KelError::RotationError)
    }

    pub fn finalize_inception(
        &self,
        event: String,
        signature: SelfSigningPrefix,
    ) -> Result<String, KelError> {
        let parsed_event = key_event_message(event.as_bytes())
            .map_err(|e| KelError::ParseEventError(e.to_string()))?
            .1;
        match parsed_event {
            keri::event_parsing::EventType::KeyEvent(ke) => {
                if let EventData::Icp(_) = ke.event.get_event_data() {
                    let processor = EventProcessor::new(self.db.clone());
                    // TODO set index
                    let sigs = vec![AttachedSignaturePrefix {
                        index: 0,
                        signature,
                    }];
                    let signed_message = ke.sign(sigs, None, None);
                    let not = processor
                        .process(Message::Event(signed_message))
                        .map_err(|e| KelError::ParseEventError(e.to_string()))?;
                    self.notification_bus
                        .notify(&not)
                        .map_err(|_e| KelError::NotificationError)?;
                    // TODO check if id match
                }
                Ok(ke.event.get_prefix().to_string())
            }
            keri::event_parsing::EventType::Receipt(_) => todo!(),
        }
    }

    pub fn finalize_event(
        &self,
        event: String,
        signature: SelfSigningPrefix,
    ) -> Result<(), KelError> {
        let parsed_event = key_event_message(event.as_bytes())
            .map_err(|e| KelError::ParseEventError(e.to_string()))?
            .1;
        match parsed_event {
            keri::event_parsing::EventType::KeyEvent(ke) => {
                let processor = EventProcessor::new(self.db.clone());
                // TODO set index
                let sigs = vec![AttachedSignaturePrefix {
                    index: 0,
                    signature,
                }];
                let signed_message = ke.sign(sigs, None, None);
                let not = processor.process(Message::Event(signed_message));
                let not = not.map_err(|e| KelError::ParseEventError(e.to_string()))?;
                self.notification_bus
                    .notify(&not)
                    .map_err(|_e| KelError::NotificationError)
            }
            keri::event_parsing::EventType::Receipt(_) => todo!(),
        }
    }

    pub fn get_kel(&self, id: String) -> Result<String, KelError> {
        let storage = EventStorage::new(self.db.clone());
        String::from_utf8(
            storage
                .get_kel(
                    &id.parse::<IdentifierPrefix>()
                        .map_err(|e| KelError::ParseEventError(e.to_string()))?,
                )?
                .ok_or(KelError::UnknownIdentifierError)?,
        )
        .map_err(|e| KelError::ParseEventError(e.to_string()))
    }


    pub fn parse_and_process(&self, msg: &[u8]) -> Result<(), KelError> {
        let events = signed_event_stream(msg)
            .map_err(|e| KelError::ParseEventError(e.to_string()))?
            .1
            .into_iter()
            .map(|data| Message::try_from(data).unwrap());
        events.clone().for_each(|msg| {
            self.process(&vec![msg.clone()]).unwrap();
            // check if receipts are attached
            if let Message::Event(ev) = msg {
                if let Some(witness_receipts) = ev.witness_receipts {
                    let id = ev.event_message.event.get_prefix();
                    let receipt = Receipt {
                        receipted_event_digest: ev.event_message.get_digest(),
                        prefix: id,
                        sn: ev.event_message.event.get_sn(),
                    };
                    let signed_receipt = SignedNontransferableReceipt::new(
                        &receipt.to_message(SerializationFormats::JSON).unwrap(),
                        None,
                        Some(witness_receipts),
                    );
                    self.process(&vec![Message::NontransferableRct(signed_receipt)])
                        .unwrap();
                }
            }
        });
        Ok(())
    }

    pub fn process(&self, msg: &[Message]) -> Result<(), KelError> {
        let processor = EventProcessor::new(self.db.clone());
        let (process_ok, process_failed): (Vec<_>, Vec<_>) = msg
            .iter()
            .map(|message| {
                processor
                    .process(message.clone())
                    .and_then(|not| {
                        self.notification_bus.notify(&not)
                    })
            })
            .partition(Result::is_ok);
        let _oks = process_ok
            .into_iter()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        let _errs = process_failed
            .into_iter()
            .map(Result::unwrap_err)
            .collect::<Vec<_>>();

        Ok(())
    }


    pub fn parse_attachment(
        &self,
        att_str: String,
    ) -> Result<Vec<(BasicPrefix, SelfSigningPrefix)>, KelError> {
        let storage = EventStorage::new(self.db.clone());
        parse_attachment(storage, &att_str)
    }
}

#[derive(Error, Debug)]
pub enum KelError {
    #[error("can't generate inception event")]
    InceptionError,
    #[error("can't generate rotation event")]
    RotationError,
    #[error("can't parse event: {0}")]
    ParseEventError(String),
    #[error("can't notify")]
    NotificationError,
    #[error("missing event")]
    MissingEventError,
    #[error("general error {0}")]
    GeneralError(String),
    #[error("unknown identifier")]
    UnknownIdentifierError,
    #[error("keri error")]
    KeriError(#[from] keri::error::Error),
    #[error("base64 decode error")]
    Base64Error(#[from] base64::DecodeError),
    #[error("hex decode error")]
    HexError(#[from] hex::FromHexError),
}

#[test]
pub fn test_ed_key() {
    let public_key = "6UMthURGxkWVEKxJ/m3OpgV3Be/STsM//4tONKaiTrA=";
    let decoded_pk = base64::decode(public_key).unwrap();
    let pk = keri::keys::PublicKey::new(decoded_pk);
    let bp = Basic::Ed25519.derive(pk);
    let sig_hex = "F36EBB3CC564630B1A306CA5AE639D88A8884CE8CAF3FBB69E2616000DD24E5A34AB555EC0039D9CBD52488DF2A054B99AA18D4FF63529C8E4E6C389DD0BFE03";
    let decoded_signature = hex::decode(sig_hex).expect("Decoding failed");
    let ss = SelfSigning::Ed25519Sha512.derive(decoded_signature);
    let res = bp.verify("kotki".as_bytes(), &ss).unwrap();
    assert!(res);
}

#[test]
pub fn test_parse_attachment() {
    use tempfile::Builder;

    // Create temporary db file.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let kel = Kel::init(root.path().to_str().unwrap().into());

    let issuer_kel = r#"{"v":"KERI10JSON0001b7_","t":"icp","d":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","i":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","s":"0","kt":"1","k":["DruZ2ykSgEmw2EHm34wIiEGsUa_1QkYlsCAidBSzUkTU"],"nt":"1","n":["Eao8tZQinzilol20Ot-PPlVz6ta8C4z-NpDOeVs63U8s"],"bt":"3","b":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"],"c":[],"a":[]}-VBq-AABAA0EpZtBNLxOIncUDeLgwX3trvDXFA5adfjpUwb21M5HWwNuzBMFiMZQ9XqM5L2bFUVi6zXomcYuF-mR7CFpP8DQ-BADAAWUZOb17DTdCd2rOaWCf01ybl41U7BImalPLJtUEU-FLrZhDHls8iItGRQsFDYfqft_zOr8cNNdzUnD8hlSziBwABmUbyT6rzGLWk7SpuXGAj5pkSw3vHQZKQ1sSRKt6x4P13NMbZyoWPUYb10ftJlfXSyyBRQrc0_TFqfLTu_bXHCwACKPLkcCa_tZKalQzn3EgZd1e_xImWdVyzfYQmQvBpfJZFfg2c-sYIL3zl1WHpMQQ_iDmxLSmLSQ9jZ9WAjcmDCg-EAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-04-11T20c50c16d643400p00c00{"v":"KERI10JSON00013a_","t":"ixn","d":"Ek48ahzTIUA1ynJIiRd3H0WymilgqDbj8zZp4zzrad-w","i":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","s":"1","p":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","a":[{"i":"EoLNCdag8PlHpsIwzbwe7uVNcPE1mTr-e1o9nCIDPWgM","s":"0","d":"EoLNCdag8PlHpsIwzbwe7uVNcPE1mTr-e1o9nCIDPWgM"}]}-VBq-AABAAZZlCpwL0QwqF-eTuqEgfn95QV9S4ruh4wtxKQbf1-My60Nmysprv71y0tJGEHkMsUBRz0bf-JZsMKyZ3N8m7BQ-BADAA6ghW2PpLC0P9CxmW13G6AeZpHinH-_HtVOu2jWS7K08MYkDPrfghmkKXzdsMZ44RseUgPPty7ZEaAxZaj95bAgABKy0uBR3LGMwg51xjMZeVZcxlBs6uARz6quyl0t65BVrHX3vXgoFtzwJt7BUl8LXuMuoM9u4PQNv6yBhxg_XEDwACJe4TwVqtGy1fTDrfPxa14JabjsdRxAzZ90wz18-pt0IwG77CLHhi9vB5fF99-fgbYp2Zoa9ZVEI8pkU6iejcDg-EAB0AAAAAAAAAAAAAAAAAAAAAAQ1AAG2022-04-11T20c50c22d909900p00c00{"v":"KERI10JSON00013a_","t":"ixn","d":"EPYT0dEpoc_5QKIGnRYFRqpXHGpeYOhveJTmHoVC6LMU","i":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","s":"2","p":"Ek48ahzTIUA1ynJIiRd3H0WymilgqDbj8zZp4zzrad-w","a":[{"i":"EzSVC7-SuizvdVkpXmHQx5FhUElLjUOjCbgN81ymeWOE","s":"0","d":"EQ6RIFoVUDmmyuoMDMPPHDm14GtXaIf98j4AG2vNfZ1U"}]}-VBq-AABAAYycRM_VyvV2fKyHdUceMcK8ioVrBSixEFqY1nEO9eTZQ2NV8hrLc_ux9_sKn1p58kyZv5_y2NW3weEiqn-5KAA-BADAAQl22xz4Vzkkf14xsHMAOm0sDkuxYY8SAgJV-RwDDwdxhN4WPr-3Pi19x57rDJAE_VkyYwKloUuzB5Dekh-JzCQABk98CK_xwG52KFWt8IEUU-Crmf058ZJPB0dCffn-zjiNNgjv9xyGVs8seb0YGInwrB351JNu0sMHuEEgPJLKxAgACw556h2q5_BG6kPHAF1o9neMLDrZN_sCaJ-3slWWX-y8M3ddPN8Zp89R9A36t3m2rq-sbC5h_UDg5qdnrZ-ZxAw-EAB0AAAAAAAAAAAAAAAAAAAAAAg1AAG2022-04-11T20c50c23d726188p00c00"#;
  
    kel.parse_and_process(issuer_kel.as_bytes()).unwrap();

    let attachment_stream = "-FABEw-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M0AAAAAAAAAAAAAAAAAAAAAAAEw-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M-AABAAKcvAE-GzYu4_aboNjC0vNOcyHZkm5Vw9-oGGtpZJ8pNdzVEOWhnDpCWYIYBAMVvzkwowFVkriY3nCCiBAf8JDw";

    let a = kel.parse_attachment(attachment_stream.into());
    let public_key_signature_pair = a
        .unwrap()
        .iter()
        .map(|(bp, sp)| (bp.to_str(), sp.to_str()))
        .collect::<Vec<_>>();
    assert_eq!(public_key_signature_pair.len(), 1);
}
