pub use keri::derivation::{
    basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning,
};
use keri::event::sections::seal::EventSeal;
pub use keri::event::sections::threshold::SignatureThreshold;
pub use keri::event_parsing::Attachment;
pub use keri::keys::PublicKey;
pub use keri::oobi::{EndRole, LocationScheme, Role};
pub use keri::prefix::{
    AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, Prefix, SelfAddressingPrefix,
    SelfSigningPrefix,
};
pub use keri::signer::{CryptoBox, KeyManager};
use keri::state::IdentifierState;
use keri::{
    database::sled::SledEventDatabase,
    event::{receipt::Receipt, SerializationFormats},
    event_message::signed_event_message::{Message, SignedNontransferableReceipt},
    event_parsing::message::signed_event_stream,
    processor::{
        escrow::default_escrow_bus,
        event_storage::EventStorage,
        notification::{JustNotification, NotificationBus, Notifier},
        EventProcessor,
    },
};
use std::{path::Path, sync::Arc};
use thiserror::Error;

use crate::utils::get_current_public_key;

pub struct Kel {
    db: Arc<SledEventDatabase>,
    notification_bus: NotificationBus,
}
impl Kel {
    pub fn init(path: &str) -> Result<Self, KelError> {
        let db = Arc::new(SledEventDatabase::new(Path::new(&path))?);
        Ok(Kel {
            db: db.clone(),
            notification_bus: default_escrow_bus(db.clone()),
        })
    }

    pub fn register_observer(
        &mut self,
        notifier: Arc<dyn Notifier + Send + Sync>,
        notification: Vec<JustNotification>,
    ) {
        self.notification_bus
            .register_observer(notifier.clone(), notification);
    }

    pub fn get_state_for_id(&self, id: &IdentifierPrefix) -> Result<IdentifierState, KelError> {
        let storage = EventStorage::new(self.db.clone());
        storage
            .get_state(&id)?
            .ok_or_else(|| KelError::UnknownIdentifierError)
    }

    pub fn get_kel(&self, id: &IdentifierPrefix) -> Result<String, KelError> {
        let storage = EventStorage::new(self.db.clone());
        String::from_utf8(
            storage
                .get_kel(&id)?
                .ok_or(KelError::UnknownIdentifierError)?,
        )
        .map_err(|e| KelError::ParseEventError(e.to_string()))
    }

    pub fn parse_and_process(&self, msg: &[u8]) -> Result<(), KelError> {
        let (_, events) =
            signed_event_stream(msg).map_err(|e| KelError::ParseEventError(e.to_string()))?;

        events
            .into_iter()
            .try_for_each(|parsed_event| -> Result<_, _> {
                let msg = Message::try_from(parsed_event)?;
                self.process(&vec![msg.clone()])?;
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
                            &receipt.to_message(SerializationFormats::JSON)?,
                            None,
                            Some(witness_receipts),
                        );
                        self.process(&vec![Message::NontransferableRct(signed_receipt)])
                    } else {
                        Ok(())
                    }
                } else {
                    Ok(())
                }
            })?;
        Ok(())
    }

    pub fn process(&self, msg: &[Message]) -> Result<(), KelError> {
        let processor = EventProcessor::new(self.db.clone());
        let (_process_ok, _process_failed): (Vec<_>, Vec<_>) = msg
            .iter()
            .map(|message| {
                processor
                    .process(message.clone())
                    .and_then(|not| self.notification_bus.notify(&not))
            })
            .partition(Result::is_ok);
        Ok(())
    }

    pub fn get_current_public_keys(
        &self,
        prefix: &IdentifierPrefix,
    ) -> Result<Vec<BasicPrefix>, KelError> {
        let keys = self.get_state_for_id(prefix)?.current.public_keys;
        Ok(keys)
    }

    pub fn get_current_witness_list(
        &self,
        prefix: &IdentifierPrefix,
    ) -> Result<Vec<BasicPrefix>, KelError> {
        let keys = self.get_state_for_id(prefix)?.witness_config.witnesses;
        Ok(keys)
    }

    pub fn get_public_key_for_attachment(
        &self,
        att_str: String,
    ) -> Result<Vec<(BasicPrefix, SelfSigningPrefix)>, KelError> {
        let storage = EventStorage::new(self.db.clone());
        get_current_public_key(storage, &att_str)
    }

    pub fn get_last_establishment_event_seal(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<EventSeal, KelError> {
        let storage = EventStorage::new(self.db.clone());
        storage
            .get_last_establishment_event_seal(id)?
            .ok_or_else(|| KelError::UnknownIdentifierError)
    }

    pub fn get_receipts_of_event(
        &self,
        event_seal: EventSeal,
    ) -> Result<SignedNontransferableReceipt, KelError> {
        let storage = EventStorage::new(self.db.clone());
        storage
            .get_nt_receipts(&event_seal.prefix, event_seal.sn, &event_seal.event_digest)?
            .ok_or_else(|| KelError::NoReceipts(event_seal))
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
    #[error("can't notify: {0}")]
    NotificationError(String),
    #[error("missing event")]
    MissingEventError,
    #[error("general error {0}")]
    GeneralError(String),
    #[error("unknown identifier")]
    UnknownIdentifierError,
    #[error("Can't find receipts of {0:?}")]
    NoReceipts(EventSeal),
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
    let kel = Kel::init(root.path().to_str().unwrap().into()).unwrap();

    let issuer_kel = r#"{"v":"KERI10JSON0001b7_","t":"icp","d":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","i":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","s":"0","kt":"1","k":["DruZ2ykSgEmw2EHm34wIiEGsUa_1QkYlsCAidBSzUkTU"],"nt":"1","n":["Eao8tZQinzilol20Ot-PPlVz6ta8C4z-NpDOeVs63U8s"],"bt":"3","b":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"],"c":[],"a":[]}-VBq-AABAA0EpZtBNLxOIncUDeLgwX3trvDXFA5adfjpUwb21M5HWwNuzBMFiMZQ9XqM5L2bFUVi6zXomcYuF-mR7CFpP8DQ-BADAAWUZOb17DTdCd2rOaWCf01ybl41U7BImalPLJtUEU-FLrZhDHls8iItGRQsFDYfqft_zOr8cNNdzUnD8hlSziBwABmUbyT6rzGLWk7SpuXGAj5pkSw3vHQZKQ1sSRKt6x4P13NMbZyoWPUYb10ftJlfXSyyBRQrc0_TFqfLTu_bXHCwACKPLkcCa_tZKalQzn3EgZd1e_xImWdVyzfYQmQvBpfJZFfg2c-sYIL3zl1WHpMQQ_iDmxLSmLSQ9jZ9WAjcmDCg-EAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-04-11T20c50c16d643400p00c00{"v":"KERI10JSON00013a_","t":"ixn","d":"Ek48ahzTIUA1ynJIiRd3H0WymilgqDbj8zZp4zzrad-w","i":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","s":"1","p":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","a":[{"i":"EoLNCdag8PlHpsIwzbwe7uVNcPE1mTr-e1o9nCIDPWgM","s":"0","d":"EoLNCdag8PlHpsIwzbwe7uVNcPE1mTr-e1o9nCIDPWgM"}]}-VBq-AABAAZZlCpwL0QwqF-eTuqEgfn95QV9S4ruh4wtxKQbf1-My60Nmysprv71y0tJGEHkMsUBRz0bf-JZsMKyZ3N8m7BQ-BADAA6ghW2PpLC0P9CxmW13G6AeZpHinH-_HtVOu2jWS7K08MYkDPrfghmkKXzdsMZ44RseUgPPty7ZEaAxZaj95bAgABKy0uBR3LGMwg51xjMZeVZcxlBs6uARz6quyl0t65BVrHX3vXgoFtzwJt7BUl8LXuMuoM9u4PQNv6yBhxg_XEDwACJe4TwVqtGy1fTDrfPxa14JabjsdRxAzZ90wz18-pt0IwG77CLHhi9vB5fF99-fgbYp2Zoa9ZVEI8pkU6iejcDg-EAB0AAAAAAAAAAAAAAAAAAAAAAQ1AAG2022-04-11T20c50c22d909900p00c00{"v":"KERI10JSON00013a_","t":"ixn","d":"EPYT0dEpoc_5QKIGnRYFRqpXHGpeYOhveJTmHoVC6LMU","i":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","s":"2","p":"Ek48ahzTIUA1ynJIiRd3H0WymilgqDbj8zZp4zzrad-w","a":[{"i":"EzSVC7-SuizvdVkpXmHQx5FhUElLjUOjCbgN81ymeWOE","s":"0","d":"EQ6RIFoVUDmmyuoMDMPPHDm14GtXaIf98j4AG2vNfZ1U"}]}-VBq-AABAAYycRM_VyvV2fKyHdUceMcK8ioVrBSixEFqY1nEO9eTZQ2NV8hrLc_ux9_sKn1p58kyZv5_y2NW3weEiqn-5KAA-BADAAQl22xz4Vzkkf14xsHMAOm0sDkuxYY8SAgJV-RwDDwdxhN4WPr-3Pi19x57rDJAE_VkyYwKloUuzB5Dekh-JzCQABk98CK_xwG52KFWt8IEUU-Crmf058ZJPB0dCffn-zjiNNgjv9xyGVs8seb0YGInwrB351JNu0sMHuEEgPJLKxAgACw556h2q5_BG6kPHAF1o9neMLDrZN_sCaJ-3slWWX-y8M3ddPN8Zp89R9A36t3m2rq-sbC5h_UDg5qdnrZ-ZxAw-EAB0AAAAAAAAAAAAAAAAAAAAAAg1AAG2022-04-11T20c50c23d726188p00c00"#;

    kel.parse_and_process(issuer_kel.as_bytes()).unwrap();

    let attachment_stream = "-FABEw-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M0AAAAAAAAAAAAAAAAAAAAAAAEw-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M-AABAAKcvAE-GzYu4_aboNjC0vNOcyHZkm5Vw9-oGGtpZJ8pNdzVEOWhnDpCWYIYBAMVvzkwowFVkriY3nCCiBAf8JDw";

    let a = kel.get_public_key_for_attachment(attachment_stream.into());
    let public_key_signature_pair = a
        .unwrap()
        .iter()
        .map(|(bp, sp)| (bp.to_str(), sp.to_str()))
        .collect::<Vec<_>>();
    assert_eq!(public_key_signature_pair.len(), 1);
}
