use std::{
    fmt::{self, Debug},
    path::Path,
};

use keri::{database::sled::SledEventDatabase, derivation::{self_addressing::SelfAddressing, self_signing::SelfSigning}, event::{EventMessage, sections::{KeyConfig, seal::{DigestSeal, Seal}}}, event_message::SignedEventMessage, event_message::parse::signed_message, event_message::parse::{message, signed_event_stream}, prefix::AttachedSignaturePrefix, prefix::{IdentifierPrefix, Prefix}, processor::EventProcessor, signer::KeyManager, state::IdentifierState};

pub mod error;
use error::Error;
pub mod event_generator;

pub struct KEL {
    prefix: IdentifierPrefix,
    database: Option<SledEventDatabase>,
    database_root: String,
}

impl Debug for KEL {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}",
            self.get_kel()
                .map_err(|_e| fmt::Error)?
                .map(|k| String::from_utf8(k))
                .unwrap()
        )
    }
}

impl<'d> KEL {
    // incept a state and keys
    pub fn new(path: &str) -> Result<KEL, Error> {
        Ok(KEL {
            prefix: IdentifierPrefix::default(),
            database: None,
            database_root: path.to_owned(),
        })
    }

    fn create_kel_db(path: &Path) -> Result<SledEventDatabase, Error> {
        SledEventDatabase::new(path).map_err(|e| e.into())
    }

    pub fn process_event(&self, msg: &[u8], signature: &[u8]) -> Result<SignedEventMessage, Error> {
        let processor = match self.database {
            Some(ref db) => Ok(EventProcessor::new(db)),
            None => Err(Error::NoDatabase),
        }?;
        let message = message(&msg).unwrap().1.event;
        let sigged = message.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature.to_vec(),
            0,
        )]);
        processor.process(signed_message(&sigged.serialize()?).unwrap().1)?;

        Ok(sigged)
    }

    pub fn process_stream(&self, stream: &[u8]) -> Result<(), Error> {
        let processor = match self.database {
            Some(ref db) => Ok(EventProcessor::new(db)),
            None => Err(Error::NoDatabase),
        }?;
        let (_rest, events) =
            signed_event_stream(stream).map_err(|e| Error::Generic(e.to_string()))?;
        let (_processed_ok, _processed_failed): (Vec<_>, Vec<_>) = events
            .into_iter()
            .map(|event| processor.process(event.clone()).and_then(|_| Ok(event)))
            .partition(Result::is_ok);
        Ok(())
    }

    pub fn incept<K: KeyManager>(&mut self, key_manager: &K) -> Result<SignedEventMessage, Error> {
        let icp = event_generator::make_icp(key_manager, Some(self.prefix.clone())).unwrap();
        let prefix = icp.event.prefix.clone();
        self.database = Some(KEL::create_kel_db(Path::new(&[self.database_root.clone(), prefix.to_str()].join("/")))?);

        let sigged = icp.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            key_manager.sign(&icp.serialize()?)?,
            0,
        )]);

        let processor = match self.database {
            Some(ref db) => Ok(EventProcessor::new(db)),
            None => Err(Error::NoDatabase),
        }?;
        processor.process(signed_message(&sigged.serialize()?).unwrap().1)?;

        self.prefix = prefix;

        Ok(sigged)
    }

    pub fn rotate<K: KeyManager>(&self, key_manager: &K) -> Result<SignedEventMessage, Error> {
        let rot = event_generator::make_rot(key_manager, self.get_state()?.unwrap()).unwrap();

        let rot = rot.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            key_manager.sign(&rot.serialize()?)?,
            0,
        )]);

        let processor = match self.database {
            Some(ref db) => Ok(EventProcessor::new(db)),
            None => Err(Error::NoDatabase),
        }?;
        processor.process(signed_message(&rot.serialize()?).unwrap().1)?;

        Ok(rot)
    }

    pub fn make_ixn<K: KeyManager>(
        &mut self,
        payload: Option<&str>,
        key_manager: &K,
    ) -> Result<SignedEventMessage, Error> {
        let state = self.get_state()?.unwrap();
        let seal_list = match payload {
            Some(payload) => {
                vec![Seal::Digest(DigestSeal {
                    dig: SelfAddressing::Blake3_256.derive(payload.as_bytes()),
                })]
            }
            None => vec![],
        };

        let ev = event_generator::make_ixn_with_seal(&seal_list, state).unwrap();

        let ixn = ev.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            key_manager.sign(&ev.serialize()?)?,
            0,
        )]);

        let processor = match self.database {
            Some(ref db) => Ok(EventProcessor::new(db)),
            None => Err(Error::NoDatabase),
        }?;

        processor.process(signed_message(&ixn.serialize()?).unwrap().1)?;

        Ok(ixn)
    }

    pub fn make_ixn_with_seal<K: KeyManager>(
        &self,
        seal_list: &[Seal],
        key_manager: &K,
    ) -> Result<SignedEventMessage, Error> {
        let state = self.get_state()?.unwrap();

        let ev = event_generator::make_ixn_with_seal(seal_list, state).unwrap();

        let ixn = ev.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            key_manager.sign(&ev.serialize()?)?,
            0,
        )]);

        let processor = match self.database {
            Some(ref db) => Ok(EventProcessor::new(db)),
            None => Err(Error::NoDatabase),
        }?;
        processor.process(signed_message(&ixn.serialize()?).unwrap().1)?;

        Ok(ixn)
    }

    pub fn make_ixn_seal(&self, seal_list: &[Seal]) -> Result<EventMessage, Error> {
        let state = self.get_state()?.unwrap();

        let ev = event_generator::make_ixn_with_seal(seal_list, state).unwrap();

        Ok(ev)
    }

    pub fn get_prefix(&self) -> IdentifierPrefix {
        self.prefix.clone()
    }

    pub fn get_state(&self) -> Result<Option<IdentifierState>, Error> {
        let processor = match self.database {
            Some(ref db) => Ok(EventProcessor::new(db)),
            None => Err(Error::NoDatabase),
        }?;
        processor
            .compute_state(&self.prefix)
            .map_err(|e| Error::KeriError(e))
    }

    pub fn get_event_at_sn(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Option<EventMessage>, Error> {
        let processor = match self.database {
            Some(ref db) => Ok(EventProcessor::new(db)),
            None => Err(Error::NoDatabase),
        }?;
        Ok(processor
            .get_event_at_sn(id, sn)?
            .map(|e| e.event.event_message))
    }

    pub fn get_kel(&self) -> Result<Option<Vec<u8>>, Error> {
        let processor = match self.database {
            Some(ref db) => Ok(EventProcessor::new(db)),
            None => Err(Error::NoDatabase),
        }?;
        processor
            .get_kerl(&self.prefix)
            .map_err(|e| Error::KeriError(e))
    }

    pub fn get_kel_for_prefix(&self, prefix: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Error> {
        let processor = match self.database {
            Some(ref db) => Ok(EventProcessor::new(db)),
            None => Err(Error::NoDatabase),
        }?;
        processor
            .get_kerl(prefix)
            .map_err(|e| Error::KeriError(e))
    }

    pub fn get_state_for_prefix(
        &self,
        prefix: &IdentifierPrefix,
    ) -> Result<Option<IdentifierState>, Error> {
        let processor = match self.database {
            Some(ref db) => Ok(EventProcessor::new(db)),
            None => Err(Error::NoDatabase),
        }?;
        processor
            .compute_state(prefix)
            .map_err(|e| Error::KeriError(e))
    }

    pub fn get_keys_at_sn(
        &self,
        prefix: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Option<KeyConfig>, Error> {
        let processor = match self.database {
            Some(ref db) => Ok(EventProcessor::new(db)),
            None => Err(Error::NoDatabase),
        }?;
        Ok(processor
            .compute_state_at_sn(&prefix, sn)
            .map_err(|e| Error::KeriError(e))?
            .map(|st| st.current))
        
    }
}
