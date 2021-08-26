use std::{
    fmt::{self, Debug},
    path::Path,
};

use keri::{
    database::sled::SledEventDatabase,
    derivation::self_signing::SelfSigning,
    event::{
        sections::{
            KeyConfig,
        },
        EventMessage,
    },
    event_message::parse::signed_message,
    event_message::parse::{message, signed_event_stream},
    event_message::SignedEventMessage,
    prefix::AttachedSignaturePrefix,
    prefix::{IdentifierPrefix, Prefix},
    processor::EventProcessor,
    state::IdentifierState,
};

pub mod error;
use error::Error;

use self::event_generator::PublicKeysConfig;
pub mod event_generator;

pub struct KEL {
    prefix: IdentifierPrefix,
    database: Option<SledEventDatabase>,
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

    pub fn incept(keys: &PublicKeysConfig) -> Result<EventMessage, Error> {
        event_generator::make_icp(keys, None)
    }

    pub fn finalize_incept(
        database_root: &str,
        icp: EventMessage,
        signature: Vec<u8>,
    ) -> Result<KEL, Error> {
        let prefix = icp.event.prefix.clone();
        let database = Some(KEL::create_kel_db(Path::new(
            &[database_root, &prefix.to_str()].join("/"),
        ))?);

        let sigged = icp.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )]);

        let processor = match database {
            Some(ref db) => Ok(EventProcessor::new(db)),
            None => Err(Error::NoDatabase),
        }?;
        processor.process(signed_message(&sigged.serialize()?).unwrap().1)?;

        Ok(KEL {
            prefix,
            database,
        })
    }

    pub fn rotate(&self, keys: &PublicKeysConfig) -> Result<EventMessage, Error> {
        event_generator::make_rot(keys, self.get_state()?.unwrap())
    }

    pub fn finalize_rotate(
        &self,
        rotation: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<SignedEventMessage, Error> {
        let rot_event = message(&rotation).unwrap().1.event;
        let rot = rot_event.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )]);

        let processor = match self.database {
            Some(ref db) => Ok(EventProcessor::new(db)),
            None => Err(Error::NoDatabase),
        }?;
        processor.process(signed_message(&rot.serialize()?).unwrap().1)?;

        Ok(rot)
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
        processor.get_kerl(prefix).map_err(|e| Error::KeriError(e))
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
