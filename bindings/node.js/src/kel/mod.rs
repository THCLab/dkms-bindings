use std::{
    fmt::{self, Debug},
    path::Path,
};

use keri::{
    database::sled::SledEventDatabase,
    event::{sections::KeyConfig, EventMessage},
    event_message::parse::signed_message,
    event_message::parse::{message, signed_event_stream},
    event_message::SignedEventMessage,
    prefix::AttachedSignaturePrefix,
    prefix::{parse::self_signing_prefix, IdentifierPrefix, Prefix, SelfSigningPrefix},
    processor::EventProcessor,
    state::IdentifierState,
};

pub mod error;
use error::Error;

use self::event_generator::{Key, PublicKeysConfig};
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
    pub fn new() -> Result<KEL, Error> {
        Ok(KEL {
            prefix: IdentifierPrefix::default(),
            database: None,
        })
    }

    fn create_kel_db(path: &Path) -> Result<SledEventDatabase, Error> {
        SledEventDatabase::new(path).map_err(|e| e.into())
    }

    /// Process event and signature
    ///
    /// Checks if event message matches signature and adds it to database.
    /// # Arguments
    ///
    /// * `event` - Bytes of serialized evednt message
    /// * `signature` 
    pub fn process_event(
        &self,
        event: &[u8],
        signature: &SelfSigningPrefix,
    ) -> Result<SignedEventMessage, Error> {
        let processor = match self.database {
            Some(ref db) => Ok(EventProcessor::new(db)),
            None => Err(Error::NoDatabase),
        }?;
        let message = message(&event).unwrap().1.event;
        let sigged = message.sign(vec![AttachedSignaturePrefix::new(
            signature.derivation,
            signature.derivative(),
            0,
        )]);
        processor.process(signed_message(&sigged.serialize()?).unwrap().1)?;

        Ok(sigged)
    }

    /// Process incoming events stream
    ///
    /// Parses stream of events, checks them and adds to database
    /// # Arguments
    ///
    /// * `stream` - Bytes of serialized events stream
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

    /// Generate inception event for given public key config.
    /// # Arguments
    ///
    /// * `keys` - `PublicKeysConfig` which store current and next public keys.
    pub fn incept(keys: &PublicKeysConfig) -> Result<EventMessage, Error> {
        event_generator::make_icp(keys, None)
    }

    /// Finalize inception.
    ///
    /// Initiate key event log for prefix from inception event.
    /// # Arguments
    /// * `database_root` - srtring representing path where database files will be stored.
    /// * `icp` - inception event message.
    /// *` signature` 
    pub fn finalize_incept(
        database_root: &str,
        icp: EventMessage,
        signature: SelfSigningPrefix,
    ) -> Result<KEL, Error> {
        let prefix = icp.event.prefix.clone();
        let database = Some(KEL::create_kel_db(Path::new(
            &[database_root, &prefix.to_str()].join("/"),
        ))?);

        let sigged = icp.sign(vec![AttachedSignaturePrefix::new(
            signature.derivation,
            signature.derivative(),
            0,
        )]);

        let processor = match database {
            Some(ref db) => Ok(EventProcessor::new(db)),
            None => Err(Error::NoDatabase),
        }?;
        processor.process(signed_message(&sigged.serialize()?).unwrap().1)?;

        Ok(KEL { prefix, database })
    }

    /// Generate rotation event for given public key config.
    /// # Arguments
    ///
    /// * `keys` - public keys config for new rotation event.
    pub fn rotate(&self, keys: &PublicKeysConfig) -> Result<EventMessage, Error> {
        event_generator::make_rot(keys, self.get_state()?.unwrap())
    }

    /// Finalize rotation.
    ///
    /// Update current keys of identifier if signature matches rotation event.
    /// # Arguments
    /// * `rotation` - bytes of serialized rotation event message.
    /// *` signature` - signature of rotation event.
    pub fn finalize_rotation(
        &self,
        rotation: Vec<u8>,
        signature: SelfSigningPrefix,
    ) -> Result<SignedEventMessage, Error> {
        let rot_event = message(&rotation).unwrap().1.event;
        let rot = rot_event.sign(vec![AttachedSignaturePrefix::new(
            signature.derivation,
            signature.derivative(),
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

    /// Returns own key event log.
    pub fn get_kel(&self) -> Result<Option<Vec<u8>>, Error> {
        let processor = match self.database {
            Some(ref db) => Ok(EventProcessor::new(db)),
            None => Err(Error::NoDatabase),
        }?;
        processor
            .get_kerl(&self.prefix)
            .map_err(|e| Error::KeriError(e))
    }

    /// Returns key event log of given prefix.
    /// (Only if database contains kel of given prefix. It can be out of
    /// date if most recent events weren't processed yet)
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

    pub fn get_current_public_keys(
        &self,
        prefix: &IdentifierPrefix,
    ) -> Result<Option<Vec<Key>>, Error> {
        let keys = self.get_state_for_prefix(prefix)?.map(|state| {
            state
                .current
                .public_keys
                .iter()
                .map(|bp| Key {
                    key: bp.public_key.key(),
                    key_type: bp.derivation,
                })
                .collect()
        });
        Ok(keys)
    }

    /// Verify signature of given message
    ///
    /// Checks if message matches signature made by identity of given prefix.
    /// # Arguments
    ///
    /// * `message` - Bytes of message
    /// * `signature` - A string slice that holds the signature in base64
    /// * `prefix` - A string slice that holds the prefix of signer
    pub fn verify(
        &self,
        message: &[u8],
        signature: &SelfSigningPrefix,
        prefix: &IdentifierPrefix,
    ) -> Result<bool, Error> {
        let key_conf = self
            .get_state_for_prefix(&prefix)?
            .ok_or(Error::Generic("There is no state".into()))?
            .current;
        let sigs = vec![AttachedSignaturePrefix::new(
            signature.derivation,
            signature.derivative(),
            0,
        )];
        key_conf
            .verify(message, &sigs)
            .map_err(|e| Error::Generic(e.to_string()))
    }

    /// Verify signature of given message using keys at `sn`
    ///
    /// Checks if message matches signature made identity of given prefix
    /// using key from event od given seqence number.
    ///
    /// # Arguments
    ///
    /// * `message` - Bytes of message
    /// * `signature` - A string slice that holds the signature in base64
    /// * `prefix` - A string slice that holds the prefix of signer
    /// * `sn` - A sequence number of event which established keys used to sign message.
    pub fn verify_at_sn(
        &self,
        message: &[u8],
        signature: &SelfSigningPrefix,
        prefix: &IdentifierPrefix,
        sn: u64,
    ) -> Result<bool, Error> {
        let key_conf = self
            .get_keys_at_sn(prefix, sn)?
            .ok_or(Error::Generic(format!(
                "There are no key config fo identifier {} at {}",
                prefix.to_str(),
                sn
            )))?;
        let sigs = vec![AttachedSignaturePrefix::new(
            signature.derivation,
            signature.derivative(),
            0,
        )];
        key_conf
            .verify(message, &sigs)
            .map_err(|e| Error::Generic(e.to_string()))
    }

    pub fn current_sn(&self) -> Result<u64, Error> {
        Ok(self.get_state()?.unwrap().sn)
    }
}
