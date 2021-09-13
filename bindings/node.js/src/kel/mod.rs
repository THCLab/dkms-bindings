use std::{fmt::{self, Debug}, path::Path};

use keri::{database::sled::SledEventDatabase, event::{sections::KeyConfig, EventMessage}, event_message::SignedEventMessage, event_message::parse::signed_message, event_message::parse::{message, signed_event_stream}, prefix::AttachedSignaturePrefix, prefix::{BasicPrefix, IdentifierPrefix, Prefix, SelfAddressingPrefix, SelfSigningPrefix}, processor::EventProcessor, state::IdentifierState};

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

    pub fn load_kel(database_root: &str, prefix: IdentifierPrefix) -> Result<KEL, Error> {
        let path = &[database_root, &prefix.to_str()].join("/");
        if std::path::Path::new(path).exists() {
            let database = Some(KEL::create_kel_db(Path::new(path))?);
            Ok(KEL { prefix, database })
        } else {
            Err(Error::Generic("No identifer in db".into()))
        }
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
        let message = message(&event).unwrap().1.event_message;
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
        event_generator::make_icp(keys)
    }

    /// Finalize inception.
    ///
    /// Initiate key event log for prefix from inception event.
    /// # Arguments
    /// * `database_root` - srtring representing path where database files will be stored.
    /// * `icp` - inception event message.
    /// *` signatures`
    pub fn finalize_incept(
        database_root: &str,
        icp: &EventMessage,
        signatures: Vec<SelfSigningPrefix>,
    ) -> Result<KEL, Error> {
        let prefix = icp.event.prefix.clone();
        let database = Some(KEL::create_kel_db(Path::new(
            &[database_root, &prefix.to_str()].join("/"),
        ))?);

        let pub_keys = match icp.event.event_data {
            keri::event::event_data::EventData::Icp(ref icp) => {
                Ok(icp.key_config.public_keys.to_owned())
            }
            _ => Err(Error::Generic("Improper event type".into())),
        }?;

        let indexed_signatures: Vec<AttachedSignaturePrefix> = signatures
            .into_iter()
            .map(|signature| {
                (
                    pub_keys
                        .iter()
                        .position(|x| x.verify(&icp.serialize().unwrap(), &signature).unwrap())
                        .unwrap(),
                    signature,
                )
            })
            .map(|(i, signature)| {
                AttachedSignaturePrefix::new(signature.derivation, signature.derivative(), i as u16)
            })
            .collect();

        let sigged = icp.sign(indexed_signatures);

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
    /// *` signatures` - list of signatures of rotation event.
    pub fn finalize_rotation(
        &self,
        rotation: Vec<u8>,
        signatures: Vec<SelfSigningPrefix>,
    ) -> Result<SignedEventMessage, Error> {
        let rot_event = message(&rotation).unwrap().1.event_message;

        let pub_keys = match rot_event.event.event_data {
            keri::event::event_data::EventData::Rot(ref rot) => {
                Ok(rot.key_config.public_keys.to_owned())
            }
            _ => Err(Error::Generic("Improper event type".into())),
        }?;

        let indexed_signatures: Vec<AttachedSignaturePrefix> = signatures
            .into_iter()
            .map(|signature| {
                (
                    pub_keys
                        .iter()
                        .position(|x| x.verify(&rotation, &signature).unwrap())
                        .unwrap(),
                    signature,
                )
            })
            .map(|(i, signature)| {
                AttachedSignaturePrefix::new(signature.derivation, signature.derivative(), i as u16)
            })
            .collect();

        let rot = rot_event.sign(indexed_signatures);

        let processor = match self.database {
            Some(ref db) => Ok(EventProcessor::new(db)),
            None => Err(Error::NoDatabase),
        }?;
        processor.process(signed_message(&rot.serialize()?).unwrap().1)?;

        Ok(rot)
    }

    pub fn anchor(&self, payload: &[SelfAddressingPrefix]) -> Result<EventMessage, Error> {
        event_generator::make_ixn(payload, self.get_state()?.unwrap())
    }
    
     pub fn finalize_anchor(
        &self,
        ixn: Vec<u8>,
        signatures: Vec<SelfSigningPrefix>,
    ) -> Result<SignedEventMessage, Error> {
        let ixn_event = message(&ixn).unwrap().1.event_message;

        let pub_keys = self.get_state()?.unwrap().current.public_keys;

        let indexed_signatures: Vec<AttachedSignaturePrefix> = signatures
            .into_iter()
            .map(|signature| {
                (
                    pub_keys
                        .iter()
                        .position(|x| x.verify(&ixn, &signature).unwrap())
                        .unwrap(),
                    signature,
                )
            })
            .map(|(i, signature)| {
                AttachedSignaturePrefix::new(signature.derivation, signature.derivative(), i as u16)
            })
            .collect();

        let signed_ixn = ixn_event.sign(indexed_signatures);

        let processor = match self.database {
            Some(ref db) => Ok(EventProcessor::new(db)),
            None => Err(Error::NoDatabase),
        }?;
        processor.process(signed_message(&signed_ixn.serialize()?).unwrap().1)?;

        Ok(signed_ixn)
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
            .map(|e| e.signed_event_message.event_message))
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
    ) -> Result<Option<Vec<BasicPrefix>>, Error> {
        let keys = self
            .get_state_for_prefix(prefix)?
            .map(|state| state.current.public_keys);
        Ok(keys)
    }

    /// Verify signature of given message
    ///
    /// Checks if message matches signature made by identity of given prefix.
    /// # Arguments
    ///
    /// * `message` - Bytes of message
    /// * `signatures` - A list of signatures
    /// * `prefix` - A string slice that holds the prefix of signer
    pub fn verify(
        &self,
        message: &[u8],
        signatures: &[SelfSigningPrefix],
        prefix: &IdentifierPrefix,
    ) -> Result<bool, Error> {
        let key_config = self
            .get_state_for_prefix(&prefix)?
            .ok_or(Error::Generic("There is no state".into()))?
            .current;

        let indexed_signatures: Result<Vec<AttachedSignaturePrefix>, _> = signatures
            .into_iter()
            .map(|signature| {
                (
                    key_config
                        .public_keys
                        .iter()
                        .position(|x| x.verify(message, &signature).unwrap()),
                    // .ok_or(napi::Error::from_reason(format!("There is no key for signature: {}", signature.to_str())).unwrap(),
                    signature,
                )
            })
            .map(|(i, signature)| match i {
                Some(i) => Ok(AttachedSignaturePrefix::new(
                    signature.derivation,
                    signature.derivative(),
                    i as u16,
                )),
                None => Err(Error::Generic(
                    "Signature doesn't match any public key".into(),
                )),
            })
            .collect();

        key_config
            .verify(message, &indexed_signatures?)
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

#[test]
pub fn test_inception() -> Result<(), Error> {
    use ed25519_compact::{KeyPair, Seed};
    use keri::derivation::{basic::Basic, self_signing::SelfSigning};
    use keri::event::sections::threshold::SignatureThreshold;
    use tempfile::Builder;

    // Create test db and event processor.
    let db_root = Builder::new().prefix("test-db").tempdir().unwrap();
    // Create two keypairs
    let current_keypair = KeyPair::from_seed(Seed::default());
    let next_keypair = KeyPair::from_seed(Seed::default());

    // Set key configs.
    let key_conig = PublicKeysConfig::new(
        vec![(Basic::Ed25519, current_keypair.pk.to_vec())],
        vec![(Basic::Ed25519, next_keypair.pk.to_vec())],
        SignatureThreshold::Simple(1),
    );
    // Create inception event.
    let inception = KEL::incept(&key_conig)?;
    // Create wrong signature and try to process event.
    let wrong_signature = next_keypair.sk.sign(&inception.serialize()?, None).to_vec();
    let wrong_signature_prefix = SelfSigning::Ed25519Sha512.derive(wrong_signature);
    let controller = KEL::finalize_incept(
        db_root.path().to_str().unwrap(),
        &inception,
        vec![wrong_signature_prefix],
    );
    assert!(matches!(
        controller,
        Err(Error::KeriError(
            keri::error::Error::FaultySignatureVerification
        ))
    ));

    // Create signature and to process event.
    let signature = current_keypair
        .sk
        .sign(&inception.serialize()?, None)
        .to_vec();
    let signature_prefix = SelfSigning::Ed25519Sha512.derive(signature);
    let controller = KEL::finalize_incept(
        db_root.path().to_str().unwrap(),
        &inception,
        vec![signature_prefix],
    );
    assert!(controller.is_ok());

    Ok(())
}
