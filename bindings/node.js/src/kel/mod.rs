use std::{
    fmt::{self, Debug},
    path::Path,
};

use keri::{
    database::sled::SledEventDatabase,
    event::{
        event_data::EventData,
        sections::{seal::Seal, KeyConfig},
        EventMessage,
    },
    event_message::parse::signed_message,
    event_message::parse::{self, message, signed_event_stream, Deserialized},
    event_message::SignedEventMessage,
    prefix::AttachedSignaturePrefix,
    prefix::{BasicPrefix, IdentifierPrefix, Prefix, SelfAddressingPrefix, SelfSigningPrefix},
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
            String::from_utf8(self.get_kel().map_err(|_e| fmt::Error)?.unwrap_or_default())
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
        let message = message(event).unwrap().1.event_message;
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
            .map(|event| processor.process(event.clone()).map(|_| event))
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
        KEL::finalize_event(database.as_ref(), icp, &signatures, &pub_keys)?;
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
    ) -> Result<bool, Error> {
        let (_rest, rot_event) =
            message(&rotation).map_err(|_e| Error::Generic("Invalid rotation event".into()))?;

        let pub_keys = match rot_event.event_message.event.event_data {
            keri::event::event_data::EventData::Rot(ref rot) => {
                Ok(rot.key_config.public_keys.to_owned())
            }
            _ => Err(Error::Generic("Improper event type".into())),
        }?;

        KEL::finalize_event(
            self.database.as_ref(),
            &rot_event.event_message,
            &signatures,
            &pub_keys,
        )
    }

    pub fn anchor(&self, payload: &[SelfAddressingPrefix]) -> Result<EventMessage, Error> {
        event_generator::make_ixn(payload, self.get_state()?.unwrap())
    }

    pub fn finalize_anchor(
        &self,
        ixn: Vec<u8>,
        signatures: Vec<SelfSigningPrefix>,
    ) -> Result<bool, Error> {
        let (_rest, ixn_event) = message(&ixn).map_err(|_e| Error::Generic("Invalid interaction event".into()))?;
        let pub_keys = self
            .get_state()?
            .ok_or(Error::NoPublicKeys)?
            .current
            .public_keys;

        KEL::finalize_event(
            self.database.as_ref(),
            &ixn_event.event_message,
            &signatures,
            &pub_keys,
        )
    }

    pub fn is_anchored(&self, sai: SelfAddressingPrefix) -> Result<bool, Error> {
        let kel = self.get_kel()?.unwrap();
        let parsed_kel = parse::signed_event_stream(&kel).unwrap().1;
        Ok(parsed_kel.iter().any(|des| match des {
            Deserialized::Event(ev) => match ev.deserialized_event.event_message.event.event_data {
                EventData::Ixn(ref ixn) => ixn.data.iter().any(|seal| match seal {
                    Seal::Digest(dig) => dig.dig == sai,
                    _ => false,
                }),
                _ => false,
            },
            _ => false,
        }))
    }

    fn find_signatures_indexes(
        msg: &[u8],
        signatures: &[SelfSigningPrefix],
        pub_keys: &[BasicPrefix],
    ) -> Result<(Vec<AttachedSignaturePrefix>, Vec<Error>), Error> {
        let (found_indexes, not_found_indexes): (Vec<Result<AttachedSignaturePrefix, Error>>, _) =
            signatures
                .iter()
                .map(|signature| {
                    // make tuples (Option<index>, signature)
                    (
                        pub_keys
                            .iter()
                            .position(|x| x.verify(msg, signature).unwrap_or(false)),
                        signature,
                    )
                })
                .map(|(index, signature)| -> Result<_, Error> {
                    Ok(AttachedSignaturePrefix::new(
                        signature.derivation,
                        signature.derivative(),
                        index.ok_or(Error::KeyNotFound)? as u16,
                    ))
                })
                .partition(Result::is_ok);
        let signatures: Vec<AttachedSignaturePrefix> =
            found_indexes.into_iter().map(Result::unwrap).collect();
        let errors = not_found_indexes
            .into_iter()
            .map(|e| e.unwrap_err())
            .collect();
        Ok((signatures, errors))
    }

    fn finalize_event(
        db: Option<&SledEventDatabase>,
        event: &EventMessage,
        signatures_list: &[SelfSigningPrefix],
        current_pub_keys: &[BasicPrefix],
    ) -> Result<bool, Error> {
        let (signatures, errors) =
            KEL::find_signatures_indexes(&event.serialize()?, signatures_list, current_pub_keys)?;
        let signed_event = event.sign(signatures);

        let processor = match db {
            Some(db) => Ok(EventProcessor::new(db)),
            None => Err(Error::NoDatabase),
        }?;
        // TODO avoid unwrap
        match processor.process(signed_message(&signed_event.serialize()?).unwrap().1) {
            Ok(_) => Ok(true),
            Err(keri::error::Error::NotEnoughSigsError) => {
                if !errors.is_empty() {
                    Err(Error::Generic(
                        "Not enough signatures. Some signatures don't match identifier public keys"
                            .into(),
                    ))
                } else {
                    Err(Error::NotEnoughSignatures)
                }
            }
            Err(e) => Err(e.into()),
        }
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
            .map_err(Error::KeriError)
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
        Ok(processor.get_kerl(&self.prefix)?)
    }

    /// Returns key event log of given prefix.
    /// (Only if database contains kel of given prefix. It can be out of
    /// date if most recent events weren't processed yet)
    pub fn get_kel_for_prefix(&self, prefix: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Error> {
        let processor = match self.database {
            Some(ref db) => Ok(EventProcessor::new(db)),
            None => Err(Error::NoDatabase),
        }?;
        processor.get_kerl(prefix).map_err(Error::KeriError)
    }

    pub fn get_state_for_prefix(
        &self,
        prefix: &IdentifierPrefix,
    ) -> Result<Option<IdentifierState>, Error> {
        let processor = match self.database {
            Some(ref db) => Ok(EventProcessor::new(db)),
            None => Err(Error::NoDatabase),
        }?;
        processor.compute_state(prefix).map_err(Error::KeriError)
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
            .compute_state_at_sn(prefix, sn)
            .map_err(Error::KeriError)?
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
            .get_state_for_prefix(prefix)?
            .ok_or_else(|| Error::Generic("There is no state".into()))?
            .current;

        let indexed_signatures: Result<Vec<AttachedSignaturePrefix>, _> = signatures
            .iter()
            .map(|signature| {
                (
                    key_config
                        .public_keys
                        .iter()
                        .position(|x| x.verify(message, signature).unwrap()),
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
        let key_conf = self.get_keys_at_sn(prefix, sn)?.ok_or_else(|| {
            Error::Generic(format!(
                "There are no key config fo identifier {} at {}",
                prefix.to_str(),
                sn
            ))
        })?;
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
