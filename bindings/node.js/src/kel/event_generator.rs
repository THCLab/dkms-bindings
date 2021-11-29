use super::error::Error;
use keri::{
    derivation::{basic::Basic, self_addressing::SelfAddressing},
    event::{
        event_data::{EventData, Receipt},
        sections::{
            seal::{DigestSeal, EventSeal, Seal},
            threshold::SignatureThreshold,
        },
        Event, EventMessage, SerializationFormats,
    },
    event_message::event_msg_builder::{EventMsgBuilder, EventType},
    prefix::{BasicPrefix, SelfAddressingPrefix},
    state::IdentifierState,
};

pub struct Key {
    pub key_type: Basic,
    pub key: Vec<u8>,
}

pub struct PublicKeysConfig {
    pub current: Vec<BasicPrefix>,
    pub next: Vec<BasicPrefix>,
    pub current_threshold: SignatureThreshold,
    pub next_threshold: SignatureThreshold,
}

impl PublicKeysConfig {
    pub fn new(
        current: Vec<(Basic, Vec<u8>)>,
        next: Vec<(Basic, Vec<u8>)>,
        current_threshold: SignatureThreshold,
        next_threshold: SignatureThreshold,
    ) -> PublicKeysConfig {
        let current = current
            .into_iter()
            .map(|(der, key)| Key { key_type: der, key }.derive())
            .collect();
        let next = next
            .into_iter()
            .map(|(der, key)| Key { key_type: der, key }.derive())
            .collect();
        PublicKeysConfig {
            current,
            next,
            current_threshold,
            next_threshold,
        }
    }

    pub fn rotate(
        &self,
        new_next_keys: Vec<(Basic, Vec<u8>)>,
        new_next_threshold: SignatureThreshold,
    ) -> PublicKeysConfig {
        let new_next = new_next_keys
            .into_iter()
            .map(|(der, key)| (Key { key_type: der, key }.derive()))
            .collect();
        PublicKeysConfig {
            current: self.next.clone(),
            next: new_next,
            current_threshold: self.next_threshold.clone(),
            next_threshold: new_next_threshold,
        }
    }
}

impl Key {
    pub fn derive(&self) -> BasicPrefix {
        self.key_type
            .derive(keri::keys::PublicKey::new(self.key.clone()))
    }
}

pub fn make_icp(keys: &PublicKeysConfig) -> Result<EventMessage, Error> {
    let icp = EventMsgBuilder::new(EventType::Inception)
        .with_keys(keys.current.clone())
        .with_next_keys(keys.next.clone())
        .with_threshold(&keys.current_threshold.clone())
        .with_next_threshold(&keys.next_threshold.clone())
        .build()?;
    Ok(icp)
}

pub fn make_rot(keys: &PublicKeysConfig, state: IdentifierState) -> Result<EventMessage, Error> {
    let ixn = EventMsgBuilder::new(EventType::Rotation)
        .with_prefix(&state.prefix)
        .with_sn(state.sn + 1)
        .with_previous_event(&SelfAddressing::Blake3_256.derive(&state.last))
        .with_keys(keys.current.clone())
        .with_next_keys(keys.next.clone())
        .with_threshold(&keys.current_threshold.clone())
        .with_next_threshold(&keys.next_threshold.clone())
        .build()?;
    Ok(ixn)
}

pub fn make_ixn(
    payload: &[SelfAddressingPrefix],
    state: IdentifierState,
) -> Result<EventMessage, Error> {
    let seal_list = payload
        .iter()
        .map(|seal| {
            Seal::Digest(DigestSeal {
                dig: seal.to_owned(),
            })
        })
        .collect();
    let ev = EventMsgBuilder::new(EventType::Interaction)
        .with_prefix(&state.prefix)
        .with_sn(state.sn + 1)
        .with_previous_event(&SelfAddressing::Blake3_256.derive(&state.last))
        .with_seal(seal_list)
        .build()?;
    Ok(ev)
}

pub fn make_ixn_with_seal(
    seal_list: &[Seal],
    state: IdentifierState,
) -> Result<EventMessage, Error> {
    let ev = EventMsgBuilder::new(EventType::Interaction)
        .with_prefix(&state.prefix)
        .with_sn(state.sn + 1)
        .with_previous_event(&SelfAddressing::Blake3_256.derive(&state.last))
        .with_seal(seal_list.to_owned())
        .build()?;
    Ok(ev)
}

pub fn make_rct(
    event: EventMessage,
    _validator_seal: EventSeal,
    _state: IdentifierState,
) -> Result<EventMessage, Error> {
    let ser = event.serialize()?;
    let rcp = Event {
        prefix: event.event.prefix,
        sn: event.event.sn,
        event_data: EventData::Rct(Receipt {
            receipted_event_digest: SelfAddressing::Blake3_256.derive(&ser),
        }),
    }
    .to_message(SerializationFormats::JSON)?;
    Ok(rcp)
}
