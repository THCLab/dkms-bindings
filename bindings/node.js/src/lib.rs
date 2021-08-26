use std::{collections::HashMap, convert::TryInto, path::Path};

use keri::{
    derivation::{basic::Basic, self_signing::SelfSigning},
    event_message::parse::message,
    prefix::{AttachedSignaturePrefix, IdentifierPrefix, Prefix},
    signer::{CryptoBox, KeyManager},
};
use napi::{
    CallContext, Env, JsBoolean, JsBuffer, JsNumber, JsObject, JsString, JsUndefined, Property,
    Result as JsResult,
};
use napi_derive::{js_function, module_exports};
pub mod kel;
use base64::{self, URL_SAFE};
use kel::{
    error::Error,
    event_generator::{Key, PublicKeysConfig},
    KEL,
};
use simple_config_parser::config::Config;

pub struct Controller {
    kel: KEL,
}

impl Controller {
    pub fn get_prefix(&self) -> String {
        self.kel.get_prefix().to_str()
    }

    /// Returns own key event log of controller.
    pub fn get_kel(&self) -> Result<String, Error> {
        Ok(String::from_utf8(
            self.kel
                .get_kel()?
                .ok_or(Error::Generic("There is no kel".into()))?,
        )?)
    }

    /// Returns key event log of controller of given prefix.
    /// (Only if controller "knows" the identity of given prefix. It can be out of
    /// date kel if controller didn't get most recent events yet.)
    pub fn get_kel_for_prefix(&self, prefix: &str) -> Result<String, Error> {
        let prefix = prefix.parse()?;
        Ok(String::from_utf8(
            self.kel
                .get_kel_for_prefix(&prefix)?
                .ok_or(Error::Generic("There is no kel".into()))?,
        )?)
    }

    pub fn rotate(&self, keys: PublicKeysConfig) -> Result<Vec<u8>, Error> {
        let rot = self.kel.rotate(&keys);
        Ok(rot?.serialize()?)
    }

    pub fn current_sn(&self) -> Result<u64, Error> {
        Ok(self.kel.get_state()?.unwrap().sn)
    }

    /// Process incoming events stream
    ///
    /// Parses stream of events, checks them and adds to database
    /// # Arguments
    ///
    /// * `stream` - Bytes of serialized events stream
    pub fn process(&self, stream: &[u8]) -> Result<(), Error> {
        self.kel.process_stream(stream)
    }

    pub fn get_current_public_keys(
        &self,
        prefix: &IdentifierPrefix,
    ) -> Result<Option<Vec<Key>>, Error> {
        let keys = self.kel.get_state_for_prefix(prefix)?.map(|state| {
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
    /// Checks if message matches signature made by controller of given prefix.
    /// # Arguments
    ///
    /// * `message` - Bytes of message
    /// * `signature` - A string slice that holds the signature in base64
    /// * `prefix` - A string slice that holds the prefix of signer
    pub fn verify(&self, message: &[u8], signature: &str, prefix: &str) -> Result<bool, Error> {
        let prefix = prefix.parse()?;
        let signature = base64::decode_config(signature, URL_SAFE)?;
        let key_conf = self
            .kel
            .get_state_for_prefix(&prefix)?
            .ok_or(Error::Generic("There is no state".into()))?
            .current;
        let sigs = vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature.to_vec(),
            0,
        )];
        key_conf
            .verify(message, &sigs)
            .map_err(|e| Error::Generic(e.to_string()))
    }

    /// Verify signature of given message using keys at `sn`
    ///
    /// Checks if message matches signature made by controller of given prefix
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
        signature: &str,
        prefix: &str,
        sn: u64,
    ) -> Result<bool, Error> {
        let pref = prefix.parse()?;
        let signature = base64::decode_config(signature, URL_SAFE)?;
        let key_conf = self
            .kel
            .get_keys_at_sn(&pref, sn)?
            .ok_or(Error::Generic(format!(
                "There are no key config fo identifier {} at {}",
                prefix, sn
            )))?;
        let sigs = vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature.to_vec(),
            0,
        )];
        key_conf
            .verify(message, &sigs)
            .map_err(|e| Error::Generic(e.to_string()))
    }
}

#[module_exports]
pub fn init(mut exports: JsObject, env: Env) -> JsResult<()> {
    let controller_class = env.define_class(
        "Controller",
        controller_constructor,
        &[
            Property::new(&env, "get_prefix")?.with_method(get_prefix),
            Property::new(&env, "get_kel")?.with_method(get_kel),
            Property::new(&env, "rotate")?.with_method(rotate),
            Property::new(&env, "finalize_rotation")?.with_method(finalize_rotation),
            Property::new(&env, "process")?.with_method(process),
            Property::new(&env, "get_current_public_key")?.with_method(get_current_public_key),
        ],
    )?;
    exports.set_named_property("Controller", controller_class)?;
    exports.create_named_method("incept", incept)?;

    Ok(())
}

#[js_function(2)]
fn controller_constructor(ctx: CallContext) -> JsResult<JsUndefined> {
    let icp = ctx.get::<JsBuffer>(0)?.into_value()?.to_vec();
    let signature = ctx.get::<JsBuffer>(1)?.into_value()?.to_vec();
    let mut cfg = Config::new(Some("settings.cfg"));
    // Read / parse config file
    cfg.read().ok().expect("Error reading the config file");

    let path_str = cfg
        .get("db_path")
        .expect("Missing database path in settings");
    let icp = message(&icp).unwrap().1.event;
    let kel = KEL::finalize_incept(&path_str, icp, signature).expect("Error while creating kel");
    let mut this: JsObject = ctx.this_unchecked();
    ctx.env.wrap(&mut this, Controller { kel })?;
    ctx.env.get_undefined()
}

#[js_function(2)]
fn incept(ctx: CallContext) -> JsResult<JsBuffer> {
    let current = ctx.get::<JsBuffer>(0)?.into_value()?;
    let next = ctx.get::<JsBuffer>(1)?.into_value()?;

    let pub_keys = PublicKeysConfig::new(
        vec![(Basic::Ed25519, current.to_vec())],
        vec![(Basic::Ed25519, next.to_vec())],
    );
    let icp = KEL::incept(&pub_keys).unwrap().serialize().unwrap();

    ctx.env.create_buffer_copy(&icp).map(|b| b.into_raw())
}

#[js_function(0)]
fn get_prefix(ctx: CallContext) -> JsResult<JsString> {
    let this: JsObject = ctx.this_unchecked();
    let native_class: &mut Controller = ctx.env.unwrap(&this)?;
    let preifx = native_class.get_prefix();
    ctx.env.create_string(&preifx)
}

#[js_function(0)]
fn get_kel(ctx: CallContext) -> JsResult<JsString> {
    let this: JsObject = ctx.this_unchecked();
    let native_class: &Controller = ctx.env.unwrap(&this)?;
    ctx.env.create_string(&native_class.get_kel().unwrap())
}

#[js_function(2)]
fn rotate(ctx: CallContext) -> JsResult<JsBuffer> {
    let new_current = ctx.get::<JsBuffer>(0)?.into_value()?;
    let new_next = ctx.get::<JsBuffer>(1)?.into_value()?;

    let pub_keys = PublicKeysConfig::new(
        vec![(Basic::Ed25519, new_current.to_vec())],
        vec![(Basic::Ed25519, new_next.to_vec())],
    );

    let this: JsObject = ctx.this_unchecked();
    let controller: &mut Controller = ctx.env.unwrap(&this)?;
    let rot_event = controller.rotate(pub_keys).expect("No rotation event");
    ctx.env.create_buffer_copy(&rot_event).map(|b| b.into_raw())
}

#[js_function(2)]
fn finalize_rotation(ctx: CallContext) -> JsResult<JsBoolean> {
    let rot = ctx.get::<JsBuffer>(0)?.into_value()?.to_vec();
    let signature = ctx.get::<JsBuffer>(1)?.into_value()?.to_vec();
    let this: JsObject = ctx.this_unchecked();
    let controller: &mut Controller = ctx.env.unwrap(&this)?;
    let rot_result = controller.kel.finalize_rotate(rot, signature);
    ctx.env.get_boolean(rot_result.is_ok())
}

#[js_function(1)]
fn process(ctx: CallContext) -> JsResult<JsUndefined> {
    let stream = ctx.get::<JsBuffer>(0)?.into_value()?.to_vec();
    let this: JsObject = ctx.this_unchecked();
    let controller: &mut Controller = ctx.env.unwrap(&this)?;
    controller.process(&stream).expect("Error while processing");
    ctx.env.get_undefined()
}

#[js_function(1)]
fn get_current_public_key(ctx: CallContext) -> JsResult<JsBuffer> {
    let identifier: String = ctx.get::<JsString>(2)?.into_utf8()?.as_str()?.to_owned();
    let prefix: IdentifierPrefix = identifier.parse().unwrap();
    let this: JsObject = ctx.this_unchecked();
    let controller: &mut Controller = ctx.env.unwrap(&this)?;
    // TODO For now assume that there is only one key.
    let key = controller.get_current_public_keys(&prefix).expect("Error while processing").unwrap()[0].key.clone();
    ctx.env.create_buffer_copy(&key).map(|b| b.into_raw())
}

#[js_function(3)]
fn verify(ctx: CallContext) -> JsResult<JsBoolean> {
    let message: String = ctx.get::<JsString>(0)?.into_utf8()?.as_str()?.to_owned();
    let signature: String = ctx.get::<JsString>(1)?.into_utf8()?.as_str()?.to_owned();
    let identifier: String = ctx.get::<JsString>(2)?.into_utf8()?.as_str()?.to_owned();
    let this: JsObject = ctx.this_unchecked();
    let native_class: &mut Controller = ctx.env.unwrap(&this)?;
    ctx.env.get_boolean(native_class.verify(&message.as_bytes(), &signature, &identifier).expect("Error while verifing"))
}

#[js_function(4)]
fn verify_at_sn(ctx: CallContext) -> JsResult<JsBoolean> {
    let message: String = ctx.get::<JsString>(0)?.into_utf8()?.as_str()?.to_owned();
    let signature: String = ctx.get::<JsString>(1)?.into_utf8()?.as_str()?.to_owned();
    let identifier: String = ctx.get::<JsString>(2)?.into_utf8()?.as_str()?.to_owned();
    let sn :i64 = ctx.get::<JsNumber>(3)?.try_into()?;
    let this: JsObject = ctx.this_unchecked();
    let native_class: &mut Controller = ctx.env.unwrap(&this)?;
    ctx.env.get_boolean(native_class.verify_at_sn(&message.as_bytes(), &signature, &identifier, sn as u64).expect("Error while verifing"))
}

#[js_function(0)]
fn get_current_sn(ctx: CallContext) -> JsResult<JsNumber> {
    let this: JsObject = ctx.this_unchecked();
    let controller: &mut Controller = ctx.env.unwrap(&this)?;
    let sn = controller.current_sn().expect("Can't get sn");
    ctx.env.create_int64(sn as i64)
}
