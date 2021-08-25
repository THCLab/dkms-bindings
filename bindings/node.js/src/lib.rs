use std::{collections::HashMap, convert::TryInto, path::Path};

use keri::{
    derivation::self_signing::SelfSigning,
    prefix::{AttachedSignaturePrefix, Prefix},
    signer::{CryptoBox, KeyManager},
};
use napi::{CallContext, JsBoolean, JsNumber, JsObject, JsString, JsUndefined, Property, Result as JsResult};
use napi_derive::{js_function, module_exports};
pub mod kel;
use base64::{self, URL_SAFE};
use kel::{error::Error, KEL};

pub struct Controller {
    km: CryptoBox,
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

    pub fn rotate(&mut self) -> Result<String, Error> {
        self.km.rotate()?;
        let rot = self.kel.rotate(&self.km);
        Ok(String::from_utf8(rot?.serialize()?)?)
    }

    /// Sign given message
    ///
    /// Returns signature encoded in base64
    /// # Arguments
    ///
    /// * `message` - Bytes of message that will be signed
    pub fn sign(&self, message: &Vec<u8>) -> Result<String, Error> {
        Ok(base64::encode_config(self.km.sign(message)?, URL_SAFE))
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
    pub fn verify_at_sn(&self, message: &[u8], signature: &str, prefix: &str, sn: u64) -> Result<bool, Error> {
        let pref = prefix.parse()?;
        let signature = base64::decode_config(signature, URL_SAFE)?;
        let key_conf = self
            .kel
            .get_keys_at_sn(&pref, sn)?.ok_or(Error::Generic(format!("There are no key config fo identifier {} at {}", prefix, sn)))?;
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

#[js_function(1)]
fn controller_constructor(ctx: CallContext) -> JsResult<JsUndefined> {
    let mut settings = config::Config::default();
    settings
        // Get settings from `./Settings.toml`
        .merge(config::File::with_name("Settings")).unwrap();

    let settings = settings.try_into::<HashMap<String, String>>().unwrap();
    let path_str = settings.get("db_path").expect("Missing database path in settings");
    let mut kel = KEL::new(path_str).expect("Error while creating kel");
    let km = CryptoBox::new().expect("Error while generating keys");
    kel.incept(&km).expect("Error while creating inception event");
    let mut this: JsObject = ctx.this_unchecked();
    ctx
      .env
      .wrap(&mut this, Controller {km, kel})?;
    ctx.env.get_undefined()
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

#[js_function(0)]
fn rotate(ctx: CallContext) -> JsResult<JsString> {
    let this: JsObject = ctx.this_unchecked();
    let native_class: &mut Controller = ctx.env.unwrap(&this)?;
    let rot_event = native_class.rotate().expect("No rotation event");
    ctx.env.create_string(&rot_event)
}

#[js_function(1)]
fn sign(ctx: CallContext) -> JsResult<JsString> {
    let message: String = ctx.get::<JsString>(0)?.into_utf8()?.as_str()?.to_owned();
    let this: JsObject = ctx.this_unchecked();
    let native_class: &mut Controller = ctx.env.unwrap(&this)?;
    let signature = native_class.sign(&message.as_bytes().to_vec()).expect("Error while signing");
    ctx.env.create_string(&signature)
}

#[js_function(1)]
fn process(ctx: CallContext) -> JsResult<JsUndefined> {
    let stream: String = ctx.get::<JsString>(0)?.into_utf8()?.as_str()?.to_owned();
    let this: JsObject = ctx.this_unchecked();
    let native_class: &mut Controller = ctx.env.unwrap(&this)?;
    native_class.process(&stream.as_bytes()).expect("Error while processing");
    ctx.env.get_undefined()
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
    let native_class: &mut Controller = ctx.env.unwrap(&this)?;
    let sn = native_class.current_sn().expect("Can't get sn");
    ctx.env.create_int64(sn as i64)
}

#[js_function(0)]
fn new_controller(ctx: CallContext) -> JsResult<JsObject> {
  let get_prefix_method = Property::new(ctx.env, "get_prefix")?.with_method(get_prefix);
  let get_kel_method = Property::new(ctx.env, "get_kel")?.with_method(get_kel);
  let rotate_method = Property::new(ctx.env, "rotate")?.with_method(rotate);
  let sign_method = Property::new(ctx.env, "sign")?.with_method(sign);
  let process_method = Property::new(ctx.env, "process")?.with_method(process);
  let verify_method = Property::new(ctx.env, "verify")?.with_method(verify);
  let verify_at_sn_method = Property::new(ctx.env, "verify_at_sn")?.with_method(verify_at_sn);
  let current_sn_method = Property::new(ctx.env, "get_current_sn")?.with_method(get_current_sn);

  let properties = vec![get_prefix_method, get_kel_method, rotate_method, sign_method, process_method, verify_method, verify_at_sn_method, current_sn_method];
  let test_class =
    ctx
      .env
      .define_class("Controller", controller_constructor, properties.as_slice())?;

  test_class.new(&[ctx.env.create_int32(42)?])
}

#[module_exports]
fn init(mut exports: JsObject) -> JsResult<()> {
  exports.create_named_method("Controller", new_controller)?;
  Ok(())
}

