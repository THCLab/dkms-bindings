use std::convert::TryInto;

use keri::{
    event_message::parse::message,
    prefix::{BasicPrefix, IdentifierPrefix, Prefix, SelfSigningPrefix},
};
use napi::{
    CallContext, Env, JsBoolean, JsBuffer, JsNumber, JsObject, JsString, JsUndefined, Property,
    Result as JsResult,
};
use napi_derive::{js_function, module_exports};
pub mod kel;
use kel::{event_generator::PublicKeysConfig, KEL};
use simple_config_parser::config::Config;

#[module_exports]
pub fn init(mut exports: JsObject, env: Env) -> JsResult<()> {
    let controller_class = env.define_class(
        "Controller",
        load_controller,
        &[
            Property::new(&env, "get_prefix")?.with_method(get_prefix),
            Property::new(&env, "get_kel")?.with_method(get_kel),
            Property::new(&env, "rotate")?.with_method(rotate),
            Property::new(&env, "finalize_rotation")?.with_method(finalize_rotation),
            Property::new(&env, "process")?.with_method(process),
            Property::new(&env, "get_current_public_key")?.with_method(get_current_public_key),
            Property::new(&env, "verify")?.with_method(verify),
        ],
    )?;
    exports.set_named_property("Controller", controller_class)?;
    exports.create_named_method("incept", incept)?;
    exports.create_named_method("finalize_incept", finalize_inception)?;

    Ok(())
}

#[js_function(2)]
fn finalize_inception(ctx: CallContext) -> JsResult<JsString> {
    let icp = ctx.get::<JsBuffer>(0)?.into_value()?.to_vec();
    let signatures = get_signature_array_argument(&ctx, 1)?;
    let mut cfg = Config::new(Some("settings.cfg"));
    // Read / parse config file
    cfg.read().ok().expect("There is no `settings.cfg` file");

    let path_str = cfg.get("db_path").ok_or(napi::Error::from_reason(
        "Missing `db_path` setting in settings.cfg".into(),
    ))?;
    let icp = message(&icp)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?
        .1
        .event_message;
    let kel = KEL::finalize_incept(&path_str, &icp, signatures)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    let identifier = kel.get_prefix().to_str();
    ctx.env.create_string(&identifier)
}

#[js_function(1)]
fn load_controller(ctx: CallContext) -> JsResult<JsUndefined> {
    let prefix = ctx
        .get::<JsString>(0)?
        .into_utf8()
        .map_err(|_e| napi::Error::from_reason("Missing identifier prefix parameter".into()))?
        .as_str()?
        .to_owned();

    let mut cfg = Config::new(Some("settings.cfg"));
    // Read / parse config file
    cfg.read()
        .ok()
        .ok_or(napi::Error::from_reason("Can't read a config file".into()))?;

    let path_str = cfg.get("db_path").ok_or(napi::Error::from_reason(
        "Missing `db_path` setting in settings.cfg".into(),
    ))?;
    let prefix: IdentifierPrefix = prefix.parse().expect("Can't parse signature");
    let kel =
        KEL::load_kel(&path_str, prefix).map_err(|e| napi::Error::from_reason(e.to_string()))?;
    let mut this: JsObject = ctx.this_unchecked();
    ctx.env.wrap(&mut this, kel)?;
    ctx.env.get_undefined()
}

fn get_keys_array_argument(ctx: &CallContext, arg_index: usize) -> JsResult<Vec<BasicPrefix>> {
    let cur = ctx
        .get::<JsObject>(arg_index)
        .map_err(|_e| napi::Error::from_reason("Missing keys parameter".into()))?;
    let len = if cur.is_array()? {
        cur.get_array_length()?
    } else {
        0
    };
    let mut current_keys: Vec<BasicPrefix> = vec![];
    for i in 0..len {
        let val: JsString = cur.get_element(i)?;
        let bp = val
            .into_utf8()?
            .as_str()?
            .parse()
            .map_err(|_e| napi::Error::from_reason("Can't pase public key prefix".into()))?;
        current_keys.push(bp);
    }
    Ok(current_keys)
}

fn get_signature_array_argument(
    ctx: &CallContext,
    arg_index: usize,
) -> JsResult<Vec<SelfSigningPrefix>> {
    let signatures = ctx
        .get::<JsObject>(arg_index)
        .map_err(|_e| napi::Error::from_reason("Missing signatures parameter".into()))?;
    let len = if signatures.is_array()? {
        signatures.get_array_length()?
    } else {
        0
    };
    let mut parsed_signatures: Vec<SelfSigningPrefix> = vec![];
    for i in 0..len {
        let val: JsString = signatures.get_element(i)?;
        let bp = val
            .into_utf8()?
            .as_str()?
            .parse()
            .map_err(|_e| napi::Error::from_reason("Can't parse signature prefix".into()))?;
        parsed_signatures.push(bp);
    }
    Ok(parsed_signatures)
}

#[js_function(2)]
fn incept(ctx: CallContext) -> JsResult<JsBuffer> {
    let current_keys = get_keys_array_argument(&ctx, 0)?;

    let next_keys = get_keys_array_argument(&ctx, 1)?;

    let pub_keys = PublicKeysConfig {
        current: current_keys,
        next: next_keys,
    };
    let icp = KEL::incept(&pub_keys)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?
        .serialize()
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;

    ctx.env.create_buffer_copy(&icp).map(|b| b.into_raw())
}

#[js_function(0)]
fn get_prefix(ctx: CallContext) -> JsResult<JsString> {
    let this: JsObject = ctx.this_unchecked();
    let kel: &KEL = ctx.env.unwrap(&this)?;
    let preifx = kel.get_prefix().to_str();
    ctx.env.create_string(&preifx)
}

#[js_function(0)]
fn get_kel(ctx: CallContext) -> JsResult<JsString> {
    let this: JsObject = ctx.this_unchecked();
    let kel: &KEL = ctx.env.unwrap(&this)?;
    let kel_str = match kel
        .get_kel()
        .map_err(|e| napi::Error::from_reason(e.to_string()))?
    {
        Some(kel) => String::from_utf8(kel).map_err(|e| napi::Error::from_reason(e.to_string()))?,
        None => "".to_owned(),
    };
    ctx.env.create_string(&kel_str)
}

#[js_function(2)]
fn rotate(ctx: CallContext) -> JsResult<JsBuffer> {
    let current_keys = get_keys_array_argument(&ctx, 0)?;

    let next_keys = get_keys_array_argument(&ctx, 1)?;

    let pub_keys = PublicKeysConfig {
        current: current_keys,
        next: next_keys,
    };

    let this: JsObject = ctx.this_unchecked();
    let kel: &mut KEL = ctx.env.unwrap(&this)?;
    let rot_event = kel
        .rotate(&pub_keys)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?
        .serialize()
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    ctx.env.create_buffer_copy(&rot_event).map(|b| b.into_raw())
}

#[js_function(2)]
fn finalize_rotation(ctx: CallContext) -> JsResult<JsBoolean> {
    let rot = ctx
        .get::<JsBuffer>(0)?
        .into_value() //?.to_vec()
        .map_err(|_e| napi::Error::from_reason("Missing rotation event parameter".into()))?
        .to_vec();
    let signatures = get_signature_array_argument(&ctx, 1)?;

    let this: JsObject = ctx.this_unchecked();
    let kel: &KEL = ctx.env.unwrap(&this)?;

    let rot_result = kel.finalize_rotation(rot, signatures);
    ctx.env.get_boolean(rot_result.is_ok())
}

#[js_function(1)]
fn process(ctx: CallContext) -> JsResult<JsUndefined> {
    let stream = ctx
        .get::<JsBuffer>(0)?
        .into_value()
        .map_err(|_e| napi::Error::from_reason("Missing event stream parameter".into()))?
        .to_vec();
    let this: JsObject = ctx.this_unchecked();
    let kel: &KEL = ctx.env.unwrap(&this)?;
    kel.process_stream(&stream)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    ctx.env.get_undefined()
}

#[js_function(1)]
fn get_current_public_key(ctx: CallContext) -> JsResult<JsBuffer> {
    let identifier: String = ctx
        .get::<JsString>(0)?
        .into_utf8()
        .map_err(|_e| napi::Error::from_reason("Missing identifier prefix parameter".into()))?
        .as_str()?
        .to_owned();
    let prefix: IdentifierPrefix = identifier
        .parse()
        .map_err(|_e| napi::Error::from_reason("Wrong identifeir prefix".into()))?;
    let this: JsObject = ctx.this_unchecked();
    let kel: &KEL = ctx.env.unwrap(&this)?;
    let key = kel
        .get_current_public_keys(&prefix)
        .map_err(|_e| napi::Error::from_reason("Wrong identifeir prefix".into()))?
        .ok_or(napi::Error::from_reason(format!("There is no keys for prefix {}", identifier)))?
        // TODO For now assume that there is only one key.
        [0]
    .key
    .clone();
    ctx.env.create_buffer_copy(&key).map(|b| b.into_raw())
}

#[js_function(3)]
fn verify(ctx: CallContext) -> JsResult<JsBoolean> {
    let message = ctx
        .get::<JsBuffer>(0)?
        .into_value()
        .map_err(|_e| napi::Error::from_reason("Missing message parameter".into()))?
        .to_vec();
    let signature = ctx
        .get::<JsString>(1)?
        .into_utf8()
        .map_err(|_e| napi::Error::from_reason("Missing signature parameter".into()))?
        .as_str()?
        .to_owned();
    let identifier: String = ctx
        .get::<JsString>(2)?
        .into_utf8()
        .map_err(|_e| napi::Error::from_reason("Missing identifier prefix parameter".into()))?
        .as_str()?
        .to_owned();
    let this: JsObject = ctx.this_unchecked();
    let kel: &KEL = ctx.env.unwrap(&this)?;
    let prefix = identifier
        .parse()
        .map_err(|_e| napi::Error::from_reason("Wrong identifeir prefix".into()))?;

    let signature: SelfSigningPrefix = signature
        .parse()
        .map_err(|_e| napi::Error::from_reason("Wrong signature prefix".into()))?;

    ctx.env
        .get_boolean(kel.verify(&message, &signature, &prefix).map_err(|e| {
            napi::Error::from_reason(format!("Error while verifing: {}", e.to_string()))
        })?)
}

#[js_function(4)]
fn verify_at_sn(ctx: CallContext) -> JsResult<JsBoolean> {
    let message = ctx
        .get::<JsBuffer>(0)?
        .into_value()
        .map_err(|_e| napi::Error::from_reason("Missing message parameter".into()))?
        .to_vec();
    let signature = ctx
        .get::<JsString>(0)?
        .into_utf8()
        .map_err(|_e| napi::Error::from_reason("Missing signature parameter".into()))?
        .as_str()?
        .to_owned();
    let identifier: String = ctx
        .get::<JsString>(2)?
        .into_utf8()
        .map_err(|_e| napi::Error::from_reason("Missing signature parameter".into()))?
        .as_str()?
        .to_owned();
    let sn: i64 = ctx.get::<JsNumber>(3)?.try_into()?;
    let this: JsObject = ctx.this_unchecked();
    let kel: &KEL = ctx.env.unwrap(&this)?;
    let prefix = identifier
        .parse()
        .map_err(|_e| napi::Error::from_reason("Wrong identifier prefix".into()))?;
    let signature: SelfSigningPrefix = signature
        .parse()
        .map_err(|_e| napi::Error::from_reason("Wrong signature prefix".into()))?;
    ctx.env.get_boolean(
        kel.verify_at_sn(&message, &signature, &prefix, sn as u64)
            .map_err(|e| {
                napi::Error::from_reason(format!("Error while verifing: {}", e.to_string()))
            })?,
    )
}

#[js_function(0)]
fn get_current_sn(ctx: CallContext) -> JsResult<JsNumber> {
    let this: JsObject = ctx.this_unchecked();
    let kel: &KEL = ctx.env.unwrap(&this)?;
    let sn = kel
        .current_sn()
        .map_err(|e| napi::Error::from_reason(format!("Can't get sn: {}", e.to_string())))?;
    ctx.env.create_int64(sn as i64)
}
