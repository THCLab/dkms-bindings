use std::convert::TryInto;

use keri::{
    event_message::parse::message,
    prefix::{
        parse::{self, self_signing_prefix},
        IdentifierPrefix, Prefix,
    },
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
        controller_constructor,
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
    let icp = message(&icp).unwrap().1.event_message;
    let signature = parse::self_signing_prefix(&signature)
        .expect("Can't parse signature")
        .1;
    let kel = KEL::finalize_incept(&path_str, &icp, signature).expect("Error while creating kel");
    let mut this: JsObject = ctx.this_unchecked();
    ctx.env.wrap(&mut this, kel)?;
    ctx.env.get_undefined()
}

#[js_function(2)]
fn incept(ctx: CallContext) -> JsResult<JsBuffer> {
    let current = ctx.get::<JsBuffer>(0)?.into_value()?;
    let next = ctx.get::<JsBuffer>(1)?.into_value()?;

    let pub_keys = PublicKeysConfig {
        current: vec![
            parse::basic_prefix(&current.to_vec())
                .expect("Can't parse key")
                .1,
        ],
        next: vec![
            parse::basic_prefix(&next.to_vec())
                .expect("Can't parse key")
                .1,
        ],
    };
    let icp = KEL::incept(&pub_keys).unwrap().serialize().unwrap();

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
    let kel_str = match kel.get_kel().unwrap() {
        Some(kel) => String::from_utf8(kel).unwrap(),
        None => "".to_owned(),
    };
    ctx.env.create_string(&kel_str)
}

#[js_function(2)]
fn rotate(ctx: CallContext) -> JsResult<JsBuffer> {
    let new_current = ctx.get::<JsBuffer>(0)?.into_value()?;
    let new_next = ctx.get::<JsBuffer>(1)?.into_value()?;

    let pub_keys = PublicKeysConfig {
        current: vec![
            parse::basic_prefix(&new_current.to_vec())
                .expect("Cn't parse key")
                .1,
        ],
        next: vec![
            parse::basic_prefix(&new_next.to_vec())
                .expect("Can't parse key")
                .1,
        ],
    };

    let this: JsObject = ctx.this_unchecked();
    let kel: &mut KEL = ctx.env.unwrap(&this)?;
    let rot_event = kel
        .rotate(&pub_keys)
        .expect("No rotation event")
        .serialize()
        .unwrap();
    ctx.env.create_buffer_copy(&rot_event).map(|b| b.into_raw())
}

#[js_function(2)]
fn finalize_rotation(ctx: CallContext) -> JsResult<JsBoolean> {
    let rot = ctx.get::<JsBuffer>(0)?.into_value()?.to_vec();
    let signature = ctx.get::<JsBuffer>(1)?.into_value()?.to_vec();
    let this: JsObject = ctx.this_unchecked();
    let kel: &KEL = ctx.env.unwrap(&this)?;
    let signature = parse::self_signing_prefix(&signature)
        .expect("Can't parse signature")
        .1;
    let rot_result = kel.finalize_rotation(rot, signature);
    ctx.env.get_boolean(rot_result.is_ok())
}

#[js_function(1)]
fn process(ctx: CallContext) -> JsResult<JsUndefined> {
    let stream = ctx.get::<JsBuffer>(0)?.into_value()?.to_vec();
    let this: JsObject = ctx.this_unchecked();
    let kel: &KEL = ctx.env.unwrap(&this)?;
    kel.process_stream(&stream).expect("Error while processing");
    ctx.env.get_undefined()
}

#[js_function(1)]
fn get_current_public_key(ctx: CallContext) -> JsResult<JsBuffer> {
    let identifier: String = ctx.get::<JsString>(0)?.into_utf8()?.as_str()?.to_owned();
    let prefix: IdentifierPrefix = identifier.parse().expect("Can't parse prefix");
    let this: JsObject = ctx.this_unchecked();
    let kel: &KEL = ctx.env.unwrap(&this)?;
    // TODO For now assume that there is only one key.
    let key = kel
        .get_current_public_keys(&prefix)
        .expect("Error while processing")
        .unwrap()[0]
        .key
        .clone();
    ctx.env.create_buffer_copy(&key).map(|b| b.into_raw())
}

#[js_function(3)]
fn verify(ctx: CallContext) -> JsResult<JsBoolean> {
    let message = ctx.get::<JsBuffer>(0)?.into_value()?.to_vec();
    let signature = ctx.get::<JsBuffer>(1)?.into_value()?.to_vec();
    let identifier: String = ctx.get::<JsString>(2)?.into_utf8()?.as_str()?.to_owned();
    let this: JsObject = ctx.this_unchecked();
    let kel: &KEL = ctx.env.unwrap(&this)?;
    let prefix = identifier.parse().expect("Can't parse prefix");
    let signature = self_signing_prefix(&signature)
        .expect("Can't parse signature")
        .1;
    ctx.env.get_boolean(
        kel.verify(&message, &signature, &prefix)
            .expect("Error while verifing"),
    )
}

#[js_function(4)]
fn verify_at_sn(ctx: CallContext) -> JsResult<JsBoolean> {
    let message = ctx.get::<JsBuffer>(0)?.into_value()?.to_vec();
    let signature = ctx.get::<JsBuffer>(0)?.into_value()?.to_vec();
    let identifier: String = ctx.get::<JsString>(2)?.into_utf8()?.as_str()?.to_owned();
    let sn: i64 = ctx.get::<JsNumber>(3)?.try_into()?;
    let this: JsObject = ctx.this_unchecked();
    let kel: &KEL = ctx.env.unwrap(&this)?;
    let prefix = identifier.parse().expect("Can't parse prefix");
    let signature = self_signing_prefix(&signature)
        .expect("Can't parse signature")
        .1;
    ctx.env.get_boolean(
        kel.verify_at_sn(&message, &signature, &prefix, sn as u64)
            .expect("Error while verifing"),
    )
}

#[js_function(0)]
fn get_current_sn(ctx: CallContext) -> JsResult<JsNumber> {
    let this: JsObject = ctx.this_unchecked();
    let kel: &KEL = ctx.env.unwrap(&this)?;
    let sn = kel.current_sn().expect("Can't get sn");
    ctx.env.create_int64(sn as i64)
}
