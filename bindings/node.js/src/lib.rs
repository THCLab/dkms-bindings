use std::convert::TryInto;

use utils::PublicKeysConfig;
use keriox_wrapper::kel::{Kel, Identifier, SignaturePrefix, KeyPrefix, Threshold, SAI};
use napi::{
    CallContext, Env, JsBoolean, JsBuffer, JsNumber, JsObject, JsString, JsUndefined, JsUnknown,
    Property, Result as JsResult,
};
use napi_derive::{js_function, module_exports};
pub mod utils;
use simple_config_parser::config::Config;

#[module_exports]
pub fn init(mut exports: JsObject, env: Env) -> JsResult<()> {
    let controller_class = env.define_class(
        "Controller",
        load_controller,
        &[
            // Property::new("get_prefix")?.with_method(get_prefix),
            Property::new("get_kel")?.with_method(get_kel),
            // Property::new("get_kel_for_prefix")?.with_method(get_kel_for_prefix),
            Property::new("incept")?.with_method(incept),
            Property::new("rotate")?.with_method(rotate),
            Property::new("finalize_rotation")?.with_method(finalize_rotation),
            // Property::new("anchor")?.with_method(anchor),
            // Property::new("finalize_anchor")?.with_method(finalize_anchor),
            Property::new("process")?.with_method(process),
            // Property::new("get_current_public_key")?.with_method(get_current_public_key),
            // Property::new("verify")?.with_method(verify),
            // Property::new("is_anchored")?.with_method(is_anchored),
        ],
    )?;
    exports.set_named_property("Controller", controller_class)?;
    exports.create_named_method("finalize_incept", finalize_inception)?;

    Ok(())
}



#[js_function(1)]
fn load_controller(ctx: CallContext) -> JsResult<JsUndefined> {
    // Read / parse config file
    let mut cfg = Config::new(Some("settings.cfg"));
    cfg.read()
        .ok()
        .ok_or_else(|| napi::Error::from_reason("Can't read a config file"))?;
    let path_str = cfg.get("db_path").ok_or_else(|| {
        napi::Error::from_reason("Missing `db_path` setting in settings.cfg")
    })?;


    let kel = match ctx.get::<JsString>(0)?.into_utf8() {
        Ok(pref_str) => {
            let prefix = pref_str.as_str()?.to_owned();

            let prefix: Identifier = prefix.parse().expect("Can't parse signature");
            Kel::load_kel(&path_str, prefix).map_err(|e| napi::Error::from_reason(e.to_string()))?
        }
        Err(_err) => {
            // If there's no arguments, return empty kel
            Kel::init(&path_str)
        }
    };

    let mut this: JsObject = ctx.this_unchecked();
    ctx.env.wrap(&mut this, kel)?;
    ctx.env.get_undefined()
}

fn get_keys_settings_argument(
    key_object: JsObject,
) -> JsResult<(
    Option<KeyPrefix>,
    Option<KeyPrefix>,
    Option<String>,
    Option<String>,
)> {
    let curr_pk: Option<KeyPrefix> = get_key(&key_object, 0)?;
    let next_pk: Option<KeyPrefix> = get_key(&key_object, 1)?;
    let current_threshold = match key_object.get_element::<JsString>(2) {
        Ok(t) => Some(t.into_utf8()?.as_str()?.to_string()),
        Err(_) => None,
    };
    let next_threshold = match key_object.get_element::<JsString>(3) {
        Ok(t) => Some(t.into_utf8()?.as_str()?.to_string()),
        Err(_) => None,
    };

    Ok((curr_pk, next_pk, current_threshold, next_threshold))
}

fn get_key(key_object: &JsObject, index: u32) -> JsResult<Option<KeyPrefix>> {
    Ok(match key_object.get_element::<JsString>(index) {
        Ok(pk) => Some(
            pk.into_utf8()?
                .as_str()?
                .parse()
                .map_err(|_e| napi::Error::from_reason("Can't parse public key prefix"))?,
        ),
        Err(_) => match key_object.get_element::<JsUnknown>(index)?.get_type()? {
            napi::ValueType::Null => None,
            _ => {
                return Err(napi::Error::from_reason(
                    "Missing public key argument",
                ))
            }
        },
    })
}

fn get_keys_array_argument(ctx: &CallContext, arg_index: usize) -> JsResult<PublicKeysConfig> {
    let cur = ctx
        .get::<JsObject>(arg_index)
        .map_err(|_e| napi::Error::from_reason("Missing keys parameter"))?;
    let len = if cur.is_array()? {
        cur.get_array_length()?
    } else {
        0
    };
    let mut current: Vec<KeyPrefix> = vec![];
    let mut next: Vec<KeyPrefix> = vec![];
    let mut current_thresholds: Vec<Option<String>> = vec![];
    let mut next_thresholds: Vec<Option<String>> = vec![];
    for i in 0..len {
        let val: JsObject = cur.get_element(i)?;
        let (cur, nxt, current_threshold, next_threshold) = get_keys_settings_argument(val)?;
        match cur {
            Some(key) => current.push(key),
            None => (),
        };
        match nxt {
            Some(key) => next.push(key),
            None => (),
        };
        current_thresholds.push(current_threshold);
        next_thresholds.push(next_threshold);
    }

    let current_threshold = set_threshold(ctx, current_thresholds)?;
    let next_threshold = set_threshold(ctx, next_thresholds)?;
    Ok(PublicKeysConfig {
        current,
        next,
        current_threshold,
        next_threshold,
    })
}

fn set_threshold(ctx: &CallContext, thres: Vec<Option<String>>) -> JsResult<Threshold> {
    Ok(if thres.iter().any(|t| t.is_none()) {
        // Any key has no weighted threshold set.
        let threshold: JsResult<i32> = ctx.get::<JsNumber>(1)?.try_into();
        match threshold {
            Ok(threshold) => Threshold::simple(threshold as u64),
            Err(_) => {
                // Set default threshold if not provided
                Threshold::simple(1)
            }
        }
    } else {
        // All keys has weighted threshold set. Or at least should.
        // If not, error is returned.
        let thres: JsResult<Vec<(u64, u64)>> = thres
            .into_iter()
            .map(|t| {
                t.ok_or_else(|| napi::Error::from_reason("Missing threshold settings"))
            })
            .map(|t| -> JsResult<_> {
                let unwrapped_t = t?;
                parse_weighted_threshold(unwrapped_t)
            })
            .collect();

        Threshold::single_weighted(thres?)
    })
}

fn parse_weighted_threshold(threshold: String) -> JsResult<(u64, u64)> {
    let mut split = threshold.split('/');

    let fraction_tuple: (Option<JsResult<u64>>, Option<JsResult<u64>>) = (
        split.next().map(|numerator| -> JsResult<_> {
            numerator.parse().map_err(|_e| {
                napi::Error::from_reason("Wrong threshold format. Can't parse numerator")
            })
        }),
        split.next().map(|denominator| {
            denominator.parse().map_err(|_e| {
                napi::Error::from_reason("Wrong threshold format. Can't parse denominator")
            })
        }),
    );
    match fraction_tuple {
        (Some(num), Some(den)) => {
            let numerator = num?;
            let denominator = den?;
            if numerator > denominator {
                Err(napi::Error::from_reason(
                    "Wrong fraction. Should be not greater than 1",
                ))
            } else {
                Ok((numerator, denominator))
            }
        }
        (Some(num), None) => {
            let numerator = num?;
            if numerator > 1 {
                Err(napi::Error::from_reason(
                    "Wrong fraction. Should be not greater than 1",
                ))
            } else {
                Ok((numerator, 1))
            }
        }
        _ => Err(napi::Error::from_reason(
            "Wrong threshold format. Should be fraction",
        )),
    }
}

fn get_signature_array_argument(
    ctx: &CallContext,
    arg_index: usize,
) -> JsResult<Vec<SignaturePrefix>> {
    let signatures = ctx
        .get::<JsObject>(arg_index)
        .map_err(|_e| napi::Error::from_reason("Missing signatures parameter"))?;
    let len = if signatures.is_array()? {
        signatures.get_array_length()?
    } else {
        0
    };
    let mut parsed_signatures: Vec<SignaturePrefix> = vec![];
    for i in 0..len {
        let val: JsString = signatures.get_element(i)?;
        let bp = val
            .into_utf8()?
            .as_str()?
            .parse()
            .map_err(|_e| napi::Error::from_reason("Can't parse signature prefix"))?;
        parsed_signatures.push(bp);
    }
    Ok(parsed_signatures)
}

fn get_sai_array_argument(
    ctx: &CallContext,
    arg_index: usize,
) -> JsResult<Vec<SAI>> {
    let sai = ctx
        .get::<JsObject>(arg_index)
        .map_err(|_e| napi::Error::from_reason("Missing sai parameter"))?;
    let len = if sai.is_array()? {
        sai.get_array_length()?
    } else {
        0
    };
    let mut parsed_sai: Vec<SAI> = vec![];
    for i in 0..len {
        let val: JsString = sai.get_element(i)?;
        let bp = val
            .into_utf8()?
            .as_str()?
            .parse()
            .map_err(|_e| napi::Error::from_reason("Can't parse sai prefix"))?;
        parsed_sai.push(bp);
    }
    Ok(parsed_sai)
}

#[js_function(2)]
fn incept(ctx: CallContext) -> JsResult<JsBuffer> {
    let pub_keys = get_keys_array_argument(&ctx, 0)?;
    let this: JsObject = ctx.this_unchecked();
    let kel: &mut Kel = ctx.env.unwrap(&this)?;

    let icp = kel.incept(pub_keys.current, pub_keys.next, vec![], 0)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;

    ctx.env.create_buffer_copy(&icp).map(|b| b.into_raw())
}

// #[js_function(0)]
// fn get_prefix(ctx: CallContext) -> JsResult<JsString> {
//     let this: JsObject = ctx.this_unchecked();
//     let kel: &KEL = ctx.env.unwrap(&this)?;
//     let preifx = kel.get_prefix().to_str();
//     ctx.env.create_string(&preifx)
// }

#[js_function(2)]
fn finalize_inception(ctx: CallContext) -> JsResult<JsString> {
    let icp = ctx.get::<JsBuffer>(0)?.into_value()?.to_vec();
    let signatures = get_signature_array_argument(&ctx, 1)?;

    let this: JsObject = ctx.this_unchecked();
    let kel: &mut Kel = ctx.env.unwrap(&this)?;
    let prefix = kel.finalize_inception(String::from_utf8(icp).unwrap(), signatures[0].clone())
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;

    ctx.env.create_string(&prefix)
}

#[js_function(1)]
fn get_kel(ctx: CallContext) -> JsResult<JsString> {
    let id = ctx.get::<JsString>(0)?.into_utf8()
        .map_err(|_e| napi::Error::from_reason("Missing identifier prefix parameter"))?
        .as_str()?
        .to_owned();
    let this: JsObject = ctx.this_unchecked();
    let kel: &Kel = ctx.env.unwrap(&this)?;
    let kel_str = kel.get_kel(id)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;

    ctx.env.create_string(&kel_str)
}


#[js_function(3)]
fn rotate(ctx: CallContext) -> JsResult<JsBuffer> {
    let pub_keys = get_keys_array_argument(&ctx, 0)?;
    let id = ctx.get::<JsString>(0)?
        .into_utf8()
        .map_err(|_e| napi::Error::from_reason("Missing identifier prefix parameter"))?
        .as_str()?
        .to_owned();

    let this: JsObject = ctx.this_unchecked();
    let kel: &mut Kel = ctx.env.unwrap(&this)?;
    let rot_event = kel
        .rotate(id, pub_keys.current, pub_keys.next, vec![], vec![], 0)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;

    ctx.env.create_buffer_copy(&rot_event).map(|b| b.into_raw())
}

#[js_function(2)]
fn finalize_rotation(ctx: CallContext) -> JsResult<JsBoolean> {
    let rot = ctx
        .get::<JsString>(0)?
        .into_utf8()
        .map_err(|_e| napi::Error::from_reason("Missing event string parameter"))?
        .as_str()?
        .to_owned();
    let signatures = get_signature_array_argument(&ctx, 1)?;

    let this: JsObject = ctx.this_unchecked();
    let kel: &Kel = ctx.env.unwrap(&this)?;

    let rot_result = kel
        .finalize_event(rot, signatures[0].clone())
        .map_err(|e| napi::Error::from_reason(e.to_string())).is_ok();
    ctx.env.get_boolean(rot_result)
}

// #[js_function(1)]
// fn anchor(ctx: CallContext) -> JsResult<JsBuffer> {
//     let payload = get_sai_array_argument(&ctx, 0)?;

//     let this: JsObject = ctx.this_unchecked();
//     let kel: &mut KEL = ctx.env.unwrap(&this)?;
//     let ixn_event = kel
//         .anchor(&payload)
//         .map_err(|e| napi::Error::from_reason(e.to_string()))?
//         .serialize()
//         .map_err(|e| napi::Error::from_reason(e.to_string()))?;
//     ctx.env.create_buffer_copy(&ixn_event).map(|b| b.into_raw())
// }

// #[js_function(2)]
// fn finalize_anchor(ctx: CallContext) -> JsResult<JsBoolean> {
//     let ixn = ctx
//         .get::<JsBuffer>(0)?
//         .into_value() //?.to_vec()
//         .map_err(|_e| napi::Error::from_reason("Missing interaction event parameter"))?
//         .to_vec();
//     let signatures = get_signature_array_argument(&ctx, 1)?;

//     let this: JsObject = ctx.this_unchecked();
//     let kel: &KEL = ctx.env.unwrap(&this)?;

//     let ixn_result = kel
//         .finalize_anchor(ixn, signatures)
//         .map_err(|e| napi::Error::from_reason(e.to_string()))?;

//     ctx.env.get_boolean(ixn_result)
// }

// #[js_function(1)]
// fn is_anchored(ctx: CallContext) -> JsResult<JsBoolean> {
//     let val: JsString = ctx.get::<JsString>(0)?;
//     let sai = val
//         .into_utf8()?
//         .as_str()?
//         .parse()
//         .map_err(|_e| napi::Error::from_reason("Can't parse sai prefix"))?;

//     let this: JsObject = ctx.this_unchecked();
//     let kel: &mut KEL = ctx.env.unwrap(&this)?;
//     let check_result = kel
//         .is_anchored(sai)
//         .map_err(|e| napi::Error::from_reason(e.to_string()))?;
//     ctx.env.get_boolean(check_result)
// }

#[js_function(1)]
fn process(ctx: CallContext) -> JsResult<JsUndefined> {
    let stream = ctx
        .get::<JsBuffer>(0)?
        .into_value()
        .map_err(|_e| napi::Error::from_reason("Missing event stream parameter"))?
        .to_vec();
    let this: JsObject = ctx.this_unchecked();
    let kel: &Kel = ctx.env.unwrap(&this)?;
    kel.parse_and_process(&stream)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    ctx.env.get_undefined()
}

// #[js_function(1)]
// fn get_current_public_key(ctx: CallContext) -> JsResult<JsObject> {
//     let identifier: String = ctx
//         .get::<JsString>(0)?
//         .into_utf8()
//         .map_err(|_e| napi::Error::from_reason("Missing identifier prefix parameter"))?
//         .as_str()?
//         .to_owned();
//     let prefix: Identifier = identifier
//         .parse()
//         .map_err(|_e| napi::Error::from_reason("Wrong identifeir prefix"))?;
//     let this: JsObject = ctx.this_unchecked();
//     let kel: &KEL = ctx.env.unwrap(&this)?;
//     let mut key_array = ctx.env.create_array_with_length(2)?;
//     let _key: Vec<_> = kel
//         .get_current_public_keys(&prefix)
//         .map_err(|_e| napi::Error::from_reason("Wrong identifeir prefix"))?
//         .ok_or_else(|| {
//             napi::Error::from_reason(format!("There is no keys for prefix {}", identifier))
//         })?
//         .iter()
//         .enumerate()
//         .map(|(i, key)| {
//             key_array.set_element(i as u32, ctx.env.create_string_from_std(key.to_str())?)
//         })
//         .collect();
//     Ok(key_array)
// }

// #[js_function(3)]
// fn verify(ctx: CallContext) -> JsResult<JsBoolean> {
//     let message = ctx
//         .get::<JsBuffer>(0)?
//         .into_value()
//         .map_err(|_e| napi::Error::from_reason("Missing message parameter"))?
//         .to_vec();
//     let signatures = get_signature_array_argument(&ctx, 1)?;

//     let identifier: String = ctx
//         .get::<JsString>(2)?
//         .into_utf8()
//         .map_err(|_e| napi::Error::from_reason("Missing identifier prefix parameter"))?
//         .as_str()?
//         .to_owned();
//     let this: JsObject = ctx.this_unchecked();
//     let kel: &KEL = ctx.env.unwrap(&this)?;
//     let prefix = identifier
//         .parse()
//         .map_err(|_e| napi::Error::from_reason("Wrong identifeir prefix"))?;

//     ctx.env
//         .get_boolean(kel.verify(&message, &signatures, &prefix).map_err(|e| {
//             napi::Error::from_reason(format!("Error while verifing: {}", e.to_string()))
//         })?)
// }

// #[js_function(4)]
// fn verify_at_sn(ctx: CallContext) -> JsResult<JsBoolean> {
//     let message = ctx
//         .get::<JsBuffer>(0)?
//         .into_value()
//         .map_err(|_e| napi::Error::from_reason("Missing message parameter"))?
//         .to_vec();
//     let signature = ctx
//         .get::<JsString>(0)?
//         .into_utf8()
//         .map_err(|_e| napi::Error::from_reason("Missing signature parameter"))?
//         .as_str()?
//         .to_owned();
//     let identifier: String = ctx
//         .get::<JsString>(2)?
//         .into_utf8()
//         .map_err(|_e| napi::Error::from_reason("Missing signature parameter"))?
//         .as_str()?
//         .to_owned();
//     let sn: i64 = ctx.get::<JsNumber>(3)?.try_into()?;
//     let this: JsObject = ctx.this_unchecked();
//     let kel: &KEL = ctx.env.unwrap(&this)?;
//     let prefix = identifier
//         .parse()
//         .map_err(|_e| napi::Error::from_reason("Wrong identifier prefix"))?;
//     let signature: SignaturePrefix = signature
//         .parse()
//         .map_err(|_e| napi::Error::from_reason("Wrong signature prefix"))?;
//     ctx.env.get_boolean(
//         kel.verify_at_sn(&message, &signature, &prefix, sn as u64)
//             .map_err(|e| {
//                 napi::Error::from_reason(format!("Error while verifing: {}", e))
//             })?,
//     )
// }

// #[js_function(0)]
// fn get_current_sn(ctx: CallContext) -> JsResult<JsNumber> {
//     let this: JsObject = ctx.this_unchecked();
//     let kel: &KEL = ctx.env.unwrap(&this)?;
//     let sn = kel
//         .current_sn()
//         .map_err(|e| napi::Error::from_reason(format!("Can't get sn: {}", e.to_string())))?;
//     ctx.env.create_int64(sn as i64)
// }
