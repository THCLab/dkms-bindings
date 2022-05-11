// use std::{
//     convert::TryFrom,
//     io::{self, Read},
//     sync::Arc,
// };

// use clap::{App, Arg, Error};
// use keri::{
//     database::sled::SledEventDatabase,
//     error::Error,
//     event_message::{
//         event_msg_builder::EventMsgBuilder, signed_event_message::Message, EventTypeTag,
//     },
//     event_parsing::message::{message, signed_event_stream, signed_message},
//     prefix::{AttachedSignaturePrefix, BasicPrefix, Prefix, SelfSigningPrefix},
//     processor::EventProcessor,
//     state::IdentifierState,
// };

fn main() {
    // let mut serialized_kel = String::new();
    // let mut stdin = io::stdin();
    // stdin.read_to_string(&mut serialized_kel).unwrap();

    // use tempfile::Builder;

    // // Create test db and event processor.
    // let db_root = Builder::new().prefix("test-db").tempdir().unwrap();
    // let path = db_root.path();

    // let db = Arc::new(SledEventDatabase::new(path)?);
    // let proc = EventProcessor::new(Arc::clone(&db));
    // let states: Vec<Option<IdentifierState>> = signed_event_stream(serialized_kel.as_bytes())
    //     .unwrap()
    //     .1
    //     .into_iter()
    //     .map(|sem| Message::try_from(sem))
    //     .map(|msg| proc.process(msg.unwrap()).unwrap())
    //     .collect();

    // // Parse arguments
    // let matches = App::new("kel")
    //     .version("1.0")
    //     .subcommand(
    //         App::new("process")
    //             .about("Process event with signature")
    //             .arg(
    //                 Arg::new("event")
    //                     .short('e')
    //                     .long("event")
    //                     .takes_value(true)
    //                     .value_name("EVENT"),
    //                 // .about("Process event"),
    //             )
    //             .arg(
    //                 Arg::new("signature")
    //                     .short('s')
    //                     .long("signature")
    //                     .takes_value(true)
    //                     .value_name("SIGNATURE"),
    //                 // .about("Signature of message"),
    //             ),
    //     )
    //     .subcommand(
    //         App::new("incept")
    //             .about("Generate inception event")
    //             .arg(
    //                 Arg::new("current")
    //                     .short('c')
    //                     .long("current")
    //                     .takes_value(true)
    //                     .multiple_occurrences(true)
    //                     .value_name("PREFIX"),
    //                 // .about("Set current public key"),
    //             )
    //             .arg(
    //                 Arg::new("next")
    //                     .short('n')
    //                     .long("next")
    //                     .takes_value(true)
    //                     .multiple_occurrences(true)
    //                     .value_name("PREFIX"),
    //                 // .about("Set next public key"),
    //             ),
    //     )
    //     .subcommand(
    //         App::new("rotate")
    //             .about("Set next key of rotatrion event")
    //             .arg(
    //                 Arg::new("current")
    //                     .short('c')
    //                     .long("current")
    //                     .takes_value(true)
    //                     .multiple_occurrences(true)
    //                     .value_name("PREFIX"),
    //                 // .about("Set current public key"),
    //             )
    //             .arg(
    //                 Arg::new("next")
    //                     .short('n')
    //                     .long("next")
    //                     .takes_value(true)
    //                     .multiple_occurrences(true)
    //                     .value_name("PREFIX"),
    //                 // .about("Set next public key"),
    //             ),
    //     )
    //     .get_matches();

    // if let Some(ref matches) = matches.subcommand_matches("incept") {
    //     // get current keys
    //     let current_keys: Vec<BasicPrefix> = if let Some(c) = matches.values_of("current") {
    //         c.map(|p| p.parse().unwrap()).collect()
    //     } else {
    //         vec![]
    //     };

    //     // get next keys
    //     let next_keys: Vec<BasicPrefix> = if let Some(c) = matches.values_of("next") {
    //         c.map(|p| p.parse().unwrap()).collect()
    //     } else {
    //         vec![]
    //     };

    //     let icp = EventMsgBuilder::new(EventTypeTag::Icp)
    //         .with_keys(current_keys.clone())
    //         .with_next_keys(next_keys.clone())
    //         .build()?;
    //     println!("{}", String::from_utf8(icp.serialize().unwrap()).unwrap())
    // };

    // if let Some(ref matches) = matches.subcommand_matches("rotate") {
    //     // get current keys
    //     let current_keys: Vec<BasicPrefix> = if let Some(c) = matches.values_of("current") {
    //         c.map(|p| p.parse().unwrap()).collect()
    //     } else {
    //         vec![]
    //     };

    //     // get next keys
    //     let next_keys: Vec<BasicPrefix> = if let Some(c) = matches.values_of("next") {
    //         c.map(|p| p.parse().unwrap()).collect()
    //     } else {
    //         vec![]
    //     };

    //     let prefix = states.last().clone().unwrap().to_owned().unwrap().prefix;
    //     let last = states
    //         .last()
    //         .clone()
    //         .unwrap()
    //         .to_owned()
    //         .unwrap()
    //         .last_event_digest;

    //     let rot = EventMsgBuilder::new(EventTypeTag::Rot)
    //         .with_prefix(&prefix)
    //         .with_keys(current_keys.clone())
    //         .with_next_keys(next_keys.clone())
    //         .with_previous_event(&last)
    //         .build()?;
    //     println!("{}", String::from_utf8(rot.serialize().unwrap()).unwrap())
    // };

    // if let Some(ref matches) = matches.subcommand_matches("process") {
    //     let event = if let Some(c) = matches.value_of("event") {
    //         let (_rest, msg) = message(c.as_bytes()).unwrap();
    //         Ok(msg)
    //     } else {
    //         Err(Error::SemanticError("not event msg".into()))
    //     }?;

    //     // get sigatures
    //     let signature: SelfSigningPrefix = if let Some(c) = matches.value_of("signature") {
    //         c.parse()
    //     } else {
    //         Err(Error::SemanticError("incorrect signature".into()))
    //     }?;
    //     let att = AttachedSignaturePrefix::new(signature.derivation, signature.derivative(), 0);

    //     let sig_message = event.sign(vec![att], None).serialize().unwrap();
    //     let s = signed_message(&sig_message).unwrap().1;

    //     let p = proc.process(Message::try_from(s)?)?;
    //     let prefix = p.unwrap().prefix;
    //     let kel = proc.get_kerl(&prefix)?.unwrap();
    //     println!("{}", String::from_utf8(kel).unwrap())
    // }
}
