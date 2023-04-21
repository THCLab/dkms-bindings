use anyhow::Result;
use cesrox::primitives::{
    codes::{basic::Basic, self_signing::SelfSigning},
    CesrPrimitive,
};
use keri::signer::{CryptoBox, KeyManager};
use said::derivation::{HashFunction, HashFunctionCode};
use tempfile::Builder;

use crate::api::{
    add_watcher, anchor, anchor_digest, change_controller, finalize_event, finalize_group_incept,
    finalize_inception, finalize_query, get_kel, incept, incept_group, init_kel, new_public_key,
    notify_witnesses, process_stream, query_mailbox, query_watchers, resolve_oobi, rotate,
    send_oobi_to_watcher, sign_to_cesr, signature_from_hex, split_oobis_and_data, verify_from_cesr,
    Action, Config, DataAndSignature, Identifier,
};

#[test]
pub fn test_new_key() -> Result<()> {
    let public_key = "-Ladn-aIv4Rzr9o5RvZfM9zLWa8R0u5Dtok2dhN5b-k=".to_string();
    let not_base_64 = "wrong_base_64".to_string();
    let to_short_public_key = "-Ladn-aIv4Rzr9o5RvZfM9zLWa8R0u5Dtok2dhN5b-".to_string();
    let to_long_public_key = "-Ladn-aIv4Rzr9o5RvZfM9zLWa8R0u5Dtok2dhN5b-k=GGG".to_string();

    assert!(new_public_key(Basic::Ed25519Nontrans, public_key).is_ok());
    assert!(new_public_key(Basic::Ed25519Nontrans, not_base_64).is_err());
    assert!(new_public_key(Basic::Ed25519Nontrans, to_short_public_key).is_err());
    assert!(new_public_key(Basic::Ed25519Nontrans, to_long_public_key).is_err());

    Ok(())
}

#[test]
pub fn test_signature_from_hex() -> Result<()> {
    let signature = "F426738DFEC3EED52D36CB2B825ADFB3D06D98B3AF986EAE2F70B8E536C60C1C7DC41E49D30199D107AB57BD43D458A14064AB3A963A51450DBDE253CD94BB0C".to_string();
    let _sig = signature_from_hex(SelfSigning::Ed25519Sha512, signature);

    Ok(())
}

#[test]
pub fn test_api() -> Result<()> {
    use crate::api::{finalize_inception, get_kel, incept, init_kel};
    use tempfile::Builder;

    // Create temporary db file.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let public_key = "hcBkAr-U14x2zW-mw1pvPXOOZPUjXLVUnt-b13tpQvg=".to_string();
    let next_public_key = "hPaigCAM-HoeHx5H1lZnTJpoGR4GEN0diyt2j4qZurg=".to_string();

    init_kel(root.path().to_str().unwrap().into(), None)?;

    let pk = new_public_key(Basic::Ed25519, public_key)?;
    let npk = new_public_key(Basic::Ed25519, next_public_key.into())?;
    let icp_event = incept(vec![pk], vec![npk], vec![], 0)?;

    let expected_icp = r#"{"v":"KERI10JSON00012b_","t":"icp","d":"EHJ-ufEDTUc9BDhXrOEKUEmlKRIQ41LVa-1QsxzEeuMy","i":"EHJ-ufEDTUc9BDhXrOEKUEmlKRIQ41LVa-1QsxzEeuMy","s":"0","kt":"1","k":["DIXAZAK_lNeMds1vpsNabz1zjmT1I1y1VJ7fm9d7aUL4"],"nt":"1","n":["EPO4i4pfpPM4nN6f1Cu-DsI3RUM0mdO27hBNbB6x2ga8"],"bt":"0","b":[],"c":[],"a":[]}"#;
    assert_eq!(icp_event, expected_icp);
    // sign icp event
    let signature = "264f1d560485c5e114c5be0295bc556cb5e9ab2515b0666c3a61c6d6e9af5d353ffd53b941ba7626bcc7dacb8943317624d04c34f7eceecc934c9b9947c7df0c".to_string();
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, signature);

    let controller = finalize_inception(icp_event, signature)?;
    let kel = get_kel(controller)?;
    println!("kel: {}", kel);
    Ok(())
}

#[test]
pub fn test_process() -> Result<()> {
    use crate::api::{init_kel, process_stream};
    use tempfile::Builder;

    // Create temporary db file.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    init_kel(root.path().to_str().unwrap().into(), None)?;

    let test_kel = r#"{"v":"KERI10JSON0001e7_","t":"icp","d":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"0","kt":"2","k":["DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q","DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS","DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f"],"nt":"2","n":["EDJk5EEpC4-tQ7YDwBiKbpaZahh1QCyQOnZRF7p2i8k8","EAXfDjKvUFRj-IEB_o4y-Y_qeJAjYfZtOMD9e7vHNFss","EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m"],"bt":"0","b":[],"c":[],"a":[]}-AADAAD4SyJSYlsQG22MGXzRGz2PTMqpkgOyUfq7cS99sC2BCWwdVmEMKiTEeWe5kv-l_d9auxdadQuArLtAGEArW8wEABD0z_vQmFImZXfdR-0lclcpZFfkJJJNXDcUNrf7a-mGsxNLprJo-LROwDkH5m7tVrb-a1jcor2dHD9Jez-r4bQIACBFeU05ywfZycLdR0FxCvAR9BfV9im8tWe1DglezqJLf-vHRQSChY1KafbYNc96hYYpbuN90WzuCRMgV8KgRsEC{"v":"KERI10JSON00021c_","t":"rot","d":"EHjzZj4i_-RpTN2Yh-NocajFROJ_GkBtlByhRykqiXgz","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"1","p":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","kt":"2","k":["DCjxOXniUc5EUzDqERlXdptfKPHy6jNo_ZGsS4Vd8fAE","DNZHARO4dCJlluv0qezEMRmErIWWc-lzOzolBOQ15tHV","DOCQ4KN1jUlKbfjRteDYt9fxgpq1NK9_MqO5IA7shpED"],"nt":"2","n":["EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m","EATiZAHl0kzKID6faaQP2O7zB3Hj7eH3bE-vgKVAtsyU","EG6e7dJhh78ZqeIZ-eMbe-OB3TwFMPmrSsh9k75XIjLP"],"bt":"0","br":[],"ba":[],"a":[]}-AADAAAqV6xpsAAEB_FJP5UdYO5qiJphz8cqXbTjB9SRy8V0wIim-lgafF4o-b7TW0spZtzx2RXUfZLQQCIKZsw99k8AABBP8nfF3t6bf4z7eNoBgUJR-hdhw7wnlljMZkeY5j2KFRI_s8wqtcOFx1A913xarGJlO6UfrqFWo53e9zcD8egIACB8DKLMZcCGICuk98RCEVuS0GsqVngi1d-7gAX0jid42qUcR3aiYDMp2wJhqJn-iHJVvtB-LK7TRTggBtMDjuwB"#;

    process_stream(test_kel.to_string())?;
    let identifier =
        Identifier::new_from_str("EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen".to_string())?;
    let kel = get_kel(identifier)?;
    println!("kel: {}", kel);

    Ok(())
}

#[test]
pub fn test_optional_config() -> Result<()> {
    use crate::api::init_kel;
    use tempfile::Builder;

    // Create temporary db file.
    let root_path = Builder::new()
        .prefix("test-db")
        .tempdir()
        .unwrap()
        .into_path();

    let config = Config {
        initial_oobis: "random".into(),
    };
    let oc = config.build(root_path.clone());
    assert!(oc.is_err());

    let config = Config { initial_oobis: r#"[{"eid":"BKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ","scheme":"http","url":"http://127.0.0.1:0/"}]"#.into() };

    // Fail to resolve oobi
    let result = init_kel(root_path.to_str().unwrap().into(), Some(config));
    assert!(result.is_err());

    Ok(())
}

#[test]
pub fn test_add_watcher() -> Result<()> {
    use tempfile::Builder;

    // Create temporary db file.
    let root_path = Builder::new()
        .prefix("test-db")
        .tempdir()
        .unwrap()
        .path()
        .to_str()
        .unwrap()
        .into();

    init_kel(root_path, None)?;
    let identifier =
        Identifier::new_from_str("EM7ml1EF4PNuuA8leM7ec0E95ukz5oBf3-gAjHEvQgsc".to_string())?;

    let add_watcher_message = add_watcher(identifier.clone(), "[{}]".into());
    assert!(add_watcher_message.is_err());

    let add_watcher_message = add_watcher(identifier.clone(), r#"[{"eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://sandbox.argo.colossi.network:3232/"}]"#.into());
    assert!(add_watcher_message.is_err());

    let add_watcher_message = add_watcher(
        identifier.clone(),
        r#"{"eid":"EA","scheme":"http","url":"http://sandbox.argo.colossi.network:3232/"}"#.into(),
    );
    assert!(add_watcher_message.is_err());

    // Nobody listen
    let add_watcher_message = add_watcher(identifier.clone(), r#"{"eid":"BSuhyBcPZEZLK-fcw4tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://sandbox.argo.colossi.network:8888/"}"#.into());
    assert!(add_watcher_message.is_err());

    let add_watcher_message = add_watcher(identifier.clone(), r#"{"eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://sandbox.argo.colossi.network:3232/"}"#.into());
    assert!(add_watcher_message.is_ok());

    Ok(())
}

#[test]
pub fn test_resolve_oobi() -> Result<()> {
    use tempfile::Builder;

    // Create temporary db file.
    let root_path = Builder::new()
        .prefix("test-db")
        .tempdir()
        .unwrap()
        .path()
        .to_str()
        .unwrap()
        .into();

    init_kel(root_path, None)?;

    let resolve_result = resolve_oobi("".into());
    assert!(resolve_result.is_err());

    let resolve_result = resolve_oobi(r#"[{"eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://sandbox.argo.colossi.network:3232/"}]"#.into());
    assert!(resolve_result.is_err());

    let resolve_result = resolve_oobi(r#"random"#.into());
    assert!(resolve_result.is_err());

    // Nobody listen
    let resolve_result = resolve_oobi(r#"{"eid":"BSuhyBcPZEZLK-fcw4tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://localhost:3232/"}"#.into());
    assert!(resolve_result.is_err());

    let resolvr_result = resolve_oobi(r#"{"eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://sandbox.argo.colossi.network:3232/"}"#.into());
    assert!(resolvr_result.is_ok());

    Ok(())
}

#[test]
pub fn test_multisig() -> Result<()> {
    use crate::api::{finalize_inception, get_kel, incept, init_kel};

    // Create temporary db file.
    let root_path: String = Builder::new()
        .prefix("test-db")
        .tempdir()
        .unwrap()
        .path()
        .to_str()
        .unwrap()
        .into();

    // Create temporary db file.
    let root_path2: String = Builder::new()
        .prefix("test-db")
        .tempdir()
        .unwrap()
        .path()
        .to_str()
        .unwrap()
        .into();

    init_kel(root_path.clone(), None)?;

    // Tests assumses that witness DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA is listening on http://127.0.0.1:3232
    // It can be run from keriox/components/witness using command:
    // cargo run -- -c ./src/witness.json
    let witness_id = "BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC".to_string();
    let wit_location = r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://127.0.0.1:3232/"}"#.to_string();

    // Incept first group participant
    let key_manager = CryptoBox::new().unwrap();
    let current_b64key = base64::encode_config(key_manager.public_key().key(), base64::URL_SAFE);
    let next_b64key = base64::encode_config(key_manager.next_public_key().key(), base64::URL_SAFE);

    let pk = new_public_key(Basic::Ed25519, current_b64key)?;
    let npk = new_public_key(Basic::Ed25519, next_b64key)?;
    let icp_event = incept(vec![pk], vec![npk], vec![wit_location.clone()], 1)?;
    let hex_signature = hex::encode(key_manager.sign(icp_event.as_bytes())?);

    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
    let identifier = finalize_inception(icp_event, signature)?;

    // Publish own event to witnesses
    notify_witnesses(identifier.clone())?;

    // Quering own mailbox to get receipts
    // TODO always qry mailbox
    let query = query_mailbox(
        identifier.clone(),
        identifier.clone(),
        vec![witness_id.clone()],
    )?;

    for qry in query {
        let hex_signature = hex::encode(key_manager.sign(qry.as_bytes())?);
        let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
        finalize_query(identifier.clone(), qry, signature)?;
    }

    let initiator_kel = get_kel(identifier.clone())?;
    println!("\ninitiator's kel: {}", initiator_kel);

    change_controller(root_path2.clone())?;
    process_stream(initiator_kel)?;
    // Incept second group participant
    let participants_key_manager = CryptoBox::new().unwrap();
    let current_b64key = base64::encode_config(
        participants_key_manager.public_key().key(),
        base64::URL_SAFE,
    );
    let next_b64key = base64::encode_config(
        participants_key_manager.next_public_key().key(),
        base64::URL_SAFE,
    );

    let participant_pk = new_public_key(Basic::Ed25519, current_b64key)?;
    let participant_npk = new_public_key(Basic::Ed25519, next_b64key)?;
    let icp_event = incept(
        vec![participant_pk],
        vec![participant_npk],
        vec![wit_location.clone()],
        1,
    )?;
    let hex_signature = hex::encode(participants_key_manager.sign(icp_event.as_bytes())?);
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);

    let participant = finalize_inception(icp_event, signature)?;

    // Publish own event to witnesses
    notify_witnesses(participant.clone())?;

    // Quering own mailbox to get receipts
    let query = query_mailbox(
        participant.clone(),
        participant.clone(),
        vec![witness_id.clone()],
    )?;

    for qry in query {
        let hex_signature = hex::encode(participants_key_manager.sign(qry.as_bytes())?);
        let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
        finalize_query(participant.clone(), qry, signature)?;
    }

    let patricipant_kel = get_kel(participant.clone())?;
    println!("\nparticipant's kel: {}", patricipant_kel);

    change_controller(root_path.clone())?;
    process_stream(patricipant_kel)?;
    // initiate group by first particiapnt. To accept event bouth participants signature must be provided.
    let icp = incept_group(
        identifier.clone(),
        vec![participant.clone()],
        2,
        vec![witness_id.clone()],
        1,
    )?;
    assert_eq!(icp.exchanges.len(), 1);

    // sign group inception by first participant
    let hex_signature = hex::encode(key_manager.sign(icp.icp_event.as_bytes())?);
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);

    // sign exchanges to forward it to other participants
    let exn_signature = hex::encode(key_manager.sign(icp.exchanges[0].as_bytes())?);
    let exn_signature = signature_from_hex(SelfSigning::Ed25519Sha512, exn_signature);

    let group_identifier = finalize_group_incept(
        identifier.clone(),
        icp.icp_event,
        signature,
        vec![DataAndSignature::new(
            icp.exchanges[0].clone(),
            exn_signature,
        )],
    )?;

    // event wasn't fully signed, it shouldn't be accepted into kel.
    let kel = get_kel(group_identifier.clone());
    assert!(kel.is_err());

    change_controller(root_path2.clone())?;
    // Second participants query about own mailbox, to get forwarded group event.
    // Quering mailbox to get receipts
    let query = query_mailbox(
        participant.clone(),
        participant.clone(),
        vec![witness_id.clone()],
    )?;
    assert_eq!(query.len(), 1);

    let qry = query[0].clone();
    let hex_signature = hex::encode(participants_key_manager.sign(qry.as_bytes())?);
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
    // here second time the same multisig icp is processed
    let action_required = finalize_query(participant.clone(), qry, signature)?;
    assert_eq!((&action_required).len(), 1);

    let action = &action_required[0];
    match action.action {
        Action::MultisigRequest => {
            // sign icp event by participant
            let hex_signature = hex::encode(participants_key_manager.sign(action.data.as_bytes())?);
            let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);

            let exn_signature =
                hex::encode(participants_key_manager.sign(action.additiona_data.as_bytes())?);
            let exn_signature = signature_from_hex(SelfSigning::Ed25519Sha512, exn_signature);

            let group_controller = finalize_group_incept(
                participant.clone(),
                action.data.clone(),
                signature,
                vec![DataAndSignature::new(
                    action.additiona_data.clone(),
                    exn_signature,
                )],
            )?;

            // Group inception should not be accepted yet. Lack of receipt.
            let kel = get_kel(group_controller);
            assert!(kel.is_err());
        }
        Action::DelegationRequest => todo!(),
    };

    change_controller(root_path.clone())?;
    // Quering group mailbox to get receipts of group icp
    let query = query_mailbox(
        identifier.clone(),
        group_identifier.clone(),
        vec![witness_id.clone()],
    )?;
    assert_eq!(query.len(), 1);

    let qry = query[0].clone();
    let hex_signature = hex::encode(key_manager.sign(qry.as_bytes())?);
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
    let action_required = finalize_query(identifier.clone(), qry, signature);
    assert_eq!((&action_required?).len(), 0);

    // Group inception should not be accepted yet. Lack of receipt.
    let kel = get_kel(group_identifier.clone());
    assert!(kel.is_err());

    // Query group mailbox again for multisig inception receipt.
    let query = query_mailbox(
        identifier.clone(),
        group_identifier.clone(),
        vec![witness_id.clone()],
    )?;
    assert_eq!(query.len(), 1);

    let qry = query[0].clone();
    let hex_signature = hex::encode(key_manager.sign(qry.as_bytes())?);
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
    let action_required = finalize_query(identifier, qry, signature);
    assert_eq!((&action_required?).len(), 0);

    // Group inception should be accepted now.
    let kel = get_kel(group_identifier.clone());
    assert!(kel.is_ok());

    // Same for other participant
    change_controller(root_path2.clone())?;
    let query = query_mailbox(
        participant.clone(),
        group_identifier.clone(),
        vec![witness_id.clone()],
    )?;
    assert_eq!(query.len(), 1);

    let qry = query[0].clone();
    let hex_signature = hex::encode(participants_key_manager.sign(qry.as_bytes())?);
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
    let action_required = finalize_query(participant, qry, signature);
    assert_eq!((&action_required?).len(), 0);

    // Group inception should be accepted now.
    let kel = get_kel(group_identifier);
    assert!(kel.is_ok());

    Ok(())
}

#[test]
pub fn test_demo() -> Result<()> {
    use crate::api::{finalize_inception, get_kel, incept, init_kel};
    use tempfile::Builder;

    // Create temporary db file.
    let root_path = Builder::new()
        .prefix("test-db")
        .tempdir()
        .unwrap()
        .path()
        .to_str()
        .unwrap()
        .into();

    let mut key_manager = CryptoBox::new().unwrap();
    let current_b64key = base64::encode_config(key_manager.public_key().key(), base64::URL_SAFE);
    let next_b64key = base64::encode_config(key_manager.next_public_key().key(), base64::URL_SAFE);

    init_kel(root_path, None)?;

    let pk = new_public_key(Basic::Ed25519, current_b64key)?;
    let npk = new_public_key(Basic::Ed25519, next_b64key)?;
    let icp_event = incept(vec![pk], vec![npk], vec![], 0)?;
    let hex_signature = hex::encode(key_manager.sign(icp_event.as_bytes())?);

    // sign icp event
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);

    let controller = finalize_inception(icp_event, signature)?;

    key_manager.rotate()?;
    let current_b64key = base64::encode_config(key_manager.public_key().key(), base64::URL_SAFE);
    let next_b64key = base64::encode_config(key_manager.next_public_key().key(), base64::URL_SAFE);
    let pk = new_public_key(Basic::Ed25519, current_b64key)?;
    let npk = new_public_key(Basic::Ed25519, next_b64key)?;

    let rotation_event = rotate(controller.clone(), vec![pk], vec![npk], vec![], vec![], 0)?;

    let hex_signature = hex::encode(key_manager.sign(rotation_event.as_bytes())?);

    // sign rot event
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);

    println!("rotation: \n{}", rotation_event);

    assert!(finalize_event(controller.clone(), "random data".into(), signature.clone()).is_err());

    finalize_event(controller.clone(), rotation_event, signature)?;

    let sai = HashFunction::from(HashFunctionCode::Blake3_256)
        .derive("some data".as_bytes())
        .to_str();
    let ixn_event = anchor_digest(controller.clone(), vec![sai])?;
    println!("\nixn: {}", ixn_event);

    let hex_signature = hex::encode(key_manager.sign(ixn_event.as_bytes())?);
    // sign rot event
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
    finalize_event(controller.clone(), ixn_event, signature)?;

    let ixn_event = anchor(
        controller.clone(),
        "some data".into(),
        HashFunctionCode::Blake3_256,
    )?;
    println!("\nixn: {}", ixn_event);

    let hex_signature = hex::encode(key_manager.sign(ixn_event.as_bytes())?);
    // sign rot event
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
    finalize_event(controller.clone(), ixn_event, signature)?;

    let kel = get_kel(controller.clone())?;
    println!("\nCurrent controller kel: \n{}", kel);

    // let watcher_oobi = r#"{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://sandbox.argo.colossi.network:3236/"}"#.into();

    // let add_watcher_message = add_watcher(controller.clone(), watcher_oobi)?;
    // println!(
    //     "\nController generate end role message to add watcher: \n{}",
    //     add_watcher_message
    // );
    // let hex_sig = hex::encode(key_manager.sign(add_watcher_message.as_bytes()).unwrap());
    // let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_sig);

    // finalize_event(controller.clone(), add_watcher_message, signature).unwrap();

    // let issuer_oobi: String = r#"[{"cid":"EWln-QVizE_qYcfv_S4mc_Dbzc3zyCApYomojukM8YI0","role":"witness","eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"},{"eid":"BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://localhost:3232/"}]"#.into();

    // println!("\nQuering about issuer kel...");
    // println!("\nSending issuer oobi to watcher: \n{}", issuer_oobi);
    // query(controller.clone(), "random".into()).unwrap();
    // query(controller, issuer_oobi).unwrap();

    // // Get acdc signed by issuer
    // let acdc = r#"{"issuer":"EWln-QVizE_qYcfv_S4mc_Dbzc3zyCApYomojukM8YI0","data":"EjLNcJrUEs8PX0LLFFowS-_e9dpX3SEf3C4U1CdhJFUE"}"#;
    // let attachment_stream = r#"-FABEWln-QVizE_qYcfv_S4mc_Dbzc3zyCApYomojukM8YI00AAAAAAAAAAAAAAAAAAAAAAAEWln-QVizE_qYcfv_S4mc_Dbzc3zyCApYomojukM8YI0-AABAAG3NikDFb-2C20mTxhKet-jt5os5D-8NDGTNgeHKgUPaRzBnIZC9csSgcDP4CmtEJVkNzAsrX4SFUq4SFzxCyAA"#;

    // let key_sig_pair = get_current_public_key(attachment_stream.into()).unwrap();

    // // Checking if key verify signature
    // let public_key_signature_pair = key_sig_pair.iter().collect::<Vec<_>>();
    // assert_eq!(public_key_signature_pair.len(), 1);
    // let key_signature_pair = public_key_signature_pair[0];
    // let pk_raw = base64::decode(&key_signature_pair.key.key).unwrap();
    // let key_bp = Basic::Ed25519.derive(keri::keys::PublicKey::new(pk_raw));
    // let sig =
    //     SelfSigning::Ed25519Sha512.derive(hex::decode(&key_signature_pair.signature.key).unwrap());

    // assert!(key_bp.verify(acdc.as_bytes(), &sig).unwrap());

    Ok(())
}

#[test]
pub fn test_sign_verify() -> Result<()> {
    // Create temporary db file.
    let root_path = Builder::new()
        .prefix("test-db")
        .tempdir()
        .unwrap()
        .path()
        .to_str()
        .unwrap()
        .into();

    let key_manager = CryptoBox::new().unwrap();
    let current_b64key = base64::encode_config(key_manager.public_key().key(), base64::URL_SAFE);
    let next_b64key = base64::encode_config(key_manager.next_public_key().key(), base64::URL_SAFE);

    init_kel(root_path, None)?;

    let pk = new_public_key(Basic::Ed25519, current_b64key)?;
    let npk = new_public_key(Basic::Ed25519, next_b64key)?;
    let icp_event = incept(vec![pk], vec![npk], vec![], 0)?;
    let hex_signature = hex::encode(key_manager.sign(icp_event.as_bytes())?);

    // sign icp event
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);

    let identifier = finalize_inception(icp_event, signature)?;
    let data_to_sing = r#"{"hello":"world"}"#;

    let hex_signature = hex::encode(key_manager.sign(data_to_sing.as_bytes())?);

    // sign icp event
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
    let signed = sign_to_cesr(identifier, data_to_sing.to_string(), signature)?;
    println!("signed: {}", &signed);

    assert!(verify_from_cesr(signed)?);

    Ok(())
}

#[test]
pub fn test_signing_verifing() -> Result<()> {
    // Create temporary db file.
    let signing_id_path: String = Builder::new()
        .prefix("test-db")
        .tempdir()
        .unwrap()
        .path()
        .to_str()
        .unwrap()
        .into();

    // Create temporary db file.
    let verifing_id_path: String = Builder::new()
        .prefix("test-db")
        .tempdir()
        .unwrap()
        .path()
        .to_str()
        .unwrap()
        .into();

    init_kel(signing_id_path.clone(), None)?;
    // Tests assumses that witness DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA is listening on http://127.0.0.1:3232
    // It can be run from keriox/components/witness using command:
    // cargo run -- -c ./witness.yaml
    let witness_id = "BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC".to_string();
    let wit_location = r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://127.0.0.1:3232/"}"#.to_string();

    // Setup signing identifier
    let key_manager = CryptoBox::new().unwrap();
    let current_b64key = base64::encode_config(key_manager.public_key().key(), base64::URL_SAFE);
    let next_b64key = base64::encode_config(key_manager.next_public_key().key(), base64::URL_SAFE);

    let pk = new_public_key(Basic::Ed25519, current_b64key)?;
    let npk = new_public_key(Basic::Ed25519, next_b64key)?;
    let icp_event = incept(vec![pk], vec![npk], vec![wit_location.clone()], 1)?;
    let hex_signature = hex::encode(key_manager.sign(icp_event.as_bytes())?);
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
    let signing_identifier = finalize_inception(icp_event, signature)?;
    let oobi = format!(
        r#"{{"cid":"{}","role":"witness","eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"}}"#,
        signing_identifier.id
    );
    println!("\n\noobi: {}\n\n", oobi);

    // Publish own event to witnesses
    notify_witnesses(signing_identifier.clone())?;

    // Quering own mailbox to get receipts
    // TODO always qry mailbox
    let query = query_mailbox(
        signing_identifier.clone(),
        signing_identifier.clone(),
        vec![witness_id.clone()],
    )?;

    for qry in query {
        let hex_signature = hex::encode(key_manager.sign(qry.as_bytes())?);
        let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
        finalize_query(signing_identifier.clone(), qry, signature)?;
    }

    // let signingn_idenifeir_kel = get_kel(signing_identifier.clone())?;

    // Sign data by signing identifier
    let data_to_sing = r#"{"hello":"world"}"#;
    let hex_signature = hex::encode(key_manager.sign(data_to_sing.as_bytes())?);

    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
    let signed = sign_to_cesr(
        signing_identifier.clone(),
        data_to_sing.to_string(),
        signature,
    )?;
    println!("signed: {}", &signed);

    // Simulate using other device, with no signing identifier kel events inside.
    change_controller(verifing_id_path.clone())?;

    // Setup verifing identifier
    let key_manager = CryptoBox::new().unwrap();
    let current_b64key = base64::encode_config(key_manager.public_key().key(), base64::URL_SAFE);
    let next_b64key = base64::encode_config(key_manager.next_public_key().key(), base64::URL_SAFE);

    let pk = new_public_key(Basic::Ed25519, current_b64key)?;
    let npk = new_public_key(Basic::Ed25519, next_b64key)?;
    let icp_event = incept(vec![pk], vec![npk], vec![], 0)?;
    let hex_signature = hex::encode(key_manager.sign(icp_event.as_bytes())?);
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);

    let verifing_identifier = finalize_inception(icp_event, signature)?;

    // Configure watcher for verifing identifier
    let watcher_oobi = r#"{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://localhost:3236/"}"#.to_string();

    let add_watcher_message = add_watcher(verifing_identifier.clone(), watcher_oobi)?;
    println!(
        "\nController generate end role message to add watcher: \n{}",
        add_watcher_message
    );
    let hex_sig = hex::encode(key_manager.sign(add_watcher_message.as_bytes()).unwrap());
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_sig);

    finalize_event(verifing_identifier.clone(), add_watcher_message, signature).unwrap();
    let kel = get_kel(verifing_identifier.clone());
    assert!(kel.is_ok());
    println!("\n\nverifing id kel: {}\n\n", kel.unwrap());

    let kel = get_kel(signing_identifier.clone());
    // Unknown identifier error
    assert!(kel.is_err());

    let stream = format!("{}{}{}", wit_location, oobi, signed);
    let splitted = split_oobis_and_data(stream)?;

    // Provide signing identifier oobi to watcher.
    for oobi in splitted.oobis {
        send_oobi_to_watcher(verifing_identifier.clone(), oobi)?;
    }

    let kel = get_kel(signing_identifier.clone());
    // Unknown identifier error
    assert!(kel.is_err());

    // Query watcher for results of resolving signing identifier oobis. It will provide signing identifier kel events.
    let query = query_watchers(verifing_identifier.clone(), signing_identifier.clone())?;

    for qry in query {
        let hex_signature = hex::encode(key_manager.sign(qry.as_bytes())?);
        let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
        finalize_query(verifing_identifier.clone(), qry, signature)?;
    }

    let kel = get_kel(signing_identifier.clone());
    assert!(kel.is_ok());

    // Verify provied signed message.
    for acdc in splitted.credentials {
        assert!(verify_from_cesr(acdc).unwrap());
    }

    Ok(())
}
