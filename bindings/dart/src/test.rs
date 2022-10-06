use anyhow::Result;
use keri::{
    derivation::self_addressing::SelfAddressing,
    prefix::Prefix,
    signer::{CryptoBox, KeyManager},
};
use tempfile::Builder;

use crate::api::{
    add_watcher, anchor, anchor_digest, change_controller, finalize_event, finalize_group_incept,
    finalize_mailbox_query, get_kel, incept_group, init_kel, process_stream, query_mailbox,
    resolve_oobi, rotate, Action, Config, DataAndSignature, DigestType, Identifier,
};

#[test]
pub fn test_api() -> Result<()> {
    use crate::api::{
        finalize_inception, get_kel, incept, init_kel, KeyType, PublicKey, Signature, SignatureType,
    };
    use tempfile::Builder;

    // Create temporary db file.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let public_key = "6UMthURGxkWVEKxJ/m3OpgV3Be/STsM//4tONKaiTrA=".to_string();
    let next_public_key = "xeIGdSW6mJsPqFysR6diH0/4lXXgyy36Hb9BzcLOp+s=".to_string();

    init_kel(root.path().to_str().unwrap().into(), None)?;

    let pk = PublicKey::new(KeyType::Ed25519NT, public_key);
    let npk = PublicKey::new(KeyType::Ed25519NT, next_public_key.into());
    // println!("pk: {:?}", key_prefix_from_b64(&pk.key, pk.algorithm).unwrap().to_str());
    let icp_event = incept(vec![pk], vec![npk], vec![], 0)?;
    println!("icp: {}", icp_event);

    // sign icp event
    let signature = "F426738DFEC3EED52D36CB2B825ADFB3D06D98B3AF986EAE2F70B8E536C60C1C7DC41E49D30199D107AB57BD43D458A14064AB3A963A51450DBDE253CD94BB0C".to_string();
    let signature = Signature::new_from_hex(SignatureType::Ed25519Sha512, signature);

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

    // let test_kel = r#"{"v":"KERI10JSON0001b7_","t":"icp","d":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","i":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","s":"0","kt":"1","k":["DruZ2ykSgEmw2EHm34wIiEGsUa_1QkYlsCAidBSzUkTU"],"nt":"1","n":["Eao8tZQinzilol20Ot-PPlVz6ta8C4z-NpDOeVs63U8s"],"bt":"3","b":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"],"c":[],"a":[]}-VBq-AABAA0EpZtBNLxOIncUDeLgwX3trvDXFA5adfjpUwb21M5HWwNuzBMFiMZQ9XqM5L2bFUVi6zXomcYuF-mR7CFpP8DQ-BADAAWUZOb17DTdCd2rOaWCf01ybl41U7BImalPLJtUEU-FLrZhDHls8iItGRQsFDYfqft_zOr8cNNdzUnD8hlSziBwABmUbyT6rzGLWk7SpuXGAj5pkSw3vHQZKQ1sSRKt6x4P13NMbZyoWPUYb10ftJlfXSyyBRQrc0_TFqfLTu_bXHCwACKPLkcCa_tZKalQzn3EgZd1e_xImWdVyzfYQmQvBpfJZFfg2c-sYIL3zl1WHpMQQ_iDmxLSmLSQ9jZ9WAjcmDCg-EAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-04-11T20c50c16d643400p00c00{"v":"KERI10JSON00013a_","t":"ixn","d":"Ek48ahzTIUA1ynJIiRd3H0WymilgqDbj8zZp4zzrad-w","i":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","s":"1","p":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","a":[{"i":"EoLNCdag8PlHpsIwzbwe7uVNcPE1mTr-e1o9nCIDPWgM","s":"0","d":"EoLNCdag8PlHpsIwzbwe7uVNcPE1mTr-e1o9nCIDPWgM"}]}-VBq-AABAAZZlCpwL0QwqF-eTuqEgfn95QV9S4ruh4wtxKQbf1-My60Nmysprv71y0tJGEHkMsUBRz0bf-JZsMKyZ3N8m7BQ-BADAA6ghW2PpLC0P9CxmW13G6AeZpHinH-_HtVOu2jWS7K08MYkDPrfghmkKXzdsMZ44RseUgPPty7ZEaAxZaj95bAgABKy0uBR3LGMwg51xjMZeVZcxlBs6uARz6quyl0t65BVrHX3vXgoFtzwJt7BUl8LXuMuoM9u4PQNv6yBhxg_XEDwACJe4TwVqtGy1fTDrfPxa14JabjsdRxAzZ90wz18-pt0IwG77CLHhi9vB5fF99-fgbYp2Zoa9ZVEI8pkU6iejcDg-EAB0AAAAAAAAAAAAAAAAAAAAAAQ1AAG2022-04-11T20c50c22d909900p00c00{"v":"KERI10JSON00013a_","t":"ixn","d":"EPYT0dEpoc_5QKIGnRYFRqpXHGpeYOhveJTmHoVC6LMU","i":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","s":"2","p":"Ek48ahzTIUA1ynJIiRd3H0WymilgqDbj8zZp4zzrad-w","a":[{"i":"EzSVC7-SuizvdVkpXmHQx5FhUElLjUOjCbgN81ymeWOE","s":"0","d":"EQ6RIFoVUDmmyuoMDMPPHDm14GtXaIf98j4AG2vNfZ1U"}]}-VBq-AABAAYycRM_VyvV2fKyHdUceMcK8ioVrBSixEFqY1nEO9eTZQ2NV8hrLc_ux9_sKn1p58kyZv5_y2NW3weEiqn-5KAA-BADAAQl22xz4Vzkkf14xsHMAOm0sDkuxYY8SAgJV-RwDDwdxhN4WPr-3Pi19x57rDJAE_VkyYwKloUuzB5Dekh-JzCQABk98CK_xwG52KFWt8IEUU-Crmf058ZJPB0dCffn-zjiNNgjv9xyGVs8seb0YGInwrB351JNu0sMHuEEgPJLKxAgACw556h2q5_BG6kPHAF1o9neMLDrZN_sCaJ-3slWWX-y8M3ddPN8Zp89R9A36t3m2rq-sbC5h_UDg5qdnrZ-ZxAw-EAB0AAAAAAAAAAAAAAAAAAAAAAg1AAG2022-04-11T20c50c23d726188p00c00"#;
    let test_kel = r#"{"v":"KERI10JSON0001e7_","t":"icp","d":"EZrJQSdhdiyXNpEzHo-dR0EEbLfcIopBSImdLnQGOKkg","i":"EZrJQSdhdiyXNpEzHo-dR0EEbLfcIopBSImdLnQGOKkg","s":"0","kt":"2","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"nt":"2","n":["E_IkdcjsIFrFba-LS1sJDjpec_4vM3XtIPa6D51GcUIw","EU28GjHFKeXzncPxgwlHQZ0iO7f09Y89vy-3VkZ23bBI","E2PRzip7UZ5UTA_1ucb5eoAzxeRS3sIThrSbZhdRaZY8"],"bt":"0","b":[],"c":[],"a":[]}-AADAAzclB26m4VWp5R8ANlTU2qhqE6GA9siAK_vhtqtNNR6qhVed-xEoXRadnL5Jc0kxPZi8XUqSk5KSaOnke_SxXDAABX--x4JGI0Dp0Ran-t1LMg3NEgizu1Jb85LTImofYqD6jz9w5TTPNAmj7rfIFvd4mfJ_ioH0Z0mzLWuIvTIFCBAACQTiHacY3flY9y_Wup66bNzcyQvJUT-WGkv4CPgqkMwq5mOEFf2ps74bur1AE9OSGgrEBlcOQ9HWuTcr80FMKCg{"v":"KERI10JSON00021c_","t":"rot","d":"EcR5L1yzQeSOFBdFwmWouiEMzCFC6GhJ28Q2RWta4GxQ","i":"EZrJQSdhdiyXNpEzHo-dR0EEbLfcIopBSImdLnQGOKkg","s":"1","p":"EZrJQSdhdiyXNpEzHo-dR0EEbLfcIopBSImdLnQGOKkg","kt":"2","k":["DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ","D1kcBE7h0ImWW6_Sp7MQxGYSshZZz6XM7OiUE5DXm0dU","D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM"],"nt":"2","n":["E2PRzip7UZ5UTA_1ucb5eoAzxeRS3sIThrSbZhdRaZY8","Ea450np2ffBYk-mkVaxPk9h17OykLKqEkGrBFKomwe1A","EcNDEzyAJJsUOCa2YIBE3N-8KtpsZBShxxXhddAGVFko"],"bt":"0","br":[],"ba":[],"a":[]}-AADAAZte0g5dCVxAD4qxbBf-Y8uLqMu-4NlrqoVi1FR2JxmZuHAXU-8BUhEJ7z8nxPycvTBJW7kXR30Wyk19GVm-fBwAB8NydT0xIWiYLPuavDpzlZZrYVF_nFgBgf-joxH0FSmyTuDEDhwz9H6b0EY47PhQeJ6cy6PtH8AXK_HVZ2yojDwACeHxfXD8MNjnqjkl0JmpFHNwlif7V0_DjUx3VHkGjDcMfW2bCt16jRW0Sefh45sb4ZXHfMNZ1vmwhPv1L5lNGDA"#;

    process_stream(test_kel.to_string())?;
    let identifier =
        Identifier::from_str("EZrJQSdhdiyXNpEzHo-dR0EEbLfcIopBSImdLnQGOKkg".to_string())?;
    let kel = get_kel(identifier)?;
    println!("kel: {}", kel);

    Ok(())
}

#[test]
pub fn test_optional_config() -> Result<()> {
    use crate::api::init_kel;
    use tempfile::Builder;

    // Create temporary db file.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();

    let config = Config {
        initial_oobis: "random".into(),
    };
    let oc = config.build();
    assert!(oc.is_err());

    let config = Config { initial_oobis: r#"[{"eid":"BKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ","scheme":"http","url":"http://127.0.0.1:0/"}]"#.into() };

    // Fail to resolve oobi
    let result = init_kel(root.path().to_str().unwrap().into(), Some(config));
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
        Identifier::from_str("EM7ml1EF4PNuuA8leM7ec0E95ukz5oBf3-gAjHEvQgsc".to_string())?;

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
    use crate::api::{
        finalize_inception, get_kel, incept, init_kel, KeyType, PublicKey, Signature, SignatureType,
    };

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
    let witness_id = "DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA".to_string();
    let wit_location = r#"{"eid":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","scheme":"http","url":"http://127.0.0.1:3232/"}"#.to_string();

    // Incept first group participant
    let key_manager = CryptoBox::new().unwrap();
    let current_b64key = base64::encode(key_manager.public_key().key());
    let next_b64key = base64::encode(key_manager.next_public_key().key());

    let pk = PublicKey::new(KeyType::Ed25519, current_b64key);
    let npk = PublicKey::new(KeyType::Ed25519, next_b64key);
    let icp_event = incept(vec![pk], vec![npk], vec![wit_location.clone()], 1)?;
    let hex_signature = hex::encode(key_manager.sign(icp_event.as_bytes())?);

    let signature = Signature::new_from_hex(SignatureType::Ed25519Sha512, hex_signature);
    let identifier = finalize_inception(icp_event, signature)?;

    // Quering own mailbox to get receipts
    // TODO always qry mailbox
    let query = query_mailbox(
        identifier.clone(),
        identifier.clone(),
        vec![witness_id.clone()],
    )?;

    for qry in query {
        let hex_signature = hex::encode(key_manager.sign(qry.as_bytes())?);
        let signature = Signature::new_from_hex(SignatureType::Ed25519Sha512, hex_signature);
        finalize_mailbox_query(identifier.clone(), qry, signature)?;
    }

    let initiator_kel = get_kel(identifier.clone())?;
    println!("\ninitiator's kel: {}", initiator_kel);

    change_controller(root_path2.clone())?;
    process_stream(initiator_kel)?;
    // Incept second group participant
    let participants_key_manager = CryptoBox::new().unwrap();
    let current_b64key = base64::encode(participants_key_manager.public_key().key());
    let next_b64key = base64::encode(participants_key_manager.next_public_key().key());

    let participant_pk = PublicKey::new(KeyType::Ed25519, current_b64key);
    let participant_npk = PublicKey::new(KeyType::Ed25519, next_b64key);
    let icp_event = incept(
        vec![participant_pk],
        vec![participant_npk],
        vec![wit_location.clone()],
        1,
    )?;
    let hex_signature = hex::encode(participants_key_manager.sign(icp_event.as_bytes())?);
    let signature = Signature::new_from_hex(SignatureType::Ed25519Sha512, hex_signature);

    let participant = finalize_inception(icp_event, signature)?;

    // Quering own mailbox to get receipts
    let query = query_mailbox(
        participant.clone(),
        participant.clone(),
        vec![witness_id.clone()],
    )?;

    for qry in query {
        let hex_signature = hex::encode(participants_key_manager.sign(qry.as_bytes())?);
        let signature = Signature::new_from_hex(SignatureType::Ed25519Sha512, hex_signature);
        finalize_mailbox_query(participant.clone(), qry, signature)?;
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
    let signature = Signature::new_from_hex(SignatureType::Ed25519Sha512, hex_signature);

    // sign exchanges to forward it to other participants
    let exn_signature = hex::encode(key_manager.sign(icp.exchanges[0].as_bytes())?);
    let exn_signature = Signature::new_from_hex(SignatureType::Ed25519Sha512, exn_signature);

    let group_identifier = finalize_group_incept(
        identifier.clone(),
        icp.icp_event,
        signature,
        vec![DataAndSignature {
            data: icp.exchanges[0].clone(),
            signature: exn_signature,
        }],
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
    let signature = Signature::new_from_hex(SignatureType::Ed25519Sha512, hex_signature);
    // here second time the same multisig icp is processed
    let action_required = finalize_mailbox_query(participant.clone(), qry, signature)?;
    assert_eq!((&action_required).len(), 1);

    let action = &action_required[0];
    match action.action {
        Action::MultisigRequest => {
            // sign icp event by participant
            let hex_signature = hex::encode(participants_key_manager.sign(action.data.as_bytes())?);
            let signature = Signature::new_from_hex(SignatureType::Ed25519Sha512, hex_signature);

            let exn_signature =
                hex::encode(participants_key_manager.sign(action.additiona_data.as_bytes())?);
            let exn_signature =
                Signature::new_from_hex(SignatureType::Ed25519Sha512, exn_signature);

            let group_controller = finalize_group_incept(
                participant.clone(),
                action.data.clone(),
                signature,
                vec![DataAndSignature {
                    data: action.additiona_data.clone(),
                    signature: exn_signature,
                }],
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
    let signature = Signature::new_from_hex(SignatureType::Ed25519Sha512, hex_signature);
    let action_required = finalize_mailbox_query(identifier.clone(), qry, signature);
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
    let signature = Signature::new_from_hex(SignatureType::Ed25519Sha512, hex_signature);
    let action_required = finalize_mailbox_query(identifier, qry, signature);
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
    let signature = Signature::new_from_hex(SignatureType::Ed25519Sha512, hex_signature);
    let action_required = finalize_mailbox_query(participant, qry, signature);
    assert_eq!((&action_required?).len(), 0);

    // Group inception should be accepted now.
    let kel = get_kel(group_identifier);
    assert!(kel.is_ok());

    Ok(())
}

#[test]
pub fn test_demo() -> Result<()> {
    use crate::api::{
        finalize_inception, get_kel, incept, init_kel, KeyType, PublicKey, Signature, SignatureType,
    };
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
    let current_b64key = base64::encode(key_manager.public_key().key());
    let next_b64key = base64::encode(key_manager.next_public_key().key());

    init_kel(root_path, None)?;

    let pk = PublicKey::new(KeyType::Ed25519, current_b64key);
    let npk = PublicKey::new(KeyType::Ed25519, next_b64key);
    let icp_event = incept(vec![pk], vec![npk], vec![], 0)?;
    let hex_signature = hex::encode(key_manager.sign(icp_event.as_bytes())?);

    // sign icp event
    let signature = Signature::new_from_hex(SignatureType::Ed25519Sha512, hex_signature);

    let controller = finalize_inception(icp_event, signature)?;

    key_manager.rotate()?;
    let current_b64key = base64::encode(key_manager.public_key().key());
    let next_b64key = base64::encode(key_manager.next_public_key().key());
    let pk = PublicKey::new(KeyType::Ed25519, current_b64key);
    let npk = PublicKey::new(KeyType::Ed25519, next_b64key);
    let rotation_event = rotate(controller.clone(), vec![pk], vec![npk], vec![], vec![], 0)?;

    let hex_signature = hex::encode(key_manager.sign(rotation_event.as_bytes())?);

    // sign rot event
    let signature = Signature::new_from_hex(SignatureType::Ed25519Sha512, hex_signature);

    println!("rotation: \n{}", rotation_event);

    assert!(finalize_event(controller.clone(), "random data".into(), signature.clone()).is_err());

    finalize_event(controller.clone(), rotation_event, signature)?;

    let sai = SelfAddressing::Blake3_256
        .derive("some data".as_bytes())
        .to_str();
    let ixn_event = anchor_digest(controller.clone(), vec![sai])?;
    println!("\nixn: {}", ixn_event);

    let hex_signature = hex::encode(key_manager.sign(ixn_event.as_bytes())?);
    // sign rot event
    let signature = Signature::new_from_hex(SignatureType::Ed25519Sha512, hex_signature);
    finalize_event(controller.clone(), ixn_event, signature)?;

    let ixn_event = anchor(
        controller.clone(),
        "some data".into(),
        DigestType::Blake3_256,
    )?;
    println!("\nixn: {}", ixn_event);

    let hex_signature = hex::encode(key_manager.sign(ixn_event.as_bytes())?);
    // sign rot event
    let signature = Signature::new_from_hex(SignatureType::Ed25519Sha512, hex_signature);
    finalize_event(controller.clone(), ixn_event, signature)?;

    let kel = get_kel(controller.clone())?;
    println!("\nCurrent controller kel: \n{}", kel);

    // let watcher_oobi = r#"{"eid":"BKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ","scheme":"http","url":"http://sandbox.argo.colossi.network:3236/"}"#.into();

    // let add_watcher_message = add_watcher(controller.clone(), watcher_oobi)?;
    // println!(
    //     "\nController generate end role message to add watcher: \n{}",
    //     add_watcher_message
    // );
    // let hex_sig = hex::encode(key_manager.sign(add_watcher_message.as_bytes()).unwrap());
    // let signature = Signature::new_from_hex(SignatureType::Ed25519Sha512, hex_sig);

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
