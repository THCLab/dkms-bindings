use anyhow::Result;
use cesrox::primitives::codes::{basic::Basic, self_signing::SelfSigning};
use keri::signer::{CryptoBox, KeyManager};
use tempfile::Builder;

use dartkeriox::api::{
    add_watcher, change_controller, finalize_event, finalize_inception, finalize_query, get_kel,
    incept, init_kel, new_public_key, notify_witnesses, query_mailbox, query_watchers,
    send_oobi_to_watcher, sign_to_cesr, signature_from_hex, split_oobis_and_data, verify_from_cesr,
};

#[test]
pub fn test_sign_verify() -> Result<()> {
    use dartkeriox::api::to_cesr_signature;
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
    let signed = sign_to_cesr(
        identifier.clone(),
        data_to_sing.to_string(),
        signature.clone(),
    )?;
    println!("signed: {}", &signed);

    let signed = to_cesr_signature(identifier, signature)?;
    println!("\n\nsignature: {}", &signed);

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
    let wit_location = r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://witness1.sandbox.argo.colossi.network/"}"#.to_string();

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
    // let watcher_oobi = r#"{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://localhost:3236/"}"#.to_string();
    let watcher_oobi = r#"{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://watcher.sandbox.argo.colossi.network/"}"#.to_string();

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
