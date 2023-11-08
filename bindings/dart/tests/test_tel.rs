use anyhow::Result;
use cesrox::primitives::codes::{basic::Basic, self_signing::SelfSigning};
use keri::signer::{CryptoBox, KeyManager};
use said::derivation::{HashFunction, HashFunctionCode};
use tempfile::Builder;

use dartkeriox::api::{
    change_controller, finalize_event, finalize_inception, finalize_query, finalize_tel_query,
    get_credential_state, get_kel, incept, incept_registry, init_kel, issue_credential,
    new_public_key, notify_backers, notify_witnesses, process_stream, query_mailbox, query_tel,
    revoke_credential, signature_from_hex, Identifier, IssuanceData, RegistryData,
};

fn collect_receipts(
    identifier: &Identifier,
    witness_ids: Vec<String>,
    key_manager: &CryptoBox,
) -> Result<()> {
    // Publish own event to witnesses
    notify_witnesses(identifier.clone())?;

    // Quering own mailbox to get receipts
    // TODO always qry mailbox
    let query = query_mailbox(identifier.clone(), identifier.clone(), witness_ids)?;

    for qry in query {
        let hex_signature = hex::encode(key_manager.sign(qry.as_bytes())?);
        let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
        finalize_query(identifier.clone(), qry, signature)?;
    }
    Ok(())
}

#[test]
fn test_tel() -> Result<()> {
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

    // Setup signing identifier
    let key_manager = CryptoBox::new().unwrap();
    let current_b64key = base64::encode_config(key_manager.public_key().key(), base64::URL_SAFE);
    let next_b64key = base64::encode_config(key_manager.next_public_key().key(), base64::URL_SAFE);

    let pk = new_public_key(Basic::Ed25519, current_b64key)?;
    let npk = new_public_key(Basic::Ed25519, next_b64key)?;

    // Tests assumses that witness BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC is listening on http://127.0.0.1:3232
    // It can be run from keriox/components/witness using command:
    // cargo run -- -c ./src/witness.json
    let witness_id = "BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC".to_string();
    // let wit_location = r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://127.0.0.1:3232/"}"#.to_string();
    let wit_location = r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://witness1.sandbox.argo.colossi.network/"}"#.to_string();
    // Incept identifier
    let icp_event = incept(vec![pk], vec![npk], vec![wit_location.clone()], 1)?;
    let hex_signature = hex::encode(key_manager.sign(icp_event.as_bytes())?);
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
    let signing_identifier = finalize_inception(icp_event, signature)?;
    collect_receipts(&signing_identifier, vec![witness_id.clone()], &key_manager)?;

    // Incept Registry
    let RegistryData { registry_id, ixn } = incept_registry(signing_identifier.clone())?;
    let hex_signature = hex::encode(key_manager.sign(ixn.as_bytes())?);
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
    finalize_event(signing_identifier.clone(), ixn, signature)?;
    collect_receipts(&signing_identifier, vec![witness_id.clone()], &key_manager)?;

    // Issue
    let message = format!("{} said hello", &signing_identifier.id);
    let message_sai = HashFunction::from(HashFunctionCode::Blake3_256).derive(message.as_bytes());
    let IssuanceData { vc_id, ixn } = issue_credential(signing_identifier.clone(), message_sai.to_string())?;

    // Ixn not eut accepted so vc is not issued yet.
    let state = get_credential_state(signing_identifier.clone(), vc_id.clone())?;
    assert_eq!(state, None);

    let hex_signature = hex::encode(key_manager.sign(ixn.as_bytes())?);
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
    finalize_event(signing_identifier.clone(), ixn, signature)?;
    collect_receipts(&signing_identifier, vec![witness_id.clone()], &key_manager)?;

    let state = get_credential_state(signing_identifier.clone(), vc_id.clone())?;
    assert!(state.unwrap().contains("Issued"));

    // Revoke
    let ixn = revoke_credential(signing_identifier.clone(), vc_id.clone())?;
    let hex_signature = hex::encode(key_manager.sign(ixn.as_bytes())?);
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
    finalize_event(signing_identifier.clone(), ixn, signature)?;
    collect_receipts(&signing_identifier, vec![witness_id.clone()], &key_manager)?;

    let state = get_credential_state(signing_identifier.clone(), vc_id.clone())?;
    assert_eq!(state, Some("Revoked".to_string()));

    let signing_id_kel = get_kel(signing_identifier.clone())?;

    // publish tel events so other identifier can find them
    notify_backers(signing_identifier.clone())?;

    // Simulate using other device, with no signing identifier kel events inside.
    change_controller(verifing_id_path.clone())?;

    // Setup verifing identifier
    let key_manager = CryptoBox::new().unwrap();
    let current_b64key = base64::encode_config(key_manager.public_key().key(), base64::URL_SAFE);
    let next_b64key = base64::encode_config(key_manager.next_public_key().key(), base64::URL_SAFE);

    let pk = new_public_key(Basic::Ed25519, current_b64key)?;
    let npk = new_public_key(Basic::Ed25519, next_b64key)?;
    let icp_event = incept(vec![pk], vec![npk], vec![wit_location], 1)?;
    let hex_signature = hex::encode(key_manager.sign(icp_event.as_bytes())?);
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);

    let verifing_identifier = finalize_inception(icp_event, signature)?;
    collect_receipts(&verifing_identifier, vec![witness_id.clone()], &key_manager)?;
    // TODO query tel
    let query_tel = query_tel(verifing_identifier.clone(), registry_id, vc_id.clone())?;
    let hex_signature = hex::encode(key_manager.sign(query_tel.as_bytes())?);
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
    finalize_tel_query(verifing_identifier.clone(), query_tel, signature)?;
    process_stream(signing_id_kel)?;

    let state = get_credential_state(signing_identifier, vc_id).unwrap();
    assert_eq!(state, Some("Revoked".to_string()));

    Ok(())
}
