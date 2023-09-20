use anyhow::Result;
use cesrox::primitives::codes::{basic::Basic, self_signing::SelfSigning};
use keri::signer::{CryptoBox, KeyManager};
use tempfile::Builder;

use dartkeriox::api::{
    add_messagebox, change_controller, finalize_event, finalize_inception, get_messagebox, incept,
    init_kel, new_public_key, resolve_oobi, signature_from_hex,
};

#[test]
fn test_messagebox_setup() -> Result<()> {
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

    // Incept identifier
    let icp_event = incept(vec![pk], vec![npk], vec![], 0)?;
    let hex_signature = hex::encode(key_manager.sign(icp_event.as_bytes())?);
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
    let signing_identifier = finalize_inception(icp_event, signature)?;

    // Identifier1 adds messagebox
    let messagebox_oobi = r#"{"eid":"BFY1nGjV9oApBzo5Oq5JqjwQsZEQqsCCftzo3WJjMMX-","scheme":"http","url":"http://messagebox.sandbox.argo.colossi.network/"}"#.to_string();
    let messagebox_id = "BFY1nGjV9oApBzo5Oq5JqjwQsZEQqsCCftzo3WJjMMX-";

    // Generate reply that contains end role message inside.
    let add_messagebox = add_messagebox(signing_identifier.clone(), messagebox_oobi.clone())?;

    let add_message_box_sig = hex::encode(key_manager.sign(add_messagebox.as_bytes())?);
    let signature = signature_from_hex(SelfSigning::Ed25519Sha512, add_message_box_sig);

    // Sign and send message to messagebox.
    finalize_event(signing_identifier.clone(), add_messagebox, signature)?;

    let saved_messagebox_location = get_messagebox(signing_identifier.to_str())?;

    assert_eq!(saved_messagebox_location[0], messagebox_oobi);

    // Simulate using other device, with no signing identifier data inside.
    change_controller(verifing_id_path.clone())?;

    // Don't need identifier to resolve oobis and save them, because we skip verification for now.
    let saved_messagebox_location = get_messagebox(signing_identifier.id.clone())?;
    assert!(saved_messagebox_location.is_empty());

    let end_role_oobi = format!(
        r#"{{"cid":"{}","role":"messagebox","eid":"{}"}}"#,
        &signing_identifier.id, &messagebox_id
    );
    // Resolve oobis that specify messagebox of identifier1
    resolve_oobi(messagebox_oobi.clone())?;
    resolve_oobi(end_role_oobi.clone())?;

    // Check saved identifier1 messagebox information.
    let saved_messagebox_location = get_messagebox(signing_identifier.id)?;

    assert_eq!(saved_messagebox_location[0], messagebox_oobi);

    Ok(())
}
