use anyhow::Result;
use cesrox::primitives::codes::{basic::Basic, self_signing::SelfSigning};
use keri::signer::{CryptoBox, KeyManager};
use tempfile::Builder;

use dartkeriox::api::{
    change_controller, finalize_group_incept, finalize_query, incept_group, new_public_key,
    notify_witnesses, process_stream, query_mailbox, signature_from_hex, Action, DataAndSignature,
};

#[test]
pub fn test_multisig() -> Result<()> {
    use dartkeriox::api::{finalize_inception, get_kel, incept, init_kel};

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
    let wit_location = r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://witness1.sandbox.argo.colossi.network/"}"#.to_string();

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
