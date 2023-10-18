use anyhow::Result;
use cesrox::primitives::codes::{basic::Basic, self_signing::SelfSigning};
use cesrox::primitives::CesrPrimitive;
use dartkeriox::api::{
    anchor, anchor_digest, finalize_event, finalize_inception, get_kel, incept, init_kel,
    new_public_key, process_stream, rotate, signature_from_hex, Identifier,
};
use keri::signer::CryptoBox;
use keri::signer::KeyManager;
use said::derivation::{HashFunction, HashFunctionCode};
use tempfile::Builder;

#[test]
pub fn test_incept() -> Result<()> {
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
pub fn test_kel() -> Result<()> {
    use dartkeriox::api::{finalize_inception, get_kel, incept, init_kel};
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
