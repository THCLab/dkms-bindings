use anyhow::Result;

#[test]
pub fn test_api() -> Result<()> {
    use crate::api::{
        finalize_inception, get_kel, incept, init_kel, KeyType, PublicKey, Signature, SignatureType,
    };
    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let public_key = "AtGFZ859eFY4miPzIa2/S+qehC2d4QRAtPJoCLmO7bs=";
    let next_public_key = "iyeqxcd9P48e0bFXAAdWjSO83CNwNKxbnyoYnFGJx6U=";
    let sig_hex = "08C00CA0FCEFD34FF57D28D19D3CE08399B5149D93B652DCA399D8E26BDDB668C44D28159E3B59E15AE3FA1CF1E05BACDCEC9778BAB419593F3BE0D77E01420A".as_bytes();

    init_kel(root.path().to_str().unwrap().into())?;

    let pk = PublicKey::new(KeyType::Ed25519, public_key);
    let npk = PublicKey::new(KeyType::Ed25519, next_public_key);
    let icp_event = incept(vec![pk], vec![npk], vec![], 0)?;
    println!("icp event: {}", icp_event);

    // // sign icp event
    // let signature = "";
    // let signature = Signature::new(SignatureType::Ed25519Sha512, signature);

    // let controller = finalize_inception(icp_event, signature)?;
    // let kel = get_kel(controller.get_id())?;
    Ok(())
}
