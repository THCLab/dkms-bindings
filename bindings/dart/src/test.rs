use anyhow::Result;

#[test]
pub fn test_api() -> Result<()> {
    use crate::api::{
        finalize_inception, get_kel, incept, init_kel, KeyType, PublicKey, Signature, SignatureType,
    };
    use tempfile::Builder;

    // Create temporary db file.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let public_key = "6UMthURGxkWVEKxJ/m3OpgV3Be/STsM//4tONKaiTrA=";
    let next_public_key = "xeIGdSW6mJsPqFysR6diH0/4lXXgyy36Hb9BzcLOp+s=";

    init_kel(root.path().to_str().unwrap().into())?;

    let pk = PublicKey::new(KeyType::Ed25519, public_key);
    let npk = PublicKey::new(KeyType::Ed25519, next_public_key);
    let icp_event = incept(vec![pk], vec![npk], vec![], 0)?;

    // sign icp event
    let signature = "F426738DFEC3EED52D36CB2B825ADFB3D06D98B3AF986EAE2F70B8E536C60C1C7DC41E49D30199D107AB57BD43D458A14064AB3A963A51450DBDE253CD94BB0C".to_string();
    let signature = Signature::new(SignatureType::Ed25519Sha512, signature);

    let controller = finalize_inception(icp_event, signature)?;
    let kel = get_kel(controller.get_id())?;
    println!("kel: {}", kel);
    Ok(())
}
