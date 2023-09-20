use anyhow::Result;
use cesrox::primitives::codes::{basic::Basic, self_signing::SelfSigning};
use dartkeriox::api::{new_public_key, signature_from_hex, Config};

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
pub fn test_optional_config() -> Result<()> {
    use dartkeriox::api::init_kel;
    use tempfile::Builder;

    // Create temporary db file.
    let root_path = Builder::new()
        .prefix("test-db")
        .tempdir()
        .unwrap()
        .into_path();

    // let config = Config {
    //     initial_oobis: "random".into(),
    // };
    // let oc = config.build(root_path.clone());
    // assert!(oc.is_err());

    let config = Config { initial_oobis: r#"[{"eid":"BKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ","scheme":"http","url":"http://127.0.0.1:0/"}]"#.into() };

    // Fail to resolve oobi
    let result = init_kel(root_path.to_str().unwrap().into(), Some(config));
    assert!(result.is_err());

    Ok(())
}
