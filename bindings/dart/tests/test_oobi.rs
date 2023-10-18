use anyhow::Result;
use dartkeriox::api::{init_kel, resolve_oobi};

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
