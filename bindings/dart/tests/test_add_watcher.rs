use anyhow::Result;
use dartkeriox::api::{add_watcher, init_kel, Identifier};

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
        Identifier::new_from_str("EM7ml1EF4PNuuA8leM7ec0E95ukz5oBf3-gAjHEvQgsc".to_string())?;

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
