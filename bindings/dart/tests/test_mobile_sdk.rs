use std::sync::{Arc, Mutex};

#[test]
fn test_sdk_init_and_key_provider_registration() {
    let dir = tempfile::tempdir().unwrap();
    let mut sdk = dartkeriox::api::KeriMobileSdk::new(dir.path().to_str().unwrap().to_string()).unwrap();

    let keys: Arc<Mutex<Vec<(String, Vec<u8>)>>> = Arc::new(Mutex::new(vec![]));
    let keys_clone = keys.clone();

    sdk.register_key_provider(
        move |label: String, _algo: String| {
            let pk = vec![1u8; 32];
            keys_clone.lock().unwrap().push((label, pk.clone()));
            Ok(pk)
        },
        {
            let keys = keys.clone();
            move |label: String| {
                keys.lock()
                    .unwrap()
                    .iter()
                    .find(|(l, _)| l == &label)
                    .map(|(_, pk)| pk.clone())
                    .ok_or_else(|| anyhow::anyhow!("key not found: {label}"))
            }
        },
        {
            move |_label: String, msg: Vec<u8>| {
                let mut sig = vec![0u8; 64];
                if !msg.is_empty() {
                    sig[0] = msg[0];
                }
                Ok(sig)
            }
        },
        {
            let keys = keys.clone();
            move |label: String| {
                keys.lock().unwrap().retain(|(l, _)| l != &label);
                Ok(())
            }
        },
        {
            let keys = keys.clone();
            move || {
                Ok(keys.lock().unwrap().iter().map(|(l, _)| l.clone()).collect())
            }
        },
    );

    assert!(sdk.list_aliases().unwrap().is_empty());
}

#[test]
fn test_types_roundtrip() {
    use dartkeriox::types::*;

    let config = FfiIdentifierConfig {
        witness_urls: vec!["http://example.com".to_string()],
        witness_threshold: 1,
        watcher_urls: vec![],
    };
    assert_eq!(config.witness_threshold, 1);

    let status = FfiCredentialStatus::Unknown;
    assert_eq!(status, FfiCredentialStatus::Unknown);

    let rotation = FfiRotationConfig {
        new_next_pk_b64: "test".to_string(),
        witness_to_add: vec![],
        witness_to_remove: vec![],
        witness_threshold: 0,
    };
    assert_eq!(rotation.witness_threshold, 0);
}

#[tokio::test]
async fn test_host_callback_key_provider() {
    use keri_keyprovider::{host::HostKeyProviderFactory, KeyProvider, KeyProviderFactory, SignatureAlgorithm};

    let keys: Arc<Mutex<Vec<(String, Vec<u8>)>>> = Arc::new(Mutex::new(vec![]));

    let factory = {
        let keys_c = keys.clone();
        let keys_c2 = keys.clone();
        let keys_c3 = keys.clone();
        let keys_c4 = keys.clone();

        HostKeyProviderFactory::new(
            move |label: &str, _algo: SignatureAlgorithm| {
                let pk = vec![2u8; 32];
                keys_c.lock().unwrap().push((label.to_string(), pk.clone()));
                Ok(keri_keyprovider::PublicKeyData::ed25519(pk))
            },
            move |label: &str| {
                keys_c2
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|(l, _)| l == label)
                    .map(|(_, pk)| keri_keyprovider::PublicKeyData::ed25519(pk.clone()))
                    .ok_or_else(|| keri_keyprovider::KeyProviderError::NotFound(label.to_string()))
            },
            |_label: &str, msg: &[u8]| {
                let mut sig = vec![0u8; 64];
                if !msg.is_empty() {
                    sig[0] = msg[0];
                }
                Ok(sig)
            },
            move |label: &str| {
                keys_c3.lock().unwrap().retain(|(l, _)| l != label);
                Ok(())
            },
            move || {
                Ok(keys_c4.lock().unwrap().iter().map(|(l, _)| l.clone()).collect())
            },
        )
    };

    let provider = factory.create("test", SignatureAlgorithm::Ed25519).await.unwrap();
    assert_eq!(provider.label(), "test");
    assert_eq!(provider.public_key().bytes, vec![2u8; 32]);

    let sig = provider.sign(b"hello").await.unwrap();
    assert_eq!(sig.len(), 64);
    assert_eq!(sig[0], b'h');

    assert_eq!(factory.list().await.unwrap(), vec!["test"]);

    let opened = factory.open("test").await.unwrap();
    assert_eq!(opened.label(), "test");

    factory.delete("test").await.unwrap();
    assert!(factory.list().await.unwrap().is_empty());
}
