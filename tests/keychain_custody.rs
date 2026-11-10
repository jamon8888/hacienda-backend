use std::collections::HashMap;

use hacienda_backend::config::{AssuranceMode, EncryptionConfig, KmsConfig};
use hacienda_backend::custody::{DocumentIdentity, seal_custody, verify_and_decrypt};
use hacienda_backend::dual_store::EngineEraFingerprint;
use hacienda_backend::encryption::FixtureVaultKeyProvider;

fn fixture_snapshot() -> Vec<u8> {
    gaze::Session::new(gaze::Scope::Conversation("custody-test".to_owned()))
        .expect("create conversation session")
        .export()
        .expect("export session snapshot")
        .into_bytes()
}

fn fixture_inputs() -> (
    DocumentIdentity,
    EngineEraFingerprint,
    Vec<u8>,
    HashMap<String, String>,
) {
    (
        DocumentIdentity::new("tenant-a", "doc-a", "content-hash-a"),
        EngineEraFingerprint("fingerprint-a".to_owned()),
        fixture_snapshot(),
        HashMap::from([("[EMAIL_1]".to_owned(), "owner@example.test".to_owned())]),
    )
}

#[test]
fn custody_requires_all_artifacts() {
    let (document, fingerprint, snapshot, map) = fixture_inputs();
    let provider = FixtureVaultKeyProvider([7; 32]);
    let mut artifacts = seal_custody(
        b"canonical-gaze-manifest",
        &snapshot,
        &map,
        document.clone(),
        fingerprint.clone(),
        &provider,
    )
    .expect("seal custody");

    artifacts.encrypted_sensitive_snapshot.clear();
    let error = verify_and_decrypt(&artifacts, &document, &fingerprint, &provider)
        .expect_err("missing snapshot must fail closed");
    assert!(error.to_string().contains("sensitive snapshot"));
}

#[test]
fn missing_key_fails_closed() {
    let (document, fingerprint, snapshot, map) = fixture_inputs();
    let provider = FixtureVaultKeyProvider([7; 32]);
    let artifacts = seal_custody(
        b"canonical-gaze-manifest",
        &snapshot,
        &map,
        document.clone(),
        fingerprint.clone(),
        &provider,
    )
    .expect("seal custody");

    let wrong_provider = FixtureVaultKeyProvider([8; 32]);
    assert!(verify_and_decrypt(&artifacts, &document, &fingerprint, &wrong_provider).is_err());
}

#[test]
fn fingerprint_mismatch_fails_before_decryption() {
    let (document, fingerprint, snapshot, map) = fixture_inputs();
    let provider = FixtureVaultKeyProvider([7; 32]);
    let artifacts = seal_custody(
        b"canonical-gaze-manifest",
        &snapshot,
        &map,
        document.clone(),
        fingerprint,
        &provider,
    )
    .expect("seal custody");

    let wrong_fingerprint = EngineEraFingerprint("fingerprint-b".to_owned());
    let error = verify_and_decrypt(&artifacts, &document, &wrong_fingerprint, &provider)
        .expect_err("fingerprint mismatch must fail closed");
    assert!(error.to_string().contains("fingerprint"));
}

#[test]
fn local_kms_is_rejected_in_production() {
    let config = EncryptionConfig {
        assurance_mode: AssuranceMode::Production,
        ..EncryptionConfig::default()
    };
    let kms = KmsConfig::Local {
        key_path: "/tmp/hacienda-test-local-kms.key".to_owned(),
    };

    let runtime = tokio::runtime::Runtime::new().expect("create test runtime");
    let result = runtime.block_on(hacienda_backend::encryption::EncryptionEngine::new(
        config,
        Some(kms),
    ));
    let error = match result {
        Ok(_) => panic!("production Local KMS must be rejected"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("Local KMS"));
}

#[test]
fn tampered_manifest_fails_closed() {
    let (document, fingerprint, snapshot, map) = fixture_inputs();
    let provider = FixtureVaultKeyProvider([7; 32]);
    let mut artifacts = seal_custody(
        b"canonical-gaze-manifest",
        &snapshot,
        &map,
        document.clone(),
        fingerprint.clone(),
        &provider,
    )
    .expect("seal custody");

    artifacts.manifest = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "fingerprint": "wrong",
    }))
    .expect("serialize tampered manifest");
    assert!(verify_and_decrypt(&artifacts, &document, &fingerprint, &provider).is_err());
}
