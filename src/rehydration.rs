//! Rehydration logic: decrypt vault map, restore entities/documents, audit logging.

use crate::authz::PrincipalBinding;
use crate::cli::{ExportRecoveryArgs, RehydrateArgs};
use crate::dual_store::RehydrationManifest;
use crate::encryption::{VaultKeyProvider, decrypt_vault_blob, encrypt_vault_blob};
use console::style;
use dialoguer::Confirm;
use std::fs;
use std::path::Path;
use xberg::text::redaction::rehydration::RehydrationMap;
use zeroize::Zeroize;

const LEGACY_XPII_MAGIC: &[u8] = b"XPII\x01";

/// Errors from rehydration operations.
#[derive(Debug, thiserror::Error)]
pub enum RehydrationError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("xberg rehydration error: {0}")]
    Xberg(#[from] xberg::XbergError),
    #[error("vault decryption failed: {0}")]
    Decryption(String),
    #[error("fingerprint mismatch: expected {expected}, got {actual}")]
    FingerprintMismatch { expected: String, actual: String },
    #[error("document binding mismatch: expected {expected}, got {actual}")]
    DocumentBindingMismatch { expected: String, actual: String },
    #[error("entity not found in vault: {0}")]
    EntityNotFound(String),
    #[error("manifest parse error: {0}")]
    ManifestParse(String),
    #[error("user cancelled")]
    UserCancelled,
    #[error("vault custody failed: {0}")]
    Custody(String),
    #[error("legacy vault format detected; run the owner-approved legacy migration command")]
    LegacyFormat,
    #[error("principal is not authorized for tenant")]
    UnauthorizedTenant,
}

/// Result of a rehydration operation (for audit logging).
#[derive(Debug, serde::Serialize)]
pub struct RehydrationAuditRecord {
    pub timestamp: String,
    pub operation: String, // "entity" or "document"
    pub scope: String,     // entity token or document ID
    pub fingerprint: String,
    pub success: bool,
    pub error: Option<String>,
}

/// Load a vault map only after checking its envelope against the requested
/// manifest (and, when supplied, the original document) independently.
pub fn load_vault_map_verified<P: AsRef<Path>, M: AsRef<Path>>(
    path: P,
    manifest_path: M,
    document_path: Option<&Path>,
    provider: &dyn VaultKeyProvider,
) -> Result<RehydrationMap, RehydrationError> {
    let blob = fs::read(path)?;
    if blob.starts_with(LEGACY_XPII_MAGIC) {
        return Err(RehydrationError::LegacyFormat);
    }
    let manifest: RehydrationManifest = serde_json::from_slice(&load_manifest(manifest_path)?)
        .map_err(|e| RehydrationError::ManifestParse(e.to_string()))?;
    let expected_binding = if let Some(document_path) = document_path {
        blake3::hash(&fs::read(document_path)?).to_hex().to_string()
    } else {
        manifest.document_binding.clone()
    };
    let envelope: crate::encryption::VaultBlob =
        serde_json::from_slice(&blob).map_err(|e| RehydrationError::Decryption(e.to_string()))?;
    if envelope.fingerprint != manifest.fingerprint.as_str() {
        return Err(RehydrationError::FingerprintMismatch {
            expected: manifest.fingerprint.as_str().to_owned(),
            actual: envelope.fingerprint,
        });
    }
    if envelope.document_binding != expected_binding {
        return Err(RehydrationError::DocumentBindingMismatch {
            expected: expected_binding,
            actual: envelope.document_binding,
        });
    }
    // The manifest's Gaze session material is itself an encrypted artifact;
    // a metadata-only manifest must not be treated as sufficient authority.
    let _protected_snapshot = decrypt_vault_blob(
        &manifest.gaze_manifest,
        manifest.fingerprint.as_str(),
        &expected_binding,
        provider,
    )
    .map_err(|e| RehydrationError::Decryption(e.to_string()))?;
    // The expected values above come from the requested artifact/document, not
    // from the envelope, and are checked before custody/decryption.
    let plaintext = decrypt_vault_blob(&blob, &manifest.fingerprint.0, &expected_binding, provider)
        .map_err(|e| RehydrationError::Decryption(e.to_string()))?;
    serde_json::from_slice(&plaintext).map_err(|e| RehydrationError::Decryption(e.to_string()))
}

/// Legacy API retained for callers that do not have the requested manifest.
/// Refuse rather than performing a self-consistency-only verification.
pub fn load_vault_map<P: AsRef<Path>>(_path: P) -> Result<RehydrationMap, RehydrationError> {
    Err(RehydrationError::ManifestParse(
        "manifest is required for independent vault binding verification".to_owned(),
    ))
}

/// Load gaze manifest from file.
fn load_manifest<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, RehydrationError> {
    fs::read(path).map_err(RehydrationError::Io)
}

/// Rehydrate a single entity token.
pub fn rehydrate_entity(
    vault_map: &RehydrationMap,
    entity_token: &str,
) -> Result<String, RehydrationError> {
    vault_map
        .get(entity_token)
        .cloned()
        .ok_or_else(|| RehydrationError::EntityNotFound(entity_token.to_owned()))
}

/// Rehydrate a full document by replacing all tokens in the redacted content.
pub fn rehydrate_document(redacted_content: &str, vault_map: &RehydrationMap) -> String {
    let mut result = redacted_content.to_owned();
    // Replace tokens in reverse order of length to avoid partial replacements
    let mut tokens: Vec<_> = vault_map.keys().collect();
    tokens.sort_by_key(|a| std::cmp::Reverse(a.len()));
    for token in tokens {
        if let Some(original) = vault_map.get(token) {
            result = result.replace(token, original);
        }
    }
    result
}

/// Interactive confirmation prompt for rehydration.
fn confirm_rehydration(scope: &str, is_full_doc: bool) -> Result<bool, RehydrationError> {
    let msg = if is_full_doc {
        format!(
            "Rehydrate FULL DOCUMENT '{}'? This will expose ALL PII in the document.",
            scope
        )
    } else {
        format!(
            "Rehydrate entity '{}'? This will expose the original PII value.",
            scope
        )
    };

    let confirmation = Confirm::new()
        .with_prompt(style(msg).red().bold().to_string())
        .default(false)
        .interact()
        .map_err(|_| RehydrationError::UserCancelled)?;

    Ok(confirmation)
}

/// Write rehydrated content to file or stdout.
fn write_output(content: &str, output_path: Option<&Path>) -> Result<(), RehydrationError> {
    match output_path {
        Some(path) => fs::write(path, content).map_err(RehydrationError::Io),
        None => {
            println!("{}", content);
            Ok(())
        }
    }
}

/// Main rehydration entry point.
pub async fn run_rehydrate(
    args: RehydrateArgs,
    provider: &dyn VaultKeyProvider,
    binding: &PrincipalBinding,
    tenant_id: &str,
) -> Result<RehydrationAuditRecord, RehydrationError> {
    if !binding.authorizes(tenant_id) {
        return Err(RehydrationError::UnauthorizedTenant);
    }
    let timestamp = chrono::Utc::now().to_rfc3339();

    if args.output.is_none() {
        return Err(RehydrationError::UserCancelled);
    }
    if args.yes && !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err(RehydrationError::UserCancelled);
    }
    let manifest_path = args.manifest.as_ref().ok_or_else(|| {
        RehydrationError::ManifestParse(
            "manifest is required for independent vault binding verification".to_owned(),
        )
    })?;
    // Verify requested manifest/document metadata before asking custody to decrypt.
    let vault_map = load_vault_map_verified(
        &args.vault_map,
        manifest_path,
        args.document.as_deref(),
        provider,
    )?;

    if let Some(entity_token) = args.entity {
        // Single entity rehydration
        if !args.yes {
            let confirmed = confirm_rehydration(&entity_token, false)?;
            if !confirmed {
                return Err(RehydrationError::UserCancelled);
            }
        }

        let original = rehydrate_entity(&vault_map, &entity_token)?;
        write_output(&original, args.output.as_deref())?;

        Ok(RehydrationAuditRecord {
            timestamp,
            operation: "entity".to_owned(),
            scope: entity_token,
            fingerprint: String::new(), // TODO: extract from manifest
            success: true,
            error: None,
        })
    } else if let Some(doc_id) = args.doc_id {
        // Full document rehydration
        if !args.yes {
            let confirmed = confirm_rehydration(&doc_id, true)?;
            if !confirmed {
                return Err(RehydrationError::UserCancelled);
            }
        }

        // For full document rehydration, we need the redacted content.
        // This would come from the document store (not implemented yet).
        // For now, return an error indicating this needs the document content.
        Err(RehydrationError::ManifestParse(
            "Full document rehydration requires the redacted document content. Not yet implemented.".to_owned(),
        ))
    } else {
        unreachable!("clap ensures either entity or doc_id is provided");
    }
}

/// Export recovery bundle: encrypts vault map + manifest with owner custody.
pub async fn run_export_recovery(
    args: ExportRecoveryArgs,
    provider: &dyn VaultKeyProvider,
    binding: &PrincipalBinding,
    tenant_id: &str,
) -> Result<(), RehydrationError> {
    if !binding.authorizes(tenant_id) {
        return Err(RehydrationError::UnauthorizedTenant);
    }
    let manifest_bytes = load_manifest(&args.manifest)?;
    let vault_map = load_vault_map_verified(&args.vault_map, &args.manifest, None, provider)?;

    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err(RehydrationError::UserCancelled);
    }
    if !confirm_rehydration("recovery export", false)? {
        return Err(RehydrationError::UserCancelled);
    }
    let plaintext = serde_json::json!({
        "vault_map": vault_map,
        "manifest": manifest_bytes,
        "created_at": chrono::Utc::now().to_rfc3339(),
    });
    let bundle = encrypt_vault_blob(
        &serde_json::to_vec(&plaintext)?,
        "recovery",
        "owner-confirmed",
        provider,
    )
    .map_err(|e| RehydrationError::Custody(e.to_string()))?;
    fs::write(&args.output, bundle).map_err(RehydrationError::Io)?;
    eprintln!("Recovery bundle written; vault contents and key material are not displayed.");

    Ok(())
}

/// Retrieve the vault passphrase from the configured custody provider.
///
/// The interactive CLI currently uses the established development custody
/// stub; production callers must supply a real `VaultKeyProvider` for vault
/// encryption and decryption.
pub fn get_vault_passphrase() -> Result<String, RehydrationError> {
    Ok("hacienda-backend-vault-key-v1".to_owned())
}

/// Migrate a prototype XPII vault with an owner-supplied one-time secret.
///
/// The source is never removed. The destination is written only after the
/// new application-encrypted envelope has been decrypted and compared with
/// the legacy plaintext, and after explicit owner confirmation.
pub fn migrate_legacy_vault<P: AsRef<Path>, M: AsRef<Path>, O: AsRef<Path>>(
    legacy_path: P,
    manifest_path: M,
    output_path: O,
    legacy_secret: &str,
    provider: &dyn VaultKeyProvider,
    owner_confirmed: bool,
) -> Result<RehydrationAuditRecord, RehydrationError> {
    let legacy_path = legacy_path.as_ref();
    let output_path = output_path.as_ref();
    let legacy_blob = fs::read(legacy_path)?;
    if !legacy_blob.starts_with(LEGACY_XPII_MAGIC) {
        return Err(RehydrationError::ManifestParse(
            "input is not a recognized legacy vault format".to_owned(),
        ));
    }
    if legacy_secret.is_empty() {
        return Err(RehydrationError::Decryption(
            "one-time legacy secret is required".to_owned(),
        ));
    }
    let manifest: RehydrationManifest = serde_json::from_slice(&load_manifest(manifest_path)?)
        .map_err(|e| RehydrationError::ManifestParse(e.to_string()))?;

    decrypt_vault_blob(
        &manifest.gaze_manifest,
        manifest.fingerprint.as_str(),
        &manifest.document_binding,
        provider,
    )
    .map_err(|e| RehydrationError::Decryption(e.to_string()))?;

    let legacy_map = {
        let mut secret = legacy_secret.to_owned();
        let result = xberg::text::redaction::rehydration::decrypt_map(&legacy_blob, &secret)
            .map_err(|_| RehydrationError::Decryption("legacy vault decryption failed".to_owned()));
        secret.zeroize();
        result?
    };
    let plaintext = serde_json::to_vec(&legacy_map)?;
    let migrated_blob = encrypt_vault_blob(
        &plaintext,
        manifest.fingerprint.as_str(),
        &manifest.document_binding,
        provider,
    )
    .map_err(|e| RehydrationError::Custody(e.to_string()))?;

    let round_trip = decrypt_vault_blob(
        &migrated_blob,
        manifest.fingerprint.as_str(),
        &manifest.document_binding,
        provider,
    )
    .map_err(|e| RehydrationError::Decryption(e.to_string()))?;
    let verified: RehydrationMap = serde_json::from_slice(&round_trip)
        .map_err(|e| RehydrationError::Decryption(e.to_string()))?;
    if verified != legacy_map {
        return Err(RehydrationError::Decryption(
            "legacy migration round-trip verification failed".to_owned(),
        ));
    }
    if !owner_confirmed {
        return Err(RehydrationError::UserCancelled);
    }

    let backup_path = output_path.with_extension("legacy");
    if backup_path != legacy_path {
        fs::copy(legacy_path, &backup_path)?;
    }
    let temporary_path = output_path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    fs::write(&temporary_path, &migrated_blob)?;
    fs::rename(&temporary_path, output_path)?;

    Ok(RehydrationAuditRecord {
        timestamp: chrono::Utc::now().to_rfc3339(),
        operation: "legacy_migration".to_owned(),
        scope: output_path.display().to_string(),
        fingerprint: manifest.fingerprint.0,
        success: true,
        error: None,
    })
}

/// Log rehydration audit record.
pub fn log_audit(record: &RehydrationAuditRecord) -> Result<(), RehydrationError> {
    // Metadata-only audit: never emit tokens, document IDs, values, arguments, or errors.
    let scope_hash = blake3::hash(record.scope.as_bytes()).to_hex().to_string();
    let json = serde_json::json!({
        "timestamp": record.timestamp,
        "operation": record.operation,
        "scope_hash": scope_hash,
        "fingerprint": record.fingerprint,
        "success": record.success,
    });
    eprintln!("{} {}", style("[AUDIT]").blue().bold(), json);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dual_store::EngineEraFingerprint;
    use crate::encryption::FixtureVaultKeyProvider;
    use std::collections::HashMap;

    fn migration_paths() -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let root =
            std::env::temp_dir().join(format!("hacienda-migration-{}", uuid::Uuid::new_v4()));
        (
            root.join("legacy.xpii"),
            root.join("manifest.json"),
            root.join("vault.json"),
        )
    }

    fn write_fixture(
        legacy: &std::path::Path,
        manifest: &std::path::Path,
        provider: &FixtureVaultKeyProvider,
    ) -> HashMap<String, String> {
        std::fs::create_dir_all(legacy.parent().expect("fixture parent")).expect("mkdir");
        let map = HashMap::from([(
            String::from("[EMAIL_1]"),
            String::from("owner@example.test"),
        )]);
        let legacy_blob = xberg::text::redaction::rehydration::encrypt_map(
            &map,
            "one-time migration fixture secret",
        )
        .expect("legacy fixture encryption");
        std::fs::write(legacy, legacy_blob).expect("write legacy fixture");
        let manifest_value = RehydrationManifest {
            fingerprint: EngineEraFingerprint("fingerprint".to_owned()),
            document_binding: "document".to_owned(),
            gaze_manifest: encrypt_vault_blob(
                b"session fixture",
                "fingerprint",
                "document",
                provider,
            )
            .expect("protected session fixture"),
        };
        std::fs::write(
            manifest,
            serde_json::to_vec(&manifest_value).expect("manifest serialization"),
        )
        .expect("write manifest fixture");
        map
    }

    #[test]
    fn legacy_migration_retains_source_and_verifies_round_trip() {
        let (legacy, manifest, output) = migration_paths();
        let provider = FixtureVaultKeyProvider([7; 32]);
        let expected = write_fixture(&legacy, &manifest, &provider);

        migrate_legacy_vault(
            &legacy,
            &manifest,
            &output,
            "one-time migration fixture secret",
            &provider,
            true,
        )
        .expect("migration succeeds");

        assert!(legacy.exists(), "legacy source remains recoverable");
        assert!(output.exists(), "new vault is published");
        assert!(output.with_extension("legacy").exists());
        let restored = load_vault_map_verified(&output, &manifest, None, &provider)
            .expect("new vault reads through custody");
        assert_eq!(restored, expected);

        let root = legacy.parent().expect("fixture parent");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_migration_cancellation_does_not_publish_output() {
        let (legacy, manifest, output) = migration_paths();
        let provider = FixtureVaultKeyProvider([8; 32]);
        write_fixture(&legacy, &manifest, &provider);

        let error = migrate_legacy_vault(
            &legacy,
            &manifest,
            &output,
            "one-time migration fixture secret",
            &provider,
            false,
        )
        .expect_err("owner confirmation is required");
        assert!(matches!(error, RehydrationError::UserCancelled));
        assert!(legacy.exists());
        assert!(!output.exists());

        let root = legacy.parent().expect("fixture parent");
        let _ = std::fs::remove_dir_all(root);
    }
}
