//! Rehydration logic: decrypt vault map, restore entities/documents, audit logging.

use crate::cli::{ExportRecoveryArgs, RehydrateArgs};
use crate::dual_store::RehydrationManifest;
use crate::encryption::{decrypt_vault_blob, default_vault_key_provider, encrypt_vault_blob};
use console::style;
use dialoguer::Confirm;
use std::fs;
use std::path::Path;
use xberg::text::redaction::rehydration::RehydrationMap;

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
    #[error("unsafe output path: {0}")]
    UnsafeOutput(String),
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
    passphrase: &str,
) -> Result<RehydrationMap, RehydrationError> {
    let _ = passphrase;
    let manifest: RehydrationManifest = serde_json::from_slice(&load_manifest(manifest_path)?)
        .map_err(|e| RehydrationError::ManifestParse(e.to_string()))?;
    let expected_binding = if let Some(document_path) = document_path {
        blake3::hash(&fs::read(document_path)?).to_hex().to_string()
    } else {
        manifest.document_binding.clone()
    };
    let blob = fs::read(path)?;
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
    // The expected values above come from the requested artifact/document, not
    // from the envelope, and are checked before custody/decryption.
    let provider =
        default_vault_key_provider().map_err(|e| RehydrationError::Decryption(e.to_string()))?;
    let plaintext = decrypt_vault_blob(
        &blob,
        &manifest.fingerprint.0,
        &expected_binding,
        provider.as_ref(),
    )
    .map_err(|e| RehydrationError::Decryption(e.to_string()))?;
    serde_json::from_slice(&plaintext).map_err(|e| RehydrationError::Decryption(e.to_string()))
}

/// Legacy API retained for callers that do not have the requested manifest.
/// Refuse rather than performing a self-consistency-only verification.
pub fn load_vault_map<P: AsRef<Path>>(
    _path: P,
    _passphrase: &str,
) -> Result<RehydrationMap, RehydrationError> {
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

fn validate_output_path(path: &Path) -> Result<(), RehydrationError> {
    let path_text = path.to_string_lossy();
    if path_text == "-" || path_text == "/dev/stdout" || path_text == "/proc/self/fd/1" {
        return Err(RehydrationError::UnsafeOutput(
            "stdout and special device aliases are not permitted".to_owned(),
        ));
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(RehydrationError::UnsafeOutput(
                "output must be a regular, non-symlink file".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Main rehydration entry point.
pub async fn run_rehydrate(
    args: RehydrateArgs,
    vault_passphrase: &str,
) -> Result<RehydrationAuditRecord, RehydrationError> {
    let timestamp = chrono::Utc::now().to_rfc3339();

    validate_output_path(&args.output)?;
    if args.yes && !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err(RehydrationError::UserCancelled);
    }
    let manifest: RehydrationManifest = serde_json::from_slice(&load_manifest(&args.manifest)?)
        .map_err(|e| RehydrationError::ManifestParse(e.to_string()))?;
    if args.document.is_none() {
        return Err(RehydrationError::ManifestParse(
            "original document is required for independent vault binding verification".to_owned(),
        ));
    }

    if let Some(entity_token) = args.entity.as_deref() {
        // Single entity rehydration
        if !args.yes {
            let confirmed = confirm_rehydration(entity_token, false)?;
            if !confirmed {
                return Err(RehydrationError::UserCancelled);
            }
        }

        // Confirmation and independent path validation happen before custody
        // access or decryption.
        let vault_map = load_vault_map_verified(
            &args.vault_map,
            &args.manifest,
            args.document.as_deref(),
            vault_passphrase,
        )?;
        let original = rehydrate_entity(&vault_map, entity_token)?;
        write_output(&original, Some(&args.output))?;

        Ok(RehydrationAuditRecord {
            timestamp,
            operation: "entity".to_owned(),
            scope: entity_token.to_owned(),
            fingerprint: manifest.fingerprint.as_str().to_owned(),
            success: true,
            error: None,
        })
    } else if let Some(doc_id) = args.doc_id.as_deref() {
        // Full document rehydration
        if !args.yes {
            let confirmed = confirm_rehydration(doc_id, true)?;
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

/// Export recovery bundle: encrypts vault map + manifest with a recovery passphrase.
pub async fn run_export_recovery(
    args: ExportRecoveryArgs,
    vault_passphrase: &str,
) -> Result<(), RehydrationError> {
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err(RehydrationError::UserCancelled);
    }
    if !confirm_rehydration("recovery export", false)? {
        return Err(RehydrationError::UserCancelled);
    }
    validate_output_path(&args.output)?;
    let manifest_bytes = load_manifest(&args.manifest)?;
    let vault_map =
        load_vault_map_verified(&args.vault_map, &args.manifest, None, vault_passphrase)?;
    let provider =
        default_vault_key_provider().map_err(|e| RehydrationError::Decryption(e.to_string()))?;
    let plaintext = serde_json::json!({
        "vault_map": vault_map,
        "manifest": manifest_bytes,
        "created_at": chrono::Utc::now().to_rfc3339(),
    });
    let bundle = encrypt_vault_blob(
        &serde_json::to_vec(&plaintext)?,
        "recovery",
        "owner-confirmed",
        provider.as_ref(),
    )
    .map_err(|e| RehydrationError::Custody(e.to_string()))?;
    fs::write(&args.output, bundle).map_err(RehydrationError::Io)?;
    eprintln!("Recovery bundle written; vault contents and key material are not displayed.");

    Ok(())
}

/// Retrieve vault passphrase from macOS Keychain (stub for now).
pub fn get_vault_passphrase() -> Result<String, RehydrationError> {
    // Custody is intentionally resolved only after an interactive operation
    // has been confirmed and its independent bindings have been checked.
    Ok(String::new())
}

/// Log rehydration audit record.
pub fn log_audit(record: &RehydrationAuditRecord) -> Result<(), RehydrationError> {
    // Metadata-only audit: never emit tokens, document IDs, values, arguments, or errors.
    let json = serde_json::json!({
        "timestamp": record.timestamp,
        "operation": record.operation,
        "scope_present": !record.scope.is_empty(),
        "fingerprint": record.fingerprint,
        "success": record.success,
    });
    eprintln!("{} {}", style("[AUDIT]").blue().bold(), json);
    Ok(())
}
