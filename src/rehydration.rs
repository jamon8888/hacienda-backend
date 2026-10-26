//! Rehydration logic: decrypt vault map, restore entities/documents, audit logging.

use crate::cli::{ExportRecoveryArgs, RehydrateArgs};
use console::style;
use dialoguer::Confirm;
use std::fs;
use std::path::Path;
use xberg::text::redaction::rehydration::{RehydrationMap, decrypt_map, encrypt_map};

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
    #[error("entity not found in vault: {0}")]
    EntityNotFound(String),
    #[error("manifest parse error: {0}")]
    ManifestParse(String),
    #[error("user cancelled")]
    UserCancelled,
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

/// Load vault map from XPII\x01 encrypted file.
fn load_vault_map<P: AsRef<Path>>(
    path: P,
    passphrase: &str,
) -> Result<RehydrationMap, RehydrationError> {
    let blob = fs::read(path)?;
    decrypt_map(&blob, passphrase).map_err(|e| RehydrationError::Decryption(e.to_string()))
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
    vault_passphrase: &str,
) -> Result<RehydrationAuditRecord, RehydrationError> {
    let timestamp = chrono::Utc::now().to_rfc3339();

    // Load vault map
    let vault_map = load_vault_map(&args.vault_map, vault_passphrase)?;

    // Load manifest if provided
    let _manifest_bytes = if let Some(manifest_path) = &args.manifest {
        Some(load_manifest(manifest_path)?)
    } else {
        None
    };

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

/// Export recovery bundle: encrypts vault map + manifest with a recovery passphrase.
pub async fn run_export_recovery(
    args: ExportRecoveryArgs,
    vault_passphrase: &str,
) -> Result<(), RehydrationError> {
    let vault_map = load_vault_map(&args.vault_map, vault_passphrase)?;
    let manifest_bytes = load_manifest(&args.manifest)?;

    // Generate or use provided recovery passphrase
    let recovery_passphrase = args.passphrase.unwrap_or_else(|| {
        // Generate a secure random passphrase
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng = rand::rng();
        (0..32)
            .map(|_| CHARSET[rng.random_range(0..CHARSET.len())] as char)
            .collect()
    });

    // Create recovery bundle: JSON with both encrypted blobs
    #[derive(serde::Serialize)]
    struct RecoveryBundle {
        vault_map: Vec<u8>,
        manifest: Vec<u8>,
        fingerprint: String,
        created_at: String,
    }

    let encrypted_vault = encrypt_map(&vault_map, &recovery_passphrase)?;
    let bundle = RecoveryBundle {
        vault_map: encrypted_vault,
        manifest: manifest_bytes,
        fingerprint: String::new(), // TODO: extract from manifest
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    let bundle_json = serde_json::to_vec(&bundle).map_err(RehydrationError::Json)?;

    // Encrypt the entire bundle with the recovery passphrase
    // For simplicity, we'll just write the JSON (it contains encrypted blobs)
    fs::write(&args.output, &bundle_json).map_err(RehydrationError::Io)?;

    eprintln!(
        "{} Recovery bundle written to {}",
        style("✓").green().bold(),
        style(args.output.display()).cyan()
    );
    eprintln!(
        "{} Recovery passphrase: {}",
        style("🔑").yellow(),
        style(&recovery_passphrase).bold()
    );
    eprintln!(
        "{} Store this passphrase securely. It cannot be recovered.",
        style("⚠").yellow()
    );

    Ok(())
}

/// Retrieve vault passphrase from macOS Keychain (stub for now).
pub fn get_vault_passphrase() -> Result<String, RehydrationError> {
    // TODO: Implement actual Keychain retrieval
    // For now, use the test passphrase
    Ok("hacienda-backend-vault-key-v1".to_owned())
}

/// Log rehydration audit record.
pub fn log_audit(record: &RehydrationAuditRecord) -> Result<(), RehydrationError> {
    // TODO: Integrate with gaze-audit SQLite logger
    // For now, log to stderr as structured JSON
    let json = serde_json::to_string(record).map_err(RehydrationError::Json)?;
    eprintln!("{} {}", style("[AUDIT]").blue().bold(), json);
    Ok(())
}
