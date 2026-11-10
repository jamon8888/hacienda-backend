//! Atomic verification of owner-vault artifacts.
//!
//! A restore operation is admitted only when the canonical manifest, the
//! encrypted Gaze snapshot/session, the encrypted xberg TokenReplace map, the
//! document identity, and the engine-era fingerprint agree.  Verification is
//! intentionally all-or-nothing: no decrypted artifact is returned before all
//! checks have passed.

use crate::dual_store::EngineEraFingerprint;
use crate::encryption::{VaultKeyProvider, decrypt_vault_blob, encrypt_vault_blob};
use serde::{Deserialize, Serialize};
use std::path::Path;
use xberg::text::redaction::rehydration::RehydrationMap;

const CUSTODY_MANIFEST_VERSION: u8 = 1;
const SNAPSHOT_KIND: &str = "sensitive-snapshot";
const TOKEN_REPLACE_KIND: &str = "token-replace";

#[derive(Debug, thiserror::Error)]
pub enum CustodyError {
    #[error("custody artifact is missing: {0}")]
    MissingArtifact(&'static str),
    #[error("custody manifest is invalid: {0}")]
    InvalidManifest(String),
    #[error("document identity mismatch")]
    DocumentIdentityMismatch,
    #[error("shared engine fingerprint mismatch")]
    FingerprintMismatch,
    #[error("custody decryption failed: {0}")]
    Decryption(String),
    #[error("custody artifact integrity check failed: {0}")]
    Integrity(String),
    #[error("custody artifact I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("custody serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Stable identity of the document whose restore material is being held.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentIdentity {
    pub tenant_id: String,
    pub document_id: String,
    /// Blake3 hash of the original document bytes, encoded as lowercase hex.
    pub content_hash: String,
}

impl DocumentIdentity {
    pub fn new(
        tenant_id: impl Into<String>,
        document_id: impl Into<String>,
        content_hash: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            document_id: document_id.into(),
            content_hash: content_hash.into(),
        }
    }

    fn validate(&self) -> Result<(), CustodyError> {
        if self.tenant_id.is_empty() || self.document_id.is_empty() || self.content_hash.is_empty()
        {
            return Err(CustodyError::InvalidManifest(
                "document identity is incomplete".to_owned(),
            ));
        }
        Ok(())
    }

    fn binding(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.tenant_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.document_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.content_hash.as_bytes());
        hasher.finalize().to_hex().to_string()
    }
}

/// The metadata envelope that binds the canonical manifest to both encrypted
/// restore artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyManifest {
    pub version: u8,
    pub fingerprint: EngineEraFingerprint,
    pub document: DocumentIdentity,
    /// Canonical Gaze provenance. It is not restore authority by itself.
    pub gaze_manifest: Vec<u8>,
    pub gaze_manifest_digest: String,
    pub sensitive_snapshot_digest: String,
    pub token_replace_digest: String,
}

/// The three persisted artifact bytes needed for a restore attempt.
#[derive(Clone, Serialize, Deserialize)]
pub struct CustodyArtifacts {
    /// Serialized [`CustodyManifest`].
    pub manifest: Vec<u8>,
    /// Authenticated encrypted Gaze SensitiveSnapshot/session bytes.
    pub encrypted_sensitive_snapshot: Vec<u8>,
    /// Authenticated encrypted xberg TokenReplace map bytes.
    pub encrypted_token_replace: Vec<u8>,
}

/// Result returned only after every custody check has passed.
#[derive(Debug)]
pub struct VerifiedCustody {
    pub manifest: CustodyManifest,
    pub sensitive_snapshot: Vec<u8>,
    pub token_replace: RehydrationMap,
}

/// Encrypt and bind all restore material under one document/fingerprint pair.
pub fn seal_custody(
    gaze_manifest: &[u8],
    sensitive_snapshot: &[u8],
    token_replace: &RehydrationMap,
    document: DocumentIdentity,
    fingerprint: EngineEraFingerprint,
    provider: &dyn VaultKeyProvider,
) -> Result<CustodyArtifacts, CustodyError> {
    if gaze_manifest.is_empty() {
        return Err(CustodyError::MissingArtifact("manifest"));
    }
    if sensitive_snapshot.is_empty() {
        return Err(CustodyError::MissingArtifact("sensitive snapshot/session"));
    }
    if token_replace.is_empty() {
        return Err(CustodyError::MissingArtifact("TokenReplace map"));
    }
    document.validate()?;
    if fingerprint.as_str().is_empty() {
        return Err(CustodyError::InvalidManifest(
            "fingerprint is empty".to_owned(),
        ));
    }

    let token_replace_bytes = serde_json::to_vec(token_replace)?;
    let manifest = CustodyManifest {
        version: CUSTODY_MANIFEST_VERSION,
        fingerprint: fingerprint.clone(),
        document: document.clone(),
        gaze_manifest: gaze_manifest.to_vec(),
        gaze_manifest_digest: digest(gaze_manifest),
        sensitive_snapshot_digest: digest(sensitive_snapshot),
        token_replace_digest: digest(&token_replace_bytes),
    };
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let snapshot = encrypt_artifact(
        sensitive_snapshot,
        &fingerprint,
        &document,
        SNAPSHOT_KIND,
        provider,
    )?;
    let token_replace = encrypt_artifact(
        &token_replace_bytes,
        &fingerprint,
        &document,
        TOKEN_REPLACE_KIND,
        provider,
    )?;

    Ok(CustodyArtifacts {
        manifest: manifest_bytes,
        encrypted_sensitive_snapshot: snapshot,
        encrypted_token_replace: token_replace,
    })
}

/// Atomically verify and decrypt custody artifacts.
pub fn verify_and_decrypt(
    artifacts: &CustodyArtifacts,
    expected_document: &DocumentIdentity,
    expected_fingerprint: &EngineEraFingerprint,
    provider: &dyn VaultKeyProvider,
) -> Result<VerifiedCustody, CustodyError> {
    if artifacts.manifest.is_empty() {
        return Err(CustodyError::MissingArtifact("manifest"));
    }
    if artifacts.encrypted_sensitive_snapshot.is_empty() {
        return Err(CustodyError::MissingArtifact("sensitive snapshot/session"));
    }
    if artifacts.encrypted_token_replace.is_empty() {
        return Err(CustodyError::MissingArtifact("TokenReplace map"));
    }
    expected_document.validate()?;

    let manifest: CustodyManifest = serde_json::from_slice(&artifacts.manifest)
        .map_err(|e| CustodyError::InvalidManifest(e.to_string()))?;
    if manifest.version != CUSTODY_MANIFEST_VERSION {
        return Err(CustodyError::InvalidManifest(
            "unsupported custody manifest version".to_owned(),
        ));
    }
    manifest.document.validate()?;
    if &manifest.document != expected_document {
        return Err(CustodyError::DocumentIdentityMismatch);
    }
    if &manifest.fingerprint != expected_fingerprint {
        return Err(CustodyError::FingerprintMismatch);
    }
    if manifest.gaze_manifest.is_empty()
        || manifest.gaze_manifest_digest != digest(&manifest.gaze_manifest)
    {
        return Err(CustodyError::Integrity(
            "manifest digest does not match".to_owned(),
        ));
    }

    // The two decryptions happen only after every independent binding check
    // above. No partial artifact is returned if either one fails.
    let sensitive_snapshot = decrypt_artifact(
        &artifacts.encrypted_sensitive_snapshot,
        expected_fingerprint,
        expected_document,
        SNAPSHOT_KIND,
        provider,
    )?;
    if manifest.sensitive_snapshot_digest != digest(&sensitive_snapshot) {
        return Err(CustodyError::Integrity(
            "sensitive snapshot digest does not match".to_owned(),
        ));
    }

    let token_replace_bytes = decrypt_artifact(
        &artifacts.encrypted_token_replace,
        expected_fingerprint,
        expected_document,
        TOKEN_REPLACE_KIND,
        provider,
    )?;
    if manifest.token_replace_digest != digest(&token_replace_bytes) {
        return Err(CustodyError::Integrity(
            "TokenReplace digest does not match".to_owned(),
        ));
    }
    let token_replace: RehydrationMap = serde_json::from_slice(&token_replace_bytes)
        .map_err(|e| CustodyError::Integrity(format!("TokenReplace map is invalid: {e}")))?;
    if token_replace.is_empty() {
        return Err(CustodyError::MissingArtifact("TokenReplace map"));
    }

    // The session format is signed by Gaze. Importing it verifies the
    // SensitiveSnapshot/session envelope before it can be used for restore.
    gaze::Session::import(gaze::SensitiveSnapshot::from(sensitive_snapshot.clone()))
        .map_err(|e| CustodyError::Integrity(format!("SensitiveSnapshot is invalid: {e}")))?;

    Ok(VerifiedCustody {
        manifest,
        sensitive_snapshot,
        token_replace,
    })
}

/// Read three artifact files and perform the same all-or-nothing verification.
pub fn verify_files(
    manifest_path: &Path,
    snapshot_path: &Path,
    token_replace_path: &Path,
    expected_document: &DocumentIdentity,
    expected_fingerprint: &EngineEraFingerprint,
    provider: &dyn VaultKeyProvider,
) -> Result<VerifiedCustody, CustodyError> {
    let artifacts = CustodyArtifacts {
        manifest: std::fs::read(manifest_path)?,
        encrypted_sensitive_snapshot: std::fs::read(snapshot_path)?,
        encrypted_token_replace: std::fs::read(token_replace_path)?,
    };
    verify_and_decrypt(
        &artifacts,
        expected_document,
        expected_fingerprint,
        provider,
    )
}

fn encrypt_artifact(
    plaintext: &[u8],
    fingerprint: &EngineEraFingerprint,
    document: &DocumentIdentity,
    kind: &str,
    provider: &dyn VaultKeyProvider,
) -> Result<Vec<u8>, CustodyError> {
    encrypt_vault_blob(
        plaintext,
        fingerprint.as_str(),
        &artifact_binding(document, kind),
        provider,
    )
    .map_err(|e| CustodyError::Decryption(e.to_string()))
}

fn decrypt_artifact(
    blob: &[u8],
    fingerprint: &EngineEraFingerprint,
    document: &DocumentIdentity,
    kind: &str,
    provider: &dyn VaultKeyProvider,
) -> Result<Vec<u8>, CustodyError> {
    decrypt_vault_blob(
        blob,
        fingerprint.as_str(),
        &artifact_binding(document, kind),
        provider,
    )
    .map_err(|e| CustodyError::Decryption(e.to_string()))
}

fn artifact_binding(document: &DocumentIdentity, kind: &str) -> String {
    format!("{}:{kind}", document.binding())
}

fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
