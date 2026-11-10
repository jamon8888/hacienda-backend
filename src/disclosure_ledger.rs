//! Separate metadata-only disclosure ledger foundation.
//!
//! This store is intentionally distinct from [`crate::audit::AuditLog`]. It
//! records the lifecycle of a future human-disclosure request, not operational
//! tool activity. No request arguments, values, tokens, paths, queries,
//! manifests, snapshots, or content may cross this module's public boundary.
//!
//! TODO(#23/#29/#31): bind these APIs to the authenticated owner-side request,
//! viewer, and acceptance/release workflows. SQLite epochs and external
//! anchoring belong to #35, not this foundation.

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// Opaque handle used by future disclosure request/status tools.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DisclosureHandle(String);

impl DisclosureHandle {
    fn fresh() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

/// Lifecycle states for a disclosure request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DisclosureStatus {
    Requested,
    Approved,
    Denied,
    Cancelled,
    Expired,
    OpenedViewer,
}

/// Signed, allowlisted metadata for one disclosure request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureRequest {
    pub handle: DisclosureHandle,
    pub status: DisclosureStatus,
    pub tenant_id: String,
    pub principal_fingerprint: String,
    pub engine_fingerprint: String,
    pub policy_fingerprint: String,
    pub requested_at: String,
    pub updated_at: String,
    pub item_count: u64,
    pub class_counts: BTreeMap<String, u64>,
    pub signature: String,
    pub public_key: String,
}

#[derive(Debug, Clone)]
struct LedgerState {
    records: HashMap<DisclosureHandle, DisclosureRequest>,
}

/// Append-only signed disclosure ledger. This is not the operational audit log.
pub struct DisclosureLedger {
    path: PathBuf,
    writer: Arc<Mutex<BufWriter<std::fs::File>>>,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    state: Arc<Mutex<LedgerState>>,
}

impl DisclosureLedger {
    /// Open/create a ledger and reconstruct its latest lifecycle state.
    pub async fn new(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let key_path = path.with_extension("key");
        let signing_key = if key_path.exists() {
            let bytes = tokio::fs::read(&key_path).await?;
            SigningKey::from_bytes(
                &bytes
                    .as_slice()
                    .try_into()
                    .context("invalid ledger key length")?,
            )
        } else {
            let mut bytes = [0u8; 32];
            rand::rng().fill_bytes(&mut bytes);
            let key = SigningKey::from_bytes(&bytes);
            #[cfg(unix)]
            {
                let mut file = tokio::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&key_path)
                    .await?;
                tokio::io::AsyncWriteExt::write_all(&mut file, &bytes).await?;
            }
            #[cfg(not(unix))]
            tokio::fs::write(&key_path, bytes).await?;
            key
        };
        let verifying_key = signing_key.verifying_key();
        let mut records = HashMap::new();
        if path.exists() {
            let content = tokio::fs::read_to_string(path).await?;
            for line in content.lines().filter(|line| !line.trim().is_empty()) {
                let record: DisclosureRequest = serde_json::from_str(line)?;
                verify_record(&record, &verifying_key)?;
                records.insert(record.handle.clone(), record);
            }
        }
        Ok(Self {
            path: path.to_path_buf(),
            writer: Arc::new(Mutex::new(BufWriter::new(
                OpenOptions::new().create(true).append(true).open(path)?,
            ))),
            signing_key,
            verifying_key,
            state: Arc::new(Mutex::new(LedgerState { records })),
        })
    }

    /// Create a new request and append its initial `requested` event.
    pub async fn create_request(
        &self,
        tenant_id: String,
        principal_fingerprint: String,
        engine_fingerprint: String,
        policy_fingerprint: String,
        item_count: u64,
        class_counts: BTreeMap<String, u64>,
    ) -> Result<DisclosureHandle> {
        let now = chrono::Utc::now().to_rfc3339();
        let record = DisclosureRequest {
            handle: DisclosureHandle::fresh(),
            status: DisclosureStatus::Requested,
            tenant_id,
            principal_fingerprint,
            engine_fingerprint,
            policy_fingerprint,
            requested_at: now.clone(),
            updated_at: now,
            item_count,
            class_counts,
            signature: String::new(),
            public_key: String::new(),
        };
        let handle = record.handle.clone();
        self.append(record).await?;
        Ok(handle)
    }

    /// Append a lifecycle record. Only valid forward transitions are accepted.
    pub async fn append(&self, mut record: DisclosureRequest) -> Result<()> {
        validate_metadata(&record)?;
        let mut state = self.state.lock().await;
        if let Some(previous) = state.records.get(&record.handle) {
            if !valid_transition(previous.status, record.status) {
                bail!("invalid disclosure status transition");
            }
            if record.requested_at != previous.requested_at
                || record.tenant_id != previous.tenant_id
                || record.principal_fingerprint != previous.principal_fingerprint
                || record.engine_fingerprint != previous.engine_fingerprint
                || record.policy_fingerprint != previous.policy_fingerprint
            {
                bail!("disclosure identity metadata is immutable");
            }
        } else if record.status != DisclosureStatus::Requested {
            bail!("first disclosure record must be requested");
        }
        record.updated_at = chrono::Utc::now().to_rfc3339();
        record.signature = String::new();
        record.public_key = String::new();
        let canonical = serde_json::to_vec(&record)?;
        record.signature = B64.encode(self.signing_key.sign(&canonical).to_bytes());
        record.public_key = B64.encode(self.verifying_key.to_bytes());
        let line = serde_json::to_string(&record)?;
        let mut writer = self.writer.lock().await;
        writeln!(writer, "{}", line)?;
        writer.flush()?;
        state.records.insert(record.handle.clone(), record);
        Ok(())
    }

    /// Append a status update while preserving immutable request metadata.
    pub async fn append_status(
        &self,
        handle: &DisclosureHandle,
        status: DisclosureStatus,
    ) -> Result<()> {
        let record = self
            .query_by_handle(handle)
            .await
            .context("disclosure handle not found")?;
        self.append(DisclosureRequest {
            status,
            signature: String::new(),
            public_key: String::new(),
            ..record
        })
        .await
    }

    pub async fn status(&self, handle: &DisclosureHandle) -> Option<DisclosureStatus> {
        self.state
            .lock()
            .await
            .records
            .get(handle)
            .map(|r| r.status)
    }
    pub async fn query_by_handle(&self, handle: &DisclosureHandle) -> Option<DisclosureRequest> {
        self.state.lock().await.records.get(handle).cloned()
    }
    pub fn verifying_key_b64(&self) -> String {
        B64.encode(self.verifying_key.to_bytes())
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn validate_metadata(record: &DisclosureRequest) -> Result<()> {
    if record.tenant_id.is_empty()
        || record.principal_fingerprint.is_empty()
        || record.engine_fingerprint.is_empty()
        || record.policy_fingerprint.is_empty()
    {
        bail!("disclosure metadata fields must not be empty");
    }
    if record
        .class_counts
        .keys()
        .any(|class| class.is_empty() || class.len() > 128)
    {
        bail!("invalid disclosure class");
    }
    Ok(())
}

fn valid_transition(from: DisclosureStatus, to: DisclosureStatus) -> bool {
    matches!(
        (from, to),
        (
            DisclosureStatus::Requested,
            DisclosureStatus::Approved
                | DisclosureStatus::Denied
                | DisclosureStatus::Cancelled
                | DisclosureStatus::Expired
        ) | (DisclosureStatus::Approved, DisclosureStatus::OpenedViewer)
            | (
                DisclosureStatus::OpenedViewer,
                DisclosureStatus::OpenedViewer
            )
    )
}

fn verify_record(record: &DisclosureRequest, key: &VerifyingKey) -> Result<()> {
    let mut unsigned = record.clone();
    let signature = B64.decode(&unsigned.signature)?;
    unsigned.signature.clear();
    unsigned.public_key.clear();
    let sig: [u8; 64] = signature
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid ledger signature"))?;
    key.verify(
        &serde_json::to_vec(&unsigned)?,
        &Signature::from_bytes(&sig),
    )
    .map_err(|_| anyhow::anyhow!("invalid ledger signature"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn test_path(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("hacienda-{name}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[tokio::test]
    async fn append_verify_and_transition() {
        let dir = test_path("ledger-transition");
        let ledger = DisclosureLedger::new(&dir.join("disclosure.log"))
            .await
            .unwrap();
        let handle = ledger
            .create_request(
                "tenant-a".into(),
                "blake3:principal".into(),
                "engine".into(),
                "policy".into(),
                2,
                BTreeMap::from([("email".into(), 2)]),
            )
            .await
            .unwrap();
        assert_eq!(
            ledger.status(&handle).await,
            Some(DisclosureStatus::Requested)
        );
        ledger
            .append_status(&handle, DisclosureStatus::Approved)
            .await
            .unwrap();
        assert_eq!(
            ledger.status(&handle).await,
            Some(DisclosureStatus::Approved)
        );
        assert!(
            ledger
                .append_status(&handle, DisclosureStatus::Requested)
                .await
                .is_err()
        );
        let raw = tokio::fs::read_to_string(ledger.path()).await.unwrap();
        assert!(raw.contains("signature"));
    }

    #[tokio::test]
    async fn serialized_ledger_never_contains_raw_sensitive_inputs() {
        let dir = test_path("ledger-negative");
        let ledger = DisclosureLedger::new(&dir.join("disclosure.log"))
            .await
            .unwrap();
        let handle = ledger
            .create_request(
                "tenant-a".into(),
                "blake3:principal".into(),
                "engine".into(),
                "policy".into(),
                1,
                BTreeMap::from([("email".into(), 1)]),
            )
            .await
            .unwrap();
        let serialized =
            serde_json::to_string(&ledger.query_by_handle(&handle).await.unwrap()).unwrap();
        for forbidden in [
            "alice@example.com",
            "secret-token",
            "/private/file",
            "raw-value",
            "snapshot",
        ] {
            assert!(!serialized.contains(forbidden));
        }
    }
}
