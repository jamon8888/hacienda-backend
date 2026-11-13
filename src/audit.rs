//! Durable tamper-evident audit trail with Ed25519 signatures and hash-chain.
//!
//! This module implements the #24 audit contract:
//! - Ed25519 signing with a key protected OUTSIDE the log directory.
//! - Strict sequence/order under concurrent appends.
//! - Hash-chain so truncation or record removal is detectable.
//! - Explicit rotation and retention.
//! - Failure semantics: required audit writes fail closed.
//!
//! Records are metadata-only: never raw arguments, values, tokens, snapshots,
//! manifests, queries, or errors.

use anyhow::{Context, Result};
use base64::Engine as _;
use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::warn;

/// Standard base64 engine (padded) for signatures and public keys.
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// Zero hash used as the genesis previous_hash for the first record.
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// MCP tools whose calls may be represented in this audit log.
///
/// Audit records are metadata-only: arguments are reduced to counts and result
/// details are reduced to safe status codes before they cross the append boundary.
pub const MCP_AUDIT_TOOLS: &[&str] = &[
    "search",
    "sync",
    "status",
    "attach_local_doc",
    "request_human_disclosure",
    "disclosure_status",
    "graph_entities",
    "graph_rag",
];

/// Failure policy for an audit append. Mutations fail closed; read-only calls
/// are allowed to return with an explicit audit-failed marker at their caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOperationClass {
    SideEffecting,
    ReadOnly,
}

impl AuditOperationClass {
    pub fn for_tool(tool: &str) -> Self {
        match tool {
            "sync" | "attach_local_doc" | "request_human_disclosure" | "disclosure_status" => {
                Self::SideEffecting
            }
            _ => Self::ReadOnly,
        }
    }
}

/// Metadata-only authorization result persisted with every audit record.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthorizationMetadata {
    pub principal_fingerprint: String,
    pub tenant_id: Option<String>,
    pub tool: String,
    pub decision: String,
    pub reason_class: String,
}

/// Audit record for a single MCP tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Unique sequence number (monotonically increasing within an epoch).
    pub sequence: u64,
    /// Epoch number (increments on each rotation).
    pub epoch: u64,
    /// Timestamp (RFC3339).
    pub timestamp: String,
    /// Principal ID that made the call (hashed fingerprint).
    pub principal_id: String,
    /// Allowlisted MCP tool name.
    pub tool: String,
    /// Metadata-only argument summary; never raw arguments or values.
    pub arguments: serde_json::Value,
    /// Structured authorization outcome; all values are metadata-only.
    #[serde(default)]
    pub authz: AuthorizationMetadata,
    /// Safe result status code; never an error detail.
    pub result_summary: String,
    /// Hash of the previous record (genesis uses all-zeros).
    pub previous_hash: String,
    /// Hash of this record's canonical content (excluding signature).
    pub record_hash: String,
    /// Ed25519 signature of the canonical JSON of this record (excluding signature field).
    pub signature: String,
    /// Public key used for verification (base64).
    pub public_key: String,
}

impl AuditRecord {
    /// Compute the canonical bytes for signing/hashing (excluding signature fields).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut to_sign = self.clone();
        to_sign.signature = String::new();
        to_sign.public_key = String::new();
        serde_json::to_vec(&to_sign).map_err(|e| anyhow::anyhow!("serialize: {}", e))
    }
}

/// Configuration for the durable audit log.
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Directory for rotated log files.
    pub log_dir: PathBuf,
    /// Directory for the signing key (must be OUTSIDE log_dir).
    pub key_dir: PathBuf,
    /// Maximum size in bytes before rotating to a new log file.
    pub max_size_bytes: u64,
    /// Maximum number of rotated log files to retain (0 = unlimited).
    pub max_rotated_files: u64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_dir: PathBuf::from("~/.local/share/hacienda/audit"),
            key_dir: PathBuf::from("~/.local/share/hacienda/keys/audit"),
            max_size_bytes: 10 * 1024 * 1024, // 10 MB
            max_rotated_files: 30,
        }
    }
}

/// Audit log manager with durable tamper-evident guarantees.
pub struct AuditLog {
    config: AuditConfig,
    writer: Arc<Mutex<BufWriter<std::fs::File>>>,
    current_path: Arc<Mutex<PathBuf>>,
    current_size: Arc<Mutex<u64>>,
    epoch: Arc<Mutex<u64>>,
    sequence: Arc<Mutex<u64>>,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl AuditLog {
    /// Create or open an audit log. Fails closed if the key cannot be loaded
    /// or generated, or if the log directory is not writable.
    pub async fn new(config: AuditConfig) -> Result<Self> {
        // Validate that key_dir is not inside log_dir (key must be outside log directory).
        let log_canonical = shellexpand::tilde(&config.log_dir.to_string_lossy())
            .into_owned()
            .parse::<std::path::PathBuf>()
            .unwrap_or(config.log_dir.clone());
        let key_canonical = shellexpand::tilde(&config.key_dir.to_string_lossy())
            .into_owned()
            .parse::<std::path::PathBuf>()
            .unwrap_or(config.key_dir.clone());

        if key_canonical.starts_with(&log_canonical) || log_canonical.starts_with(&key_canonical) {
            return Err(anyhow::anyhow!(
                "audit key_dir must not be inside log_dir and vice versa"
            ));
        }

        // Create directories.
        tokio::fs::create_dir_all(&config.log_dir)
            .await
            .map_err(|e| anyhow::anyhow!("create audit log dir: {}", e))?;
        tokio::fs::create_dir_all(&config.key_dir)
            .await
            .map_err(|e| anyhow::anyhow!("create audit key dir: {}", e))?;

        // Load or generate Ed25519 key pair OUTSIDE the log directory.
        let key_path = key_canonical.join("audit_signing_key");
        let signing_key = if key_path.exists() {
            let key_bytes = tokio::fs::read(&key_path)
                .await
                .map_err(|e| anyhow::anyhow!("read signing key: {}", e))?;
            let key_arr: [u8; 32] = key_bytes
                .as_slice()
                .try_into()
                .context("invalid signing key length (expected 32 bytes)")?;
            SigningKey::from_bytes(&key_arr)
        } else {
            let mut key_bytes = [0u8; 32];
            rand::rng().fill_bytes(&mut key_bytes);
            let key = SigningKey::from_bytes(&key_bytes);
            #[cfg(unix)]
            {
                let mut file = tokio::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&key_path)
                    .await
                    .map_err(|e| anyhow::anyhow!("create signing key file: {}", e))?;
                tokio::io::AsyncWriteExt::write_all(&mut file, &key.to_bytes())
                    .await
                    .map_err(|e| anyhow::anyhow!("write signing key: {}", e))?;
            }
            #[cfg(not(unix))]
            {
                tokio::fs::write(&key_path, key.to_bytes())
                    .await
                    .map_err(|e| anyhow::anyhow!("write signing key: {}", e))?;
            }
            key
        };
        let verifying_key = signing_key.verifying_key();

        // Determine current epoch by scanning existing log files.
        let (epoch, current_path, current_size) = Self::discover_current_log(&config).await?;

        // Determine current sequence by scanning the current log file.
        let sequence = Self::count_lines(&current_path).await.unwrap_or(0);

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&current_path)
            .context("reopen audit log for writing")?;
        let writer = BufWriter::new(file);

        Ok(Self {
            config,
            writer: Arc::new(Mutex::new(writer)),
            current_path: Arc::new(Mutex::new(current_path)),
            current_size: Arc::new(Mutex::new(current_size)),
            epoch: Arc::new(Mutex::new(epoch)),
            sequence: Arc::new(Mutex::new(sequence)),
            signing_key,
            verifying_key,
        })
    }

    /// Scan existing log files to find the current epoch and log file.
    async fn discover_current_log(config: &AuditConfig) -> Result<(u64, PathBuf, u64)> {
        let mut entries: Vec<(u64, PathBuf)> = Vec::new();
        if let Ok(mut readdir) = tokio::fs::read_dir(&config.log_dir).await {
            while let Some(entry) = readdir.next_entry().await.ok().flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("log") {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        if let Ok(epoch_num) = stem.parse::<u64>() {
                            let metadata = entry.metadata().await?;
                            entries.push((epoch_num, path));
                            _ = metadata;
                        }
                    }
                }
            }
        }

        if entries.is_empty() {
            let initial_path = config.log_dir.join("0.log");
            let size = if initial_path.exists() {
                tokio::fs::metadata(&initial_path)
                    .await
                    .map(|m| m.len())
                    .unwrap_or(0)
            } else {
                0
            };
            return Ok((0, initial_path, size));
        }

        entries.sort_by_key(|(e, _)| *e);
        let (latest_epoch, latest_path) = entries.last().cloned().unwrap();
        let size = tokio::fs::metadata(&latest_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        Ok((latest_epoch, latest_path, size))
    }

    async fn count_lines(path: &Path) -> Result<u64> {
        if !path.exists() {
            return Ok(0);
        }
        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);
        Ok(reader
            .lines()
            .filter(|l| l.is_ok() && !l.as_ref().unwrap().trim().is_empty())
            .count() as u64)
    }

    /// Compute the hash chain value for a record.
    fn compute_record_hash(canonical: &[u8], previous_hash: &str) -> String {
        let mut hasher = Hasher::new();
        hasher.update(previous_hash.as_bytes());
        hasher.update(canonical);
        hasher.finalize().to_hex().to_string()
    }

    /// Rotate to a new log file if the current one exceeds max_size_bytes.
    async fn maybe_rotate(&self) -> Result<()> {
        let size = *self.current_size.lock().await;
        if size < self.config.max_size_bytes {
            return Ok(());
        }

        // Flush and close current writer.
        {
            let mut writer = self.writer.lock().await;
            writer.flush()?;
            writer.get_ref().sync_all()?;
        }

        // Increment epoch.
        let new_epoch = {
            let mut e = self.epoch.lock().await;
            *e += 1;
            *e
        };

        // Enforce retention: remove oldest rotated files if over the limit.
        self.enforce_retention().await?;

        let new_path = self.config.log_dir.join(format!("{}.log", new_epoch));
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&new_path)
            .context("open new rotated audit log")?;
        {
            let mut writer = self.writer.lock().await;
            *writer = BufWriter::new(file);
        }
        *self.current_path.lock().await = new_path.clone();
        *self.current_size.lock().await = 0;

        tracing::info!("audit log rotated to epoch {}", new_epoch);
        Ok(())
    }

    /// Remove oldest rotated files beyond max_rotated_files.
    async fn enforce_retention(&self) -> Result<()> {
        if self.config.max_rotated_files == 0 {
            return Ok(());
        }

        let mut entries: Vec<(u64, PathBuf)> = Vec::new();
        if let Ok(mut readdir) = tokio::fs::read_dir(&self.config.log_dir).await {
            while let Some(entry) = readdir.next_entry().await.ok().flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("log") {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        if let Ok(epoch_num) = stem.parse::<u64>() {
                            entries.push((epoch_num, path));
                        }
                    }
                }
            }
        }

        entries.sort_by_key(|(e, _)| *e);
        let keep = self.config.max_rotated_files as usize;
        if entries.len() > keep {
            let to_remove = &entries[..entries.len() - keep];
            for (_, path) in to_remove {
                let _ = tokio::fs::remove_file(path).await;
                tracing::info!("audit rotation removed old log: {:?}", path);
            }
        }
        Ok(())
    }

    /// Get the last record hash from the current log file (for hash-chain continuity).
    async fn last_record_hash(&self) -> Result<String> {
        let path = self.current_path.lock().await.clone();
        if !path.exists() {
            return Ok(GENESIS_HASH.to_string());
        }
        let file = std::fs::File::open(&path)?;
        let reader = BufReader::new(file);
        let mut last_hash = GENESIS_HASH.to_string();
        for line in reader.lines().flatten() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(record) = serde_json::from_str::<AuditRecord>(&line) {
                last_hash = record.record_hash.clone();
            }
        }
        Ok(last_hash)
    }

    /// Append an audit record (WORM: append-only, signed, hash-chained).
    pub async fn append(&self, mut record: AuditRecord) -> Result<()> {
        // Enforce the MCP allowlist and metadata-only boundary before signing or writing.
        record = sanitize_record(record)?;

        // Assign sequence number and epoch.
        let (seq, epoch) = {
            let mut seq_guard = self.sequence.lock().await;
            *seq_guard += 1;
            let e = *self.epoch.lock().await;
            (*seq_guard, e)
        };
        record.sequence = seq;
        record.epoch = epoch;
        record.timestamp = chrono::Utc::now().to_rfc3339();

        // Hash-chain: link to previous record.
        let previous_hash = self.last_record_hash().await?;
        record.previous_hash = previous_hash;

        // Canonicalize for signing and record_hash.
        let canonical = record.canonical_bytes()?;
        let record_hash = Self::compute_record_hash(&canonical, &record.previous_hash);
        record.record_hash = record_hash.clone();

        // Sign.
        let signature = self.signing_key.sign(&canonical);
        record.signature = B64.encode(signature.to_bytes());
        record.public_key = B64.encode(self.verifying_key.to_bytes());

        // Write line-delimited JSON.
        let line = serde_json::to_string(&record)
            .map_err(|e| anyhow::anyhow!("serialize record: {}", e))?;
        let line_len = line.len() as u64 + 1; // +1 for newline

        // Rotate if needed (all mutable state is behind Arc<Mutex<>>).
        self.maybe_rotate().await?;

        let mut writer = self.writer.lock().await;
        writeln!(writer, "{}", line).map_err(|e| anyhow::anyhow!("write audit record: {}", e))?;
        writer
            .flush()
            .map_err(|e| anyhow::anyhow!("flush audit log: {}", e))?;

        *self.current_size.lock().await += line_len;

        Ok(())
    }

    /// Required append path. Callers must await this result before completing a
    /// side-effecting operation; an unavailable/unwritable audit store fails closed.
    pub async fn append_required(&self, record: AuditRecord) -> Result<()> {
        self.append(record).await
    }

    /// Append according to the operation policy. Read-only callers may choose
    /// to surface `audit_failed: true`; side-effecting callers must propagate.
    pub async fn append_for_operation(
        &self,
        record: AuditRecord,
        class: AuditOperationClass,
    ) -> Result<bool> {
        match self.append(record).await {
            Ok(()) => Ok(true),
            Err(error) if class == AuditOperationClass::ReadOnly => {
                warn!("read-only audit append failed: {}", error);
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    /// Verify the integrity of the entire audit log (all epochs).
    /// Checks: sequence continuity, hash-chain integrity, signatures.
    pub async fn verify_integrity(&self) -> Result<Vec<String>> {
        let mut errors = Vec::new();

        // Gather all log files sorted by epoch.
        let mut entries: Vec<(u64, PathBuf)> = Vec::new();
        if let Ok(mut readdir) = tokio::fs::read_dir(&self.config.log_dir).await {
            while let Some(entry) = readdir.next_entry().await.ok().flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("log") {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        if let Ok(epoch_num) = stem.parse::<u64>() {
                            entries.push((epoch_num, path));
                        }
                    }
                }
            }
        }
        entries.sort_by_key(|(e, _)| *e);

        if entries.is_empty() {
            return Ok(errors);
        }

        let mut expected_seq = 0u64;
        let mut previous_hash = GENESIS_HASH.to_string();

        for (epoch, path) in entries {
            let file = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    errors.push(format!("Epoch {}: cannot open log file: {}", epoch, e));
                    continue;
                }
            };
            let reader = BufReader::new(file);
            for (line_num, line) in reader.lines().enumerate() {
                let line = match line {
                    Ok(l) => l,
                    Err(e) => {
                        errors.push(format!(
                            "Epoch {} line {}: read error: {}",
                            epoch,
                            line_num + 1,
                            e
                        ));
                        continue;
                    }
                };
                if line.trim().is_empty() {
                    continue;
                }
                let record: AuditRecord = match serde_json::from_str(&line) {
                    Ok(r) => r,
                    Err(e) => {
                        errors.push(format!(
                            "Epoch {} line {}: parse error: {}",
                            epoch,
                            line_num + 1,
                            e
                        ));
                        continue;
                    }
                };

                expected_seq += 1;
                if record.sequence != expected_seq {
                    errors.push(format!(
                        "Epoch {} line {}: sequence gap (expected {}, got {})",
                        epoch,
                        line_num + 1,
                        expected_seq,
                        record.sequence
                    ));
                }
                if record.epoch != epoch {
                    errors.push(format!(
                        "Epoch {} line {}: epoch mismatch (expected {}, got {})",
                        epoch,
                        line_num + 1,
                        epoch,
                        record.epoch
                    ));
                }

                // Verify hash-chain continuity.
                if record.previous_hash != previous_hash {
                    errors.push(format!(
                        "Epoch {} line {}: hash-chain break (expected previous_hash {}, got {})",
                        epoch,
                        line_num + 1,
                        previous_hash,
                        record.previous_hash
                    ));
                }

                // Recompute record_hash.
                let mut to_verify = record.clone();
                to_verify.signature = String::new();
                to_verify.public_key = String::new();
                let canonical = match serde_json::to_vec(&to_verify) {
                    Ok(c) => c,
                    Err(e) => {
                        errors.push(format!(
                            "Epoch {} line {}: serialize error: {}",
                            epoch,
                            line_num + 1,
                            e
                        ));
                        continue;
                    }
                };
                let computed_hash = Self::compute_record_hash(&canonical, &record.previous_hash);
                if computed_hash != record.record_hash {
                    errors.push(format!(
                        "Epoch {} line {}: record_hash mismatch",
                        epoch,
                        line_num + 1
                    ));
                }
                previous_hash = record.record_hash.clone();

                // Verify signature against the trusted key (never the record's public_key).
                if record.public_key != B64.encode(self.verifying_key.to_bytes()) {
                    errors.push(format!(
                        "Epoch {} line {}: public key mismatch",
                        epoch,
                        line_num + 1
                    ));
                    continue;
                }
                let sig_bytes = match B64.decode(&record.signature) {
                    Ok(b) => b,
                    Err(e) => {
                        errors.push(format!(
                            "Epoch {} line {}: signature decode error: {}",
                            epoch,
                            line_num + 1,
                            e
                        ));
                        continue;
                    }
                };
                let sig_array: [u8; 64] = match sig_bytes.try_into() {
                    Ok(a) => a,
                    Err(_) => {
                        errors.push(format!(
                            "Epoch {} line {}: invalid signature length",
                            epoch,
                            line_num + 1
                        ));
                        continue;
                    }
                };
                if self
                    .verifying_key
                    .verify(&canonical, &Signature::from_bytes(&sig_array))
                    .is_err()
                {
                    errors.push(format!(
                        "Epoch {} line {}: invalid signature",
                        epoch,
                        line_num + 1
                    ));
                }
            }
        }

        Ok(errors)
    }

    /// Get the verifying key (base64) for external verification.
    pub fn verifying_key_b64(&self) -> String {
        B64.encode(self.verifying_key.to_bytes())
    }

    /// Get the current epoch.
    pub async fn current_epoch(&self) -> u64 {
        *self.epoch.lock().await
    }
}

/// Sanitize an audit record to enforce metadata-only boundary.
pub fn sanitize_record(mut record: AuditRecord) -> Result<AuditRecord> {
    if !MCP_AUDIT_TOOLS.contains(&record.tool.as_str()) {
        return Err(anyhow::anyhow!("audit tool is not allowlisted"));
    }

    // Store only a stable principal fingerprint; raw identity is not audit data.
    record.principal_id = format!(
        "blake3:{}",
        blake3::hash(record.principal_id.as_bytes()).to_hex()
    );
    record.arguments = serde_json::json!({
        "argument_count": match &record.arguments {
            serde_json::Value::Object(fields) => fields.len(),
            serde_json::Value::Array(values) => values.len(),
            serde_json::Value::Null => 0,
            _ => 1,
        },
    });
    record.result_summary = if record.result_summary.trim_start().starts_with("OK") {
        "OK".to_string()
    } else {
        "ERROR_CODE".to_string()
    };
    Ok(record)
}

/// Middleware to automatically audit MCP tool calls.
pub struct AuditMiddleware {
    audit_log: Arc<AuditLog>,
}

impl AuditMiddleware {
    pub fn new(audit_log: Arc<AuditLog>) -> Self {
        Self { audit_log }
    }

    /// Wrap a tool call with auditing.
    pub async fn audit_call<T>(
        &self,
        principal_id: &str,
        tool: &str,
        arguments: serde_json::Value,
        call: impl FnOnce() -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, anyhow::Error>> + Send>,
        >,
    ) -> Result<T, anyhow::Error> {
        let start = std::time::Instant::now();
        let result = call().await;
        let duration = start.elapsed();

        let result_summary = match &result {
            Ok(_) => format!("OK ({}ms)", duration.as_millis()),
            Err(_) => format!("ERROR_CODE ({}ms)", duration.as_millis()),
        };

        let record = AuditRecord {
            sequence: 0,
            epoch: 0,
            timestamp: String::new(),
            principal_id: principal_id.to_string(),
            tool: tool.to_string(),
            arguments,
            authz: AuthorizationMetadata::default(),
            result_summary,
            previous_hash: String::new(),
            record_hash: String::new(),
            signature: String::new(),
            public_key: String::new(),
        };

        let audit_ok = self
            .audit_log
            .append_for_operation(record, AuditOperationClass::for_tool(tool))
            .await?;
        if !audit_ok {
            warn!("read-only audit record was not persisted");
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AuditConfig {
        let dir = std::env::temp_dir().join(format!("hacienda-audit-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let key_dir = dir.join("keys");
        AuditConfig {
            log_dir: dir.join("logs"),
            key_dir,
            max_size_bytes: 1024, // small to force rotation quickly
            max_rotated_files: 3,
        }
    }

    #[tokio::test]
    async fn append_creates_hash_chain() {
        let config = test_config();
        let log = AuditLog::new(config.clone()).await.unwrap();

        let record1 = AuditRecord {
            sequence: 0,
            epoch: 0,
            timestamp: String::new(),
            principal_id: "principal-a".into(),
            tool: "search".into(),
            arguments: serde_json::json!({"q": "test"}),
            authz: AuthorizationMetadata::default(),
            result_summary: "OK".into(),
            previous_hash: String::new(),
            record_hash: String::new(),
            signature: String::new(),
            public_key: String::new(),
        };
        log.append(record1).await.unwrap();

        let record2 = AuditRecord {
            sequence: 0,
            epoch: 0,
            timestamp: String::new(),
            principal_id: "principal-b".into(),
            tool: "sync".into(),
            arguments: serde_json::json!({"path": "/x"}),
            authz: AuthorizationMetadata::default(),
            result_summary: "OK".into(),
            previous_hash: String::new(),
            record_hash: String::new(),
            signature: String::new(),
            public_key: String::new(),
        };
        log.append(record2).await.unwrap();

        let errors = log.verify_integrity().await.unwrap();
        assert!(errors.is_empty(), "integrity errors: {:?}", errors);
    }

    #[tokio::test]
    async fn rotation_preserves_hash_chain() {
        let config = test_config();
        let log = AuditLog::new(config.clone()).await.unwrap();

        for i in 0..10u64 {
            let record = AuditRecord {
                sequence: 0,
                epoch: 0,
                timestamp: String::new(),
                principal_id: format!("p{}", i),
                tool: "search".into(),
                arguments: serde_json::json!({"i": i}),
                authz: AuthorizationMetadata::default(),
                result_summary: "OK".into(),
                previous_hash: String::new(),
                record_hash: String::new(),
                signature: String::new(),
                public_key: String::new(),
            };
            log.append(record).await.unwrap();
        }

        let errors = log.verify_integrity().await.unwrap();
        assert!(
            errors.is_empty(),
            "integrity errors after rotation: {:?}",
            errors
        );

        // Check that rotation actually happened (multiple epoch files).
        let entries: Vec<_> = std::fs::read_dir(&config.log_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("log"))
            .collect();
        assert!(
            entries.len() > 1,
            "expected rotation to create multiple log files"
        );
    }

    #[tokio::test]
    async fn key_is_outside_log_dir() {
        let config = test_config();
        let _log = AuditLog::new(config.clone()).await.unwrap();
        assert!(!config.key_dir.starts_with(&config.log_dir));
        assert!(!config.log_dir.starts_with(&config.key_dir));
    }

    #[tokio::test]
    async fn audit_record_rejects_non_mcp_tools() {
        let record = AuditRecord {
            sequence: 0,
            epoch: 0,
            timestamp: String::new(),
            principal_id: "principal".into(),
            tool: "rehydrate".into(),
            arguments: serde_json::Value::Null,
            authz: AuthorizationMetadata::default(),
            result_summary: "OK".into(),
            previous_hash: String::new(),
            record_hash: String::new(),
            signature: String::new(),
            public_key: String::new(),
        };
        assert!(sanitize_record(record).is_err());
    }

    #[tokio::test]
    async fn metadata_only_sanitization() {
        let record = AuditRecord {
            sequence: 0,
            epoch: 0,
            timestamp: String::new(),
            principal_id: "principal".into(),
            tool: "search".into(),
            arguments: serde_json::json!({
                "query": "PII_QUERY_SHOULD_NOT_APPEAR",
                "token": "PII_TOKEN_SHOULD_NOT_APPEAR",
            }),
            authz: AuthorizationMetadata::default(),
            result_summary: "ERROR: PII_ERROR_SHOULD_NOT_APPEAR".into(),
            previous_hash: String::new(),
            record_hash: String::new(),
            signature: String::new(),
            public_key: String::new(),
        };
        let serialized = serde_json::to_string(&sanitize_record(record).unwrap()).unwrap();
        assert!(!serialized.contains("PII_QUERY_SHOULD_NOT_APPEAR"));
        assert!(!serialized.contains("PII_TOKEN_SHOULD_NOT_APPEAR"));
        assert!(!serialized.contains("PII_ERROR_SHOULD_NOT_APPEAR"));
        assert!(serialized.contains("argument_count"));
        assert!(serialized.contains("ERROR_CODE"));
    }
}
