//! WORM (Write Once Read Many) audit trail with Ed25519 signatures.
//! Provides tamper-evident logging for all MCP tool calls.

use anyhow::{Context, Result};
use rand::RngCore;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

/// Audit record for a single MCP tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Unique sequence number (monotonically increasing).
    pub sequence: u64,
    /// Timestamp (RFC3339).
    pub timestamp: String,
    /// Principal ID that made the call.
    pub principal_id: String,
    /// Tool name (e.g., "search", "rehydrate", "sync", "status").
    pub tool: String,
    /// Arguments passed to the tool (JSON).
    pub arguments: serde_json::Value,
    /// Result summary (success/error, not full payload).
    pub result_summary: String,
    /// Ed25519 signature of the canonical JSON of this record (excluding signature field).
    pub signature: String,
    /// Public key used for verification (base64).
    pub public_key: String,
}

/// Audit log manager with WORM guarantees.
pub struct AuditLog {
    path: std::path::PathBuf,
    writer: Arc<Mutex<BufWriter<std::fs::File>>>,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    sequence: Arc<Mutex<u64>>,
    /// In-memory index for fast lookups (optional).
    index: Arc<Mutex<HashMap<u64, u64>>>,
}

impl AuditLog {
    /// Create or open an audit log file.
    pub async fn new(log_path: &Path) -> Result<Self> {
        // Create parent directory if needed
        if let Some(parent) = log_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| anyhow::anyhow!("create audit log directory: {}", e))?;
        }

        // Open file in append mode
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .map_err(|e| anyhow::anyhow!("open audit log file: {}", e))?;
        let writer = BufWriter::new(file);

        // Load or generate Ed25519 key pair
        let key_path = log_path.with_extension("key");
        let (signing_key, verifying_key) = if key_path.exists() {
            let key_bytes = tokio::fs::read(&key_path).await.map_err(|e| anyhow::anyhow!("read signing key: {}", e))?;
            let signing_key = SigningKey::from_bytes(&key_bytes[..32].try_into().context("invalid key length")?);
            let verifying_key = signing_key.verifying_key();
            (signing_key, verifying_key)
        } else {
            let mut key_bytes = [0u8; 32];
            let mut rng = rand::thread_rng();
            rand::RngCore::fill_bytes(&mut rng, &mut key_bytes);
            let signing_key = SigningKey::from_bytes(&key_bytes);
            let verifying_key = signing_key.verifying_key();
            // Persist private key (in production, store securely)
            tokio::fs::write(&key_path, signing_key.to_bytes()).await.map_err(|e| anyhow::anyhow!("write signing key: {}", e))?;
            (signing_key, verifying_key)
        };

        // Determine current sequence by scanning file (simplified: count lines)
        let sequence = if log_path.exists() {
            let content = tokio::fs::read_to_string(log_path).await.unwrap_or_default();
            content.lines().count() as u64
        } else {
            0
        };

        Ok(Self {
            path: log_path.to_path_buf(),
            writer: Arc::new(Mutex::new(BufWriter::new(
                OpenOptions::new().create(true).append(true).open(log_path).context("reopen for writing")?
            ))),
            signing_key,
            verifying_key,
            sequence: Arc::new(Mutex::new(sequence)),
            index: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Append an audit record (WORM: append-only, signed).
    pub async fn append(&self, mut record: AuditRecord) -> Result<()> {
        // Assign sequence number
        let seq = {
            let mut seq_guard = self.sequence.lock().await;
            *seq_guard += 1;
            *seq_guard
        };
        record.sequence = seq;
        record.timestamp = chrono::Utc::now().to_rfc3339();

        // Canonicalize for signing (exclude signature field)
        let mut to_sign = record.clone();
        to_sign.signature = String::new();
        to_sign.public_key = String::new();
        let canonical = serde_json::to_vec(&to_sign).map_err(|e| anyhow::anyhow!("serialize for signing: {}", e))?;

        // Sign
        let signature = self.signing_key.sign(&canonical);
        record.signature = base64::encode(signature.to_bytes());
        record.public_key = base64::encode(self.verifying_key.to_bytes());

        // Write line-delimited JSON
        let line = serde_json::to_string(&record).map_err(|e| anyhow::anyhow!("serialize record: {}", e))?;
        let mut writer = self.writer.lock().await;
        use std::io::{Seek, SeekFrom};
        let pos = writer.get_ref().seek(std::io::SeekFrom::Current(0)).map_err(|e| anyhow::anyhow!("get stream position: {}", e))?;
        writeln!(writer, "{}", line).map_err(|e| anyhow::anyhow!("write audit record: {}", e))?;
        writer.flush().map_err(|e| anyhow::anyhow!("flush audit log: {}", e))?;

        // Update index
        self.index.lock().await.insert(record.sequence, pos);

        Ok(())
    }

    /// Verify the integrity of the audit log (check signatures and sequence).
    pub async fn verify_integrity(&self) -> Result<Vec<String>> {
        let content = tokio::fs::read_to_string(&self.path).await.map_err(|e| anyhow::anyhow!("read audit log: {}", e))?;
        let mut errors = Vec::new();
        let mut expected_seq = 0u64;

        for (line_num, line) in content.lines().enumerate() {
            if line.trim().is_empty() { continue; }
            let record: AuditRecord = serde_json::from_str(line).map_err(|e| anyhow::anyhow!("parse audit record: {}", e))?;
            expected_seq += 1;
            if record.sequence != expected_seq {
                errors.push(format!("Line {}: sequence gap (expected {}, got {})", line_num + 1, expected_seq, record.sequence));
            }
            // Verify signature
            let mut to_verify = record.clone();
            to_verify.signature = String::new();
            to_verify.public_key = String::new();
            let canonical = serde_json::to_vec(&to_verify).map_err(|e| anyhow::anyhow!("serialize for verification: {}", e))?;
            let sig_bytes = base64::decode(&record.signature).map_err(|e| anyhow::anyhow!("decode signature: {}", e))?;
            let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| anyhow::anyhow!("invalid signature length"))?;
            let sig = Signature::from_bytes(&sig_array);
            let pk_bytes = base64::decode(&record.public_key).map_err(|e| anyhow::anyhow!("decode public key: {}", e))?;
            let pk_array: [u8; 32] = pk_bytes.try_into().map_err(|_| anyhow::anyhow!("invalid key length"))?;
            let verifying_key = VerifyingKey::from_bytes(&pk_array).map_err(|e| anyhow::anyhow!("invalid verifying key: {}", e))?;
            if verifying_key.verify(&canonical, &sig).is_err() {
                errors.push(format!("Line {}: invalid signature", line_num + 1));
            }
        }
        Ok(errors)
    }

    /// Get the verifying key (base64) for external verification.
    pub fn verifying_key_b64(&self) -> String {
        base64::encode(self.verifying_key.to_bytes())
    }
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
        call: impl FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, anyhow::Error>> + Send>>,
    ) -> Result<T, anyhow::Error> {
        let start = std::time::Instant::now();
        let result = call().await;
        let duration = start.elapsed();

        let (result_summary, success) = match &result {
            Ok(_) => (format!("OK ({}ms)", duration.as_millis()), true),
            Err(e) => (format!("ERROR: {} ({}ms)", e, duration.as_millis()), false),
        };

        let record = AuditRecord {
            sequence: 0, // will be set by append
            timestamp: String::new(),
            principal_id: principal_id.to_string(),
            tool: tool.to_string(),
            arguments,
            result_summary,
            signature: String::new(),
            public_key: String::new(),
        };

        // Fire-and-forget audit (non-blocking)
        let audit_log = self.audit_log.clone();
        tokio::spawn(async move {
            if let Err(e) = audit_log.append(record).await {
                warn!("Failed to write audit record: {}", e);
            }
        });

        result
    }
}
