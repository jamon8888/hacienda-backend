//! Durable metadata-only EvidenceLedger integration (#24/#35).
//!
//! Evidence is stored in SQLite, not JSONL. Signing keys come from custody;
//! this module never reads or writes plaintext key files. Test fixtures inject
//! an in-memory key and are separate from production constructors.

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rusqlite::{Connection, params};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use crate::disclosure::{AuditError, DisclosureAuditEntry, DisclosureAuditSink};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

pub trait EvidenceKeyCustody: Send + Sync {
    fn signing_key(&self) -> Result<[u8; 32]>;
}

#[derive(Debug, Clone)]
pub struct MacOsEvidenceKeyCustody {
    pub service: String,
    pub account: String,
}
impl EvidenceKeyCustody for MacOsEvidenceKeyCustody {
    fn signing_key(&self) -> Result<[u8; 32]> {
        #[cfg(target_os = "macos")]
        {
            let bytes =
                security_framework::passwords::get_generic_password(&self.service, &self.account)
                    .context("evidence keychain item unavailable")?;
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("evidence keychain item invalid"))
        }
        #[cfg(not(target_os = "macos"))]
        {
            bail!("macOS Keychain custody unavailable on this platform")
        }
    }
}

/// Windows Credential Manager custody. Credential Manager protects the blob
/// with the current Windows logon/DPAPI boundary; the key is never stored as a
/// plaintext file. The same-user compromise limitation is documented by ADR-0005.
#[derive(Debug, Clone, Default)]
pub struct WindowsCredentialEvidenceKeyCustody;
impl WindowsCredentialEvidenceKeyCustody {
    /// Provision the protected Windows Credential Manager item once during
    /// installation. Existing credentials are never overwritten.
    pub fn provision() -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            if WindowsCredentialEvidenceKeyCustody.signing_key().is_ok() {
                return Ok(());
            }
            use rand::RngCore;
            use windows::{
                Win32::Security::Credentials::{
                    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredWriteW,
                },
                core::PWSTR,
            };
            let mut target: Vec<u16> = "Hacienda-EvidenceLedger-SigningKey-v1"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut key = [0u8; 32];
            rand::rng().fill_bytes(&mut key);
            let credential = CREDENTIALW {
                Type: CRED_TYPE_GENERIC,
                TargetName: PWSTR(target.as_mut_ptr()),
                CredentialBlobSize: key.len() as u32,
                CredentialBlob: key.as_mut_ptr(),
                Persist: CRED_PERSIST_LOCAL_MACHINE,
                ..Default::default()
            };
            // SAFETY: `credential` points to live, writable UTF-16 and key
            // buffers for the synchronous CredWriteW call; Windows copies the
            // data before this function returns and no pointer escapes.
            unsafe { CredWriteW(&credential, 0) }
                .context("write protected Windows evidence key")?;
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            bail!("Windows Credential Manager unavailable on this platform")
        }
    }
}

impl EvidenceKeyCustody for WindowsCredentialEvidenceKeyCustody {
    fn signing_key(&self) -> Result<[u8; 32]> {
        #[cfg(target_os = "windows")]
        {
            use std::{ptr, slice};
            use windows::{
                Win32::Security::Credentials::{
                    CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW,
                },
                core::{HSTRING, PCWSTR},
            };
            let target = HSTRING::from("Hacienda-EvidenceLedger-SigningKey-v1");
            let mut raw: *mut CREDENTIALW = ptr::null_mut();
            // SAFETY: `target` is a live, NUL-terminated HSTRING for this
            // synchronous call; `raw` is a valid out-pointer and the API
            // allocates one buffer that is released exactly once with
            // CredFree below. The returned blob is copied before release.
            unsafe {
                CredReadW(
                    PCWSTR(target.as_ptr()),
                    CRED_TYPE_GENERIC,
                    Some(0),
                    &mut raw,
                )
            }
            .context("Windows Credential Manager evidence key unavailable")?;
            if raw.is_null() {
                bail!("Windows Credential Manager returned no evidence key")
            }
            // SAFETY: CredReadW succeeded and returned a non-null CREDENTIALW;
            // CredentialBlob/Size are the documented fields within that
            // allocation and are copied before CredFree invalidates them.
            let bytes = unsafe {
                let credential = &*raw;
                if credential.CredentialBlob.is_null() || credential.CredentialBlobSize != 32 {
                    CredFree(raw.cast());
                    bail!("Windows evidence key has invalid length");
                }
                slice::from_raw_parts(credential.CredentialBlob, 32).to_vec()
            };
            // SAFETY: raw is the single allocation returned by CredReadW and
            // has not been freed yet.
            unsafe { CredFree(raw.cast()) };
            bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Windows evidence key has invalid length"))
        }
        #[cfg(not(target_os = "windows"))]
        {
            bail!("Windows Credential Manager unavailable on this platform")
        }
    }
}

#[derive(Clone)]
pub struct FixtureEvidenceKey(pub [u8; 32]);
impl EvidenceKeyCustody for FixtureEvidenceKey {
    fn signing_key(&self) -> Result<[u8; 32]> {
        Ok(self.0)
    }
}

#[derive(Debug, Clone)]
pub struct EvidenceLedgerConfig {
    pub path: PathBuf,
}

pub struct EvidenceLedger {
    db: Arc<Mutex<Connection>>,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl EvidenceLedger {
    pub fn open(config: EvidenceLedgerConfig, custody: &dyn EvidenceKeyCustody) -> Result<Self> {
        if let Some(parent) = config.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db = Connection::open(&config.path).context("open evidence ledger database")?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS evidence (seq INTEGER PRIMARY KEY, epoch INTEGER NOT NULL, timestamp TEXT NOT NULL, event_json TEXT NOT NULL, previous_hash TEXT NOT NULL, record_hash TEXT NOT NULL, signature TEXT NOT NULL, public_key TEXT NOT NULL); CREATE INDEX IF NOT EXISTS evidence_event_idx ON evidence(event_json);")?;
        let key = SigningKey::from_bytes(&custody.signing_key()?);
        let verifying_key = key.verifying_key();
        let ledger = Self {
            db: Arc::new(Mutex::new(db)),
            signing_key: key,
            verifying_key,
        };
        ledger
            .verify()
            .context("evidence ledger integrity check failed")?;
        Ok(ledger)
    }

    pub fn append(&self, entry: DisclosureAuditEntry) -> Result<()> {
        validate_entry(&entry)?;
        let payload = serde_json::to_vec(&entry)?;
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("evidence ledger lock poisoned"))?;
        let seq: i64 = db.query_row("SELECT COALESCE(MAX(seq), 0) + 1 FROM evidence", [], |r| {
            r.get(0)
        })?;
        let previous = db
            .query_row(
                "SELECT record_hash FROM evidence ORDER BY seq DESC LIMIT 1",
                [],
                |r| r.get::<_, String>(0),
            )
            .unwrap_or_else(|_| "0".repeat(64));
        let mut hash_input = previous.as_bytes().to_vec();
        hash_input.extend_from_slice(&payload);
        let record_hash = blake3::hash(&hash_input).to_hex().to_string();
        let signature = B64.encode(self.signing_key.sign(&payload).to_bytes());
        let public_key = B64.encode(self.verifying_key.to_bytes());
        let json = String::from_utf8(payload).map_err(|_| anyhow::anyhow!("metadata encoding"))?;
        db.execute("INSERT INTO evidence(seq,epoch,timestamp,event_json,previous_hash,record_hash,signature,public_key) VALUES(?1,0,?2,?3,?4,?5,?6,?7)", params![seq, entry.timestamp, json, previous, record_hash, signature, public_key])?;
        Ok(())
    }

    pub fn verify(&self) -> Result<u64> {
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("evidence ledger lock poisoned"))?;
        let mut stmt = db.prepare("SELECT seq,event_json,previous_hash,record_hash,signature,public_key FROM evidence ORDER BY seq")?;
        let mut rows = stmt.query([])?;
        let mut previous = "0".repeat(64);
        let mut count = 0;
        while let Some(row) = rows.next()? {
            let seq_i64: i64 = row.get(0)?;
            let seq: u64 = seq_i64
                .try_into()
                .context("evidence sequence is outside the u64 range")?;
            let payload: Vec<u8> = row.get::<_, String>(1)?.into_bytes();
            let prev: String = row.get(2)?;
            let hash: String = row.get(3)?;
            let sig: String = row.get(4)?;
            let pubkey: String = row.get(5)?;
            if prev != previous {
                bail!("evidence chain mismatch at sequence {seq}");
            }
            let mut input = prev.as_bytes().to_vec();
            input.extend_from_slice(&payload);
            if blake3::hash(&input).to_hex().to_string() != hash {
                bail!("evidence hash mismatch at sequence {seq}");
            }
            let pk = VerifyingKey::from_bytes(
                &B64.decode(pubkey)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("public key length"))?,
            )?;
            let signature = Signature::from_bytes(
                &B64.decode(sig)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("signature length"))?,
            );
            pk.verify(&payload, &signature)
                .map_err(|_| anyhow::anyhow!("evidence signature mismatch"))?;
            previous = hash;
            count += 1;
        }
        Ok(count)
    }
}

fn validate_entry(entry: &DisclosureAuditEntry) -> Result<()> {
    if entry.request_id.is_empty()
        || entry.handle_hash.len() != 64
        || entry.principal_id.is_empty()
        || entry.tenant_id.is_empty()
        || entry.scope_ref.len() > 256
        || entry.scope_ref.contains('<')
        || entry.scope_ref.contains('>')
        || entry.scope_ref.contains('\n')
        || entry.scope_ref.contains('\r')
        || (entry.scope_kind == "entity"
            && !(entry.scope_ref.starts_with('[') && entry.scope_ref.ends_with(']')))
    {
        bail!("disclosure evidence metadata rejected");
    }
    Ok(())
}

#[async_trait]
impl DisclosureAuditSink for EvidenceLedger {
    async fn record(&self, entry: DisclosureAuditEntry) -> Result<(), AuditError> {
        self.append(entry).map_err(|_| AuditError::Unavailable)
    }
}

pub type DisclosureLedger = EvidenceLedger;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disclosure::{DisclosureAuditEntry, DisclosureEvent};

    #[test]
    fn sqlite_chain_is_signed_without_plaintext_key_file() {
        let path =
            std::env::temp_dir().join(format!("hacienda-evidence-{}.sqlite", uuid::Uuid::new_v4()));
        let ledger = EvidenceLedger::open(
            EvidenceLedgerConfig { path: path.clone() },
            &FixtureEvidenceKey([7; 32]),
        )
        .unwrap();
        ledger
            .append(DisclosureAuditEntry {
                timestamp: "2026-01-01T00:00:00Z".into(),
                event: DisclosureEvent::Requested,
                request_id: "request".into(),
                handle_hash: "a".repeat(64),
                scope_kind: "entity".into(),
                scope_ref: "[EMAIL_1]".into(),
                principal_id: "agent".into(),
                tenant_id: "tenant".into(),
                outcome: "accepted",
                reason: None,
            })
            .unwrap();
        assert_eq!(ledger.verify().unwrap(), 1);
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.starts_with(b"SQLite format 3\0"));
        assert!(!path.with_extension("key").exists());
        let _ = std::fs::remove_file(path);
    }
}
