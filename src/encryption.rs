//! Encryption at rest for LanceDB, Tantivy, and Vault.
//! Supports AES-256-GCM and ChaCha20-Poly1305 with KMS/HSM integration.

#[cfg(target_os = "windows")]
use anyhow::bail;
use anyhow::{Context, Result};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::config::EncryptionConfig;

/// Service/account names are identifiers, never key material.
pub const VAULT_KEYCHAIN_SERVICE: &str = "hacienda-backend-vault";
pub const VAULT_KEYCHAIN_ACCOUNT: &str = "vault-key-v1";
#[cfg(target_os = "windows")]
const WINDOWS_VAULT_CREDENTIAL_TARGET: &str = "Hacienda-Vault-Key-v1";

/// Custody seam for vault encryption. Implementations must never expose key material in logs.
pub trait VaultKeyProvider: Send + Sync {
    fn key(&self) -> Result<[u8; 32]>;
}

/// Explicit development/test fixture. Production constructors reject this provider.
pub struct FixtureVaultKeyProvider(pub [u8; 32]);
impl VaultKeyProvider for FixtureVaultKeyProvider {
    fn key(&self) -> Result<[u8; 32]> {
        Ok(self.0)
    }
}

/// macOS Keychain-backed vault custody.
pub struct KeychainVaultKeyProvider;
impl VaultKeyProvider for KeychainVaultKeyProvider {
    fn key(&self) -> Result<[u8; 32]> {
        #[cfg(target_os = "macos")]
        {
            use security_framework::passwords::get_generic_password;
            let bytes = get_generic_password(VAULT_KEYCHAIN_SERVICE, VAULT_KEYCHAIN_ACCOUNT)
                .context("vault Keychain item is unavailable")?;
            let key: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("vault Keychain item has invalid length"))?;
            Ok(key)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(anyhow::anyhow!(
                "production vault custody requires macOS Keychain"
            ))
        }
    }
}

/// Windows Credential Manager-backed vault custody. Credential Manager/DPAPI
/// is the production Windows custody seam; missing or malformed credentials
/// fail closed instead of falling back to a passphrase or environment value.
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsCredentialVaultKeyProvider;

#[cfg(target_os = "windows")]
impl VaultKeyProvider for WindowsCredentialVaultKeyProvider {
    fn key(&self) -> Result<[u8; 32]> {
        use std::{ptr, slice};
        use windows::{
            Win32::Security::Credentials::{CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW},
            core::{HSTRING, PCWSTR},
        };
        let target = HSTRING::from(WINDOWS_VAULT_CREDENTIAL_TARGET);
        let mut raw: *mut CREDENTIALW = ptr::null_mut();
        // SAFETY: target is a live NUL-terminated UTF-16 string and raw is a
        // valid out-pointer for this synchronous API. The returned allocation
        // is copied and released exactly once below.
        unsafe {
            CredReadW(
                PCWSTR(target.as_ptr()),
                CRED_TYPE_GENERIC,
                Some(0),
                &mut raw,
            )
        }
        .context("Windows Credential Manager vault key unavailable")?;
        if raw.is_null() {
            bail!("Windows Credential Manager returned no vault key");
        }
        // SAFETY: CredReadW succeeded and returned a live CREDENTIALW. The
        // blob is copied before CredFree invalidates the allocation.
        let result = unsafe {
            let credential = &*raw;
            if credential.CredentialBlob.is_null() || credential.CredentialBlobSize != 32 {
                CredFree(raw.cast());
                bail!("Windows vault credential has invalid length");
            }
            slice::from_raw_parts(credential.CredentialBlob, 32).try_into()
        };
        // SAFETY: raw is the one allocation returned by CredReadW and is not
        // used after this release.
        unsafe { CredFree(raw.cast()) };
        result.map_err(|_| anyhow::anyhow!("Windows vault credential has invalid length"))
    }
}

/// Select custody from validated configuration. Production never accepts a
/// fixture key; development/test fixtures must be explicitly supplied.
pub fn vault_key_provider(config: &EncryptionConfig) -> Result<Box<dyn VaultKeyProvider>> {
    let mode = if config.assurance_mode.is_production() {
        "production"
    } else {
        "development"
    };
    select_vault_key_provider(mode)
}

/// Backwards-compatible custody entry point for CLI paths that have not yet
/// been given a loaded config. The environment is an explicit development/test
/// seam only; production still defaults to fail-closed Keychain custody.
pub fn default_vault_key_provider() -> Result<Box<dyn VaultKeyProvider>> {
    let mode = std::env::var("HACIENDA_ASSURANCE_MODE").unwrap_or_else(|_| "production".to_owned());
    select_vault_key_provider(&mode)
}

fn select_vault_key_provider(mode: &str) -> Result<Box<dyn VaultKeyProvider>> {
    match mode {
        "production" => {
            #[cfg(target_os = "macos")]
            {
                let provider: Box<dyn VaultKeyProvider> = Box::new(KeychainVaultKeyProvider);
                provider
                    .key()
                    .context("production vault custody unavailable")?;
                Ok(provider)
            }
            #[cfg(target_os = "windows")]
            {
                let provider: Box<dyn VaultKeyProvider> =
                    Box::new(WindowsCredentialVaultKeyProvider);
                provider
                    .key()
                    .context("production vault custody unavailable")?;
                Ok(provider)
            }
            #[cfg(not(any(target_os = "macos", target_os = "windows")))]
            {
                Err(anyhow::anyhow!(
                    "production vault custody unavailable on this platform"
                ))
            }
        }
        "development" | "test" => {
            let raw = std::env::var("HACIENDA_VAULT_FIXTURE_KEY").context(
                "development/test requires explicit ephemeral HACIENDA_VAULT_FIXTURE_KEY",
            )?;
            let bytes = blake3::hash(raw.as_bytes());
            Ok(Box::new(FixtureVaultKeyProvider(*bytes.as_bytes())))
        }
        _ => Err(anyhow::anyhow!(
            "invalid assurance mode or development fixture refused"
        )),
    }
}

/// Authenticated vault blob bound to fingerprint and document identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultBlob {
    pub algorithm: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub fingerprint: String,
    pub document_binding: String,
}

pub fn encrypt_vault_blob(
    plaintext: &[u8],
    fingerprint: &str,
    document_binding: &str,
    provider: &dyn VaultKeyProvider,
) -> Result<Vec<u8>> {
    use aes_gcm::{
        Aes256Gcm, KeyInit, Nonce,
        aead::{Aead, Payload},
    };
    let cipher = Aes256Gcm::new((&provider.key()?).into());
    let nonce_bytes: [u8; 12] = rand::random();
    let aad = format!("hacienda-vault-v1\\0{fingerprint}\\0{document_binding}");
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("vault encryption failed"))?;
    serde_json::to_vec(&VaultBlob {
        algorithm: "aes256gcm".into(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
        fingerprint: fingerprint.into(),
        document_binding: document_binding.into(),
    })
    .context("serialize vault blob")
}

pub fn decrypt_vault_blob(
    blob: &[u8],
    expected_fingerprint: &str,
    document_binding: &str,
    provider: &dyn VaultKeyProvider,
) -> Result<Vec<u8>> {
    use aes_gcm::{
        Aes256Gcm, KeyInit, Nonce,
        aead::{Aead, Payload},
    };
    let envelope: VaultBlob = serde_json::from_slice(blob).context("parse vault blob")?;
    if envelope.algorithm != "aes256gcm"
        || envelope.fingerprint != expected_fingerprint
        || envelope.document_binding != document_binding
        || envelope.nonce.len() != 12
    {
        return Err(anyhow::anyhow!("vault binding mismatch"));
    }
    let cipher = Aes256Gcm::new((&provider.key()?).into());
    let aad = format!("hacienda-vault-v1\\0{expected_fingerprint}\\0{document_binding}");
    cipher
        .decrypt(
            Nonce::from_slice(&envelope.nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("vault authentication failed"))
}

/// Master key for encryption (wrapped by KMS or derived from passphrase).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    key: [u8; 32], // 256-bit key for AES-256-GCM / ChaCha20-Poly1305
}

impl MasterKey {
    /// Generate a new random master key.
    pub fn generate() -> Result<Self> {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        Ok(Self { key })
    }

    /// Get the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Construct from raw key bytes (used when unwrapping from custody).
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Wrap (encrypt) this master key using the KMS.
    pub async fn wrap(&self, kms: &dyn KmsClient) -> Result<WrappedKey> {
        kms.wrap_key(&self.key).await
    }

    /// Unwrap (decrypt) a wrapped master key using the KMS.
    pub async fn unwrap(wrapped: &WrappedKey, kms: &dyn KmsClient) -> Result<Self> {
        let key = kms.unwrap_key(wrapped).await?;
        Ok(Self { key })
    }
}
/// Provider tag for keys wrapped with the vault custody key (not a KMS).
const CUSTODY_WRAP_PROVIDER: &str = "vault-custody";

/// AAD binding for key-wrapping operations (domain separation from data and vault blobs).
const KEY_WRAP_AAD: &[u8] = b"hacienda-key-wrap-v1";

/// Wrap a 32-byte key with the master key (AES-256-GCM envelope, nonce prepended).
fn wrap_key_with_master(master: &MasterKey, key: &[u8; 32]) -> Result<WrappedKey> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let cipher = Aes256Gcm::new(master.as_bytes().into());
    let nonce_bytes: [u8; 12] = rand::random();
    let mut ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: key,
                aad: KEY_WRAP_AAD,
            },
        )
        .map_err(|_| anyhow::anyhow!("key wrapping failed"))?;
    let mut blob = nonce_bytes.to_vec();
    blob.append(&mut ciphertext);
    Ok(WrappedKey {
        ciphertext: blob,
        provider: "local-envelope".to_string(),
        key_id: "master-key".to_string(),
        metadata: serde_json::json!({}),
    })
}

/// Unwrap a 32-byte key wrapped with the master key.
fn unwrap_key_with_master(master: &MasterKey, wrapped: &WrappedKey) -> Result<[u8; 32]> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    // nonce (12) + at least tag (16)
    anyhow::ensure!(
        wrapped.ciphertext.len() >= 12 + 16,
        "wrapped key is too short"
    );
    let (nonce, ct) = wrapped.ciphertext.split_at(12);
    let cipher = Aes256Gcm::new(master.as_bytes().into());
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: KEY_WRAP_AAD,
            },
        )
        .map_err(|_| anyhow::anyhow!("key unwrapping failed"))?;
    plaintext
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("unwrapped key has invalid length"))
}

/// Wrap a 32-byte key with the vault custody key (AES-256-GCM envelope).
fn wrap_key_with_custody(provider: &dyn VaultKeyProvider, key: &[u8; 32]) -> Result<WrappedKey> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let cipher = Aes256Gcm::new((&provider.key()?).into());
    let nonce_bytes: [u8; 12] = rand::random();
    let mut ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: key,
                aad: KEY_WRAP_AAD,
            },
        )
        .map_err(|_| anyhow::anyhow!("custody key wrapping failed"))?;
    let mut blob = nonce_bytes.to_vec();
    blob.append(&mut ciphertext);
    Ok(WrappedKey {
        ciphertext: blob,
        provider: CUSTODY_WRAP_PROVIDER.to_string(),
        key_id: VAULT_KEYCHAIN_ACCOUNT.to_string(),
        metadata: serde_json::json!({}),
    })
}

/// Unwrap a 32-byte key wrapped with the vault custody key.
fn unwrap_key_with_custody(
    provider: &dyn VaultKeyProvider,
    wrapped: &WrappedKey,
) -> Result<[u8; 32]> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    anyhow::ensure!(
        wrapped.ciphertext.len() >= 12 + 16,
        "wrapped key is too short"
    );
    let (nonce, ct) = wrapped.ciphertext.split_at(12);
    let cipher = Aes256Gcm::new((&provider.key()?).into());
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: KEY_WRAP_AAD,
            },
        )
        .map_err(|_| anyhow::anyhow!("custody key unwrapping failed"))?;
    plaintext
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("unwrapped key has invalid length"))
}

/// Atomically create a key file with owner-only permissions and write `data`.
async fn write_key_file(path: &Path, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .await
            .with_context(|| format!("create key file {}", path.display()))?;
        tokio::io::AsyncWriteExt::write_all(&mut file, data)
            .await
            .with_context(|| format!("write key file {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        tokio::fs::write(path, data)
            .await
            .with_context(|| format!("write key file {}", path.display()))?;
    }
    Ok(())
}

/// A master key wrapped (encrypted) by the KMS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    /// The encrypted key material.
    pub ciphertext: Vec<u8>,
    /// KMS provider identifier.
    pub provider: String,
    /// Key ID/alias used for wrapping.
    pub key_id: String,
    /// Additional metadata.
    #[serde(default)]
    pub metadata: serde_json::Value,
}

impl TryFrom<Vec<u8>> for WrappedKey {
    type Error = anyhow::Error;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        serde_json::from_slice(&data).context("parse wrapped key")
    }
}

/// KMS client trait for key wrapping/unwrapping.
#[async_trait::async_trait]
pub trait KmsClient: Send + Sync {
    /// Wrap (encrypt) a data encryption key.
    async fn wrap_key(&self, key: &[u8; 32]) -> Result<WrappedKey>;

    /// Unwrap (decrypt) a wrapped data encryption key.
    async fn unwrap_key(&self, wrapped: &WrappedKey) -> Result<[u8; 32]>;

    /// Get the provider name.
    fn provider_name(&self) -> &str;

    /// Get the key ID/alias.
    fn key_id(&self) -> &str;
}

/// Encrypted file format for at-rest encryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedFile {
    /// Encryption algorithm used.
    pub algorithm: String,
    /// Nonce/IV used for encryption.
    pub nonce: Vec<u8>,
    /// Encrypted data.
    pub ciphertext: Vec<u8>,
    /// Authentication tag (for AES-GCM).
    #[serde(default)]
    pub tag: Option<Vec<u8>>,
    /// Wrapped data encryption key.
    pub wrapped_dek: WrappedKey,
    /// File metadata.
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Encryption engine for file-level encryption.
pub struct EncryptionEngine {
    config: EncryptionConfig,
    kms_client: Option<Box<dyn KmsClient>>,
    vault_provider: Option<Box<dyn VaultKeyProvider>>,
    master_key: Option<MasterKey>,
}

impl EncryptionEngine {
    /// Create a new encryption engine.
    pub async fn new(
        config: EncryptionConfig,
        kms_config: Option<crate::config::KmsConfig>,
    ) -> Result<Self> {
        // Resolve custody from the validated config rather than silently using
        // HACIENDA_ASSURANCE_MODE when an application supplies configuration.
        // This also preserves production's fail-closed Keychain requirement.
        let vault_provider = vault_key_provider(&config)?;
        let kms_client = if let Some(kms_config) = kms_config {
            Some(create_kms_client(kms_config).await?)
        } else {
            None
        };

        Ok(Self {
            config,
            kms_client,
            vault_provider: Some(vault_provider),
            master_key: None,
        })
    }

    /// Initialize the engine (generate or load master key).
    ///
    /// Fails closed when encryption is enabled but no durable key source is
    /// available: a silently generated ephemeral master key would be lost on
    /// restart and make every previously encrypted file unrecoverable.
    pub async fn initialize(&mut self, key_path: Option<&Path>) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        if let Some(path) = key_path
            && path.exists()
        {
            // Load existing wrapped key
            let data = tokio::fs::read(path).await.context("read wrapped key")?;
            let wrapped: WrappedKey = serde_json::from_slice(&data).context("parse wrapped key")?;

            self.master_key = Some(self.unwrap_master_key(&wrapped).await?);
        }

        // Generate a new master key only when it can be persisted wrapped.
        if self.master_key.is_none() {
            let path = key_path.ok_or_else(|| {
                anyhow::anyhow!(
                    "encryption is enabled but no key_path was provided to persist the wrapped master key"
                )
            })?;
            let master_key = MasterKey::generate()?;
            let wrapped = self.wrap_master_key(&master_key).await?;
            let data = serde_json::to_vec(&wrapped).context("serialize wrapped key")?;
            write_key_file(path, &data).await?;
            self.master_key = Some(master_key);
        }

        Ok(())
    }

    /// Wrap the master key with the configured KMS, or with the vault custody
    /// key when no KMS is configured.
    async fn wrap_master_key(&self, master_key: &MasterKey) -> Result<WrappedKey> {
        if let Some(kms) = &self.kms_client {
            return master_key.wrap(kms.as_ref()).await;
        }
        if let Some(provider) = &self.vault_provider {
            return wrap_key_with_custody(provider.as_ref(), master_key.as_bytes());
        }
        Err(anyhow::anyhow!(
            "no key source (KMS or vault custody) available to wrap the master key"
        ))
    }

    /// Unwrap the master key from a persisted `WrappedKey`.
    async fn unwrap_master_key(&self, wrapped: &WrappedKey) -> Result<MasterKey> {
        if wrapped.provider == CUSTODY_WRAP_PROVIDER {
            let provider = self.vault_provider.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "wrapped master key uses vault custody but no custody provider is configured"
                )
            })?;
            let key = unwrap_key_with_custody(provider.as_ref(), wrapped)?;
            return Ok(MasterKey::from_bytes(key));
        }
        let kms = self.kms_client.as_ref().ok_or_else(|| {
            anyhow::anyhow!("wrapped key file exists but no KMS client is configured to unwrap it")
        })?;
        MasterKey::unwrap(wrapped, kms.as_ref()).await
    }

    /// Encrypt data using the master key.
    pub fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<EncryptedFile> {
        let master_key = self
            .master_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("encryption engine not initialized"))?;

        match self.config.algorithm.as_str() {
            "aes256gcm" => self.encrypt_aes256gcm(master_key, plaintext, associated_data),
            "chacha20poly1305" => {
                self.encrypt_chacha20poly1305(master_key, plaintext, associated_data)
            }
            _ => Err(anyhow::anyhow!(
                "unsupported algorithm: {}",
                self.config.algorithm
            )),
        }
    }

    /// Decrypt data using the master key.
    pub fn decrypt(&self, encrypted: &EncryptedFile, associated_data: &[u8]) -> Result<Vec<u8>> {
        let master_key = self
            .master_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("encryption engine not initialized"))?;

        match encrypted.algorithm.as_str() {
            "aes256gcm" => self.decrypt_aes256gcm(master_key, encrypted, associated_data),
            "chacha20poly1305" => {
                self.decrypt_chacha20poly1305(master_key, encrypted, associated_data)
            }
            _ => Err(anyhow::anyhow!(
                "unsupported algorithm: {}",
                encrypted.algorithm
            )),
        }
    }

    fn encrypt_aes256gcm(
        &self,
        key: &MasterKey,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncryptedFile> {
        use aes_gcm::aead::{Aead, Payload};
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

        // Per-file DEK: the long-lived master key only wraps DEKs, so a random
        // nonce is never reused under the master key for data encryption.
        let dek = MasterKey::generate()?;
        let cipher = Aes256Gcm::new(dek.as_bytes().into());
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|e| anyhow::anyhow!("AES-GCM encryption failed: {e}"))?;

        // Split ciphertext and tag (AES-GCM appends tag)
        anyhow::ensure!(ciphertext.len() >= 16, "AES-GCM output too short");
        let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - 16);

        let wrapped_dek = wrap_key_with_master(key, dek.as_bytes())?;

        Ok(EncryptedFile {
            algorithm: "aes256gcm".to_string(),
            nonce: nonce_bytes.to_vec(),
            ciphertext: ciphertext.to_vec(),
            tag: Some(tag.to_vec()),
            wrapped_dek,
            metadata: serde_json::json!({}),
        })
    }

    fn decrypt_aes256gcm(
        &self,
        key: &MasterKey,
        encrypted: &EncryptedFile,
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        use aes_gcm::aead::{Aead, Payload};
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

        anyhow::ensure!(
            encrypted.nonce.len() == 12,
            "invalid nonce length (expected 12 bytes)"
        );
        let dek = unwrap_key_with_master(key, &encrypted.wrapped_dek)?;
        let cipher = Aes256Gcm::new((&dek).into());
        let nonce = Nonce::from_slice(&encrypted.nonce);

        // Reconstruct ciphertext with tag
        let mut ciphertext_with_tag = encrypted.ciphertext.clone();
        if let Some(tag) = &encrypted.tag {
            ciphertext_with_tag.extend_from_slice(tag);
        }

        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ciphertext_with_tag,
                    aad,
                },
            )
            .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed: {e}"))?;

        Ok(plaintext)
    }

    fn encrypt_chacha20poly1305(
        &self,
        key: &MasterKey,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncryptedFile> {
        use chacha20poly1305::aead::{Aead, Payload};
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

        // Per-file DEK, same rationale as the AES-GCM path.
        let dek = MasterKey::generate()?;
        let cipher = ChaCha20Poly1305::new(dek.as_bytes().into());
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|e| anyhow::anyhow!("ChaCha20-Poly1305 encryption failed: {e}"))?;

        // ChaCha20-Poly1305 includes tag in ciphertext
        let wrapped_dek = wrap_key_with_master(key, dek.as_bytes())?;

        Ok(EncryptedFile {
            algorithm: "chacha20poly1305".to_string(),
            nonce: nonce_bytes.to_vec(),
            ciphertext,
            tag: None,
            wrapped_dek,
            metadata: serde_json::json!({}),
        })
    }

    fn decrypt_chacha20poly1305(
        &self,
        key: &MasterKey,
        encrypted: &EncryptedFile,
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        use chacha20poly1305::aead::{Aead, Payload};
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

        anyhow::ensure!(
            encrypted.nonce.len() == 12,
            "invalid nonce length (expected 12 bytes)"
        );
        let dek = unwrap_key_with_master(key, &encrypted.wrapped_dek)?;
        let cipher = ChaCha20Poly1305::new((&dek).into());
        let nonce = Nonce::from_slice(&encrypted.nonce);

        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &encrypted.ciphertext,
                    aad,
                },
            )
            .map_err(|e| anyhow::anyhow!("ChaCha20-Poly1305 decryption failed: {e}"))?;

        Ok(plaintext)
    }
}

/// Create a KMS client from configuration.
async fn create_kms_client(config: crate::config::KmsConfig) -> Result<Box<dyn KmsClient>> {
    match config {
        crate::config::KmsConfig::AwsKms {
            region,
            key_id,
            role_arn,
        } => Ok(Box::new(AwsKmsClient::new(region, key_id, role_arn).await?)),
        crate::config::KmsConfig::AzureKeyVault {
            vault_url,
            key_name,
            client_id,
        } => Ok(Box::new(
            AzureKeyVaultClient::new(vault_url, key_name, client_id).await?,
        )),
        crate::config::KmsConfig::HashiCorpVault {
            address,
            transit_path,
            key_name,
            auth_method,
            auth_config,
        } => Ok(Box::new(
            HashiCorpVaultClient::new(address, transit_path, key_name, auth_method, auth_config)
                .await?,
        )),
        crate::config::KmsConfig::Local { key_path } => {
            Ok(Box::new(LocalKmsClient::new(key_path).await?))
        }
    }
}

/// Local KMS client for development (stores key in file).
#[derive(Zeroize, ZeroizeOnDrop)]
struct LocalKmsClient {
    #[zeroize(skip)] // path is not secret
    _key_path: std::path::PathBuf,
    _key: [u8; 32],
}

impl LocalKmsClient {
    async fn new(key_path: String) -> Result<Self> {
        let path = std::path::PathBuf::from(&key_path);
        let key = if path.exists() {
            let data = tokio::fs::read(&path).await?;
            // Reject truncated key files instead of panicking on a short slice.
            let key: [u8; 32] = data
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("local key file must be exactly 32 bytes"))?;
            key
        } else {
            let mut key = [0u8; 32];
            rand::rng().fill_bytes(&mut key);
            write_key_file(&path, &key).await?;
            key
        };
        Ok(Self {
            _key_path: path,
            _key: key,
        })
    }
}

#[async_trait::async_trait]
impl KmsClient for LocalKmsClient {
    async fn wrap_key(&self, _key: &[u8; 32]) -> Result<WrappedKey> {
        Err(anyhow::anyhow!(
            "experimental local KMS is disabled: authenticated KMS required"
        ))
    }

    async fn unwrap_key(&self, _wrapped: &WrappedKey) -> Result<[u8; 32]> {
        Err(anyhow::anyhow!(
            "experimental local KMS is disabled: authenticated KMS required"
        ))
    }

    fn provider_name(&self) -> &str {
        "local"
    }

    fn key_id(&self) -> &str {
        "local-dev-key"
    }
}

/// AWS KMS client (stub - requires aws-sdk-kms).
struct AwsKmsClient {
    key_id: String,
}

impl AwsKmsClient {
    async fn new(_region: String, key_id: String, _role_arn: Option<String>) -> Result<Self> {
        Ok(Self { key_id })
    }
}

#[async_trait::async_trait]
impl KmsClient for AwsKmsClient {
    async fn wrap_key(&self, _key: &[u8; 32]) -> Result<WrappedKey> {
        // In production: use AWS KMS Encrypt API
        Err(anyhow::anyhow!("AWS KMS not implemented"))
    }

    async fn unwrap_key(&self, _wrapped: &WrappedKey) -> Result<[u8; 32]> {
        Err(anyhow::anyhow!("AWS KMS not implemented"))
    }

    fn provider_name(&self) -> &str {
        "aws-kms"
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// Azure Key Vault client (stub).
struct AzureKeyVaultClient {
    key_name: String,
}

impl AzureKeyVaultClient {
    async fn new(_vault_url: String, key_name: String, _client_id: Option<String>) -> Result<Self> {
        Ok(Self { key_name })
    }
}

#[async_trait::async_trait]
impl KmsClient for AzureKeyVaultClient {
    async fn wrap_key(&self, _key: &[u8; 32]) -> Result<WrappedKey> {
        Err(anyhow::anyhow!("Azure Key Vault not implemented"))
    }

    async fn unwrap_key(&self, _wrapped: &WrappedKey) -> Result<[u8; 32]> {
        Err(anyhow::anyhow!("Azure Key Vault not implemented"))
    }

    fn provider_name(&self) -> &str {
        "azure-keyvault"
    }

    fn key_id(&self) -> &str {
        &self.key_name
    }
}

/// HashiCorp Vault client (stub).
struct HashiCorpVaultClient {
    key_name: String,
}

impl HashiCorpVaultClient {
    async fn new(
        _address: String,
        _transit_path: String,
        key_name: String,
        _auth_method: String,
        _auth_config: serde_json::Value,
    ) -> Result<Self> {
        Ok(Self { key_name })
    }
}

#[async_trait::async_trait]
impl KmsClient for HashiCorpVaultClient {
    async fn wrap_key(&self, _key: &[u8; 32]) -> Result<WrappedKey> {
        Err(anyhow::anyhow!("HashiCorp Vault not implemented"))
    }

    async fn unwrap_key(&self, _wrapped: &WrappedKey) -> Result<[u8; 32]> {
        Err(anyhow::anyhow!("HashiCorp Vault not implemented"))
    }

    fn provider_name(&self) -> &str {
        "hashicorp-vault"
    }

    fn key_id(&self) -> &str {
        &self.key_name
    }
}
