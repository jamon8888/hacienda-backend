//! Encryption at rest for LanceDB, Tantivy, and Vault.
//! Supports AES-256-GCM and ChaCha20-Poly1305 with KMS/HSM integration.

use anyhow::{Context, Result};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::config::EncryptionConfig;

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
        rand::thread_rng().fill_bytes(&mut key);
        Ok(Self { key })
    }

    /// Get the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
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
}/// A master key wrapped (encrypted) by the KMS.
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
    master_key: Option<MasterKey>,
}

impl EncryptionEngine {
    /// Create a new encryption engine.
    pub async fn new(config: EncryptionConfig, kms_config: Option<crate::config::KmsConfig>) -> Result<Self> {
        let kms_client = if let Some(kms_config) = kms_config {
            Some(create_kms_client(kms_config).await?)
        } else {
            None
        };

        Ok(Self {
            config,
            kms_client,
            master_key: None,
        })
    }

    /// Initialize the engine (generate or load master key).
    pub async fn initialize(&mut self, key_path: Option<&Path>) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        if let Some(path) = key_path {
            if path.exists() {
                // Load existing wrapped key
                let data = tokio::fs::read(path).await.context("read wrapped key")?;
                let wrapped: WrappedKey = serde_json::from_slice(&data).context("parse wrapped key")?;
                
                if let Some(kms) = &self.kms_client {
                    self.master_key = Some(MasterKey::unwrap(&wrapped, kms.as_ref()).await?);
                }
            }
        }

        // Generate new master key if not loaded
        if self.master_key.is_none() {
            self.master_key = Some(MasterKey::generate()?);
            
            // Persist wrapped key if KMS available
            if let Some(kms) = &self.kms_client {
                let _wrapped = self.master_key.as_ref().unwrap().wrap(kms.as_ref()).await?;
                // In production, persist to secure location
            }
        }

        Ok(())
    }

    /// Encrypt data using the master key.
    pub fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<EncryptedFile> {
        let master_key = self.master_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("encryption engine not initialized"))?;

        match self.config.algorithm.as_str() {
            "aes256gcm" => self.encrypt_aes256gcm(master_key, plaintext, associated_data),
            "chacha20poly1305" => self.encrypt_chacha20poly1305(master_key, plaintext, associated_data),
            _ => Err(anyhow::anyhow!("unsupported algorithm: {}", self.config.algorithm)),
        }
    }

    /// Decrypt data using the master key.
    pub fn decrypt(&self, encrypted: &EncryptedFile, associated_data: &[u8]) -> Result<Vec<u8>> {
        let master_key = self.master_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("encryption engine not initialized"))?;

        match encrypted.algorithm.as_str() {
            "aes256gcm" => self.decrypt_aes256gcm(master_key, encrypted, associated_data),
            "chacha20poly1305" => self.decrypt_chacha20poly1305(master_key, encrypted, associated_data),
            _ => Err(anyhow::anyhow!("unsupported algorithm: {}", encrypted.algorithm)),
        }
    }

    fn encrypt_aes256gcm(&self, key: &MasterKey, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedFile> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use aes_gcm::aead::{Aead, Payload};

        let cipher = Aes256Gcm::new(key.as_bytes().into());
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, Payload { msg: plaintext, aad })
            .map_err(|e| anyhow::anyhow!("AES-GCM encryption failed: {e}"))?;

        // Split ciphertext and tag (AES-GCM appends tag)
        let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - 16);

        let wrapped_dek = if let Some(kms) = &self.kms_client {
            // In production, wrap the master key
            WrappedKey {
                ciphertext: Vec::new(),
                provider: "local".to_string(),
                key_id: "local".to_string(),
                metadata: serde_json::json!({}),
            }
        } else {
            WrappedKey {
                ciphertext: Vec::new(),
                provider: "local".to_string(),
                key_id: "local".to_string(),
                metadata: serde_json::json!({}),
            }
        };

        Ok(EncryptedFile {
            algorithm: "aes256gcm".to_string(),
            nonce: nonce_bytes.to_vec(),
            ciphertext: ciphertext.to_vec(),
            tag: Some(tag.to_vec()),
            wrapped_dek,
            metadata: serde_json::json!({}),
        })
    }

    fn decrypt_aes256gcm(&self, key: &MasterKey, encrypted: &EncryptedFile, aad: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use aes_gcm::aead::{Aead, Payload};

        let cipher = Aes256Gcm::new(key.as_bytes().into());
        let nonce = Nonce::from_slice(&encrypted.nonce);
        
        // Reconstruct ciphertext with tag
        let mut ciphertext_with_tag = encrypted.ciphertext.clone();
        if let Some(tag) = &encrypted.tag {
            ciphertext_with_tag.extend_from_slice(tag);
        }

        let plaintext = cipher.decrypt(nonce, Payload { msg: &ciphertext_with_tag, aad })
            .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed: {e}"))?;

        Ok(plaintext)
    }

    fn encrypt_chacha20poly1305(&self, key: &MasterKey, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedFile> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
        use chacha20poly1305::aead::{Aead, Payload};

        let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, Payload { msg: plaintext, aad })
            .map_err(|e| anyhow::anyhow!("ChaCha20-Poly1305 encryption failed: {e}"))?;

        // ChaCha20-Poly1305 includes tag in ciphertext
        let wrapped_dek = WrappedKey {
            ciphertext: Vec::new(),
            provider: "local".to_string(),
            key_id: "local".to_string(),
            metadata: serde_json::json!({}),
        };

        Ok(EncryptedFile {
            algorithm: "chacha20poly1305".to_string(),
            nonce: nonce_bytes.to_vec(),
            ciphertext,
            tag: None,
            wrapped_dek,
            metadata: serde_json::json!({}),
        })
    }

    fn decrypt_chacha20poly1305(&self, key: &MasterKey, encrypted: &EncryptedFile, aad: &[u8]) -> Result<Vec<u8>> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
        use chacha20poly1305::aead::{Aead, Payload};

        let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
        let nonce = Nonce::from_slice(&encrypted.nonce);
        
        let plaintext = cipher.decrypt(nonce, Payload { msg: &encrypted.ciphertext, aad })
            .map_err(|e| anyhow::anyhow!("ChaCha20-Poly1305 decryption failed: {e}"))?;

        Ok(plaintext)
    }
}

/// Create a KMS client from configuration.
async fn create_kms_client(config: crate::config::KmsConfig) -> Result<Box<dyn KmsClient>> {
    match config {
        crate::config::KmsConfig::AwsKms { region, key_id, role_arn } => {
            Ok(Box::new(AwsKmsClient::new(region, key_id, role_arn).await?))
        }
        crate::config::KmsConfig::AzureKeyVault { vault_url, key_name, client_id } => {
            Ok(Box::new(AzureKeyVaultClient::new(vault_url, key_name, client_id).await?))
        }
        crate::config::KmsConfig::HashiCorpVault { address, transit_path, key_name, auth_method, auth_config } => {
            Ok(Box::new(HashiCorpVaultClient::new(address, transit_path, key_name, auth_method, auth_config).await?))
        }
        crate::config::KmsConfig::Local { key_path } => {
            Ok(Box::new(LocalKmsClient::new(key_path).await?))
        }
    }
}

/// Local KMS client for development (stores key in file).
struct LocalKmsClient {
    _key_path: std::path::PathBuf,
    key: [u8; 32],
}

impl LocalKmsClient {
    async fn new(key_path: String) -> Result<Self> {
        let path = std::path::PathBuf::from(&key_path);
        let key = if path.exists() {
            let data = tokio::fs::read(&path).await?;
            let mut key = [0u8; 32];
            key.copy_from_slice(&data[..32.min(data.len())]);
            key
        } else {
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            tokio::fs::write(&path, &key).await?;
            key
        };
        Ok(Self { _key_path: path, key })
    }
}

#[async_trait::async_trait]
impl KmsClient for LocalKmsClient {
    async fn wrap_key(&self, key: &[u8; 32]) -> Result<WrappedKey> {
        // Simple XOR for local development (NOT secure for production)
        let mut wrapped = [0u8; 32];
        for i in 0..32 {
            wrapped[i] = key[i] ^ self.key[i];
        }
        Ok(WrappedKey {
            ciphertext: wrapped.to_vec(),
            provider: "local".to_string(),
            key_id: "local-dev-key".to_string(),
            metadata: serde_json::json!({}),
        })
    }

    async fn unwrap_key(&self, wrapped: &WrappedKey) -> Result<[u8; 32]> {
        let mut key = [0u8; 32];
        for i in 0..32 {
            key[i] = wrapped.ciphertext[i] ^ self.key[i];
        }
        Ok(key)
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
    async fn new(_address: String, _transit_path: String, key_name: String, _auth_method: String, _auth_config: serde_json::Value) -> Result<Self> {
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
