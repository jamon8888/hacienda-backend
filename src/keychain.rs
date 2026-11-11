//! OS-backed custody for the owner vault.
//!
//! Production custody is deliberately narrow: the only supported production
//! key store is the macOS Keychain.  Development and tests may inject an
//! explicit fixture key, but that constructor is never selected for
//! [`AssuranceMode::Production`].

use anyhow::{Context, Result, anyhow};

use crate::config::{AssuranceMode, EncryptionConfig, KmsConfig};

/// Service/account names are identifiers, never key material.
pub const VAULT_KEYCHAIN_SERVICE: &str = "hacienda-backend-vault";
pub const VAULT_KEYCHAIN_ACCOUNT: &str = "vault-key-v1";

/// Custody seam for vault encryption. Implementations must never expose key
/// material in logs or diagnostics.
pub trait VaultKeyProvider: Send + Sync {
    fn key(&self) -> Result<[u8; 32]>;
}

/// Explicit development/test fixture. It is not a production custody method.
#[derive(Clone)]
pub struct FixtureVaultKeyProvider(pub [u8; 32]);

impl VaultKeyProvider for FixtureVaultKeyProvider {
    fn key(&self) -> Result<[u8; 32]> {
        Ok(self.0)
    }
}

/// macOS Keychain adapter used as the production vault KMS.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeychainKms;

/// Compatibility name for callers that used the pre-issue provider type.
pub type KeychainVaultKeyProvider = KeychainKms;

impl KeychainKms {
    /// Read and validate the vault key. A missing item is an error; production
    /// never creates a replacement key implicitly.
    pub fn load_vault_key(&self) -> Result<[u8; 32]> {
        #[cfg(target_os = "macos")]
        {
            use security_framework::passwords::get_generic_password;

            let bytes = get_generic_password(VAULT_KEYCHAIN_SERVICE, VAULT_KEYCHAIN_ACCOUNT)
                .context("vault Keychain item is unavailable")?;
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("vault Keychain item has invalid length"))
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(anyhow!("production vault custody requires macOS Keychain"))
        }
    }

    /// Store or replace the vault key in the macOS Keychain.
    ///
    /// This is an explicit provisioning operation, never an implicit startup
    /// fallback. The caller is responsible for generating the key securely.
    pub fn store_vault_key(&self, key: [u8; 32]) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            use security_framework::passwords::set_generic_password;

            set_generic_password(VAULT_KEYCHAIN_SERVICE, VAULT_KEYCHAIN_ACCOUNT, &key)
                .context("store vault key in macOS Keychain")
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = key;
            Err(anyhow!("production vault custody requires macOS Keychain"))
        }
    }
}

impl VaultKeyProvider for KeychainKms {
    fn key(&self) -> Result<[u8; 32]> {
        self.load_vault_key()
    }
}

/// Reject insecure KMS choices before any encryption engine is started.
pub fn validate_assurance_mode(config: &EncryptionConfig, kms: Option<&KmsConfig>) -> Result<()> {
    if config.assurance_mode == AssuranceMode::Production {
        if matches!(kms, Some(KmsConfig::Local { .. })) {
            return Err(anyhow!(
                "production assurance mode rejects Local KMS; use macOS Keychain or an authenticated KMS"
            ));
        }
        if std::env::var_os("HACIENDA_VAULT_FIXTURE_KEY").is_some() {
            return Err(anyhow!(
                "production assurance mode rejects fixture vault custody"
            ));
        }
    }
    Ok(())
}

/// Resolve custody from validated configuration.
pub fn provider_for_config(config: &EncryptionConfig) -> Result<Box<dyn VaultKeyProvider>> {
    match config.assurance_mode {
        AssuranceMode::Production => {
            let provider = KeychainKms;
            provider
                .load_vault_key()
                .context("production vault Keychain custody unavailable")?;
            Ok(Box::new(provider))
        }
        AssuranceMode::Development => {
            let raw = std::env::var("HACIENDA_VAULT_FIXTURE_KEY")
                .context("development requires explicit ephemeral HACIENDA_VAULT_FIXTURE_KEY")?;
            let digest = blake3::hash(raw.as_bytes());
            Ok(Box::new(FixtureVaultKeyProvider(*digest.as_bytes())))
        }
    }
}

/// Resolve custody for legacy CLI paths that do not yet pass a loaded config.
/// The default is production and therefore fail-closed on non-Keychain hosts.
pub fn default_provider() -> Result<Box<dyn VaultKeyProvider>> {
    match std::env::var("HACIENDA_ASSURANCE_MODE").as_deref() {
        Ok("development" | "test") => {
            let raw = std::env::var("HACIENDA_VAULT_FIXTURE_KEY").context(
                "development/test requires explicit ephemeral HACIENDA_VAULT_FIXTURE_KEY",
            )?;
            let digest = blake3::hash(raw.as_bytes());
            Ok(Box::new(FixtureVaultKeyProvider(*digest.as_bytes())))
        }
        Ok("production") | Err(_) => {
            if std::env::var_os("HACIENDA_VAULT_FIXTURE_KEY").is_some() {
                return Err(anyhow!(
                    "production assurance mode rejects fixture vault custody"
                ));
            }
            let provider = KeychainKms;
            provider
                .load_vault_key()
                .context("production vault Keychain custody unavailable")?;
            Ok(Box::new(provider))
        }
        Ok(_) => Err(anyhow!("invalid assurance mode; custody refused")),
    }
}
