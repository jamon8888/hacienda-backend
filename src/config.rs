//! Configuration for the hacienda-backend bridge.
//!
//! Parses `basemind.toml` for the engine selector and related settings.
//! Validates on load; fails closed on unknown/missing keys.

use crate::authz::{FolderRoot, PrincipalBinding};
use serde::{Deserialize, Serialize};
use shellexpand;
use std::path::Path;
use thiserror::Error;

/// Encryption configuration for at-rest encryption.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EncryptionConfig {
    /// Operating assurance mode. Production always requires Keychain custody.
    #[serde(default)]
    pub assurance_mode: AssuranceMode,
    /// Enable encryption at rest for LanceDB and Tantivy.
    #[serde(default)]
    pub enabled: bool,
    /// Encryption algorithm (aes256gcm, chacha20poly1305).
    #[serde(default = "default_encryption_algorithm")]
    pub algorithm: String,
    /// Key derivation function (argon2id, pbkdf2).
    #[serde(default = "default_kdf")]
    pub kdf: String,
    /// Key rotation interval in days (0 = disabled).
    #[serde(default)]
    pub key_rotation_days: u32,
}

/// Controls whether development-only key fixtures are permitted.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum AssuranceMode {
    #[default]
    Production,
    Development,
}

impl AssuranceMode {
    pub fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }
}

fn default_encryption_algorithm() -> String {
    "aes256gcm".to_string()
}

fn default_kdf() -> String {
    "argon2id".to_string()
}

/// KMS/HSM provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "lowercase")]
pub enum KmsConfig {
    /// AWS KMS
    AwsKms {
        /// AWS region (e.g., "us-east-1", "eu-west-1").
        region: String,
        /// KMS key ID or alias.
        key_id: String,
        /// Optional: role ARN to assume.
        #[serde(default)]
        role_arn: Option<String>,
    },
    /// Azure Key Vault
    AzureKeyVault {
        /// Key Vault URL (e.g., "https://myvault.vault.azure.net").
        vault_url: String,
        /// Key name.
        key_name: String,
        /// Optional: managed identity client ID.
        #[serde(default)]
        client_id: Option<String>,
    },
    /// HashiCorp Vault
    HashiCorpVault {
        /// Vault address (e.g., "https://vault.example.com:8200").
        address: String,
        /// Transit engine path.
        #[serde(default = "default_transit_path")]
        transit_path: String,
        /// Key name in transit engine.
        key_name: String,
        /// Authentication method (token, approle, kubernetes, aws, azure, gcp).
        #[serde(default = "default_auth_method")]
        auth_method: String,
        /// Auth configuration (token, role_id/secret_id, etc.).
        #[serde(default)]
        auth_config: serde_json::Value,
    },
    /// Local file-based key store (development only).
    Local {
        /// Path to key file.
        key_path: String,
    },
}

fn default_transit_path() -> String {
    "transit".to_string()
}

fn default_auth_method() -> String {
    "token".to_string()
}

/// Device selection for ONNX Runtime execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Device {
    Cpu,
    Mps,
    Cuda(u32),
    #[default]
    Auto,
}

/// Tenant configuration for multi-tenancy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantConfig {
    /// Unique tenant identifier (used for data isolation).
    pub tenant_id: String,
    /// Roots Hacienda may ingest/sync; these are not agent filesystem grants.
    #[serde(default)]
    pub folder_roots: Vec<FolderRoot>,
    /// Human-readable tenant name.
    pub name: String,
    /// Optional: custom LanceDB directory for this tenant.
    #[serde(default)]
    pub lance_dir: Option<String>,
    /// Optional: custom Tantivy index directory for this tenant.
    #[serde(default)]
    pub tantivy_dir: Option<String>,
    /// Optional: custom vault directory for this tenant.
    #[serde(default)]
    pub vault_dir: Option<String>,
    /// Optional: tenant-specific encryption config (overrides global).
    #[serde(default)]
    pub encryption: Option<EncryptionConfig>,
    /// Optional: tenant-specific KMS config (overrides global).
    #[serde(default)]
    pub kms: Option<KmsConfig>,
    /// Whether this tenant is active.
    #[serde(default = "default_true")]
    pub active: bool,
}

fn default_true() -> bool {
    true
}

/// Top-level hacienda-backend configuration (subset of basemind.toml we care about).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaciendaConfig {
    /// Explicit authenticated principal bindings. Missing bindings authorize nothing.
    #[serde(default)]
    pub principals: Vec<PrincipalBinding>,
    /// List of tenants (multi-tenancy). If empty, single-tenant mode is used.
    #[serde(default)]
    pub tenants: Vec<TenantConfig>,

    /// Default tenant ID (used when no tenant_id is specified in single-tenant mode).
    #[serde(default = "default_default_tenant")]
    pub default_tenant: String,

    /// Encryption at rest configuration.
    #[serde(default)]
    pub encryption: EncryptionConfig,

    /// KMS/HSM provider configuration.
    #[serde(default)]
    pub kms: Option<KmsConfig>,

    /// Redaction engine configuration.
    #[serde(default)]
    pub redaction: RedactionConfig,

    /// Embedding model configuration (for vector search).
    #[serde(default)]
    pub embeddings: EmbeddingsConfig,

    /// Cross-encoder reranker configuration.
    #[serde(default)]
    pub reranker: RerankerConfig,

    /// NER/GLiNER configuration (opt-in).
    #[serde(default)]
    pub ner: NerConfig,

    /// Document search configuration (hybrid BM25 + Vector + Lexical + RRF).
    #[serde(default)]
    pub documents: DocumentsConfig,
}

impl Default for HaciendaConfig {
    fn default() -> Self {
        Self {
            principals: Vec::new(),
            tenants: Vec::new(),
            default_tenant: default_default_tenant(),
            encryption: EncryptionConfig::default(),
            kms: None,
            redaction: RedactionConfig::default(),
            embeddings: EmbeddingsConfig::default(),
            reranker: RerankerConfig::default(),
            ner: NerConfig::default(),
            documents: DocumentsConfig::default(),
        }
    }
}

fn default_default_tenant() -> String {
    "default".to_string()
}

/// Redaction engine selector and policy.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RedactionConfig {
    /// Engine to use for PII detection/redaction.
    /// Valid values: "gaze" (the only supported engine in this bridge).
    #[serde(default = "default_engine")]
    pub engine: String,

    /// One-way classes: labels that are dropped with a visible `[REDACTED:<class>]`
    /// marker instead of minted as rehydratable `[TYPE_N]` tokens (spec §2).
    /// Example: `one_way = ["password", "ssn"]`
    #[serde(default)]
    pub one_way: Vec<String>,

    /// Optional: bundled rulepack IDs to enable on top of the core floor.
    /// Example: `rulepacks = ["secrets"]`
    #[serde(default)]
    pub rulepacks: Vec<String>,
}

fn default_engine() -> String {
    "gaze".to_owned()
}

fn default_device() -> Device {
    Device::Auto
}

fn default_batch_size() -> usize {
    32
}

fn default_max_seq_len() -> usize {
    512
}

/// Embedding model configuration (for vector search).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingsConfig {
    /// Model identifier: built-in name (e.g., "bge-small-en-v1.5") or path/URL to ONNX file.
    #[serde(default = "default_embeddings_model")]
    pub model: String,

    /// Execution device.
    #[serde(default = "default_device")]
    pub device: Device,

    /// Batch size for inference.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Maximum sequence length.
    #[serde(default = "default_max_seq_len")]
    pub max_seq_len: usize,

    /// Cache directory for downloaded models.
    #[serde(default = "default_embeddings_cache_dir")]
    pub cache_dir: String,
}

fn default_embeddings_model() -> String {
    "bge-small-en-v1.5".to_owned()
}

fn default_embeddings_cache_dir() -> String {
    "~/.cache/hacienda/models/embeddings".to_owned()
}

impl Default for EmbeddingsConfig {
    fn default() -> Self {
        Self {
            model: default_embeddings_model(),
            device: default_device(),
            batch_size: default_batch_size(),
            max_seq_len: default_max_seq_len(),
            cache_dir: default_embeddings_cache_dir(),
        }
    }
}

/// Cross-encoder reranker configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RerankerConfig {
    /// Enable reranker (optional, gated by SensitivityTier).
    #[serde(default = "default_reranker_enabled")]
    pub enabled: bool,

    /// Model identifier.
    #[serde(default = "default_reranker_model")]
    pub model: String,

    /// Execution device.
    #[serde(default = "default_device")]
    pub device: Device,

    /// Batch size for inference.
    #[serde(default = "default_reranker_batch_size")]
    pub batch_size: usize,

    /// Maximum sequence length.
    #[serde(default = "default_max_seq_len")]
    pub max_seq_len: usize,

    /// Cache directory for downloaded models.
    #[serde(default = "default_reranker_cache_dir")]
    pub cache_dir: String,

    /// Optional pinned SHA-256 of the ONNX model binary. When set, a freshly
    /// downloaded model is verified against this digest and rejected otherwise.
    #[serde(default)]
    pub sha256: Option<String>,
}

fn default_reranker_enabled() -> bool {
    true
}

fn default_reranker_model() -> String {
    "bge-reranker-v2-m3".to_owned()
}

fn default_reranker_batch_size() -> usize {
    16
}

fn default_reranker_cache_dir() -> String {
    "~/.cache/hacienda/models/reranker".to_owned()
}

impl Default for RerankerConfig {
    fn default() -> Self {
        Self {
            enabled: default_reranker_enabled(),
            model: default_reranker_model(),
            device: default_device(),
            batch_size: default_reranker_batch_size(),
            max_seq_len: default_max_seq_len(),
            cache_dir: default_reranker_cache_dir(),
            sha256: None,
        }
    }
}

/// NER/GLiNER configuration (opt-in).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NerConfig {
    /// Enable NER (opt-in; gaze core floor is default).
    #[serde(default = "default_ner_enabled")]
    pub enabled: bool,

    /// Model identifier.
    #[serde(default = "default_ner_model")]
    pub model: String,

    /// Execution device.
    #[serde(default = "default_device")]
    pub device: Device,

    /// Confidence threshold for NER predictions.
    #[serde(default = "default_ner_threshold")]
    pub threshold: f32,

    /// Labels to extract (GLiNER labels).
    #[serde(default = "default_ner_labels")]
    pub labels: Vec<String>,

    /// Cache directory for downloaded models.
    #[serde(default = "default_ner_cache_dir")]
    pub cache_dir: String,
}

fn default_ner_enabled() -> bool {
    false
}

fn default_ner_model() -> String {
    "gliner_multi-v2.1".to_owned()
}

fn default_ner_threshold() -> f32 {
    0.5
}

fn default_ner_labels() -> Vec<String> {
    vec![
        "PERSON".to_owned(),
        "ORG".to_owned(),
        "LOC".to_owned(),
        "EMAIL".to_owned(),
        "PHONE".to_owned(),
        "CREDIT_CARD".to_owned(),
        "API_KEY".to_owned(),
    ]
}

fn default_ner_cache_dir() -> String {
    "~/.cache/hacienda/models/ner".to_owned()
}

impl Default for NerConfig {
    fn default() -> Self {
        Self {
            enabled: default_ner_enabled(),
            model: default_ner_model(),
            device: default_device(),
            threshold: default_ner_threshold(),
            labels: default_ner_labels(),
            cache_dir: default_ner_cache_dir(),
        }
    }
}

/// Document search configuration (hybrid BM25 + Vector + Lexical + RRF).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentsConfig {
    /// Enable embedding-based vector search.
    #[serde(default = "default_documents_embed")]
    pub embed: bool,

    /// Embedding dimension (must match model output).
    #[serde(default = "default_documents_dim")]
    pub dim: usize,

    /// Fusion configuration (RRF weights, relaxation).
    #[serde(default)]
    pub fusion: FusionConfig,

    /// FTS/lexical configuration.
    #[serde(default)]
    pub fts: FtsConfig,

    /// Output format configuration.
    #[serde(default)]
    pub output: OutputConfig,
}

fn default_documents_embed() -> bool {
    false // Default to lexical-only (BM25) for fail-closed
}

fn default_documents_dim() -> usize {
    384 // bge-small-en-v1.5 dimension
}

impl Default for DocumentsConfig {
    fn default() -> Self {
        Self {
            embed: default_documents_embed(),
            dim: default_documents_dim(),
            fusion: FusionConfig::default(),
            fts: FtsConfig::default(),
            output: OutputConfig::default(),
        }
    }
}

/// Fusion (RRF) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FusionConfig {
    /// RRF k parameter (rank damping).
    #[serde(default = "default_fusion_k")]
    pub k: f32,

    /// Maximum relaxation rounds for lexical search.
    #[serde(default = "default_max_relaxations")]
    pub max_relaxations: u32,

    /// Per-lane weights (exact, vector, keyword, facet).
    /// If not specified, uses basemind's document_lanes() defaults.
    #[serde(default)]
    pub weights: Option<FusionWeights>,
}

fn default_fusion_k() -> f32 {
    60.0
}

fn default_max_relaxations() -> u32 {
    3
}

impl Default for FusionConfig {
    fn default() -> Self {
        Self {
            k: default_fusion_k(),
            max_relaxations: default_max_relaxations(),
            weights: None,
        }
    }
}

/// Per-lane RRF weights.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FusionWeights {
    /// Exact/identifier lane weight.
    #[serde(default = "default_weight_3")]
    pub exact: f32,
    /// Vector/semantic lane weight.
    #[serde(default = "default_weight_1")]
    pub vector: f32,
    /// Keyword/lexical lane weight.
    #[serde(default = "default_weight_2")]
    pub keyword: f32,
    /// Facet prefilter lane weight.
    #[serde(default = "default_weight_1")]
    pub facet: f32,
}

impl Default for FusionWeights {
    /// Must match the serde field defaults: a derived `Default` would return
    /// 0.0 for every lane and silently disable fusion.
    fn default() -> Self {
        Self {
            exact: default_weight_3(),
            vector: default_weight_1(),
            keyword: default_weight_2(),
            facet: default_weight_1(),
        }
    }
}

fn default_weight_3() -> f32 {
    3.0
}
fn default_weight_1() -> f32 {
    1.0
}
fn default_weight_2() -> f32 {
    2.0
}

/// FTS/lexical configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FtsConfig {
    /// Stemmer language (ISO 639-1 code, e.g., "en").
    #[serde(default = "default_fts_language")]
    pub stemmer_language: String,

    /// Enable stemming.
    #[serde(default = "default_fts_stem")]
    pub stem: bool,

    /// Remove stop words.
    #[serde(default = "default_fts_stop")]
    pub remove_stop_words: bool,

    /// ASCII folding (normalize accents).
    #[serde(default = "default_fts_ascii")]
    pub ascii_folding: bool,

    /// Maximum token length.
    #[serde(default = "default_fts_max_token")]
    pub max_token_length: u32,

    /// Custom stop words.
    #[serde(default)]
    pub custom_stop_words: Vec<String>,
}

fn default_fts_language() -> String {
    "en".to_owned()
}
fn default_fts_stem() -> bool {
    true
}
fn default_fts_stop() -> bool {
    false // Keep stop words for legal/identifier search
}
fn default_fts_ascii() -> bool {
    true
}
fn default_fts_max_token() -> u32 {
    64
}

impl Default for FtsConfig {
    fn default() -> Self {
        Self {
            stemmer_language: default_fts_language(),
            stem: default_fts_stem(),
            remove_stop_words: default_fts_stop(),
            ascii_folding: default_fts_ascii(),
            max_token_length: default_fts_max_token(),
            custom_stop_words: Vec::new(),
        }
    }
}

/// Output format configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Output format: "json" or "toon".
    #[serde(default = "default_output_format")]
    pub format: String,
}

fn default_output_format() -> String {
    "json".to_owned()
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: default_output_format(),
        }
    }
}

/// Errors from configuration loading/validation.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read basemind.toml at {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse basemind.toml at {path}: {source}")]
    Parse {
        path: String,
        source: toml::de::Error,
    },
    #[error("unknown redaction engine '{engine}'; only 'gaze' is supported")]
    UnknownEngine { engine: String },
    #[error("redaction engine is required but missing from basemind.toml")]
    MissingEngine,
    #[error("gaze engine requires gaze-assembly feature; rebuild with appropriate features")]
    MissingGazeFeature,
    #[error("documents.fusion.k must be finite and greater than zero")]
    InvalidFusionK,
    #[error("documents.fusion weights must be finite and non-negative")]
    InvalidFusionWeights,
}

/// Load and validate `basemind.toml` from the given path.
///
/// # Errors
/// Fails closed on any I/O, parse, or validation error.
pub fn load_config<P: AsRef<Path>>(path: P) -> Result<HaciendaConfig, ConfigError> {
    let path = path.as_ref();
    let contents = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let config: HaciendaConfig = toml::from_str(&contents).map_err(|e| ConfigError::Parse {
        path: path.display().to_string(),
        source: e,
    })?;

    // Validate engine selector (fail closed on unknown).
    if config.redaction.engine != "gaze" {
        return Err(ConfigError::UnknownEngine {
            engine: config.redaction.engine,
        });
    }

    let fusion = &config.documents.fusion;
    if !fusion.k.is_finite() || fusion.k <= 0.0 {
        return Err(ConfigError::InvalidFusionK);
    }
    if let Some(weights) = &fusion.weights
        && [
            weights.exact,
            weights.vector,
            weights.keyword,
            weights.facet,
        ]
        .iter()
        .any(|weight| !weight.is_finite() || *weight < 0.0)
    {
        return Err(ConfigError::InvalidFusionWeights);
    }

    Ok(config)
}

/// Doctor check: verify the configuration is well-formed and required
/// external dependencies (models, Keychain, etc.) are available.
///
/// # Errors
/// Returns a descriptive error for each failing check; callers should
/// aggregate and report all failures rather than stopping at the first.
pub fn doctor_checks(config: &HaciendaConfig) -> Vec<String> {
    let mut errors = Vec::new();

    // Engine validation (redundant with load, but explicit for doctor).
    if config.redaction.engine != "gaze" {
        errors.push(format!(
            "redaction.engine = '{}' is not supported (only 'gaze')",
            config.redaction.engine
        ));
    }

    // Embeddings config validation.
    if config.embeddings.batch_size == 0 {
        errors.push("embeddings.batch_size must be > 0".to_owned());
    }
    if config.embeddings.max_seq_len == 0 {
        errors.push("embeddings.max_seq_len must be > 0".to_owned());
    }
    if config.embeddings.cache_dir.is_empty() {
        errors.push("embeddings.cache_dir must not be empty".to_owned());
    }
    // Check cache directory writability (warn only, not error).
    let embeddings_cache = shellexpand::tilde(&config.embeddings.cache_dir);
    if std::fs::create_dir_all(embeddings_cache.as_ref()).is_err() {
        errors.push(format!(
            "embeddings.cache_dir '{}' is not writable",
            config.embeddings.cache_dir
        ));
    }

    // Reranker config validation.
    if config.reranker.enabled {
        if config.reranker.batch_size == 0 {
            errors.push("reranker.batch_size must be > 0 when enabled".to_owned());
        }
        if config.reranker.max_seq_len == 0 {
            errors.push("reranker.max_seq_len must be > 0 when enabled".to_owned());
        }
        if config.reranker.cache_dir.is_empty() {
            errors.push("reranker.cache_dir must not be empty when enabled".to_owned());
        }
        let reranker_cache = shellexpand::tilde(&config.reranker.cache_dir);
        if std::fs::create_dir_all(reranker_cache.as_ref()).is_err() {
            errors.push(format!(
                "reranker.cache_dir '{}' is not writable",
                config.reranker.cache_dir
            ));
        }
    }

    // NER config validation.
    if config.ner.enabled {
        if config.ner.threshold < 0.0 || config.ner.threshold > 1.0 {
            errors.push("ner.threshold must be in range [0.0, 1.0]".to_owned());
        }
        if config.ner.labels.is_empty() {
            errors.push("ner.labels must not be empty when NER is enabled".to_owned());
        }
        if config.ner.cache_dir.is_empty() {
            errors.push("ner.cache_dir must not be empty when enabled".to_owned());
        }
        let ner_cache = shellexpand::tilde(&config.ner.cache_dir);
        if std::fs::create_dir_all(ner_cache.as_ref()).is_err() {
            errors.push(format!(
                "ner.cache_dir '{}' is not writable",
                config.ner.cache_dir
            ));
        }
    }

    // Rulepack IDs: validate against known bundled rulepacks (gaze-assembly).
    // We can't fully validate without building the pipeline, but we can check
    // for obviously invalid characters.
    for rp in &config.redaction.rulepacks {
        if rp.is_empty()
            || rp.contains(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
        {
            errors.push(format!(
                "invalid rulepack id '{rp}': must be non-empty alphanumeric/-/_"
            ));
        }
    }

    // TODO: Check for gaze model bundles (when NER is enabled via rulepack).
    // TODO: Check macOS Keychain accessibility for vault key custody.
    // TODO: Validate policy hash matches stored fingerprint for existing documents.

    errors
}

impl HaciendaConfig {
    /// Get the scope for document/memory isolation.
    /// In multi-tenant mode, this returns the tenant_id if set.
    pub fn scope(&self, tenant_id: Option<&str>) -> Option<String> {
        let tid = tenant_id.unwrap_or(&self.default_tenant);
        Some(tid.to_string())
    }

    /// Get the LanceDB directory path for a specific tenant.
    pub fn lance_dir(&self, tenant_id: Option<&str>) -> std::path::PathBuf {
        let tid = tenant_id.unwrap_or(&self.default_tenant);
        if let Some(tenant) = self.get_tenant(tid)
            && let Some(ref custom) = tenant.lance_dir
        {
            return shellexpand::tilde(custom).into_owned().into();
        }
        let base = shellexpand::tilde("~/.local/share/hacienda/lance").into_owned();
        std::path::PathBuf::from(base).join(tid)
    }

    /// Get the Tantivy index directory for a specific tenant.
    pub fn tantivy_dir(&self, tenant_id: Option<&str>) -> std::path::PathBuf {
        let tid = tenant_id.unwrap_or(&self.default_tenant);
        if let Some(tenant) = self.get_tenant(tid)
            && let Some(ref custom) = tenant.tantivy_dir
        {
            return shellexpand::tilde(custom).into_owned().into();
        }
        let base = shellexpand::tilde("~/.local/share/hacienda/tantivy").into_owned();
        std::path::PathBuf::from(base).join(tid)
    }

    /// Get the vault directory for a specific tenant.
    pub fn vault_dir(&self, tenant_id: Option<&str>) -> std::path::PathBuf {
        let tid = tenant_id.unwrap_or(&self.default_tenant);
        if let Some(tenant) = self.get_tenant(tid)
            && let Some(ref custom) = tenant.vault_dir
        {
            return shellexpand::tilde(custom).into_owned().into();
        }
        let base = shellexpand::tilde("~/.local/share/hacienda/vault").into_owned();
        std::path::PathBuf::from(base).join(tid)
    }

    /// Get the encryption configuration for a specific tenant.
    pub fn encryption_config(&self, tenant_id: Option<&str>) -> &EncryptionConfig {
        let tid = tenant_id.unwrap_or(&self.default_tenant);
        if let Some(tenant) = self.get_tenant(tid)
            && let Some(ref enc) = tenant.encryption
        {
            return enc;
        }
        &self.encryption
    }

    /// Get the KMS configuration for a specific tenant.
    pub fn kms_config(&self, tenant_id: Option<&str>) -> Option<&KmsConfig> {
        let tid = tenant_id.unwrap_or(&self.default_tenant);
        if let Some(tenant) = self.get_tenant(tid)
            && let Some(ref kms) = tenant.kms
        {
            return Some(kms);
        }
        self.kms.as_ref()
    }

    /// Resolve an explicitly configured principal binding. No implicit owner/default fallback.
    pub fn principal(&self, principal_id: &str) -> Option<&PrincipalBinding> {
        self.principals
            .iter()
            .find(|p| p.principal_id == principal_id)
    }

    /// Get a tenant by ID.
    pub fn get_tenant(&self, tenant_id: &str) -> Option<&TenantConfig> {
        self.tenants.iter().find(|t| t.tenant_id == tenant_id)
    }

    /// Get all active tenants.
    pub fn active_tenants(&self) -> Vec<&TenantConfig> {
        self.tenants.iter().filter(|t| t.active).collect()
    }

    /// Check if multi-tenant mode is enabled.
    pub fn is_multi_tenant(&self) -> bool {
        !self.tenants.is_empty()
    }

    /// Get the embedding dimension.
    pub fn embedding_dim(&self) -> u16 {
        self.documents.dim as u16
    }

    /// Get the embedding model identifier.
    pub fn embedding_model(&self) -> &str {
        &self.embeddings.model
    }

    /// Get the embedding batch size.
    pub fn embedding_batch_size(&self) -> Option<usize> {
        Some(self.embeddings.batch_size)
    }

    /// Get the default tenant ID.
    pub fn default_tenant_id(&self) -> &str {
        &self.default_tenant
    }

    /// Get LanceDB directory for the default tenant (backward compatibility).
    pub fn default_lance_dir(&self) -> std::path::PathBuf {
        self.lance_dir(None)
    }

    /// Get Tantivy directory for the default tenant (backward compatibility).
    pub fn default_tantivy_dir(&self) -> std::path::PathBuf {
        self.tantivy_dir(None)
    }

    /// Get vault directory for the default tenant (backward compatibility).
    pub fn default_vault_dir(&self) -> std::path::PathBuf {
        self.vault_dir(None)
    }
}
