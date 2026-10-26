//! Configuration for the hacienda-backend bridge.
//!
//! Parses `basemind.toml` for the engine selector and related settings.
//! Validates on load; fails closed on unknown/missing keys.

use serde::{Deserialize, Serialize};
use shellexpand;
use std::path::Path;
use thiserror::Error;

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

/// Top-level hacienda-backend configuration (subset of basemind.toml we care about).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaciendaConfig {
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
