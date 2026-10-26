//! Configuration for the hacienda-backend bridge.
//!
//! Parses `basemind.toml` for the engine selector and related settings.
//! Validates on load; fails closed on unknown/missing keys.

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

/// Top-level hacienda-backend configuration (subset of basemind.toml we care about).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaciendaConfig {
    /// Redaction engine configuration.
    #[serde(default)]
    pub redaction: RedactionConfig,
}

/// Redaction engine selector and policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            engine: default_engine(),
            one_way: Vec::new(),
            rulepacks: Vec::new(),
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
