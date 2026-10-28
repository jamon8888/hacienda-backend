//! Class-stable index projection for semantic search (ADR-0004).
//!
//! The agent-facing index (embedding + BM25) must only see class-stable
//! `<Class_…>` tokens — never raw session tokens, format-preserving fakes,
//! or gaze-internal token shapes. This module provides the projection logic
//! and sensitivity tier suppression.

use std::collections::HashSet;

/// Sensitivity tier for index projection (ADR-0004 table).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default,
)]
pub enum SensitivityTier {
    /// Name, Location, Organization — minimal suppression, searchable.
    Minimal,
    /// Email — low suppression, searchable with caveats.
    Low,
    /// Custom classes (credential-shaped) — HIGH fail-closed.
    #[default]
    High,
    /// Credential-shaped customs (API keys, secrets) — HARD_BLOCK, never indexed.
    HardBlock,
}

impl SensitivityTier {
    /// Map from gaze PiiClass to SensitivityTier.
    ///
    /// Custom classes default to HIGH (fail-closed); specific credential-shaped
    /// patterns can be upgraded to HARD_BLOCK via configuration.
    pub fn from_pii_class(class: &gaze::PiiClass, credential_patterns: &HashSet<String>) -> Self {
        use gaze::PiiClass;
        #[allow(unreachable_patterns)]
        match class {
            PiiClass::Name | PiiClass::Location | PiiClass::Organization => Self::Minimal,
            PiiClass::Email => Self::Low,
            PiiClass::Custom(name) if credential_patterns.contains(name) => Self::HardBlock,
            PiiClass::Custom(_) => Self::High,
            // All other built-in classes default to HIGH (fail-closed)
            _ => Self::High,
        }
    }

    /// Whether this tier allows the token in the search index.
    pub fn allows_indexing(&self) -> bool {
        !matches!(self, Self::HardBlock)
    }

    /// Whether this tier requires cross-encoder rerank (always for Custom).
    pub fn requires_rerank(&self) -> bool {
        matches!(self, Self::High | Self::HardBlock)
    }
}

/// The class-stable projection token format: `<Class_…>`.
///
/// Raw gaze tokens like `[EMAIL_1]` or `[CUSTOM_API_KEY_1]` are transformed
/// to `<EMAIL>` or `<CUSTOM_API_KEY>` — stable, class-only, no ordinals.
pub fn project_token(token: &str) -> Option<String> {
    // Match `[TYPE_N]` or `[TYPE]` format
    let token = token.trim();
    if !token.starts_with('[') || !token.ends_with(']') {
        return None;
    }
    let inner = &token[1..token.len() - 1];
    // Split on last underscore to separate class from ordinal
    let class = if let Some(pos) = inner.rfind('_') {
        &inner[..pos]
    } else {
        inner
    };
    Some(format!("<{}>", class.to_uppercase()))
}

/// Project a full document's tokenized content to class-stable form.
///
/// Replaces every `[TYPE_N]` token with `<TYPE>`.
pub fn project_document(content: &str) -> String {
    let mut result = content.to_owned();
    // Find all tokens and replace them
    let mut tokens: Vec<_> = find_tokens(content).collect();
    // Sort by length descending to avoid partial replacements
    tokens.sort_by_key(|t| std::cmp::Reverse(t.0.len()));
    for (token, _class) in tokens {
        if let Some(projected) = project_token(&token) {
            result = result.replace(&token, &projected);
        }
    }
    result
}

/// Find all `[TYPE_N]` tokens in content, returning (token, class).
fn find_tokens(content: &str) -> impl Iterator<Item = (String, String)> + '_ {
    content
        .split([
            ' ', '\n', '\t', '\r', ',', '.', ';', ':', '(', ')', '[', ']', '{', '}',
        ])
        .filter(|s| !s.is_empty())
        .filter_map(|s| {
            let s = s.trim();
            if s.starts_with('[') && s.ends_with(']') {
                let inner = &s[1..s.len() - 1];
                let class = inner.rsplit_once('_').map(|(c, _)| c).unwrap_or(inner);
                Some((s.to_owned(), class.to_owned()))
            } else {
                None
            }
        })
}

/// Configuration for index projection and suppression.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProjectionConfig {
    /// Custom class names that are credential-shaped → HARD_BLOCK.
    #[serde(default)]
    pub credential_patterns: HashSet<String>,
    /// Whether to include MINIMAL tier in BM25/embedding index.
    #[serde(default = "default_true")]
    pub include_minimal: bool,
    /// Whether to include LOW tier in BM25/embedding index.
    #[serde(default = "default_true")]
    pub include_low: bool,
    /// Whether to include HIGH tier in BM25/embedding index.
    #[serde(default = "default_true")]
    pub include_high: bool,
}

fn default_true() -> bool {
    true
}

impl Default for ProjectionConfig {
    fn default() -> Self {
        Self {
            credential_patterns: HashSet::from([
                "api_key".to_owned(),
                "secret".to_owned(),
                "password".to_owned(),
                "token".to_owned(),
                "access_key".to_owned(),
                "private_key".to_owned(),
            ]),
            include_minimal: true,
            include_low: true,
            include_high: true,
        }
    }
}

impl ProjectionConfig {
    /// Check if a projected token should be indexed.
    pub fn should_index(&self, token: &str) -> bool {
        // Extract class from projected token `<CLASS>`
        let Some(class) = token.strip_prefix('<').and_then(|s| s.strip_suffix('>')) else {
            return false;
        };
        let class_lower = class.to_lowercase();
        let tier =
            if class == "HARD_BLOCK" || self.credential_patterns.contains(class_lower.as_str()) {
                SensitivityTier::HardBlock
            } else {
                // Determine tier from class name
                match class_lower.as_str() {
                    "name" | "location" | "organization" => SensitivityTier::Minimal,
                    "email" => SensitivityTier::Low,
                    _ => SensitivityTier::High,
                }
            };

        if !tier.allows_indexing() {
            return false;
        }
        match tier {
            SensitivityTier::Minimal => self.include_minimal,
            SensitivityTier::Low => self.include_low,
            SensitivityTier::High => self.include_high,
            SensitivityTier::HardBlock => false,
        }
    }
}
