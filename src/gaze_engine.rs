//! Gaze detection surface for the bridge.
//!
//! Owns a gaze pipeline (consumed as a dependency, never patched) and exposes the
//! detection pass on raw text: original-document byte spans + PII classes. See
//! ADR-0001 (composition contract) in `docs/`.

use gaze_assembly::CorePipelineConfig;
use uuid::Uuid;

/// One detected PII span, in original-text byte offsets (ADR-0004: these are the
/// canonical offsets).
#[derive(Debug, Clone)]
pub struct Detection {
    pub start: usize,
    pub end: usize,
    pub class: gaze::PiiClass,
}

#[derive(Debug)]
pub enum EngineError {
    /// Pipeline assembly failed — no recognizers admitted, missing bundles, …
    Build(gaze_assembly::BuildError),
    /// Detection itself failed (session, pipeline execution, …).
    Detect(gaze::Error),
    /// Injected failure used by fail-closed tests only.
    Broken(String),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Build(e) => write!(f, "gaze pipeline build failed: {e}"),
            Self::Detect(e) => write!(f, "gaze detection failed: {e}"),
            Self::Broken(msg) => write!(f, "gaze engine broken: {msg}"),
        }
    }
}

impl std::error::Error for EngineError {}

/// A fail-closed gaze engine. All gaze APIs are consumed as they are published;
/// the bridge never re-derives detection itself.
pub struct GazeEngine {
    inner: EngineInner,
}

enum EngineInner {
    Real(gaze_assembly::CorePipeline),
    Broken(String),
}

impl GazeEngine {
    /// Assemble from a `[gaze_assembly::CorePipelineConfig]`.
    ///
    /// # Errors
    /// Fails closed when the pipeline cannot be built.
    pub fn from_config(config: CorePipelineConfig) -> Result<Self, EngineError> {
        Ok(Self {
            inner: EngineInner::Real(config.build().map_err(EngineError::Build)?),
        })
    }

    /// The `core` floor pipeline — the same default `CorePipelineConfig::new()`
    /// gaze itself ships (email, credit card, IBAN, IP, …). Healvier policy
    /// configurations join via [`Self::from_config`].
    ///
    /// # Errors
    /// Fails closed when the pipeline cannot be built.
    pub fn core_floor() -> Result<Self, EngineError> {
        Self::from_config(CorePipelineConfig::new())
    }

    /// Core floor plus extra bundled rulepacks (e.g. `"secrets"` for the
    /// credential classes — spec §2 one-way candidates).
    ///
    /// # Errors
    /// Fails closed when the pipeline cannot be built.
    pub fn core_floor_with(rulepack_ids: &[&str]) -> Result<Self, EngineError> {
        let mut config = CorePipelineConfig::new();
        for id in rulepack_ids {
            config = config.with_bundled_rulepack(id);
        }
        Self::from_config(config)
    }

    /// Test-only engine that always fails detection (ADR-0003: fail-closed, never
    /// degrade).
    pub fn broken(reason: impl Into<String>) -> Self {
        Self {
            inner: EngineInner::Broken(reason.into()),
        }
    }

    /// Detect PII spans on `text` and capture the session manifest.
    ///
    /// Returns both the detections and the exported session manifest bytes.
    /// The manifest is a sensitive snapshot containing token-to-PII mappings
    /// and evidence tiers — treat as sensitive as the original document.
    ///
    /// Uses a `Scope::Conversation` with a generated ID so the session can be
    /// exported (ephemeral sessions cannot be exported).
    ///
    /// # Errors
    /// Fails closed on any gaze-side failure; never degrades to a fallback.
    pub fn detect_with_manifest(
        &self,
        text: &str,
    ) -> Result<(Vec<Detection>, Vec<u8>), EngineError> {
        match &self.inner {
            EngineInner::Broken(msg) => Err(EngineError::Broken(msg.clone())),
            EngineInner::Real(core) => {
                // Use Conversation scope so the session can be exported.
                let conversation_id = Uuid::new_v4().to_string();
                let session = gaze::Session::new(gaze::Scope::Conversation(conversation_id))
                    .map_err(EngineError::Detect)?;
                let policy = gaze::SafetyNetPolicy::new(
                    gaze::SafetyNetMode::Resolve,
                    gaze::SafetyNetFallback::Redact,
                );
                let (_, _, _, trace) = core
                    .pipeline()
                    .clean_text_with_safety_net_policy_detect_context_and_protection_trace(
                        &session,
                        text,
                        &[gaze::LocaleTag::Global],
                        &gaze::DictionaryBundle::default(),
                        policy,
                    )
                    .map_err(EngineError::Detect)?;

                // Export the session manifest (sensitive snapshot).
                let manifest_bytes = session
                    .export()
                    .map_err(|e| EngineError::Broken(format!("session export failed: {e}")))?
                    .into_bytes();

                let detections = trace
                    .into_iter()
                    .map(|item| Detection {
                        start: item.raw_start(),
                        end: item.raw_end(),
                        class: item.class().clone(),
                    })
                    .collect();

                Ok((detections, manifest_bytes))
            }
        }
    }

    /// Detect PII spans on `text` (without manifest).
    ///
    /// Uses an ephemeral session since no manifest export is needed.
    ///
    /// # Errors
    /// Fails closed on any gaze-side failure; never degrades to a fallback.
    pub fn detect(&self, text: &str) -> Result<Vec<Detection>, EngineError> {
        match &self.inner {
            EngineInner::Broken(msg) => Err(EngineError::Broken(msg.clone())),
            EngineInner::Real(core) => {
                let session =
                    gaze::Session::new(gaze::Scope::Ephemeral).map_err(EngineError::Detect)?;
                let policy = gaze::SafetyNetPolicy::new(
                    gaze::SafetyNetMode::Resolve,
                    gaze::SafetyNetFallback::Redact,
                );
                let (_, _, _, trace) = core
                    .pipeline()
                    .clean_text_with_safety_net_policy_detect_context_and_protection_trace(
                        &session,
                        text,
                        &[gaze::LocaleTag::Global],
                        &gaze::DictionaryBundle::default(),
                        policy,
                    )
                    .map_err(EngineError::Detect)?;
                Ok(trace
                    .into_iter()
                    .map(|item| Detection {
                        start: item.raw_start(),
                        end: item.raw_end(),
                        class: item.class().clone(),
                    })
                    .collect())
            }
        }
    }
}
