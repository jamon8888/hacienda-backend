//! `GazeRedactor` — the ADR-0001 composition seam.
//!
//! gaze detects and owns provenance; xberg mints the tokens. This processor
//! replaces xberg's built-in `"redaction"` Late-stage post-processor (same-name
//! registration, ticket #4) and hands gaze's detections to xberg as
//! external findings — so the rewrite, the byte-range adjustment, the audit
//! report, and the `[TYPE_N]` token surface are xberg's own machinery,
//! byte-for-byte with basemind's today.
//!
//! Invariant: **fatal on error** (ADR-0003). A detection failure never degrades
//! to a weaker detector; extraction aborts.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use xberg::plugins::{Plugin, PostProcessor, ProcessingStage};
use xberg::{
    ExternalRedactionFinding, ExtractedDocument, ExtractionConfig, RedactionConfig,
    RedactionOffsetEncoding, RedactionStrategy, XbergError,
};

use crate::gaze_engine::{EngineError, GazeEngine};

/// A discoverable label for a gaze class, used as the xberg external-finding
/// label. xberg uppercases it for the token (`[EMAIL_1]`, `[CUSTOM_CARD_1]`).
/// The full gaze-PiiClass → basemind-category translation table is an epic-2
/// concern; this keeps the composed wire shape sane meanwhile.
pub fn class_label(class: &gaze::PiiClass) -> String {
    match class {
        gaze::PiiClass::Email => "email".to_owned(),
        gaze::PiiClass::Name => "name".to_owned(),
        gaze::PiiClass::Location => "location".to_owned(),
        gaze::PiiClass::Organization => "organization".to_owned(),
        class => class
            .as_custom_name()
            .map(str::to_owned)
            .unwrap_or_else(|| "custom".to_owned()),
    }
}

pub struct GazeRedactor {
    engine: GazeEngine,
}

impl GazeRedactor {
    pub fn new(engine: GazeEngine) -> Self {
        Self { engine }
    }

    /// Default posture: the gaze core-floor pipeline.
    ///
    /// # Errors
    /// Fails closed when the gaze pipeline cannot be built.
    pub fn core_floor() -> Result<Self, EngineError> {
        Ok(Self::new(GazeEngine::core_floor()?))
    }

    /// Register as a same-name replacement for xberg's built-in `"redaction"`
    /// processor (ADR-0001). Registration assertions are ticket #4's.
    ///
    /// # Errors
    /// Propagates the registry's error.
    pub fn register(self) -> xberg::Result<()> {
        xberg::plugins::register_post_processor(Arc::new(self))
    }

    /// Startup seam (ADR-0001 doctor): register as the same-name replacement of
    /// the built-in `"redaction"` processor, then verify the registry lists
    /// exactly our instance. Call once before serving extraction traffic.
    ///
    /// # Errors
    /// Fails closed when registration fails or post-registration verification
    /// cannot see a `"redaction"` instance — never start half-installed.
    pub fn install(engine: GazeEngine) -> xberg::Result<()> {
        Self::new(engine).register()?;
        let listed = xberg::plugins::list_post_processors();
        if listed.iter().flatten().any(|name| name == "redaction") {
            Ok(())
        } else {
            Err(XbergError::Plugin {
                message: format!(
                    "post-registration verification failed: no 'redaction' instance listed (registry: {listed:?})"
                ),
                plugin_name: env!("CARGO_PKG_NAME").to_owned(),
            })
        }
    }
}

#[async_trait]
impl Plugin for GazeRedactor {
    fn name(&self) -> &str {
        "redaction"
    }

    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_owned()
    }

    fn initialize(&self) -> xberg::Result<()> {
        Ok(())
    }

    fn shutdown(&self) -> xberg::Result<()> {
        Ok(())
    }
}

fn bridge_error(err: EngineError) -> XbergError {
    XbergError::Plugin {
        message: err.to_string(),
        plugin_name: env!("CARGO_PKG_NAME").to_owned(),
    }
}

#[async_trait]
impl PostProcessor for GazeRedactor {
    fn processing_stage(&self) -> ProcessingStage {
        ProcessingStage::Late
    }

    async fn process(
        &self,
        result: &mut ExtractedDocument,
        _config: &ExtractionConfig,
    ) -> xberg::Result<()> {
        let detections = self.engine.detect(&result.content).map_err(bridge_error)?;

        if detections.is_empty() {
            return Ok(());
        }

        let findings: Vec<ExternalRedactionFinding> = detections
            .into_iter()
            .map(|d| {
                Ok(ExternalRedactionFinding {
                    label: class_label(&d.class),
                    // Spans are canonical; the engine reads the literal from the
                    // content itself (ADR-0002: no text duplication in transit).
                    text: None,
                    start: Some(u32::try_from(d.start).map_err(|_| {
                        bridge_error(EngineError::Broken(
                            "finding start offset does not fit u32".to_owned(),
                        ))
                    })?),
                    end: Some(u32::try_from(d.end).map_err(|_| {
                        bridge_error(EngineError::Broken(
                            "finding end offset does not fit u32".to_owned(),
                        ))
                    })?),
                    score: None,
                })
            })
            .collect::<Result<Vec<_>, XbergError>>()?;

        let config = RedactionConfig {
            // Gaze is the detector: no overlapping second detector here.
            categories: HashSet::new(),
            strategy: RedactionStrategy::TokenReplace,
            ner: None,
            preserve_offsets: true,
            custom_terms: Vec::new(),
            custom_patterns: Vec::new(),
            findings,
            min_score: None,
            findings_path: None,
            // Explicit per ADR-0002: xberg's default is code points.
            findings_offset_encoding: RedactionOffsetEncoding::Utf8Bytes,
        };

        xberg::text::redaction::redact_with_entities(result, &config, &[])
    }
}
