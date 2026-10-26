//! `GazeRedactor` — the ADR-0001 composition seam.
//!
//! gaze detects and owns provenance; xberg mints the tokens. This processor
//! replaces xberg's built-in `"redaction"` Late-stage post-processor (same-name
//! registration, ticket #4) and hands gaze's detections to xberg as
//! external findings — so the rewrite, the byte-range adjustment, the audit
//! report, and the `[TYPE_N]` token surface are xberg's own machinery,
//! byte-for-byte with basemind's today.
//!
//! One-way classes (spec §2): labels configured via [`GazeRedactor::one_way`]
//! are removed outright (xberg `Drop`, empty replacement) and surface as
//! Drop-class findings — never as rehydratable tokens. Multi-pass runs keep
//! offsets canonical the whole way (ADR-0002).
//!
//! Invariant: **fatal on error** (ADR-0003). A detection failure never degrades
//! to a weaker detector; extraction aborts.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use xberg::plugins::{Plugin, PostProcessor, ProcessingStage};
use xberg::{
    ExternalRedactionFinding, ExtractedDocument, ExtractionConfig, PiiCategory, RedactionConfig,
    RedactionOffsetEncoding, RedactionReport, RedactionStrategy, XbergError,
};

use crate::gaze_engine::{Detection, EngineError, GazeEngine};

/// Sentinel category that turns xberg's built-in pattern engine off while
/// keeping Custom-labeled external findings flowing (`findings_config`).
const BRIDGE_CATEGORY: &str = "gaze";

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

/// One externally-sourced finding: a gaze detection in xberg's wire shape.
///
/// The span is canonical (ADR-0002); the engine reads the literal from the
/// document content itself, so the original text never travels alongside it.
fn span_finding(
    label: String,
    start: usize,
    end: usize,
) -> Result<ExternalRedactionFinding, XbergError> {
    let try_u32 = |value: usize| {
        u32::try_from(value).map_err(|_| {
            bridge_error(EngineError::Broken(format!(
                "span offset {value} does not fit u32 wire offsets"
            )))
        })
    };
    Ok(ExternalRedactionFinding {
        label,
        text: None,
        start: Some(try_u32(start)?),
        end: Some(try_u32(end)?),
        score: None,
    })
}

/// Redaction config for gaze findings: xberg owns the rewrite strategy; gaze is
/// the only detector (ADR-0001), so the pattern engine stays off.
fn findings_config(
    strategy: RedactionStrategy,
    findings: Vec<ExternalRedactionFinding>,
) -> RedactionConfig {
    RedactionConfig {
        // Gaze is the detector — the built-in pattern engine must not run.
        // CAVEAT: xberg treats an EMPTY category set as "default all on"
        // (`active_categories` enables Email/Phone/Ssn/CreditCard/PostalCode/
        // IpAddress/Iban/SwiftBic), so `HashSet::new()` here would silently
        // double-detect. The built-in IBAN scan uppercases the text and its
        // greedy tail `(?:[ ]?[A-Z0-9]){11,30}` then swallows following words,
        // overlapping adjacent gaze findings (observed: an email after an IBAN
        // lost its token and leaked raw). A single `Custom` category scans
        // nothing (patterns/mod.rs maps Custom to no builtin regex) while the
        // engine's retain filter still passes every Custom-labeled external
        // finding through. Custom-only = the only "off" switch that exists.
        categories: HashSet::from([PiiCategory::Custom(BRIDGE_CATEGORY.to_owned())]),
        strategy,
        ner: None,
        // Chunk byte ranges stay consistent with the rewritten content
        // (ADR-0002: token length bakes into chunk byte_end).
        preserve_offsets: true,
        custom_terms: Vec::new(),
        custom_patterns: Vec::new(),
        findings,
        min_score: None,
        findings_path: None,
        // Explicit per ADR-0002: xberg's default is code points.
        findings_offset_encoding: RedactionOffsetEncoding::Utf8Bytes,
    }
}

pub struct GazeRedactor {
    engine: GazeEngine,
    /// Labels removed outright (xberg `Drop`) instead of token-replaced —
    /// spec §2 one-way markers.
    one_way: HashSet<String>,
}

impl GazeRedactor {
    pub fn new(engine: GazeEngine) -> Self {
        Self {
            engine,
            one_way: HashSet::new(),
        }
    }

    /// Mark labels for one-way removal: detections of these classes are
    /// dropped (empty replacement) rather than minted as rehydratable `[TYPE_N]`
    /// tokens — spec §2's "visible, never rehydratable, never indexed".
    pub fn one_way(mut self, labels: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.one_way.extend(labels.into_iter().map(Into::into));
        self
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
        Self::install_with(engine, std::iter::empty::<String>())
    }

    /// [`install`](Self::install) with spec-§2 one-way labels configured.
    ///
    /// # Errors
    /// Same as [`install`](Self::install).
    pub fn install_with(
        engine: GazeEngine,
        one_way: impl IntoIterator<Item = impl Into<String>>,
    ) -> xberg::Result<()> {
        Self::new(engine).one_way(one_way).register()?;
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

/// Merge a pass's report into the accumulated one. xberg attaches a fresh
/// `redaction_report` per pass (`engine.rs` overwrites the field), so the
/// bridge owns the merge.
fn merge_report(merged: &mut RedactionReport, report: RedactionReport) {
    let RedactionReport {
        findings,
        total_redacted,
    } = report;
    merged.findings.extend(findings);
    merged.total_redacted += total_redacted;
}

/// Shift `offset` by the total length of dropped spans that ended at or before
/// it: the Drop pass replaced each span with the empty string.
fn shifted(offset: usize, dropped: &[Detection]) -> usize {
    let mut shift = offset;
    for drop in dropped {
        if drop.end <= offset {
            shift -= drop.end - drop.start;
        }
    }
    shift
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

        let (dropped, kept): (Vec<Detection>, Vec<Detection>) = {
            let classified: Vec<(String, Detection)> = detections
                .into_iter()
                .map(|d| (class_label(&d.class), d))
                .collect();
            let guard = |name: &str| {
                bridge_error(EngineError::Broken(format!(
                    "overlapping one-way (`{name}`) and tokenized gaze spans — refusing ambiguous rewrite"
                )))
            };
            let mut dropped = Vec::new();
            let mut kept = Vec::new();
            for (label, detection) in classified {
                if self.one_way.contains(label.as_str()) {
                    // Disjointness guard: xberg's rewrite passes anchor spans to
                    // content offsets; an overlap across strategies would make
                    // the pass-B shift ambiguous. Fail closed instead.
                    if kept
                        .iter()
                        .any(|k: &Detection| k.start < detection.end && detection.start < k.end)
                    {
                        return Err(guard(&label));
                    }
                    dropped.push(detection);
                } else {
                    if dropped
                        .iter()
                        .any(|d: &Detection| d.start < detection.end && detection.start < d.end)
                    {
                        return Err(guard(&label));
                    }
                    kept.push(detection);
                }
            }
            (dropped, kept)
        };

        let mut merged = RedactionReport {
            findings: Vec::new(),
            total_redacted: 0,
        };

        // Pass A — one-way spans go first: the empty replacement shortens the
        // content, and pass B's findings are pre-shifted to stay anchored
        // (ADR-0002: offsets canonical, never post-hoc renamed).
        if !dropped.is_empty() {
            let findings = dropped
                .iter()
                .map(|d| span_finding(class_label(&d.class), d.start, d.end))
                .collect::<Result<Vec<_>, XbergError>>()?;
            xberg::text::redaction::redact_with_entities(
                result,
                &findings_config(RedactionStrategy::Drop, findings),
                &[],
            )?;
            let Some(report) = result.redaction_report.take() else {
                return Err(bridge_error(EngineError::Broken(
                    "drop pass produced no redaction report".to_owned(),
                )));
            };
            merge_report(&mut merged, report);
        }

        // Pass B — rehydratable findings over the post-Drop content.
        if !kept.is_empty() {
            let findings = kept
                .iter()
                .map(|d| {
                    span_finding(
                        class_label(&d.class),
                        shifted(d.start, &dropped),
                        shifted(d.end, &dropped),
                    )
                })
                .collect::<Result<Vec<_>, XbergError>>()?;
            xberg::text::redaction::redact_with_entities(
                result,
                &findings_config(RedactionStrategy::TokenReplace, findings),
                &[],
            )?;
            let Some(report) = result.redaction_report.take() else {
                return Err(bridge_error(EngineError::Broken(
                    "token pass produced no redaction report".to_owned(),
                )));
            };
            merge_report(&mut merged, report);
        }

        result.redaction_report = (!merged.findings.is_empty()).then_some(merged);
        Ok(())
    }
}
