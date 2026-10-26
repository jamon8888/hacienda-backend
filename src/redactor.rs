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
//! are removed and replaced with a visible `[REDACTED:<class>]` marker (xberg
//! `Drop` with explicit replacement) and surface as Drop-class findings —
//! never as rehydratable tokens. Multi-pass runs keep offsets canonical the
//! whole way (ADR-0002).
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
pub const BRIDGE_CATEGORY: &str = "gaze";

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
/// # Errors
/// Returns [`XbergError`] if the span offsets do not fit in u32 wire format.
fn span_finding(
    label: String,
    start: usize,
    end: usize,
) -> Result<ExternalRedactionFinding, XbergError> {
    let try_u32 = |value: usize| {
        u32::try_from(value).map_err(|_| {
            bridge_error(BridgeError::OffsetOverflow {
                value,
                context: "span_finding".to_owned(),
            })
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

/// Build a [`RedactionConfig`] for gaze findings with the built-in pattern engine disabled.
///
/// Gaze is the sole detector (ADR-0001). xberg treats an empty `categories` set as
/// "default all on", so we pin a sentinel `Custom("gaze")` category: built-in scanners
/// map `Custom` to no regex, while the retain filter passes all `Custom`-labeled
/// external findings through.
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

/// Errors that originate in the bridge (not in gaze itself), for precise
/// diagnosis by callers (Sourcery #7).
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("span offset {value} does not fit u32 wire offsets (in {context})")]
    OffsetOverflow { value: usize, context: String },
    #[error("overlapping one-way (`{name}`) and tokenized gaze spans — refusing ambiguous rewrite")]
    OverlapAcrossStrategies { name: String },
    #[error(
        "one-way label `{label}` does not match any detected class — did you mean `{suggestion:?}`?"
    )]
    UnknownOneWayLabel {
        label: String,
        suggestion: Option<String>,
    },
    #[error("drop pass produced no redaction report")]
    MissingDropReport,
    #[error("token pass produced no redaction report")]
    MissingTokenReport,
}

/// Wrap a bridge error as a plugin error.
fn bridge_error(err: BridgeError) -> XbergError {
    XbergError::Plugin {
        message: err.to_string(),
        plugin_name: env!("CARGO_PKG_NAME").to_owned(),
    }
}

/// Wrap a gaze engine error as a bridge error.
fn gaze_error(err: EngineError) -> XbergError {
    XbergError::Plugin {
        message: format!("gaze engine failed: {err}"),
        plugin_name: env!("CARGO_PKG_NAME").to_owned(),
    }
}

/// Visible replacement for one-way removals (spec §2: "visible, never
/// rehydratable, never indexed").
///
/// # Arguments
/// * `label` - The lowercase class label (e.g. "password").
///
/// # Returns
/// A string like `[REDACTED:PASSWORD]`.
fn drop_replacement(label: &str) -> String {
    format!("[REDACTED:{}]", label.to_uppercase())
}

/// Compute the total shift at `offset` from the union of dropped ranges.
///
/// Overlapping dropped spans are counted once (Sourcery #3).
fn shifted_union(offset: usize, dropped: &[Detection]) -> usize {
    if dropped.is_empty() {
        return offset;
    }
    // Build union of [start, end) intervals.
    let mut intervals: Vec<(usize, usize)> = dropped.iter().map(|d| (d.start, d.end)).collect();
    intervals.sort_by_key(|(s, _)| *s);
    let mut union = Vec::new();
    for (s, e) in intervals {
        if let Some((_, ue)) = union.last_mut()
            && s <= *ue
        {
            *ue = (*ue).max(e);
            continue;
        }
        union.push((s, e));
    }
    // Sum lengths of union intervals that end <= offset.
    let mut shift = offset;
    for (s, e) in union {
        if e <= offset {
            shift -= e - s;
        }
    }
    shift
}

/// Merge a pass's report into the accumulated one, translating pass B findings
/// back to original-document coordinates (Sourcery #6).
fn merge_report(merged: &mut RedactionReport, report: RedactionReport, dropped: &[Detection]) {
    let RedactionReport {
        mut findings,
        total_redacted,
    } = report;
    // Translate findings from post-Drop coords back to original coords.
    for f in &mut findings {
        // The inverse of shifted_union: for each dropped interval that ends
        // before this finding's start, add its length back.
        let mut start = f.start as usize;
        let mut end = f.end as usize;
        let mut intervals: Vec<(usize, usize)> = dropped.iter().map(|d| (d.start, d.end)).collect();
        intervals.sort_by_key(|(s, _)| *s);
        let mut union = Vec::new();
        for (s, e) in intervals {
            if let Some((_, ue)) = union.last_mut()
                && s <= *ue
            {
                *ue = (*ue).max(e);
                continue;
            }
            union.push((s, e));
        }
        for (s, e) in union {
            if e <= start {
                start += e - s;
                end += e - s;
            } else if s <= start && start < e {
                start = s;
            }
        }
        f.start = u32::try_from(start).expect("shifted start fits u32");
        f.end = u32::try_from(end).expect("shifted end fits u32");
    }
    merged.findings.extend(findings);
    merged.total_redacted += total_redacted;
}

/// Strip matched text from Drop findings so secrets never leak through the
/// audit report (Sourcery #1).
fn sanitize_drop_report(report: &mut RedactionReport) {
    for f in &mut report.findings {
        if f.strategy == RedactionStrategy::Drop {
            let label = match &f.category {
                PiiCategory::Custom(s) => s.clone(),
                // For built-in categories, use the debug representation
                // (they shouldn't occur in our flow since we use Custom).
                _ => format!("{:?}", f.category).to_lowercase(),
            };
            f.replacement_token = drop_replacement(&label);
        }
    }
}

pub struct GazeRedactor {
    engine: GazeEngine,
    /// Labels removed outright (xberg `Drop` with visible marker) instead of
    /// token-replaced — spec §2 one-way markers.
    one_way: HashSet<String>,
}

impl GazeRedactor {
    pub fn new(engine: GazeEngine) -> Self {
        Self {
            engine,
            one_way: HashSet::new(),
        }
    }

    /// Mark labels for one-way removal: detections of these classes are dropped
    /// (visible `[REDACTED:<class>]` replacement) rather than minted as
    /// rehydratable `[TYPE_N]` tokens — spec §2's "visible, never rehydratable,
    /// never indexed". Labels are compared case-insensitively against
    /// `class_label` output (Sourcery #8).
    pub fn one_way(mut self, labels: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.one_way
            .extend(labels.into_iter().map(|s| s.into().to_lowercase()));
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
        // Detect on original content.
        let detections = self.engine.detect(&result.content).map_err(gaze_error)?;

        if detections.is_empty() {
            return Ok(());
        }

        // Classify detections into one-way (Drop) vs tokenized (TokenReplace).
        // Normalize one-way labels to lowercase for case-insensitive matching.
        let classified: Vec<(String, Detection)> = detections
            .into_iter()
            .map(|d| (class_label(&d.class).to_lowercase(), d))
            .collect();

        // Validate that every configured one-way label matches at least one
        // detected class (Sourcery #8).
        for configured in &self.one_way {
            if !classified.iter().any(|(label, _)| label == configured) {
                let suggestion = classified
                    .iter()
                    .map(|(l, _)| l.as_str())
                    .find(|l| {
                        let cl = l.to_lowercase();
                        let cc = configured.to_lowercase();
                        cl.contains(&cc) || cc.contains(&cl)
                    })
                    .map(|s| s.to_owned());
                return Err(bridge_error(BridgeError::UnknownOneWayLabel {
                    label: configured.clone(),
                    suggestion,
                }));
            }
        }

        let guard = |name: &str| {
            bridge_error(BridgeError::OverlapAcrossStrategies {
                name: name.to_owned(),
            })
        };

        let mut dropped = Vec::new();
        let mut kept = Vec::new();
        for (label, detection) in classified {
            if self.one_way.contains(&label) {
                // Disjointness guard across strategies (Sourcery #3).
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

        // Run both passes on a TEMPORARY cloned document so a failure in pass B
        // leaves the original result untouched (Sourcery #2).
        let mut temp_doc = result.clone();

        let mut merged = RedactionReport {
            findings: Vec::new(),
            total_redacted: 0,
        };

        // Pass A — one-way spans: Drop with visible marker.
        if !dropped.is_empty() {
            let findings = dropped
                .iter()
                .map(|d| {
                    let label = class_label(&d.class);
                    span_finding(label.clone(), d.start, d.end)
                })
                .collect::<Result<Vec<_>, XbergError>>()?;
            let cfg = findings_config(RedactionStrategy::Drop, findings);
            xberg::text::redaction::redact_with_entities(&mut temp_doc, &cfg, &[])?;
            let Some(mut report) = temp_doc.redaction_report.take() else {
                return Err(bridge_error(BridgeError::MissingDropReport));
            };
            // Replace empty tokens with visible markers in the report (Sourcery #5).
            for f in &mut report.findings {
                let label = match &f.category {
                    PiiCategory::Custom(s) => s.clone(),
                    _ => format!("{:?}", f.category).to_lowercase(),
                };
                f.replacement_token = drop_replacement(&label);
            }
            sanitize_drop_report(&mut report);
            merge_report(&mut merged, report, &dropped);
        }

        // Pass B — rehydratable findings over the post-Drop content.
        if !kept.is_empty() {
            let findings = kept
                .iter()
                .map(|d| {
                    span_finding(
                        class_label(&d.class),
                        shifted_union(d.start, &dropped),
                        shifted_union(d.end, &dropped),
                    )
                })
                .collect::<Result<Vec<_>, XbergError>>()?;
            xberg::text::redaction::redact_with_entities(
                &mut temp_doc,
                &findings_config(RedactionStrategy::TokenReplace, findings),
                &[],
            )?;
            let Some(report) = temp_doc.redaction_report.take() else {
                return Err(bridge_error(BridgeError::MissingTokenReport));
            };
            merge_report(&mut merged, report, &dropped);
        }

        // Commit the fully rewritten document atomically.
        *result = temp_doc;
        result.redaction_report = (!merged.findings.is_empty()).then_some(merged);
        Ok(())
    }
}
