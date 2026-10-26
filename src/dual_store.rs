//! Dual-store write: gaze manifest + XPII vault map under one engine-era fingerprint.
//!
//! One detection pass produces both stores (ADR-0002). The fingerprint
//! `engine_id × token_grammar_version × redaction_config` gates all cross-era reuse.

use crate::{BRIDGE_CATEGORY, BridgeError, EngineError, GazeEngine};
use blake3 as blake3_crate;
use xberg::{
    ExtractedDocument, RedactionConfig, RedactionReport, RedactionStrategy,
    text::redaction::{redact_capturing_rehydration_map, rehydration::RehydrationMap},
};

/// Engine-era fingerprint: Blake3 hash of (engine_id, token_grammar_version, redaction_config).
///
/// Serialized deterministically for stable cross-process identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct EngineEraFingerprint(pub String);

impl EngineEraFingerprint {
    /// Compute the fingerprint from the components that affect detection output.
    pub fn compute(
        engine_id: &str,
        token_grammar_version: &str,
        redaction_config: &RedactionConfig,
    ) -> Self {
        let mut hasher = blake3_crate::Hasher::new();
        hasher.update(engine_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(token_grammar_version.as_bytes());
        hasher.update(b"\0");
        // Deterministic serialization of the redaction config fields that affect output.
        let config_bytes = serde_json::to_vec(&SerializableRedactionConfig {
            strategy: format!("{:?}", redaction_config.strategy),
            categories: redaction_config
                .categories
                .iter()
                .map(|c| format!("{:?}", c))
                .collect::<Vec<_>>()
                .join(","),
            preserve_offsets: redaction_config.preserve_offsets,
            findings_count: redaction_config.findings.len(),
            findings_offset_encoding: format!("{:?}", redaction_config.findings_offset_encoding),
        })
        .expect("serialization infallible");
        hasher.update(&config_bytes);
        Self(hasher.finalize().to_hex().to_string())
    }

    /// Get the fingerprint as a hex string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Serializable subset of RedactionConfig for fingerprinting.
#[derive(serde::Serialize)]
struct SerializableRedactionConfig {
    strategy: String,
    categories: String,
    preserve_offsets: bool,
    findings_count: usize,
    findings_offset_encoding: String,
}

/// Result of a dual-store write: the gaze manifest bytes and the encrypted vault map.
#[derive(Debug)]
pub struct DualStoreOutput {
    /// Engine-era fingerprint for this write.
    pub fingerprint: EngineEraFingerprint,
    /// Gaze manifest bytes (sensitive snapshot + evidence tiers).
    pub gaze_manifest: Vec<u8>,
    /// XPII\x01 encrypted vault map (token -> original PII).
    pub vault_map: Vec<u8>,
    /// The redaction report from xberg (for audit).
    pub redaction_report: Option<RedactionReport>,
}

/// Errors from dual-store operations.
#[derive(Debug, thiserror::Error)]
pub enum DualStoreError {
    #[error("gaze engine error: {0}")]
    GazeEngine(#[from] EngineError),
    #[error("xberg error: {0}")]
    Xberg(#[from] xberg::XbergError),
    #[error("bridge error: {0}")]
    Bridge(#[from] BridgeError),
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Produce dual-store output for a single document.
///
/// Runs the gaze pipeline to get detections + manifest, then runs xberg's
/// redaction with the same findings to produce the vault map. Both are
/// bound to the same engine-era fingerprint.
///
/// # Errors
/// Fails closed on any gaze/xberg failure; never produces partial output.
pub async fn write_dual_store(
    engine: &GazeEngine,
    document: &mut ExtractedDocument,
    redaction_config: &RedactionConfig,
    one_way_labels: &[String],
) -> Result<DualStoreOutput, DualStoreError> {
    // Compute fingerprint before any mutation.
    let fingerprint =
        EngineEraFingerprint::compute("gaze-assembly", TOKEN_GRAMMAR_VERSION, redaction_config);

    // Run gaze detection to get detections AND the manifest.
    let (detections, gaze_manifest) = engine.detect_with_manifest(&document.content)?;

    // Classify detections into one-way vs tokenized (same logic as redactor).
    let (dropped, kept) = classify_detections(detections, one_way_labels)?;

    // Prepare xberg external findings for both passes.
    let dropped_findings = findings_from_detections(&dropped)?;
    let kept_findings = findings_from_detections(&kept)?;

    // Run dual-pass redaction on a temp doc to get the vault map.
    // We use `redact_capturing_rehydration_map` which captures the token->original map.
    let mut temp_doc = document.clone();

    // Pass A: Drop one-way spans.
    if !dropped_findings.is_empty() {
        let cfg = findings_config(RedactionStrategy::Drop, dropped_findings);
        redact_capturing_rehydration_map(&mut temp_doc, &cfg).await?;
    }

    // Pass B: TokenReplace kept spans (with pre-shifted offsets).
    if !kept_findings.is_empty() {
        let shifted_findings = shift_findings(kept_findings, &dropped)?;
        let cfg = findings_config(RedactionStrategy::TokenReplace, shifted_findings);
        let vault_map = redact_capturing_rehydration_map(&mut temp_doc, &cfg).await?;
        let encrypted_vault = encrypt_vault_map(vault_map)?;
        // Commit the rewritten content back.
        document.content = temp_doc.content;
        document.chunks = temp_doc.chunks;
        document.formatted_content = temp_doc.formatted_content;
        // Note: other fields (entities, tables, etc.) would also be updated in full impl.

        return Ok(DualStoreOutput {
            fingerprint,
            gaze_manifest,
            vault_map: encrypted_vault,
            redaction_report: temp_doc.redaction_report,
        });
    }

    // No kept findings: just the drop pass happened.
    document.content = temp_doc.content;
    document.chunks = temp_doc.chunks;
    document.formatted_content = temp_doc.formatted_content;

    Ok(DualStoreOutput {
        fingerprint,
        gaze_manifest,
        vault_map: Vec::new(), // No vault map needed if nothing tokenized.
        redaction_report: temp_doc.redaction_report,
    })
}

/// Convert detections to xberg external findings.
fn findings_from_detections(
    detections: &[crate::Detection],
) -> Result<Vec<xberg::ExternalRedactionFinding>, DualStoreError> {
    detections
        .iter()
        .map(|d| {
            let label = crate::redactor::class_label(&d.class);
            Ok(xberg::ExternalRedactionFinding {
                label,
                text: None,
                start: Some(
                    u32::try_from(d.start).map_err(|_| BridgeError::OffsetOverflow {
                        value: d.start,
                        context: "findings_from_detections".to_owned(),
                    })?,
                ),
                end: Some(
                    u32::try_from(d.end).map_err(|_| BridgeError::OffsetOverflow {
                        value: d.end,
                        context: "findings_from_detections".to_owned(),
                    })?,
                ),
                score: None,
            })
        })
        .collect()
}

/// Classify detections into one-way (Drop) vs tokenized (TokenReplace).
fn classify_detections(
    detections: Vec<crate::Detection>,
    one_way_labels: &[String],
) -> Result<(Vec<crate::Detection>, Vec<crate::Detection>), DualStoreError> {
    let one_way_set: std::collections::HashSet<_> =
        one_way_labels.iter().map(|s| s.to_lowercase()).collect();

    let mut dropped = Vec::new();
    let mut kept = Vec::new();

    for d in detections {
        let label = crate::redactor::class_label(&d.class).to_lowercase();
        if one_way_set.contains(&label) {
            // Check overlap with kept (cross-strategy guard).
            if kept
                .iter()
                .any(|k: &crate::Detection| k.start < d.end && d.start < k.end)
            {
                return Err(DualStoreError::Bridge(
                    BridgeError::OverlapAcrossStrategies { name: label },
                ));
            }
            dropped.push(d);
        } else {
            // Check overlap with dropped.
            if dropped
                .iter()
                .any(|d2: &crate::Detection| d2.start < d.end && d.start < d2.end)
            {
                return Err(DualStoreError::Bridge(
                    BridgeError::OverlapAcrossStrategies { name: label },
                ));
            }
            kept.push(d);
        }
    }
    Ok((dropped, kept))
}

/// Shift finding offsets by the union of dropped ranges.
fn shift_findings(
    findings: Vec<xberg::ExternalRedactionFinding>,
    dropped: &[crate::Detection],
) -> Result<Vec<xberg::ExternalRedactionFinding>, DualStoreError> {
    // Build union of dropped intervals.
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

    // Shift each finding.
    findings
        .into_iter()
        .map(|mut f| {
            if let (Some(start), Some(end)) = (f.start, f.end) {
                let start = start as usize;
                let end = end as usize;
                let mut shift_start = start;
                let mut shift_end = end;
                for (s, e) in &union {
                    if *e <= start {
                        shift_start += e - s;
                        shift_end += e - s;
                    }
                }
                f.start =
                    Some(
                        u32::try_from(shift_start).map_err(|_| BridgeError::OffsetOverflow {
                            value: shift_start,
                            context: "shift_findings".to_owned(),
                        })?,
                    );
                f.end =
                    Some(
                        u32::try_from(shift_end).map_err(|_| BridgeError::OffsetOverflow {
                            value: shift_end,
                            context: "shift_findings".to_owned(),
                        })?,
                    );
            }
            Ok(f)
        })
        .collect()
}

/// Build the findings config with the bridge's Custom-only category set.
fn findings_config(
    strategy: RedactionStrategy,
    findings: Vec<xberg::ExternalRedactionFinding>,
) -> RedactionConfig {
    RedactionConfig {
        categories: std::collections::HashSet::from([xberg::PiiCategory::Custom(
            BRIDGE_CATEGORY.to_owned(),
        )]),
        strategy,
        ner: None,
        preserve_offsets: true,
        custom_terms: Vec::new(),
        custom_patterns: Vec::new(),
        findings,
        min_score: None,
        findings_path: None,
        findings_offset_encoding: xberg::RedactionOffsetEncoding::Utf8Bytes,
    }
}

/// Encrypt the rehydration map to XPII\x01 format.
fn encrypt_vault_map(map: RehydrationMap) -> Result<Vec<u8>, DualStoreError> {
    // In production, this would use a key from macOS Keychain.
    // For now, use a fixed passphrase (TODO: Keychain integration).
    const TEST_PASSPHRASE: &str = "hacienda-backend-vault-key-v1";
    xberg::text::redaction::rehydration::encrypt_map(&map, TEST_PASSPHRASE)
        .map_err(DualStoreError::Xberg)
}

/// Token grammar version for fingerprinting.
/// Increment when the `[TYPE_N]` token format changes.
pub const TOKEN_GRAMMAR_VERSION: &str = "1";
