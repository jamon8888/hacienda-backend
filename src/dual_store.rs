//! Dual-store write: gaze manifest + XPII vault map under one engine-era fingerprint.
//!
//! One detection pass produces both stores (ADR-0002). The fingerprint
//! `engine_id × token_grammar_version × redaction_config` gates all cross-era reuse.

use crate::custody::{CustodyArtifacts, DocumentIdentity, seal_custody};
use crate::encryption::{VaultKeyProvider, default_vault_key_provider};
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

/// Metadata written alongside the gaze snapshot so rehydration can verify the
/// vault envelope against an independent artifact before decrypting it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RehydrationManifest {
    pub fingerprint: EngineEraFingerprint,
    pub document_binding: String,
    pub gaze_manifest: Vec<u8>,
}

/// Result of a dual-store write: the gaze manifest bytes and the encrypted vault map.
#[derive(Debug)]
pub struct DualStoreOutput {
    /// Engine-era fingerprint for this write.
    pub fingerprint: EngineEraFingerprint,
    /// Canonical custody manifest bytes. It contains no raw snapshot bytes.
    pub manifest: Vec<u8>,
    /// Authenticated encrypted Gaze SensitiveSnapshot/session bytes.
    pub encrypted_sensitive_snapshot: Vec<u8>,
    /// XPII\x01-compatible authenticated encrypted TokenReplace map.
    pub vault_map: Vec<u8>,
    /// Document identity bound into all three persisted artifacts.
    pub document_identity: DocumentIdentity,
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
    #[error("vault custody failed: {0}")]
    Custody(String),
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
    let provider =
        default_vault_key_provider().map_err(|e| DualStoreError::Custody(e.to_string()))?;
    let document_identity = DocumentIdentity::new(
        "legacy",
        "legacy",
        blake3_crate::hash(document.content.as_bytes())
            .to_hex()
            .to_string(),
    );
    write_dual_store_for_document(
        engine,
        document,
        redaction_config,
        one_way_labels,
        document_identity,
        provider.as_ref(),
    )
    .await
}

/// Produce a custody-bound dual-store output for an authenticated document.
///
/// The returned manifest, encrypted SensitiveSnapshot/session, and encrypted
/// TokenReplace map are created as one logical unit. Callers must persist all
/// three successfully before indexing the redacted content.
pub async fn write_dual_store_for_document(
    engine: &GazeEngine,
    document: &mut ExtractedDocument,
    redaction_config: &RedactionConfig,
    one_way_labels: &[String],
    document_identity: DocumentIdentity,
    provider: &dyn VaultKeyProvider,
) -> Result<DualStoreOutput, DualStoreError> {
    // Compute fingerprint before any mutation.
    let fingerprint =
        EngineEraFingerprint::compute("gaze-assembly", TOKEN_GRAMMAR_VERSION, redaction_config);

    let actual_content_hash = blake3_crate::hash(document.content.as_bytes())
        .to_hex()
        .to_string();
    if document_identity.content_hash != actual_content_hash {
        return Err(DualStoreError::Custody(
            "document identity content hash does not match source content".to_owned(),
        ));
    }

    // Run gaze detection to get detections AND the manifest.
    let (detections, gaze_manifest) = engine.detect_with_manifest(&document.content)?;

    // Classify detections into one-way vs tokenized (same logic as redactor).
    let (dropped, kept) = classify_detections(detections.clone(), one_way_labels)?;

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
    let mut token_replace = RehydrationMap::new();
    if !kept_findings.is_empty() {
        let shifted_findings = shift_findings(kept_findings, &dropped)?;
        let cfg = findings_config(RedactionStrategy::TokenReplace, shifted_findings);
        token_replace = redact_capturing_rehydration_map(&mut temp_doc, &cfg).await?;
    }

    // The raw Gaze session snapshot is never put in the plaintext manifest.
    // The canonical manifest records only class/offset provenance and is bound
    // to the encrypted snapshot by `seal_custody`'s digest.
    let canonical_gaze_manifest =
        canonical_gaze_manifest(&fingerprint, &document_identity, &detections)?;
    let custody = seal_custody(
        &canonical_gaze_manifest,
        &gaze_manifest,
        &token_replace,
        document_identity.clone(),
        fingerprint.clone(),
        provider,
    )
    .map_err(|e| DualStoreError::Custody(e.to_string()))?;

    // Commit the rewritten content back only after all custody artifacts have
    // been successfully sealed. Persistence happens in the production sync
    // caller before it creates an index entry.
    document.content = temp_doc.content;
    document.chunks = temp_doc.chunks;
    document.formatted_content = temp_doc.formatted_content;

    Ok(DualStoreOutput {
        fingerprint,
        manifest: custody.manifest,
        encrypted_sensitive_snapshot: custody.encrypted_sensitive_snapshot,
        vault_map: custody.encrypted_token_replace,
        document_identity,
        redaction_report: temp_doc.redaction_report,
    })
}

/// Explicitly retain the complete custody result for callers that need to
/// persist it as a bundle without unpacking the output fields.
pub fn custody_artifacts(output: &DualStoreOutput) -> CustodyArtifacts {
    CustodyArtifacts {
        manifest: output.manifest.clone(),
        encrypted_sensitive_snapshot: output.encrypted_sensitive_snapshot.clone(),
        encrypted_token_replace: output.vault_map.clone(),
    }
}

#[derive(serde::Serialize)]
struct CanonicalGazeManifest<'a> {
    version: u8,
    fingerprint: &'a EngineEraFingerprint,
    document: &'a DocumentIdentity,
    findings: Vec<CanonicalFinding>,
}

#[derive(serde::Serialize)]
struct CanonicalFinding {
    label: String,
    start: usize,
    end: usize,
}

fn canonical_gaze_manifest(
    fingerprint: &EngineEraFingerprint,
    document: &DocumentIdentity,
    detections: &[crate::Detection],
) -> Result<Vec<u8>, DualStoreError> {
    let findings = detections
        .iter()
        .map(|d| CanonicalFinding {
            label: crate::redactor::class_label(&d.class),
            start: d.start,
            end: d.end,
        })
        .collect();
    Ok(serde_json::to_vec(&CanonicalGazeManifest {
        version: 1,
        fingerprint,
        document,
        findings,
    })?)
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

/// Token grammar version for fingerprinting.
/// Increment when the `[TYPE_N]` token format changes.
pub const TOKEN_GRAMMAR_VERSION: &str = "1";
