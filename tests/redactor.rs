//! `GazeRedactor` unit tests (hacienda-backend#3 acceptance).

use xberg::plugins::PostProcessor as _;
use xberg::{ExtractedDocument, ExtractionConfig};

use hacienda_backend::{GazeEngine, GazeRedactor};

fn fixture_doc(text: &str) -> ExtractedDocument {
    let mut doc = ExtractedDocument::default();
    doc.content = text.to_owned();
    doc
}

const EMAIL_TEXT: &str = "Contact jane.roe@example.com about the 4111 1111 1111 1111 card and IBAN AT61 1904 3002 3457 3201.";

#[tokio::test]
async fn detects_and_redacts_with_type_n_tokens() {
    let redactor = GazeRedactor::core_floor().expect("core-floor engine");
    let mut doc = fixture_doc(EMAIL_TEXT);

    redactor
        .process(&mut doc, &ExtractionConfig::default())
        .await
        .expect("detection + redaction must succeed");

    // ADR-0003 floor: no raw planted value survives in the agent-facing content.
    assert!(
        !doc.content.contains("jane.roe@example.com"),
        "raw email leaked: {:?}",
        doc.content
    );
    assert!(
        !doc.content.contains("4111 1111 1111 1111"),
        "raw card leaked: {:?}",
        doc.content
    );
    assert!(
        !doc.content.contains("AT61 1904 3002 3457 3201"),
        "raw IBAN leaked: {:?}",
        doc.content
    );

    // xberg's TokenCounter minted the tokens (`[<LABEL>_<n>]`), in the document.
    let mut token_hits = 0;
    for part in doc.content.split([' ', ',', '.']) {
        let part = part.trim();
        if looks_like_type_n(part) {
            token_hits += 1;
        }
    }
    assert!(
        token_hits >= 3,
        "expected >=3 minted tokens, got content: {:?}",
        doc.content
    );

    // The audit report is xberg's RedactionReport, attached in place.
    let report = doc.redaction_report.expect("redaction report attached");
    assert_eq!(
        report.findings.len(),
        token_hits,
        "report covers exactly the applied redactions"
    );
    assert_eq!(report.total_redacted as usize, token_hits);
}

#[tokio::test]
async fn no_detections_leaves_document_untouched() {
    let redactor = GazeRedactor::core_floor().expect("core-floor engine");
    let mut doc = fixture_doc("Nothing sensitive lives here.");

    redactor
        .process(&mut doc, &ExtractionConfig::default())
        .await
        .expect("empty pass must succeed");

    assert!(
        doc.redaction_report.is_none(),
        "no report when nothing redacted"
    );
    assert_eq!(doc.content, "Nothing sensitive lives here.");
}

#[tokio::test]
async fn engine_failure_is_fatal_not_degraded() {
    let redactor = GazeRedactor::new(GazeEngine::broken("policy parse failure"));
    let mut doc = fixture_doc(EMAIL_TEXT);

    let outcome = redactor
        .process(&mut doc, &ExtractionConfig::default())
        .await;
    let err = outcome.expect_err("engine failure must abort, never degrade");
    // The error is a Plugin error naming our bridge, per ADR-0003.
    let message = err.to_string();
    assert!(
        message.contains("gaze"),
        "error should mention the engine: {message}"
    );

    // No half-redacted output: the document is untouched (extraction aborts).
    assert_eq!(
        doc.content, EMAIL_TEXT,
        "failed pass must not partially redact"
    );
}

fn looks_like_type_n(part: &str) -> bool {
    let bytes = part.as_bytes();
    if bytes.len() < 4 || !part.starts_with('[') || !part.ends_with(']') {
        return false;
    }
    let inner = &part[1..part.len() - 1];
    let Some((label, ordinal)) = inner.rsplit_once('_') else {
        return false;
    };
    let _ = ordinal;
    !label.is_empty()
        && label.chars().all(|c| c.is_ascii_uppercase() || c == '_')
        && ordinal.chars().all(|c| c.is_ascii_digit())
}
