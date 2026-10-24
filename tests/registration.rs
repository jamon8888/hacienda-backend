//! hacienda-backend#4 — same-name registration + fail-closed assertions.
//!
//! The registry is process-global, so the three acceptance phases serialize on
//! one lock (tokio `Mutex`, held across `extract` awaits by design).

use std::sync::OnceLock;

use xberg::{ExtractInput, ExtractionConfig};

use hacienda_backend::{GazeEngine, GazeRedactor};

const EMAIL_TEXT: &str = "Contact jane.roe@example.com about the 4111 1111 1111 1111 card or IBAN AT61 1904 3002 3457 3201.";

fn synthetic_input() -> ExtractInput {
    ExtractInput::from_bytes(
        EMAIL_TEXT.as_bytes(),
        "text/plain",
        Some("note.txt".to_owned()),
    )
}

fn counts_type_n_tokens(content: &str) -> usize {
    content
        .split([' ', ',', '.'])
        .filter(|part| {
            let part = part.trim();
            let Some(inner) = part.strip_prefix('[').and_then(|p| p.strip_suffix(']')) else {
                return false;
            };
            let Some((label, ordinal)) = inner.rsplit_once('_') else {
                return false;
            };
            !label.is_empty()
                && label.chars().all(|c| c.is_ascii_uppercase() || c == '_')
                && !ordinal.is_empty()
                && ordinal.chars().all(|c| c.is_ascii_digit())
        })
        .count()
}

/// Serialize the global registry between the acceptance phases.
fn seq() -> &'static tokio::sync::Mutex<()> {
    static SEQ: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    SEQ.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Best-effort cleanup between phases: drop our same-name replacement so the
/// built-in can re-register on the next extraction.
async fn cleanup() {
    let _ = xberg::plugins::unregister_post_processor("redaction");
}

// (a) Registry state: after install, exactly one "redaction" instance is
// listed — ours, having replaced (or pre-empted) the built-in.
#[tokio::test]
async fn registry_lists_exactly_one_redaction_instance() {
    let _guard = seq().lock().await;
    cleanup().await;

    GazeRedactor::install(GazeEngine::core_floor().expect("core-floor engine must build"))
        .expect("install must succeed");

    let listed = xberg::plugins::list_post_processors();
    let instances = listed
        .iter()
        .flatten()
        .filter(|name| *name == "redaction")
        .count();
    assert_eq!(
        instances, 1,
        "exactly one 'redaction' instance, registry: {listed:?}"
    );

    cleanup().await;
}

// (b) Extract-path: with no redaction config at all, our processor still runs
// (the built-in would do nothing without one) — gaze findings, xberg tokens.
#[tokio::test]
async fn extract_redacts_without_any_redaction_config() {
    let _guard = seq().lock().await;
    cleanup().await;

    GazeRedactor::install(GazeEngine::core_floor().expect("core-floor engine must build"))
        .expect("install must succeed");

    let result = xberg::core::extract::extract(synthetic_input(), &ExtractionConfig::default())
        .await
        .expect("extraction must not fail");
    assert!(
        result.errors.is_empty(),
        "extraction reported errors: {:?}",
        result.errors
    );

    let doc = result.results.first().expect("one extracted document");
    let report = doc.redaction_report.as_ref().expect(
        "redaction_report present — proves our processor ran, not the (config-less) built-in",
    );

    // ADR-0003 floor: no planted raw value survives into agent-facing content.
    for raw in [
        "jane.roe@example.com",
        "4111 1111 1111 1111",
        "AT61 1904 3002 3457 3201",
    ] {
        assert!(
            !doc.content.contains(raw),
            "raw value leaked: {raw:?} in {:?}",
            doc.content
        );
    }

    // Single redaction pass: report parity with minted tokens, no double-run.
    let minted = counts_type_n_tokens(&doc.content);
    assert!(
        minted >= 3,
        "expected >=3 [TYPE_N] tokens, content: {:?}",
        doc.content
    );
    assert_eq!(
        report.findings.len(),
        minted,
        "report findings must match minted tokens (no double redaction)"
    );

    cleanup().await;
}

// (c) Fail-closed: a broken gaze engine must abort extraction outright —
// xberg treats the Plugin error variant as fatal in the pipeline branch.
#[tokio::test]
async fn broken_engine_aborts_extraction() {
    let _guard = seq().lock().await;
    cleanup().await;

    GazeRedactor::install(GazeEngine::broken("policy parse failure"))
        .expect("install of a broken engine succeeds (failure surfaces at use)");

    let outcome =
        xberg::core::extract::extract(synthetic_input(), &ExtractionConfig::default()).await;
    let err = outcome.expect_err("a broken engine must abort extraction, never degrade");
    let rendered = err.to_string();
    assert!(
        rendered.contains("gaze"),
        "error must name the failing engine: {rendered:?}"
    );

    cleanup().await;
}
