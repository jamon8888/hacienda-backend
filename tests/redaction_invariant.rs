//! Integration test for the redaction invariant (Slice 1 acceptance).
//!
//! This test proves that CI will fail if the redaction invariant is broken:
//! - Gaze is the *only* allowed redaction engine.
//! - No bypass (rehydrate, raw passthrough, owner fallback) can be audited.
//! - Audit records are metadata-only: never raw PII, tokens, or error details.

use hacienda_backend::audit::{AuditOperationClass, AuditRecord, MCP_AUDIT_TOOLS, sanitize_record};
use hacienda_backend::config::{HaciendaConfig, RedactionConfig, doctor_checks};
use serde_json::json;

#[test]
fn gaze_is_the_only_allowed_redaction_engine() {
    // Any engine other than "gaze" must be rejected by configuration validation.
    let mut config = HaciendaConfig::default();
    config.redaction.engine = "gaze".to_string();
    let errors = doctor_checks(&config);
    assert!(
        errors.is_empty(),
        "gaze engine should be valid, got errors: {:?}",
        errors
    );

    config.redaction.engine = "regex".to_string();
    let errors = doctor_checks(&config);
    assert!(
        errors.iter().any(|e| e.contains("not supported")),
        "non-gaze engine should be rejected"
    );

    config.redaction.engine = "plaintext".to_string();
    let errors = doctor_checks(&config);
    assert!(
        errors.iter().any(|e| e.contains("not supported")),
        "plaintext engine should be rejected"
    );
}

#[test]
fn audit_allowlist_rejects_all_bypass_tools() {
    // The audit allowlist must not contain any bypass/rehydrate/raw tool.
    let bypass_tools = [
        "rehydrate",
        "recover",
        "raw_passthrough",
        "owner_fallback",
        "decrypt",
        "export_raw",
    ];
    for tool in &bypass_tools {
        assert!(
            !MCP_AUDIT_TOOLS.contains(tool),
            "bypass tool '{tool}' must not be in the audit allowlist"
        );
    }
}

#[test]
fn sanitize_record_rejects_non_allowlisted_tools() {
    let record = AuditRecord {
        sequence: 0,
        epoch: 0,
        timestamp: String::new(),
        principal_id: "principal".into(),
        tool: "rehydrate".into(),
        arguments: serde_json::Value::Null,
        authz: Default::default(),
        result_summary: "OK".into(),
        previous_hash: String::new(),
        record_hash: String::new(),
        signature: String::new(),
        public_key: String::new(),
    };
    assert!(
        sanitize_record(record).is_err(),
        "rehydrate must be rejected"
    );
}

#[test]
fn audit_record_is_metadata_only() {
    let record = AuditRecord {
        sequence: 0,
        epoch: 0,
        timestamp: String::new(),
        principal_id: "alice@example.com".into(),
        tool: "search".into(),
        arguments: json!({
            "query": "PII_QUERY_SHOULD_NOT_APPEAR",
            "token": "PII_TOKEN_SHOULD_NOT_APPEAR",
            "path": "/private/file.pdf",
        }),
        authz: Default::default(),
        result_summary: "ERROR: raw error detail with PII@example.com".into(),
        previous_hash: String::new(),
        record_hash: String::new(),
        signature: String::new(),
        public_key: String::new(),
    };
    let sanitized = sanitize_record(record).unwrap();
    let serialized = serde_json::to_string(&sanitized).unwrap();

    // No raw PII, values, tokens, or paths.
    assert!(!serialized.contains("alice@example.com"));
    assert!(!serialized.contains("PII_QUERY_SHOULD_NOT_APPEAR"));
    assert!(!serialized.contains("PII_TOKEN_SHOULD_NOT_APPEAR"));
    assert!(!serialized.contains("/private/file.pdf"));
    assert!(!serialized.contains("PII@example.com"));

    // Error details are reduced to a safe code.
    assert!(!serialized.contains("raw error detail"));
    assert!(serialized.contains("ERROR_CODE"));

    // Arguments are reduced to a count.
    assert!(serialized.contains("argument_count"));
}

#[test]
fn side_effecting_tools_require_audit() {
    // Side-effecting operations must fail closed if audit append fails.
    assert_eq!(
        AuditOperationClass::for_tool("sync"),
        AuditOperationClass::SideEffecting
    );
    assert_eq!(
        AuditOperationClass::for_tool("attach_local_doc"),
        AuditOperationClass::SideEffecting
    );
    assert_eq!(
        AuditOperationClass::for_tool("request_human_disclosure"),
        AuditOperationClass::SideEffecting
    );
    assert_eq!(
        AuditOperationClass::for_tool("disclosure_status"),
        AuditOperationClass::SideEffecting
    );
}

#[test]
fn read_only_tools_may_surface_audit_failed() {
    // Read-only operations are allowed to continue with audit_failed=true.
    assert_eq!(
        AuditOperationClass::for_tool("search"),
        AuditOperationClass::ReadOnly
    );
    assert_eq!(
        AuditOperationClass::for_tool("status"),
        AuditOperationClass::ReadOnly
    );
}
