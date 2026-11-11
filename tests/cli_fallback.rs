//! CLI fallback contract tests (issue #19 acceptance 4).
//!
//! The CLI `rehydrate`/`export-recovery` commands are a controlled
//! migration/recovery fallback only — never a security boundary against a
//! same-user agent process. These tests prove, from a non-interactive test
//! harness (stdin is never a TTY here):
//!
//! - interactive owner approval is required (unattended runs fail closed);
//! - unattended `--yes` is rejected;
//! - raw content can never reach stdout (`--output` is mandatory and the
//!   fail-closed checks run before any vault material is read).

use std::path::PathBuf;

use hacienda_backend::authz::{PrincipalBinding, PrincipalRole};
use hacienda_backend::cli::{ExportRecoveryArgs, RehydrateArgs};
use hacienda_backend::encryption::FixtureVaultKeyProvider;
use hacienda_backend::rehydration::{RehydrationError, run_export_recovery, run_rehydrate};

fn binding() -> PrincipalBinding {
    PrincipalBinding {
        principal_id: "owner".into(),
        role: PrincipalRole::Owner,
        tenant_ids: ["tenant".to_owned()].into(),
    }
}

fn nonexistent() -> PathBuf {
    // Proves ordering: every error below must be UserCancelled from the
    // fail-closed approval gate, before this path would ever be read.
    PathBuf::from("/nonexistent/hacienda/definitely-absent-vault.bin")
}

fn rehydrate_args(yes: bool, output: Option<PathBuf>) -> RehydrateArgs {
    RehydrateArgs {
        config: nonexistent(),
        tenant: Some("tenant".into()),
        doc_id: None,
        entity: Some("[EMAIL_1]".into()),
        vault_map: nonexistent(),
        manifest: Some(nonexistent()),
        output,
        yes,
        document: None,
    }
}

#[tokio::test]
async fn unattended_rehydrate_without_yes_is_rejected_before_vault_access() {
    let provider = FixtureVaultKeyProvider([7u8; 32]);
    let error = run_rehydrate(
        rehydrate_args(false, Some(nonexistent())),
        &provider,
        &binding(),
        "tenant",
    )
    .await
    .expect_err("unattended run must fail closed");
    assert_eq!(error, RehydrationError::UserCancelled);
}

#[tokio::test]
async fn unattended_yes_is_rejected_before_vault_access() {
    let provider = FixtureVaultKeyProvider([7u8; 32]);
    let error = run_rehydrate(
        rehydrate_args(true, Some(nonexistent())),
        &provider,
        &binding(),
        "tenant",
    )
    .await
    .expect_err("unattended --yes must be rejected");
    assert_eq!(error, RehydrationError::UserCancelled);
}

#[tokio::test]
async fn rehydrate_requires_explicit_output_file_never_stdout() {
    let provider = FixtureVaultKeyProvider([7u8; 32]);
    let error = run_rehydrate(rehydrate_args(true, None), &provider, &binding(), "tenant")
        .await
        .expect_err("raw content must never go to stdout");
    assert_eq!(error, RehydrationError::UserCancelled);
}

#[tokio::test]
async fn unattended_export_recovery_is_rejected_before_vault_access() {
    let provider = FixtureVaultKeyProvider([7u8; 32]);
    let args = ExportRecoveryArgs {
        config: nonexistent(),
        tenant: Some("tenant".into()),
        vault_map: nonexistent(),
        manifest: nonexistent(),
        output: nonexistent(),
    };
    let error = run_export_recovery(args, &provider, &binding(), "tenant")
        .await
        .expect_err("unattended recovery export must fail closed");
    assert_eq!(error, RehydrationError::UserCancelled);
}
