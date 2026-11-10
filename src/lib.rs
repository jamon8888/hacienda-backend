pub mod audit;
pub mod authz;
pub mod cli;
pub mod cli_error;
pub mod config;
pub mod custody;
pub mod disclosure_ledger;
pub mod dual_store;
pub mod encryption;
pub mod folder_sync;
pub mod gaze_engine;
pub mod index_projection;
pub mod keychain;
pub mod mcp_resolver;
pub mod mcp_server;
pub mod mcp_types;
pub mod redactor;
pub mod rehydration;
pub mod search;

pub use authz::{
    AuthzError, CleanDocumentRef, FolderRoot, PrincipalBinding, PrincipalRole, attach_local_doc,
};
pub use cli::{Cli, Commands, DoctorArgs, ExportRecoveryArgs, McpArgs, RehydrateArgs, SyncArgs};
pub use cli_error::CliError;
pub use config::{ConfigError, HaciendaConfig, RedactionConfig, doctor_checks, load_config};
pub use custody::{
    CustodyArtifacts, CustodyError, CustodyManifest, DocumentIdentity, VerifiedCustody,
};
pub use disclosure_ledger::{
    DisclosureHandle, DisclosureLedger, DisclosureRequest, DisclosureStatus,
};
pub use dual_store::{
    DualStoreError, DualStoreOutput, EngineEraFingerprint, TOKEN_GRAMMAR_VERSION, write_dual_store,
};
pub use folder_sync::{
    FolderSync, IndexedDocument, SyncEvent, run_manual_refresh, run_manual_refresh_scoped,
};
pub use gaze_engine::{Detection, EngineError, GazeEngine};
pub use index_projection::{ProjectionConfig, SensitivityTier, project_document, project_token};
pub use keychain::{KeychainKms, validate_assurance_mode};
pub use mcp_resolver::DefaultResolver;
pub use mcp_server::{McpServer, ToolRegistry};
pub use mcp_types::{Capability, Principal, PrincipalResolver, ResolutionContext, ResolverError};
pub use redactor::{BRIDGE_CATEGORY, BridgeError, GazeRedactor, class_label};
pub use rehydration::{
    RehydrationAuditRecord, RehydrationError, get_vault_passphrase, log_audit, run_export_recovery,
    run_rehydrate,
};
pub use search::{
    SearchEngine, SearchFilter, SearchParams, SearchResult, TenantSearchEngineManager,
};

/// Crate version, for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold_smoke() {
        assert!(!super::VERSION.is_empty());
    }
}
