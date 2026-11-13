pub mod audit;
pub mod authz;
pub mod cli;
pub mod cli_error;
pub mod config;
pub mod disclosure;
pub mod disclosure_ledger;
pub mod dual_store;
pub mod encryption;
pub mod folder_sync;
pub mod gaze_engine;
pub mod index_projection;
pub mod mcp_resolver;
pub mod mcp_server;
pub mod mcp_types;
pub mod native_viewer;
pub mod redactor;
pub mod rehydration;
pub mod search;
pub mod sidecar;

pub use authz::{
    AuthzError, CleanDocumentRef, FolderRoot, PrincipalBinding, PrincipalRole, attach_local_doc,
};
pub use cli::{Cli, Commands, DoctorArgs, ExportRecoveryArgs, McpArgs, RehydrateArgs, SyncArgs};
pub use cli_error::CliError;
pub use config::{ConfigError, HaciendaConfig, RedactionConfig, doctor_checks, load_config};
pub use disclosure::{
    DisclosureAction, DisclosureChallenge, DisclosureScope, HumanDisclosure, OwnerIdentity,
    RequesterRef, VaultBinding,
};
pub use disclosure_ledger::{
    DisclosureLedger, EvidenceKeyCustody, EvidenceLedger, EvidenceLedgerConfig, FixtureEvidenceKey,
    MacOsEvidenceKeyCustody, WindowsCredentialEvidenceKeyCustody,
};
pub use dual_store::{
    DualStoreError, DualStoreOutput, EngineEraFingerprint, TOKEN_GRAMMAR_VERSION, write_dual_store,
};
#[cfg(target_os = "windows")]
pub use encryption::WindowsCredentialVaultKeyProvider;
pub use encryption::{VaultKeyProvider, vault_key_provider};
pub use folder_sync::{
    FolderSync, IndexedDocument, SyncEvent, run_manual_refresh, run_manual_refresh_scoped,
};
pub use gaze_engine::{Detection, EngineError, GazeEngine};
pub use index_projection::{ProjectionConfig, SensitivityTier, project_document, project_token};
pub use mcp_resolver::DefaultResolver;
pub use mcp_server::{McpServer, ToolRegistry};
pub use mcp_types::{Capability, Principal, PrincipalResolver, ResolutionContext, ResolverError};
pub use native_viewer::{NativeViewerSink, PlatformOwnerPresence};
pub use redactor::{BRIDGE_CATEGORY, BridgeError, GazeRedactor, class_label};
pub use rehydration::{
    RehydrationAuditRecord, RehydrationError, log_audit, run_export_recovery, run_rehydrate,
};
pub use search::{
    SearchEngine, SearchFilter, SearchParams, SearchResult, TenantSearchEngineManager,
};
pub use sidecar::{
    AuthenticatedClient, ClientCredential, ClientHello, ClientProof, HmacClientAuthenticator,
    LocalSidecar, LocalSidecarClient, OpaqueDisclosureGateway, PeerIdentity, SidecarEndpoint,
    SidecarRequest, SidecarResponse,
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
