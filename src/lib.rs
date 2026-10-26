pub mod cli;
pub mod config;
pub mod dual_store;
pub mod gaze_engine;
pub mod rehydration;
pub mod redactor;

pub use cli::{Cli, Commands, RehydrateArgs, DoctorArgs, ExportRecoveryArgs};
pub use config::{ConfigError, HaciendaConfig, RedactionConfig, doctor_checks, load_config};
pub use dual_store::{
    DualStoreError, DualStoreOutput, EngineEraFingerprint, TOKEN_GRAMMAR_VERSION, write_dual_store,
};
pub use gaze_engine::{Detection, EngineError, GazeEngine};
pub use rehydration::{
    RehydrationError, RehydrationAuditRecord, run_rehydrate, run_export_recovery,
    get_vault_passphrase, log_audit,
};
pub use redactor::{BRIDGE_CATEGORY, BridgeError, GazeRedactor, class_label};

/// Crate version, for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold_smoke() {
        assert!(!super::VERSION.is_empty());
    }
}
