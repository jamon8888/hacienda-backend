mod config;
mod dual_store;
mod gaze_engine;
mod redactor;

pub use config::{ConfigError, HaciendaConfig, RedactionConfig, doctor_checks, load_config};
pub use dual_store::{
    DualStoreError, DualStoreOutput, EngineEraFingerprint, TOKEN_GRAMMAR_VERSION, write_dual_store,
};
pub use gaze_engine::{Detection, EngineError, GazeEngine};
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
