//! hacienda-backend — bridge between [CertaMesh/gaze](https://github.com/CertaMesh/gaze)
//! (fail-closed PII pseudonymization, consumed as a dependency) and the basemind agent
//! context layer ([jamon8888/basemind](https://github.com/jamon8888/basemind)).
//!
//! Status: workspace scaffold. The composition contract (gaze detects and owns
//! provenance; xberg's TokenCounter mints `[TYPE_N]` tokens) and the human-ward
//! rehydration invariant are specified in `docs/adr/` and enforced in upcoming modules.
//!
//! Architecture: [docs/spec.md](https://github.com/jamon8888/hacienda-backend/blob/main/docs/spec.md).

/// Crate version, for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold_smoke() {
        assert!(!super::VERSION.is_empty());
    }
}
