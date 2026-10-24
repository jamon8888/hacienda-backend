mod gaze_engine;
mod redactor;

pub use gaze_engine::{Detection, EngineError, GazeEngine};
pub use redactor::{GazeRedactor, class_label};

/// Crate version, for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold_smoke() {
        assert!(!super::VERSION.is_empty());
    }
}
