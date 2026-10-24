//! Thin binary front for the composition. The rehydrate CLI (spec §5, ADR-0003) grows here;
//! nothing to run yet.

fn main() {
    println!(
        "hacienda-backend v{} — spec phase; see docs/spec.md",
        hacienda_backend::VERSION
    );
}
