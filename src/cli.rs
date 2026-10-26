//! CLI for hacienda-backend: rehydration, audit, and doctor commands.

use clap::{Parser, Subcommand, Args};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "hacienda-backend", version, about = "PII-safe document backend for Claude")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Rehydrate a document or entity from the vault map.
    Rehydrate(RehydrateArgs),

    /// Run doctor checks on configuration and environment.
    Doctor(DoctorArgs),

    /// Export encrypted recovery bundle for offline restore.
    ExportRecovery(ExportRecoveryArgs),
}

/// Arguments for the rehydrate command.
#[derive(Args, Debug)]
pub struct RehydrateArgs {
    /// Document ID to rehydrate (required for full document rehydration).
    #[arg(long, short = 'd', conflicts_with = "entity")]
    pub doc_id: Option<String>,

    /// Specific entity token to rehydrate (e.g., "[EMAIL_1]").
    #[arg(long, short = 'e', conflicts_with = "doc_id")]
    pub entity: Option<String>,

    /// Path to the vault map file (XPII\x01 encrypted blob).
    #[arg(long, short = 'v', required = true)]
    pub vault_map: PathBuf,

    /// Path to the gaze manifest file (optional, for audit context).
    #[arg(long, short = 'm')]
    pub manifest: Option<PathBuf>,

    /// Output path for rehydrated content (stdout if omitted).
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,

    /// Skip interactive confirmation (for scripting).
    #[arg(long, short = 'y')]
    pub yes: bool,
}

/// Arguments for the doctor command.
#[derive(Args, Debug)]
pub struct DoctorArgs {
    /// Path to basemind.toml configuration file.
    #[arg(long, short = 'c', default_value = "basemind.toml")]
    pub config: PathBuf,

    /// Output format: text or json.
    #[arg(long, default_value = "text")]
    pub format: String,
}

/// Arguments for the export-recovery command.
#[derive(Args, Debug)]
pub struct ExportRecoveryArgs {
    /// Output path for the encrypted recovery bundle.
    #[arg(long, short = 'o', required = true)]
    pub output: PathBuf,

    /// Path to the vault map file.
    #[arg(long, short = 'v', required = true)]
    pub vault_map: PathBuf,

    /// Path to the gaze manifest file.
    #[arg(long, short = 'm', required = true)]
    pub manifest: PathBuf,

    /// Recovery passphrase (generated if omitted).
    #[arg(long, short = 'p')]
    pub passphrase: Option<String>,
}