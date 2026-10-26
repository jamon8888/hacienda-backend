//! Binary entry point for hacienda-backend CLI.
//!
//! Commands:
//! - `rehydrate`: Restore entity or full document from vault map (per-export review, audit)
//! - `doctor`: Validate configuration and environment
//! - `export-recovery`: Create encrypted recovery bundle for offline restore

use clap::Parser;
use console::style;
use hacienda_backend::{
    cli::{Cli, Commands},
    doctor_checks, get_vault_passphrase, load_config, log_audit, run_export_recovery,
    run_rehydrate,
};
use std::process;

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run_command(cli) {
        eprintln!("{} {}", style("Error:").red().bold(), e);
        process::exit(1);
    }
}

fn run_command(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    match cli.command {
        Commands::Rehydrate(args) => {
            let passphrase = get_vault_passphrase()?;
            let audit = rt.block_on(run_rehydrate(args, &passphrase))?;
            log_audit(&audit)?;
        }
        Commands::Doctor(args) => {
            let config = load_config(&args.config)?;
            let errors = doctor_checks(&config);

            match args.format.as_str() {
                "json" => {
                    let output = serde_json::json!({
                        "config": config,
                        "checks_passed": errors.is_empty(),
                        "errors": errors,
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                }
                _ => {
                    println!("{} hacienda-backend doctor", style("▶").blue().bold());
                    println!("  Config: {}", args.config.display());

                    if errors.is_empty() {
                        println!("  {} All checks passed", style("✓").green());
                    } else {
                        println!("  {} Checks failed:", style("✗").red());
                        for err in &errors {
                            println!("    - {}", err);
                        }
                        return Err("Doctor checks failed".into());
                    }
                }
            }
        }
        Commands::ExportRecovery(args) => {
            let passphrase = get_vault_passphrase()?;
            rt.block_on(run_export_recovery(args, &passphrase))?;
        }
    }
    Ok(())
}
