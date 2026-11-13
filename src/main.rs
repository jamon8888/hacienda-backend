//! Binary entry point for hacienda-backend CLI.
//!
//! Commands:
//! - `rehydrate`: Restore entity or full document from vault map (per-export review, audit)
//! - `doctor`: Validate configuration and environment
//! - `export-recovery`: Create encrypted recovery bundle for offline restore
//! - `sync`: Sync document folder (watcher or manual refresh)
//! - `mcp`: Run MCP server (stdio or HTTP)

use clap::Parser;
use console::style;
use hacienda_backend::{
    DefaultResolver, McpServer, TenantSearchEngineManager,
    audit::AuditLog,
    cli::{Cli, Commands, McpArgs},
    cli_error::CliError,
    doctor_checks, get_vault_passphrase, load_config, log_audit, run_export_recovery,
    run_manual_refresh, run_rehydrate,
};
use std::process;
use std::sync::Arc;

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run_command(cli) {
        eprintln!("{} {}", style("Error:").red().bold(), e);
        process::exit(1);
    }
}

fn run_command(cli: Cli) -> Result<(), CliError> {
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
        Commands::Sync(args) => {
            if args.watch {
                return Err(
                    "Watch mode not yet implemented; use --force-rebuild for one-shot".into(),
                );
            }
            if args.force_rebuild {
                // For force rebuild, we'd need to trigger a full rebuild
                // For now, just run manual refresh
            }
            let _ = rt.block_on(run_manual_refresh(&args.config, args.force_rebuild))?;
        }
        Commands::Mcp(args) => {
            rt.block_on(run_mcp(args))?;
        }
    }
    Ok(())
}

async fn run_mcp(args: McpArgs) -> Result<(), CliError> {
    let resolver = DefaultResolver::new();
    let mut server = McpServer::new(resolver);

    if let Some(config_path) = args.config {
        // Load config and attach the per-tenant search engine so the `search`
        // tool is actually usable over MCP (not "search engine not initialized").
        let config = load_config(&config_path).map_err(|e| CliError::Other(e.to_string()))?;
        let manager = TenantSearchEngineManager::new(config).await?;
        server = server
            .with_search_engine(manager)
            .with_config_path(config_path.clone());
        // Initialize audit log next to config file
        let audit_path = config_path.with_extension("audit.log");
        let audit_log = AuditLog::new(&audit_path)
            .await
            .map_err(|e| CliError::Other(e.to_string()))?;
        server = server.with_audit_log(Arc::new(audit_log));
    } else {
        // Default audit log location
        let audit_path = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".local/share/hacienda/audit.log");
        let audit_log = AuditLog::new(&audit_path)
            .await
            .map_err(|e| CliError::Other(e.to_string()))?;
        server = server.with_audit_log(Arc::new(audit_log));
    }

    match args.transport.as_str() {
        "stdio" => {
            eprintln!(
                "{} Starting MCP server (stdio)",
                console::style("▶").blue().bold()
            );
            server.run_stdio().await?;
        }
        "http" => {
            let addr: std::net::SocketAddr = args.http_addr.parse()?;
            println!(
                "{} Starting MCP server (HTTP) on {}",
                console::style("▶").blue().bold(),
                addr
            );
            server.run_http(addr).await?;
        }
        _ => return Err(format!("Unknown transport: {}", args.transport).into()),
    }
    Ok(())
}
