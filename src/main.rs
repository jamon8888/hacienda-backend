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
    McpServer, TenantSearchEngineManager,
    audit::AuditLog,
    cli::{AssuranceModeArg, Cli, Commands, McpArgs},
    cli_error::CliError,
    doctor_checks, load_config, log_audit, run_export_recovery, run_rehydrate,
};
use std::process;
use std::sync::Arc;

struct CliAuthContext {
    binding: hacienda_backend::authz::PrincipalBinding,
    tenant_id: String,
}

fn cli_auth(
    config: &hacienda_backend::HaciendaConfig,
    requested: Option<&str>,
) -> Result<CliAuthContext, CliError> {
    let principal_id = std::env::var("HACIENDA_PRINCIPAL")
        .map_err(|_| CliError::Other("HACIENDA_PRINCIPAL is required".into()))?;
    let binding = config
        .principal(&principal_id)
        .ok_or_else(|| CliError::Other("principal is not bound in configuration".into()))?;
    let tenant_id = match requested {
        Some(t) if binding.authorizes(t) => t.to_owned(),
        Some(_) => return Err(CliError::Other("tenant is not bound to principal".into())),
        None if binding.tenant_ids.len() == 1 => binding.tenant_ids.iter().next().cloned().unwrap(),
        _ => return Err(CliError::Other("tenant selection is ambiguous".into())),
    };
    Ok(CliAuthContext {
        binding: binding.clone(),
        tenant_id,
    })
}

fn enforce_assurance_mode(
    requested: AssuranceModeArg,
    config: &hacienda_backend::HaciendaConfig,
    tenant_id: Option<&str>,
) -> Result<(), CliError> {
    let configured = config.encryption_config(tenant_id);
    let requested = match requested {
        AssuranceModeArg::Production => hacienda_backend::config::AssuranceMode::Production,
        AssuranceModeArg::Development => hacienda_backend::config::AssuranceMode::Development,
    };
    if configured.assurance_mode != requested {
        return Err(CliError::Other(
            "--assurance-mode must explicitly match the configured custody mode".into(),
        ));
    }
    hacienda_backend::validate_assurance_mode(configured, config.kms_config(tenant_id))
        .map_err(|e| CliError::Other(e.to_string()))
}

fn enforce_assurance_mode_for_all_tenants(
    requested: AssuranceModeArg,
    config: &hacienda_backend::HaciendaConfig,
) -> Result<(), CliError> {
    enforce_assurance_mode(requested, config, None)?;
    for tenant in &config.tenants {
        enforce_assurance_mode(requested, config, Some(&tenant.tenant_id))?;
    }
    Ok(())
}

fn custody_provider(
    requested: AssuranceModeArg,
    config: &hacienda_backend::HaciendaConfig,
    tenant_id: &str,
) -> Result<Box<dyn hacienda_backend::encryption::VaultKeyProvider>, CliError> {
    enforce_assurance_mode(requested, config, Some(tenant_id))?;
    hacienda_backend::encryption::vault_key_provider(config.encryption_config(Some(tenant_id)))
        .map_err(|e| CliError::Other(e.to_string()))
}

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
            let config = load_config(&args.config)?;
            let auth = cli_auth(&config, args.tenant.as_deref())?;
            let provider = custody_provider(cli.assurance_mode, &config, &auth.tenant_id)?;
            let audit = rt.block_on(run_rehydrate(
                args,
                &auth.binding,
                &auth.tenant_id,
                provider.as_ref(),
            ))?;
            log_audit(&audit)?;
        }
        Commands::Doctor(args) => {
            let config = load_config(&args.config)?;
            let _auth = cli_auth(&config, None)?;
            enforce_assurance_mode_for_all_tenants(cli.assurance_mode, &config)?;
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
            let config = load_config(&args.config)?;
            let auth = cli_auth(&config, args.tenant.as_deref())?;
            let provider = custody_provider(cli.assurance_mode, &config, &auth.tenant_id)?;
            rt.block_on(run_export_recovery(
                args,
                &auth.binding,
                &auth.tenant_id,
                provider.as_ref(),
            ))?;
        }
        Commands::Sync(args) => {
            let config = load_config(&args.config)?;
            if args.watch {
                return Err(
                    "Watch mode not yet implemented; use --force-rebuild for one-shot".into(),
                );
            }
            if args.force_rebuild {
                // For force rebuild, we'd need to trigger a full rebuild
                // For now, just run manual refresh
            }
            let auth = cli_auth(&config, args.tenant.as_deref())?;
            enforce_assurance_mode(cli.assurance_mode, &config, Some(&auth.tenant_id))?;
            let roots = config
                .get_tenant(&auth.tenant_id)
                .ok_or_else(|| CliError::Other("tenant unavailable".into()))?
                .folder_roots
                .iter()
                .map(|r| r.path.clone())
                .collect::<Vec<_>>();
            let _ = rt.block_on(hacienda_backend::run_manual_refresh_scoped(
                &args.config,
                &auth.tenant_id,
                &roots,
                args.force_rebuild,
            ))?;
        }
        Commands::Mcp(args) => {
            rt.block_on(run_mcp(args, cli.assurance_mode))?;
        }
    }
    Ok(())
}

async fn run_mcp(args: McpArgs, assurance_mode: AssuranceModeArg) -> Result<(), CliError> {
    let principal_id = std::env::var("HACIENDA_PRINCIPAL")
        .map_err(|_| CliError::Other("HACIENDA_PRINCIPAL is required".into()))?;
    let config_path = args
        .config
        .clone()
        .ok_or_else(|| CliError::Other("--config is required for authenticated MCP".into()))?;
    let config = load_config(&config_path)?;
    enforce_assurance_mode_for_all_tenants(assurance_mode, &config)?;
    let resolver = hacienda_backend::DefaultResolver::from_config(&config, &principal_id)
        .map_err(|_| CliError::Other("principal is not bound in configuration".into()))?;
    let roots = config
        .tenants
        .iter()
        .map(|t| (t.tenant_id.clone(), t.folder_roots.clone()))
        .collect();
    let mut server = McpServer::new(resolver).with_folder_roots(roots);

    {
        // Load config and attach the per-tenant search engine so the `search`
        // tool is actually usable over MCP (not "search engine not initialized").
        let manager = TenantSearchEngineManager::new(config.clone()).await?;
        let roots = config
            .tenants
            .iter()
            .map(|t| (t.tenant_id.clone(), t.folder_roots.clone()))
            .collect();
        server = server
            .with_search_engine(manager)
            .with_config_path(config_path.clone())
            .with_folder_roots(roots);
        // Initialize audit log next to config file
        let audit_path = config_path.with_extension("audit.log");
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
