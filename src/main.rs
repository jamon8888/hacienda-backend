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
    cli::{Cli, Commands, McpArgs},
    cli_error::CliError,
    doctor_checks, get_vault_passphrase, load_config, log_audit, run_export_recovery,
    run_rehydrate,
};
use std::process;
use std::sync::Arc;

#[derive(Debug)]
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
    cli_auth_for(config, &principal_id, requested)
}

/// Principal-to-tenant authorization for CLI surfaces: the requested tenant is
/// a selector among the principal's explicitly bound tenant IDs, never a grant.
/// Fail-closed: missing/ambiguous/multi binding denies access. (issue #22)
fn cli_auth_for(
    config: &hacienda_backend::HaciendaConfig,
    principal_id: &str,
    requested: Option<&str>,
) -> Result<CliAuthContext, CliError> {
    let binding = config
        .principal(principal_id)
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
            let passphrase = get_vault_passphrase()?;
            let audit = rt.block_on(run_rehydrate(
                args,
                &passphrase,
                &auth.binding,
                &auth.tenant_id,
            ))?;
            log_audit(&audit)?;
        }
        Commands::Doctor(args) => {
            let config = load_config(&args.config)?;
            let _auth = cli_auth(&config, None)?;
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
            let passphrase = get_vault_passphrase()?;
            rt.block_on(run_export_recovery(
                args,
                &passphrase,
                &auth.binding,
                &auth.tenant_id,
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
            rt.block_on(run_mcp(args))?;
        }
    }
    Ok(())
}

async fn run_mcp(args: McpArgs) -> Result<(), CliError> {
    let principal_id = std::env::var("HACIENDA_PRINCIPAL")
        .map_err(|_| CliError::Other("HACIENDA_PRINCIPAL is required".into()))?;
    let config_path = args
        .config
        .clone()
        .ok_or_else(|| CliError::Other("--config is required for authenticated MCP".into()))?;
    let config = load_config(&config_path)?;
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

#[cfg(test)]
mod cli_auth_tests {
    use super::*;
    use clap::Parser;

    fn config_with_principals() -> hacienda_backend::HaciendaConfig {
        toml::from_str(
            "default_tenant = \"core-a\"\n\
             [[tenants]]\ntenant_id = \"core-a\"\nname = \"a\"\n\
             [[tenants]]\ntenant_id = \"core-b\"\nname = \"b\"\n\
             [[principals]]\nprincipal_id = \"owner\"\nrole = \"owner\"\n\
             tenant_ids = [\"core-a\"]\n\
             [[principals]]\nprincipal_id = \"ambidextrous\"\nrole = \"owner\"\n\
             tenant_ids = [\"core-a\", \"core-b\"]\n",
        )
        .unwrap()
    }

    /// An explicitly requested tenant outside the principal's binding is denied
    /// generically; the denial must not name any tenant. (issue #22, acceptance 5/7)
    #[test]
    fn request_denies_tenant_not_bound_to_principal() {
        let config = config_with_principals();
        for principal in ["owner", "ambidextrous"] {
            let err = cli_auth_for(&config, principal, Some("ghost")).unwrap_err();
            let message = err.to_string();
            assert!(message.contains("not bound"), "unexpected denial: {message}");
            assert!(!message.contains("core-a"));
            assert!(!message.contains("core-b"));
            assert!(!message.contains("ghost"));
        }
    }

    /// The resolved tenant used by the CLI always comes from the configured
    /// principal authorization, not from the payload. (acceptance 6/7)
    #[test]
    fn resolved_tenant_stays_within_principal_authorization() {
        let config = config_with_principals();
        assert_eq!(
            cli_auth_for(&config, "owner", Some("core-a")).unwrap().tenant_id,
            "core-a"
        );
        assert_eq!(
            cli_auth_for(&config, "ambidextrous", Some("core-b"))
                .unwrap()
                .tenant_id,
            "core-b"
        );
        // A principal bound to exactly one tenant may omit --tenant.
        assert_eq!(
            cli_auth_for(&config, "owner", None).unwrap().tenant_id,
            "core-a"
        );
    }

    /// A principal with several bindings cannot skip tenant selection, and an
    /// unknown principal fails closed. (acceptance 7)
    #[test]
    fn ambiguous_and_unknown_principals_fail_closed() {
        let config = config_with_principals();
        assert!(cli_auth_for(&config, "ambidextrous", None).is_err());
        assert!(cli_auth_for(&config, "unknown", None).is_err());
        assert!(cli_auth_for(&config, "unknown", Some("core-a")).is_err());
    }

    /// The CLI argument surface keeps accepting the documented flags.
    #[test]
    fn cli_parses_tenant_selector() {
        let cli = Cli::try_parse_from([
            "hacienda-backend",
            "sync",
            "--config",
            "basemind.toml",
            "--tenant",
            "core-a",
        ])
        .unwrap();
        let Commands::Sync(args) = cli.command else {
            panic!("expected sync command");
        };
        assert_eq!(args.tenant.as_deref(), Some("core-a"));
    }
}
