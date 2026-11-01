//! MCP server implementation.
//!
//! Provides stdio transport with tool registry and principal resolution.
//! Tools: search (tokenized snippets), rehydrate (owner-only PII rehydration with audit).

use axum::{
    Router,
    extract::State,
    response::Json,
    routing::{get, post},
};
use rmcp::{
    ServerHandler, ServiceExt,
    model::{
        CallToolRequestParams, CallToolResult, CallToolResponse, ListToolsResult, Tool,
        ToolAnnotations, ContentBlock,
        ErrorData, PaginatedRequestParams,
        CallToolRequestMethod,
    },
    schemars,
    handler::server::common::schema_for_type,
    ErrorData as McpError,
};
use serde::Serialize;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::{
    EngineEraFingerprint,
    mcp_types::{Capability, Principal, PrincipalResolver, ResolverError},
    rehydration::{load_vault_map, rehydrate_entity, log_audit, RehydrationAuditRecord},
    search::{SearchParams, SearchFilter, TenantSearchEngineManager},
    audit::{AuditLog, AuditMiddleware, AuditRecord},
};

/// Tool registry with capability-gated access.
#[derive(Debug, Clone)]
pub struct ToolRegistry {
    tools: Vec<Tool>,
    capabilities: Vec<Capability>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: Vec::new(),
            capabilities: Vec::new(),
        }
    }

    /// Register a tool with required capability.
    pub fn register(&mut self, tool: Tool, capability: Capability) {
        self.tools.push(tool);
        self.capabilities.push(capability);
    }

    /// Get tools available to a principal.
    pub fn available_tools(&self, principal: &Principal) -> Vec<Tool> {
        self.tools
            .iter()
            .zip(&self.capabilities)
            .filter_map(|(tool, cap)| {
                if principal.capabilities.contains(cap) {
                    Some(tool.clone())
                } else {
                    None
                }
            })
            .collect()
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolves vault passphrase for rehydration.
/// Adopters implement this for their key custody (Keychain, env var, KMS, etc.).
pub type PassphraseResolver = Arc<dyn Fn() -> Result<String, ResolverError> + Send + Sync>;

/// Shared server state.
#[derive(Clone)]
pub struct ServerState {
    pub registry: Arc<RwLock<ToolRegistry>>,
    pub fingerprint: Option<EngineEraFingerprint>,
    /// Hybrid search engine (BM25 + Vector + Lexical + RRF) per tenant.
    pub search_engine: Option<Arc<TenantSearchEngineManager>>,
    /// Path to the encrypted vault map (XPII) for rehydration.
    pub vault_map_path: Option<PathBuf>,
    /// Resolves the vault decryption passphrase.
    pub passphrase_resolver: Option<PassphraseResolver>,
    /// Path to hacienda.toml config (for sync operations).
    pub config_path: Option<PathBuf>,
    /// Audit log for WORM audit trail.
    pub audit_log: Option<Arc<AuditLog>>,
}

/// MCP server handler.
pub struct McpServer<R>
where
    R: PrincipalResolver,
{
    resolver: Arc<R>,
    state: ServerState,
}

impl<R> McpServer<R>
where
    R: PrincipalResolver,
{
    pub fn new(resolver: R) -> Self {
        let mut registry = ToolRegistry::new();

        // Register tool schemas (always registered; access gated by capability)
        registry.register(search_tool_schema(), Capability::Search);
        registry.register(rehydrate_tool_schema(), Capability::Rehydrate);
        registry.register(sync_tool_schema(), Capability::Sync);
        registry.register(status_tool_schema(), Capability::Status);

        Self {
            resolver: Arc::new(resolver),
            state: ServerState {
                registry: Arc::new(RwLock::new(registry)),
                fingerprint: None,
                search_engine: None,
                vault_map_path: None,
                passphrase_resolver: None,
                config_path: None,
                audit_log: None,
            },
        }
    }

    /// Attach the search engine (built after config/index is ready).
    pub fn with_search_engine(mut self, engine: TenantSearchEngineManager) -> Self {
        self.state.search_engine = Some(Arc::new(engine));
        self
    }

    /// Attach vault map path and passphrase resolver for rehydration.
    pub fn with_rehydration<F>(mut self, vault_map_path: PathBuf, passphrase_resolver: F) -> Self
    where
        F: Fn() -> Result<String, ResolverError> + Send + Sync + 'static,
    {
        self.state.vault_map_path = Some(vault_map_path);
        self.state.passphrase_resolver = Some(Arc::new(passphrase_resolver));
        self
    }

    /// Attach hacienda.toml config path for sync operations.
    pub fn with_config_path(mut self, config_path: PathBuf) -> Self {
        self.state.config_path = Some(config_path);
        self
    }

    /// Attach audit log for WORM audit trail.
    pub fn with_audit_log(mut self, audit_log: Arc<AuditLog>) -> Self {
        self.state.audit_log = Some(audit_log);
        self
    }

    /// Set the engine-era fingerprint.
    pub async fn set_fingerprint(&mut self, fp: EngineEraFingerprint) {
        self.state.fingerprint = Some(fp);
    }

    /// Run the MCP server over stdio transport.
    pub async fn run_stdio(self) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let transport = (io::stdin(), io::stdout());
        self.serve(transport).await?;
        Ok(())
    }

    /// Run the MCP server over HTTP transport.
    pub async fn run_http(
        self,
        addr: std::net::SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let state = self.state.clone();
        let resolver = self.resolver.clone();

        let app = Router::new()
            .route("/mcp", post(mcp_handler))
            .route("/mcp", get(sse_handler))
            .route("/healthz", get(healthz))
            .with_state((state, resolver));

        let listener = tokio::net::TcpListener::bind(addr).await?;
        info!("MCP HTTP server listening on {}", addr);
        axum::serve(listener, app).await?;
        Ok(())
    }
}

impl<R> ServerHandler for McpServer<R>
where
    R: PrincipalResolver,
{
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let principal = self
            .resolver
            .default_principal()
            .unwrap_or_else(|| Principal {
                id: "owner".to_string(),
                name: "Owner".to_string(),
                capabilities: vec![
                    Capability::Search,
                    Capability::Rehydrate,
                    Capability::Sync,
                    Capability::Status,
                ],
            });

        let tools = self.state.registry.read().await.available_tools(&principal);
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let principal = self
            .resolver
            .default_principal()
            .unwrap_or_else(|| Principal {
                id: "owner".to_string(),
                name: "Owner".to_string(),
                capabilities: vec![
                    Capability::Search,
                    Capability::Rehydrate,
                    Capability::Sync,
                    Capability::Status,
                ],
            });

        // Capability check (registry already filters, but double-check here)
        let has_cap = |cap: Capability| principal.capabilities.contains(&cap);

        // Audit middleware
        let audit_middleware = self.state.audit_log.as_ref().map(|log| AuditMiddleware::new(log.clone()));

        let result = match request.name.as_ref() {
            "search" => {
                if !has_cap(Capability::Search) {
                    return Err(ErrorData::invalid_params("principal lacks Search capability", None));
                }
                let args = request.arguments.clone();
                let start = std::time::Instant::now();
                let result = handle_search(&self.state, args.clone()).await;
                let duration = start.elapsed();
                let (result_summary, success) = match &result {
                    Ok(_) => (format!("OK ({}ms)", duration.as_millis()), true),
                    Err(e) => (format!("ERROR: {} ({}ms)", e, duration.as_millis()), false),
                };
                if let Some(ref audit_log) = self.state.audit_log {
                    let record = crate::audit::AuditRecord {
                        sequence: 0,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        principal_id: principal.id.clone(),
                        tool: "search".to_string(),
                        arguments: serde_json::to_value(args.clone()).unwrap_or(serde_json::Value::Null),
                        result_summary,
                        signature: String::new(),
                        public_key: String::new(),
                    };
                    let _ = audit_log.append(record).await;
                }
                result?
            }
            "rehydrate" => {
                if !has_cap(Capability::Rehydrate) {
                    return Err(ErrorData::invalid_params("principal lacks Rehydrate capability (owner-only)", None));
                }
                let args = request.arguments.clone();
                let start = std::time::Instant::now();
                let result = handle_rehydrate(&self.state, args.clone()).await;
                let duration = start.elapsed();
                let (result_summary, success) = match &result {
                    Ok(_) => (format!("OK ({}ms)", duration.as_millis()), true),
                    Err(e) => (format!("ERROR: {} ({}ms)", e, duration.as_millis()), false),
                };
                if let Some(ref audit_log) = self.state.audit_log {
                    let record = crate::audit::AuditRecord {
                        sequence: 0,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        principal_id: principal.id.clone(),
                        tool: "rehydrate".to_string(),
                        arguments: serde_json::to_value(args.clone()).unwrap_or(serde_json::Value::Null),
                        result_summary,
                        signature: String::new(),
                        public_key: String::new(),
                    };
                    let _ = audit_log.append(record).await;
                }
                result?
            }
            "sync" => {
                if !has_cap(Capability::Sync) {
                    return Err(ErrorData::invalid_params("principal lacks Sync capability", None));
                }
                let args = request.arguments.clone();
                let start = std::time::Instant::now();
                let result = handle_sync(&self.state, args.clone()).await;
                let duration = start.elapsed();
                let (result_summary, success) = match &result {
                    Ok(_) => (format!("OK ({}ms)", duration.as_millis()), true),
                    Err(e) => (format!("ERROR: {} ({}ms)", e, duration.as_millis()), false),
                };
                if let Some(ref audit_log) = self.state.audit_log {
                    let record = crate::audit::AuditRecord {
                        sequence: 0,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        principal_id: principal.id.clone(),
                        tool: "sync".to_string(),
                        arguments: serde_json::to_value(args.clone()).unwrap_or(serde_json::Value::Null),
                        result_summary,
                        signature: String::new(),
                        public_key: String::new(),
                    };
                    let _ = audit_log.append(record).await;
                }
                result?
            }
            "status" => {
                if !has_cap(Capability::Status) {
                    return Err(ErrorData::invalid_params("principal lacks Status capability", None));
                }
                let args = request.arguments.clone();
                let start = std::time::Instant::now();
                let result = handle_status(&self.state, args.clone()).await;
                let duration = start.elapsed();
                let (result_summary, success) = match &result {
                    Ok(_) => (format!("OK ({}ms)", duration.as_millis()), true),
                    Err(e) => (format!("ERROR: {} ({}ms)", e, duration.as_millis()), false),
                };
                if let Some(ref audit_log) = self.state.audit_log {
                    let record = crate::audit::AuditRecord {
                        sequence: 0,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        principal_id: principal.id.clone(),
                        tool: "status".to_string(),
                        arguments: serde_json::to_value(args.clone()).unwrap_or(serde_json::Value::Null),
                        result_summary,
                        signature: String::new(),
                        public_key: String::new(),
                    };
                    let _ = audit_log.append(record).await;
                }
                result?
            }
            _ => return Err(ErrorData::method_not_found::<CallToolRequestMethod>()),
        };

        Ok(result.into())
    }
}

// ===== Tool handlers =====

async fn handle_search(
    state: &ServerState,
    args: Option<serde_json::Map<String, Value>>,
) -> Result<CallToolResult, McpError> {
    let engine_manager = state
        .search_engine
        .as_ref()
        .ok_or_else(|| ErrorData::internal_error("search engine not initialized", None))?;

    let args_map = args.ok_or_else(|| ErrorData::invalid_params("missing arguments", None))?;
    
    // Extract tenant_id from arguments (required for multi-tenancy)
    let tenant_id = args_map
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ErrorData::invalid_params("argument 'tenant_id' (string) required", None))?;

    // Get the engine for the specific tenant
    let engine = engine_manager
        .get_engine(tenant_id)
        .ok_or_else(|| ErrorData::invalid_params(format!("tenant '{}' not found", tenant_id), None))?;

    let params = parse_search_params(Some(args_map))?;
    let results = engine
        .search(params)
        .await
        .map_err(|e| ErrorData::internal_error(format!("search failed: {e}"), None))?;

    // Serialize results — snippets already contain gaze tokens (no PII)
    let json = serde_json::to_string(&results)
        .map_err(|e| ErrorData::internal_error(format!("serialize: {e}"), None))?;

    Ok(CallToolResult::success(vec![ContentBlock::text(json)]))
}

async fn handle_rehydrate(
    state: &ServerState,
    args: Option<serde_json::Map<String, Value>>,
) -> Result<CallToolResult, McpError> {
    let vault_path = state
        .vault_map_path
        .as_ref()
        .ok_or_else(|| ErrorData::internal_error("vault map not configured", None))?;
    let passphrase_resolver = state
        .passphrase_resolver
        .as_ref()
        .ok_or_else(|| ErrorData::internal_error("passphrase resolver not configured", None))?;

    let args_map = args.ok_or_else(|| ErrorData::invalid_params("missing arguments", None))?;
    
    // Single entity rehydration: { "entity": "<anchor:Class_N>" }
    let entity_token = args_map
        .get("entity")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ErrorData::invalid_params("argument 'entity' (string) required", None))?;

    // Resolve passphrase
    let passphrase = passphrase_resolver().map_err(|e| ErrorData::internal_error(e.to_string(), None))?;

    // Load vault map (decrypted)
    let vault_map = load_vault_map(vault_path, &passphrase)
        .map_err(|e| ErrorData::internal_error(format!("load vault: {e}"), None))?;

    // Rehydrate single entity
    let original = rehydrate_entity(&vault_map, entity_token)
        .map_err(|e| ErrorData::internal_error(format!("rehydrate: {e}"), None))?;

    // Audit log
    let audit = RehydrationAuditRecord {
        timestamp: chrono::Utc::now().to_rfc3339(),
        operation: "entity".to_string(),
        scope: entity_token.to_string(),
        fingerprint: String::new(),
        success: true,
        error: None,
    };
    let _ = log_audit(&audit); // best-effort

    // Return the original value (only to Rehydrate-capable principal)
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::json!({
            "entity": entity_token,
            "original": original,
            "audit": audit
        }).to_string()
    )]))
}

async fn handle_sync(
    state: &ServerState,
    args: Option<serde_json::Map<String, Value>>,
) -> Result<CallToolResult, McpError> {
    let config_path = state
        .config_path
        .as_ref()
        .ok_or_else(|| ErrorData::internal_error("config path not configured for sync", None))?;

    let full = args
        .as_ref()
        .and_then(|a| a.get("full"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if full {
        // Full rebuild: run manual_refresh which does a complete re-index
        crate::folder_sync::run_manual_refresh(config_path).await
            .map_err(|e| ErrorData::internal_error(format!("full sync failed: {e}"), None))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(
            serde_json::json!({ "status": "ok", "mode": "full", "detail": "full rebuild completed" }).to_string()
        )]))
    } else {
        // Incremental: FolderSync's watcher handles this, but we can trigger a one-shot
        // For now, run manual_refresh with incremental logic inside
        crate::folder_sync::run_manual_refresh(config_path).await
            .map_err(|e| ErrorData::internal_error(format!("incremental sync failed: {e}"), None))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(
            serde_json::json!({ "status": "ok", "mode": "incremental", "detail": "incremental sync completed" }).to_string()
        )]))
    }
}

async fn handle_status(
    state: &ServerState,
    _args: Option<serde_json::Map<String, Value>>,
) -> Result<CallToolResult, McpError> {
    let fp = state.fingerprint.as_ref();
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::json!({
            "fingerprint": fp.map(|f| format!("{:?}", f)),
            "search_engine_ready": state.search_engine.is_some(),
            "rehydration_ready": state.vault_map_path.is_some() && state.passphrase_resolver.is_some(),
        }).to_string()
    )]))
}

// ===== Tool schemas =====

fn search_tool_schema() -> Tool {
    let input_schema = schema_for_type::<SearchParamsSchema>();
    Tool::new(
        "search",
        "Hybrid search (BM25 + Vector + Lexical + RRF) over indexed documents. \
         Returns snippets with gaze tokens (e.g., <4b31c7ee:Name_1>) — no PII exposed. \
         Use rehydrate tool (Rehydrate capability) to recover originals.",
        input_schema,
    )
    .with_annotations(
        ToolAnnotations::with_title("Search Documents")
            .read_only(true)
            .destructive(false)
            .idempotent(true)
            .open_world(false)
    )
}

fn rehydrate_tool_schema() -> Tool {
    #[derive(Serialize, schemars::JsonSchema)]
    struct RehydrateArgs {
        /// Gaze gateway token to rehydrate (e.g., "<4b31c7ee:Name_1>").
        entity: String,
    }
    let input_schema = schema_for_type::<RehydrateArgs>();
    Tool::new(
        "rehydrate",
        "Rehydrate a single gaze gateway token to its original PII value. \
         Owner-only (Rehydrate capability). Audited. \
         For full document rehydration, use the CLI.",
        input_schema,
    )
    .with_annotations(
        ToolAnnotations::with_title("Rehydrate Entity")
            .read_only(false)
            .destructive(false)
            .idempotent(true)
            .open_world(false)
    )
}

fn sync_tool_schema() -> Tool {
    #[derive(Serialize, schemars::JsonSchema)]
    struct SyncArgs {
        #[serde(default)]
        full: bool,
    }
    let input_schema = schema_for_type::<SyncArgs>();
    Tool::new("sync", "Trigger incremental or full index rebuild.", input_schema)
        .with_annotations(
            ToolAnnotations::with_title("Sync Index")
                .read_only(false)
                .destructive(false)
                .idempotent(false)
                .open_world(false)
        )
}

fn status_tool_schema() -> Tool {
    #[derive(Serialize, schemars::JsonSchema)]
    struct StatusArgs {}
    let input_schema = schema_for_type::<StatusArgs>();
    Tool::new("status", "Index status: fingerprint, engine readiness, rehydration readiness.", input_schema)
        .with_annotations(
            ToolAnnotations::with_title("Index Status")
                .read_only(true)
                .destructive(false)
                .idempotent(true)
                .open_world(false)
        )
}

/// Schema wrapper for SearchParams to satisfy JsonSchema
#[derive(Serialize, schemars::JsonSchema)]
struct SearchParamsSchema {
    /// Tenant ID for multi-tenancy isolation (required).
    tenant_id: String,
    query: String,
    #[serde(default = "default_top_k")]
    top_k: usize,
    #[serde(default = "default_true")]
    rerank: bool,
    filter: Option<SearchFilterSchema>,
}

fn default_top_k() -> usize { 10 }
fn default_true() -> bool { true }

#[derive(Serialize, schemars::JsonSchema)]
struct SearchFilterSchema {
    connector: Option<String>,
    since: Option<String>,
}

/// Parse SearchParams from raw JSON arguments.
fn parse_search_params(args: Option<serde_json::Map<String, Value>>) -> Result<SearchParams, McpError> {
    let args = args.unwrap_or_default();
    let query = args
        .get("query")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ErrorData::invalid_params("argument 'query' (string) required", None))?
        .to_string();
    let top_k = args
        .get("top_k")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(10)
        .clamp(1, 100);
    let rerank = args.get("rerank").and_then(|v| v.as_bool()).unwrap_or(true);
    let filter = args.get("filter").and_then(|v| {
        let connector = v.get("connector").and_then(|x| x.as_str()).map(|s| s.to_string());
        let since = v.get("since").and_then(|x| x.as_str()).map(|s| s.to_string());
        if connector.is_some() || since.is_some() {
            Some(SearchFilter { connector, since })
        } else {
            None
        }
    });
    Ok(SearchParams { query, top_k, rerank, filter })
}

/// HTTP handlers
async fn mcp_handler<R>(
    State((_state, _resolver)): State<(ServerState, Arc<R>)>,
    axum::extract::Json(_request): axum::extract::Json<Value>,
) -> Result<Json<Value>, axum::http::StatusCode>
where
    R: PrincipalResolver + Send + Sync + 'static,
{
    warn!("MCP HTTP handler not fully implemented — use stdio transport");
    Err(axum::http::StatusCode::NOT_IMPLEMENTED)
}

async fn sse_handler<R>(
    State((_state, _resolver)): State<(ServerState, Arc<R>)>,
) -> Result<axum::response::Response, axum::http::StatusCode>
where
    R: PrincipalResolver + Send + Sync + 'static,
{
    warn!("SSE handler not implemented — use stdio transport");
    Err(axum::http::StatusCode::NOT_IMPLEMENTED)
}

async fn healthz() -> Json<Value> {
    Json(serde_json::json!({ "status": "ok" }))
}
