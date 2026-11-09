//! MCP server implementation.
//!
//! Provides stdio transport with tool registry and principal resolution.
//! Tools expose tokenized search and metadata-only operational controls.

use axum::{
    Router,
    extract::State,
    response::Json,
    routing::{get, post},
};
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::common::schema_for_type,
    model::{
        CallToolRequestMethod, CallToolRequestParams, CallToolResponse, CallToolResult,
        ContentBlock, ErrorData, ListToolsResult, PaginatedRequestParams, Tool, ToolAnnotations,
    },
    schemars,
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
    audit::AuditLog,
    mcp_types::{Capability, Principal, PrincipalResolver, ResolutionContext},
    search::{SearchFilter, SearchParams, TenantSearchEngineManager},
};

#[cfg(feature = "basemind")]
use crate::CliError;

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

/// Shared server state.
#[derive(Clone)]
pub struct ServerState {
    pub registry: Arc<RwLock<ToolRegistry>>,
    pub fingerprint: Option<EngineEraFingerprint>,
    /// Hybrid search engine (BM25 + Vector + Lexical + RRF) per tenant.
    pub search_engine: Option<Arc<TenantSearchEngineManager>>,
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
        registry.register(sync_tool_schema(), Capability::Sync);
        registry.register(status_tool_schema(), Capability::Status);
        registry.register(graph_entities_tool_schema(), Capability::GraphRag);
        registry.register(graph_rag_tool_schema(), Capability::GraphRag);

        Self {
            resolver: Arc::new(resolver),
            state: ServerState {
                registry: Arc::new(RwLock::new(registry)),
                fingerprint: None,
                search_engine: None,
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
            .resolve(ResolutionContext {
                transport: "stdio".to_string(),
                auth_header: None,
                peer_addr: None,
            })
            .await
            .map_err(|_| ErrorData::invalid_request("authentication required", None))?;

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
            .resolve(ResolutionContext {
                transport: "stdio".to_string(),
                auth_header: None,
                peer_addr: None,
            })
            .await
            .map_err(|_| ErrorData::invalid_request("authentication required", None))?;

        // Capability check (registry already filters, but double-check here)
        let has_cap = |cap: Capability| principal.capabilities.contains(&cap);

        let result = match request.name.as_ref() {
            "search" => {
                if !has_cap(Capability::Search) {
                    return Err(ErrorData::invalid_params(
                        "principal lacks Search capability",
                        None,
                    ));
                }
                let args = request.arguments.clone();
                let start = std::time::Instant::now();
                let result = handle_search(&self.state, args.clone()).await;
                let duration = start.elapsed();
                let (result_summary, _success) = match &result {
                    Ok(_) => (format!("OK ({}ms)", duration.as_millis()), true),
                    Err(_) => (format!("ERROR ({}ms)", duration.as_millis()), false),
                };
                if let Some(ref audit_log) = self.state.audit_log {
                    let record = crate::audit::AuditRecord {
                        sequence: 0,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        principal_id: principal.id.clone(),
                        tool: "search".to_string(),
                        arguments: serde_json::json!({ "argument_count": args.as_ref().map_or(0, |a| a.len()) }),
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
                    return Err(ErrorData::invalid_params(
                        "principal lacks Sync capability",
                        None,
                    ));
                }
                let args = request.arguments.clone();
                let start = std::time::Instant::now();
                let result = handle_sync(&self.state, args.clone()).await;
                let duration = start.elapsed();
                let (result_summary, _success) = match &result {
                    Ok(_) => (format!("OK ({}ms)", duration.as_millis()), true),
                    Err(_) => (format!("ERROR ({}ms)", duration.as_millis()), false),
                };
                if let Some(ref audit_log) = self.state.audit_log {
                    let record = crate::audit::AuditRecord {
                        sequence: 0,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        principal_id: principal.id.clone(),
                        tool: "sync".to_string(),
                        arguments: serde_json::json!({ "argument_count": args.as_ref().map_or(0, |a| a.len()) }),
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
                    return Err(ErrorData::invalid_params(
                        "principal lacks Status capability",
                        None,
                    ));
                }
                let args = request.arguments.clone();
                let start = std::time::Instant::now();
                let result = handle_status(&self.state, args.clone()).await;
                let duration = start.elapsed();
                let (result_summary, _success) = match &result {
                    Ok(_) => (format!("OK ({}ms)", duration.as_millis()), true),
                    Err(_) => (format!("ERROR ({}ms)", duration.as_millis()), false),
                };
                if let Some(ref audit_log) = self.state.audit_log {
                    let record = crate::audit::AuditRecord {
                        sequence: 0,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        principal_id: principal.id.clone(),
                        tool: "status".to_string(),
                        arguments: serde_json::json!({ "argument_count": args.as_ref().map_or(0, |a| a.len()) }),
                        result_summary,
                        signature: String::new(),
                        public_key: String::new(),
                    };
                    let _ = audit_log.append(record).await;
                }
                result?
            }
            "graph_entities" => {
                if !has_cap(Capability::GraphRag) {
                    return Err(ErrorData::invalid_params(
                        "principal lacks GraphRag capability",
                        None,
                    ));
                }
                let args = request.arguments.clone();
                let start = std::time::Instant::now();
                let result = handle_graph_entities(&self.state, args.clone()).await;
                let duration = start.elapsed();
                let (result_summary, _success) = match &result {
                    Ok(_) => (format!("OK ({}ms)", duration.as_millis()), true),
                    Err(_) => (format!("ERROR ({}ms)", duration.as_millis()), false),
                };
                if let Some(ref audit_log) = self.state.audit_log {
                    let record = crate::audit::AuditRecord {
                        sequence: 0,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        principal_id: principal.id.clone(),
                        tool: "graph_entities".to_string(),
                        arguments: serde_json::json!({ "argument_count": args.as_ref().map_or(0, |a| a.len()) }),
                        result_summary,
                        signature: String::new(),
                        public_key: String::new(),
                    };
                    let _ = audit_log.append(record).await;
                }
                result?
            }
            "graph_rag" => {
                if !has_cap(Capability::GraphRag) {
                    return Err(ErrorData::invalid_params(
                        "principal lacks GraphRag capability",
                        None,
                    ));
                }
                let args = request.arguments.clone();
                let start = std::time::Instant::now();
                let result = handle_graph_rag(&self.state, args.clone()).await;
                let duration = start.elapsed();
                let (result_summary, _success) = match &result {
                    Ok(_) => (format!("OK ({}ms)", duration.as_millis()), true),
                    Err(_) => (format!("ERROR ({}ms)", duration.as_millis()), false),
                };
                if let Some(ref audit_log) = self.state.audit_log {
                    let record = crate::audit::AuditRecord {
                        sequence: 0,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        principal_id: principal.id.clone(),
                        tool: "graph_rag".to_string(),
                        arguments: serde_json::json!({ "argument_count": args.as_ref().map_or(0, |a| a.len()) }),
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
        .ok_or_else(|| ErrorData::invalid_params("tenant unavailable", None))?;

    let params = parse_search_params(Some(args_map))
        .map_err(|_| ErrorData::invalid_params("invalid search arguments", None))?;
    let results = engine
        .search(params)
        .await
        .map_err(|_| ErrorData::internal_error("search failed", None))?;

    // Serialize results — snippets already contain gaze tokens (no PII)
    let json = serde_json::to_string(&results)
        .map_err(|_| ErrorData::internal_error("serialization failed", None))?;

    Ok(CallToolResult::success(vec![ContentBlock::text(json)]))
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

    // Full rebuild clears and re-indexes everything; incremental only picks up
    // new/changed files. Status is reported on stderr inside run_manual_refresh,
    // so stdout stays clean for the stdio JSON-RPC stream; the indexed document
    // list is returned in the tool result instead.
    let indexed = crate::folder_sync::run_manual_refresh(config_path, full)
        .await
        .map_err(|_| ErrorData::internal_error("sync failed", None))?;

    let mode = if full { "full" } else { "incremental" };
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::json!({
            "status": "ok",
            "mode": mode,
            "indexed_count": indexed.len(),
            "documents": indexed.iter().map(|d| d.doc_id.clone()).collect::<Vec<_>>(),
        })
        .to_string(),
    )]))
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
        })
        .to_string(),
    )]))
}

/// Read-only Cypher query over the tenant's entity graph (basemind graphrag).
///
/// Only `MATCH`, `RETURN`, `WHERE`, `LIMIT`, `ORDER BY`, `WITH`, `UNION` pass
/// lance-graph's parser; `CREATE`/`DELETE`/`SET`/`MERGE` are rejected, so the
/// tool is safe to expose read-only.
async fn handle_graph_entities(
    state: &ServerState,
    args: Option<serde_json::Map<String, Value>>,
) -> Result<CallToolResult, McpError> {
    #[cfg(feature = "basemind")]
    {
        let engine_manager = state
            .search_engine
            .as_ref()
            .ok_or_else(|| ErrorData::internal_error("search engine not initialized", None))?;
        let args_map = args.ok_or_else(|| ErrorData::invalid_params("missing arguments", None))?;

        let tenant_id = args_map
            .get("tenant_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ErrorData::invalid_params("argument 'tenant_id' (string) required", None)
            })?;
        let cypher = args_map
            .get("cypher")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ErrorData::invalid_params("argument 'cypher' (string) required", None))?
            .to_string();
        let max_rows = args_map
            .get("max_rows")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(200)
            .clamp(1, 1000);

        let engine = engine_manager
            .get_engine(tenant_id)
            .ok_or_else(|| ErrorData::invalid_params("tenant unavailable", None))?;
        let store = engine.lance_store_clone();
        let tenant = tenant_id.to_string();

        let cypher_result =
            tokio::task::spawn_blocking(move || store.execute_cypher(&tenant, &cypher, max_rows))
                .await
                .map_err(|_| ErrorData::internal_error("cypher task failed", None))?
                .map_err(|_| ErrorData::internal_error("cypher execution failed", None))?;

        let truncated = cypher_result.rows.len() >= max_rows;
        let json = serde_json::json!({
            "tenant_id": tenant_id,
            "columns": cypher_result.columns,
            "rows": cypher_result.rows,
            "truncated": truncated,
        })
        .to_string();
        Ok(CallToolResult::success(vec![ContentBlock::text(json)]))
    }

    #[cfg(not(feature = "basemind"))]
    {
        let _ = (state, args);
        Err(ErrorData::invalid_params(
            "graph entities requires the basemind feature",
            None,
        ))
    }
}

/// GraphRAG hybrid retrieval: vector lane + entity-graph expansion + score fusion.
///
/// Requires `documents.embed = true` (the query must be embedded); the whole
/// flow runs off the async runtime in `spawn_blocking` because every LanceDB
/// step block_ons the store's own reactor.
async fn handle_graph_rag(
    state: &ServerState,
    args: Option<serde_json::Map<String, Value>>,
) -> Result<CallToolResult, McpError> {
    #[cfg(feature = "basemind")]
    {
        let engine_manager = state
            .search_engine
            .as_ref()
            .ok_or_else(|| ErrorData::internal_error("search engine not initialized", None))?;
        let args_map = args.ok_or_else(|| ErrorData::invalid_params("missing arguments", None))?;

        let tenant_id = args_map
            .get("tenant_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ErrorData::invalid_params("argument 'tenant_id' (string) required", None)
            })?;
        let query = args_map
            .get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ErrorData::invalid_params("argument 'query' (string) required", None))?
            .to_string();
        let hops = args_map
            .get("hops")
            .and_then(|v| v.as_u64())
            .map(|v| v as u8)
            .unwrap_or(2)
            .min(2);
        let max_results = args_map
            .get("max_results")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(50)
            .clamp(1, 200);

        let engine = engine_manager
            .get_engine(tenant_id)
            .ok_or_else(|| ErrorData::invalid_params("tenant unavailable", None))?;
        let store = engine.lance_store_clone();
        let embedder = engine.embedder_clone().ok_or_else(|| {
            ErrorData::invalid_params("graph rag requires documents.embed = true", None)
        })?;
        let tenant = tenant_id.to_string();

        let (hits, truncated) = tokio::task::spawn_blocking(move || -> Result<_, CliError> {
            let query_vec = embedder
                .embed(&query)
                .map_err(|e| CliError::Other(format!("embed query: {e}")))?;
            store
                .graph_rag_search(&tenant, query_vec, hops, max_results)
                .map_err(|e| CliError::Other(format!("graph rag: {e}")))
        })
        .await
        .map_err(|_| ErrorData::internal_error("rag task failed", None))?
        .map_err(|_| ErrorData::internal_error("graph retrieval failed", None))?;

        let json = serde_json::json!({
            "tenant_id": tenant_id,
            "hits": hits,
            "truncated": truncated,
        })
        .to_string();
        Ok(CallToolResult::success(vec![ContentBlock::text(json)]))
    }

    #[cfg(not(feature = "basemind"))]
    {
        let _ = (state, args);
        Err(ErrorData::invalid_params(
            "graph rag requires the basemind feature",
            None,
        ))
    }
}

// ===== Tool schemas =====

fn search_tool_schema() -> Tool {
    let input_schema = schema_for_type::<SearchParamsSchema>();
    Tool::new(
        "search",
        "Hybrid search (BM25 + Vector + Lexical + RRF) over indexed documents. \
         Returns snippets with gaze tokens (e.g., <4b31c7ee:Name_1>) — no PII exposed. \
         Results contain tokenized snippets only.",
        input_schema,
    )
    .with_annotations(
        ToolAnnotations::with_title("Search Documents")
            .read_only(true)
            .destructive(false)
            .idempotent(true)
            .open_world(false),
    )
}

fn sync_tool_schema() -> Tool {
    #[derive(Serialize, schemars::JsonSchema)]
    struct SyncArgs {
        #[serde(default)]
        full: bool,
    }
    let input_schema = schema_for_type::<SyncArgs>();
    Tool::new(
        "sync",
        "Trigger incremental or full index rebuild.",
        input_schema,
    )
    .with_annotations(
        ToolAnnotations::with_title("Sync Index")
            .read_only(false)
            .destructive(false)
            .idempotent(false)
            .open_world(false),
    )
}

fn status_tool_schema() -> Tool {
    #[derive(Serialize, schemars::JsonSchema)]
    struct StatusArgs {}
    let input_schema = schema_for_type::<StatusArgs>();
    Tool::new(
        "status",
        "Index status: fingerprint, engine readiness, rehydration readiness.",
        input_schema,
    )
    .with_annotations(
        ToolAnnotations::with_title("Index Status")
            .read_only(true)
            .destructive(false)
            .idempotent(true)
            .open_world(false),
    )
}

fn graph_entities_tool_schema() -> Tool {
    #[derive(Serialize, schemars::JsonSchema)]
    struct GraphEntitiesArgs {
        /// Tenant ID for multi-tenancy isolation (required).
        tenant_id: String,
        /// Read-only Cypher query. Only MATCH, RETURN, WHERE, LIMIT, ORDER BY,
        /// WITH, UNION are allowed; CREATE/DELETE/SET/MERGE are rejected.
        cypher: String,
        /// Row cap (1-1000, default 200).
        #[serde(default = "default_max_rows")]
        max_rows: usize,
    }
    let input_schema = schema_for_type::<GraphEntitiesArgs>();
    Tool::new(
        "graph_entities",
        "Read-only Cypher query over the tenant's entity graph (GLiNER mentions + co-occurrence). \
         GraphRag capability required.",
        input_schema,
    )
    .with_annotations(
        ToolAnnotations::with_title("Query Entity Graph")
            .read_only(true)
            .destructive(false)
            .idempotent(true)
            .open_world(false),
    )
}

fn graph_rag_tool_schema() -> Tool {
    #[derive(Serialize, schemars::JsonSchema)]
    struct GraphRagArgs {
        /// Tenant ID for multi-tenancy isolation (required).
        tenant_id: String,
        /// Natural-language query to embed and expand through the entity graph.
        query: String,
        /// Graph expansion hops (1-2, default 2).
        #[serde(default = "default_hops")]
        hops: u8,
        /// Result cap (1-200, default 50).
        #[serde(default = "default_graph_rag_results")]
        max_results: usize,
    }
    let input_schema = schema_for_type::<GraphRagArgs>();
    Tool::new(
        "graph_rag",
        "GraphRAG: hybrid retrieval via entity graph expansion (vector lane + graph lane + fusion). \
         Requires documents.embed = true. GraphRag capability required.",
        input_schema,
    )
    .with_annotations(
        ToolAnnotations::with_title("GraphRAG Retrieval")
            .read_only(true)
            .destructive(false)
            .idempotent(true)
            .open_world(false)
    )
}

fn default_max_rows() -> usize {
    200
}
fn default_hops() -> u8 {
    2
}
fn default_graph_rag_results() -> usize {
    50
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

fn default_top_k() -> usize {
    10
}
fn default_true() -> bool {
    true
}

#[derive(Serialize, schemars::JsonSchema)]
struct SearchFilterSchema {
    connector: Option<String>,
    since: Option<String>,
}

/// Parse SearchParams from raw JSON arguments.
fn parse_search_params(
    args: Option<serde_json::Map<String, Value>>,
) -> Result<SearchParams, McpError> {
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
        let connector = v
            .get("connector")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let since = v
            .get("since")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        if connector.is_some() || since.is_some() {
            Some(SearchFilter { connector, since })
        } else {
            None
        }
    });
    Ok(SearchParams {
        query,
        top_k,
        rerank,
        filter,
    })
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
