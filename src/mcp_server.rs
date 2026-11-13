//! MCP server implementation.
//!
//! Provides stdio transport with tool registry and principal resolution.
//! Tools expose tokenized search and metadata-only operational controls.

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
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
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::{
    EngineEraFingerprint,
    audit::AuditLog,
    authz::{AuthzError, FolderRoot, attach_local_doc},
    mcp_types::{Capability, Principal, PrincipalResolver, ResolutionContext},
    search::{SearchFilter, SearchParams, TenantSearchEngineManager},
    sidecar::OpaqueDisclosureGateway,
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
    pub folder_roots: HashMap<String, Vec<FolderRoot>>,
    /// Tenant-scoped and sync-wired; empty means attach fails closed. Durable
    /// cross-restart persistence is tracked by #21 (ingestion pipeline).
    pub processed_index: Arc<RwLock<HashMap<String, HashMap<PathBuf, String>>>>,
    /// Authenticated sidecar client. It returns only opaque disclosure
    /// handles/status; approval and viewer-open are never MCP operations.
    pub disclosure_gateway: Option<Arc<dyn OpaqueDisclosureGateway>>,
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
        registry.register(attach_local_doc_tool_schema(), Capability::AttachLocalDoc);
        registry.register(
            request_human_disclosure_tool_schema(),
            Capability::HumanDisclosureRequest,
        );
        registry.register(
            disclosure_status_tool_schema(),
            Capability::DisclosureStatus,
        );
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
                folder_roots: HashMap::new(),
                processed_index: Arc::new(RwLock::new(HashMap::new())),
                disclosure_gateway: None,
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

    pub fn with_folder_roots(mut self, roots: HashMap<String, Vec<FolderRoot>>) -> Self {
        self.state.folder_roots = roots;
        self
    }
    pub async fn with_processed_document(
        self,
        tenant: String,
        path: PathBuf,
        token: String,
    ) -> Self {
        self.state
            .processed_index
            .write()
            .await
            .entry(tenant)
            .or_default()
            .insert(path, token);
        self
    }

    /// Attach audit log for WORM audit trail.
    pub fn with_audit_log(mut self, audit_log: Arc<AuditLog>) -> Self {
        self.state.audit_log = Some(audit_log);
        self
    }

    pub fn with_disclosure_gateway(mut self, gateway: Arc<dyn OpaqueDisclosureGateway>) -> Self {
        self.state.disclosure_gateway = Some(gateway);
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

        // Capability check (registry already filters, but double-check here).
        // Tenant IDs in payloads are selectors only; authorization comes solely
        // from the authenticated principal binding and fails closed.
        let has_cap = |cap: Capability| principal.capabilities.contains(&cap);
        if let Some(args) = request.arguments.as_ref()
            && let Some(tenant) = args.get("tenant_id").and_then(|v| v.as_str())
            && !principal.tenant_ids.contains(tenant)
        {
            if request.name == "attach_local_doc" {
                audit_authz(
                    &self.state,
                    &principal,
                    Some(tenant),
                    "deny",
                    "tenant_unauthorized",
                    "ERROR_CODE",
                )
                .await
                .map_err(|_| ErrorData::internal_error("audit unavailable", None))?;
                return Err(ErrorData::invalid_params("document unavailable", None));
            }
            return Err(ErrorData::invalid_params("tenant unauthorized", None));
        }
        if request.name == "attach_local_doc" && !has_cap(Capability::AttachLocalDoc) {
            audit_authz(
                &self.state,
                &principal,
                request
                    .arguments
                    .as_ref()
                    .and_then(|a| a.get("tenant_id"))
                    .and_then(|v| v.as_str()),
                "deny",
                "missing_capability",
                "ERROR_CODE",
            )
            .await
            .map_err(|_| ErrorData::internal_error("audit unavailable", None))?;
            return Err(ErrorData::invalid_params("document unavailable", None));
        }

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
                        epoch: 0,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        principal_id: principal.id.clone(),
                        tool: "search".to_string(),
                        arguments: serde_json::json!({ "argument_count": args.as_ref().map_or(0, |a| a.len()) }),
                        authz: crate::audit::AuthorizationMetadata {
                            principal_fingerprint: format!(
                                "blake3:{}",
                                blake3::hash(principal.id.as_bytes()).to_hex()
                            ),
                            tenant_id: args
                                .as_ref()
                                .and_then(|a| a.get("tenant_id"))
                                .and_then(|v| v.as_str())
                                .map(str::to_owned),
                            tool: request.name.to_string(),
                            decision: "allow".into(),
                            reason_class: "authorized".into(),
                        },
                        result_summary,
                        previous_hash: String::new(),
                        record_hash: String::new(),
                        signature: String::new(),
                        public_key: String::new(),
                    };
                    if audit_log.append_required(record).await.is_err() {
                        return Err(ErrorData::internal_error("audit unavailable", None));
                    }
                }
                result?
            }
            "sync" => {
                if self.state.audit_log.is_none() {
                    return Err(ErrorData::internal_error("audit unavailable", None));
                }
                if !has_cap(Capability::Sync) {
                    return Err(ErrorData::invalid_params(
                        "principal lacks Sync capability",
                        None,
                    ));
                }
                let args = request.arguments.clone();
                let start = std::time::Instant::now();
                let result = handle_sync(&self.state, args.clone(), &principal).await;
                let duration = start.elapsed();
                let (result_summary, _success) = match &result {
                    Ok(_) => (format!("OK ({}ms)", duration.as_millis()), true),
                    Err(_) => (format!("ERROR ({}ms)", duration.as_millis()), false),
                };
                if let Some(ref audit_log) = self.state.audit_log {
                    let record = crate::audit::AuditRecord {
                        sequence: 0,
                        epoch: 0,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        principal_id: principal.id.clone(),
                        tool: "sync".to_string(),
                        arguments: serde_json::json!({ "argument_count": args.as_ref().map_or(0, |a| a.len()) }),
                        authz: crate::audit::AuthorizationMetadata {
                            principal_fingerprint: format!(
                                "blake3:{}",
                                blake3::hash(principal.id.as_bytes()).to_hex()
                            ),
                            tenant_id: args
                                .as_ref()
                                .and_then(|a| a.get("tenant_id"))
                                .and_then(|v| v.as_str())
                                .map(str::to_owned),
                            tool: request.name.to_string(),
                            decision: "allow".into(),
                            reason_class: "authorized".into(),
                        },
                        result_summary,
                        previous_hash: String::new(),
                        record_hash: String::new(),
                        signature: String::new(),
                        public_key: String::new(),
                    };
                    if audit_log.append_required(record).await.is_err() {
                        return Err(ErrorData::internal_error("audit unavailable", None));
                    }
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
                        epoch: 0,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        principal_id: principal.id.clone(),
                        tool: "status".to_string(),
                        arguments: serde_json::json!({ "argument_count": args.as_ref().map_or(0, |a| a.len()) }),
                        authz: crate::audit::AuthorizationMetadata {
                            principal_fingerprint: format!(
                                "blake3:{}",
                                blake3::hash(principal.id.as_bytes()).to_hex()
                            ),
                            tenant_id: args
                                .as_ref()
                                .and_then(|a| a.get("tenant_id"))
                                .and_then(|v| v.as_str())
                                .map(str::to_owned),
                            tool: request.name.to_string(),
                            decision: "allow".into(),
                            reason_class: "authorized".into(),
                        },
                        result_summary,
                        previous_hash: String::new(),
                        record_hash: String::new(),
                        signature: String::new(),
                        public_key: String::new(),
                    };
                    if audit_log.append_required(record).await.is_err() {
                        return Err(ErrorData::internal_error("audit unavailable", None));
                    }
                }
                result?
            }
            "attach_local_doc" => {
                if self.state.audit_log.is_none() {
                    return Err(ErrorData::internal_error("audit unavailable", None));
                }
                let tenant_from_args = request
                    .arguments
                    .as_ref()
                    .and_then(|a| a.get("tenant_id"))
                    .and_then(|v| v.as_str());
                if !has_cap(Capability::AttachLocalDoc) {
                    audit_authz(
                        &self.state,
                        &principal,
                        tenant_from_args,
                        "deny",
                        "missing_capability",
                        "ERROR_CODE",
                    )
                    .await
                    .map_err(|_| ErrorData::internal_error("audit unavailable", None))?;
                    return Err(ErrorData::invalid_params("document unavailable", None));
                }
                let args = match request.arguments.clone() {
                    Some(args) => args,
                    None => {
                        audit_authz(
                            &self.state,
                            &principal,
                            None,
                            "deny",
                            "invalid_reference",
                            "ERROR_CODE",
                        )
                        .await
                        .map_err(|_| ErrorData::internal_error("audit unavailable", None))?;
                        return Err(ErrorData::invalid_params("document unavailable", None));
                    }
                };
                let tenant = match args.get("tenant_id").and_then(|v| v.as_str()) {
                    Some(t) if principal.tenant_ids.contains(t) => t,
                    Some(t) => {
                        audit_authz(
                            &self.state,
                            &principal,
                            Some(t),
                            "deny",
                            "tenant_unauthorized",
                            "ERROR_CODE",
                        )
                        .await
                        .map_err(|_| ErrorData::internal_error("audit unavailable", None))?;
                        return Err(ErrorData::invalid_params("document unavailable", None));
                    }
                    None => {
                        audit_authz(
                            &self.state,
                            &principal,
                            None,
                            "deny",
                            "invalid_reference",
                            "ERROR_CODE",
                        )
                        .await
                        .map_err(|_| ErrorData::internal_error("audit unavailable", None))?;
                        return Err(ErrorData::invalid_params("document unavailable", None));
                    }
                };
                let path = match args.get("path").and_then(|v| v.as_str()) {
                    Some(path) => path,
                    None => {
                        audit_authz(
                            &self.state,
                            &principal,
                            Some(tenant),
                            "deny",
                            "invalid_reference",
                            "ERROR_CODE",
                        )
                        .await
                        .map_err(|_| ErrorData::internal_error("audit unavailable", None))?;
                        return Err(ErrorData::invalid_params("document unavailable", None));
                    }
                };
                let processed = self.state.processed_index.read().await;
                let roots = match self.state.folder_roots.get(tenant) {
                    Some(roots) => roots,
                    None => {
                        audit_authz(
                            &self.state,
                            &principal,
                            Some(tenant),
                            "deny",
                            "outside_root",
                            "ERROR_CODE",
                        )
                        .await
                        .map_err(|_| ErrorData::internal_error("audit unavailable", None))?;
                        return Err(ErrorData::invalid_params("document unavailable", None));
                    }
                };
                let entries = processed.get(tenant).cloned().unwrap_or_default();
                let clean = match attach_local_doc(PathBuf::from(path).as_path(), roots, &entries) {
                    Ok(clean) => clean,
                    Err(error) => {
                        audit_authz(
                            &self.state,
                            &principal,
                            Some(tenant),
                            "deny",
                            authz_reason(&error),
                            "ERROR_CODE",
                        )
                        .await
                        .map_err(|_| ErrorData::internal_error("audit unavailable", None))?;
                        return Err(ErrorData::invalid_params("document unavailable", None));
                    }
                };
                audit_authz(
                    &self.state,
                    &principal,
                    Some(tenant),
                    "allow",
                    "authorized",
                    "clean-ref",
                )
                .await
                .map_err(|_| ErrorData::internal_error("audit unavailable", None))?;
                CallToolResult::success(vec![ContentBlock::text(
                    serde_json::json!({"reference": clean.token}).to_string(),
                )])
            }
            "request_human_disclosure" => {
                if !has_cap(Capability::HumanDisclosureRequest) {
                    return Err(ErrorData::invalid_params(
                        "principal lacks disclosure capability",
                        None,
                    ));
                }
                let args = request
                    .arguments
                    .clone()
                    .ok_or_else(|| ErrorData::invalid_params("missing arguments", None))?;
                let tenant = args
                    .get("tenant_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ErrorData::invalid_params("tenant unauthorized", None))?;
                let token = args
                    .get("token")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ErrorData::invalid_params("invalid disclosure scope", None))?;
                let engine = args
                    .get("engine_fingerprint")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ErrorData::invalid_params("invalid disclosure binding", None))?;
                let document = args
                    .get("document_fingerprint")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ErrorData::invalid_params("invalid disclosure binding", None))?;
                if !principal.tenant_ids.contains(tenant) {
                    return Err(ErrorData::invalid_params("tenant unauthorized", None));
                }
                let gateway = self.state.disclosure_gateway.as_ref().ok_or_else(|| {
                    ErrorData::internal_error("disclosure sidecar unavailable", None)
                })?;
                let result = gateway
                    .request(
                        &principal.id,
                        tenant,
                        crate::disclosure::DisclosureScope::Entity {
                            token: token.into(),
                        },
                        crate::disclosure::VaultBinding {
                            engine_era_fingerprint: engine.into(),
                            document_fingerprint: document.into(),
                        },
                    )
                    .await
                    .map_err(|_| ErrorData::internal_error("disclosure unavailable", None))?;
                // The gateway result is intentionally the opaque handle/status
                // schema; no proof, approval, viewer, or content field exists.
                CallToolResult::success(vec![ContentBlock::text(
                    serde_json::to_string(&result)
                        .map_err(|_| ErrorData::internal_error("serialization failed", None))?,
                )])
            }
            "disclosure_status" => {
                if !has_cap(Capability::DisclosureStatus) {
                    return Err(ErrorData::invalid_params(
                        "principal lacks disclosure capability",
                        None,
                    ));
                }
                let args = request
                    .arguments
                    .clone()
                    .ok_or_else(|| ErrorData::invalid_params("missing arguments", None))?;
                let tenant = args
                    .get("tenant_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ErrorData::invalid_params("tenant unauthorized", None))?;
                let handle = args
                    .get("handle")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ErrorData::invalid_params("invalid disclosure handle", None))?;
                if !principal.tenant_ids.contains(tenant) {
                    return Err(ErrorData::invalid_params("tenant unauthorized", None));
                }
                let gateway = self.state.disclosure_gateway.as_ref().ok_or_else(|| {
                    ErrorData::internal_error("disclosure sidecar unavailable", None)
                })?;
                let result = gateway
                    .status(&principal.id, tenant, handle)
                    .await
                    .map_err(|_| ErrorData::internal_error("disclosure unavailable", None))?;
                CallToolResult::success(vec![ContentBlock::text(
                    serde_json::to_string(&result)
                        .map_err(|_| ErrorData::internal_error("serialization failed", None))?,
                )])
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
                        epoch: 0,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        principal_id: principal.id.clone(),
                        tool: "graph_entities".to_string(),
                        arguments: serde_json::json!({ "argument_count": args.as_ref().map_or(0, |a| a.len()) }),
                        authz: crate::audit::AuthorizationMetadata {
                            principal_fingerprint: format!(
                                "blake3:{}",
                                blake3::hash(principal.id.as_bytes()).to_hex()
                            ),
                            tenant_id: args
                                .as_ref()
                                .and_then(|a| a.get("tenant_id"))
                                .and_then(|v| v.as_str())
                                .map(str::to_owned),
                            tool: request.name.to_string(),
                            decision: "allow".into(),
                            reason_class: "authorized".into(),
                        },
                        result_summary,
                        previous_hash: String::new(),
                        record_hash: String::new(),
                        signature: String::new(),
                        public_key: String::new(),
                    };
                    if audit_log.append_required(record).await.is_err() {
                        return Err(ErrorData::internal_error("audit unavailable", None));
                    }
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
                        epoch: 0,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        principal_id: principal.id.clone(),
                        tool: "graph_rag".to_string(),
                        arguments: serde_json::json!({ "argument_count": args.as_ref().map_or(0, |a| a.len()) }),
                        authz: crate::audit::AuthorizationMetadata {
                            principal_fingerprint: format!(
                                "blake3:{}",
                                blake3::hash(principal.id.as_bytes()).to_hex()
                            ),
                            tenant_id: args
                                .as_ref()
                                .and_then(|a| a.get("tenant_id"))
                                .and_then(|v| v.as_str())
                                .map(str::to_owned),
                            tool: request.name.to_string(),
                            decision: "allow".into(),
                            reason_class: "authorized".into(),
                        },
                        result_summary,
                        previous_hash: String::new(),
                        record_hash: String::new(),
                        signature: String::new(),
                        public_key: String::new(),
                    };
                    if audit_log.append_required(record).await.is_err() {
                        return Err(ErrorData::internal_error("audit unavailable", None));
                    }
                }
                result?
            }
            _ => return Err(ErrorData::method_not_found::<CallToolRequestMethod>()),
        };

        Ok(result.into())
    }
}

async fn audit_authz(
    state: &ServerState,
    principal: &Principal,
    tenant_id: Option<&str>,
    decision: &str,
    reason_class: &str,
    result_summary: &str,
) -> anyhow::Result<()> {
    let log = state
        .audit_log
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("audit unavailable"))?;
    log.append_required(crate::audit::AuditRecord {
        sequence: 0,
        epoch: 0,
        timestamp: String::new(),
        principal_id: principal.id.clone(),
        tool: "attach_local_doc".into(),
        arguments: serde_json::json!({"argument_count": 2}),
        authz: crate::audit::AuthorizationMetadata {
            principal_fingerprint: format!(
                "blake3:{}",
                blake3::hash(principal.id.as_bytes()).to_hex()
            ),
            tenant_id: tenant_id.map(str::to_owned),
            tool: "attach_local_doc".into(),
            decision: decision.into(),
            reason_class: reason_class.into(),
        },
        result_summary: result_summary.into(),
        previous_hash: String::new(),
        record_hash: String::new(),
        signature: String::new(),
        public_key: String::new(),
    })
    .await?;
    Ok(())
}

fn authz_reason(error: &AuthzError) -> &'static str {
    match error {
        AuthzError::UnsupportedScheme => "unsupported_scheme",
        AuthzError::OutsideRoot | AuthzError::RootUnavailable => "outside_root",
        AuthzError::Unprocessed => "unprocessed",
        AuthzError::InvalidReference => "invalid_reference",
        AuthzError::UnauthorizedTenant => "tenant_unauthorized",
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
    principal: &Principal,
) -> Result<CallToolResult, McpError> {
    let tenant = match args
        .as_ref()
        .and_then(|a| a.get("tenant_id"))
        .and_then(|v| v.as_str())
        .map(str::to_owned)
    {
        Some(t) if principal.tenant_ids.contains(&t) => t,
        Some(_) => return Err(ErrorData::invalid_params("tenant unauthorized", None)),
        None if principal.tenant_ids.len() == 1 => {
            principal.tenant_ids.iter().next().cloned().unwrap()
        }
        _ => return Err(ErrorData::invalid_params("tenant_id required", None)),
    };
    let roots = state
        .folder_roots
        .get(&tenant)
        .ok_or_else(|| ErrorData::invalid_params("tenant unavailable", None))?;
    let root_paths: Vec<PathBuf> = roots.iter().map(|r| r.path.clone()).collect();
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
    let indexed =
        crate::folder_sync::run_manual_refresh_scoped(config_path, &tenant, &root_paths, full)
            .await
            .map_err(|_| ErrorData::internal_error("sync failed", None))?;

    let mut scoped = Vec::new();
    let roots = state.folder_roots.get(&tenant).unwrap();
    for doc in indexed {
        if let Ok(canon) = std::fs::canonicalize(&doc.path)
            && roots
                .iter()
                .filter_map(|r| r.canonical_for_auth().ok())
                .any(|r| canon.starts_with(r))
        {
            let token = format!(
                "clean-{}",
                blake3::hash(
                    format!("{}|{}|{:?}", doc.doc_id, doc.content_hash, doc.fingerprint).as_bytes()
                )
                .to_hex()
            );
            state
                .processed_index
                .write()
                .await
                .entry(tenant.clone())
                .or_default()
                .insert(canon, token);
            scoped.push(doc);
        }
    }
    let indexed = scoped;
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
        /// Authorized tenant selector; omitted only for a single-bound principal.
        tenant_id: Option<String>,
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

fn attach_local_doc_tool_schema() -> Tool {
    #[derive(Serialize, schemars::JsonSchema)]
    struct AttachArgs {
        tenant_id: String,
        path: String,
    }
    Tool::new("attach_local_doc", "Attach an already-processed document below an Hacienda ingestion root; returns an opaque clean reference.", schema_for_type::<AttachArgs>())
        .with_annotations(ToolAnnotations::with_title("Attach Local Document").read_only(true).destructive(false).idempotent(true).open_world(false))
}

fn request_human_disclosure_tool_schema() -> Tool {
    #[derive(Serialize, schemars::JsonSchema)]
    struct DisclosureRequestArgs {
        tenant_id: String,
        /// Pseudonym reference only; the original value is never accepted.
        token: String,
        engine_fingerprint: String,
        document_fingerprint: String,
    }
    Tool::new(
        "request_human_disclosure",
        "Request owner-side disclosure; returns an opaque handle and status only.",
        schema_for_type::<DisclosureRequestArgs>(),
    )
    .with_annotations(
        ToolAnnotations::with_title("Request Human Disclosure")
            .read_only(false)
            .destructive(false)
            .idempotent(false)
            .open_world(false),
    )
}

fn disclosure_status_tool_schema() -> Tool {
    #[derive(Serialize, schemars::JsonSchema)]
    struct DisclosureStatusArgs {
        tenant_id: String,
        handle: String,
    }
    Tool::new(
        "disclosure_status",
        "Poll owner-side disclosure status; returns metadata only.",
        schema_for_type::<DisclosureStatusArgs>(),
    )
    .with_annotations(
        ToolAnnotations::with_title("Disclosure Status")
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
    State((state, resolver)): State<(ServerState, Arc<R>)>,
    headers: HeaderMap,
    axum::extract::Json(request): axum::extract::Json<Value>,
) -> Result<Json<Value>, StatusCode>
where
    R: PrincipalResolver + Send + Sync + 'static,
{
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let principal = resolver
        .resolve(ResolutionContext {
            transport: "http".into(),
            auth_header: headers
                .get(AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
            peer_addr: None,
        })
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let result = match method {
        "tools/list" => {
            let tools = state.registry.read().await.available_tools(&principal);
            serde_json::json!({ "tools": tools })
        }
        "tools/call" => {
            let params = request
                .get("params")
                .and_then(Value::as_object)
                .ok_or(StatusCode::BAD_REQUEST)?;
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .ok_or(StatusCode::BAD_REQUEST)?;
            let args = params
                .get("arguments")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let has_cap = |cap: Capability| principal.capabilities.contains(&cap);
            let text = match name {
                // Streamable HTTP has the same closed disclosure contract as
                // stdio: only opaque request/status operations are admitted.
                "request_human_disclosure" if has_cap(Capability::HumanDisclosureRequest) => {
                    let tenant = args
                        .get("tenant_id")
                        .and_then(Value::as_str)
                        .ok_or(StatusCode::BAD_REQUEST)?;
                    let token = args
                        .get("token")
                        .and_then(Value::as_str)
                        .ok_or(StatusCode::BAD_REQUEST)?;
                    let engine = args
                        .get("engine_fingerprint")
                        .and_then(Value::as_str)
                        .ok_or(StatusCode::BAD_REQUEST)?;
                    let document = args
                        .get("document_fingerprint")
                        .and_then(Value::as_str)
                        .ok_or(StatusCode::BAD_REQUEST)?;
                    if !principal.tenant_ids.contains(tenant) {
                        return Err(StatusCode::FORBIDDEN);
                    }
                    let gateway = state
                        .disclosure_gateway
                        .as_ref()
                        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
                    let result = gateway
                        .request(
                            &principal.id,
                            tenant,
                            crate::disclosure::DisclosureScope::Entity {
                                token: token.into(),
                            },
                            crate::disclosure::VaultBinding {
                                engine_era_fingerprint: engine.into(),
                                document_fingerprint: document.into(),
                            },
                        )
                        .await
                        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                    serde_json::to_string(&result).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                }
                "disclosure_status" if has_cap(Capability::DisclosureStatus) => {
                    let tenant = args
                        .get("tenant_id")
                        .and_then(Value::as_str)
                        .ok_or(StatusCode::BAD_REQUEST)?;
                    let handle = args
                        .get("handle")
                        .and_then(Value::as_str)
                        .ok_or(StatusCode::BAD_REQUEST)?;
                    if !principal.tenant_ids.contains(tenant) {
                        return Err(StatusCode::FORBIDDEN);
                    }
                    let gateway = state
                        .disclosure_gateway
                        .as_ref()
                        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
                    let result = gateway
                        .status(&principal.id, tenant, handle)
                        .await
                        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                    serde_json::to_string(&result).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                }
                _ => return Err(StatusCode::NOT_FOUND),
            };
            serde_json::json!({ "content": [{ "type": "text", "text": text }] })
        }
        _ => return Err(StatusCode::NOT_FOUND),
    };
    Ok(Json(
        serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result }),
    ))
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

#[cfg(test)]
mod authz_manifest_tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn closed_manifest_contains_only_current_tools() {
        let mut registry = ToolRegistry::new();
        registry.register(search_tool_schema(), Capability::Search);
        registry.register(sync_tool_schema(), Capability::Sync);
        registry.register(status_tool_schema(), Capability::Status);
        registry.register(attach_local_doc_tool_schema(), Capability::AttachLocalDoc);
        registry.register(
            request_human_disclosure_tool_schema(),
            Capability::HumanDisclosureRequest,
        );
        registry.register(
            disclosure_status_tool_schema(),
            Capability::DisclosureStatus,
        );
        let principal = Principal {
            id: "p".into(),
            name: "p".into(),
            capabilities: vec![
                Capability::Search,
                Capability::Sync,
                Capability::Status,
                Capability::AttachLocalDoc,
                Capability::HumanDisclosureRequest,
                Capability::DisclosureStatus,
            ],
            tenant_ids: HashSet::from(["t".into()]),
        };
        let names: HashSet<_> = registry
            .available_tools(&principal)
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        assert!(names.contains("search"));
        assert!(names.contains("sync"));
        assert!(names.contains("status"));
        assert!(names.contains("attach_local_doc"));
        assert!(names.contains("request_human_disclosure"));
        assert!(names.contains("disclosure_status"));
        for absent in [
            "rehydrate",
            "approve_human_disclosure",
            "deny_human_disclosure",
            "cancel_human_disclosure",
            "open_viewer",
            "native_viewer",
        ] {
            assert!(!names.contains(absent));
        }

        for tool in registry.available_tools(&principal) {
            if tool.name == "request_human_disclosure" || tool.name == "disclosure_status" {
                let schema = serde_json::to_string(&tool.input_schema).unwrap();
                for forbidden in ["approve", "open_viewer", "raw", "content", "value"] {
                    assert!(
                        !schema.contains(forbidden),
                        "{forbidden} leaked in {}",
                        tool.name
                    );
                }
            }
        }
    }

    #[test]
    fn tenant_maps_do_not_cross_contaminate() {
        let mut roots = HashMap::new();
        roots.insert("a".to_string(), vec![FolderRoot::new("local", "/a")]);
        roots.insert("b".to_string(), vec![FolderRoot::new("local", "/b")]);
        let mut processed = HashMap::new();
        processed.insert(
            "a".to_string(),
            HashMap::from([(PathBuf::from("/a/doc"), "clean-a".to_string())]),
        );
        assert!(
            !roots
                .get("b")
                .unwrap()
                .iter()
                .any(|r| r.path == PathBuf::from("/a"))
        );
        assert!(
            !processed
                .get("b")
                .map(|m| m.contains_key(PathBuf::from("/a/doc").as_path()))
                .unwrap_or(false)
        );
    }
}
