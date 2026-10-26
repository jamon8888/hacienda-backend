//! MCP server implementation.
//!
//! Provides stdio and HTTP transports with tool registry and principal resolution.

use axum::{
    Router,
    extract::State,
    response::Json,
    routing::{get, post},
};
use rmcp::{
    ServerHandler, ServiceExt,
    model::{CallToolRequestParam, CallToolResult, ListToolsResult, Tool},
};
use serde_json::Value;
use std::sync::Arc;
use tokio::io;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::{
    EngineEraFingerprint,
    mcp_types::{Capability, Principal, PrincipalResolver},
};
use rmcp::model::{Annotated, RawContent};

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
        Self {
            resolver: Arc::new(resolver),
            state: ServerState {
                registry: Arc::new(RwLock::new(ToolRegistry::new())),
                fingerprint: None,
            },
        }
    }

    /// Register a tool with the server.
    pub async fn register_tool(&self, tool: Tool, capability: Capability) {
        self.state.registry.write().await.register(tool, capability);
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

        // Build the HTTP router
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
        _request: Option<rmcp::model::PaginatedRequestParam>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<ListToolsResult, rmcp::Error> {
        // For stdio, use default principal if available
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
        Ok(ListToolsResult {
            tools,
            next_cursor: None,
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParam,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<CallToolResult, rmcp::Error> {
        // In a real implementation, resolve principal from request context
        // For now, use default principal
        let _principal = self
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

        // Dispatch to tool handlers (implemented in follow-up tickets)
        match request.name.as_ref() {
            "search" => Ok(CallToolResult::success(vec![Annotated::new(
                RawContent::text("search tool not yet implemented"),
                None,
            )])),
            "rehydrate" => Ok(CallToolResult::success(vec![Annotated::new(
                RawContent::text("rehydrate tool not yet implemented"),
                None,
            )])),
            "sync" => Ok(CallToolResult::success(vec![Annotated::new(
                RawContent::text("sync tool not yet implemented"),
                None,
            )])),
            "status" => Ok(CallToolResult::success(vec![Annotated::new(
                RawContent::text("status tool not yet implemented"),
                None,
            )])),
            _ => Err(rmcp::Error::method_not_found::<
                rmcp::model::CallToolRequestMethod,
            >()),
        }
    }
}

/// HTTP handlers
async fn mcp_handler<R>(
    State((_state, _resolver)): State<(ServerState, Arc<R>)>,
    axum::extract::Json(_request): axum::extract::Json<Value>,
) -> Result<Json<Value>, axum::http::StatusCode>
where
    R: PrincipalResolver + Send + Sync + 'static,
{
    // In a real implementation, parse MCP request, resolve principal from auth header,
    // dispatch to handler, return MCP response
    warn!("MCP HTTP handler not fully implemented");
    Err(axum::http::StatusCode::NOT_IMPLEMENTED)
}

async fn sse_handler<R>(
    State((_state, _resolver)): State<(ServerState, Arc<R>)>,
) -> Result<axum::response::Response, axum::http::StatusCode>
where
    R: PrincipalResolver + Send + Sync + 'static,
{
    warn!("SSE handler not implemented");
    Err(axum::http::StatusCode::NOT_IMPLEMENTED)
}

async fn healthz() -> Json<Value> {
    Json(serde_json::json!({ "status": "ok" }))
}
