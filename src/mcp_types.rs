//! MCP server types and traits.
//!
//! Defines the sealed `PrincipalResolver` trait that adopters implement
//! to provide per-agent authentication/authorization.

use serde::{Deserialize, Serialize};
use std::future::Future;

/// Principal identity resolved from an MCP connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Principal {
    /// Unique identifier for the principal (e.g., "owner", "claude-code", "codex").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Capabilities granted to this principal.
    pub capabilities: Vec<Capability>,
}

/// Capabilities that can be granted to a principal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Can call search tool (returns tokenized snippets only).
    Search,
    /// Can call rehydrate tool (owner-only, per-export review).
    Rehydrate,
    /// Can call sync tool (trigger incremental/full rebuild).
    Sync,
    /// Can call status tool (index stats, fingerprint, etc.).
    Status,
}

/// Resolves an MCP connection to a Principal.
///
/// This trait is **sealed** — only this crate can implement it.
/// Adopters provide an implementation at binary link time.
pub trait PrincipalResolver: Send + Sync + 'static {
    /// Resolve the principal from the incoming connection context.
    ///
    /// For stdio transport, this is called once at startup.
    /// For HTTP transport, this is called per-request (with auth headers).
    fn resolve(
        &self,
        ctx: ResolutionContext,
    ) -> impl Future<Output = Result<Principal, ResolverError>> + Send;

    /// Optional: provide a default principal for stdio transport.
    fn default_principal(&self) -> Option<Principal> {
        None
    }
}

/// Context provided to the resolver during resolution.
#[derive(Debug, Clone)]
pub struct ResolutionContext {
    /// Transport type: "stdio" or "http".
    pub transport: String,
    /// For HTTP: authorization header value (if present).
    pub auth_header: Option<String>,
    /// For HTTP: remote peer address.
    pub peer_addr: Option<String>,
}

/// Errors from principal resolution.
#[derive(Debug, thiserror::Error)]
pub enum ResolverError {
    #[error("authentication required")]
    AuthRequired,
    #[error("invalid credentials: {0}")]
    InvalidCredentials(String),
    #[error("principal not found: {0}")]
    NotFound(String),
    #[error("resolver error: {0}")]
    Other(String),
}
