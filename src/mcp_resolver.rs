//! Default principal resolver implementation for testing/standalone use.

use crate::mcp_types::{Principal, PrincipalResolver, ResolutionContext, ResolverError};
use std::collections::HashMap;

/// Simple resolver that uses a static map of tokens to principals.
///
/// This is suitable for development and single-owner deployments.
/// Production deployments should implement their own resolver.
#[derive(Debug, Clone)]
pub struct DefaultResolver {
    principals: HashMap<String, Principal>,
    default_principal: Option<Principal>,
}

impl DefaultResolver {
    pub fn new() -> Self {
        let mut principals = HashMap::new();

        // Owner principal - full capabilities
        principals.insert(
            "owner".to_string(),
            Principal {
                id: "owner".to_string(),
                name: "Owner".to_string(),
                capabilities: vec![
                    crate::mcp_types::Capability::Search,
                    crate::mcp_types::Capability::Rehydrate,
                    crate::mcp_types::Capability::Sync,
                    crate::mcp_types::Capability::Status,
                ],
            },
        );

        // Agent principal - limited capabilities
        principals.insert(
            "agent".to_string(),
            Principal {
                id: "agent".to_string(),
                name: "Agent".to_string(),
                capabilities: vec![crate::mcp_types::Capability::Search],
            },
        );

        Self {
            principals,
            default_principal: Some(Principal {
                id: "owner".to_string(),
                name: "Owner".to_string(),
                capabilities: vec![
                    crate::mcp_types::Capability::Search,
                    crate::mcp_types::Capability::Rehydrate,
                    crate::mcp_types::Capability::Sync,
                    crate::mcp_types::Capability::Status,
                ],
            }),
        }
    }

    /// Add a principal with a bearer token.
    pub fn with_token(mut self, token: String, principal: crate::mcp_types::Principal) -> Self {
        self.principals.insert(token, principal);
        self
    }

    /// Set the default principal for stdio transport.
    pub fn with_default(mut self, principal: crate::mcp_types::Principal) -> Self {
        self.default_principal = Some(principal);
        self
    }
}

impl PrincipalResolver for DefaultResolver {
    fn resolve(
        &self,
        ctx: ResolutionContext,
    ) -> impl Future<Output = Result<crate::mcp_types::Principal, crate::mcp_types::ResolverError>> + Send
    {
        let principals = self.principals.clone();
        let default = self.default_principal.clone();

        async move {
            // For stdio, return default principal
            if ctx.transport == "stdio" {
                return default.ok_or(ResolverError::AuthRequired);
            }

            // For HTTP, check auth header
            if let Some(auth) = ctx.auth_header
                && let Some(token) = auth.strip_prefix("Bearer ")
                && let Some(principal) = principals.get(token)
            {
                return Ok(principal.clone());
            }

            Err(ResolverError::AuthRequired)
        }
    }

    fn default_principal(&self) -> Option<Principal> {
        self.default_principal.clone()
    }
}

impl Default for DefaultResolver {
    fn default() -> Self {
        Self::new()
    }
}
