//! Default principal resolver implementation for testing/standalone use.

use crate::{
    config::HaciendaConfig,
    mcp_types::{Capability, Principal, PrincipalResolver, ResolutionContext, ResolverError},
};
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
    /// Construct only from explicit configuration; no implicit owner/default exists.
    pub fn from_config(config: &HaciendaConfig, principal_id: &str) -> Result<Self, ResolverError> {
        let binding = config
            .principal(principal_id)
            .ok_or(ResolverError::AuthRequired)?;
        let capabilities = match binding.role {
            crate::authz::PrincipalRole::Owner => vec![
                Capability::Search,
                Capability::Sync,
                Capability::Status,
                Capability::AttachLocalDoc,
            ],
            crate::authz::PrincipalRole::Agent => {
                vec![Capability::Search, Capability::AttachLocalDoc]
            }
            crate::authz::PrincipalRole::Service => vec![
                Capability::Search,
                Capability::Sync,
                Capability::Status,
                Capability::AttachLocalDoc,
            ],
        };
        let principal = Principal {
            id: binding.principal_id.clone(),
            name: binding.principal_id.clone(),
            capabilities,
            tenant_ids: binding.tenant_ids.clone(),
        };
        Ok(Self {
            principals: HashMap::new(),
            default_principal: Some(principal),
        })
    }

    pub fn new() -> Self {
        Self {
            principals: HashMap::new(),
            default_principal: None,
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
}

impl Default for DefaultResolver {
    fn default() -> Self {
        Self::new()
    }
}
