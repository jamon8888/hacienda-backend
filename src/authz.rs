//! Fail-closed principal/tenant and ingestion-root authorization primitives.
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrincipalRole {
    Owner,
    Agent,
    Service,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PrincipalBinding {
    pub principal_id: String,
    pub role: PrincipalRole,
    #[serde(default)]
    pub tenant_ids: HashSet<String>,
}

impl PrincipalBinding {
    pub fn authorizes(&self, tenant_id: &str) -> bool {
        !tenant_id.is_empty() && self.tenant_ids.contains(tenant_id)
    }
    pub fn fingerprint(&self) -> String {
        let digest = blake3::hash(self.principal_id.as_bytes());
        format!("blake3:{}", digest.to_hex())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FolderRoot {
    /// local, smb, or nfs. Roots are ingestion inputs, never agent read grants.
    pub scheme: String,
    pub path: PathBuf,
}

impl FolderRoot {
    pub fn new(scheme: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            scheme: scheme.into(),
            path: path.into(),
        }
    }
    pub fn canonical_for_auth(&self) -> Result<PathBuf, AuthzError> {
        if !matches!(self.scheme.as_str(), "local" | "smb" | "nfs") {
            return Err(AuthzError::UnsupportedScheme);
        }
        std::fs::canonicalize(&self.path).map_err(|_| AuthzError::RootUnavailable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanDocumentRef {
    pub token: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthzError {
    #[error("tenant unauthorized")]
    UnauthorizedTenant,
    #[error("unsupported root scheme")]
    UnsupportedScheme,
    #[error("allowlisted root unavailable")]
    RootUnavailable,
    #[error("path is outside an allowlisted root")]
    OutsideRoot,
    #[error("document is not processed")]
    Unprocessed,
    #[error("document reference is invalid")]
    InvalidReference,
}

/// Validate an already-processed document and return only an opaque clean ref.
/// Canonicalization is performed on both root and candidate, preventing `..` and
/// symlink escapes. `processed` maps canonical source paths to clean tokens.
pub fn attach_local_doc(
    reference: &Path,
    roots: &[FolderRoot],
    processed: &HashMap<PathBuf, String>,
) -> Result<CleanDocumentRef, AuthzError> {
    if reference.as_os_str().is_empty() || !reference.is_absolute() {
        return Err(AuthzError::InvalidReference);
    }
    let candidate = std::fs::canonicalize(reference).map_err(|_| AuthzError::InvalidReference)?;
    if !candidate.is_file() {
        return Err(AuthzError::InvalidReference);
    }
    if !roots
        .iter()
        .filter_map(|r| r.canonical_for_auth().ok())
        .any(|root| candidate.starts_with(root))
    {
        return Err(AuthzError::OutsideRoot);
    }
    let token = processed.get(&candidate).ok_or(AuthzError::Unprocessed)?;
    if token.is_empty() {
        return Err(AuthzError::Unprocessed);
    }
    Ok(CleanDocumentRef {
        token: token.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tenant_binding_is_fail_closed() {
        let p = PrincipalBinding {
            principal_id: "a".into(),
            role: PrincipalRole::Agent,
            tenant_ids: ["t1".into()].into_iter().collect(),
        };
        assert!(p.authorizes("t1"));
        assert!(!p.authorizes("t2"));
        assert!(!p.authorizes(""));
    }

    #[test]
    fn attach_requires_processed_file_under_root() {
        let root = std::env::temp_dir().join(format!("hacienda-authz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("clean.md");
        std::fs::write(&file, "tokenized").unwrap();
        let canonical = std::fs::canonicalize(&file).unwrap();
        let roots = vec![FolderRoot::new("local", &root)];
        let mut processed = HashMap::new();
        processed.insert(canonical, "clean-token".into());
        assert_eq!(
            attach_local_doc(&file, &roots, &processed).unwrap().token,
            "clean-token"
        );
        assert_eq!(
            attach_local_doc(&file, &roots, &HashMap::new()),
            Err(AuthzError::Unprocessed)
        );
        assert_eq!(
            attach_local_doc(&root.join("../outside"), &roots, &processed),
            Err(AuthzError::InvalidReference)
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
