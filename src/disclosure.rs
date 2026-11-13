//! Human-only disclosure state machine.
//!
//! This module deliberately has no HTTP handler and no MCP response carrying a
//! value.  The only raw-value sink is [`NativeViewerSink`], which writes to a
//! private stdin pipe belonging to a separately spawned native viewer process.
//! Owner proofs are fresh, challenge-bound OS user-presence assertions; a
//! bearer token, caller supplied owner name, or shared secret is never a proof.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::Serialize;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use uuid::Uuid;
use xberg::text::redaction::rehydration::decrypt_map;
use zeroize::{Zeroize, Zeroizing};

pub const REDACTED: &str = "[REDACTED:disclosure-value]";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequesterRef {
    pub principal_id: String,
    pub tenant_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum DisclosureScope {
    Entity { token: String },
    Document { doc_id: String },
}

impl DisclosureScope {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Entity { .. } => "entity",
            Self::Document { .. } => "document",
        }
    }
    pub fn reference(&self) -> &str {
        match self {
            Self::Entity { token } => token,
            Self::Document { doc_id } => doc_id,
        }
    }
    pub fn fingerprint(&self) -> String {
        let mut h = blake3::Hasher::new();
        h.update(self.kind().as_bytes());
        h.update(b"\0");
        h.update(self.reference().as_bytes());
        h.finalize().to_hex().to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VaultBinding {
    pub engine_era_fingerprint: String,
    pub document_fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureStatus {
    Pending,
    Approved,
    Denied,
    Cancelled,
    Expired,
    Failed,
    Disclosed,
}

impl DisclosureStatus {
    fn terminal(self) -> bool {
        !matches!(self, Self::Pending | Self::Approved)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestResult {
    pub handle: String,
    pub status: DisclosureStatus,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusView {
    pub handle: String,
    pub status: DisclosureStatus,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PendingSummary {
    pub handle: String,
    pub scope_kind: String,
    pub scope_ref: String,
    pub principal_id: String,
    pub tenant_id: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ViewerSessionMeta {
    pub session_id: String,
    pub handle: String,
    pub scope_kind: String,
    pub tenant_id: String,
    pub expires_at: String,
}

/// The action is included in every user-presence challenge to prevent an
/// approval assertion from being replayed as a viewer-open assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureAction {
    Approve,
    Deny,
    Cancel,
    OpenViewer,
}

/// Fresh binding presented to macOS Keychain/LocalAuthentication.  `scope` is
/// the pseudonym reference, never the restored value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DisclosureChallenge {
    pub handle: String,
    pub scope: String,
    pub principal: String,
    pub tenant: String,
    pub action: DisclosureAction,
    pub nonce: String,
    pub expires_at: String,
}

impl DisclosureChallenge {
    fn fresh(
        handle: &str,
        scope: &DisclosureScope,
        requester: &RequesterRef,
        action: DisclosureAction,
        expires_at: DateTime<Utc>,
    ) -> Self {
        let mut nonce = [0u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        Self {
            handle: handle.to_owned(),
            // Token references are reversible identifiers; bind to a digest
            // in challenges and metadata so they never enter IPC/audit.
            scope: hash_reference(scope.reference()),
            principal: requester.principal_id.clone(),
            tenant: requester.tenant_id.clone(),
            action,
            nonce: hex(&nonce),
            expires_at: expires_at.to_rfc3339(),
        }
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("challenge is serializable")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnerIdentity {
    pub principal_id: String,
    pub tenant_id: String,
    pub method: String,
}

/// Raw content cannot be formatted or serialized.  It is consumed by the
/// viewer sink and zeroized when dropped.
pub struct ViewerContent(Zeroizing<String>);
impl ViewerContent {
    fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for ViewerContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}
impl Drop for ViewerContent {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureEvent {
    Requested,
    ApprovalGranted,
    ApprovalRejected,
    Denied,
    Cancelled,
    Expired,
    ReplayBlocked,
    Delivered,
    Failed,
}

/// The allowlist for durable evidence.  There is no argument/value field.
#[derive(Debug, Clone, Serialize)]
pub struct DisclosureAuditEntry {
    pub timestamp: String,
    pub event: DisclosureEvent,
    pub request_id: String,
    pub handle_hash: String,
    pub scope_kind: String,
    pub scope_ref: String,
    pub principal_id: String,
    pub tenant_id: String,
    pub outcome: &'static str,
    pub reason: Option<&'static str>,
}

#[derive(Debug, thiserror::Error)]
pub enum CustodyError {
    #[error("key custody unavailable")]
    Unavailable,
    #[error("key custody unauthorized")]
    Unauthorized,
}
#[derive(Debug, thiserror::Error)]
pub enum OwnerAuthError {
    #[error("owner presence rejected")]
    Invalid,
    #[error("owner presence expired")]
    Expired,
    #[error("owner presence unavailable")]
    Unavailable,
}
#[derive(Debug, thiserror::Error)]
pub enum ViewerError {
    #[error("native viewer unavailable")]
    Unavailable,
    #[error("native viewer delivery failed")]
    DeliveryFailed,
}
#[derive(Debug, thiserror::Error)]
pub enum VaultStoreError {
    #[error("vault unavailable")]
    Unavailable,
    #[error("vault not found")]
    NotFound,
}
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("evidence ledger unavailable")]
    Unavailable,
    #[error("evidence row rejected")]
    Rejected,
}

#[async_trait]
pub trait VaultCustody: Send + Sync {
    async fn unlock(&self) -> Result<Zeroizing<String>, CustodyError>;
}
#[async_trait]
pub trait OwnerPresence: Send + Sync {
    async fn verify(
        &self,
        challenge: &DisclosureChallenge,
    ) -> Result<OwnerIdentity, OwnerAuthError>;
}
#[async_trait]
pub trait SecureViewerSink: Send + Sync {
    async fn deliver(
        &self,
        meta: &ViewerSessionMeta,
        content: ViewerContent,
    ) -> Result<(), ViewerError>;
}
#[async_trait]
pub trait VaultStore: Send + Sync {
    async fn load(
        &self,
        binding: &VaultBinding,
    ) -> Result<(Vec<u8>, VaultBinding), VaultStoreError>;
}
#[async_trait]
pub trait DisclosureAuditSink: Send + Sync {
    async fn record(&self, entry: DisclosureAuditEntry) -> Result<(), AuditError>;
}

#[derive(Debug, thiserror::Error)]
pub enum DisclosureError {
    #[error("unknown or unusable disclosure handle")]
    UnknownHandle,
    #[error("disclosure request expired")]
    Expired,
    #[error("disclosure request is terminal: {0}")]
    Terminal(&'static str),
    #[error("owner presence challenge required")]
    ChallengeRequired,
    #[error("owner authorization failed")]
    OwnerAuthFailed,
    #[error("owner is not authorized for this tenant")]
    UnauthorizedOwner,
    #[error("vault restore failed: {0}")]
    Restore(&'static str),
    #[error("audit failed")]
    AuditFailed,
    #[error("unsupported scope")]
    UnsupportedScope,
}

struct RequestRecord {
    id: String,
    handle: String,
    handle_hash: String,
    scope: DisclosureScope,
    requester: RequesterRef,
    binding: VaultBinding,
    expires_at: DateTime<Utc>,
    status: DisclosureStatus,
    approved_owner: Option<OwnerIdentity>,
    challenge: Option<DisclosureChallenge>,
    challenge_used: bool,
}

pub struct HumanDisclosure {
    custody: Arc<dyn VaultCustody>,
    presence: Arc<dyn OwnerPresence>,
    viewer: Arc<dyn SecureViewerSink>,
    vault: Arc<dyn VaultStore>,
    audit: Arc<dyn DisclosureAuditSink>,
    owners: HashMap<String, Vec<String>>,
    ttl: Duration,
    requests: Mutex<HashMap<String, RequestRecord>>,
}

impl HumanDisclosure {
    pub fn new(
        custody: Arc<dyn VaultCustody>,
        presence: Arc<dyn OwnerPresence>,
        viewer: Arc<dyn SecureViewerSink>,
        vault: Arc<dyn VaultStore>,
        audit: Arc<dyn DisclosureAuditSink>,
        owners: HashMap<String, Vec<String>>,
        ttl: Duration,
    ) -> Self {
        Self {
            custody,
            presence,
            viewer,
            vault,
            audit,
            owners,
            ttl,
            requests: Mutex::new(HashMap::new()),
        }
    }

    pub async fn request(
        &self,
        scope: DisclosureScope,
        requester: RequesterRef,
        binding: VaultBinding,
    ) -> Result<RequestResult, DisclosureError> {
        let DisclosureScope::Entity { token } = &scope else {
            return Err(DisclosureError::UnsupportedScope);
        };
        if !valid_token(token) {
            return Err(DisclosureError::UnsupportedScope);
        }
        let now = Utc::now();
        let expires =
            now + chrono::Duration::from_std(self.ttl).unwrap_or(chrono::Duration::minutes(5));
        let handle = hex(&random_bytes());
        let id = Uuid::new_v4().to_string();
        let record = RequestRecord {
            id: id.clone(),
            handle: handle.clone(),
            handle_hash: hash(&handle),
            scope,
            requester: requester.clone(),
            binding,
            expires_at: expires,
            status: DisclosureStatus::Pending,
            approved_owner: None,
            challenge: None,
            challenge_used: false,
        };
        self.audit
            .record(self.row(&record, DisclosureEvent::Requested, "accepted", None))
            .await
            .map_err(|_| DisclosureError::AuditFailed)?;
        self.requests.lock().await.insert(handle.clone(), record);
        Ok(RequestResult {
            handle,
            status: DisclosureStatus::Pending,
            expires_at: expires.to_rfc3339(),
        })
    }

    pub async fn status(&self, handle: &str) -> Result<StatusView, DisclosureError> {
        let mut g = self.requests.lock().await;
        let r = g.get_mut(handle).ok_or(DisclosureError::UnknownHandle)?;
        self.expire(r).await?;
        Ok(StatusView {
            handle: r.handle.clone(),
            status: r.status,
            expires_at: r.expires_at.to_rfc3339(),
        })
    }

    pub async fn status_for(
        &self,
        handle: &str,
        principal_id: &str,
        tenant_id: &str,
    ) -> Result<StatusView, DisclosureError> {
        let mut g = self.requests.lock().await;
        let r = g.get_mut(handle).ok_or(DisclosureError::UnknownHandle)?;
        if r.requester.principal_id != principal_id || r.requester.tenant_id != tenant_id {
            return Err(DisclosureError::UnknownHandle);
        }
        self.expire(r).await?;
        Ok(StatusView {
            handle: r.handle.clone(),
            status: r.status,
            expires_at: r.expires_at.to_rfc3339(),
        })
    }

    pub async fn pending_for_owner(&self) -> Vec<PendingSummary> {
        let g = self.requests.lock().await;
        g.values()
            .filter(|r| !r.status.terminal())
            .map(|r| PendingSummary {
                handle: r.handle.clone(),
                scope_kind: r.scope.kind().into(),
                scope_ref: hash_reference(r.scope.reference()),
                principal_id: r.requester.principal_id.clone(),
                tenant_id: r.requester.tenant_id.clone(),
                expires_at: r.expires_at.to_rfc3339(),
            })
            .collect()
    }

    pub async fn prepare(
        &self,
        handle: &str,
        action: DisclosureAction,
    ) -> Result<DisclosureChallenge, DisclosureError> {
        let mut g = self.requests.lock().await;
        let r = g.get_mut(handle).ok_or(DisclosureError::UnknownHandle)?;
        self.expire(r).await?;
        if r.status.terminal() {
            return Err(DisclosureError::Terminal("terminal"));
        }
        let c = DisclosureChallenge::fresh(handle, &r.scope, &r.requester, action, r.expires_at);
        r.challenge = Some(c.clone());
        r.challenge_used = false;
        Ok(c)
    }

    pub async fn approve(
        &self,
        handle: &str,
        challenge: DisclosureChallenge,
    ) -> Result<DisclosureStatus, DisclosureError> {
        let mut g = self.requests.lock().await;
        let r = g.get_mut(handle).ok_or(DisclosureError::UnknownHandle)?;
        self.expire(r).await?;
        self.verify(r, challenge, DisclosureAction::Approve).await?;
        r.status = DisclosureStatus::Approved;
        if self
            .audit
            .record(self.row(r, DisclosureEvent::ApprovalGranted, "accepted", None))
            .await
            .is_err()
        {
            r.status = DisclosureStatus::Failed;
            return Err(DisclosureError::AuditFailed);
        }
        Ok(r.status)
    }

    pub async fn deny(
        &self,
        handle: &str,
        challenge: DisclosureChallenge,
    ) -> Result<DisclosureStatus, DisclosureError> {
        self.transition(
            handle,
            challenge,
            DisclosureAction::Deny,
            DisclosureStatus::Denied,
            DisclosureEvent::Denied,
        )
        .await
    }
    pub async fn cancel(
        &self,
        handle: &str,
        challenge: DisclosureChallenge,
    ) -> Result<DisclosureStatus, DisclosureError> {
        self.transition(
            handle,
            challenge,
            DisclosureAction::Cancel,
            DisclosureStatus::Cancelled,
            DisclosureEvent::Cancelled,
        )
        .await
    }

    async fn transition(
        &self,
        handle: &str,
        challenge: DisclosureChallenge,
        action: DisclosureAction,
        target: DisclosureStatus,
        event: DisclosureEvent,
    ) -> Result<DisclosureStatus, DisclosureError> {
        let mut g = self.requests.lock().await;
        let r = g.get_mut(handle).ok_or(DisclosureError::UnknownHandle)?;
        self.expire(r).await?;
        self.verify(r, challenge, action).await?;
        r.status = target;
        self.audit
            .record(self.row(r, event, "accepted", None))
            .await
            .map_err(|_| DisclosureError::AuditFailed)?;
        Ok(target)
    }

    pub async fn open_viewer(
        &self,
        handle: &str,
        challenge: DisclosureChallenge,
    ) -> Result<ViewerSessionMeta, DisclosureError> {
        let mut g = self.requests.lock().await;
        let r = g.get_mut(handle).ok_or(DisclosureError::UnknownHandle)?;
        self.expire(r).await?;
        if r.status != DisclosureStatus::Approved {
            return Err(DisclosureError::Terminal("not-approved"));
        }
        let owner = self
            .verify(r, challenge, DisclosureAction::OpenViewer)
            .await?;
        if r.approved_owner.as_ref() != Some(&owner) {
            return Err(DisclosureError::UnauthorizedOwner);
        }
        if r.challenge_used {
            let _ = self
                .audit
                .record(self.row(
                    r,
                    DisclosureEvent::ReplayBlocked,
                    "rejected",
                    Some("replay"),
                ))
                .await;
            return Err(DisclosureError::Terminal("replay"));
        }
        r.challenge_used = true;
        let key = self
            .custody
            .unlock()
            .await
            .map_err(|_| DisclosureError::Restore("custody"))?;
        let (blob, binding) = self
            .vault
            .load(&r.binding)
            .await
            .map_err(|_| DisclosureError::Restore("vault"))?;
        if binding != r.binding {
            r.status = DisclosureStatus::Failed;
            return Err(DisclosureError::Restore("binding"));
        }
        let map =
            decrypt_map(&blob, key.as_str()).map_err(|_| DisclosureError::Restore("decrypt"))?;
        let value = map
            .get(r.scope.reference())
            .ok_or(DisclosureError::Restore("missing"))?
            .to_string();
        let meta = ViewerSessionMeta {
            session_id: hex(&random_bytes()),
            handle: r.handle.clone(),
            scope_kind: r.scope.kind().into(),
            tenant_id: r.requester.tenant_id.clone(),
            expires_at: (Utc::now() + chrono::Duration::minutes(1)).to_rfc3339(),
        };
        self.viewer
            .deliver(&meta, ViewerContent::new(value))
            .await
            .map_err(|_| DisclosureError::Restore("viewer"))?;
        r.status = DisclosureStatus::Disclosed;
        self.audit
            .record(self.row(r, DisclosureEvent::Delivered, "accepted", None))
            .await
            .map_err(|_| DisclosureError::AuditFailed)?;
        Ok(meta)
    }

    async fn verify(
        &self,
        r: &mut RequestRecord,
        challenge: DisclosureChallenge,
        action: DisclosureAction,
    ) -> Result<OwnerIdentity, DisclosureError> {
        let Some(expected) = r.challenge.take() else {
            return Err(DisclosureError::ChallengeRequired);
        };
        if expected.action != action || expected != challenge || r.challenge_used {
            return Err(DisclosureError::OwnerAuthFailed);
        }
        let identity = self
            .presence
            .verify(&expected)
            .await
            .map_err(|_| DisclosureError::OwnerAuthFailed)?;
        if identity.tenant_id != r.requester.tenant_id
            || !self
                .owners
                .get(&r.requester.tenant_id)
                .is_some_and(|v| v.contains(&identity.principal_id))
        {
            return Err(DisclosureError::UnauthorizedOwner);
        }
        if action == DisclosureAction::Approve {
            r.approved_owner = Some(identity.clone());
        }
        Ok(identity)
    }

    async fn expire(&self, r: &mut RequestRecord) -> Result<(), DisclosureError> {
        if !r.status.terminal() && Utc::now() >= r.expires_at {
            r.status = DisclosureStatus::Expired;
            self.audit
                .record(self.row(r, DisclosureEvent::Expired, "rejected", Some("expired")))
                .await
                .map_err(|_| DisclosureError::AuditFailed)?;
            return Err(DisclosureError::Expired);
        }
        Ok(())
    }
    fn row(
        &self,
        r: &RequestRecord,
        event: DisclosureEvent,
        outcome: &'static str,
        reason: Option<&'static str>,
    ) -> DisclosureAuditEntry {
        DisclosureAuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            event,
            request_id: r.id.clone(),
            handle_hash: r.handle_hash.clone(),
            scope_kind: r.scope.kind().into(),
            scope_ref: hash_reference(r.scope.reference()),
            principal_id: r.requester.principal_id.clone(),
            tenant_id: r.requester.tenant_id.clone(),
            outcome,
            reason,
        }
    }
}

fn valid_token(token: &str) -> bool {
    token.len() <= 256
        && token.starts_with('[')
        && token.ends_with(']')
        && !token.contains('<')
        && !token.contains('>')
        && !token.contains('\n')
        && !token.contains('\r')
}
fn random_bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    b
}
fn hash(s: &str) -> String {
    blake3::hash(s.as_bytes()).to_hex().to_string()
}
fn hash_reference(s: &str) -> String {
    format!("blake3:{}", hash(s))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
