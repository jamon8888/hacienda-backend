//! Focused negative tests for the production owner-disclosure boundary.

use async_trait::async_trait;
use hacienda_backend::disclosure::{
    AuditError, DisclosureAuditEntry, DisclosureAuditSink, DisclosureChallenge, DisclosureScope,
    HumanDisclosure, OwnerAuthError, OwnerIdentity, OwnerPresence, RequesterRef, SecureViewerSink,
    VaultBinding, VaultCustody, VaultStore, VaultStoreError, ViewerContent, ViewerError,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use zeroize::Zeroizing;

const TOKEN: &str = "[EMAIL_1]";
const TENANT: &str = "tenant-a";
const RAW: &str = "<script>alert('owner@example.test')</script>";

#[derive(Clone)]
struct Presence {
    identity: OwnerIdentity,
}
#[async_trait]
impl OwnerPresence for Presence {
    async fn verify(
        &self,
        challenge: &DisclosureChallenge,
    ) -> Result<OwnerIdentity, OwnerAuthError> {
        if challenge.tenant != TENANT {
            return Err(OwnerAuthError::Invalid);
        }
        Ok(self.identity.clone())
    }
}

struct Custody;
#[async_trait]
impl VaultCustody for Custody {
    async fn unlock(
        &self,
    ) -> Result<Zeroizing<String>, hacienda_backend::disclosure::CustodyError> {
        Ok(Zeroizing::new("fixture-key".into()))
    }
}

struct Vault {
    blob: Vec<u8>,
    binding: VaultBinding,
}
#[async_trait]
impl VaultStore for Vault {
    async fn load(&self, _: &VaultBinding) -> Result<(Vec<u8>, VaultBinding), VaultStoreError> {
        Ok((self.blob.clone(), self.binding.clone()))
    }
}

#[derive(Default, Clone)]
struct Audit(Arc<Mutex<Vec<DisclosureAuditEntry>>>);
#[async_trait]
impl DisclosureAuditSink for Audit {
    async fn record(&self, entry: DisclosureAuditEntry) -> Result<(), AuditError> {
        self.0.lock().unwrap().push(entry);
        Ok(())
    }
}

#[derive(Default, Clone)]
struct Viewer(Arc<Mutex<Vec<String>>>);
#[async_trait]
impl SecureViewerSink for Viewer {
    async fn deliver(
        &self,
        _: &hacienda_backend::disclosure::ViewerSessionMeta,
        content: ViewerContent,
    ) -> Result<(), ViewerError> {
        self.0.lock().unwrap().push(content.expose().to_owned());
        Ok(())
    }
}

fn binding() -> VaultBinding {
    VaultBinding {
        engine_era_fingerprint: "era".into(),
        document_fingerprint: "doc".into(),
    }
}
fn requester() -> RequesterRef {
    RequesterRef {
        principal_id: "agent".into(),
        tenant_id: TENANT.into(),
    }
}
fn engine(identity: OwnerIdentity, raw: &str) -> (Arc<HumanDisclosure>, Viewer, Audit) {
    let mut map = HashMap::new();
    map.insert(TOKEN.to_owned(), raw.to_owned());
    let blob = xberg::text::redaction::rehydration::encrypt_map(&map, "fixture-key").unwrap();
    let viewer = Viewer::default();
    let audit = Audit::default();
    let h = Arc::new(HumanDisclosure::new(
        Arc::new(Custody),
        Arc::new(Presence { identity }),
        Arc::new(viewer.clone()),
        Arc::new(Vault {
            blob,
            binding: binding(),
        }),
        Arc::new(audit.clone()),
        HashMap::from([(TENANT.into(), vec!["owner".into()])]),
        Duration::from_secs(60),
    ));
    (h, viewer, audit)
}

#[tokio::test]
async fn tenant_binding_rejects_owner_from_another_tenant() {
    let (h, _, _) = engine(
        OwnerIdentity {
            principal_id: "owner".into(),
            tenant_id: "tenant-b".into(),
            method: "test".into(),
        },
        RAW,
    );
    let req = h
        .request(
            DisclosureScope::Entity {
                token: TOKEN.into(),
            },
            requester(),
            binding(),
        )
        .await
        .unwrap();
    let c = h
        .prepare(&req.handle, hacienda_backend::DisclosureAction::Approve)
        .await
        .unwrap();
    assert!(matches!(
        h.approve(&req.handle, c).await,
        Err(hacienda_backend::disclosure::DisclosureError::UnauthorizedOwner)
    ));
}

#[tokio::test]
async fn owner_challenge_replay_is_rejected() {
    let (h, _, _) = engine(
        OwnerIdentity {
            principal_id: "owner".into(),
            tenant_id: TENANT.into(),
            method: "test".into(),
        },
        RAW,
    );
    let req = h
        .request(
            DisclosureScope::Entity {
                token: TOKEN.into(),
            },
            requester(),
            binding(),
        )
        .await
        .unwrap();
    let c = h
        .prepare(&req.handle, hacienda_backend::DisclosureAction::Approve)
        .await
        .unwrap();
    assert!(h.approve(&req.handle, c.clone()).await.is_ok());
    assert!(matches!(
        h.approve(&req.handle, c).await,
        Err(hacienda_backend::disclosure::DisclosureError::ChallengeRequired)
    ));
}

#[tokio::test]
async fn approval_and_viewer_challenges_cannot_be_confused() {
    let (h, _, _) = engine(
        OwnerIdentity {
            principal_id: "owner".into(),
            tenant_id: TENANT.into(),
            method: "test".into(),
        },
        RAW,
    );
    let req = h
        .request(
            DisclosureScope::Entity {
                token: TOKEN.into(),
            },
            requester(),
            binding(),
        )
        .await
        .unwrap();
    let approval = h
        .prepare(&req.handle, hacienda_backend::DisclosureAction::Approve)
        .await
        .unwrap();
    let viewer = h
        .prepare(&req.handle, hacienda_backend::DisclosureAction::OpenViewer)
        .await
        .unwrap();
    assert!(matches!(
        h.approve(&req.handle, approval).await,
        Err(hacienda_backend::disclosure::DisclosureError::OwnerAuthFailed)
    ));
    assert!(matches!(
        h.open_viewer(&req.handle, viewer).await,
        Err(hacienda_backend::disclosure::DisclosureError::Terminal(
            "not-approved"
        ))
    ));
}

#[tokio::test]
async fn markup_scope_is_rejected_and_raw_markup_stays_out_of_evidence() {
    let (h, viewer, audit) = engine(
        OwnerIdentity {
            principal_id: "owner".into(),
            tenant_id: TENANT.into(),
            method: "test".into(),
        },
        RAW,
    );
    assert!(matches!(
        h.request(
            DisclosureScope::Entity {
                token: "<script>".into()
            },
            requester(),
            binding()
        )
        .await,
        Err(hacienda_backend::disclosure::DisclosureError::UnsupportedScope)
    ));
    let req = h
        .request(
            DisclosureScope::Entity {
                token: TOKEN.into(),
            },
            requester(),
            binding(),
        )
        .await
        .unwrap();
    let c = h
        .prepare(&req.handle, hacienda_backend::DisclosureAction::Approve)
        .await
        .unwrap();
    h.approve(&req.handle, c).await.unwrap();
    let c = h
        .prepare(&req.handle, hacienda_backend::DisclosureAction::OpenViewer)
        .await
        .unwrap();
    h.open_viewer(&req.handle, c).await.unwrap();
    assert_eq!(viewer.0.lock().unwrap().as_slice(), &[RAW.to_owned()]);
    let encoded = serde_json::to_string(&*audit.0.lock().unwrap()).unwrap();
    assert!(!encoded.contains(RAW));
    assert!(!encoded.contains(TOKEN));
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
#[tokio::test]
async fn unsupported_platform_fails_closed_for_presence() {
    let p = hacienda_backend::PlatformOwnerPresence::new("owner".into(), TENANT.into());
    let c = DisclosureChallenge {
        handle: "h".into(),
        scope: TOKEN.into(),
        principal: "agent".into(),
        tenant: TENANT.into(),
        action: hacienda_backend::DisclosureAction::Approve,
        nonce: "n".into(),
        expires_at: (chrono::Utc::now() + chrono::Duration::minutes(1)).to_rfc3339(),
    };
    assert!(matches!(
        p.verify(&c).await,
        Err(OwnerAuthError::Unavailable)
    ));
}
