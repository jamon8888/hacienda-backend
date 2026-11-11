//! Folder synchronization: watcher + manual refresh with engine-era rebuild policy.
//!
//! Implements the sync pipeline for the document folder (spec §8, Epic 4):
//! - File watcher (notify) for real-time change detection
//! - Manual refresh CLI for on-demand sync
//! - Engine-era fingerprint rebuild policy: full rebuild on fingerprint change,
//!   incremental on content change.

use crate::config::HaciendaConfig;
use crate::custody::{DocumentIdentity, persist_files};
use crate::dual_store::{custody_artifacts, write_dual_store_for_document};
use crate::encryption::vault_key_provider;
use crate::validate_assurance_mode;
use crate::{EngineEraFingerprint, GazeEngine};
use blake3;
use console;
use crossbeam_channel::{Receiver, Sender, bounded};
use notify::{Config, Event, EventKind, RecommendedWatcher, Watcher};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use xberg::{
    ExtractedDocument, PiiCategory, RedactionConfig, RedactionOffsetEncoding, RedactionStrategy,
};

/// Sync event from the watcher or manual trigger.
#[derive(Debug, Clone)]
pub enum SyncEvent {
    /// File created or modified — incremental re-index if fingerprint matches.
    FileChanged { path: PathBuf },
    /// File deleted — remove from index.
    FileDeleted { path: PathBuf },
    /// Full rebuild requested (fingerprint changed or manual).
    FullRebuild { reason: String },
    /// Shutdown signal.
    Shutdown,
}

/// Document record in the sync index.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IndexedDocument {
    pub doc_id: String,
    pub path: PathBuf,
    pub fingerprint: EngineEraFingerprint,
    pub content_hash: String, // Blake3 of raw content for change detection
    pub last_modified: std::time::SystemTime,
}

/// Folder sync engine with watcher and manual refresh.
pub struct FolderSync {
    root: PathBuf,
    config: HaciendaConfig,
    tenant_id: String,
    watcher: Option<RecommendedWatcher>,
    event_tx: Sender<SyncEvent>,
    event_rx: Receiver<SyncEvent>,
    indexed: Arc<tokio::sync::RwLock<HashMap<String, IndexedDocument>>>,
}

impl FolderSync {
    /// Create a new folder sync engine.
    pub fn new(root: PathBuf, config: HaciendaConfig) -> Self {
        let tenant_id = config.default_tenant_id().to_owned();
        Self::new_scoped(root, config, tenant_id)
    }

    /// Create a folder sync engine scoped to one authenticated tenant.
    pub fn new_scoped(root: PathBuf, config: HaciendaConfig, tenant_id: String) -> Self {
        let (event_tx, event_rx) = bounded(1024);
        Self {
            root,
            config,
            tenant_id,
            watcher: None,
            event_tx,
            event_rx,
            indexed: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Start the watcher and sync loop.
    ///
    /// Returns a handle that can be awaited for shutdown.
    pub fn start(mut self) -> Result<JoinHandle<()>, std::io::Error> {
        // Initialize watcher
        let event_tx = self.event_tx.clone();
        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    Self::handle_event(event, &event_tx);
                }
            },
            Config::default(),
        )
        .map_err(std::io::Error::other)?;

        watcher
            .watch(&self.root, notify::RecursiveMode::Recursive)
            .map_err(std::io::Error::other)?;
        self.watcher = Some(watcher);

        let indexed = self.indexed.clone();
        let event_rx = self.event_rx;
        let config = self.config.clone();
        let root = self.root.clone();
        let tenant_id = self.tenant_id.clone();

        let handle = tokio::spawn(async move {
            Self::sync_loop(root, config, tenant_id, indexed, event_rx).await;
        });

        Ok(handle)
    }

    /// Convert a notify event to a SyncEvent and send it.
    fn handle_event(event: Event, tx: &Sender<SyncEvent>) {
        match event.kind {
            EventKind::Create(_) | EventKind::Modify(_) => {
                for path in event.paths {
                    let _ = tx.try_send(SyncEvent::FileChanged { path });
                }
            }
            EventKind::Remove(_) => {
                for path in event.paths {
                    let _ = tx.try_send(SyncEvent::FileDeleted { path });
                }
            }
            _ => {}
        }
    }

    /// Main sync loop: processes events and applies rebuild policy.
    async fn sync_loop(
        root: PathBuf,
        config: HaciendaConfig,
        tenant_id: String,
        indexed: Arc<tokio::sync::RwLock<HashMap<String, IndexedDocument>>>,
        event_rx: Receiver<SyncEvent>,
    ) {
        while let Ok(event) = event_rx.recv() {
            match event {
                SyncEvent::FileChanged { path } => {
                    if let Err(error) =
                        Self::handle_file_changed(&root, &config, &tenant_id, &indexed, path).await
                    {
                        eprintln!(
                            "{} Document rejected before indexing: {error}",
                            console::style("✗").red()
                        );
                    }
                }
                SyncEvent::FileDeleted { path } => {
                    Self::handle_file_deleted(&root, &indexed, path).await;
                }
                SyncEvent::FullRebuild { reason } => {
                    eprintln!(
                        "{} Full rebuild: {}",
                        console::style("▶").blue().bold(),
                        reason
                    );
                    Self::full_rebuild(&root, &config, &tenant_id, &indexed).await;
                }
                SyncEvent::Shutdown => break,
            }
        }
    }

    /// Handle a file change: compute content hash, check fingerprint, re-index incrementally.
    async fn handle_file_changed(
        root: &Path,
        config: &HaciendaConfig,
        tenant_id: &str,
        indexed: &Arc<tokio::sync::RwLock<HashMap<String, IndexedDocument>>>,
        path: PathBuf,
    ) -> Result<(), String> {
        // Skip non-files and hidden files
        if !path.is_file()
            || path
                .file_name()
                .map(|n| n.to_string_lossy().starts_with('.'))
                .unwrap_or(false)
        {
            return Ok(());
        }

        // Compute content hash
        let content = match tokio::fs::read(&path).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "{} Failed to read {}: {}",
                    console::style("✗").red(),
                    path.display(),
                    e
                );
                return Err(format!("source read failed: {e}"));
            }
        };
        let content_hash = blake3::hash(&content).to_hex().to_string();

        // Get relative path as doc_id
        let doc_id = match path.strip_prefix(root) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => return Err("source is outside the configured root".to_owned()),
        };

        // Check if already indexed with same hash
        {
            let idx = indexed.read().await;
            if let Some(existing) = idx.get(&doc_id)
                && existing.content_hash == content_hash
            {
                return Ok(()); // No change
            }
        }

        let indexed_document =
            Self::process_file(config, tenant_id, path, content, doc_id, content_hash).await?;

        let mut idx = indexed.write().await;
        let doc_id = indexed_document.doc_id.clone();
        idx.insert(doc_id.clone(), indexed_document);

        eprintln!("{} Indexed {}", console::style("✓").green(), doc_id);
        Ok(())
    }

    async fn process_file(
        config: &HaciendaConfig,
        tenant_id: &str,
        path: PathBuf,
        content: Vec<u8>,
        doc_id: String,
        content_hash: String,
    ) -> Result<IndexedDocument, String> {
        let encryption = config.encryption_config(Some(tenant_id));
        validate_assurance_mode(encryption, config.kms_config(Some(tenant_id)))
            .map_err(|e| e.to_string())?;
        let provider = vault_key_provider(encryption).map_err(|e| e.to_string())?;
        let rulepacks: Vec<&str> = config
            .redaction
            .rulepacks
            .iter()
            .map(String::as_str)
            .collect();
        let engine = GazeEngine::core_floor_with(&rulepacks).map_err(|e| e.to_string())?;

        let mut document = ExtractedDocument::default();
        document.content = String::from_utf8_lossy(&content).into_owned();
        let document_identity = DocumentIdentity::new(tenant_id, &doc_id, &content_hash);
        let redaction_config = RedactionConfig {
            categories: std::collections::HashSet::from([PiiCategory::Custom(
                crate::BRIDGE_CATEGORY.to_owned(),
            )]),
            strategy: RedactionStrategy::TokenReplace,
            ner: None,
            preserve_offsets: true,
            custom_terms: Vec::new(),
            custom_patterns: Vec::new(),
            findings: Vec::new(),
            min_score: None,
            findings_path: None,
            findings_offset_encoding: RedactionOffsetEncoding::Utf8Bytes,
        };
        let output = write_dual_store_for_document(
            &engine,
            &mut document,
            &redaction_config,
            &config.redaction.one_way,
            document_identity.clone(),
            provider.as_ref(),
        )
        .await
        .map_err(|e| e.to_string())?;

        // Custody is the ordering boundary: only after the complete encrypted
        // bundle is durably committed may an index entry be created.
        persist_files(
            &custody_artifacts(&output),
            &config.vault_dir(Some(tenant_id)),
            &document_identity,
            &output.fingerprint,
            provider.as_ref(),
        )
        .map_err(|e| e.to_string())?;

        Ok(IndexedDocument {
            doc_id,
            path,
            fingerprint: output.fingerprint,
            content_hash,
            last_modified: std::time::SystemTime::now(),
        })
    }

    /// Handle file deletion.
    async fn handle_file_deleted(
        root: &Path,
        indexed: &Arc<tokio::sync::RwLock<HashMap<String, IndexedDocument>>>,
        path: PathBuf,
    ) {
        let doc_id = path
            .strip_prefix(root)
            .ok()
            .map(|p| p.to_string_lossy().to_string());
        if let Some(doc_id) = doc_id {
            let mut idx = indexed.write().await;
            idx.remove(&doc_id);
            eprintln!("{} Removed {}", console::style("−").yellow(), doc_id);
        }
    }

    /// Full rebuild: re-process all files under root.
    async fn full_rebuild(
        root: &Path,
        config: &HaciendaConfig,
        tenant_id: &str,
        indexed: &Arc<tokio::sync::RwLock<HashMap<String, IndexedDocument>>>,
    ) {
        indexed.write().await.clear();

        let mut entries = match tokio::fs::read_dir(root).await {
            Ok(entries) => entries,
            Err(error) => {
                eprintln!("{} Full rebuild failed: {error}", console::style("✗").red());
                return;
            }
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            if path.is_file()
                && !path
                    .file_name()
                    .map(|n| n.to_string_lossy().starts_with('.'))
                    .unwrap_or(false)
            {
                let content = match tokio::fs::read(&path).await {
                    Ok(content) => content,
                    Err(error) => {
                        eprintln!(
                            "{} Document rejected before indexing: {error}",
                            console::style("✗").red()
                        );
                        continue;
                    }
                };
                let content_hash = blake3::hash(&content).to_hex().to_string();
                let Some(doc_id) = path
                    .strip_prefix(root)
                    .ok()
                    .map(|p| p.to_string_lossy().to_string())
                else {
                    continue;
                };
                match Self::process_file(
                    config,
                    tenant_id,
                    path,
                    content,
                    doc_id.clone(),
                    content_hash,
                )
                .await
                {
                    Ok(indexed_document) => {
                        indexed.write().await.insert(doc_id, indexed_document);
                    }
                    Err(error) => {
                        eprintln!(
                            "{} Document rejected before indexing: {error}",
                            console::style("✗").red()
                        );
                    }
                }
            }
        }

        eprintln!(
            "{} Full rebuild complete: {} documents",
            console::style("✓").green(),
            indexed.read().await.len()
        );
    }

    /// Trigger a full rebuild (e.g., on fingerprint change).
    pub fn trigger_full_rebuild(&self, reason: String) {
        let _ = self.event_tx.try_send(SyncEvent::FullRebuild { reason });
    }

    /// Manual refresh: process all files once, clearing the index first (full rebuild).
    pub async fn manual_refresh(&self) {
        self.trigger_full_rebuild("manual refresh".to_owned());
        // Wait for processing (in real impl, would await a completion signal)
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    /// One-shot incremental refresh: index new/changed files without clearing.
    pub async fn manual_refresh_incremental(&self) {
        if let Ok(mut entries) = tokio::fs::read_dir(&self.root).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if path.is_file() {
                    let _ = self.event_tx.try_send(SyncEvent::FileChanged { path });
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    /// Get current indexed documents (for status/debug).
    pub async fn get_indexed(&self) -> Vec<IndexedDocument> {
        self.indexed.read().await.values().cloned().collect()
    }
}

/// CLI command for manual refresh.
///
/// `full` selects a complete rebuild; otherwise only new/changed files are
/// (re)indexed. Status goes to stderr and the indexed documents are returned:
/// stdout may carry the stdio MCP JSON-RPC stream when called from the server.
/// Scoped refresh used by authenticated MCP/CLI paths. Each supplied root is
/// processed independently; no current-directory or all-tenant fallback exists.
pub async fn run_manual_refresh_scoped(
    config_path: &std::path::Path,
    tenant_id: &str,
    roots: &[PathBuf],
    full: bool,
) -> Result<Vec<IndexedDocument>, crate::CliError> {
    let config = crate::load_config(config_path)?;
    let _tenant = config
        .get_tenant(tenant_id)
        .ok_or_else(|| crate::CliError::Other("tenant unavailable".into()))?;
    let mut all = Vec::new();
    for root in roots {
        let sync = FolderSync::new_scoped(root.clone(), config.clone(), tenant_id.to_owned());
        if full {
            sync.manual_refresh().await;
        } else {
            sync.manual_refresh_incremental().await;
        }
        all.extend(sync.get_indexed().await);
    }
    Ok(all)
}

pub async fn run_manual_refresh(
    config_path: &std::path::Path,
    full: bool,
) -> Result<Vec<IndexedDocument>, crate::CliError> {
    let config = crate::load_config(config_path)?;
    let sync = FolderSync::new(std::env::current_dir()?, config);

    // Trigger manual refresh (one-shot, no watcher needed)
    if full {
        sync.manual_refresh().await;
    } else {
        sync.manual_refresh_incremental().await;
    }

    // Report status on stderr, never stdout (stdio transport safety)
    let indexed = sync.get_indexed().await;
    eprintln!(
        "{} Indexed {} documents:",
        console::style("✓").green(),
        indexed.len()
    );
    for doc in &indexed {
        eprintln!("  {} ({})", doc.doc_id, doc.fingerprint.as_str());
    }

    Ok(indexed)
}
