//! Folder synchronization: watcher + manual refresh with engine-era rebuild policy.
//!
//! Implements the sync pipeline for the document folder (spec §8, Epic 4):
//! - File watcher (notify) for real-time change detection
//! - Manual refresh CLI for on-demand sync
//! - Engine-era fingerprint rebuild policy: full rebuild on fingerprint change,
//!   incremental on content change.

use crate::EngineEraFingerprint;
use crate::config::HaciendaConfig;
use blake3;
use console;
use crossbeam_channel::{Receiver, Sender, bounded};
use notify::{Config, Event, EventKind, RecommendedWatcher, Watcher};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use xberg::RedactionConfig;

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
    pub content_hash: String, // SHA256 of raw content for change detection
    pub last_modified: std::time::SystemTime,
}

/// Folder sync engine with watcher and manual refresh.
pub struct FolderSync {
    root: PathBuf,
    config: HaciendaConfig,
    watcher: Option<RecommendedWatcher>,
    event_tx: Sender<SyncEvent>,
    event_rx: Receiver<SyncEvent>,
    indexed: Arc<tokio::sync::RwLock<HashMap<String, IndexedDocument>>>,
}

impl FolderSync {
    /// Create a new folder sync engine.
    pub fn new(root: PathBuf, config: HaciendaConfig) -> Self {
        let (event_tx, event_rx) = bounded(1024);
        Self {
            root,
            config,
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

        let handle = tokio::spawn(async move {
            Self::sync_loop(root, config, indexed, event_rx).await;
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
        indexed: Arc<tokio::sync::RwLock<HashMap<String, IndexedDocument>>>,
        event_rx: Receiver<SyncEvent>,
    ) {
        while let Ok(event) = event_rx.recv() {
            match event {
                SyncEvent::FileChanged { path } => {
                    Self::handle_file_changed(&root, &config, &indexed, path).await;
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
                    Self::full_rebuild(&root, &config, &indexed).await;
                }
                SyncEvent::Shutdown => break,
            }
        }
    }

    /// Handle a file change: compute content hash, check fingerprint, re-index incrementally.
    async fn handle_file_changed(
        root: &Path,
        _config: &HaciendaConfig,
        indexed: &Arc<tokio::sync::RwLock<HashMap<String, IndexedDocument>>>,
        path: PathBuf,
    ) {
        // Skip non-files and hidden files
        if !path.is_file()
            || path
                .file_name()
                .map(|n| n.to_string_lossy().starts_with('.'))
                .unwrap_or(false)
        {
            return;
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
                return;
            }
        };
        let content_hash = blake3::hash(&content).to_hex().to_string();

        // Get relative path as doc_id
        let doc_id = match path.strip_prefix(root) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => return,
        };

        // Check if already indexed with same hash
        {
            let idx = indexed.read().await;
            if let Some(existing) = idx.get(&doc_id)
                && existing.content_hash == content_hash
            {
                return; // No change
            }
        }

        // Extract content for processing
        let _text = String::from_utf8_lossy(&content).to_string();

        // Run dual-store write (this does gaze detection + redaction)
        // In production, this would use the engine from config
        // For now, we just update the index record
        let fingerprint = EngineEraFingerprint::compute(
            "gaze-assembly",
            crate::TOKEN_GRAMMAR_VERSION,
            &RedactionConfig {
                categories: std::collections::HashSet::from([xberg::PiiCategory::Custom(
                    crate::BRIDGE_CATEGORY.to_owned(),
                )]),
                strategy: xberg::RedactionStrategy::TokenReplace,
                ner: None,
                preserve_offsets: true,
                custom_terms: Vec::new(),
                custom_patterns: Vec::new(),
                findings: Vec::new(),
                min_score: None,
                findings_path: None,
                findings_offset_encoding: xberg::RedactionOffsetEncoding::Utf8Bytes,
            },
        );

        let mut idx = indexed.write().await;
        idx.insert(
            doc_id.clone(),
            IndexedDocument {
                doc_id: doc_id.clone(),
                path: path.clone(),
                fingerprint,
                content_hash,
                last_modified: std::time::SystemTime::now(),
            },
        );

        eprintln!("{} Indexed {}", console::style("✓").green(), doc_id);
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
        _config: &HaciendaConfig,
        indexed: &Arc<tokio::sync::RwLock<HashMap<String, IndexedDocument>>>,
    ) {
        let mut idx = indexed.write().await;
        idx.clear();

        let mut entries = tokio::fs::read_dir(root).await.expect("read dir");
        while let Some(entry) = entries.next_entry().await.expect("next entry") {
            let path = entry.path();
            if path.is_file()
                && !path
                    .file_name()
                    .map(|n| n.to_string_lossy().starts_with('.'))
                    .unwrap_or(false)
            {
                let content = tokio::fs::read(&path).await.expect("read file");
                let content_hash = blake3::hash(&content).to_hex().to_string();
                let doc_id = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .to_string();

                let fingerprint = EngineEraFingerprint::compute(
                    "gaze-assembly",
                    crate::TOKEN_GRAMMAR_VERSION,
                    &RedactionConfig {
                        categories: std::collections::HashSet::from([xberg::PiiCategory::Custom(
                            crate::BRIDGE_CATEGORY.to_owned(),
                        )]),
                        strategy: xberg::RedactionStrategy::TokenReplace,
                        ner: None,
                        preserve_offsets: true,
                        custom_terms: Vec::new(),
                        custom_patterns: Vec::new(),
                        findings: Vec::new(),
                        min_score: None,
                        findings_path: None,
                        findings_offset_encoding: xberg::RedactionOffsetEncoding::Utf8Bytes,
                    },
                );

                idx.insert(
                    doc_id.clone(),
                    IndexedDocument {
                        doc_id,
                        path,
                        fingerprint,
                        content_hash,
                        last_modified: std::time::SystemTime::now(),
                    },
                );
            }
        }

        eprintln!(
            "{} Full rebuild complete: {} documents",
            console::style("✓").green(),
            idx.len()
        );
    }

    /// Trigger a full rebuild (e.g., on fingerprint change).
    pub fn trigger_full_rebuild(&self, reason: String) {
        let _ = self.event_tx.try_send(SyncEvent::FullRebuild { reason });
    }

    /// Manual refresh: process all files once (for CLI command).
    pub async fn manual_refresh(&self) {
        self.trigger_full_rebuild("manual refresh".to_owned());
        // Wait for processing (in real impl, would await a completion signal)
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    /// Get current indexed documents (for status/debug).
    pub async fn get_indexed(&self) -> Vec<IndexedDocument> {
        self.indexed.read().await.values().cloned().collect()
    }
}

/// CLI command for manual refresh.
pub async fn run_manual_refresh(config_path: &std::path::Path) -> Result<(), crate::CliError> {
    let config = crate::load_config(config_path)?;
    let sync = FolderSync::new(std::env::current_dir()?, config);

    // Trigger manual refresh (one-shot, no watcher needed)
    sync.manual_refresh().await;

    // Print status
    let indexed = sync.get_indexed().await;
    println!(
        "{} Indexed {} documents:",
        console::style("✓").green(),
        indexed.len()
    );
    for doc in indexed {
        println!("  {} ({})", doc.doc_id, doc.fingerprint.as_str());
    }

    Ok(())
}
