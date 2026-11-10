//! Hybrid search: BM25 (Tantivy) + Vector (basemind LanceStore) + Lexical (basemind FTS) with RRF fusion.
//!
//! Implements the search MCP tool (Epic 14): agent-facing search over tokenized
//! documents. Only class-stable `<Class_...>` tokens are indexed -- raw session
//! tokens poison the blob cache; format-preserving fakes stay out of the
//! lexical index (ADR-0004).
//!
//! Pipeline:
//! 1. BM25 over class-stable `<Class_...>` tokens (Tantivy) - ALWAYS available
//! 2. Vector search via basemind's LanceStore (optional, gated by `basemind` feature)
//! 3. Lexical search via basemind's FTS (optional, gated by `basemind` feature)
//! 4. RRF fusion of all lanes using basemind's RRF module
//! 5. Cross-encoder rerank (optional, gated by `rerank` feature + SensitivityTier)
//!
//! Returns: tokenized snippets + doc IDs -- never raw PII.

use std::collections::HashMap;
use std::ops::Bound;
#[cfg(feature = "rerank")]
use std::path::{Path, PathBuf};
#[cfg(feature = "rerank")]
use std::sync::{Mutex, OnceLock};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tantivy::{
    Index, IndexWriter, Term,
    collector::TopDocs,
    doc,
    query::{BooleanQuery, Occur, QueryParser, RangeQuery, TermQuery},
    schema::{Field, IndexRecordOption, STORED, STRING, TEXT, Value},
};

use crate::{
    CliError,
    config::{HaciendaConfig, RerankerConfig},
    index_projection::{SensitivityTier, project_document},
};

#[cfg(feature = "rerank")]
use ort::{
    session::{Session, builder::GraphOptimizationLevel},
    value::Tensor,
};

/// Maximum accepted `top_k` (guards against `TopDocs::with_limit(0)` panics and
/// `top_k * 2` overflow in every lane).
const MAX_TOP_K: usize = 100;

/// Escape a string for use in a SQL literal (LanceDB predicate).
#[allow(dead_code)]
fn escape_sql_literal(s: &str) -> String {
    s.replace('\'', "''")
}

/// Cross-encoder reranker using ort with bge-reranker-v2-m3 ONNX model.
#[cfg(feature = "rerank")]
struct Reranker {
    session: Mutex<Session>,
    /// The model's own tokenizer (XLM-RoBERTa SentencePiece), loaded from
    /// tokenizer.json. Token IDs MUST come from here — hashing a whitespace
    /// split produces IDs the model has never seen.
    tokenizer: tokenizers::Tokenizer,
    max_seq_len: usize,
    /// Kept for API compatibility / future batching; not used in the current
    /// single-pass implementation.
    #[allow(dead_code)]
    batch_size: usize,
}

#[cfg(feature = "rerank")]
impl Reranker {
    /// Load or create a reranker instance (cached globally on success only).
    ///
    /// A failed load is deliberately NOT cached: a transient network or disk
    /// error must not disable reranking until process restart.
    fn get_or_init(config: &RerankerConfig) -> Result<&'static Reranker> {
        static INSTANCE: OnceLock<Reranker> = OnceLock::new();
        if let Some(loaded) = INSTANCE.get() {
            return Ok(loaded);
        }
        let loaded = Self::load(config)?;
        Ok(INSTANCE.get_or_init(|| loaded))
    }

    /// Load the bge-reranker-v2-m3 ONNX model + tokenizer.
    fn load(config: &RerankerConfig) -> Result<Reranker> {
        let cache_dir = shellexpand::tilde(&config.cache_dir).into_owned();
        let model_path = PathBuf::from(&cache_dir).join("model.onnx");
        let tokenizer_path = PathBuf::from(&cache_dir).join("tokenizer.json");

        // Ensure cache directory exists
        std::fs::create_dir_all(&cache_dir)
            .map_err(|e| anyhow::anyhow!("Failed to create cache dir {}: {}", cache_dir, e))?;

        // Download model + tokenizer if not present
        if !model_path.exists() || !tokenizer_path.exists() {
            Self::download_model(&config.model, &cache_dir, config.sha256.as_deref())?;
        }

        // Configure ONNX Runtime session
        let session = Session::builder()
            .map_err(|e| anyhow::anyhow!("Failed to create session builder: {}", e))?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(|e| anyhow::anyhow!("Failed to set optimization level: {}", e))?
            .with_intra_threads(4)
            .map_err(|e| anyhow::anyhow!("Failed to set intra threads: {}", e))?
            .commit_from_file(&model_path)
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to load ONNX model from {}: {}",
                    model_path.display(),
                    e
                )
            })?;

        let tokenizer = tokenizers::Tokenizer::from_file(&tokenizer_path).map_err(|e| {
            anyhow::anyhow!(
                "Failed to load tokenizer from {}: {}",
                tokenizer_path.display(),
                e
            )
        })?;

        Ok(Reranker {
            session: Mutex::new(session),
            tokenizer,
            max_seq_len: config.max_seq_len,
            batch_size: config.batch_size.max(1),
        })
    }

    /// Download the model ONNX + tokenizer.json from Hugging Face.
    fn download_model(model_name: &str, cache_dir: &str, model_sha256: Option<&str>) -> Result<()> {
        let base = format!("https://huggingface.co/BAAI/{}/resolve/main", model_name);
        tracing::info!(
            "Downloading reranker model {} into {}",
            model_name,
            cache_dir
        );

        // Checksum pin (when configured) applies to the ONNX model binary.
        Self::download_file(
            &format!("{}/onnx/model.onnx", base),
            &PathBuf::from(cache_dir).join("model.onnx"),
            model_sha256,
        )?;
        Self::download_file(
            &format!("{}/tokenizer.json", base),
            &PathBuf::from(cache_dir).join("tokenizer.json"),
            None,
        )?;

        tracing::info!("Successfully downloaded reranker model {}", model_name);
        Ok(())
    }

    /// Stream a download to `<dest>.part`, verify the pinned SHA-256 (if any),
    /// then atomically rename into place. A partial or failed download never
    /// leaves a corrupt file that a later run would trust.
    fn download_file(url: &str, dest: &Path, expected_sha256: Option<&str>) -> Result<()> {
        let response = reqwest::blocking::get(url)
            .map_err(|e| anyhow::anyhow!("Failed to download {}: {}", url, e))?;
        if !response.status().is_success() {
            anyhow::bail!("Download failed with status {}: {}", response.status(), url);
        }

        let part_path = dest.with_extension("part");
        let mut file = std::fs::File::create(&part_path)
            .map_err(|e| anyhow::anyhow!("Failed to create {}: {}", part_path.display(), e))?;
        std::io::copy(&mut std::io::BufReader::new(response), &mut file)
            .map_err(|e| anyhow::anyhow!("Failed to stream {}: {}", url, e))?;
        file.sync_all().ok();

        if let Some(expected) = expected_sha256 {
            let actual = Self::sha256_file(&part_path)?;
            if !actual.eq_ignore_ascii_case(expected) {
                let _ = std::fs::remove_file(&part_path);
                anyhow::bail!(
                    "Checksum mismatch for {}: expected {}, got {}",
                    dest.display(),
                    expected,
                    actual
                );
            }
        }

        std::fs::rename(&part_path, dest)
            .map_err(|e| anyhow::anyhow!("Failed to finalize {}: {}", dest.display(), e))?;
        Ok(())
    }

    /// SHA-256 of a file, hex-encoded.
    fn sha256_file(path: &Path) -> Result<String> {
        use sha2::{Digest, Sha256};
        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        std::io::copy(&mut file, &mut hasher)?;
        Ok(hasher
            .finalize()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect())
    }

    /// Run cross-encoder inference on query-document pairs.
    /// Returns exactly one relevance score per document.
    fn predict(&self, query: &str, documents: &[&str]) -> Result<Vec<f32>> {
        let batch_size = documents.len();
        anyhow::ensure!(batch_size > 0, "rerank called with no documents");

        // Tokenize each (query, document) pair with the model's own tokenizer.
        // bge-reranker-v2-m3 is XLM-RoBERTa based: encode_pair inserts the
        // model's real pair separator; the vocabulary has no token_type_ids.
        let mut input_ids = Vec::with_capacity(batch_size * self.max_seq_len);
        let mut attention_mask = Vec::with_capacity(batch_size * self.max_seq_len);

        for doc in documents {
            let encoding = self
                .tokenizer
                .encode((query, *doc), true)
                .map_err(|e| anyhow::anyhow!("tokenizer encode: {}", e))?;
            let ids = encoding.get_ids();
            let mask = encoding.get_attention_mask();
            for i in 0..self.max_seq_len {
                input_ids.push(*ids.get(i).unwrap_or(&0) as i64);
                attention_mask.push(*mask.get(i).unwrap_or(&0) as i64);
            }
        }

        // Feed only the inputs the ONNX graph actually declares. XLM-R has no
        // token_type_ids; sending an undeclared input makes session.run fail.
        let mut session = self
            .session
            .lock()
            .map_err(|e| anyhow::anyhow!("Failed to lock session: {}", e))?;
        let declares_token_type_ids = session
            .inputs()
            .iter()
            .any(|input| input.name().contains("token_type_ids"));

        let inputs = if declares_token_type_ids {
            let token_type_ids = vec![0i64; input_ids.len()];
            HashMap::from([
                (
                    "input_ids",
                    Tensor::from_array(([batch_size, self.max_seq_len], input_ids))?,
                ),
                (
                    "attention_mask",
                    Tensor::from_array(([batch_size, self.max_seq_len], attention_mask))?,
                ),
                (
                    "token_type_ids",
                    Tensor::from_array(([batch_size, self.max_seq_len], token_type_ids))?,
                ),
            ])
        } else {
            HashMap::from([
                (
                    "input_ids",
                    Tensor::from_array(([batch_size, self.max_seq_len], input_ids))?,
                ),
                (
                    "attention_mask",
                    Tensor::from_array(([batch_size, self.max_seq_len], attention_mask))?,
                ),
            ])
        };

        let outputs = session.run(inputs)?;

        // Extract logits. bge-reranker-v2-m3 emits [batch, 1], so derive the
        // row width from the output instead of assuming max_seq_len.
        let output_value = outputs
            .values()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No output from model"))?;
        let (_, data) = output_value.try_extract_tensor::<f32>()?;
        let row_width = (data.len() / batch_size.max(1)).max(1);
        let scores: Vec<f32> = data.chunks(row_width).map(|row| row[0]).collect();

        if scores.len() != batch_size {
            anyhow::bail!(
                "reranker returned {} scores for {} documents",
                scores.len(),
                batch_size
            );
        }

        Ok(scores)
    }
}

/// Placeholder reranker when feature is disabled
#[cfg(not(feature = "rerank"))]
struct Reranker;

#[cfg(not(feature = "rerank"))]
impl Reranker {
    #[allow(dead_code)]
    fn get_or_init(_config: &RerankerConfig) -> Result<&'static Reranker> {
        Err(anyhow::anyhow!("rerank feature not enabled"))
    }
}

/// Search result returned to the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub doc_id: String,
    pub snippet: String,
    pub score: f32,
    pub tier: SensitivityTier,
    pub connector: String,
    pub matched_lanes: Vec<String>,
}

/// Search request parameters.
#[derive(Debug, Clone, Deserialize)]
pub struct SearchParams {
    pub query: String,
    #[serde(default = "default_top_k")]
    pub top_k: usize,
    #[serde(default = "default_true")]
    pub rerank: bool,
    pub filter: Option<SearchFilter>,
}

fn default_top_k() -> usize {
    10
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct SearchFilter {
    pub connector: Option<String>,
    pub since: Option<String>, // ISO8601 timestamp
}

/// A ranked hit from any search lane.
#[derive(Debug, Clone)]
struct LaneHit {
    doc_id: String,
    snippet: String,
    tier: SensitivityTier,
    connector: String,
    lane: &'static str,
    /// 1-based rank within the lane, kept for debuggability/future tie-breaks.
    #[allow(dead_code)]
    rank: usize,
}

/// Search engine combining BM25 (Tantivy) + Vector (LanceStore) + Lexical (FTS) with RRF fusion.
/// Tenant-aware search engine that manages per-tenant indices.
pub struct TenantSearchEngineManager {
    config: HaciendaConfig,
    /// Map of tenant_id -> SearchEngine
    engines: std::collections::HashMap<String, SearchEngine>,
}

impl TenantSearchEngineManager {
    /// Create a new tenant search engine manager.
    pub async fn new(config: HaciendaConfig) -> Result<Self, CliError> {
        let mut engines = std::collections::HashMap::new();

        if config.is_multi_tenant() {
            // Multi-tenant mode: create engine for each active tenant
            for tenant in config.active_tenants() {
                let tenant_id = tenant.tenant_id.clone();
                let engine = SearchEngine::new_for_tenant(&config, &tenant_id).await?;
                engines.insert(tenant_id, engine);
            }
        } else {
            // Single-tenant mode (backward compatibility)
            let engine = SearchEngine::new_for_tenant(&config, config.default_tenant_id()).await?;
            engines.insert(config.default_tenant_id().to_string(), engine);
        }

        Ok(Self { config, engines })
    }

    /// Get a search engine for a specific tenant.
    pub fn get_engine(&self, tenant_id: &str) -> Option<&SearchEngine> {
        self.engines.get(tenant_id)
    }

    /// Get a mutable search engine for a specific tenant.
    pub fn get_engine_mut(&mut self, tenant_id: &str) -> Option<&mut SearchEngine> {
        self.engines.get_mut(tenant_id)
    }

    /// Get the default tenant's engine.
    pub fn default_engine(&self) -> Option<&SearchEngine> {
        self.engines.get(self.config.default_tenant_id())
    }

    /// Get the default tenant's engine (mutable).
    pub fn default_engine_mut(&mut self) -> Option<&mut SearchEngine> {
        self.engines.get_mut(self.config.default_tenant_id())
    }

    /// List all tenant IDs with active engines.
    pub fn tenant_ids(&self) -> Vec<String> {
        self.engines.keys().cloned().collect()
    }
}

/// Search engine for a single tenant.
pub struct SearchEngine {
    config: HaciendaConfig,
    tenant_id: String,
    tantivy_index: Index,
    text_field: Field,
    doc_id_field: Field,
    connector_field: Field,
    tier_field: Field,
    indexed_at_field: Field,
    tenant_id_field: Field,

    #[cfg(feature = "basemind")]
    lance_store: basemind::lance::LanceStore,

    /// Loaded only when `documents.embed` is true (default false keeps the
    /// fail-closed, BM25-only behavior and avoids any model download).
    #[cfg(feature = "basemind")]
    embedder: Option<basemind::embeddings::SharedEmbedder>,
}

impl SearchEngine {
    /// Create a new search engine for a specific tenant.
    pub async fn new_for_tenant(
        config: &HaciendaConfig,
        tenant_id: &str,
    ) -> Result<Self, CliError> {
        // Build Tantivy schema for BM25.
        // doc_id and connector are STRING (exact-match) fields so a
        // re-index can delete the previous entry via TermQuery.
        let mut schema_builder = tantivy::schema::Schema::builder();
        let text_field = schema_builder.add_text_field("text", TEXT | STORED);
        let doc_id_field = schema_builder.add_text_field("doc_id", STRING | STORED);
        let connector_field = schema_builder.add_text_field("connector", STRING | STORED);
        let tier_field = schema_builder.add_text_field("tier", STRING | STORED);
        let indexed_at_field = schema_builder.add_date_field(
            "indexed_at",
            tantivy::schema::DateOptions::default()
                .set_indexed()
                .set_stored(),
        );
        // Add tenant_id field for multi-tenancy isolation
        let tenant_id_field = schema_builder.add_text_field("tenant_id", STRING | STORED);
        let schema = schema_builder.build();

        // Create in-memory Tantivy index for BM25
        let tantivy_index = Index::create_in_ram(schema.clone());

        #[cfg(feature = "basemind")]
        let lance_store = {
            let lance_dir = config.lance_dir(Some(tenant_id));
            let dim = config.embedding_dim();
            let embedding_model = config.embedding_model().to_string();
            basemind::lance::LanceStore::open(&lance_dir, dim, &embedding_model)
                .map_err(|e| CliError::Other(format!("open lance store: {e}")))?
        };

        // Honor documents.embed: no embedder load, no vector indexing and
        // no vector/lexical lanes when disabled (lexical-only default).
        #[cfg(feature = "basemind")]
        let embedder = if config.documents.embed {
            let preset = config.embedding_model();
            let batch_size = config.embedding_batch_size().unwrap_or(32);
            Some(
                basemind::embeddings::SharedEmbedder::load(preset, 0, batch_size)
                    .map_err(|e| CliError::Other(format!("load embedder: {e}")))?,
            )
        } else {
            None
        };

        Ok(Self {
            config: config.clone(),
            tenant_id: tenant_id.to_string(),
            tantivy_index,
            text_field,
            doc_id_field,
            connector_field,
            tier_field,
            indexed_at_field,
            tenant_id_field,
            #[cfg(feature = "basemind")]
            lance_store,
            #[cfg(feature = "basemind")]
            embedder,
        })
    }

    /// Get the tenant ID for this engine.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Cloned handle to the Lance store, for `spawn_blocking` graph/cypher work.
    ///
    /// The graphrag calls block_on the store's own reactor, so they must never run
    /// inside the async runtime; handlers clone the store and move it into a
    /// blocking task instead.
    #[cfg(feature = "basemind")]
    pub fn lance_store_clone(&self) -> basemind::lance::LanceStore {
        self.lance_store.clone()
    }

    /// Cloned shared embedder handle, if `documents.embed` is enabled.
    #[cfg(feature = "basemind")]
    pub fn embedder_clone(&self) -> Option<basemind::embeddings::SharedEmbedder> {
        self.embedder.clone()
    }

    /// Read-only Cypher query over this tenant's entity graph (basemind graphrag).
    ///
    /// Blocking call (the store owns the reactor): invoke from `spawn_blocking`
    /// on the async path. Gated by the `basemind` feature, which pulls the
    /// graphrag feature transitively.
    #[cfg(feature = "basemind")]
    pub fn graph_cypher(
        &self,
        cypher: &str,
        max_rows: usize,
    ) -> Result<basemind::lance::CypherResult, CliError> {
        self.lance_store
            .execute_cypher(&self.tenant_id, cypher, max_rows)
            .map_err(|e| CliError::Other(format!("cypher: {e}")))
    }

    /// GraphRAG hybrid retrieval for this tenant: vector lane + graph expansion + fusion.
    ///
    /// `query_vec` comes from the shared embedder (requires `documents.embed`).
    /// Blocking call: invoke from `spawn_blocking` on the async path.
    #[cfg(feature = "basemind")]
    pub fn graph_rag(
        &self,
        query_vec: Vec<f32>,
        hops: u8,
        max_results: usize,
    ) -> Result<(Vec<basemind::lance::GraphRagHit>, bool), CliError> {
        self.lance_store
            .graph_rag_search(&self.tenant_id, query_vec, hops, max_results)
            .map_err(|e| CliError::Other(format!("graph rag: {e}")))
    }

    /// Index a document (called by folder_sync after extraction).
    pub async fn index_document(
        &self,
        doc_id: &str,
        content: &str,
        connector: &str,
        tier: SensitivityTier,
    ) -> Result<(), CliError> {
        // Fail closed: HardBlock content never enters any index.
        if !tier.allows_indexing() {
            return Ok(());
        }

        // Project to class-stable tokens
        let projected = project_document(content);
        let projected_str = projected.to_string();

        // Index in Tantivy (BM25) - ALWAYS
        let mut index_writer: IndexWriter = self.tantivy_index.writer(50_000_000)?;
        // Replace any previous entry for this doc_id instead of appending
        // a duplicate (doc_id is a STRING field, so the term is exact).
        index_writer.delete_term(tantivy::Term::from_field_text(self.doc_id_field, doc_id));
        let mut doc = tantivy::TantivyDocument::default();
        doc.add_text(self.text_field, &projected_str);
        doc.add_text(self.doc_id_field, doc_id);
        doc.add_text(self.connector_field, connector);
        doc.add_text(self.tier_field, format!("{:?}", tier));
        doc.add_date(
            self.indexed_at_field,
            tantivy::DateTime::from_timestamp_secs(chrono::Utc::now().timestamp()),
        );
        doc.add_text(self.tenant_id_field, &self.tenant_id);
        index_writer.add_document(doc)?;
        index_writer.commit()?;

        // Index in basemind's LanceStore (vector + FTS) - OPTIONAL, behind feature
        #[cfg(feature = "basemind")]
        if let Some(embedder) = &self.embedder {
            // Generate embedding for the projected content
            let embedding = embedder
                .embed(&projected_str)
                .map_err(|e| CliError::Other(format!("embed: {e}")))?;

            let doc_row = basemind::lance::DocumentRow {
                scope: self.tenant_id.clone(), // Use tenant_id as scope
                path: doc_id.to_string(),
                chunk_idx: 0,
                mime_type: "text/plain".to_string(),
                text: projected_str.clone(),
                heading_path: "".to_string(),
                byte_start: 0,
                byte_end: projected_str.len() as u32,
                rehydration_ref: None,
                embedding,
            };

            self.lance_store
                .replace_document(
                    &self.tenant_id, // Use tenant_id as scope
                    doc_id,
                    vec![doc_row],
                )
                .map_err(|e| CliError::Other(format!("lance store: {e}")))?;

            // Build FTS index after ingest (batched, not per-doc in production)
            // basemind::lance::fts::build_index_after_ingest(&self.lance_store, &self.config.documents.fts)?;
        }

        Ok(())
    }

    /// Search with hybrid BM25 + Vector + Lexical + RRF fusion + optional rerank.
    pub async fn search(&self, params: SearchParams) -> Result<Vec<SearchResult>> {
        // Clamp to a safe range: TopDocs::with_limit(0) panics and `* 2`
        // overflows for absurd caller-supplied values.
        let top_k = params.top_k.clamp(1, MAX_TOP_K);
        #[cfg(feature = "basemind")]
        let scope = self.tenant_id.clone();
        #[cfg(feature = "basemind")]
        let scope_predicate = format!("scope = '{}'", escape_sql_literal(&scope));

        // Collect hits from all lanes
        let mut all_lane_hits: Vec<LaneHit> = Vec::new();

        // 1. BM25 search via Tantivy - ALWAYS
        let bm25_hits = self.bm25_search_lane(&params, top_k).await?;
        all_lane_hits.extend(bm25_hits);

        // 2. Vector + lexical lanes via basemind - OPTIONAL, only when
        // documents.embed is enabled (matches the indexing side).
        #[cfg(feature = "basemind")]
        if self.embedder.is_some() {
            let vector_hits = self.vector_search_lane(&params, &scope, top_k).await?;
            all_lane_hits.extend(vector_hits);

            let lexical_hits = self
                .lexical_search_lane(&params, scope_predicate, top_k)
                .await?;
            all_lane_hits.extend(lexical_hits);
        }

        // 4. RRF fusion using basemind's RRF module
        let fused = self.rrf_fuse(all_lane_hits)?;

        // 5. Cross-encoder rerank (if enabled)
        let reranked = if params.rerank {
            self.rerank(&params.query, fused).await?
        } else {
            fused
        };

        // Apply top_k
        let results = reranked.into_iter().take(top_k).collect();

        Ok(results)
    }

    /// BM25 search lane via Tantivy (tenant-isolated).
    async fn bm25_search_lane(&self, params: &SearchParams, top_k: usize) -> Result<Vec<LaneHit>> {
        let reader = self.tantivy_index.reader()?;
        let searcher = reader.searcher();

        let query_parser = QueryParser::for_index(&self.tantivy_index, vec![self.text_field]);

        // Lenient parse: a natural-language query with an unbalanced quote or
        // stray `field:` syntax must degrade, not fail the whole search.
        let (user_query, _parse_errors) = query_parser.parse_query_lenient(&params.query);

        // Build the boolean query structurally — never by string concatenation
        // (a connector value like `x OR text:secret` would rewrite the query).
        let mut clauses: Vec<(Occur, Box<dyn tantivy::query::Query>)> =
            vec![(Occur::Must, Box::new(user_query))];

        // ALWAYS filter by tenant_id for multi-tenancy isolation
        clauses.push((
            Occur::Must,
            Box::new(TermQuery::new(
                Term::from_field_text(self.tenant_id_field, &self.tenant_id),
                IndexRecordOption::Basic,
            )),
        ));

        if let Some(connector) = params.filter.as_ref().and_then(|f| f.connector.as_deref()) {
            clauses.push((
                Occur::Must,
                Box::new(TermQuery::new(
                    Term::from_field_text(self.connector_field, connector),
                    IndexRecordOption::Basic,
                )),
            ));
        }

        // Apply `since` against the index-time timestamp when it parses.
        if let Some(since) = params.filter.as_ref().and_then(|f| f.since.as_deref()) {
            match chrono::DateTime::parse_from_rfc3339(since) {
                Ok(ts) => {
                    let start = tantivy::DateTime::from_timestamp_secs(ts.timestamp());
                    clauses.push((
                        Occur::Must,
                        Box::new(RangeQuery::new_date_bounds(
                            "indexed_at".to_string(),
                            Bound::Included(start),
                            Bound::Unbounded,
                        )),
                    ));
                }
                Err(e) => {
                    tracing::warn!("ignoring unparseable filter.since {since:?}: {e}");
                }
            }
        }

        let query = BooleanQuery::new(clauses);

        let top_docs = searcher.search(&query, &TopDocs::with_limit(top_k.saturating_mul(2)))?;

        let mut hits = Vec::new();
        for (rank, (_score, doc_address)) in top_docs.into_iter().enumerate() {
            let doc: tantivy::TantivyDocument = searcher.doc(doc_address).unwrap();

            let doc_id = doc
                .get_first(self.doc_id_field)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let snippet = doc
                .get_first(self.text_field)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let connector = doc
                .get_first(self.connector_field)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let tier_str = doc
                .get_first(self.tier_field)
                .and_then(|v| v.as_str())
                .unwrap_or("HardBlock");

            // Unknown tier strings fail closed to HardBlock (dropped below).
            let tier = match tier_str {
                "Minimal" => SensitivityTier::Minimal,
                "Low" => SensitivityTier::Low,
                "High" => SensitivityTier::High,
                _ => SensitivityTier::HardBlock,
            };

            // Fail closed: HardBlock (and unknown) tiers are never returned.
            if !tier.allows_indexing() {
                continue;
            }

            hits.push(LaneHit {
                doc_id,
                snippet,
                tier,
                connector,
                lane: "bm25",
                rank: rank + 1,
            });
        }

        Ok(hits)
    }

    /// Vector search lane via basemind's LanceStore.
    #[cfg(feature = "basemind")]
    async fn vector_search_lane(
        &self,
        params: &SearchParams,
        scope: &str,
        top_k: usize,
    ) -> Result<Vec<LaneHit>> {
        let embedder = self
            .embedder
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("vector lane requires documents.embed = true"))?;
        let query_embedding = embedder
            .embed(&params.query)
            .map_err(|e| CliError::Other(format!("embed query: {e}")))?;

        let hits = self
            .lance_store
            .search_documents(scope, query_embedding, top_k.saturating_mul(2), None)
            .map_err(|e| CliError::Other(format!("vector search: {e}")))?;

        let mut lane_hits = Vec::new();
        for (rank, hit) in hits.into_iter().enumerate() {
            // Get tier from metadata (simplified - in production would look up)
            let tier = SensitivityTier::High;

            lane_hits.push(LaneHit {
                doc_id: hit.path,
                snippet: hit.text.chars().take(200).collect::<String>(),
                tier,
                connector: "lance".to_string(),
                lane: "vector",
                rank: rank + 1,
            });
        }

        Ok(lane_hits)
    }

    /// Lexical search lane via basemind's FTS.
    #[cfg(feature = "basemind")]
    async fn lexical_search_lane(
        &self,
        params: &SearchParams,
        scope_predicate: String,
        top_k: usize,
    ) -> Result<Vec<LaneHit>> {
        let terms: Vec<String> = params
            .query
            .split_whitespace()
            .map(str::to_string)
            .collect();

        let max_relaxations = self.config.documents.fusion.max_relaxations;
        let limit = top_k.saturating_mul(2);

        let lance_store = self.lance_store.clone();
        let scope_pred = scope_predicate;

        let hits = tokio::task::spawn_blocking(move || {
            basemind::lance::fts::search_relaxed_on(
                &lance_store,
                &terms,
                &scope_pred,
                limit,
                max_relaxations,
            )
        })
        .await
        .map_err(|e| CliError::Other(format!("spawn_blocking: {e}")))?
        .map_err(|e| CliError::Other(format!("lexical search: {e}")))?;

        let mut lane_hits = Vec::new();
        for (rank, hit) in hits.into_iter().enumerate() {
            let tier = SensitivityTier::High; // Simplified - would look up from metadata

            lane_hits.push(LaneHit {
                doc_id: hit.path,
                snippet: hit.text.chars().take(200).collect::<String>(),
                tier,
                connector: "lance".to_string(),
                lane: "keyword",
                rank: rank + 1,
            });
        }

        Ok(lane_hits)
    }

    /// RRF fusion using basemind's RRF module (when available) or built-in fallback.
    fn rrf_fuse(&self, lane_hits: Vec<LaneHit>) -> Result<Vec<SearchResult>> {
        #[cfg(feature = "basemind")]
        {
            self.rrf_fuse_with_basemind(lane_hits)
        }
        #[cfg(not(feature = "basemind"))]
        {
            self.rrf_fuse_builtin(lane_hits)
        }
    }

    #[cfg(feature = "basemind")]
    fn rrf_fuse_with_basemind(&self, lane_hits: Vec<LaneHit>) -> Result<Vec<SearchResult>> {
        use basemind::search::rrf::{
            FusionLane, LANE_EXACT, LANE_KEYWORD, LANE_VECTOR, rrf_fuse_detailed,
        };

        // Honor documents.fusion.k / .weights so FusionConfig actually takes
        // effect; fall back to basemind's document-tier defaults otherwise.
        let fusion = &self.config.documents.fusion;
        let weights = match &fusion.weights {
            Some(w) => basemind::search::rrf::FusionWeights {
                exact: w.exact,
                vector: w.vector,
                keyword: w.keyword,
                facet: w.facet,
            },
            None => basemind::search::rrf::FusionWeights::document_lanes(),
        };

        // Group hits by lane
        let mut bm25_ids = Vec::new();
        let mut vector_ids = Vec::new();
        let mut keyword_ids = Vec::new();

        // Build lookup for hit details. The BM25 lane is first and the only one
        // carrying the real tier/connector; keep the FIRST entry per doc.
        let mut hit_details: HashMap<String, (String, SensitivityTier, String)> = HashMap::new();

        for hit in lane_hits {
            let key = hit.doc_id.clone();
            hit_details
                .entry(key.clone())
                .or_insert((hit.snippet, hit.tier, hit.connector));

            match hit.lane {
                "bm25" => bm25_ids.push(key),
                "vector" => vector_ids.push(key),
                "keyword" => keyword_ids.push(key),
                _ => {}
            }
        }

        // Build fusion lanes with document-tier weights (keyword > vector)
        let lanes = vec![
            FusionLane::new(LANE_EXACT, &[], weights.exact), // Exact lane not used yet
            FusionLane::new(LANE_VECTOR, &vector_ids, weights.vector),
            FusionLane::new(LANE_KEYWORD, &bm25_ids, weights.keyword), // BM25 as keyword lane
            FusionLane::new(LANE_KEYWORD, &keyword_ids, weights.keyword),
        ];

        // Run RRF fusion with the configured k
        let fused = rrf_fuse_detailed(&lanes, fusion.k);

        // Convert to SearchResult
        let mut results = Vec::new();
        for hit in fused {
            if let Some((snippet, tier, connector)) = hit_details.get(&hit.chunk_id) {
                let matched_lanes: Vec<String> = hit
                    .lane_ranks
                    .iter()
                    .map(|(lane, _rank)| (*lane).to_string())
                    .collect();

                results.push(SearchResult {
                    doc_id: hit.chunk_id,
                    snippet: snippet.clone(),
                    score: hit.score,
                    tier: *tier,
                    connector: connector.clone(),
                    matched_lanes,
                });
            }
        }

        // Sort by score descending
        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());

        Ok(results)
    }

    /// Built-in RRF fusion (no basemind dependency).
    #[cfg(not(feature = "basemind"))]
    fn rrf_fuse_builtin(&self, lane_hits: Vec<LaneHit>) -> Result<Vec<SearchResult>> {
        // Honor documents.fusion so FusionConfig affects both build paths.
        let fusion = &self.config.documents.fusion;
        let k = fusion.k;
        let weights = fusion.weights.clone().unwrap_or_default();

        let mut bm25_ids = Vec::new();
        let mut vector_ids = Vec::new();
        let mut keyword_ids = Vec::new();
        let mut hit_details: HashMap<String, (String, SensitivityTier, String)> = HashMap::new();

        for hit in lane_hits {
            let key = hit.doc_id.clone();
            hit_details
                .entry(key.clone())
                .or_insert((hit.snippet, hit.tier, hit.connector));

            match hit.lane {
                "bm25" => bm25_ids.push(key),
                "vector" => vector_ids.push(key),
                "keyword" => keyword_ids.push(key),
                _ => {}
            }
        }

        // Compute RRF scores manually. BM25 and FTS both ride the keyword
        // weight, matching the basemind fusion path.
        let mut scores: HashMap<String, f32> = HashMap::new();
        let mut matched_lanes_map: HashMap<String, Vec<String>> = HashMap::new();

        // BM25 lane (keyword weight)
        for (rank, doc_id) in bm25_ids.iter().enumerate() {
            let score = weights.keyword / (k + (rank + 1) as f32);
            *scores.entry(doc_id.clone()).or_insert(0.0) += score;
            matched_lanes_map
                .entry(doc_id.clone())
                .or_default()
                .push("bm25".to_string());
        }

        // Vector lane
        for (rank, doc_id) in vector_ids.iter().enumerate() {
            let score = weights.vector / (k + (rank + 1) as f32);
            *scores.entry(doc_id.clone()).or_insert(0.0) += score;
            matched_lanes_map
                .entry(doc_id.clone())
                .or_default()
                .push("vector".to_string());
        }

        // Keyword lane (keyword weight)
        for (rank, doc_id) in keyword_ids.iter().enumerate() {
            let score = weights.keyword / (k + (rank + 1) as f32);
            *scores.entry(doc_id.clone()).or_insert(0.0) += score;
            matched_lanes_map
                .entry(doc_id.clone())
                .or_default()
                .push("keyword".to_string());
        }

        // Convert to SearchResult
        let mut results: Vec<SearchResult> = scores
            .into_iter()
            .map(|(doc_id, score)| {
                let (snippet, tier, connector) =
                    hit_details.get(&doc_id).cloned().unwrap_or_default();
                let matched_lanes = matched_lanes_map.get(&doc_id).cloned().unwrap_or_default();
                SearchResult {
                    doc_id,
                    snippet,
                    score,
                    tier,
                    connector,
                    matched_lanes,
                }
            })
            .collect();

        // Sort by score descending
        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());

        Ok(results)
    }

    /// Cross-encoder rerank using ort with bge-reranker-v2-m3 ONNX model.
    async fn rerank(
        &self,
        #[cfg_attr(not(feature = "rerank"), allow(unused_variables))] query: &str,
        results: Vec<SearchResult>,
    ) -> Result<Vec<SearchResult>> {
        #[cfg(feature = "rerank")]
        {
            if results.is_empty() {
                return Ok(results);
            }

            // Check if reranker is enabled in config
            if !self.config.reranker.enabled {
                return Ok(results);
            }

            // Run model init + CPU-bound ONNX inference off the async executor:
            // reqwest::blocking panics inside a Tokio worker and predict()
            // blocks for the whole batch otherwise.
            let config = self.config.reranker.clone();
            let query = query.to_string();
            let snippets: Vec<String> = results.iter().map(|r| r.snippet.clone()).collect();

            let scores = tokio::task::spawn_blocking(move || {
                let reranker = Reranker::get_or_init(&config)?;
                let doc_refs: Vec<&str> = snippets.iter().map(String::as_str).collect();
                reranker.predict(&query, &doc_refs)
            })
            .await
            .map_err(|e| anyhow::anyhow!("rerank task failed: {e}"))??;

            // Combine results with new scores (predict validated the count).
            let mut reranked: Vec<SearchResult> = results
                .into_iter()
                .zip(scores)
                .map(|(mut r, score)| {
                    r.score = score;
                    r
                })
                .collect();

            // Sort by new score descending
            reranked.sort_by(|a, b| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            Ok(reranked)
        }

        #[cfg(not(feature = "rerank"))]
        {
            // Rerank feature not enabled, return results unchanged
            Ok(results)
        }
    }

    /// Get the Tantivy index for external access (e.g., folder_sync).
    pub fn tantivy_index(&self) -> &Index {
        &self.tantivy_index
    }

    /// Get reference to the LanceStore for advanced operations (optional, behind feature).
    #[cfg(feature = "basemind")]
    pub fn lance_store(&self) -> &basemind::lance::LanceStore {
        &self.lance_store
    }
}

#[cfg(test)]
mod tenant_path_tests {
    use super::*;
    use crate::config::{HaciendaConfig, TenantConfig};

    fn config_with_tenant(tenant_id: &str) -> HaciendaConfig {
        toml::from_str(&format!(
            "default_tenant = \"{tid}\"\n\
             [[tenants]]\ntenant_id = \"{tid}\"\nname = \"t\"\n",
            tid = tenant_id
        ))
        .unwrap()
    }

    fn extra_tenant(tenant_id: &str) -> TenantConfig {
        TenantConfig {
            tenant_id: tenant_id.into(),
            folder_roots: Vec::new(),
            name: tenant_id.into(),
            lance_dir: None,
            tantivy_dir: None,
            vault_dir: None,
            encryption: None,
            kms: None,
            active: true,
        }
    }

    /// Unique per-test temp directory; cleaned up on drop (LanceDB paths only).
    #[cfg(feature = "basemind")]
    struct TempDir(std::path::PathBuf);

    #[cfg(feature = "basemind")]
    impl TempDir {
        fn new(label: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("hacienda-srch-{}-{}", label, std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    #[cfg(feature = "basemind")]
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The manager keys engines strictly by the requested (authorized) tenant —
    /// one engine per active tenant, and no engine exists for an unknown tenant
    /// (issue #22, acceptance 4/6).
    #[tokio::test]
    async fn manager_creates_engine_per_requested_tenant() {
        let mut config = config_with_tenant("slice-a");
        config.tenants.push(extra_tenant("slice-b"));
        let manager = TenantSearchEngineManager::new(config).await.unwrap();

        assert_eq!(manager.get_engine("slice-a").unwrap().tenant_id(), "slice-a");
        assert_eq!(manager.get_engine("slice-b").unwrap().tenant_id(), "slice-b");
        // An unknown tenant never mints an engine; the surface fails closed
        // before any storage access and reports a generic denial.
        assert!(manager.get_engine("ghost").is_none());
    }

    /// Default tenant: `default_engine` is bound to the configured default and
    /// must not leak an engine of a different tenant. (issue #22, acceptance 6)
    #[tokio::test]
    async fn default_engine_is_the_configured_default_tenant() {
        let config = config_with_tenant("only");
        let manager = TenantSearchEngineManager::new(config).await.unwrap();
        assert_eq!(manager.default_engine().unwrap().tenant_id(), "only");
        assert!(manager.get_engine("other").is_none());
    }

    /// Opening tenant A must touch only tenant A's LanceDB directory and never
    /// create or read tenant B's or the default tenant's path. Every tenant is
    /// given an explicit temp directory, so no tenant ever touches the shared
    /// default location under `~/.local/share/hacienda`. (issue #22, acceptance 2)
    #[cfg(feature = "basemind")]
    #[tokio::test]
    async fn opening_tenant_a_never_creates_default_or_b_lance_paths() {
        let tmp = TempDir::new("lanceiso");
        let dir_a = tmp.0.join("a");
        let dir_b = tmp.0.join("b");
        let dir_def = tmp.0.join("default");

        let mut config = config_with_tenant("slice-a");
        let tenant_conf = extra_tenant("slice-b");
        let tenant_a = config.tenants.get_mut(0).unwrap();
        tenant_a.lance_dir = Some(dir_a.to_string_lossy().into_owned());
        let mut tenant_b = tenant_conf;
        tenant_b.lance_dir = Some(dir_b.to_string_lossy().into_owned());
        config.tenants.push(tenant_b);
        // The default tenant gets its own explicit directory, so "untouched"
        // assertions are meaningful instead of colliding with tenant A's path.
        config.default_tenant = "slice-default".into();
        let mut tenant_default = extra_tenant("slice-default");
        tenant_default.lance_dir = Some(dir_def.to_string_lossy().into_owned());
        config.tenants.push(tenant_default);

        // Open ONLY tenant A's engine (exactly where `new_for_tenant` is the fix).
        let _engine = SearchEngine::new_for_tenant(&config, "slice-a").await.unwrap();

        assert!(
            dir_a.exists(),
            "tenant A's requested LanceDB path must be opened/created"
        );
        for (label, dir) in [
            ("tenant B", dir_b.as_path()),
            ("default tenant", dir_def.as_path()),
        ] {
            assert!(
                !dir.exists(),
                "opening tenant A must not create the {label} LanceDB path"
            );
        }
    }
}

