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
//! 5. Cross-encoder rerank (optional, gated by SensitivityTier)
//!
//! Returns: tokenized snippets + doc IDs -- never raw PII.

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use tantivy::{
    collector::TopDocs,
    doc,
    query::QueryParser,
    schema::{Field, Schema, TEXT, STORED, Value},
    Index, IndexWriter,
    Document,
    TantivyDocument,
};
use serde::{Deserialize, Serialize};

use crate::{
    index_projection::{project_document, ProjectionConfig, SensitivityTier},
    CliError, HaciendaConfig,
};

/// Escape a string for use in a SQL literal (LanceDB predicate).
fn escape_sql_literal(s: &str) -> String {
    s.replace('\'', "''")
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
    rank: usize,
}

/// Search engine combining BM25 (Tantivy) + Vector (LanceStore) + Lexical (FTS) with RRF fusion.
pub struct SearchEngine {
    config: HaciendaConfig,
    tantivy_index: Index,
    text_field: Field,
    doc_id_field: Field,
    connector_field: Field,
    tier_field: Field,
    projection_config: ProjectionConfig,

    #[cfg(feature = "basemind")]
    lance_store: basemind::lance::LanceStore,

    #[cfg(feature = "basemind")]
    embedder: basemind::embeddings::SharedEmbedder,
}

impl SearchEngine {
    /// Create a new search engine from configuration.
    pub async fn new(config: HaciendaConfig) -> Result<Self, CliError> {
        // Build Tantivy schema for BM25
        let mut schema_builder = tantivy::schema::Schema::builder();
        let text_field = schema_builder.add_text_field("text", TEXT | STORED);
        let doc_id_field = schema_builder.add_text_field("doc_id", TEXT | STORED);
        let connector_field = schema_builder.add_text_field("connector", TEXT | STORED);
        let tier_field = schema_builder.add_text_field("tier", TEXT | STORED);
        let schema = schema_builder.build();

        // Create in-memory Tantivy index for BM25
        let tantivy_index = Index::create_in_ram(schema.clone());

        let projection_config = ProjectionConfig::default();

        #[cfg(feature = "basemind")]
        let lance_store = {
            let lance_dir = config.lance_dir();
            let dim = config.embedding_dim();
            let embedding_model = config.embedding_model().to_string();
            basemind::lance::LanceStore::open(&lance_dir, dim, &embedding_model)
                .map_err(|e| CliError::Other(format!("open lance store: {e}")))?
        };

        #[cfg(feature = "basemind")]
        let embedder = {
            let preset = config.embedding_model();
            let batch_size = config.embedding_batch_size().unwrap_or(32);
            basemind::embeddings::SharedEmbedder::load(preset, 0, batch_size)
                .map_err(|e| CliError::Other(format!("load embedder: {e}")))?
        };

        Ok(Self {
            config,
            tantivy_index,
            text_field,
            doc_id_field,
            connector_field,
            tier_field,
            projection_config,
            #[cfg(feature = "basemind")]
            lance_store,
            #[cfg(feature = "basemind")]
            embedder,
        })
    }

    /// Index a document (called by folder_sync after extraction).
    pub async fn index_document(
        &self,
        doc_id: &str,
        content: &str,
        connector: &str,
        tier: SensitivityTier,
    ) -> Result<(), CliError> {
        // Project to class-stable tokens
        let projected = project_document(content);
        let projected_str = projected.to_string();

        // Index in Tantivy (BM25) - ALWAYS
        let mut index_writer: IndexWriter = self.tantivy_index.writer(50_000_000)?;
        index_writer.add_document(tantivy::doc!(
            self.text_field => &*projected_str,
            self.doc_id_field => doc_id,
            self.connector_field => connector,
            self.tier_field => format!("{:?}", tier),
        ))?;
        index_writer.commit()?;

        // Index in basemind's LanceStore (vector + FTS) - OPTIONAL, behind feature
        #[cfg(feature = "basemind")]
        {
            // Generate embedding for the projected content
            let embedding = self.embedder.embed(&projected_str)
                .map_err(|e| CliError::Other(format!("embed: {e}")))?;
            
            let doc_row = basemind::lance::DocumentRow {
                scope: self.config.scope().unwrap_or_else(|| "default".to_string()),
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
            
            self.lance_store.replace_document(
                &self.config.scope().unwrap_or_else(|| "default".to_string()),
                doc_id,
                vec![doc_row]
            ).map_err(|e| CliError::Other(format!("lance store: {e}")))?;
            
            // Build FTS index after ingest (batched, not per-doc in production)
            // basemind::lance::fts::build_index_after_ingest(&self.lance_store, &self.config.documents.fts)?;
        }

        Ok(())
    }

    /// Search with hybrid BM25 + Vector + Lexical + RRF fusion + optional rerank.
    pub async fn search(&self, params: SearchParams) -> Result<Vec<SearchResult>> {
        let top_k = params.top_k;
        let scope = self.config.scope().unwrap_or_else(|| "default".to_string());
        let scope_predicate = format!("scope = '{}'", escape_sql_literal(&scope));

        // Collect hits from all lanes
        let mut all_lane_hits: Vec<LaneHit> = Vec::new();

        // 1. BM25 search via Tantivy - ALWAYS
        let bm25_hits = self.bm25_search_lane(&params, &scope).await?;
        all_lane_hits.extend(bm25_hits);

        // 2. Vector search via basemind's LanceStore - OPTIONAL
        #[cfg(feature = "basemind")]
        {
            let vector_hits = self.vector_search_lane(&params, &scope).await?;
            all_lane_hits.extend(vector_hits);
        }

        // 3. Lexical search via basemind's FTS - OPTIONAL
        #[cfg(feature = "basemind")]
        {
            let lexical_hits = self.lexical_search_lane(&params, scope_predicate.clone()).await?;
            all_lane_hits.extend(lexical_hits);
        }

        // 4. RRF fusion using basemind's RRF module
        let fused = self.rrf_fuse(all_lane_hits, top_k)?;

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

    /// BM25 search lane via Tantivy.
    async fn bm25_search_lane(&self, params: &SearchParams, _scope: &str) -> Result<Vec<LaneHit>> {
        let reader = self.tantivy_index.reader()?;
        let searcher = reader.searcher();

        let query_parser = QueryParser::for_index(&self.tantivy_index, vec![self.text_field]);

        let query_str = if let Some(filter) = &params.filter {
            if let Some(connector) = &filter.connector {
                format!("{} connector:{}", params.query, connector)
            } else {
                params.query.clone()
            }
        } else {
            params.query.clone()
        };

        let query = query_parser.parse_query(&query_str)?;

        let top_docs = searcher.search(&query, &TopDocs::with_limit(params.top_k * 2))?;

        let mut hits = Vec::new();
        for (rank, (_score, doc_address)) in top_docs.into_iter().enumerate() {
            let doc: tantivy::TantivyDocument = searcher.doc(doc_address).unwrap();

            let doc_id = doc.get_first(self.doc_id_field)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let snippet = doc.get_first(self.text_field)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let connector = doc.get_first(self.connector_field)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let tier_str = doc.get_first(self.tier_field)
                .and_then(|v| v.as_str())
                .unwrap_or("High");

            let tier = match tier_str {
                "Minimal" => SensitivityTier::Minimal,
                "Low" => SensitivityTier::Low,
                "High" => SensitivityTier::High,
                _ => SensitivityTier::HardBlock,
            };

            // Check tier filtering
            if !self.projection_config.should_index(&format!("<{}>", tier_str)) {
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
    async fn vector_search_lane(&self, params: &SearchParams, scope: &str) -> Result<Vec<LaneHit>> {
        let query_embedding = self.embedder.embed(&params.query)
            .map_err(|e| CliError::Other(format!("embed query: {e}")))?;
        
        let hits = self.lance_store.search_documents(
            scope,
            query_embedding,
            params.top_k * 2,
            None,
        ).map_err(|e| CliError::Other(format!("vector search: {e}")))?;

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
    async fn lexical_search_lane(&self, params: &SearchParams, scope_predicate: String) -> Result<Vec<LaneHit>> {
        let terms: Vec<String> = params.query.split_whitespace().map(str::to_string).collect();
        
        let max_relaxations = self.config.documents.fusion.max_relaxations;
        let limit = params.top_k * 2;
        
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
    fn rrf_fuse(&self, lane_hits: Vec<LaneHit>, _top_k: usize) -> Result<Vec<SearchResult>> {
        #[cfg(feature = "basemind")]
        {
            use basemind::search::rrf::{
                rrf_fuse_detailed, FusionLane, FusionWeights, LANE_EXACT, LANE_VECTOR, LANE_KEYWORD, DEFAULT_RRF_K,
            };
            self.rrf_fuse_with_basemind(lane_hits, DEFAULT_RRF_K)
        }
        #[cfg(not(feature = "basemind"))]
        {
            self.rrf_fuse_builtin(lane_hits)
        }
    }

    #[cfg(feature = "basemind")]
    fn rrf_fuse_with_basemind(&self, lane_hits: Vec<LaneHit>, k: f32) -> Result<Vec<SearchResult>> {
        use basemind::search::rrf::{
            rrf_fuse_detailed, FusionLane, FusionWeights, LANE_EXACT, LANE_VECTOR, LANE_KEYWORD,
        };

        // Group hits by lane
        let mut bm25_ids = Vec::new();
        let mut vector_ids = Vec::new();
        let mut keyword_ids = Vec::new();

        // Build lookup for hit details
        let mut hit_details: HashMap<String, (String, SensitivityTier, String)> = HashMap::new();

        for hit in lane_hits {
            let key = hit.doc_id.clone();
            hit_details.insert(key.clone(), (hit.snippet, hit.tier, hit.connector));

            match hit.lane {
                "bm25" => bm25_ids.push(key),
                "vector" => vector_ids.push(key),
                "keyword" => keyword_ids.push(key),
                _ => {}
            }
        }

        // Build fusion lanes with document-tier weights (keyword > vector)
        let weights = FusionWeights::document_lanes();
        let mut lanes = vec![
            FusionLane::new(LANE_EXACT, &[], weights.exact), // Exact lane not used yet
            FusionLane::new(LANE_VECTOR, &vector_ids, weights.vector),
            FusionLane::new(LANE_KEYWORD, &bm25_ids, weights.keyword), // BM25 as keyword lane
        ];

        // Also add keyword lane from FTS if available
        #[cfg(feature = "basemind")]
        {
            lanes.push(FusionLane::new(LANE_KEYWORD, &keyword_ids, weights.keyword));
        }

        // Run RRF fusion
        let fused = rrf_fuse_detailed(&lanes, DEFAULT_RRF_K);

        // Convert to SearchResult
        let mut results = Vec::new();
        for hit in fused {
            if let Some((snippet, tier, connector)) = hit_details.get(&hit.chunk_id) {
                let matched_lanes: Vec<String> = hit.lane_ranks.iter()
                    .map(|(lane, _rank)| (*lane).to_string())
                    .collect();

                results.push(SearchResult {
                    doc_id: hit.chunk_id,
                    snippet: snippet.clone(),
                    score: hit.score,
                    tier: tier.clone(),
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
        // Simple RRF implementation without basemind
        const K: f32 = 60.0;
        
        let mut bm25_ids = Vec::new();
        let mut vector_ids = Vec::new();
        let mut keyword_ids = Vec::new();
        let mut hit_details: HashMap<String, (String, SensitivityTier, String)> = HashMap::new();

        for hit in lane_hits {
            let key = hit.doc_id.clone();
            hit_details.insert(key.clone(), (hit.snippet, hit.tier, hit.connector));

            match hit.lane {
                "bm25" => bm25_ids.push(key),
                "vector" => vector_ids.push(key),
                "keyword" => keyword_ids.push(key),
                _ => {}
            }
        }

        // Compute RRF scores manually
        use std::collections::HashMap;
        let mut scores: HashMap<String, f32> = HashMap::new();
        let mut matched_lanes_map: HashMap<String, Vec<String>> = HashMap::new();

        // BM25 lane (weight 2.0)
        for (rank, doc_id) in bm25_ids.iter().enumerate() {
            let score = 2.0 / (K + (rank + 1) as f32);
            *scores.entry(doc_id.clone()).or_insert(0.0) += score;
            matched_lanes_map.entry(doc_id.clone()).or_default().push("bm25".to_string());
        }

        // Vector lane (weight 1.0)
        for (rank, doc_id) in vector_ids.iter().enumerate() {
            let score = 1.0 / (K + (rank + 1) as f32);
            *scores.entry(doc_id.clone()).or_insert(0.0) += score;
            matched_lanes_map.entry(doc_id.clone()).or_default().push("vector".to_string());
        }

        // Keyword lane (weight 2.0)
        for (rank, doc_id) in keyword_ids.iter().enumerate() {
            let score = 2.0 / (K + (rank + 1) as f32);
            *scores.entry(doc_id.clone()).or_insert(0.0) += score;
            matched_lanes_map.entry(doc_id.clone()).or_default().push("keyword".to_string());
        }

        // Convert to SearchResult
        let mut results: Vec<SearchResult> = scores
            .into_iter()
            .map(|(doc_id, score)| {
                let (snippet, tier, connector) = hit_details.get(&doc_id).cloned().unwrap_or_default();
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

    /// Cross-encoder rerank (placeholder - will use ort with bge-reranker-v2-m3).
    async fn rerank(
        &self,
        _query: &str,
        results: Vec<SearchResult>,
    ) -> Result<Vec<SearchResult>> {
        // TODO: Implement cross-encoder reranking using ort
        // Load bge-reranker-v2-m3 ONNX model
        // Run query x doc inference
        // Re-score and re-order
        Ok(results)
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
mod tests {
    use super::*;
    use crate::HaciendaConfig;

    #[tokio::test]
    async fn test_search_engine_bm25_only() {
        let config = HaciendaConfig::default();
        let engine = SearchEngine::new(config).await.unwrap();
        
        engine.index_document("doc1", "John Smith lives at 123 Main St", "filesystem", SensitivityTier::High).await.unwrap();
        engine.index_document("doc2", "Jane Doe works at Acme Corp", "filesystem", SensitivityTier::Low).await.unwrap();
        
        let params = SearchParams {
            query: "John Smith".to_string(),
            top_k: 10,
            rerank: false,
            filter: None,
        };
        
        let results = engine.search(params).await.unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].doc_id, "doc1");
    }
}