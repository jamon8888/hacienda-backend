# ADR-0004: The class-stable projection is the only indexed form

- **Status:** Accepted
- **Date:** 2026-10-24
- **Deciders:** owner (jamon8888) with research from gaze#5
- **Related:** ADR-0001, ADR-0002; basemind ADR-0015

## Context

Nothing in basemind's retrieval stack is tuned to the `[TYPE_N]` grammar — the pipeline already embeds
and BM25-scores redacted token text. But not every redaction spelling is indexable:

- Gaze's native session tokens carry a per-session distinguishing part (`<{session_hex}:{Class}_{n}>`);
  embedding them means the same underlying value projects differently across sessions and the
  document-blob cache is poisoned (never cache-hits, never deduplicates).
- Format-preserving fakes (e.g. `email1.<hex>@gaze-fake.invalid`) are domain-shaped strings that add
  BPE noise and hit the lexical index as nearly-real text — the worst of both worlds for BM25.

Suppression tiers (SensitivityTier) attach post-rerank via `suppress_by_sensitivity` and are keyed by
class label, not token string, so the reranker itself is shape-agnostic. Byte ranges, however, are only
canonical in original-document offsets: gaze output offsets ride the manifest (raw↔clean spans) because
gaze tokens are shape-preserving but not length-preserving.

## Decision

**Embed and index exactly one projection: the class-stable projection (`<Class_…>` spelling), computed
from the gaze policy vocabulary at the engine layer before chunking. BM25 scores the same projection.**
Rules:

- Raw session tokens never reach the index or a persisted blob.
- Format-preserving fakes never reach the lexical index.
- Suppression tier mapping from gaze PiiClass is fail-closed by default:
  Name/Location/Organization → MINIMAL, Email → LOW, **Custom → HIGH** unless mapped otherwise,
  credential-shaped customs → HARD_BLOCK. Downgrades are explicit table entries, never inferred.
- Byte ranges are canonical only in original-document offsets; consumers needing raw↔clean spans take
  them from the manifest (ADR-0002).
- Index rebuilds key on the engine-era fingerprint: when the fingerprint changes, xberg-era and gaze-era
  blobs never mix — stale blobs are detected and rebuilt, never reused.

## Consequences

- The bridge layer owns the projection step (see spec §6); gaz things like `gaze-token-bridge`'s
  domain-alias template exist in-tree and are referenced, not invented here.
- The blob cache regains deduplication across sessions; embedding cost drops accordingly.
- The tier table lives beside the fingerprint config so a policy change is visibly also a rebuild.
- Class-stable excepts are auditable: every persisted embedding is traceable to a document-fingerprint
  + class pair.

## Alternatives considered

- **Index raw session tokens** — rejected: non-deterministic per session; kills the blob cache and
  cross-session stability of embeddings.
- **Index format-preserving fakes** — rejected: BM25 ranks near-real text; lexical leakage surface.
- **Embed original values** — rejected outright: the human-ward invariant (ADR-0003) makes real values
  an input to indexing only for the manifest, never for any agent-scoped store.
