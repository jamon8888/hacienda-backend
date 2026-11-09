# ADR-0002: Dual store written once, gated by one engine-era fingerprint

- **Status:** Accepted
- **Date:** 2026-10-24
- **Deciders:** owner (jamon8888) via wayfinder grilling (HITL, live)
- **Related:** ADR-0001, ADR-0003, ADR-0004; basemind ADR-0015

## Context

Two stores already exist and each earns its keep:

- Basemind's vault rehydration map is deliberately minimal — a persisted
  `HashMap<String, String>` (token → original value) in the pinned `XPII\x01` format, consumed by the
  TypeScript side. It cannot go away without breaking pinned consumers.
- Gaze's manifest is the *rich* record — evidence tiers, `decided_by: ConflictTier`, validator fail
  reasons, ambiguity records, collision families — but is session-shaped and carries no token strings.
  Gaze daemon session manifests are additionally transient (LRU + idle eviction): they are never trusted
  across sessions, which is exactly wrong for a long-lived RAG index.

Cross-store translation is lossy in both directions (map → manifest cannot reconstruct provenance;
manifest → map cannot always reconstruct token strings), so "derive one from the other after the fact"
is not safe.

## Decision

**One detection pass writes both stores, once, under a single engine-era fingerprint.** The fingerprint
is the tuple `engine id × token-grammar version × redaction config`, persisted with every store
generation. Per ingest run:

- the **gaze manifest** is written to a persistent, owner-held store keyed by document id
  (canonical provenance; not restore authority and not the durable operational audit);
- encrypted Gaze SensitiveSnapshot/session material and the encrypted **xberg TokenReplace map** are
  written atomically as the jointly required restore material (`XPII\x01` map form for basemind flows).

The manifest, snapshot/session material, and TokenReplace map are all bound to the same document/content/
tenant/engine-era/policy fingerprint. There is no second write path, so drift is structurally impossible. A fingerprint mismatch blocks
cross-generation reuse (reads fail closed) and triggers an index rebuild per ADR-0004's policy. Offsets
are persisted with the explicit `Utf8Bytes` encoding selected at composition time (xberg's default is
code points), and no post-hoc token renames are permitted once persisted, because token length
determines chunk `byte_end` (basemind ADR-0015).

## Consequences

- Keys and storage live owner-side (see ADR-0003): macOS Keychain custody, encrypted recovery export;
  fixed passphrases and insecure fallbacks are dev/test-only.
- Index blobs and all restore/provenance stores carry the fingerprint; rebuild tooling keys on it.
- Durable operational audit is separate metadata-only data, not a restatement of the manifest and not a
  source of restore material.
- The bridge repo owns the fingerprint computation and the consistency checks, in one place.
- Multi-turn/projects flows keep working: gaze daemon sessions reference the persistent stores via
  projections, never store restore data themselves.

## Alternatives considered

- **Gaze manifest as the single store, vault map derived on demand** — rejected: `XPII\x01` is a pinned
  consumer contract, and on-demand derivation diverges from every operation basemind already performs.
- **Vault-only writes, gaze audit rows as sole provenance** — rejected: cheapest, but loses spans,
  evidence tiers and conflict records; a later forensic restore or leak analysis fails.
- **Dual-write with two independent write paths** — rejected: the whole point is *one* write path;
  two paths reintroduce the drift this ADR exists to prevent.

## Operational boundary addendum

The dual-store write is reached only from an allowed local or mounted network folder after watched-root xberg MIME/OCR extraction and fail-closed Gaze processing. The encrypted vault, provenance manifest, xberg map, and `clean.md`/class-stable projection carry the same document/content/tenant/engine-era/policy binding. Folder-sync bypass, disconnected roots, and in-memory-only index state are current implementation gaps, not exceptions to this decision.
