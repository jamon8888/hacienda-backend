# ADR-0008: Evidence ledger and anchoring

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** owner (jamon8888)
- **Related:** ADR-0003, ADR-0005, ADR-0006, ADR-0007

## Context

Professional secrecy requires evidence that policy gates and provider egress were applied without creating another store of sensitive content. Ordinary logs and audit arguments can accidentally retain prompts, values, tokens, maps, or snapshots. Integrity evidence must therefore be metadata-only and independently verifiable.

## Decision

Implement a SQLite metadata-only ledger with a hash chain and Ed25519 signatures. Records contain operation identifiers, timestamps, tenant and policy fingerprints, hashes, counts, classes, result codes, and lifecycle metadata—never raw arguments, values, prompts, queries, errors, tokens, reversible maps, manifests, snapshots, or document content. Sign epochs, define retention and legal-hold behavior, and fail closed or mark the operation failed when a required write cannot complete.

Support optional RFC3161 TSA and Sigstore Rekor anchoring for signed epoch commitments. Export a signed audit pack containing allowlisted ledger/audit metadata and anchor references. Provide an offline verifier that checks signatures, chain continuity, epoch commitments, and pack integrity. Seeded corpus tests enforce the no-PII invariant, including negative checks that no raw value or token is present in a record or export.

The ledger is separate from the Gaze manifest, owner vault, canonical token-only transcript, and operational audit. It proves the integrity and recorded policy outcome of traffic that passed through the Hacienda Gateway and MCP gate, plus the continuity of exported evidence. It does not prove that bypass traffic was safe, that an unobserved host action did not occur, or that a fully compromised host/user account was secure; stronger isolation is required for those claims.

## Consequences

Ledger schema, signing-key custody, epoch rotation, retention, legal hold, anchor availability, and required-write failure semantics become release contracts. Anchoring is optional evidence strengthening, not a substitute for local signatures or gateway/gate coverage. “WORM” is not claimed without an external immutable retention target.

## Current gap

No production ledger, signed epochs, RFC3161/Rekor integration, audit-pack exporter, offline verifier, or seeded no-PII ledger test is shipped yet.
