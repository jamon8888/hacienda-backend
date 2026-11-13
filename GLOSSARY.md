# Glossary

Gaze × basemind composed-system vocabulary for the production target. Definitions distinguish target
contracts from the currently incomplete scaffold; implementation details and decisions remain in the
architecture spec and ADRs.

## Engine-era fingerprint

A record of the detection engine, token-grammar version, redaction configuration, and document identity
that produced a store generation. Every manifest, encrypted SensitiveSnapshot, xberg TokenReplace map,
and agent-visible index generation bound to a document shares this fingerprint; a mismatch blocks use.

## Class-stable projection

A deterministic spelling of pseudonymization tokens in which each PII class renders identically across
documents and sessions. It is the only form eligible for agent-visible indexing. Session-scoped tokens,
format-preserving fakes, and original values are not projections.

## Human disclosure

An owner-authorized presentation of a recovered real value to a human in a trusted human-only viewing
context. Human disclosure never means returning the value to an agent, an MCP caller, or an agent-visible
log, index, query, or error.

## Disclosure request

A pending, owner-reviewable request to disclose selected pseudonymized content. A request has opaque
identity and allowlisted status metadata only; its interface cannot return raw values or restore material.

## Owner vault / restore material

The encrypted owner-controlled custody of material required for strict recovery: the Gaze SensitiveSnapshot
and session material, the xberg TokenReplace map, and their manifest/document/engine fingerprint bindings.
A Gaze manifest or provenance record alone is not restore authority.

## Agent bundle

The data bundle available to an agent through MCP: class-stable projections plus allowlisted document,
class, ranking, and lifecycle metadata. It excludes raw PII, restore material, reversible tokens, maps,
snapshots, manifests, and raw queries or errors.

## Agent-visible projection

The class-stable, metadata-only representation derived after Gaze redaction and before indexing or MCP
output. Every ingestion path must apply this projection before persistence in an agent-scoped store.

## Human-ward rehydration

A legacy name for human disclosure: recovery toward the owner only, never through an MCP route. In the
production contract, the owner-controlled sidecar and secure viewer are the primary path; a controlled
interactive CLI is a migration/recovery fallback and is not a security boundary.

## Dual store

The restore-data topology in which one detection pass writes a provenance-canonical Gaze manifest and
separately encrypted owner restore material: Gaze SensitiveSnapshot/session material and xberg's
operational TokenReplace map. All artifacts are atomically persisted under one fingerprint; the manifest
alone cannot restore.

## Token minting

The act of generating the token string for a finding. In this composition it belongs to xberg's
TokenCounter over Gaze findings — Gaze detects, xberg mints. Ownership matters because token length bakes
into chunk byte ranges and the TokenReplace map's key.

## Stateful proxy/gateway

The production boundary that maintains authenticated session, tenant, policy, sequencing, and transcript
state while routing client requests. It is not a transparent MITM: it may adapt protocols but must never
become a raw-value path or receive restore material solely because it proxies traffic.

## Authoritative token-only transcript

The canonical durable record of requests, responses, events, errors, and relevant lifecycle metadata.
It contains class-stable tokens and allowlisted metadata only. Raw PII, reversible tokens, restore
material, raw queries, and raw errors are forbidden. Replay and recovery semantics must use this record,
not an incidental transport log.

## Token-only MCP

The MCP contract in which every tool, resource, prompt, result, error, and MCP-visible log is limited to
class-stable tokens, opaque handles, and allowlisted metadata. Rehydration is not an MCP capability.

## Egress validator

The final fail-closed policy check before data is returned to a client/agent or written to a durable
agent-visible transcript, log, or index. It rejects raw values, restore material, disallowed tokens, and
non-allowlisted metadata regardless of which upstream component produced them.

## Durable index

A crash-safe, persisted search index generation bound to document, tenant, policy, and engine-era
fingerprints. BM25 and optional vector/lexical indexes may use in-memory caches, but a cache is not the
authoritative index and must be rebuildable from approved token-only input.

## Client parity

The requirement that Claude Code, Codex, CLI, and supported protocol adapters receive the same token-only
semantics, disclosure boundaries, validation, and fail-closed behavior. A client-specific workaround is
not production parity.

## Explicit non-goals

Raw PII in MCP, transcripts, indexes, logs, queries, errors, or agent-visible storage; transparent MITM
inspection; agent-initiated rehydration; implicit owner fallback; unattended approval; and using the
TypeScript extension as a security or recovery boundary are outside the production target.

## Provider egress gateway

The Hacienda loopback reverse proxy at `127.0.0.1:8787`, selected through provider `BASE_URL` settings, and the only permitted provider egress. It allowlists hosts, pins TLS, validates SSE and attachments, and permits only tokenized prompts, history, tool traffic, and results. It is not a generic MITM or CA-injection design.

## MCP gate

The closed-manifest JSON-RPC interceptor in front of the Hacienda MCP backend. It locks tool schemas, rejects drift, can apply policy and DSSE exact-call approval for side effects, enforces idempotency, and fails closed. It never rehydrates; `attach_local_doc` accepts only processed paths under allowed roots and returns a tokenized clean reference.

## Pseudonymized workspace

An explicitly allowed local or mounted network folder whose documents have passed xberg MIME/OCR extraction and fail-closed Gaze processing. Agents receive only clean/class-stable references through MCP, not raw file-tool access.

## Inbox

The watched local upload folder used as a layered control because Claude Desktop's native `+` picker is not officially plugin-hookable. The gateway sanitizes or blocks attachments, and MCP attachment is available through `attach_local_doc`.

## Evidence ledger

A proposed SQLite hash-chain and Ed25519 metadata-only record of gateway/gate traffic, signed epochs, retention/legal-hold state, and verification metadata. It contains fingerprints, hashes, counts, and classes, never raw values or content.

## Audit pack

A signed export of allowlisted evidence-ledger and audit metadata suitable for offline verification. It does not contain prompts, arguments, values, tokens, maps, snapshots, or content.

## Anchored epoch

A signed ledger epoch whose hash or Merkle commitment may additionally be published to an RFC3161 TSA or Sigstore Rekor. Anchoring supports later integrity verification; it does not prove traffic that bypassed the gateway or protect a compromised host.
