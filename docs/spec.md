# Architecture spec — gaze-powered PII-safe document backend for Claude

Status: **normative target locked; implementation not complete** (wayfinder map `jamon8888/gaze#1`).
The production target is a stateful local proxy/gateway with proxy-owned MCP, a canonical token-only
transcript, and a final egress validator. ADR-0005 remains **Proposed**, not shipped. Current raw MCP,
implicit owner fallback, fixed-key custody, stdout/`--yes` paths, and the missing proxy controls are
noncompliant implementation gaps.

This document is the canonical production contract. It separates the approved target from the current
repository state: **implemented** means present and covered by the current supported path, **partial**
means a seam or primitive exists but the end-to-end production contract is not proven, and **planned**
means the target is documented but not shipped. A configuration field, helper, or unit test is not by
itself evidence that a production capability is implemented.

## 1. Purpose and scope

Claude Code/Desktop works a folder of common office documents (basemind's 90+ format extractors):
extract → redact (gaze engine) → index → agent-searchable RAG, with **raw PII flowing human-ward only**.
Local-first, single-user, one folder tree, macOS Keychain-custodied keys. `hacienda-backend` is a bridge
repo consuming gaze and basemind as dependencies — neither upstream is forked or patched for the primary path.

## 2. Trust boundary and invariants

- **Human-ward rehydration** ([ADR-0003]): no agent-facing surface — including MCP tools, resources,
  capabilities, results, status, errors, transcripts, or client history — ever carries rehydrated content.
  The agent sees only class-stable projections, allowlisted metadata, or opaque disclosure handles/status;
  owners disclose through the proposed (ADR-0005) HumanDisclosure sidecar/viewer target.
- **The stateful local proxy/gateway is the protocol boundary.** It owns the MCP endpoint, maintains the
  session and canonical transcript, and forwards only validated token-safe messages to the provider/client.
  The canonical transcript is token-only and is the source for replay, resume, audit references, and
  egress validation; it is not a raw-value cache.
- **Fail-closed everywhere:** plugin/processor errors are fatal in xberg terms (a degrade-to-regex fallback
  is a leak channel, not a convenience); store/key/fingerprint mismatches block operations.
- **Final egress validation is mandatory.** Before any response, tool result, error, event, or transcript
  update leaves the proxy, a validator rejects raw PII, restore material, and unapproved protocol fields.
  Validation is defense in depth, not a substitute for token-only ingress and storage.
- One-way gaze `[REDACTED:<class>]` markers surface to consumers as Drop-class findings — visible,
  never rehydratable, never indexed. Gaze is the exclusive detection/redaction ingress; no raw bypass
  reaches projection, indexing, MCP, the transcript, or an agent-visible store.

## 3. Release-blocking invariants

These invariants are normative and release-blocking (issues #15/#17 and the production-readiness plan). Each
must have an executable test or an operational gate with the stated outcome:

1. **Gaze-exclusive, fail-closed ingress.** Every persisted or searchable document enters through xberg
   extraction, Gaze detection/redaction, and class-stable projection; any Gaze, processor, or bypass failure
   rejects the operation and writes no indexable output.
2. **No raw PII on any agent-facing surface.** MCP tools/resources, capabilities, responses, snippets, status,
   errors, extensions, graph results, transcript entries, and client history contain no raw PII or restore
   material; tests scan every response and reject any raw value, query, token, map, snapshot, or manifest.
3. **Proxy-owned MCP and canonical transcript.** Clients connect to the stateful local proxy/gateway, not
   directly to a raw-capable backend. The proxy is the sole MCP owner, persists/replays only the canonical
   token-only transcript, and treats transcript or session-state failure as a failed operation.
4. **Final egress validation.** Every outbound MCP/provider/client message is validated at the final boundary,
   including errors and streaming fragments; a validator failure sends no message and fails closed.
5. **Human disclosure is owner-only and out of the agent channel.** The proposed ADR-0005 sidecar/viewer is
   the target: independent owner authentication and user presence render raw values only in the viewer,
   while MCP and the proxy receive only opaque handles/status. It is not shipped until this outcome is demonstrated.
6. **No embedded production secrets.** Production startup requires Keychain custody and rejects fixed keys,
   passphrases, and insecure fallbacks; custody failure blocks the operation.
7. **Tenant isolation and principal authorization.** Every read, write, rebuild, deletion, and audit/ledger
   lookup resolves an authorized principal-to-tenant binding; a payload tenant ID is never authorization, and
   cross-tenant access or mutation is rejected without sensitive error leakage.
8. **Durable restart state and deterministic rebuild.** Index generations, fingerprints, owner-vault artifacts,
   proxy session/transcript state, disclosure metadata, and audit survive restart and resume with the same
   bindings. Changes to engine era, document, tenant binding, or projection policy make the old generation
   unusable and trigger an explicit, observable rebuild; missing or partial state fails closed.
9. **Truthful capability claims.** Advertised tools, resources, capabilities, and documentation match the
   implemented surface; `rehydrate`, implicit owner fallback, and any unimplemented ADR-0005 control are not
   claimed as available.
10. **Fail-closed provider egress.** All provider traffic passes through the Hacienda Gateway; captured
   requests, responses, attachments, streams, logs, and errors contain no raw PII, and unknown providers,
   pinning failures, sanitizer failures, or unavailable gateway state block the operation.
11. **Independently verifiable evidence.** Durable audit and the separate disclosure ledger are metadata-only,
   allowlisted, hash-chained, and independently verifiable/anchorable; they retain no raw args/values/tokens/
   maps/snapshots/manifests/queries/errors/content, and required writes fail closed or mark the operation failed.

### Invariant implementation status

The following status is part of the contract and must be updated with implementation evidence, not merely
when a design is approved:

| Invariant | Current status | Required release evidence |
|---|---|---|
| 1. Gaze-exclusive, fail-closed ingress | Partial | End-to-end watched-root extraction, planted-span/class assertions, and negative bypass tests |
| 2. No raw PII on agent-facing surfaces | Partial, with noncompliant legacy paths | Direct Claude Code/Codex stdio and Streamable HTTP scans covering success, errors, status, snippets, and transcripts |
| 3. Proxy-owned MCP and canonical transcript | Planned | Proxy ownership, durable token-only replay/resume, and client-history suppression |
| 4. Final egress validation | Planned | Validation of every response, error, notification, and stream fragment with fail-closed send behavior |
| 5. Owner-only human disclosure | Planned; ADR-0005 Proposed | Independent owner/user-presence approval and secure viewer tests with no agent-readable raw destination |
| 6. No embedded production secrets | Partial | Production startup proves Keychain custody and rejects fixed keys, passphrases, and insecure fallbacks |
| 7. Tenant isolation and principal authorization | Partial | Positive and negative cross-tenant tests for every public read, write, rebuild, delete, status, and audit operation |
| 8. Durable restart state and deterministic rebuild | Partial | Restart/resume plus engine/projection/tenant drift tests that reject stale data and verify explicit rebuild |
| 9. Truthful capability claims | Partial, current direct MCP surface is not the closed production gate | Closed-manifest contract tests and documentation/advertised-capability parity |
| 10. Fail-closed provider egress | Planned | Gateway allowlist/TLS/SSE/attachment tests and captured-request no-PII scans |
| 11. Independently verifiable evidence | Partial | Durable audit plus separate disclosure ledger, hash-chain/signature/anchor verification, no-PII scans, and required-write failure tests |

## 4. Composition contract ([ADR-0001])

One detection pass: **gaze detects and owns provenance; xberg's TokenCounter mints the `[TYPE_N]` tokens**,
reproducing today's surface byte-for-byte. Gaze never emits tokens on the wire (its grammar is fixed and
shape-guarded). Integration seam: `xberg::register_post_processor` same-name replacement of the built-in
`"redaction"` Late processor (public; `extract_with_external_redaction` as the dual-engine alternative);
The target preserves basemind's capture → vault contract; the current path is not claimed to keep working
unchanged and remains subject to the implementation gaps below. Fork-patch fallback is documented but unused.

## 5. Store topology ([ADR-0002])

**Dual store, single write path.** Each ingest run under one engine-era fingerprint
(`engine id × token-grammar version × redaction config`) emits:
- the **gaze manifest** — canonical provenance (evidence tiers, conflict records, validator reasons),
  but neither restore authority nor durable audit;
- encrypted Gaze SensitiveSnapshot/session material plus the encrypted xberg TokenReplace map
  (`XPII\x01`, TS-pinned) — jointly required operational restore material for basemind flows.
All artifacts are atomically bound to document/content/tenant/engine-era/policy fingerprint and share
one fingerprint. Drift is structurally impossible; fingerprint mismatch blocks cross-era reuse and
triggers rebuild.
Offsets: explicit `Utf8Bytes` encoding; no post-hoc token renames once persisted (token length bakes into
chunk `byte_end`, basemind ADR-0015).

### Encryption and index-at-rest boundary

The MVP storage contract distinguishes application encryption from storage durability. Vault restore
material (the Gaze SensitiveSnapshot/session material and xberg map) is application-encrypted, with the
production data-encryption key wrapped/custodied by macOS Keychain. Keychain custody is a release
requirement; a passphrase, fixed key, or local fallback is not a production substitute. The encryption
helpers and configuration seams in this repository do not, by themselves, prove that the production
write path is wired.

Tantivy/LanceDB index-at-rest protection is a separate contract. The MVP does not claim a custom encrypted
Tantivy or LanceDB codec, nor does vault encryption implicitly protect an index. Until an index-specific
control and restart/recovery tests are shipped, index-at-rest protection and durable index persistence are
**partial/noncompliant** and must not be described as production-ready. A deployment must use an explicit,
documented storage protection control and fail closed when that control is required but unavailable.

## 6. Rehydration surface ([ADR-0003], [ADR-0005])

The proposed production target is a deep HumanDisclosure module with request/status/approve/deny/cancel/open-viewer,
served by an authenticated local sidecar and isolated secure viewer. Approval is independent,
owner-authenticated, OS/user-presence-backed, and cannot self-approve; spoofed clients are rejected.
This is ADR-0005's proposed target behavior, not a shipped capability; the current implementation remains
noncompliant until these controls exist.

Raw content goes only to the dedicated non-agent-readable viewer destination. Authenticated local IPC alone
is not isolation from a fully compromised same-user process; that residual risk is out of scope, but no-raw-MCP
is absolute. CLI rehydration + owner-only file export remains only an interactive migration/recovery fallback:
no raw stdout and no unattended `--yes`, and it is not a security boundary. Keychain custody is required in
production; fixed passphrases/insecure fallbacks are dev/test-only. No MCP tool/resource/capability returns raw text.
Durable operational audit and the disclosure ledger are separate metadata-only stores with allowlisted fields;
no raw args/values/tokens/maps/snapshots/manifests/queries/errors are retained.

### Closed MCP contract

The production MCP surface is authenticated and closed. The core tools are `search`, `sync`, and `status`;
`attach_local_doc`, `request_human_disclosure`, and `disclosure_status` are controlled boundary tools;
`graph_entities` and `graph_rag` are optional, feature-gated, and tenant-scoped. `doctor` is CLI-only.
There is no `rehydrate`, `restore`, or other raw-returning MCP tool, resource, capability, or fallback.

The principal is resolved from authenticated connection/session state, never from a caller-provided identity
or tenant field. Tenant selection is the intersection of the authenticated principal's authorized bindings
and the operation's server-side scope; a payload tenant ID can select only among already-authorized tenants
and can never grant authorization. Missing, ambiguous, spoofed, expired, or cross-tenant bindings fail
closed with non-sensitive errors. This contract remains a target until the closed MCP gate and its direct
Claude Code/Codex contract tests are shipped.

## 7. Index projection ([ADR-0004])

Embed and BM25 **only the class-stable projection** (`<Class_…>` spelling): raw session tokens poison the
blob cache; format-preserving fakes stay out of the lexical index. Cross-encoder rerank is shape-agnostic;
suppression tiers map from gaze PiiClass (Name/Location/Organization → MINIMAL, Email → LOW,
**Custom → HIGH fail-closed**, credential-shaped customs → HARD_BLOCK). Byte ranges are canonical in
original-document offsets; gaze-output offsets ride the manifest. Index rebuilds are keyed on the
engine-era fingerprint.

## 8. Accepted architecture constraints

- gaze audit/isolation gates (`no-tenant-knowledge`, audit-sink isolation, tokenbridge-* behavioral gates)
  are the composition's floor: the bridge must keep gaze's protected feature graphs clean.
- Detection *configs* composed here do not alter gaze rules — the gaze benchmark gain gate is not
  triggered by this repo; acceptance instead = zero raw bytes in agent surfaces + manifest restore
  round-trip on a representative corpus.
- A transparent HTTP/SOCKS or TLS MITM proxy is not this gateway: it can forward bytes but cannot establish
  token-only transcript state, own MCP semantics, or guarantee final egress validation. It may be used only
  as transport adaptation and must not be described as the security boundary.
- Stock Claude Code configuration cannot be treated as a security modification. A wrapper/mod that does not
  make the proxy the MCP owner, disable raw client persistence, and enforce final egress validation is not
  production compliant; provider-side history behavior remains an explicit deployment concern.

## 9. Workstreams (implementation epics, downstream of the spec)

1. **Bridge scaffold + plugin** — repo/CI; `GazeRedactor` PostProcessor (name `"redaction"`, stage Late,
   fatal-on-error); acceptance: Office/PDF corpus extracts with zero raw bytes in `ExtractedDocument`.
2. **Ingest integration** — gaze-assembly assembly from `basemind.toml` (`[redaction].engine = "gaze"`),
   dual-store writes, fingerprint computation, doctor checks (models present, Keychain unlocked, policy
   valid); acceptance: whole-index fingerprint match, restore round-trip on the representative corpus.
3. **Stateful proxy/gateway** — proxy-owned MCP, canonical token-only transcript with durable restart state,
   final egress validator, client-history suppression, and fail-closed streaming/error handling.
4. **Human disclosure surface (ADR-0005 Proposed target)** — implement the HumanDisclosure sidecar/viewer,
   interactive CLI migration/recovery fallback, per-export review, owner-only export folder, recovery export,
   metadata-only audit and disclosure ledger; acceptance: every event is allowlisted metadata, MCP surface
   provably projection/handle/status-only. This target is not shipped; it remains an implementation gap.
5. **Index projection + sync** — projection pre-chunking, BM25/vector split, tier mapping, byte-range canon,
   engine-era rebuild policy; acceptance: stale-blob detection on fingerprint change; tier behavior matches
   ADR-0004 table.

Each epic gets sliced in its own session (`/to-tickets`) against this spec.

The workspace is not yet production-compliant: raw MCP rehydrate, implicit owner fallback, fixed-key custody,
stdout/`--yes` assumptions, disconnected folder sync, unfiltered audit arguments, missing proxy-owned MCP,
non-canonical/raw transcript or ordinary client history, absent final egress validation, and the unimplemented
ADR-0005 HumanDisclosure sidecar/viewer (including user-presence approval and secure-viewer isolation) remain
implementation gaps. These are current behavior, not the normative target. Stock Claude Code and a transparent
proxy do not satisfy the target without the explicitly controlled wrapper/mod and stateful gateway.

## 10. Open questions (deferred deliberately)

Upstream contribution strategy (gaze as an xberg plugin is a candidate); eval & acceptance mapping
to basemind/gaze harnesses; eyes-only local viewer; per-entity single-use capability downgrades;
multi-tenant/folder-per-tenant growth. Tracked as fog on the wayfinder map.

## 11. References

Findings and resolutions (owner-side secret gists) are linked from each wayfinder ticket
(`jamon8888/gaze` issues #2–#6) and from the ADRs below. Glossary terms: `GLOSSARY.md` in this repo
(echoed in `~/gaze/GLOSSARY.md`).

## 12. Platform contract addendum: folders, gateway, and gates

Every local or network folder opened in Claude Desktop, Claude Code, Codex, or a supported adapter passes through the Hacienda app. Agent raw filesystem and file-tool access is prohibited entirely, both inside and outside any configured root; an allowlisted root is not an agent read permission. Roots are solely Hacienda ingestion/sync inputs (including SMB and NFS). Agents use only MCP tokenized document references and search results.

Folder sync watches the opened root and processes each change as `xberg extraction (MIME + OCR) -> Gaze fail-closed detection/redaction -> encrypted vault + manifest + xberg map -> clean.md/class-stable projection -> persistent per-tenant Tantivy/LanceDB`. The current disconnected folder-sync path, in-memory index, and any bypass are implementation gaps.

The Hacienda Gateway is the only provider egress. Clients set `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL` to `http://127.0.0.1:8787`; it allowlists provider hosts, pins upstream TLS, buffers/validates SSE, sanitizes attachments, and logs metadata only. It handles `/v1/messages` and `/v1/chat/completions`. Gaze tokenizes outbound prompts, history, tool calls/results, and attachments; the provider sees token-only content. Only a separate local UI may rehydrate for an authenticated owner, never the provider transcript. This is a base-URL reverse proxy, not generic MITM/CA injection. A client that pins or ignores `base_url` requires a custom client/fork and degrades the guarantee.

A JSON-RPC MCP gate fronts the Hacienda MCP backend. Its closed manifest exposes `search`, `sync`, `status`, `attach_local_doc`, and `request_human_disclosure`, `disclosure_status`; optional feature-gated tools are `graph_entities` and `graph_rag`. No other MCP tools are exposed: `doctor` is CLI-only and `rehydrate` is absent. Schemas are locked and drift is rejected. It never rehydrates. Optional Cedar-like policy, DSSE exact-call approvals for side effects, idempotency keys, and fail-closed error codes apply at the gate. `attach_local_doc` accepts only a previously processed path under an allowed root and returns a tokenized clean reference.

The loopback UI target is `127.0.0.1:8788`, authenticated and owner-local. It provides folder navigation, clean.md Markdown viewing/editing, search, Inbox upload, and audit views. Raw values appear only in a separate sidecar viewer after ADR-0005 owner authentication and user presence; the UI never feeds a provider transcript. Claude Desktop's native `+` picker is not officially hookable by a plugin: controls therefore layer a watched Inbox, gateway attachment extraction/redaction-or-blocking, `attach_local_doc`, and an optional mod warning.

Plugins/mods are UX and onboarding only, packaged as `bin/hacienda` plus `.mcp.json`. `prompt.submit` tokenizes the current prompt, `tool.call` sanitizes MCP results, and a pane may show sent-versus-local views. Official client documentation does not guarantee arbitrary UI content is excluded from all persisted or future API requests; the hard guarantee remains the gateway and authoritative token-only transcript.

## 13. Evidence and current implementation gaps

ADR-0008 proposes a SQLite hash-chain, Ed25519 metadata-only evidence ledger with signed epochs, optional RFC3161 TSA/Sigstore Rekor anchors, signed audit-pack export, offline verification, legal hold/retention, and seeded no-PII-invariant tests. Records contain only fingerprints, hashes, counts, and classes—not raw arguments, values, tokens, maps, snapshots, or content. It proves integrity of traffic that passed through the gateway/MCP gate, not host compromise; stronger isolation is required for that threat.

Current gaps remain: raw rehydrate, owner fallback, fixed key, folder-sync bypass, in-memory index, stdout pollution, HTTP stubs, audit raw arguments, and no gateway, local UI, MCP gate, or ledger. These are not claims of completion.
