# Architecture spec — gaze-powered PII-safe document backend for Claude

Status: **skeleton locked** (wayfinder map `jamon8888/gaze#1`; decisions resolved and closed in that tracker).
This document names the sections; each covers a route already walked — nothing here is undecided.

## 1. Purpose and scope

Claude Code/Desktop works a folder of common office documents (basemind's 90+ format extractors):
extract → redact (gaze engine) → index → agent-searchable RAG, with **raw PII flowing human-ward only**.
Local-first, single-user, one folder tree, macOS Keychain-custodied keys. `hacienda-backend` is a bridge
repo consuming gaze and basemind as dependencies — neither upstream is forked or patched for the primary path.

## 2. Trust boundary and invariants

- **Human-ward rehydration** ([ADR-0003]): no agent-facing surface — including MCP tool results — ever
  carries rehydrated content. The agent sees tokens; owners rehydrate via reviewed CLI/export channels.
- **Fail-closed everywhere**: plugin/processor errors are fatal in xberg terms (a degrade-to-regex fallback
  is a leak channel, not a convenience); store/key/fingerprint mismatches block operations.
- One-way gaze `[REDACTED:<class>]` markers surface to consumers as Drop-class findings — visible,
  never rehydratable, never indexed.

## 3. Composition contract ([ADR-0001])

One detection pass: **gaze detects and owns provenance; xberg's TokenCounter mints the `[TYPE_N]` tokens**,
reproducing today's surface byte-for-byte. Gaze never emits tokens on the wire (its grammar is fixed and
shape-guarded). Integration seam: `xberg::register_post_processor` same-name replacement of the built-in
`"redaction"` Late processor (public; `extract_with_external_redaction` as the dual-engine alternative);
basemind's capture → vault flow keeps working unchanged. Fork-patch fallback documented but unused.

## 4. Store topology ([ADR-0002])

**Dual store, single write path.** Each ingest run under one engine-era fingerprint
(`engine id × token-grammar version × redaction config`) emits:
- the **gaze manifest** — provenance/audit canonical (evidence tiers, conflict records, validator reasons);
- the **vault rehydration map** (`XPII\x01`, TS-pinned) — operational restore for basemind flows.
Drift is structurally impossible; fingerprint mismatch blocks cross-era reuse and triggers rebuild.
Offsets: explicit `Utf8Bytes` encoding; no post-hoc token renames once persisted (token length bakes into
chunk `byte_end`, basemind ADR-0015).

## 5. Rehydration surface ([ADR-0003])

CLI rehydration + owner-only file export; per-export review shows tokens-by-class before anything writes.
Keychain-held keys + offline encrypted recovery export. **No MCP tool returns raw text, ever.**
Every rehydration and capability grant/deny lands in gaze audit rows (`SqliteLogger`, restricted columns,
queryable via `gaze audit`) plus basemind's call log.

## 6. Index projection ([ADR-0004])

Embed and BM25 **only the class-stable projection** (`<Class_…>` spelling): raw session tokens poison the
blob cache; format-preserving fakes stay out of the lexical index. Cross-encoder rerank is shape-agnostic;
suppression tiers map from gaze PiiClass (Name/Location/Organization → MINIMAL, Email → LOW,
**Custom → HIGH fail-closed**, credential-shaped customs → HARD_BLOCK). Byte ranges are canonical in
original-document offsets; gaze-output offsets ride the manifest. Index rebuilds are keyed on the
engine-era fingerprint.

## 7. Accepted architecture constraints

- gaze audit/isolation gates (`no-tenant-knowledge`, audit-sink isolation, tokenbridge-* behavioral gates)
  are the composition's floor: the bridge must keep gaze's protected feature graphs clean.
- Detection *configs* composed here do not alter gaze rules — the gaze benchmark gain gate is not
  triggered by this repo; acceptance instead = zero raw bytes in agent surfaces + manifest restore
  round-trip on a representative corpus.

## 8. Workstreams (implementation epics, downstream of the spec)

1. **Bridge scaffold + plugin** — repo/CI; `GazeRedactor` PostProcessor (name `"redaction"`, stage Late,
   fatal-on-error); acceptance: Office/PDF corpus extracts with zero raw bytes in `ExtractedDocument`.
2. **Ingest integration** — gaze-assembly assembly from `basemind.toml` (`[redaction].engine = "gaze"`),
   dual-store writes, fingerprint computation, doctor checks (models present, Keychain unlocked, policy
   valid); acceptance: whole-index fingerprint match, restore round-trip on the representative corpus.
3. **Rehydration surface** — rehydrate CLI, per-export review, owner-only export folder, recovery export,
   audit wiring; acceptance: audit rows for every event; MCP surface provably token-only.
4. **Index projection + sync** — projection pre-chunking, BM25/vector split, tier mapping, byte-range canon,
   engine-era rebuild policy; acceptance: stale-blob detection on fingerprint change; tier behavior matches
   ADR-0004 table.

Each epic gets sliced in its own session (`/to-tickets`) against this spec.

## 9. Open questions (deferred deliberately)

Upstream contribution strategy (gaze as an xberg plugin is a candidate); eval & acceptance mapping
to basemind/gaze harnesses; eyes-only local viewer; per-entity single-use capability downgrades;
multi-tenant/folder-per-tenant growth. Tracked as fog on the wayfinder map.

## 10. References

Findings and resolutions (owner-side secret gists) are linked from each wayfinder ticket
(`jamon8888/gaze` issues #2–#6) and from the ADRs below. Glossary terms: `GLOSSARY.md` in this repo
(echoed in `~/gaze/GLOSSARY.md`).
