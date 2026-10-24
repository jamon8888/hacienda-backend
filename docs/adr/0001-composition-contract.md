# ADR-0001: Gaze detects and owns provenance; xberg's TokenCounter mints tokens

- **Status:** Accepted
- **Date:** 2026-10-24
- **Deciders:** owner (jamon8888) via wayfinder grilling, on research from gaze#2 + gaze#3
- **Related:** ADR-0002, ADR-0004; basemind ADR-0015 (bounded document extraction)

## Context

Basemind's ingest pipeline redacts documents before they reach the index and the agent. Today xberg's
built-in redaction post-processor does detection and token emission in one step, and
`xberg::text::redaction::redact_capturing_rehydration_map` is the function basemind calls when it wants
the rehydration map (basemind `src/extract/doc.rs`, TokenReplace bypass path). Gaze is a stronger,
fail-closed detector — evidence tiers, conflict records, validator vetoes, ambiguity records — but its
token wire grammar is hard-coded (`<{session_hex}:{Class}_{n}>`, `crates/gaze/src/session.rs`), policies
that would match its own token shape are rejected at load (`TokenShapeShadow`), and `token.format` is a
per-recognizer format-preservation field, not a token-wire template.

Meanwhile the `[TYPE_N]` surface (`[EMAIL_1]`, …) is load-bearing downstream: token length bakes into
chunk `byte_end` at index time (basemind ADR-0015), basemind's shape-coupled consumers
(`src/pii/tax_id.rs`: `rename_tokens`, `relabel_in_text`) pattern-match the bracket shape, and the vault
rehydration map is keyed by those exact token strings.

## Decision

**Gaze detects and owns provenance; xberg's TokenCounter mints the `[TYPE_N]` tokens.** One detection
pass per ingest run: gaze emits `ExternalRedactionFinding {label, start, end, score}`-shaped findings,
xberg's redaction post-processor applies its TokenReplace strategy over those findings and produces the
rehydration report — reproducing today's token surface byte-for-byte. The integration seam is
`xberg::register_post_processor` with a same-name replacement of the built-in `"redaction"` Late-stage
processor (or `xberg::extract_with_external_redaction` from the same public API family). Gaze never
emits tokens on the wire in the composed path.

## Consequences

- No fork edit to basemind and none to gaze on the primary path; the bridge repo carries both as
  dependencies (gaze crates are on crates.io, `0.17.0`).
- The gaze manifest becomes the provenance-canonical store; xberg's redaction report is a projection
  (see ADR-0002).
- Plugin/processor errors must be made fatal: xberg treats post-processor errors as non-fatal by
  default, and a degrade-to-regex fallback is a leak channel. The bridge wraps accordingly.
- If gaze ever gains a configurable token-wire template, this ADR is revisited — not before.

## Alternatives considered

- **Full engine swap (gaze also emits tokens)** — rejected: gaze's grammar cannot be configured into
  `[TYPE_N]` shape (`TokenShapeShadow` rejects it at load; `token.format` is accepted-then-rejected,
  "planned v0.4.1"); emulating it would break basemind's shape-coupled consumers or require migrating
  them all — a large fork-side change for zero functional gain.
- **Vault map stays the only store, gaze manifests derived** — rejected: loses audit-grade provenance;
  see ADR-0002.
- **In-fork patch at `src/extract/doc.rs`'s bypass call site** — kept only as a documented fallback;
  carries patch-maintenance against upstream basemind forever, contradicting the dependency posture.
