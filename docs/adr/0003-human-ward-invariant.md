# ADR-0003: Raw PII flows human-ward only — no MCP surface ever carries it

- **Status:** Accepted
- **Date:** 2026-10-24
- **Deciders:** owner (jamon8888) via wayfinder grilling (HITL, live)
- **Related:** ADR-0002, ADR-0004

## Context

The composed system has exactly one reader of real document content worth trusting: the owner. Agents
(Claude Code/Desktop through basemind's MCP server) are capable readers — of tokens. Gaze-token-bridge
already demonstrates the owner-side pattern: owner-held encryption, default-deny capability policy,
single-use entity capabilities, translation from persistent tokens to per-session tokens. Meanwhile
xberg's plugin system treats post-processor errors as non-fatal by default, which in this trust context
is a leak channel dressed as resilience.

Anything that returns document content through an agent-facing channel — an MCP tool result, a tool
"restore" convenience, a chat-surfaced snippet — collapses the entire redaction investment the moment
one caller asks the wrong question.

## Decision

**The agent-facing surface only ever serves token views. Rehydration is human-ward, reviewed, and
owner-operated.** Concretely, Locked.

- There is deliberately **no MCP tool that returns raw text — ever**. Not "gated", not "admin-only":
  absent. Tests assert the absence.
- Rehydration v1: a CLI rehydrate command plus owner-only file export (restored copies into a dedicated
  owner-only folder; original inputs untouched).
- **Per-export review**: before anything is written, the command shows what will restore — tokens by
  class with counts — and nothing writes unreviewed.
- Keys: macOS Keychain-held, with an explicit encrypted recovery export the owner can move offline.
  No plaintext-at-rest option exists.
- Every rehydration event and every capability grant/deny writes **gaze audit rows** (passive
  SqliteLogger sink, restricted columns, queryable via `gaze audit`), alongside basemind's own call log.
- Failure mode is fail-closed end to end: a missing store, an unavailable key, or a fingerprint
  mismatch blocks the operation; nothing degrades to a weaker channel.
- One-way gaze `[REDACTED:<class>]` markers surface to consumers as Drop-class findings: visible,
  explicitly not rehydratable, never indexed.

## Consequences

- The rehydrate CLI, the export folder, and the review flow are first-class, tested components — not
  scripts beside the code.
- MCP tool surface work must include the negative assertion (no raw-text tool) forever.
- An eyes-only local viewer can be added later as an owner-side surface only; it never becomes an MCP
  tool. Deferred fog.
- Per-entity downgrades (single-use capabilities from gaze-token-bridge) can tighten granularity later
  without touching this invariant.

## Alternatives considered

- **An MCP `restore` tool gated by permissions** — rejected: it makes the invariant a configuration
  matter; one misconfiguration is a full-text exfiltration of everything ever indexed.
- **Auto-rehydrate on export** — rejected: review-then-write is cheap for a single owner and is the
  only gate that keeps the bot from writing plain text anywhere.
- **Passphrase-derived keys per session** — rejected as v1 default: maximal control, real friction;
  the Keychain + offline recovery export achieves the custody boundary the owner actually operates.
