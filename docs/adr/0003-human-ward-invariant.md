# ADR-0003: Raw PII flows human-ward only — no MCP surface ever carries it

- **Status:** Accepted
- **Date:** 2026-10-24
- **Deciders:** owner (jamon8888) via wayfinder grilling (HITL, live)
- **Related:** ADR-0002, ADR-0004, ADR-0005
- **Implementation status:** Target boundary is authoritative; the proxy-owned MCP, final egress validator,
  and HumanDisclosure sidecar/viewer are not shipped. Current raw-capable recovery paths remain noncompliant.

## Context

The composed system has exactly one reader of real document content worth trusting: the owner. Agents
(Claude Code/Desktop through basemind's MCP server) are capable readers — of tokens. Gaze-token-bridge
already demonstrates the owner-side pattern: owner-held encryption, default-deny capability policy,
single-use entity capabilities, translation from persistent tokens to per-session tokens. Meanwhile
xberg's plugin system treats post-processor errors as non-fatal by default, which in this trust context
is a leak channel dressed as resilience.

Anything that returns document content through an agent-facing channel — an MCP tool result, a tool
"restore" convenience, a chat-surfaced snippet, a transcript, or ordinary client history — collapses the
entire redaction investment the moment one caller asks the wrong question. A transparent transport proxy
cannot repair that boundary: it does not own MCP state, the transcript, or the final bytes delivered to a
client.

## Decision

**The agent-facing surface only ever serves class-stable projections, allowlisted metadata, or opaque
handles/status. Rehydration is human-ward, reviewed, and owner-operated.** Concretely, Locked.

- The production protocol boundary is a **stateful local proxy/gateway**. It owns MCP, maintains the session,
  and writes the canonical transcript. The canonical transcript is token-only and is the only transcript
  used for replay, resume, audit references, and egress checks; raw values never enter it.
- The proxy applies a **final egress validator** to every response, tool result, error, event, and streaming
  fragment before delivery. A validation failure emits nothing and fails closed. This is defense in depth,
  not permission to accept raw input elsewhere.
- There is deliberately **no MCP raw `rehydrate` tool, resource, or capability — ever**. Not "gated",
  not "admin-only": absent. There is no implicit owner fallback; tests assert the absence.
- No raw value is written to ordinary agent/client history. A client integration must suppress or replace
  such history with the canonical token-only transcript; stock Claude Code behavior and an unmodified client
  are not a production security boundary.
- Production disclosure is a deep `HumanDisclosure` module with `request`, `status`, `approve`, `deny`,
  `cancel`, and `open-viewer`, served by an authenticated local sidecar and isolated secure viewer.
- Approval requires an independent owner-authenticated, OS/user-presence-backed channel; a request cannot
  approve itself, and spoofed clients are rejected. Raw content goes only to a dedicated non-agent-readable
  viewer destination. Authenticated local IPC alone is not isolation from a fully compromised same-user
  process; that residual risk is out of scope and does not weaken no-raw-MCP.
- CLI rehydration and owner-only export are only an interactive migration/recovery fallback: per-export
  review is required, raw stdout is forbidden, unattended `--yes` is forbidden, and the CLI is not a
  security boundary.
- Keys: macOS Keychain custody is required in production, with encrypted recovery export; fixed passphrases
  and insecure fallbacks are dev/test-only.
- Durable operational audit and the disclosure ledger are separate metadata-only stores with allowlisted
  fields. They exclude raw args/values/tokens/maps/snapshots/manifests/queries/errors.
- Failure mode is fail-closed end to end: a missing store, an unavailable key, a fingerprint mismatch, or
  a missing proxy/transcript/validator state blocks the operation; nothing degrades to a weaker channel.
- One-way gaze `[REDACTED:<class>]` markers surface to consumers as Drop-class findings: visible,
  explicitly not rehydratable, never indexed.

## Consequences

- The rehydrate CLI, export folder, and review flow are target first-class, tested components — not
  scripts beside the code; until issue #29 lands, the current stdout/`--yes` behavior is an implementation
  gap and must be described as noncompliant.
- The proxy/gateway, canonical token-only transcript, client-history suppression, and final egress validator
  are production conditions, not optional hardening. They are not shipped until implemented and tested.
- MCP tool surface work must include the negative assertion (no raw-text tool) forever.
- The HumanDisclosure sidecar/viewer is the production target and remains owner-side only; it never
  becomes an MCP raw-content tool. Until implemented, the repository must describe it as a target.
- Per-entity downgrades (single-use capabilities from gaze-token-bridge) can tighten granularity later
  without touching this invariant.

## Alternatives considered

- **An MCP `restore` tool gated by permissions** — rejected: it makes the invariant a configuration
  matter; one misconfiguration is a full-text exfiltration of everything ever indexed.
- **Auto-rehydrate on export** — rejected: review-then-write is cheap for a single owner and is the
  only gate that keeps the bot from writing plain text anywhere.
- **Transparent HTTP/SOCKS/TLS proxy** — rejected as the security boundary: it cannot own MCP semantics,
  maintain a canonical token-only transcript, suppress client history, or prove final egress safety. It may
  be used only for transport adaptation behind the stateful gateway.
- **Unmodified or lightly modded stock Claude Code** — rejected as the production boundary: its ordinary
  client history and transport behavior are not controlled by this invariant. A controlled wrapper/mod must
  connect only to proxy-owned MCP and enforce token-only history plus final egress validation.
- **Passphrase-derived keys per session** — rejected as v1 default: maximal control, real friction;
  the Keychain + offline recovery export achieves the custody boundary the owner actually operates.

## Gate and client integration clarification

The absolute no-raw-MCP rule is enforced by a closed-manifest JSON-RPC MCP gate in front of the backend. Its tools are limited to `search`, `sync`, `status`, `graph_*`, disclosure request/status, and `attach_local_doc`; schemas are locked against drift, side effects may require DSSE exact-call approval, operations are idempotent, and failures are fail-closed. `attach_local_doc` accepts only already-processed paths beneath an allowed local/SMB/NFS root and returns a tokenized clean reference.

The Hacienda Gateway is the only provider egress, using client `BASE_URL` reverse-proxy configuration rather than generic MITM/CA injection. Gaze tokenizes prompts, history, tool calls/results, and attachments before upstream delivery; the provider transcript remains token-only. A plugin/mod (`bin/hacienda`, `.mcp.json`) may tokenize `prompt.submit`, sanitize `tool.call`, and show sent-versus-local UX, but it is onboarding only: official client UI does not guarantee arbitrary content is excluded from future persisted/API requests. The gateway and canonical transcript remain the security boundary. Native Claude Desktop `+` upload interception is unavailable to plugins, so Inbox watching, attachment sanitizer/blocking, and MCP attach are layered controls.
