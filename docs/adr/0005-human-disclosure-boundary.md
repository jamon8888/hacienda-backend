# ADR-0005: Human disclosure belongs in an owner-only sidecar and viewer

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** owner (jamon8888)
- **Related:** ADR-0002, ADR-0003, ADR-0004

## Context

MCP output is model-visible, so raw recovery cannot be made safe by a permission bit or an owner
principal. Strict recovery needs the encrypted, fingerprint-bound Gaze SensitiveSnapshot/session material
and xberg TokenReplace map held in the owner vault. The current raw `rehydrate` MCP path, implicit owner
fallback, CLI stdout/`--yes` assumptions, and absent proxy controls are implementation gaps. The accepted
invariant is already clear: no raw MCP route ever exists.

The reviewed production shape is a stateful local proxy/gateway, not a transparent transport proxy. The
gateway owns MCP, keeps a canonical token-only transcript, suppresses raw values from ordinary client
history, and runs a final egress validator on every outbound response, error, event, and stream fragment.
This protects the agent channel only when the client is deliberately integrated with the gateway; stock
Claude Code behavior or a thin mod that merely changes transport cannot be treated as that boundary.

## Decision

The production human-disclosure choice is **Proposed**, not shipped: a deep `HumanDisclosure` module exposes
`request`, `status`, `approve`, `deny`, `cancel`, and `open-viewer`. Its interface can return only an
opaque request handle and allowlisted status metadata, never a raw value or restore artifact. An
owner-controlled local sidecar serves it over authenticated local IPC, and a secure viewer renders raw
values only to the authenticated owner. The MCP adapter may create a pending request but cannot approve,
read, or transport its value.

The production deployment also requires the stateful local proxy/gateway to be the sole MCP owner. The
proxy maintains the session and canonical token-only transcript; it is the only transcript used for
replay, resume, and audit references. Raw values must not be written to ordinary Claude Code or other
client history. Before anything leaves the proxy, the final egress validator rejects raw PII, restore
material, and unapproved fields, including in errors and streaming fragments. A validator failure is
fail-closed and sends no output.

### Threat model and qualified boundary

The primary boundary protects the agent conversation, model context, and ordinary client history: a request
originating through MCP must not cause a raw value to return through MCP, logs, model-visible errors,
client history, or other agent-readable destinations. The design does **not** claim that local IPC alone
creates owner-only isolation between processes running as the same OS user. Another process under that
account may be able to connect to the sidecar, impersonate a client, observe IPC destinations, or inspect
shared-user resources unless stronger controls are enforced.

The target design therefore requires, and its security case depends on, all of the following:

- the proxy is stateful and proxy-owned MCP is the only supported client route; transparent forwarding alone
  is insufficient;
- the canonical transcript contains tokens and allowlisted metadata only, and ordinary client history is
  disabled, filtered, or replaced with that transcript;
- the final egress validator covers every outbound protocol path, including errors, notifications, and
  streaming fragments, and fails closed;
- the sidecar rejects clients whose identity cannot be authenticated; it must not treat a caller-provided
  name, PID, or request field as proof of owner identity, and must reject spoofed clients;
- a request cannot approve itself, and request, approval, and denial are distinct transitions with
  independent authorization;
- approval requires an independent owner-authenticated, OS/user-presence-backed channel that cannot be
  satisfied by the requester alone;
- viewer content is delivered only to the owner-authenticated viewer over a dedicated non-agent-readable
  destination, with viewer isolation and access controls that prevent ordinary agent-readable IPC
  destinations from receiving raw content;
- missing, ambiguous, or spoofed identities and absent user presence fail closed.

A fully compromised process under the same OS account may defeat these local controls, including by
intercepting or impersonating the viewer channel. Protection against that residual risk is outside this
target's proven boundary and requires stronger platform isolation or a separate design. This qualification
does not weaken the no-raw-MCP invariant: regardless of same-user compromise, no MCP path may return raw
values or restore material.

Before rendering, the sidecar verifies Keychain custody, encrypted Gaze snapshot/session material,
xberg TokenReplace map, manifest, document identity, and the shared engine/document fingerprint. Missing
or mismatched prerequisites fail closed. The Gaze manifest is the canonical Gaze provenance/evidence
record, not the durable operational audit. The manifest, durable operational audit, and metadata-only
disclosure ledger are separate schemas with distinct retention and failure semantics; none substitutes
for another. Their allowlisted metadata excludes arguments, values, tokens, maps, snapshots, manifests,
queries, and raw errors. The owner CLI remains a controlled interactive migration/recovery fallback: no
raw stdout, no unattended `--yes`, and no claim that it is a security boundary.

## Invariants

- No MCP tool, resource, response, status, error, query, extension, transcript, or ordinary client history
  contains raw PII or restore material; `rehydrate` and Rehydrate are absent.
- MCP is owned by the stateful proxy/gateway, whose canonical transcript is token-only and whose final egress
  validator covers every outbound path.
- Agent-visible bundles contain only class-stable projections and allowlisted metadata.
- Only the owner viewer renders raw values, after explicit approval through an independent
  owner-authenticated, OS/user-presence-backed channel and complete binding verification.
- The sidecar rejects spoofed or unauthenticated clients; requests cannot self-approve.
- Raw viewer content is never sent to an agent-readable IPC destination or through MCP.
- Production custody requires macOS Keychain; fixed passphrases and insecure local fallbacks are dev/test-only.
- Disclosure is deny-by-default, auditable with metadata only, and safe under cancellation, expiry, restart,
  and IPC failure.
- A transparent proxy or stock Claude Code integration alone does not satisfy these invariants.

## Alternatives considered

- **Owner CLI as primary path:** rejected as a security boundary because stdout, shell capture, and
  unattended `--yes` can disclose values. Retained only for controlled migration/recovery.
- **Browser viewer:** not selected as the default because browser origin/process and navigation surfaces
  expand the boundary; it may be considered only with equivalent authenticated local IPC and isolation.
- **Clipboard or file export:** rejected as primary because other processes, sync tools, or agents can
  capture the value.
- **Signed reveal/capability:** rejected for agent recovery; a signed token still becomes a raw-value
  route if consumed by an agent. It may authorize a human viewer only.
- **Transparent HTTP/SOCKS/TLS MITM proxy:** rejected as the production solution; it forwards transport but
  does not own MCP, maintain a canonical token-only transcript, suppress client history, or guarantee final
  egress validation. It may adapt protocol only when it cannot see restore material or raw values.
- **Stock Claude Code configuration or a transport-only mod:** rejected as the security boundary because
  ordinary client history and outbound behavior remain uncontrolled. A controlled wrapper/mod must route to
  proxy-owned MCP, use token-only history, and enforce the final validator.

## Consequences

The sidecar/viewer requires a local IPC protocol, owner authentication, OS/user-presence-backed approval,
lifecycle handling, and a securely isolated rendering surface. The stateful gateway additionally requires
session persistence, canonical transcript storage, client-history controls, and final egress validation.
These components add a TCB to build and audit, but keep provider credentials, raw values, and restore
material out of the MCP process and model conversation under the stated threat model. They do not claim
protection from a fully compromised same-user process.

Until this ADR is implemented, the repository must describe the sidecar/viewer, stateful gateway,
proxy-owned MCP, canonical transcript, and final egress validator as proposed targets rather than shipped
features. The existing raw MCP path and ordinary client history are noncompliant and must not be presented
as production behavior.

## Local UI and upload boundary

A separate Proposed local web UI binds to `127.0.0.1:8788` with authentication and user presence. It provides folder navigation, clean.md Markdown view/edit, search, Inbox upload, and audit views. Raw values are rendered only in the separate owner-authenticated sidecar viewer; the UI never feeds a provider transcript.

Claude Desktop's native `+` picker is not officially hookable by a plugin. The deployment therefore uses layered controls: a watched Inbox, Hacienda Gateway attachment extraction/redaction or request blocking, and MCP `attach_local_doc` for paths under already-processed allowed roots. A mod warning is advisory. None of these changes the absolute no-raw-MCP rule or makes a plugin a security boundary.
