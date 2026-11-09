# ADR-0007: Local Markdown workspace UI

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** owner (jamon8888)
- **Related:** ADR-0003, ADR-0005, ADR-0006, ADR-0008

## Context

Agents need a useful local workspace without raw file-tool access or raw values in provider traffic. Claude Desktop's native `+` picker is not officially hookable by a plugin, so upload interception cannot depend on a plugin callback.

## Decision

Provide an authenticated loopback web app at `127.0.0.1:8788`. It navigates explicit local and mounted network roots, views and edits the Gaze-produced `clean.md`, searches the persistent class-stable index, accepts files through a watched Inbox, and presents metadata-only audit views. Folder roots are an allowlist; sync processes MIME/OCR xberg extraction, fail-closed Gaze, encrypted vault/manifest/map, and class-stable projection before persistence.

Raw values are never rendered in the normal workspace UI or sent to a provider transcript. An owner-authenticated sidecar viewer may render raw values only after ADR-0005 authentication and user presence. The UI is not an MCP rehydration route and does not widen the no-raw-MCP invariant.

Upload controls are layered: watched Inbox, Hacienda Gateway attachment extraction/redaction or blocking, and MCP `attach_local_doc`, which accepts only processed paths under roots allowlisted for Hacienda ingestion/sync and returns a tokenized clean reference. The closed MCP manifest is `search`, `sync`, `status`, `attach_local_doc`, `request_human_disclosure`, and `disclosure_status`, plus optional feature-gated `graph_entities` and `graph_rag`; `doctor` is CLI-only and `rehydrate` is absent. An optional mod warning is advisory. The plugin/mod and UI are UX surfaces, not security boundaries; gateway and MCP gate enforcement remain authoritative.

## Consequences and limits

The UI needs loopback authentication, CSRF/session controls, tenant scoping, audit metadata, and fail-closed handling for missing or stale projections. It must not expose arbitrary filesystem browsing outside allowlisted roots. This ADR does not claim protection from a fully compromised same-user host.

## Current gap

No production UI, Inbox watcher, attachment interception, or clean.md editor is shipped yet.
