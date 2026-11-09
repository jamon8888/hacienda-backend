# ADR-0006: Hacienda Gateway is the provider egress boundary

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** owner (jamon8888)
- **Related:** ADR-0003, ADR-0005, ADR-0007, ADR-0008

## Context

Provider clients can persist prompts, history, tool calls, attachments, and responses outside Hacienda's control. A plugin or UI hook cannot guarantee that arbitrary content is absent from future provider requests. Generic MITM or CA injection is also the wrong boundary: it cannot establish a token-only transcript or reliably interpret provider protocol semantics.

## Decision

Clients configure `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL` as `http://127.0.0.1:8787`. The Hacienda Gateway is the only provider egress and is a base-URL reverse proxy, not a generic MITM. It allowlists provider hosts, pins upstream TLS, buffers and validates SSE, emits metadata-only logs, and handles `/v1/messages`, `/v1/chat/completions`, and attachments.

Gaze tokenizes outbound prompts, history, tool calls/results, and attachments. The provider receives token-only content and the authoritative transcript is token-only. A separate authenticated local UI may rehydrate only for a human owner; no raw value enters the provider transcript. Attachment handling extracts and redacts or blocks unsafe requests. A client that pins or ignores `base_url` requires a custom client/fork; the guarantee degrades rather than silently failing open.

A JSON-RPC MCP gate separately fronts the backend with the closed manifest `search`, `sync`, `status`, `attach_local_doc`, `request_human_disclosure`, and `disclosure_status`, plus optional feature-gated `graph_entities` and `graph_rag`. `doctor` is CLI-only and `rehydrate` is absent. Schemas are locked, with optional Cedar-like policy, DSSE exact-call approvals for side effects, idempotency, and fail-closed codes; the gate never rehydrates.

## Consequences and limits

The gateway becomes mandatory infrastructure and must fail closed on unsupported protocols, upstream pinning failures, redaction failures, and unsafe streams. A plugin/mod remains UX/onboarding only (`bin/hacienda`, `.mcp.json`, prompt.submit tokenization, tool.call sanitization, sent-vs-local pane). This ADR does not protect a client that bypasses the gateway, a compromised host, or a provider-side system outside the controlled transcript.

## Current gap

No production gateway, complete HTTP implementation, attachment sanitizer, MCP gate, or provider client parity is shipped yet.
