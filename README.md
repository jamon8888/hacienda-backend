# hacienda-backend

Hacienda is the composition point between [CertaMesh/gaze](https://github.com/CertaMesh/gaze) (fail-closed
PII detection and redaction) and [jamon8888/basemind](https://github.com/jamon8888/basemind) (agent context,
document RAG, and MCP). Both upstreams remain dependencies and stay untouched.

## Production target

The end-to-end target is a **stateful proxy/gateway**, not a transparent MITM. It maintains authenticated
session, tenant, policy, and transcript state while exposing a **token-only** contract. Gaze is the only
ingestion/redaction boundary; the authoritative transcript, durable indexes, MCP tools/resources, logs,
errors, and all client egress contain only class-stable tokens and allowlisted metadata. A final egress
validator fails closed before anything reaches an agent or client. Claude Code, Codex, CLI, and supported
adapters must have equivalent guarantees.

HumanDisclosure is a separate owner-controlled sidecar and secure viewer for approved human disclosure.
It is not an MCP capability, not a proxy escape hatch, and not shipped yet. Explicit non-goals are raw MCP
rehydration, agent-visible PII, implicit owner fallback, unattended approval, transparent MITM behavior,
and making the TypeScript extension a recovery boundary.

## Status and current gaps

**This workspace is a scaffold and is not production-compliant.** The shipped implementation has direct
Rust MCP over stdio/HTTP, raw-capable `rehydrate` and owner-fallback paths, fixed-key/dev custody,
stdout/`--yes` behavior, incomplete folder-sync/index durability, no authoritative token-only transcript,
no complete egress validator, and no verified client parity. HumanDisclosure, the stateful gateway, and
durable production index/recovery semantics remain to be implemented. These are gaps, not supported
production behavior.

- [Architecture overview](ARCHITECTURE.md)
- [Glossary](GLOSSARY.md)
- [Architecture spec](docs/spec.md)
- [ADR-0001 Composition contract](docs/adr/0001-composition-contract.md)
- [ADR-0002 Dual store under one engine-era fingerprint](docs/adr/0002-dual-store-engine-era-fingerprint.md)
- [ADR-0003 The human-ward rehydration invariant](docs/adr/0003-human-ward-invariant.md)
- [ADR-0004 Class-stable projection is the only indexed form](docs/adr/0004-class-stable-projection.md)
- [ADR-0005 Human disclosure boundary](docs/adr/0005-human-disclosure-boundary.md)

The TypeScript extension is optional UX/onboarding only and must not provide recovery or be treated as a security boundary. Provider traffic must use the proposed Hacienda Gateway base-URL reverse proxy; the proposed local Markdown workspace UI is separate from provider transcripts. These components are not shipped, so the scaffold is not production-compliant.

- [ADR-0006 Provider egress gateway](docs/adr/0006-provider-egress-gateway.md)
- [ADR-0007 Local Markdown workspace UI](docs/adr/0007-local-markdown-workspace-ui.md)
- [ADR-0008 Evidence ledger and anchoring](docs/adr/0008-evidence-ledger-and-anchoring.md)
