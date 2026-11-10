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

This repository is an **active partial implementation and is not production-compliant**. The canonical
target and the evidence-backed status of each capability live in [docs/spec.md](docs/spec.md); approved
designs are recorded in the ADRs below. Current raw-capable recovery/rehydration, fixed-key or development
custody, stdout/`--yes` behavior, in-memory index paths, incomplete folder-sync durability, and the absence
of the proxy-owned transcript/gateway are implementation gaps, not supported production behavior.

### MVP feature matrix

| Capability | Status | Truthful claim |
|---|---|---|
| Gaze/xberg redaction seam | Partial | Redactor and projection primitives exist; the complete watched-root acceptance path is not claimed shipped |
| Class-stable projection | Partial | Projection logic exists; durable per-tenant index generations and rebuilds remain incomplete |
| Tenant authorization and tenant-aware search | Partial | Validation and tenant-aware components exist; every public operation is not yet covered end to end |
| Vault encryption and Keychain custody | Partial | Custody/encryption seams exist; production startup and all write paths are not yet proven |
| MCP over stdio/HTTP | Partial/noncompliant target | The current direct server is not the closed, proxy-owned production MCP gate |
| HumanDisclosure sidecar and secure viewer | Planned | ADR-0005 Proposed; no raw MCP recovery is supported by the target contract |
| Hacienda Gateway and local Markdown UI | Planned | ADR-0006/0007 Proposed; provider egress and workspace isolation are not shipped |
| Durable evidence ledger and anchoring | Planned | ADR-0008 Proposed; current audit code is not a true WORM or release-complete ledger |

- [Architecture overview](ARCHITECTURE.md)
- [Glossary](GLOSSARY.md)
- [Architecture spec](docs/spec.md)
- [Production MVP readiness plan](.openbitfun/plans/production-mvp-readiness.plan.md)
- [ADR-0001 Composition contract](docs/adr/0001-composition-contract.md)
- [ADR-0002 Dual store under one engine-era fingerprint](docs/adr/0002-dual-store-engine-era-fingerprint.md)
- [ADR-0003 The human-ward rehydration invariant](docs/adr/0003-human-ward-invariant.md)
- [ADR-0004 Class-stable projection is the only indexed form](docs/adr/0004-class-stable-projection.md)
- [ADR-0005 Human disclosure boundary](docs/adr/0005-human-disclosure-boundary.md)

The TypeScript extension is optional UX/onboarding only and must not provide recovery or be treated as a security boundary. Provider traffic must use the proposed Hacienda Gateway base-URL reverse proxy; the proposed local Markdown workspace UI is separate from provider transcripts. These components are not shipped, so the repository is not production-compliant.

- [ADR-0006 Provider egress gateway](docs/adr/0006-provider-egress-gateway.md)
- [ADR-0007 Local Markdown workspace UI](docs/adr/0007-local-markdown-workspace-ui.md)
- [ADR-0008 Evidence ledger and anchoring](docs/adr/0008-evidence-ledger-and-anchoring.md)

`docs/spec.md` is the single canonical production contract. A feature is production-ready only when its
implementation, tests, operational controls, and documentation agree; an accepted ADR or configuration
option alone is not a readiness claim.
