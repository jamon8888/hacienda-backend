# hacienda-backend

The bridge between [CertaMesh/gaze](https://github.com/CertaMesh/gaze) (fail-closed PII pseudonymization,
consumed as a dependency) and [jamon8888/basemind](https://github.com/jamon8888/basemind) (the agent context
layer — xberg extraction, document RAG over Fjall + LanceDB, MCP server, vault).

**Status: workspace scaffolded** ([ticket #2](https://github.com/jamon8888/hacienda-backend/issues/2)). Implementation proceeds by workstream epics — [Epic 1: bridge scaffold + GazeRedactor plugin](https://github.com/jamon8888/hacienda-backend/issues/1) is the current frontier. The architecture, its locked decisions and the evidence behind them live here:

- [Architecture spec](docs/spec.md)
- [ADR-0001 Composition contract](docs/adr/0001-composition-contract.md)
- [ADR-0002 Dual store under one engine-era fingerprint](docs/adr/0002-dual-store-engine-era-fingerprint.md)
- [ADR-0003 The human-ward rehydration invariant](docs/adr/0003-human-ward-invariant.md)
- [ADR-0004 Class-stable projection is the only indexed form](docs/adr/0004-class-stable-projection.md)
- [Glossary](GLOSSARY.md)

Both upstreams stay untouched: gaze and basemind are consumed as dependencies; upstream updates are a
`cargo update` away. The wayfinding that produced this spec is recorded as GitHub issues on
`jamon8888/gaze` (map: [issue #1](https://github.com/jamon8888/gaze/issues/1), closed decisions per ticket).
