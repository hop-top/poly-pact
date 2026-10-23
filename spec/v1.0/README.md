# PACT specification v1.0

**Status:** Draft
**Spec version:** 1.0.0-alpha.1 | **Wire version:** `0.1` <!-- x-release-please-version -->

Version 1.0 of the language-neutral specification of PACT (Purpose-bound Access Control & Trust), with the spec version and wire version of the front matter of `draft.md`. The spec version numbers releases of this document; the wire version numbers the message format and stays `0.x` until the format is declared stable. The draft claims no implementation, interoperability suite, or independent security assessment.

| Path | Contents |
|---|---|
| `draft.md` | The protocol draft |
| `schemas/pact.schema.json` | JSON Schema for the wire objects |
| `diagrams/` | Three Mermaid diagrams: architecture, admission and approval, learning loop |
| `examples/` | Twenty informative examples – six worked use cases (U01–U13) and fourteen integration samples (I01–I14) – with an index in `README.md` |
| `profiles/` | Integration profiles, the cross-cutting profile documents they build on, the profile registry, and the profile schema, with an index in `README.md` |
| `fixtures/` | Language-neutral conformance fixtures and their manifest, `fixtures/manifest.json` |
| `spec-map.md` | Mapping from conformance checks to draft sections and fixtures |

## Where things live

The source of this directory is `spec/v1.0/` in [hop-top/poly-pact](https://github.com/hop-top/poly-pact). The read-only repository [hop-top/spec-pact](https://github.com/hop-top/spec-pact) mirrors `spec/` at its root, so this directory is `v1.0/` there; the [front matter of the tree](../README.md) describes the mirror. Open issues and pull requests against `hop-top/poly-pact`, never the mirror. A change to the draft comes with the matching change to the schema, and the reverse.

## License

MIT, © 2026 Idea Crafters LLC and Jad Bitar. See [LICENSE](../LICENSE).
