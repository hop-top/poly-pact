# Contributing to pact-go

This repository is a read-only mirror of the `go/` directory of
[hop-top/poly-pact](https://github.com/hop-top/poly-pact). Changes land
there, under `go/`, never in the mirror: open issues and pull requests
against `hop-top/poly-pact`, following its
[contributing guide](https://github.com/hop-top/poly-pact/blob/HEAD/CONTRIBUTING.md).

## Layout

The module path is `hop.top/pact-go`. An import path is `hop.top/pact-go/`
plus the directory path: the package in `core/jcs` is imported as
`hop.top/pact-go/core/jcs`. In the source repository the directory is `go/`,
with `go.mod` at its root; in the mirror it is the repository root.

```
.                         module hop.top/pact-go
  core/                   wire object types, enums and limits
  core/{strictjson,jcs,digest,jws,clock,binding}
  contract/               requirement contracts: issue and verify (draft sections 9.1 to 9.4)
  holder/                 agent side of an admission exchange (draft 11.1, 22.1)
  validator/              admission validator (draft 11.3, 11.4, 12)
  validator/conformance   the reference validator driven over the evaluation cases
  gateway/                admission as net/http middleware (draft 4.4)
  reputation/             reputation service library (draft sections 14, 15): ingestion, qualification, holds, signed snapshots, beta-decay-v1
  adapter/                native adapter contract (draft section 17.1)
  adapter/{adaptertest,enroll,enroll/memory,freshness,installed,task}
  adapter/source/{googledir,scim,ssf}  membership and status sources that are not adapters
  adapter/sourcetest      conformance harness of those sources
  adapters/memory         in-memory reference adapter
  adapters/{basic,oauth,mtls,aws,saml,ldap,graph,k8s,files,db,abac,rebac}  native adapters of the integration profiles
  adapters/graph/azurerm  executor of one Azure Resource Manager operation under the task ledger
  adapters/internal/broken  the memory adapter with deliberate defects, for the suite's own tests
  runner/                 conformance runner library
  runner/evalcase         readers of the evaluate, outcomes and learning cases
  runner/learning         reference registry state machine of draft section 16
  runner/manifest         fixture manifest and spec-map checks
  runner/reputation       reference oracle of the outcomes verb
  runner/schemas          JSON Schema of the pactc/v1 report
  internal/depcheck       test: standard library only, except the allowlisted adapter packages
  docs/deps.md            vetted dependencies
```

The commands that use the library, `pactc`, `pactconf`, `pactfix` and
`pactvalidate`, are a separate module, `hop.top/pact`, in the top-level
`cli/` directory of the source repository, mirrored to
[hop-top/pact](https://github.com/hop-top/pact).

## Modules and dependencies

The source repository holds two Go modules:

- `hop.top/pact-go` (`go/go.mod`): the library, every package of this tree.
  It uses the standard library only, except three adapter packages that
  may each use one named module: `adapters/files` uses `golang.org/x/sys`,
  `adapters/db` uses `github.com/jackc/pgx/v5` and `adapters/ldap` uses
  `github.com/go-ldap/ldap/v3`. The test in `internal/depcheck` fails when
  any other package, tests included, depends on a package outside the
  standard library and the module, directly or through an adapter package;
  when an adapter package uses a module other than its own; and when a
  `require` line of `go.mod` names a module that no adapter package
  reaches (the three modules and the indirect ones `go mod tidy` adds for
  them). A consumer that imports no adapter package does not download,
  build or `go.sum`-record those modules: with module graph pruning its
  `go.mod` gains only the `hop.top/pact-go` requirement, although
  `go list -m all` and `go mod graph` still list them from this `go.mod`.
- `hop.top/pact` (`cli/go.mod`): the commands. Their command tree, flags,
  help and `--version` come from `hop.top/kit` (`console/cli`), and JSON
  Schema validation uses `github.com/santhosh-tekuri/jsonschema/v6`. Those
  dependencies, and what they pull in, stay out of the library, and the
  library never imports the commands.

Third-party dependencies are vetted before they reach a `go.mod`; see
[docs/deps.md](docs/deps.md).

`go.work` at the root of the source repository puts both modules in one
workspace, so the commands build against the library of the same tree:
`cli/go.mod` requires `hop.top/pact-go` at the placeholder version
`v0.0.0-00010101000000-000000000000`, which `go.work` replaces with `./go`.
A released command module requires a released library version; see
Command module in
[RELEASING.md](https://github.com/hop-top/poly-pact/blob/HEAD/RELEASING.md).

## Build and test

From the root of the source repository:

```sh
make go-build go-test go-vet
```

or with the go command in each module directory:

```sh
go -C go test ./...          # library
go -C cli test ./...         # commands
go -C cli build -o bin/ ./...
```

In a bare-repository worktree add `-buildvcs=false` to every go command:
VCS stamping fails there with `error obtaining VCS status: exit status 128`.
