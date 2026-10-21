# PACT root Makefile. `make help` lists every target.
#
# One group of targets per language package (go, ts, py, rs, php), plus the
# spec, conformance, parity and release gates.
#
# A language target runs only when that package's manifest exists. Until
# then it prints a NOTICE on stderr and succeeds, so `make check` is green
# on a tree where the package has not landed. The guard switches on its own
# when the manifest appears, but it would also turn a deleted manifest into a
# silent green, so the change that lands a package deletes its guard: the
# `ifeq` line, the stub rule above `else`, and the `else` and `endif` lines.
# The spec, parity and release targets are stubs of the same kind; the check
# that lands replaces its stub recipe.
#
# Conventions
# - Prerequisites only, never $(MAKE) in a recipe: `make -n` shows exactly
#   what runs.
# - Toolchains resolve through `mise exec --` when mise is installed (pins
#   live in mise.toml) and from PATH otherwise. Override with `make MISE=`.
# - Only `setup` installs dependencies. Every other target assumes it ran.
# - A *-vectors target prints one NDJSON line per manifest entry,
#   {"id","kind","result"}, and nothing else on stdout: NOTICE lines go to
#   stderr and the recipe is silent (@).

.DEFAULT_GOAL := help

.PHONY: help setup check test lint build clean links \
	go-test go-lint go-build go-vet go-fmt go-test-windows go-vectors \
	ts-test ts-lint ts-build ts-vectors ts-sync-schema ts-check-schema ts-mutants \
	py-test py-lint py-build py-vectors py-sync-schema py-check-schema py-mutants \
	rs-test rs-lint rs-build rs-vectors rs-sync-schema rs-check-schema rs-mutants \
	php-test php-lint php-build php-vectors php-sync-schema php-check-schema \
	spec-validate spec-links spec-examples spec-map spec-manifest \
	conformance parity parity-selftest release-check release-rehearsal

ifndef MISE
MISE := $(if $(shell command -v mise 2>/dev/null),mise exec --,)
endif

LYCHEE_FLAGS ?= --no-progress --offline
PACTC_ARGS ?=

# Each SDK vendors the spec schema inside its own directory: the mirror of a
# package carries only that package's subtree, so no ../spec path may exist
# at runtime or in a built artifact. A package scaffold may move its copy by
# changing its variable.
SCHEMA_SRC := spec/v1.0/schemas/pact.schema.json
TS_SCHEMA  := ts/schema/pact.schema.json
PY_SCHEMA  := py/src/hop_top_pact/schema/pact.schema.json
RS_SCHEMA  := rs/schema/pact.schema.json
PHP_SCHEMA := php/schema/pact.schema.json

# notice prints a loud, greppable line on stderr: $(call notice,<text>).
notice = echo "NOTICE: $(1)" >&2

# sync-schema copies the spec schema to $(1). check-schema fails when $(1)
# is missing or differs; $(2) names the sync target to run.
sync-schema = mkdir -p $(dir $(1)) && cp $(SCHEMA_SRC) $(1)
check-schema = @cmp -s $(SCHEMA_SRC) $(1) || { echo "$(1) differs from $(SCHEMA_SRC); run make $(2)" >&2; diff -u $(SCHEMA_SRC) $(1) >&2; exit 1; }

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*## "; printf "Targets:\n"} /^##@/ {printf "\n%s\n", substr($$0, 5)} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

##@ Aggregate

check: lint test build spec-validate spec-examples spec-links spec-map spec-manifest spec-parity parity-selftest release-check ## Run lint, tests, builds, and the spec and release gates

test: go-test ts-test py-test rs-test php-test conformance parity ## Run every language's tests, then conformance and parity

lint: go-vet go-lint ts-lint py-lint rs-lint php-lint ## Run every language's linters

build: go-build ts-build py-build rs-build php-build ## Build every language package

setup: ## Install pinned toolchains (mise) and every package's dependencies
	@command -v mise >/dev/null 2>&1 || { echo "mise not found: install it from https://mise.jdx.dev" >&2; exit 1; }
	mise install
	mise run install

clean: ## Remove local build outputs
	rm -rf bin dist go/coverage.out ts/dist py/dist py/build py/*.egg-info py/src/*.egg-info rs/target

links: ## Check links repo-wide with lychee (skips with a NOTICE if absent)
	@if lychee --version >/dev/null 2>&1; then \
		lychee $(LYCHEE_FLAGS) .; \
	else \
		$(call notice,$@ skipped: lychee not installed; run make setup); \
	fi

##@ Go (go/go.mod, cli/go.mod)

# `go -C go` changes directory before anything else is parsed, so no subshell
# is needed. -buildvcs=false is required on every go invocation: VCS stamping
# fails with "error obtaining VCS status: exit status 128" inside a bare-repo
# worktree.
#
# Two modules: the library hop.top/pact-go (go/go.mod) and the commands
# hop.top/pact (cli/go.mod). Each go target runs once per module. go.work
# at the repository root resolves hop.top/pact-go for the command module from
# the tree.

go-test: ## Run Go tests (both modules)
	$(MISE) go -C go test -buildvcs=false ./...
	$(MISE) go -C cli test -buildvcs=false ./...

# go vet checks only the files that match GOOS, so the second pass type-checks
# the windows-tagged code on a darwin or linux host.
go-vet: ## Run go vet, then again with GOOS=windows (both modules)
	$(MISE) go -C go vet -buildvcs=false ./...
	$(MISE) go -C cli vet -buildvcs=false ./...
	GOOS=windows $(MISE) go -C go vet -buildvcs=false ./...
	GOOS=windows $(MISE) go -C cli vet -buildvcs=false ./...

# gofmt -l only lists; a non-empty list or a gofmt error fails the target. It
# walks directories, not modules, so it is given both module directories.
go-fmt: ## Fail when a Go file is not gofmt-clean
	@out=$$($(MISE) gofmt -l go cli) || exit 1; \
	if [ -n "$$out" ]; then echo "gofmt would change:" >&2; echo "$$out" >&2; exit 1; fi

# golangci-lint is not the go driver: it reads go/.golangci.yml from the working
# directory, so it needs a real `cd go`, and `cd cli` for the command module.
# It also walks up the parent directories and $HOME for a config, so until
# go/.golangci.* (or cli/.golangci.*) exists it runs with --no-config and a
# stray config outside the repo cannot change the result.
go-lint: ## Run golangci-lint on both modules (skips with a NOTICE if absent)
	@if (cd go && $(MISE) golangci-lint --version) >/dev/null 2>&1; then \
		(cd go && $(MISE) env GOFLAGS=-buildvcs=false golangci-lint run $(if $(wildcard go/.golangci.*),,--no-config) ./...) && \
		(cd cli && $(MISE) env GOFLAGS=-buildvcs=false golangci-lint run $(if $(wildcard cli/.golangci.*),,--no-config) ./...); \
	else \
		$(call notice,$@ skipped: golangci-lint not installed; run make setup); \
	fi

# `go build ./...` over a single main package would drop its binary in the
# module directory, so executables go to the gitignored cli/bin/. The library
# has no main package, and -o with a directory refuses a build without one.
go-build: ## Compile every Go package (executables land in cli/bin)
	$(MISE) go -C go build -buildvcs=false ./...
	$(MISE) go -C cli build -buildvcs=false -o bin/ ./...

# go-vectors prints the two Go legs of the parity check: pactconf for the
# vector and key entries, and the test binary of adapters/memory (built with
# go test -c, since the conformance suite takes a testing.TB) for the
# adapter-case entries. That binary finds the fixtures from its working
# directory, so it runs in go/. Both legs run even when the first fails, so
# the output is complete; the target fails when either does. core/jws
# implements Ed25519 negotiation, so pactconf declares jws-ed25519.
go-vectors: ## Print Go vector, key and adapter-case results as NDJSON
	@$(vectors_go)

# The windows leg of CI calls go-test-windows, with the test user and files of
# the Windows tier of go/adapters/files in its environment.
go-test-windows: ## Run the Go tests that must pass on Windows
	$(MISE) go -C go test -buildvcs=false ./adapters/files/...

##@ TypeScript (ts/package.json)

# PACT_REQUIRE_VECTORS=1: in the source repository a test or harness that
# reads spec/ fails when it is absent; in the package mirror it is a NOTICE.
ts-test: ## Run TypeScript tests
	cd ts && PACT_REQUIRE_VECTORS=1 $(MISE) pnpm run test

# Biome, then tsc --noEmit (node --test strips types without checking them),
# then the check that src/core/shapes.ts matches the generator.
ts-lint: ## Lint and type-check TypeScript
	cd ts && $(MISE) pnpm run lint

# The build, then the npm pack file list: dist/**, schema, README.md, LICENSE
# and package.json only, with every exports target present.
ts-build: ## Build the TypeScript package and check its file list
	cd ts && $(MISE) pnpm run build
	cd ts && $(MISE) pnpm run check-pack

ts-vectors: ## Print shared-vector results as NDJSON
	@$(vectors_ts)

ts-sync-schema: ## Copy the spec schema into ts/schema
	$(call sync-schema,$(TS_SCHEMA))

ts-check-schema: ## Fail when ts/schema differs from the spec schema
	$(call check-schema,$(TS_SCHEMA),ts-sync-schema)

# Each patch in ts/test/mutants must make the tests fail (tools/mutants.py).
ts-mutants: ## Run the TypeScript mutation patches
	$(MISE) python3 -I tools/mutants.py --package ts --patches ts/test/mutants \
		--link node_modules --with spec -- env PACT_REQUIRE_VECTORS=1 pnpm run test

##@ Python (py/pyproject.toml)

# PY_PYTHON is the interpreter of the package's virtualenv, which `mise run
# install` creates at py/.venv (pip install -c constraints.txt -e ".[dev]").
# A relative value is relative to py/; another virtualenv works with
# make PY_PYTHON=/path/to/venv/bin/python3.
PY_PYTHON ?= ./.venv/bin/python3
py_python_abs = $(if $(filter /%,$(PY_PYTHON)),$(PY_PYTHON),$(CURDIR)/py/$(PY_PYTHON))

# PACT_REQUIRE_VECTORS=1: in this repository spec/ is present, so a test
# that reads the shared fixtures fails instead of skipping when it is not.
py-test: ## Run Python tests
	cd py && PACT_REQUIRE_VECTORS=1 $(PY_PYTHON) -m pytest -q

# The last step fails when core/types.py or core/enums.py is stale against
# the vendored schema or go/core/enums.go.
py-lint: ## Lint, format-check and type-check Python (mypy --strict), check generated types
	cd py && $(PY_PYTHON) -m ruff check .
	cd py && $(PY_PYTHON) -m ruff format --check .
	cd py && $(PY_PYTHON) -m mypy
	cd py && $(PY_PYTHON) scripts/gen_types.py --check

py-build: ## Build the Python sdist and wheel
	cd py && $(PY_PYTHON) -m build

py-vectors: ## Print shared-vector results as NDJSON
	@$(vectors_py)

py-sync-schema: ## Copy the spec schema into the Python package
	$(call sync-schema,$(PY_SCHEMA))

py-check-schema: ## Fail when the Python package's schema differs from the spec schema
	$(call check-schema,$(PY_SCHEMA),py-sync-schema)

# Each patch of py/tests/mutants runs against a copy of py/ and spec/; the
# copy's src/ goes first on PYTHONPATH, ahead of the editable install.
py-mutants: ## Require every patch in py/tests/mutants to fail the Python tests
	$(MISE) python3 -I tools/mutants.py --package py --patches py/tests/mutants --copy spec -- \
		env PYTHONPATH=src PACT_REQUIRE_VECTORS=1 $(py_python_abs) -m pytest -q -p no:cacheprovider

# The long seeded run of the JCS property test (py/tests/test_jcs_property.py),
# the counterpart of Go's nightly fuzz: PY_FUZZ_EXAMPLES random trees and ten
# times as many random doubles, against the rfc8785 oracle.
PY_FUZZ_EXAMPLES ?= 20000
.PHONY: py-fuzz
py-fuzz: ## Run the Python JCS property test with a long seeded run
	cd py && PACT_FUZZ_EXAMPLES=$(PY_FUZZ_EXAMPLES) $(PY_PYTHON) -m pytest -q -p no:cacheprovider tests/test_jcs_property.py

##@ Rust (rs/Cargo.toml)

# PACT_REQUIRE_VECTORS=1: in the source repository a test or harness that
# reads spec/ fails when it is absent; in the package mirror it is a NOTICE.
# --locked: Cargo.lock holds the vetted versions (docs/sdk/deps-rs.md).
rs-test: ## Run Rust tests
	cd rs && PACT_REQUIRE_VECTORS=1 $(MISE) cargo test --locked --all-targets
	cd rs && PACT_REQUIRE_VECTORS=1 $(MISE) cargo test --locked --doc

rs-lint: ## Check rustfmt and clippy
	cd rs && $(MISE) cargo fmt --check
	cd rs && $(MISE) cargo clippy --locked --all-targets --all-features -- -D warnings

# The build, then the package: cargo package builds the crate from its
# packaged file list, which must hold the vendored schema (no ../spec path
# reaches a published crate).
rs-build: ## Build the Rust crate and check its package
	cd rs && $(MISE) cargo build --locked
	cd rs && $(MISE) cargo package --locked --allow-dirty --quiet

rs-vectors: ## Print shared-vector results as NDJSON
	@$(vectors_rs)

# Each patch in rs/tests/mutants must make the tests fail (tools/mutants.py).
# The copies link spec/ for the vectors and docs/ for the dependency guard,
# which checks docs/sdk/deps-rs.md.
# Cargo comes from rs/mise.toml: the runner starts in rs/. The copies share
# one target directory, so only the crate itself rebuilds.
# A copy keeps the modification times of the files it copies, and cargo
# judges a path package fresh by them, so each copy's sources are touched
# first: no copy can reuse the build of another.
rs-mutants: ## Run the Rust mutation patches
	cd rs && $(MISE) python3 -I ../tools/mutants.py --package rs --patches $(CURDIR)/rs/tests/mutants --with spec --with docs -q -- \
		sh -c 'find src tests examples -type f -exec touch {} + && \
		PACT_REQUIRE_VECTORS=1 CARGO_TARGET_DIR="$$0" cargo test --locked --all-targets -q' $(CURDIR)/rs/target/mutants

rs-sync-schema: ## Copy the spec schema into rs/schema
	$(call sync-schema,$(RS_SCHEMA))

rs-check-schema: ## Fail when rs/schema differs from the spec schema
	$(call check-schema,$(RS_SCHEMA),rs-sync-schema)

##@ PHP (php/composer.json)

# php and composer come from PATH, never from mise.toml (mise builds php from
# source): php-* targets run them without $(MISE). Without both on PATH each
# php-* target prints a NOTICE and succeeds.
PHP_TOOLS := $(and $(shell command -v php 2>/dev/null),$(shell command -v composer 2>/dev/null))
ifeq ($(PHP_TOOLS),)
php-test php-lint php-build php-vectors php-mutants:
	@$(call notice,$@ skipped: php or composer not on PATH)
else
# PACT_REQUIRE_VECTORS=1: in this repository spec/ is present, so a test or
# harness that reads the shared fixtures fails instead of skipping when it
# is not.
php-test: ## Run PHP tests
	cd php && PACT_REQUIRE_VECTORS=1 composer run-script test

# PHP CS Fixer in check mode, then PHPStan at level max.
php-lint: ## Check PHP code style and run PHPStan
	cd php && composer run-script lint

# --no-check-all: composer.json pins exact versions on purpose
# (docs/sdk/deps-php.md), which plain --strict reports as a warning. The
# lock file is still checked against composer.json.
php-build: ## Validate the PHP package metadata and lock file
	cd php && composer validate --strict --no-check-all

php-vectors: ## Print shared-vector results as NDJSON
	@$(vectors_php)

# Each patch of php/tests/mutants runs against a copy of php/, vendor/
# included: Composer's autoloader resolves its own real path, so a linked
# vendor/ would load the unpatched src/. spec, go, tools and docs are linked
# for the tests that read the fixtures, the Go sources, the gates file and the
# dependency record (docs/sdk/deps-php.md).
.PHONY: php-mutants
php-mutants: ## Require every patch in php/tests/mutants to fail the PHP tests
	$(MISE) python3 -I tools/mutants.py --package php --patches php/tests/mutants \
		--with spec --with go --with tools --with docs -q -- env PACT_REQUIRE_VECTORS=1 php vendor/bin/phpunit
endif

php-sync-schema: ## Copy the spec schema into php/schema
	$(call sync-schema,$(PHP_SCHEMA))

php-check-schema: ## Fail when php/schema differs from the spec schema
	$(call check-schema,$(PHP_SCHEMA),php-sync-schema)

##@ Spec

# spec-validate, spec-examples and spec-manifest run from the virtualenv at tools/spec/.venv.
# The file rule below creates it from tools/spec/requirements.txt, and again
# whenever that file changes. The pinned packages need Python 3.11 or later;
# SPEC_PYTHON picks the interpreter that creates the virtualenv, for example
# make MISE= SPEC_PYTHON=/usr/bin/python3.12 spec-validate
SPEC_PYTHON ?= $(MISE) python3
SPEC_VENV := tools/spec/.venv

$(SPEC_VENV)/bin/check-jsonschema: tools/spec/requirements.txt
	@$(SPEC_PYTHON) -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else "tools/spec/requirements.txt needs Python 3.11 or later; set SPEC_PYTHON")'
	$(SPEC_PYTHON) -m venv --clear $(SPEC_VENV)
	$(SPEC_VENV)/bin/python3 -m pip install --quiet --disable-pip-version-check -r tools/spec/requirements.txt
	touch $@

# The first command checks that the schema declares the 2020-12 dialect,
# because the second one validates against whatever dialect it declares.
spec-validate: $(SPEC_VENV)/bin/check-jsonschema ## Meta-validate the spec schema (JSON Schema 2020-12)
	$(SPEC_VENV)/bin/check-jsonschema --schemafile tools/spec/schema-dialect.json $(SCHEMA_SRC)
	$(SPEC_VENV)/bin/check-jsonschema --check-metaschema $(SCHEMA_SRC)

spec-examples: $(SPEC_VENV)/bin/check-jsonschema ## Parse and validate the JSON blocks in spec/v1.0/examples
	$(SPEC_VENV)/bin/python3 -I scripts/check-spec-examples.py

spec-links: ## Check spec and docs links and spec self-containment
	$(MISE) lychee --config .lychee.toml --offline --include-fragments spec docs
	$(MISE) python3 -I scripts/check-spec-selfcontained.py

spec-map: ## Check spec/v1.0/spec-map.md rows against the draft and fixtures
	$(MISE) python3 -I scripts/check-spec-map.py

# spec-manifest applies the manifest rules of spec/v1.0/fixtures/README.md
# (scripts/check-spec-manifest.py, standard library only), then validates the
# manifest against spec/v1.0/fixtures/manifest.schema.json with check-jsonschema
# from the virtualenv above, independently of both hand-written checkers.
spec-manifest: $(SPEC_VENV)/bin/check-jsonschema ## Check spec/v1.0/fixtures/manifest.json: every manifest rule, then its JSON Schema
	$(MISE) python3 -I scripts/check-spec-manifest.py
	$(SPEC_VENV)/bin/check-jsonschema --schemafile spec/v1.0/fixtures/manifest.schema.json spec/v1.0/fixtures/manifest.json

# spec-parity runs scripts/check-spec-manifest.py, scripts/check-spec-map.py
# and pactfix check manifest on broken copies of spec/v1.0/fixtures, at least one
# per rule, and fails unless both sides report each rule. The script builds
# pactfix with the go command on PATH, or the one the GO environment variable
# names; the package path is a constant at its top.
.PHONY: spec-parity
spec-parity: ## Check that the Python and Go manifest checks enforce the same rules
	$(MISE) python3 -I scripts/check-manifest-parity.py

##@ Conformance and parity

# conformance builds pactc and runs every manifest entry of spec/v1.0/fixtures
# against an implementation under test, writing the pactc/v1 report (pactc
# run --json) to CONFORMANCE_REPORT. It fails when pactc does: a check is FAIL
# (exit status 1), a usage error or a run that cannot start (2), or a run that
# selects no entry (3). pactc writes the report when a check is FAIL too.
# Extra pactc flags (the --*-cmd adapter commands, --capability, --fixture)
# go in PACTC_ARGS. When PACTC_ARGS names no --*-cmd, the implementation is
# the fake one of the runner tests, go/runner/testdata/fakeimpl/impl.sh, in
# the mode FAKEIMPL_MODE names: good prints its golden responses, the other
# modes inject one defect each (impl.sh lists them and the cases they touch).
# The fake implementation declares every optional capability
# (go/runner/manifest Capabilities).
# go -C changes directory, so the fixtures root is passed as an absolute path.
# pactc is in the command module; go.work builds it with the library of the
# tree.
CONFORMANCE_DIR := bin/conformance
CONFORMANCE_REPORT ?= $(CONFORMANCE_DIR)/pactc.json
FAKEIMPL := $(CURDIR)/go/runner/testdata/fakeimpl/impl.sh
FAKEIMPL_MODE ?= good
fakeimpl_args = --capability jws-ed25519 \
	--evaluate-cmd "$(FAKEIMPL) evaluate {dir} {state}" \
	--receipt-cmd "$(FAKEIMPL) receipt {state} {id}" \
	--outcomes-cmd "$(FAKEIMPL) outcomes {dir} {state}" \
	--learning-cmd "$(FAKEIMPL) learning {dir} {state}" \
	--schema-cmd "$(FAKEIMPL) schema {dir}"
ifeq ($(wildcard cli/pactc),)
conformance:
	@$(call notice,$@ skipped: cli/pactc absent)
else
conformance: ## Run pactc over spec/v1.0/fixtures against the fake implementation, or the one PACTC_ARGS names
	@mkdir -p $(CONFORMANCE_DIR) $(dir $(CONFORMANCE_REPORT))
	$(MISE) go -C cli build -buildvcs=false -o $(CURDIR)/$(CONFORMANCE_DIR)/pactc ./pactc
	@status=0; FAKEIMPL_MODE=$(FAKEIMPL_MODE) $(CONFORMANCE_DIR)/pactc run --json \
		--fixtures-root $(CURDIR)/spec/v1.0/fixtures \
		$(if $(findstring -cmd,$(PACTC_ARGS)),,$(fakeimpl_args)) $(PACTC_ARGS) \
		> $(CONFORMANCE_REPORT) || status=$$?; \
	echo "conformance: pactc exit status $$status, report $(CONFORMANCE_REPORT)"; \
	exit $$status
endif

# The command of each <lang>-vectors target, shared with parity, which runs
# it with standard output in $(PARITY_DIR)/<lang>.ndjson. The go command is
# the two Go legs described above go-vectors.
vectors_go = status=0; \
	$(MISE) go -C cli run -buildvcs=false ./pactconf vectors verify --ndjson --capability jws-ed25519 || status=1; \
	{ $(MISE) go -C go test -c -buildvcs=false -o bin/memory-cases.test ./adapters/memory && \
		(cd go && ./bin/memory-cases.test -ndjson); } || status=1; \
	exit $$status
vectors_ts = cd ts && PACT_REQUIRE_VECTORS=1 $(MISE) pnpm --silent run vectors
vectors_py = cd py && $(PY_PYTHON) -m hop_top_pact.vectors
vectors_rs = cd rs && PACT_REQUIRE_VECTORS=1 $(MISE) cargo run --quiet --locked --example vectors -- \
	--gates ../tools/parity/gates.json ../spec/v1.0/fixtures/manifest.json
vectors_php = cd php && PACT_REQUIRE_VECTORS=1 php scripts/vectors.php

# A language takes part in parity when its package manifest exists (the
# guards above); Go always does. The others are reported "not present", which
# fails only when tools/parity/gates.json has a gate required for them.
PARITY_DIR := bin/parity
PARITY_LANGS := go $(if $(wildcard ts/package.json),ts) $(if $(wildcard py/pyproject.toml),py) \
	$(if $(wildcard rs/Cargo.toml),rs) $(if $(and $(wildcard php/composer.json),$(PHP_TOOLS)),php)
# Extra tools/parity/parity.py check flags, such as --runner-report go=FILE
# for a pactc/v1 report (pactc run --json) of the runner leg.
PARITY_ARGS ?=
# The runner leg of go is the report of conformance (tools/parity/README.md,
# Go legs). CI passes the report its conformance step wrote through
# PARITY_ARGS; without a --runner-report there, parity runs conformance first
# and reads CONFORMANCE_REPORT.
parity_runner := $(if $(wildcard cli/pactc),$(if $(findstring --runner-report,$(PARITY_ARGS)),,--runner-report go=$(CONFORMANCE_REPORT)))

# Every leg runs, whatever the exit status of the one before, so the
# comparison is complete; each status is passed on and a non-zero one fails.
# --fill-na go: entries that no Go leg prints (runner entries outside the
# kinds pactc runs, native adapter cases, adapter assets) count as
# skipped:out-of-scope where their gate is n/a
# for go, and as missing anywhere else.
parity: $(if $(parity_runner),conformance) ## Compare all five languages on the shared vectors (tools/parity/gates.json)
	@rm -rf $(PARITY_DIR) && mkdir -p $(PARITY_DIR)
	@set --; \
	$(foreach l,$(PARITY_LANGS),( $(vectors_$(l)) ) > $(PARITY_DIR)/$(l).ndjson; \
	set -- "$$@" --results $(l)=$(PARITY_DIR)/$(l).ndjson --status $(l)=$$?; ) \
	$(MISE) python3 -I tools/parity/parity.py check --fill-na go "$$@" $(parity_runner) $(PARITY_ARGS)

parity-selftest: ## Mutation-test the parity comparator on synthetic NDJSON
	$(MISE) python3 -I tools/parity/selftest.py

# parity-rows is the row check of parity alone: every manifest (scope, kind,
# prefix) has a row in tools/parity/gates.json, and every row has entries.
# ci-spec runs it, so a fixture change cannot merge unclassified.
.PHONY: parity-rows
parity-rows: ## Check that tools/parity/gates.json classifies every manifest row
	$(MISE) python3 -I tools/parity/parity.py rows

##@ Release

release-check: ## Check the publish map against the release config
	$(MISE) python3 -I tools/release/check-publish-map.py

release-rehearsal: ## Rehearse the mirror and release flow on scratch repos
	@$(call notice,$@ skipped: rehearsal not landed)
