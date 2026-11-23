#!/usr/bin/env bats
# Tests for scripts/check-spec-together.sh.
#
# Run: bats scripts/check-spec-together.bats

SCRIPT="$BATS_TEST_DIRNAME/check-spec-together.sh"
DRAFT="spec/v1.0/draft.md"
SCHEMA="spec/v1.0/schemas/pact.schema.json"

setup() {
  unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY
  export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1

  TMP="$(mktemp -d)"
  REPO="$TMP/repo"
  git init -q -b next "$REPO"
  git -C "$REPO" config user.email test@example.com
  git -C "$REPO" config user.name test

  mkdir -p "$REPO/spec/v1.0/schemas"
  cat >"$REPO/$DRAFT" <<'EOF'
---
title: "PACT Protocol Specification"
spec_version: "1.0.0-alpha.0" # x-release-please-version
wire_version: "0.1"
status: "Draft"
---

# PACT Protocol Specification

* **Status:** Draft | **Spec version:** 1.0.0-alpha.0 | **Wire version:** `0.1` <!-- x-release-please-version -->

Normative text.
EOF
  printf '{"$schema":"https://json-schema.org/draft/2020-12/schema"}\n' >"$REPO/$SCHEMA"

  git -C "$REPO" add .
  git -C "$REPO" commit -q -m "chore: seed"
  BASE="$(git -C "$REPO" rev-parse HEAD)"
}

teardown() {
  rm -rf "$TMP"
}

run_check() {
  local head
  head="$(git -C "$REPO" rev-parse HEAD)"
  run bash -c 'cd "$1" && "$2" "$3" "$4"' _ "$REPO" "$SCRIPT" "$BASE" "$head"
}

@test "passes when draft is unchanged" {
  printf 'note\n' >"$REPO/README.md"
  git -C "$REPO" add README.md
  git -C "$REPO" commit -q -m "docs: readme"

  run_check
  [ "$status" -eq 0 ]
  [[ "$output" == *"draft.md unchanged"* ]]
}

@test "passes when draft and schema both change" {
  printf '\nMore normative text.\n' >>"$REPO/$DRAFT"
  printf '{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}\n' >"$REPO/$SCHEMA"
  git -C "$REPO" add "$DRAFT" "$SCHEMA"
  git -C "$REPO" commit -q -m "feat(spec): update draft and schema"

  run_check
  [ "$status" -eq 0 ]
  [[ "$output" == *"both changed"* ]]
}

@test "passes when draft changes with Schema-Unchanged trailer" {
  printf '\nEditorial clarification.\n' >>"$REPO/$DRAFT"
  git -C "$REPO" add "$DRAFT"
  git -C "$REPO" commit -q -m "docs(spec): clarify wording" -m "Schema-Unchanged: editorial only"

  run_check
  [ "$status" -eq 0 ]
  [[ "$output" == *"Schema-Unchanged: editorial only"* ]]
}

@test "passes when draft changes only x-release-please-version lines (prerelease bump)" {
  sed -i.bak 's/1\.0\.0-alpha\.0/1.0.0-alpha.1/g' "$REPO/$DRAFT"
  rm -f "$REPO/$DRAFT.bak"
  git -C "$REPO" add "$DRAFT"
  git -C "$REPO" commit -q -m "chore(release): pact-spec 1.0.0-alpha.1"

  run_check
  [ "$status" -eq 0 ]
  [[ "$output" == *"release-please version bump only"* ]]
}

@test "passes when draft changes x-release-please-version across channels to stable" {
  sed -i.bak 's/1\.0\.0-alpha\.0/1.0.0/g' "$REPO/$DRAFT"
  rm -f "$REPO/$DRAFT.bak"
  git -C "$REPO" add "$DRAFT"
  git -C "$REPO" commit -q -m "chore(release): pact-spec 1.0.0"

  run_check
  [ "$status" -eq 0 ]
}

@test "passes when draft bumps only one x-release-please-version line" {
  sed -i.bak 's/spec_version: "1\.0\.0-alpha\.0"/spec_version: "1.0.0-beta.0"/' "$REPO/$DRAFT"
  rm -f "$REPO/$DRAFT.bak"
  git -C "$REPO" add "$DRAFT"
  git -C "$REPO" commit -q -m "chore(release): pact-spec 1.0.0-beta.0"

  run_check
  [ "$status" -eq 0 ]
}

@test "fails when draft bumps version and also edits substantive text" {
  sed -i.bak 's/1\.0\.0-alpha\.0/1.0.0-alpha.1/g' "$REPO/$DRAFT"
  rm -f "$REPO/$DRAFT.bak"
  printf '\nExtra normative requirement.\n' >>"$REPO/$DRAFT"
  git -C "$REPO" add "$DRAFT"
  git -C "$REPO" commit -q -m "chore(release): sneaky change"

  run_check
  [ "$status" -eq 1 ]
}

@test "fails when draft edits non-version content on an x-release-please-version line" {
  sed -i.bak 's/Wire version:\*\* `0\.1`/Wire version:** `0.2`/' "$REPO/$DRAFT"
  rm -f "$REPO/$DRAFT.bak"
  git -C "$REPO" add "$DRAFT"
  git -C "$REPO" commit -q -m "docs(spec): bump wire version"

  run_check
  [ "$status" -eq 1 ]
}

@test "fails when draft changes status on an x-release-please-version line" {
  sed -i.bak 's/\*\*Status:\*\* Draft/\*\*Status:\*\* Approved/' "$REPO/$DRAFT"
  rm -f "$REPO/$DRAFT.bak"
  git -C "$REPO" add "$DRAFT"
  git -C "$REPO" commit -q -m "docs(spec): change status"

  run_check
  [ "$status" -eq 1 ]
}

@test "fails when draft adds a new line with x-release-please-version marker" {
  printf 'extra: "1.0.0" # x-release-please-version\n' >>"$REPO/$DRAFT"
  git -C "$REPO" add "$DRAFT"
  git -C "$REPO" commit -q -m "docs(spec): add marked line"

  run_check
  [ "$status" -eq 1 ]
}

@test "fails when draft deletes an x-release-please-version line" {
  grep -v 'spec_version:' "$REPO/$DRAFT" >"$REPO/$DRAFT.tmp"
  mv "$REPO/$DRAFT.tmp" "$REPO/$DRAFT"
  git -C "$REPO" add "$DRAFT"
  git -C "$REPO" commit -q -m "docs(spec): delete marked line"

  run_check
  [ "$status" -eq 1 ]
}

@test "fails when draft moves an x-release-please-version line to another hunk" {
  grep -v 'spec_version:' "$REPO/$DRAFT" >"$REPO/$DRAFT.tmp"
  printf 'spec_version: "1.0.0-alpha.1" # x-release-please-version\n' >>"$REPO/$DRAFT.tmp"
  mv "$REPO/$DRAFT.tmp" "$REPO/$DRAFT"
  git -C "$REPO" add "$DRAFT"
  git -C "$REPO" commit -q -m "docs(spec): move marked line"

  run_check
  [ "$status" -eq 1 ]
}

@test "fails when draft changes file mode only" {
  chmod +x "$REPO/$DRAFT"
  git -C "$REPO" add "$DRAFT"
  git -C "$REPO" commit -q -m "chore(spec): chmod draft"

  run_check
  [ "$status" -eq 1 ]
}

@test "fails when draft changes substantive text without schema or trailer" {
  printf '\nSubstantive change.\n' >>"$REPO/$DRAFT"
  git -C "$REPO" add "$DRAFT"
  git -C "$REPO" commit -q -m "docs(spec): substantive change"

  run_check
  [ "$status" -eq 1 ]
}
