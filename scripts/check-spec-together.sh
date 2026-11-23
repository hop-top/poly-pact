#!/usr/bin/env bash
# Move-together gate: a change to the draft needs a change to the schema.
#
# Usage: scripts/check-spec-together.sh BASE HEAD
#
# Fails when spec/v1.0/draft.md changed between BASE and HEAD (git diff --name-only
# BASE...HEAD, the changes since their merge base) and spec/v1.0/schemas/
# pact.schema.json did not, unless:
#   - the draft.md diff only updates SemVer literals on lines marked with
#     x-release-please-version (release-please version bumps), or
#   - a commit in that range carries a trailer
#
#     Schema-Unchanged: <reason>
#
# in the last paragraph of its message, with a non-empty reason. The key is
# matched with exactly this case. It needs the history of both revisions: a
# shallow checkout has to be deepened first (actions/checkout fetch-depth: 0).
#
# Exit status: 0 allowed; 1 draft changed without the schema and no trailer;
# 2 usage error or revisions that cannot be compared.
set -euo pipefail

draft=spec/v1.0/draft.md
schema=spec/v1.0/schemas/pact.schema.json
key=Schema-Unchanged

if [ "$#" -ne 2 ]; then
  echo "usage: $0 BASE HEAD" >&2
  exit 2
fi
base=$1
head=$2

for rev in "$base" "$head"; do
  if ! git rev-parse --verify --quiet "$rev^{commit}" >/dev/null; then
    echo "check-spec-together: $rev is not a commit in this repository" >&2
    exit 2
  fi
done
if ! merge_base=$(git merge-base "$base" "$head"); then
  echo "check-spec-together: no merge base for $base and $head; fetch the full history" >&2
  exit 2
fi

changed=$(git diff --name-only "$base...$head" -- "$draft" "$schema")

if ! grep -Fxq "$draft" <<<"$changed"; then
  echo "check-spec-together: ok ($draft unchanged)"
  exit 0
fi
if grep -Fxq "$schema" <<<"$changed"; then
  echo "check-spec-together: ok ($draft and $schema both changed)"
  exit 0
fi

is_release_version_only() {
  git diff --no-color --no-ext-diff -U0 "$base...$head" -- "$draft" | awk '
    function flush_hunk(    i) {
      if (!in_hunk) return
      if (n_old == 0 || n_old != n_new) { bad = 1; exit 1 }
      for (i = 1; i <= n_old; i++) {
        if (old_norm[i] != new_norm[i]) { bad = 1; exit 1 }
      }
      total += n_old
      n_old = 0
      n_new = 0
    }
    function normalize(s,    n) {
      if (index(s, "x-release-please-version") == 0) { bad = 1; exit 1 }
      n = gsub(/[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?/, "<VERSION>", s)
      if (n == 0) { bad = 1; exit 1 }
      return s
    }
    !in_hunk && /^(old mode|new mode|deleted file mode|new file mode|rename from|rename to|copy from|copy to|Binary files) / {
      bad = 1; exit 1
    }
    /^@@ / {
      flush_hunk()
      in_hunk = 1
      next
    }
    in_hunk {
      prefix = substr($0, 1, 1)
      body = substr($0, 2)
      if (prefix == "-") {
        old_norm[++n_old] = normalize(body)
      } else if (prefix == "+") {
        new_norm[++n_new] = normalize(body)
      } else {
        bad = 1; exit 1
      }
    }
    END {
      if (bad) exit 1
      flush_hunk()
      exit (total > 0 ? 0 : 1)
    }
  '
}

if is_release_version_only; then
  echo "check-spec-together: ok ($draft changed, $schema did not; release-please version bump only)"
  exit 0
fi

trailers=$(git log --format="%(trailers:key=$key,unfold)" "$merge_base..$head")
if grep -Eq "^$key: +[^[:space:]]" <<<"$trailers"; then
  echo "check-spec-together: ok ($draft changed, $schema did not; $(grep -E "^$key: " <<<"$trailers" | head -1))"
  exit 0
fi

cat >&2 <<MSG
check-spec-together: $draft changed but $schema did not.
  Change the schema in the same pull request, or state why it stays as it is:
  add a trailer line "$key: <reason>" to the last paragraph of the message of
  a commit in this range ($merge_base..$head).
MSG
exit 1
