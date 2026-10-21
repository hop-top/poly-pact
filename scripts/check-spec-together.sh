#!/usr/bin/env bash
# Move-together gate: a change to the draft needs a change to the schema.
#
# Usage: scripts/check-spec-together.sh BASE HEAD
#
# Fails when spec/v1.0/draft.md changed between BASE and HEAD (git diff --name-only
# BASE...HEAD, the changes since their merge base) and spec/v1.0/schemas/
# pact.schema.json did not, unless a commit in that range carries a trailer
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
