"""Entry point of ``python -m hop_top_pact.vectors [MANIFEST]``.

Plain argv, no command-line framework: make py-vectors and make parity drive
it. MANIFEST defaults to ../spec/v1.0/fixtures/manifest.json, the source
repository's manifest seen from py/. When the default is absent (a mirror
checkout) the harness prints a NOTICE on standard error and succeeds, unless
PACT_REQUIRE_VECTORS=1, which makes the absence an error.

Every vector and key entry of scope core and adapter runs through the
package function of its group (GROUPS) and is compared with its outcome and
expected file: pass or fail. Every adapter-case entry of adapters/_common is
the result of the conformance suite against the memory adapter, in both
workload modes (_adapters). An entry that lists an optional capability the
harness does not declare is skipped:capability; the Ed25519 key, a spec
defect of the digest protocol and every other entry (scope runner, or a
kind the harness does not run) are skipped. Standard output carries one
NDJSON line per entry and nothing else; every row that is not a pass and the
summary line go to standard error.

Exit status: 0 when no entry fails under a gate required for py (a fail
under a planned gate is printed and counted); 1 when one does; 2 on a
harness error (usage, unreadable or malformed manifest or gates file,
unknown kind, scope, prefix or capability, duplicate id), which prints
nothing on standard output.
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from hop_top_pact.adapter.adaptertest import LoadError
from hop_top_pact.vectors import DECLARED_CAPABILITIES
from hop_top_pact.vectors._adapters import CaseLine, evaluate_modes, is_common_case
from hop_top_pact.vectors._common import (
    CAPABILITY,
    OUT_OF_SCOPE,
    Entry,
    HarnessError,
    Skipped,
    load_manifest,
    prefix,
    runs,
)
from hop_top_pact.vectors._gates import gates_path, load_gates
from hop_top_pact.vectors._groups import (
    run_binding,
    run_digest,
    run_jcs,
    run_schema,
    run_strictjson,
)
from hop_top_pact.vectors._jws import run_jws, run_key

DEFAULT_MANIFEST = Path("..") / "spec" / "v1.0" / "fixtures" / "manifest.json"

RUNNERS: dict[tuple[str, str], Callable[[Path, Entry], None]] = {
    ("key", "keys"): run_key,
    ("vector", "vectors/binding"): run_binding,
    ("vector", "vectors/digest"): run_digest,
    ("vector", "vectors/jcs"): run_jcs,
    ("vector", "vectors/jws"): run_jws,
    ("vector", "vectors/schema"): run_schema,
    ("vector", "vectors/strictjson"): run_strictjson,
}


def one_line(s: str) -> str:
    return " ".join(s.split())


def common_case(e: Entry) -> bool:
    return is_common_case(e.kind, e.scope, e.id)


def run_case_entry(e: Entry, cases: dict[str, CaseLine]) -> tuple[dict[str, Any], str]:
    """The line of a common adapter case, from the suite's results."""
    c = cases.get(e.id)
    if c is None:
        return {"id": e.id, "kind": e.kind, "result": "fail"}, "no common case has this id"
    return {"id": e.id, "kind": e.kind, "result": c.result}, "; ".join(c.failures)


def run_entry(root: Path, e: Entry) -> tuple[dict[str, Any], str]:
    """The NDJSON line of e and the detail of a row that is not a pass."""
    line: dict[str, Any] = {"id": e.id, "kind": e.kind}
    if not runs(e):
        line["result"] = "skipped:" + OUT_OF_SCOPE
        return line, ""
    missing = [c for c in e.capabilities or () if c not in DECLARED_CAPABILITIES]
    try:
        if missing:
            raise Skipped(
                CAPABILITY,
                f"optional capability {', '.join(missing)} not declared: the entry is not run",
                missing=missing,
            )
        RUNNERS[(e.kind, prefix(e))](root, e)
    except Skipped as s:
        line["result"] = "skipped:" + s.reason
        if s.defects:
            line["spec_defects"] = s.defects
        if s.missing:
            line["missing_capabilities"] = s.missing
        return line, str(s)
    except NotImplementedError as err:
        line["result"] = "fail"
        return line, f"not implemented: {err}"
    except Exception as err:
        line["result"] = "fail"
        return line, str(err) or type(err).__name__
    line["result"] = "pass"
    return line, ""


def run(path: Path) -> int:
    entries = load_manifest(path)
    gp = gates_path(path)
    gates = load_gates(gp) if gp is not None and gp.is_file() else None
    if gates is None:
        print(f"NOTICE: no gates file beside {path}: no gate is required", file=sys.stderr)
    root = path.parent
    cases: dict[str, CaseLine] = {}
    if any(common_case(e) for e in entries):
        try:
            cases = {c.id: c for c in evaluate_modes(root)}
        except LoadError as err:
            raise HarnessError(f"adapter cases: {err}") from err
    lines: list[str] = []
    count: Counter[str] = Counter()
    blocking = 0
    for e in entries:
        line, detail = run_case_entry(e, cases) if common_case(e) else run_entry(root, e)
        result = str(line["result"])
        count[result] += 1
        if (runs(e) or common_case(e)) and result != "pass":
            row = "FAIL" if result == "fail" else "SKIP"
            print(f"{row} {e.id}: {one_line(detail)}", file=sys.stderr)
        if result == "fail" and gates is not None:
            gate = gates.get((e.scope, e.kind, prefix(e)))
            if gate is not None and gate.value == "required" and e.id not in gate.exceptions:
                blocking += 1
        lines.append(json.dumps(line, ensure_ascii=False, separators=(",", ":")))
    sys.stdout.write("".join(x + "\n" for x in lines))
    skipped = {r.removeprefix("skipped:"): n for r, n in count.items() if r.startswith("skipped:")}
    print(
        f"vectors: {count['pass']} passed, {count['fail']} failed, {sum(skipped.values())} skipped"
        f" (out-of-scope {skipped.get('out-of-scope', 0)}, spec-defect"
        f" {skipped.get('spec-defect', 0)}, capability {skipped.get('capability', 0)});"
        f" {blocking} failed under a required gate",
        file=sys.stderr,
    )
    return 1 if blocking else 0


def main(argv: list[str]) -> int:
    if len(argv) > 1 or (argv and argv[0].startswith("-")):
        print("usage: python -m hop_top_pact.vectors [MANIFEST]", file=sys.stderr)
        return 2
    path = Path(argv[0]) if argv else DEFAULT_MANIFEST
    if not argv and not path.exists() and os.environ.get("PACT_REQUIRE_VECTORS") != "1":
        print(f"NOTICE: vectors skipped: {path} absent", file=sys.stderr)
        return 0
    try:
        return run(path)
    except HarnessError as e:
        print(f"vectors: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
