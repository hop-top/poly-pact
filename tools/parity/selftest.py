#!/usr/bin/env python3
"""Mutation test of the parity comparator, tools/parity/parity.py.

Builds a small synthetic fixture tree (manifest, two digest vector files),
a gates file and one NDJSON result stream per language in a scratch
directory, then runs parity.py on a clean baseline and on one mutated copy
per rule. The baseline must exit 0; each mutation must exit with the status
it names and print its rule id on standard error, so a comparator that fails
for the wrong reason does not count. The cases required by
tools/parity/README.md (Self-test) are the first five: a wrong outcome under
a required gate, a missing id, a manifest prefix without a gate row, a
skipped:spec-defect on a vector without the flag, and a pass under an n/a
gate. The rest cover the other rules of parity.py.

Standard library only (Python 3.9 and later). Run it isolated:

    python3 -I tools/parity/selftest.py [-v]

Exit status: 0 when every case behaves as stated, 1 when one does not, 2 when
the self-test cannot run.
"""

import copy
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.realpath(__file__))
PARITY = os.path.join(HERE, "parity.py")


def entry(id_, kind, scope, path, capabilities=None):
    e = {
        "id": id_,
        "kind": kind,
        "scope": scope,
        "path": path,
        "expected": None if kind == "key" else path,
        "outcome": None if kind == "key" else "ACCEPTED",
        "spec_map_row": "R01",
        "draft_section": "1",
    }
    if capabilities:
        e["capabilities"] = capabilities
    return e


def gate(scope, kind, prefix, go, ts, py="planned", rs="planned", php="planned", exceptions=None):
    r = {
        "scope": scope,
        "kind": kind,
        "prefix": prefix,
        "go": go,
        "ts": ts,
        "py": py,
        "rs": rs,
        "php": php,
        "flipped_by": "selftest",
    }
    if exceptions is not None:
        r["exceptions"] = exceptions
    return r


DEFECT = {"vector": "printed-wrong", "appendix_value": "AAAA", "expected_digest": "BBBB"}


def baseline():
    """A state the comparator must accept: exit status 0."""
    manifest = {
        "manifest_version": 1,
        "entries": [
            entry("adapters/_common/c1", "adapter-case", "adapter", "adapters/_common/c1.json"),
            entry("adapters/native/n1", "adapter-case", "adapter", "adapters/native/n1.json"),
            entry("admission/a", "evaluate", "runner", "admission/a"),
            entry("admission/b", "evaluate", "runner", "admission/b", ["jws-ed25519"]),
            entry("keys/a", "key", "core", "keys/a.jwk.json"),
            entry("keys/ed", "key", "core", "keys/ed.jwk.json"),
            entry("sources/demo/s1.join", "source-case", "adapter", "sources/demo/s1.join.json"),
            entry("vectors/digest/flagged", "vector", "core", "vectors/digest/flagged.json"),
            entry("vectors/digest/plain", "vector", "core", "vectors/digest/plain.json"),
            entry("vectors/jws/opt", "vector", "core", "vectors/jws/opt.json", ["jws-ed25519"]),
        ],
    }
    gates = {
        "gates_version": 1,
        "rows": [
            gate("adapter", "adapter-case", "adapters/_common", "required", "planned", rs="n/a", php="n/a"),
            gate("adapter", "adapter-case", "adapters/native", "n/a", "n/a", "n/a", "n/a", "n/a"),
            gate("adapter", "source-case", "sources/demo", "n/a", "n/a", "n/a", "n/a", "n/a"),
            gate("core", "key", "keys", "required", "required",
                 exceptions=[{"id": "keys/ed", "reason": "optional algorithm"}]),
            gate("core", "vector", "vectors/digest", "required", "required"),
            gate("core", "vector", "vectors/jws", "required", "planned"),
            gate("runner", "evaluate", "admission", "n/a", "n/a", "n/a", "n/a", "n/a"),
        ],
    }
    files = {
        "vectors/digest/flagged.json": [
            {"id": "printed-right", "spec_defect": False},
            {"id": "printed-wrong", "spec_defect": True},
        ],
        "vectors/digest/plain.json": [{"id": "printed-right", "spec_defect": False}],
    }

    def line(id_, kind, result, **extra):
        out = {"id": id_, "kind": kind, "result": result}
        out.update(extra)
        return out

    # Go: the adapters/native and runner entries are absent; --fill-na go
    # records them, as their gates are n/a for go.
    go = [
        line("adapters/_common/c1", "adapter-case", "pass"),
        line("keys/a", "key", "pass"),
        line("keys/ed", "key", "skipped:out-of-scope"),
        line("vectors/digest/flagged", "vector", "skipped:spec-defect", spec_defects=[DEFECT]),
        line("vectors/digest/plain", "vector", "pass"),
        line("vectors/jws/opt", "vector", "skipped:capability", missing_capabilities=["jws-ed25519"]),
    ]
    # TypeScript: every entry printed; a fail under a planned gate is
    # accepted and counted.
    ts = [
        line("adapters/_common/c1", "adapter-case", "fail"),
        line("adapters/native/n1", "adapter-case", "skipped:out-of-scope"),
        line("admission/a", "evaluate", "skipped:out-of-scope"),
        line("admission/b", "evaluate", "skipped:capability", missing_capabilities=["jws-ed25519"]),
        line("keys/a", "key", "pass"),
        line("keys/ed", "key", "skipped:out-of-scope"),
        line("sources/demo/s1.join", "source-case", "skipped:out-of-scope"),
        line("vectors/digest/flagged", "vector", "pass"),
        line("vectors/digest/plain", "vector", "pass"),
        line("vectors/jws/opt", "vector", "skipped:os-layer"),
    ]
    # py, rs and php are absent: no gate is required for them.
    return {
        "manifest": manifest,
        "gates": gates,
        "files": files,
        "results": {"go": go, "ts": ts},
        "status": {"go": 0, "ts": 0},
        "runner": None,
        "raw": {},
        "command": "check",
    }


def find(lines, id_):
    for i, l in enumerate(lines):
        if l["id"] == id_:
            return i
    raise KeyError(id_)


def set_result(lang, id_, result, **extra):
    def mutate(s):
        lines = s["results"][lang]
        i = find(lines, id_)
        new = {"id": id_, "kind": lines[i]["kind"], "result": result}
        new.update(extra)
        lines[i] = new
    return mutate


def drop_line(lang, id_):
    def mutate(s):
        lines = s["results"][lang]
        del lines[find(lines, id_)]
    return mutate


def add_line(lang, line):
    def mutate(s):
        s["results"][lang].append(line)
    return mutate


def add_entry(e):
    def mutate(s):
        s["manifest"]["entries"].append(e)
    return mutate


def set_gate(prefix, lang, value):
    def mutate(s):
        for r in s["gates"]["rows"]:
            if r["prefix"] == prefix:
                r[lang] = value
                return
        raise KeyError(prefix)
    return mutate


def drop_gate(prefix):
    def mutate(s):
        s["gates"]["rows"] = [r for r in s["gates"]["rows"] if r["prefix"] != prefix]
    return mutate


def add_gate(row):
    # Inserted in order, so only the rule under test fires.
    def mutate(s):
        rows = s["gates"]["rows"] + [row]
        s["gates"]["rows"] = sorted(rows, key=lambda r: (r["scope"], r["kind"], r["prefix"]))
    return mutate


def reverse_gates(s):
    s["gates"]["rows"].reverse()


def drop_lang(lang):
    def mutate(s):
        del s["results"][lang]
        del s["status"][lang]
    return mutate


def set_status(lang, status):
    def mutate(s):
        s["status"][lang] = status
    return mutate


def raw_line(lang, text):
    def mutate(s):
        s["raw"].setdefault(lang, []).append(text)
    return mutate


def runner_report(status, ids=("admission/a",)):
    def mutate(s):
        s["runner"] = {
            "schema": "pactc/v1",
            "summary": {"pass": 0, "fail": 0, "skip": 0},
            "manifest": {"status": "PASS"},
            "capabilities": [],
            "fixtures": [{"id": i, "verb": "evaluate", "status": status} for i in ids],
        }
    return mutate


def rows_command(s):
    s["command"] = "rows"


def chain(*mutations):
    def mutate(s):
        for m in mutations:
            m(s)
    return mutate


# (name, mutation, expected exit status, rule id that must be reported)
CASES = [
    # tools/parity/README.md (Self-test), the five required cases.
    ("wrong outcome under a required gate",
     set_result("go", "vectors/digest/plain", "fail"), 1, "required-not-pass"),
    ("missing id", drop_line("ts", "keys/a"), 1, "id-missing"),
    ("manifest prefix without a gate row",
     add_entry(entry("vectors/jcs/x", "vector", "core", "vectors/jcs/x.json")), 1, "gate-row-missing"),
    ("spec-defect skip on a vector without the flag",
     set_result("go", "vectors/digest/plain", "skipped:spec-defect", spec_defects=[DEFECT]), 1,
     "spec-defect-unflagged"),
    ("pass under an n/a gate", set_result("ts", "admission/a", "pass"), 1, "na-not-skipped"),
    # Rule 1: what a required gate sanctions.
    ("unsanctioned skip under a required gate",
     set_result("go", "keys/a", "skipped:out-of-scope"), 1, "required-not-pass"),
    ("os-layer skip under a required gate",
     set_result("go", "keys/a", "skipped:os-layer"), 1, "required-not-pass"),
    ("fail on an exceptions entry", set_result("go", "keys/ed", "fail"), 1, "required-not-pass"),
    ("spec-defect naming a vector without the flag",
     set_result("go", "vectors/digest/flagged", "skipped:spec-defect",
                spec_defects=[dict(DEFECT, vector="printed-right")]), 1, "spec-defect-unflagged"),
    ("spec-defect without values on a vector without the flag",
     set_result("go", "vectors/digest/plain", "skipped:spec-defect"), 1, "spec-defect-unflagged"),
    ("spec-defect on an entry that is not a vector",
     set_result("go", "keys/a", "skipped:spec-defect", spec_defects=[DEFECT]), 1, "spec-defect-unflagged"),
    ("spec-defect without its values",
     set_result("go", "vectors/digest/flagged", "skipped:spec-defect"), 1, "spec-defect-values"),
    ("capability skip on an entry without capabilities",
     set_result("go", "vectors/digest/plain", "skipped:capability", missing_capabilities=["jws-ed25519"]), 1,
     "capability-unlisted"),
    ("capability skip naming a capability the entry does not list",
     set_result("go", "vectors/jws/opt", "skipped:capability", missing_capabilities=["other"]), 1,
     "capability-unlisted"),
    ("capability skip without missing_capabilities",
     set_result("go", "vectors/jws/opt", "skipped:capability"), 1, "capability-unlisted"),
    # Rule 3.
    ("fail under an n/a gate", set_result("ts", "adapters/native/n1", "fail"), 1, "na-not-skipped"),
    ("capability skip under n/a on an entry without capabilities",
     set_result("ts", "admission/a", "skipped:capability", missing_capabilities=["jws-ed25519"]), 1,
     "capability-unlisted"),
    ("os-layer skip under an n/a gate",
     set_result("ts", "admission/a", "skipped:os-layer"), 1, "na-not-skipped"),
    ("valid spec-defect skip under an n/a gate",
     chain(set_gate("vectors/digest", "ts", "n/a"),
           set_result("ts", "vectors/digest/plain", "skipped:out-of-scope"),
           set_result("ts", "vectors/digest/flagged", "skipped:spec-defect", spec_defects=[DEFECT])), 1,
     "na-not-skipped"),
    # Rule 5.
    ("duplicate id", add_line("go", {"id": "keys/a", "kind": "key", "result": "pass"}), 1, "id-duplicate"),
    ("id not in the manifest",
     add_line("go", {"id": "keys/zzz", "kind": "key", "result": "pass"}), 1, "id-unknown"),
    ("missing id under a required gate is never filled",
     drop_line("go", "adapters/_common/c1"), 1, "id-missing"),
    ("missing id of a language without --fill-na",
     drop_line("ts", "adapters/native/n1"), 1, "id-missing"),
    # Result lines.
    ("result outside the grammar", set_result("go", "keys/a", "skipped:whatever"), 1, "result-line"),
    ("kind that differs from the manifest",
     set_result("go", "keys/a", "pass", kind="vector"), 1, "result-kind"),
    ("unknown member", set_result("go", "keys/a", "pass", note="x"), 1, "result-line"),
    ("duplicate member", raw_line("go", '{"id":"keys/a","id":"keys/a","kind":"key","result":"pass"}'), 1,
     "result-line"),
    ("line that is not JSON", raw_line("go", "PASS keys/a"), 1, "result-line"),
    # Languages and harnesses.
    ("absent language with a required gate", drop_lang("ts"), 1, "language-absent"),
    ("harness exit status not zero", set_status("ts", 1), 1, "harness-status"),
    # Gates file.
    ("gate value outside required, planned and n/a",
     set_gate("vectors/jws", "py", "maybe"), 2, "gates-json"),
    ("gate row without manifest entries",
     add_gate(gate("core", "vector", "vectors/unused", "required", "planned")), 1, "gate-row-stale"),
    ("gate rows out of order", reverse_gates, 1, "gate-row-order"),
    ("duplicate gate row",
     add_gate(gate("core", "vector", "vectors/jws", "required", "planned")), 2, "gates-json"),
    ("exception for an id outside its row",
     chain(drop_gate("keys"), add_gate(gate("core", "key", "keys", "required", "required",
                                            exceptions=[{"id": "vectors/jws/opt", "reason": "x"}]))),
     1, "gate-exception"),
    # Runner leg: a pactc/v1 report mapped into the go stream.
    ("runner report pass under an n/a gate", runner_report("PASS"), 1, "na-not-skipped"),
    ("runner report id printed by a leg too",
     chain(runner_report("SKIP", ids=("admission/a",)),
           add_line("go", {"id": "admission/a", "kind": "evaluate", "result": "skipped:out-of-scope"})), 1, "id-duplicate"),
    # A runner row required for go, as make conformance makes it: the report
    # must pass every entry of the row, and no line is filled without it.
    ("runner report fail under a required gate",
     chain(set_gate("admission", "go", "required"), runner_report("FAIL", ids=("admission/a", "admission/b"))),
     1, "required-not-pass"),
    ("runner report out-of-scope skip under a required gate",
     chain(set_gate("admission", "go", "required"), runner_report("SKIP", ids=("admission/a", "admission/b"))),
     1, "required-not-pass"),
    ("required runner gate without a runner report",
     set_gate("admission", "go", "required"), 1, "id-missing"),
    # Row check (the ci-spec step).
    ("row check: manifest prefix without a gate row",
     chain(rows_command, add_entry(entry("vectors/jcs/x", "vector", "core", "vectors/jcs/x.json"))), 1,
     "gate-row-missing"),
    ("row check: gate row without manifest entries",
     chain(rows_command, add_gate(gate("core", "vector", "vectors/unused", "required", "planned"))), 1,
     "gate-row-stale"),
]

# States the comparator must accept.
CONTROLS = [
    ("baseline", lambda s: None),
    ("runner report results outside runner scope ignored",
     runner_report("SKIP", ids=("admission/a", "admission/b", "keys/a"))),
    ("runner report skips mapped to out-of-scope and capability",
     chain(runner_report("SKIP", ids=("admission/a", "admission/b")))),
    ("runner report pass under a required gate",
     chain(set_gate("admission", "go", "required"), runner_report("PASS", ids=("admission/a", "admission/b")))),
    ("planned gate accepts a fail and counts it", set_result("ts", "vectors/jws/opt", "fail")),
    ("row check on the baseline", rows_command),
]


def write_json(path, value):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(value, f, indent=2)
        f.write("\n")


def run(state, work):
    root = os.path.join(work, "fixtures")
    write_json(os.path.join(root, "manifest.json"), state["manifest"])
    for rel, value in state["files"].items():
        write_json(os.path.join(root, rel), value)
    gates = os.path.join(work, "gates.json")
    write_json(gates, state["gates"])
    args = [sys.executable, "-I", PARITY, state["command"],
            "--manifest", os.path.join(root, "manifest.json"), "--gates", gates]
    if state["command"] == "check":
        args += ["--fill-na", "go"]
        for lang, lines in state["results"].items():
            path = os.path.join(work, lang + ".ndjson")
            with open(path, "w", encoding="utf-8") as f:
                for l in lines:
                    f.write(json.dumps(l) + "\n")
                for text in state["raw"].get(lang, []):
                    f.write(text + "\n")
            args += ["--results", "%s=%s" % (lang, path), "--status", "%s=%d" % (lang, state["status"][lang])]
        if state["runner"] is not None:
            path = os.path.join(work, "pactc.json")
            write_json(path, state["runner"])
            args += ["--runner-report", "go=" + path]
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)


def main(argv):
    verbose = "-v" in argv[1:]
    if [a for a in argv[1:] if a != "-v"]:
        print("usage: selftest.py [-v]", file=sys.stderr)
        return 2
    if not os.path.isfile(PARITY):
        print("selftest: %s not found" % PARITY, file=sys.stderr)
        return 2
    failures = 0
    total = 0
    with tempfile.TemporaryDirectory(prefix="parity-selftest-") as tmp:
        for n, (name, mutate) in enumerate(CONTROLS):
            state = copy.deepcopy(baseline())
            mutate(state)
            proc = run(state, os.path.join(tmp, "control-%02d" % n))
            total += 1
            ok = proc.returncode == 0
            failures += not ok
            report(ok, "control", name, "exit 0", proc, verbose)
        for n, (name, mutate, status, rule) in enumerate(CASES):
            state = copy.deepcopy(baseline())
            mutate(state)
            proc = run(state, os.path.join(tmp, "case-%02d" % n))
            total += 1
            ok = proc.returncode == status and ("[%s]" % rule) in proc.stderr
            failures += not ok
            report(ok, "case", name, "exit %d with [%s]" % (status, rule), proc, verbose)
    print("parity selftest: %d of %d cases as expected" % (total - failures, total))
    return 1 if failures else 0


def report(ok, what, name, want, proc, verbose):
    if ok and not verbose:
        return
    print("%s %s %s: want %s, got exit %d" % ("ok  " if ok else "FAIL", what, name, want, proc.returncode))
    if not ok or verbose:
        for l in proc.stderr.splitlines():
            print("    " + l)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
