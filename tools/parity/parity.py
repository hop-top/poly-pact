#!/usr/bin/env python3
"""Cross-language parity check of the PACT harnesses against the fixture manifest.

Implements the gates and orchestrator rules of tools/parity/README.md
(Gates file, Orchestrator rules). Each language harness (make go-vectors, make ts-vectors, ...)
prints one NDJSON line per manifest entry, {"id","kind","result"}, with

    result ::= "pass" | "fail" | "skipped:" reason
    reason ::= "out-of-scope" | "spec-defect" | "os-layer" | "capability"

A skipped:spec-defect line also carries spec_defects, a non-empty array of
{"vector","appendix_value","expected_digest"}; a skipped:capability line
carries missing_capabilities. No other member is allowed.

tools/parity/gates.json has one row per (scope, kind, prefix) of the
manifest. The prefix is the first segment of the entry id, or the first two
under vectors/, adapters/ and sources/. Each row gives every language (go, ts, py, rs,
php) the value required, planned or n/a, the label of the work that flips
it (flipped_by), and optional exceptions, each {"id","reason"}.

check reads the manifest, the gates and one result file per present
language, and reports, with the rule id in brackets:

gates-json             the gates file is not one strict JSON object of the
                       format above, or two rows share (scope, kind, prefix)
                       (exit status 2)
gate-row-order         the rows are not sorted by scope, kind, prefix
gate-row-missing       a manifest (scope, kind, prefix) has no gate row
gate-row-stale         a gate row matches no manifest entry
gate-exception         an exception names an id that is not an entry of
                       its row
result-line            a line is not strict JSON, has a missing, unknown or
                       mistyped member, or a result outside the grammar
result-kind            the kind of a line differs from the manifest entry
id-duplicate           a language reports an id twice
id-unknown             a language reports an id that is not in the manifest
id-missing             a language reports no line for a manifest entry
spec-defect-unflagged  skipped:spec-defect on an entry that is not a vector
                       whose file sets spec_defect true, or naming a vector
                       of the file that does not set it
spec-defect-values     skipped:spec-defect without spec_defects
capability-unlisted    skipped:capability on an entry without
                       capabilities, or whose missing_capabilities are
                       absent or not capabilities the entry lists
required-not-pass      under a required gate, a result other than pass and
                       other than a sanctioned skip: a valid spec-defect
                       skip, a valid capability skip, or any skip of an id
                       in the row's exceptions
na-not-skipped         under an n/a gate, a result other than
                       skipped:out-of-scope and a valid skipped:capability
language-absent        a language without results has a required gate
harness-status         a harness exited with a status other than 0
runner-report          a pactc/v1 report given with --runner-report is
                       malformed or its manifest check failed

Under a planned gate every valid result is accepted and counted. The
spec-defect and capability rules check the result grammar and apply under
every gate.

The Go results come from several legs (tools/parity/README.md, Go legs).
--runner-report go=FILE maps the scope-runner results of a pactc run --json
report into the go stream: PASS is pass, FAIL is fail, SKIP is
skipped:capability when the entry lists a capability the report does not
declare and skipped:out-of-scope otherwise. --fill-na go records
skipped:out-of-scope for every entry that no Go leg printed and whose gate is
n/a for go; it never fills an entry under a planned or required gate. The
report counts the filled entries.

rows runs only the gates-file and row rules (gates-json, gate-row-order,
gate-row-missing, gate-row-stale, gate-exception). ci-spec runs it, so a
fixture change cannot merge without a gate row for every language.

Standard library only (Python 3.9 and later). Run it isolated:

    python3 -I tools/parity/parity.py check [--manifest FILE] [--gates FILE]
        [--results LANG=FILE]... [--status LANG=N]...
        [--runner-report LANG=FILE] [--fill-na LANG]...
    python3 -I tools/parity/parity.py rows [--manifest FILE] [--gates FILE]

A language without --results is not present. Exit status: 0 clean; 1
problems listed on stderr; 2 cannot run (usage, unreadable manifest, gates
file or result file, malformed gates file).
"""

import argparse
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
DEFAULT_MANIFEST = os.path.join(ROOT, "spec", "v1.0", "fixtures", "manifest.json")
DEFAULT_GATES = os.path.join(ROOT, "tools", "parity", "gates.json")

LANGS = ("go", "ts", "py", "rs", "php")
GATE_VALUES = ("required", "planned", "n/a")
REASONS = ("out-of-scope", "spec-defect", "os-layer", "capability")
RESULTS = ("pass", "fail") + tuple("skipped:" + r for r in REASONS)
TWO_SEGMENT_GROUPS = ("vectors", "adapters", "sources")
ROW_MEMBERS = ("scope", "kind", "prefix") + LANGS + ("flipped_by",)
LINE_MEMBERS = ("id", "kind", "result")
LINE_OPTIONAL = {"spec_defects": "skipped:spec-defect", "missing_capabilities": "skipped:capability"}
DEFECT_MEMBERS = ("vector", "appendix_value", "expected_digest")


def _load_specjson():
    # Loaded by path, not by import name, so the script runs under -I.
    path = os.path.join(ROOT, "scripts", "specjson.py")
    spec = importlib.util.spec_from_file_location("specjson", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


specjson = _load_specjson()


class CannotRun(Exception):
    """The check cannot start: exit status 2."""

    def __init__(self, rule, message):
        Exception.__init__(self, message)
        self.rule = rule


def prefix_of(entry_id):
    segs = entry_id.split("/")
    n = 2 if segs[0] in TWO_SEGMENT_GROUPS and len(segs) > 2 else 1
    return "/".join(segs[:n])


def row_name(key):
    return "/".join(key)


class Problems:
    def __init__(self):
        self.items = []

    def add(self, rule, where, message):
        self.items.append("[%s] %s: %s" % (rule, where, message))


# --- manifest and gates -----------------------------------------------------


def load_manifest(path):
    try:
        doc = specjson.load(path)
    except specjson.StrictJSONError as exc:
        raise CannotRun("manifest", "%s: %s" % (path, exc))
    entries = doc.get("entries") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        raise CannotRun("manifest", "%s: not an object with an entries array" % path)
    out = {}
    for i, e in enumerate(entries):
        ok = isinstance(e, dict) and all(isinstance(e.get(k), str) and e.get(k) for k in ("id", "kind", "scope"))
        if not ok:
            raise CannotRun("manifest", "%s: entries[%d] lacks a string id, kind or scope" % (path, i))
        caps = e.get("capabilities")
        if caps is not None and not (isinstance(caps, list) and all(isinstance(c, str) for c in caps)):
            raise CannotRun("manifest", "%s: %s: capabilities is not an array of strings" % (path, e["id"]))
        if e["id"] in out:
            raise CannotRun("manifest", "%s: id %s repeats" % (path, e["id"]))
        out[e["id"]] = e
    return out


def load_gates(path):
    try:
        doc = specjson.load(path)
    except specjson.StrictJSONError as exc:
        raise CannotRun("gates-json", "%s: %s" % (path, exc))
    where = os.path.basename(path)
    if not isinstance(doc, dict) or sorted(doc) != ["gates_version", "rows"]:
        raise CannotRun("gates-json", "%s: not one object with exactly gates_version and rows" % where)
    if doc["gates_version"] != 1 or isinstance(doc["gates_version"], bool):
        raise CannotRun("gates-json", "%s: gates_version is not 1" % where)
    if not isinstance(doc["rows"], list):
        raise CannotRun("gates-json", "%s: rows is not an array" % where)
    rows = []
    seen = set()
    for i, r in enumerate(doc["rows"]):
        at = "%s rows[%d]" % (where, i)
        if not isinstance(r, dict):
            raise CannotRun("gates-json", "%s: not an object" % at)
        unknown = sorted(set(r) - set(ROW_MEMBERS) - {"exceptions"})
        missing = [m for m in ROW_MEMBERS if m not in r]
        if unknown or missing:
            raise CannotRun("gates-json", "%s: unknown members %s, missing members %s" % (at, unknown, missing))
        for m in ("scope", "kind", "prefix", "flipped_by"):
            if not isinstance(r[m], str) or not r[m]:
                raise CannotRun("gates-json", "%s: %s is not a non-empty string" % (at, m))
        for lang in LANGS:
            if r[lang] not in GATE_VALUES:
                raise CannotRun("gates-json", "%s: %s is %r, not one of %s" % (at, lang, r[lang], ", ".join(GATE_VALUES)))
        exceptions = {}
        if "exceptions" in r:
            exc = r["exceptions"]
            if not isinstance(exc, list) or not exc:
                raise CannotRun("gates-json", "%s: exceptions is not a non-empty array" % at)
            for j, x in enumerate(exc):
                ok = (isinstance(x, dict) and sorted(x) == ["id", "reason"]
                      and all(isinstance(x[k], str) and x[k] for k in ("id", "reason")))
                if not ok:
                    raise CannotRun("gates-json", "%s: exceptions[%d] is not {\"id\",\"reason\"} with non-empty strings" % (at, j))
                if x["id"] in exceptions:
                    raise CannotRun("gates-json", "%s: exception %s repeats" % (at, x["id"]))
                exceptions[x["id"]] = x["reason"]
        key = (r["scope"], r["kind"], r["prefix"])
        if key in seen:
            raise CannotRun("gates-json", "%s: row %s repeats" % (at, row_name(key)))
        seen.add(key)
        rows.append((key, r, exceptions))
    return rows


def check_rows(manifest, rows, problems):
    """The row rules shared by check and rows. Returns {key: (row, exceptions)}."""
    keys = [k for k, _, _ in rows]
    for i in range(1, len(keys)):
        if keys[i - 1] > keys[i]:
            problems.add("gate-row-order", row_name(keys[i]), "sorts before the row above it, %s" % row_name(keys[i - 1]))
    gates = dict((k, (r, x)) for k, r, x in rows)
    groups = {}
    for e in manifest.values():
        groups.setdefault((e["scope"], e["kind"], prefix_of(e["id"])), []).append(e["id"])
    for key in sorted(groups):
        if key not in gates:
            ids = groups[key]
            problems.add("gate-row-missing", row_name(key),
                         "%d manifest entries (%s) have no row in the gates file; add one with a value for every language" % (len(ids), ids[0]))
    for key in keys:
        if key not in groups:
            problems.add("gate-row-stale", row_name(key), "no manifest entry has this scope, kind and prefix")
            continue
        for xid in sorted(gates[key][1]):
            if xid not in groups[key]:
                problems.add("gate-exception", row_name(key), "exception %s is not an entry of this row" % xid)
    return gates, groups


# --- result lines -----------------------------------------------------------


def parse_line(text):
    """Return (line, error) for one NDJSON line."""
    try:
        line = specjson.loads(text)
    except specjson.StrictJSONError as exc:
        return None, "not strict JSON (%s)" % exc
    if not isinstance(line, dict):
        return None, "not a JSON object"
    for m in LINE_MEMBERS:
        if not isinstance(line.get(m), str) or not line[m]:
            return None, "member %s is missing or not a non-empty string" % m
    unknown = sorted(set(line) - set(LINE_MEMBERS) - set(LINE_OPTIONAL))
    if unknown:
        return None, "unknown members %s" % ", ".join(unknown)
    if line["result"] not in RESULTS:
        return None, "result %r is outside the grammar (%s)" % (line["result"], " | ".join(RESULTS))
    for m, result in LINE_OPTIONAL.items():
        if m in line and line["result"] != result:
            return None, "member %s on a %s line" % (m, line["result"])
    if "missing_capabilities" in line:
        caps = line["missing_capabilities"]
        if not (isinstance(caps, list) and all(isinstance(c, str) and c for c in caps) and len(set(caps)) == len(caps)):
            return None, "missing_capabilities is not an array of distinct non-empty strings"
    if "spec_defects" in line and not isinstance(line["spec_defects"], list):
        return None, "spec_defects is not an array"
    return line, None


def read_results(lang, path, problems):
    try:
        with open(path, "rb") as f:
            raw = f.read()
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise CannotRun("results", "%s results %s: %s" % (lang, path, exc))
    lines = []
    for n, t in enumerate(text.split("\n"), 1):
        if t == "" and n == len(text.split("\n")):
            continue
        line, err = parse_line(t)
        if err:
            problems.add("result-line", "%s %s:%d" % (lang, os.path.basename(path), n), err)
        else:
            lines.append(line)
    return lines


def runner_lines(path, manifest, problems):
    """Map a pactc/v1 report to result lines."""
    where = "runner report %s" % os.path.basename(path)
    try:
        doc = specjson.load(path)
    except specjson.StrictJSONError as exc:
        raise CannotRun("runner-report", "%s: %s" % (where, exc))
    if not isinstance(doc, dict) or doc.get("schema") != "pactc/v1":
        problems.add("runner-report", where, "not a pactc/v1 report")
        return []
    status = doc.get("manifest", {}).get("status") if isinstance(doc.get("manifest"), dict) else None
    if status != "PASS":
        problems.add("runner-report", where, "the manifest check of the run is %s, not PASS" % status)
    declared = doc.get("capabilities", [])
    fixtures = doc.get("fixtures")
    if not isinstance(declared, list) or not isinstance(fixtures, list):
        problems.add("runner-report", where, "capabilities or fixtures is not an array")
        return []
    out = []
    for i, f in enumerate(fixtures):
        if not (isinstance(f, dict) and isinstance(f.get("id"), str) and f.get("status") in ("PASS", "FAIL", "SKIP")):
            problems.add("runner-report", "%s fixtures[%d]" % (where, i), "no string id or no status PASS, FAIL or SKIP")
            continue
        e = manifest.get(f["id"])
        if e is not None and e["scope"] != "runner":
            continue
        line = {"id": f["id"], "kind": e["kind"] if e else str(f.get("verb", "")) or "unknown"}
        if f["status"] == "PASS":
            line["result"] = "pass"
        elif f["status"] == "FAIL":
            line["result"] = "fail"
        else:
            missing = [c for c in (e or {}).get("capabilities") or [] if c not in declared]
            if missing:
                line["result"] = "skipped:capability"
                line["missing_capabilities"] = missing
            else:
                line["result"] = "skipped:out-of-scope"
        out.append(line)
    return out


_defect_cache = {}


def flagged_vectors(fixtures_root, entry):
    """Ids of the items of the entry's vector file that set spec_defect true."""
    path = os.path.join(fixtures_root, entry.get("path") or "")
    if path not in _defect_cache:
        flagged = set()
        try:
            doc = specjson.load(path)
        except specjson.StrictJSONError:
            doc = None
        items = doc if isinstance(doc, list) else [doc]
        for item in items:
            if isinstance(item, dict) and item.get("spec_defect") is True and isinstance(item.get("id"), str):
                flagged.add(item["id"])
        _defect_cache[path] = flagged
    return _defect_cache[path]


def grammar_problem(line, entry, fixtures_root):
    """Check a spec-defect or capability skip against the entry. Returns (rule, message) or None."""
    result = line["result"]
    if result == "skipped:spec-defect":
        flagged = flagged_vectors(fixtures_root, entry) if entry["kind"] == "vector" else set()
        if not flagged:
            return "spec-defect-unflagged", "skipped:spec-defect, but the entry is not a vector whose file sets spec_defect true"
        defects = line.get("spec_defects")
        if not defects:
            return "spec-defect-values", "skipped:spec-defect without spec_defects (the printed and the computed value)"
        for d in defects:
            if not (isinstance(d, dict) and sorted(d) == sorted(DEFECT_MEMBERS) and all(isinstance(d[k], str) for k in DEFECT_MEMBERS)):
                return "spec-defect-values", "a spec_defects item is not {\"vector\",\"appendix_value\",\"expected_digest\"}"
            if d["vector"] not in flagged:
                return "spec-defect-unflagged", "spec defect named for vector %s, which does not set spec_defect true" % d["vector"]
    elif result == "skipped:capability":
        listed = entry.get("capabilities") or []
        missing = line.get("missing_capabilities")
        if not listed:
            return "capability-unlisted", "skipped:capability, but the manifest entry lists no capabilities"
        if not missing:
            return "capability-unlisted", "skipped:capability without missing_capabilities"
        extra = [c for c in missing if c not in listed]
        if extra:
            return "capability-unlisted", "missing_capabilities %s are not capabilities of the entry (%s)" % (", ".join(extra), ", ".join(listed))
    return None


def judge(lang, gate, line, exceptions):
    """Apply the gate rules to a line whose grammar is valid. Returns (rule, message) or None."""
    result = line["result"]
    if gate == "required":
        if result == "pass" or result in ("skipped:spec-defect", "skipped:capability"):
            return None
        if result.startswith("skipped:") and line["id"] in exceptions:
            return None
        return "required-not-pass", "%s under a gate required for %s" % (result, lang)
    if gate == "n/a":
        if result in ("skipped:out-of-scope", "skipped:capability"):
            return None
        return "na-not-skipped", "%s under a gate that is n/a for %s: it claims coverage the gates file does not declare" % (result, lang)
    return None


# --- commands ---------------------------------------------------------------


def lang_pairs(values, flag, numeric=False):
    out = {}
    for v in values or []:
        lang, sep, rest = v.partition("=")
        if not sep or lang not in LANGS or not rest:
            raise CannotRun("usage", "%s %s: want LANG=%s with LANG one of %s" % (flag, v, "N" if numeric else "FILE", ", ".join(LANGS)))
        if lang in out:
            raise CannotRun("usage", "%s given twice for %s" % (flag, lang))
        if numeric:
            try:
                rest = int(rest)
            except ValueError:
                raise CannotRun("usage", "%s %s: N is not an integer" % (flag, v))
        out[lang] = rest
    return out


def cmd_rows(args):
    manifest = load_manifest(args.manifest)
    rows = load_gates(args.gates)
    problems = Problems()
    check_rows(manifest, rows, problems)
    print("parity rows: %d manifest entries, %d gate rows" % (len(manifest), len(rows)))
    return problems


def cmd_check(args):
    manifest = load_manifest(args.manifest)
    fixtures_root = os.path.dirname(os.path.abspath(args.manifest))
    rows = load_gates(args.gates)
    results = lang_pairs(args.results, "--results")
    statuses = lang_pairs(args.status, "--status", numeric=True)
    reports = lang_pairs(args.runner_report, "--runner-report")
    fill = []
    for lang in args.fill_na or []:
        if lang not in LANGS or lang in fill:
            raise CannotRun("usage", "--fill-na %s: not a language or given twice" % lang)
        fill.append(lang)
    for flag, langs in (("--status", statuses), ("--runner-report", reports), ("--fill-na", fill)):
        for lang in langs:
            if lang not in results:
                raise CannotRun("usage", "%s %s without --results %s=FILE" % (flag, lang, lang))

    problems = Problems()
    gates, groups = check_rows(manifest, rows, problems)
    key_of = dict((i, k) for k, ids in groups.items() for i in ids)

    # counts[key][lang] = {"pass":..,"fail":..,"skip":..,"filled":..}
    counts = dict((k, dict((l, {"pass": 0, "fail": 0, "skip": 0, "filled": 0}) for l in LANGS)) for k in gates)
    defects = []
    for lang in LANGS:
        if lang not in results:
            required = [row_name(k) for k, (r, _) in sorted(gates.items()) if r[lang] == "required"]
            if required:
                problems.add("language-absent", lang, "no results, but %d gates are required for it (%s)" % (len(required), required[0]))
            continue
        if statuses.get(lang, 0) != 0:
            problems.add("harness-status", lang, "the harness exited with status %d" % statuses[lang])
        lines = read_results(lang, results[lang], problems)
        if lang in reports:
            lines += runner_lines(reports[lang], manifest, problems)
        seen = set()
        for line in lines:
            where = "%s %s" % (lang, line["id"])
            e = manifest.get(line["id"])
            if e is None:
                problems.add("id-unknown", where, "not an id of the manifest")
                continue
            if line["id"] in seen:
                problems.add("id-duplicate", where, "reported more than once")
                continue
            seen.add(line["id"])
            if line["kind"] != e["kind"]:
                problems.add("result-kind", where, "kind %s, the manifest says %s" % (line["kind"], e["kind"]))
                continue
            key = key_of[line["id"]]
            bad = grammar_problem(line, e, fixtures_root)
            if bad:
                problems.add(bad[0], where, bad[1])
                continue
            if line["result"] == "skipped:spec-defect":
                for d in line["spec_defects"]:
                    defects.append("%s %s: vector %s, draft prints %s, computed %s" % (lang, line["id"], d["vector"], d["appendix_value"], d["expected_digest"]))
            if key not in gates:
                continue
            row, exceptions = gates[key]
            bad = judge(lang, row[lang], line, exceptions)
            if bad:
                problems.add(bad[0], where, bad[1])
            c = counts[key][lang]
            c["pass" if line["result"] == "pass" else "fail" if line["result"] == "fail" else "skip"] += 1
        for i in sorted(manifest):
            if i in seen:
                continue
            key = key_of[i]
            if lang in fill and key in gates and gates[key][0][lang] == "n/a":
                counts[key][lang]["filled"] += 1
                continue
            problems.add("id-missing", "%s %s" % (lang, i), "no result line for this manifest entry")

    write_report(manifest, gates, groups, results, counts, defects, fill)
    return problems


def cell(gate, c, present):
    if not present:
        return gate
    parts = ["%d%s" % (c[k], s) for k, s in (("pass", "P"), ("fail", "F"), ("skip", "S"), ("filled", "N")) if c[k]]
    return " ".join([gate] + parts)


def write_report(manifest, gates, groups, results, counts, defects, fill):
    present = [l for l in LANGS if l in results]
    absent = [l for l in LANGS if l not in results]
    out = sys.stdout
    out.write("parity: %d manifest entries, %d gate rows\n" % (len(manifest), len(gates)))
    out.write("present: %s; not present: %s\n" % (", ".join(present) or "none", ", ".join(absent) or "none"))
    out.write("counts: P pass, F fail, S skipped, N no line and n/a (filled for %s)\n\n" % (", ".join(fill) or "no language"))
    table = [["ROW", "ENTRIES"] + list(LANGS)]
    for key in sorted(gates):
        row = gates[key][0]
        table.append([row_name(key), str(len(groups.get(key, [])))] + [cell(row[l], counts[key][l], l in results) for l in LANGS])
    widths = [max(len(r[i]) for r in table) for i in range(len(table[0]))]
    for r in table:
        out.write("  ".join(v.ljust(widths[i]) for i, v in enumerate(r)).rstrip() + "\n")
    if defects:
        out.write("\nspec defects:\n")
        for d in defects:
            out.write("  %s\n" % d)


def main(argv):
    parser = argparse.ArgumentParser(prog="parity.py", description="Cross-language parity check (see the module docstring).")
    sub = parser.add_subparsers(dest="command")
    for name in ("check", "rows"):
        p = sub.add_parser(name)
        p.add_argument("--manifest", default=DEFAULT_MANIFEST)
        p.add_argument("--gates", default=DEFAULT_GATES)
        if name == "check":
            p.add_argument("--results", action="append", metavar="LANG=FILE")
            p.add_argument("--status", action="append", metavar="LANG=N")
            p.add_argument("--runner-report", action="append", metavar="LANG=FILE")
            p.add_argument("--fill-na", action="append", metavar="LANG")
    args = parser.parse_args(argv[1:])
    if args.command is None:
        parser.print_usage(sys.stderr)
        return 2
    try:
        problems = cmd_check(args) if args.command == "check" else cmd_rows(args)
    except CannotRun as exc:
        print("[%s] %s" % (exc.rule, exc), file=sys.stderr)
        return 2
    for p in problems.items:
        print(p, file=sys.stderr)
    if problems.items:
        print("parity: %d problems" % len(problems.items))
        return 1
    print("parity: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
