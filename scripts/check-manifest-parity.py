#!/usr/bin/env python3
"""Check that the Python and Go manifest checkers enforce the same rules.

spec/v1.0/fixtures/manifest.json has two hand-written checkers:

- the Python checks: scripts/check-spec-manifest.py, the manifest rules, and
  scripts/check-spec-map.py, the rules that read spec/v1.0/spec-map.md;
- pactfix check manifest, the Go command of this repository
  (go/runner/manifest).

The cases are in tools/spec/manifest-parity-cases.json; tools/spec/README.md
defines the file and its mutation steps, and scripts/paritycases.py reads it
and applies them. This script copies the spec tree (spec/v1.0/fixtures,
spec/v1.0/spec-map.md and spec/v1.0/draft.md) and the Python checks into a temporary
directory, makes one copy per case, applies the case's mutation and runs
every checker on the copy. It fails unless:

- on the unmodified copy, every checker passes;
- on the copy of a rule, the Python checker of the rule, pactfix and every
  --checker fail and report the rule. pactfix and check-spec-manifest.py
  print the rule id as `[rule-id]`. check-spec-map.py has no rule ids: it
  prints the label of the check group that holds the rule, or stops with
  exit status 2 when it cannot read the map;
- on a control copy, a change that the rules allow, every checker passes;
- every rule id of go/runner/manifest/problem.go has a copy, and every rule a
  case names is one of them.

A case marked as a gap is a rule of spec/v1.0/fixtures/README.md that only the
Python checker enforces: its copy must fail the Python checker, and pactfix
must not report the rule. Once pactfix reports it, the case fails until the
mark is removed.

--checker NAME=COMMAND adds a checker, for example a ported manifest module,
judged as pactfix is (gap marks included). COMMAND is split as a POSIX shell
splits words, without running a shell; {spec} in it stands for the spec
directory of the copy. The command runs in the current directory, must exit
0 on a clean tree and 1 when it finds problems, and must print each problem
on a line of its own that starts with `[rule-id] `.

pactfix is built from PACTFIX_PACKAGE with `go build`, run inside that
directory, so the build does not depend on which go.mod holds the package.
The GO environment variable names the go command (default: go); --pactfix
names a built binary to use instead.

Run it isolated, standard library only (Python 3.9 and later):

    python3 -I scripts/check-manifest-parity.py [--pactfix BIN]
        [--checker NAME=COMMAND]... [--keep] [-v]

Exit status: 0 parity holds; 1 a case failed; 2 cannot run.
"""

import argparse
import importlib.util
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
# The pactfix main package, relative to ROOT.
PACTFIX_PACKAGE = "cli/pactfix"
# The Go file that declares the rule ids, relative to ROOT.
GO_RULES = "go/runner/manifest/problem.go"
# The case table, relative to ROOT.
CASES_FILE = "tools/spec/manifest-parity-cases.json"
SPEC_FILES = ("spec-map.md", "draft.md")
SCRIPTS = ("check-spec-manifest.py", "check-spec-map.py", "specjson.py")

_LABEL = re.compile(r"^\s*\[([a-z][a-z -]*)\] ", re.M)
_GO_RULE = re.compile(r'^\s*Rule\w+\s*=\s*"([a-z][a-z-]*)"', re.M)
_CHECKER_NAME = re.compile(r"^[a-z][a-z0-9-]*$")


class SetupError(Exception):
    """The harness cannot run, or a mutation does not fit the current tree."""


def _load_sibling(name):
    path = os.path.join(ROOT, "scripts", name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


paritycases = _load_sibling("paritycases")
PYTHON_CHECKERS = paritycases.PYTHON_CHECKERS


class Result:
    def __init__(self, command):
        try:
            done = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as exc:
            raise SetupError("cannot run %s: %s" % (command[0], exc))
        self.code = done.returncode
        self.output = done.stdout
        self.labels = set(_LABEL.findall(done.stdout))

    def show(self):
        if self.code == 0:
            return "pass"
        found = " ".join("[%s]" % label for label in sorted(self.labels))
        return "fail " + (found or "(exit %d)" % self.code)


def parse_checker(text):
    """NAME=COMMAND from the command line, as (name, argv template)."""
    name, sep, command = text.partition("=")
    if not sep or not _CHECKER_NAME.match(name) or name in PYTHON_CHECKERS + ("go",):
        raise SetupError("--checker %s: want NAME=COMMAND, NAME not manifest, map or go" % text)
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise SetupError("--checker %s: %s" % (name, exc))
    if not any("{spec}" in arg for arg in argv):
        raise SetupError("--checker %s: the command has no {spec}" % name)
    return name, argv


def check_copy(root, pactfix, extra):
    script = os.path.join(root, "scripts", "check-spec-%s.py")
    spec = os.path.join(root, "spec", "v1.0")
    results = {
        "manifest": Result([sys.executable, "-I", script % "manifest"]),
        "map": Result([sys.executable, "-I", script % "map"]),
        "go": Result([pactfix, "check", "manifest", "-spec", spec]),
    }
    for name, argv in extra:
        results[name] = Result([arg.replace("{spec}", spec) for arg in argv])
    return results


def verdict(spec, results, ported):
    """Why the case fails, or None. ported: the names judged as pactfix is."""
    rule = spec["rule"]
    if rule is None:
        failed = [name for name in results if results[name].code != 0]
        return "the control fails %s" % ", ".join(failed) if failed else None
    py = results[spec["checker"]]
    why = []
    if spec["checker"] == "manifest":
        if py.code != 1 or rule not in py.labels:
            why.append("check-spec-manifest.py does not report [%s]" % rule)
    elif spec["label"] is None:
        if py.code != 2:
            why.append("check-spec-map.py does not stop (exit %d, want 2)" % py.code)
    elif py.code != 1 or spec["label"] not in py.labels:
        why.append("check-spec-map.py does not report [%s]" % spec["label"])
    for name in ported:
        shown = "pactfix" if name == "go" else name
        if spec["gap"]:
            if rule in results[name].labels:
                why.append("%s reports [%s] now: remove the gap mark" % (shown, rule))
        elif results[name].code != 1 or rule not in results[name].labels:
            why.append("%s does not report [%s]" % (shown, rule))
    for other in spec["forbid"]:
        for name in ("manifest",) + ported:
            if other in results[name].labels:
                why.append("%s reports [%s], which this copy must not trigger" % (name, other))
    return "; ".join(why) or None


def go_rules():
    try:
        with open(os.path.join(ROOT, GO_RULES), encoding="utf-8") as handle:
            found = set(_GO_RULE.findall(handle.read()))
    except OSError as exc:
        raise SetupError("%s: %s" % (GO_RULES, exc))
    if not found:
        raise SetupError("%s declares no rule ids" % GO_RULES)
    return found


def build_pactfix(out_dir):
    out = os.path.join(out_dir, "pactfix.exe" if os.name == "nt" else "pactfix")
    go = os.environ.get("GO", "go")
    try:
        done = subprocess.run(
            [go, "build", "-buildvcs=false", "-o", out, "."],
            cwd=os.path.join(ROOT, *PACTFIX_PACKAGE.split("/")),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )
    except OSError as exc:
        raise SetupError("cannot run %s: %s" % (go, exc))
    if done.returncode != 0:
        raise SetupError("go build in %s failed:\n%s" % (PACTFIX_PACKAGE, done.stdout))
    return out


def make_base(base):
    spec = os.path.join(base, "spec", "v1.0")
    shutil.copytree(
        os.path.join(ROOT, "spec", "v1.0", "fixtures"), os.path.join(spec, "fixtures"), symlinks=True
    )
    for name in SPEC_FILES:
        shutil.copy2(os.path.join(ROOT, "spec", "v1.0", name), os.path.join(spec, name))
    os.makedirs(os.path.join(base, "scripts"))
    for name in SCRIPTS:
        shutil.copy2(os.path.join(ROOT, "scripts", name), os.path.join(base, "scripts", name))


def indent(text, limit=12):
    lines = text.rstrip("\n").split("\n")
    if len(lines) > limit:
        lines = lines[:limit] + ["... (%d more lines)" % (len(lines) - limit)]
    return "\n".join("     " + line for line in lines)


def report(results, stream):
    for name, r in results.items():
        print("  -- %s (exit %d)\n%s" % (name, r.code, indent(r.output)), file=stream)


def run_cases(tmp, args):
    extra = [parse_checker(text) for text in args.checker]
    if len(set(name for name, _ in extra)) != len(extra):
        raise SetupError("--checker: a name is given twice")
    ported = ("go",) + tuple(name for name, _ in extra)
    try:
        cases = paritycases.load(os.path.join(ROOT, *CASES_FILE.split("/")), CASES_FILE)
    except paritycases.CaseError as exc:
        raise SetupError(str(exc))
    rules = go_rules()
    unknown = sorted(set(s["rule"] for s in cases if s["rule"]) - rules)
    if unknown:
        raise SetupError("cases name rules that %s lacks: %s" % (GO_RULES, ", ".join(unknown)))
    covered = set(s["rule"] for s in cases if s["rule"] and not s["gap"])
    pactfix = os.path.abspath(args.pactfix) if args.pactfix else build_pactfix(tmp)
    base = os.path.join(tmp, "base")
    make_base(base)

    def row(status, tag, name, py, results):
        shown = "".join(" | %s %s" % (n, results[n].show()) for n, _ in extra)
        print(
            "%-4s %-26s %-28s python %s | go %s%s"
            % (status, tag, name, py.show(), results["go"].show(), shown)
        )

    failures = []
    results = check_copy(base, pactfix, extra)
    failed = [name for name in results if results[name].code != 0]
    row("FAIL" if failed else "ok", "(unmodified)", "", results["manifest"], results)
    if failed:
        failures.append(("unmodified", "the unmodified tree fails %s" % ", ".join(failed), results))
    for number, spec in enumerate(cases, 1):
        root = os.path.join(tmp, "%02d-%s" % (number, spec["name"]))
        shutil.copytree(base, root, symlinks=True)
        try:
            paritycases.Copy(root).apply(spec["mutation"])
        except (paritycases.CaseError, KeyError, TypeError, ValueError, OSError) as exc:
            raise SetupError("case %s: cannot apply the mutation: %s" % (spec["name"], exc))
        results = check_copy(root, pactfix, extra)
        why = verdict(spec, results, ported)
        tag = (spec["rule"] or "(control)") + (" (gap)" if spec["gap"] else "")
        py = results["manifest" if spec["rule"] is None else spec["checker"]]
        row("FAIL" if why else "ok", tag, spec["name"], py, results)
        if why:
            failures.append((spec["name"], why, results))
        if args.verbose:
            report(results, sys.stdout)

    missing = sorted(rules - covered)
    if missing:
        failures.append(("table", "no copy for the rules %s" % ", ".join(missing), {}))
    for name, why, results in failures:
        print("FAIL %s: %s" % (name, why), file=sys.stderr)
        report(results, sys.stderr)
    if failures:
        print("check-manifest-parity: %d failure(s)" % len(failures), file=sys.stderr)
        return 1
    controls = sum(1 for s in cases if s["rule"] is None)
    gaps = sum(1 for s in cases if s["gap"])
    print(
        "check-manifest-parity: ok (%d rules, %d broken copies, %d controls, %d gaps)"
        % (len(covered), len(cases) - controls - gaps, controls, gaps)
    )
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--pactfix", help="a pactfix binary to use instead of building one")
    parser.add_argument(
        "--checker",
        action="append",
        default=[],
        metavar="NAME=COMMAND",
        help="another checker judged as pactfix is; {spec} in COMMAND is the spec directory",
    )
    parser.add_argument("--keep", action="store_true", help="keep the temporary directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="print every checker output")
    args = parser.parse_args()
    tmp = tempfile.mkdtemp(prefix="manifest-parity-")
    try:
        return run_cases(tmp, args)
    except SetupError as exc:
        print("check-manifest-parity: %s" % exc, file=sys.stderr)
        return 2
    finally:
        if args.keep:
            print("check-manifest-parity: copies kept in %s" % tmp, file=sys.stderr)
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
