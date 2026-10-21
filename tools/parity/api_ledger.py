#!/usr/bin/env python3
"""Check docs/sdk/parity-ledger.md against the exported API of the Go library.

The ledger maps every exported symbol of the Go library packages in scope to
its TypeScript name and its Python name, with a status. This script lists the
packages with `go list`, reads each one with `go doc -all`, and fails when:

1. an exported symbol has no row in its package's section (missing row);
2. a row names a symbol the package does not export (stale row);
3. a symbol has more than one row (duplicate row);
4. a row has an empty TypeScript or Python cell, or a status outside
   planned, done, deviation, SDK extra;
5. a package in scope has no section, or a section names a package that is
   not in scope;
6. a row of the SDK extras section names a Go symbol.

Symbols, as `go doc -all` prints them: every exported constant, variable,
function and type (`Name`), every exported method (`Type.Method`), every
exported method of an exported interface (`Interface.Method`) and every
exported field of an exported struct type (`Type.Field`, including an
embedded exported type). Fields of anonymous struct types are not symbols of
their own; their struct-typed field is.

The scope is SCOPE below, the package patterns of docs/sdk/ports-plan.md
section 5.5, relative to the Go library module.

Usage:
  python3 -I tools/parity/api_ledger.py [--go-dir DIR] [--ledger FILE] [--go GO]
  python3 -I tools/parity/api_ledger.py --list     # print the symbols, one per line
  python3 -I tools/parity/api_ledger.py --selftest # check the parser and the rules

Exit status: 0 when the ledger matches, 1 when it does not, 2 on a usage or
tool error. Standard library only.
"""

import argparse
import os
import re
import subprocess
import sys

SCOPE = ("./core/...", "./adapter/...", "./adapters/memory", "./contract", "./gateway", "./holder", "./runner/manifest", "./validator")
MODULE = "hop.top/pact-go"
STATUSES = ("planned", "done", "deviation", "SDK extra")
SECTIONS = ("CONSTANTS", "VARIABLES", "FUNCTIONS", "TYPES")
EXTRAS_HEADING = "SDK extras"

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class ToolError(Exception):
    """A go command failed or printed text this parser does not understand."""


# ---------------------------------------------------------------------------
# go doc -all parser


def _depth_delta(line, state):
    """Return the bracket balance of line, skipping strings and comments.

    state is a one-element list holding True while a raw string literal is
    open; raw strings may span lines.
    """
    depth = 0
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if state[0]:
            if c == "`":
                state[0] = False
            i += 1
            continue
        if c == "`":
            state[0] = True
        elif c == '"' or c == "'":
            i += 1
            while i < n and line[i] != c:
                if line[i] == "\\":
                    i += 1
                i += 1
        elif line.startswith("//", i):
            break
        elif c in "({[":
            depth += 1
        elif c in ")}]":
            depth -= 1
        i += 1
    return depth


_IDENT = r"[^\W\d]\w*"
_NAMES = re.compile(r"(%s(?:\s*,\s*%s)*)" % (_IDENT, _IDENT))
_RECV = re.compile(r"^func \((?:%s\s+)?\*?(%s)(?:\[[^\]]*\])?\)\s*(%s)" % (_IDENT, _IDENT, _IDENT))
_FUNC = re.compile(r"^func (%s)" % _IDENT)
_TYPE = re.compile(r"^type (%s)(?:\[[^\]]*\])?\s*(=?)\s*(.*)$" % _IDENT)
_SINGLE = re.compile(r"^(const|var) (%s(?:\s*,\s*%s)*)" % (_IDENT, _IDENT))
_IFACE_METHOD = re.compile(r"^\t(%s)\(" % _IDENT)
_EMBEDDED = re.compile(r"^\t\*?(?:%s\.)?(%s)(?:\[.*\])?\s*(?:`[^`]*`)?\s*(?://.*)?$" % (_IDENT, _IDENT))
_JSON_TAG = re.compile(r'json:"([^",]*)')


def exported(name):
    return name[:1].isupper()


class Symbol:
    """One exported symbol of a package."""

    __slots__ = ("name", "kind", "owner", "json", "line")

    def __init__(self, name, kind, owner=None, json=None, line=""):
        self.name = name  # Name or Type.Member
        self.kind = kind  # const, var, func, type, method, field
        self.owner = owner  # the type a const, var, func or member belongs to
        self.json = json  # the json tag name of a field, when it has one
        self.line = line  # the declaration line go doc printed

    def __repr__(self):
        return "Symbol(%r, %r, %r)" % (self.name, self.kind, self.owner)


def parse_doc(text):
    """Return the exported symbols of one package's `go doc -all` text."""
    symbols = []
    lines = text.splitlines()
    i = 0
    while i < len(lines) and lines[i] not in SECTIONS:
        i += 1
    if i == len(lines) and lines and not lines[0].startswith("package "):
        raise ToolError("go doc output does not start with a package clause")
    section = None
    owner = None  # the type the TYPES section is currently under
    block = None  # const, var, struct, interface while a block is open
    block_type = None
    depth = 0
    raw = [False]
    for line in lines[i:]:
        if depth == 0 and not raw[0]:
            if line in SECTIONS:
                section, owner, block = line, None, None
                continue
            if not line or line.startswith("    "):
                continue  # blank or documentation
            if line.startswith("\t") or line.startswith(" "):
                raise ToolError("unexpected indented line outside a block: %r" % line)
            under = owner if section == "TYPES" else None
            m = _RECV.match(line)
            if m:
                if exported(m.group(1)) and exported(m.group(2)):
                    symbols.append(Symbol(m.group(1) + "." + m.group(2), "method", m.group(1), line=line))
            elif line.startswith("func "):
                m = _FUNC.match(line)
                if not m:
                    raise ToolError("cannot read function line: %r" % line)
                if exported(m.group(1)):
                    symbols.append(Symbol(m.group(1), "func", under, line=line))
            elif line.startswith("type "):
                if line.startswith("type ("):
                    raise ToolError("grouped type declaration: %r" % line)
                m = _TYPE.match(line)
                if not m:
                    raise ToolError("cannot read type line: %r" % line)
                owner = m.group(1)
                if exported(owner):
                    symbols.append(Symbol(owner, "type", line=line))
                rest = m.group(3)
                if not m.group(2) and rest.startswith("struct {") and rest.endswith("{"):
                    block, block_type = "struct", owner
                elif not m.group(2) and rest.startswith("interface {") and rest.endswith("{"):
                    block, block_type = "interface", owner
                else:
                    block = None
            elif line in ("const (", "var ("):
                block, block_type = line[:-2], under
            elif line.startswith("const ") or line.startswith("var "):
                m = _SINGLE.match(line)
                if not m:
                    raise ToolError("cannot read declaration line: %r" % line)
                for name in re.split(r"\s*,\s*", m.group(2)):
                    if exported(name):
                        symbols.append(Symbol(name, m.group(1), under, line=line))
                block = None
            elif line in (")", "}"):
                raise ToolError("unbalanced closing line: %r" % line)
            else:
                raise ToolError("cannot read line: %r" % line)
            depth += _depth_delta(line, raw)
            if depth < 0:
                raise ToolError("unbalanced line: %r" % line)
            continue
        # Inside a bracketed declaration.
        before = depth
        if before == 1 and not raw[0] and line.startswith("\t") and not line.startswith("\t//"):
            if block in ("const", "var"):
                m = _NAMES.match(line[1:])
                if not m:
                    raise ToolError("cannot read %s block line: %r" % (block, line))
                for name in re.split(r"\s*,\s*", m.group(1)):
                    if exported(name):
                        symbols.append(Symbol(name, block, block_type, line=line.strip()))
            elif block == "interface" and exported(block_type):
                m = _IFACE_METHOD.match(line)
                if m:
                    if exported(m.group(1)):
                        symbols.append(Symbol(block_type + "." + m.group(1), "method", block_type, line=line.strip()))
                # Otherwise an embedded interface or a type constraint.
            elif block == "struct" and exported(block_type):
                m = _EMBEDDED.match(line)
                if m:
                    names = [m.group(1)]
                else:
                    m = _NAMES.match(line[1:])
                    if not m:
                        raise ToolError("cannot read struct field line: %r" % line)
                    names = re.split(r"\s*,\s*", m.group(1))
                tag = _JSON_TAG.search(line)
                for name in names:
                    if exported(name):
                        symbols.append(
                            Symbol(block_type + "." + name, "field", block_type, tag.group(1) if tag else None, line.strip())
                        )
        depth += _depth_delta(line, raw)
        if depth < 0:
            raise ToolError("unbalanced line: %r" % line)
        if depth == 0 and not raw[0]:
            block = None
    if depth != 0 or raw[0]:
        raise ToolError("go doc output ends inside a declaration")
    return symbols


# ---------------------------------------------------------------------------
# go commands


def run_go(go, go_dir, args):
    try:
        proc = subprocess.run(
            [go] + args, cwd=go_dir, capture_output=True, text=True, check=False
        )
    except OSError as e:
        raise ToolError("cannot run %s: %s" % (go, e)) from e
    if proc.returncode != 0:
        raise ToolError("%s %s failed:\n%s" % (go, " ".join(args), proc.stderr.strip()))
    return proc.stdout


def packages(go, go_dir):
    """Return the in-scope packages as paths relative to the module, sorted."""
    out = run_go(go, go_dir, ["list", "-f", "{{.ImportPath}}"] + list(SCOPE))
    paths = []
    for line in out.split():
        if line == MODULE or not line.startswith(MODULE + "/"):
            raise ToolError("package outside the library module: %s" % line)
        paths.append(line[len(MODULE) + 1 :])
    return sorted(set(paths))


def go_symbols(go, go_dir):
    """Return {package path: [Symbol, ...]} for every package in scope."""
    result = {}
    for path in packages(go, go_dir):
        result[path] = parse_doc(run_go(go, go_dir, ["doc", "-all", "./" + path]))
    return result


# ---------------------------------------------------------------------------
# Ledger


_HEADING = re.compile(r"^## (.*?)\s*$")
_PACKAGE_HEADING = re.compile(r"^`([a-z0-9_]+(?:/[a-z0-9_]+)*)`$")
_CODE = re.compile(r"^`([^`]+)`$")


def split_row(line):
    """Split a Markdown table row into its cells (no escaped pipes inside code)."""
    body = line.strip()
    if not (body.startswith("|") and body.endswith("|")):
        return None
    cells = []
    cur = []
    code = False
    for c in body[1:-1]:
        if c == "`":
            code = not code
        if c == "|" and not code:
            cells.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
    cells.append("".join(cur).strip())
    return cells


def parse_ledger(text):
    """Return (sections, extras, problems).

    sections maps a package path to a list of (line number, symbol, cells);
    extras is the list of (line number, cells) of the SDK extras section.
    """
    sections = {}
    extras = []
    problems = []
    current = None  # package path, EXTRAS_HEADING, or None
    header_seen = False
    for no, line in enumerate(text.splitlines(), 1):
        m = _HEADING.match(line)
        if m:
            title = m.group(1)
            pm = _PACKAGE_HEADING.match(title)
            if pm:
                current = pm.group(1)
                if current in sections:
                    problems.append("line %d: second section for package %s" % (no, current))
                sections.setdefault(current, [])
            elif title == EXTRAS_HEADING:
                current = EXTRAS_HEADING
            else:
                current = None
            header_seen = False
            continue
        if current is None:
            continue
        cells = split_row(line)
        if cells is None:
            header_seen = False
            continue
        if not header_seen:
            header_seen = True
            if cells[:1] != ["Go symbol"]:
                problems.append("line %d: table header must start with 'Go symbol'" % no)
            continue
        if all(re.fullmatch(r":?-+:?", c) for c in cells):
            continue
        if len(cells) != 5:
            problems.append("line %d: row has %d cells, want 5" % (no, len(cells)))
            continue
        go_cell, ts, py, status, _note = cells
        if not ts or not py:
            problems.append("line %d: empty TypeScript or Python cell" % no)
        if status not in STATUSES:
            problems.append("line %d: status %r is not one of %s" % (no, status, ", ".join(STATUSES)))
        if current == EXTRAS_HEADING:
            if go_cell != "none":
                problems.append("line %d: an SDK extras row names no Go symbol (write none)" % no)
            if status != "SDK extra":
                problems.append("line %d: an SDK extras row has status SDK extra" % no)
            extras.append((no, cells))
            continue
        cm = _CODE.match(go_cell)
        if not cm:
            problems.append("line %d: Go symbol cell must be one code span, got %r" % (no, go_cell))
            continue
        if status == "SDK extra":
            problems.append("line %d: status SDK extra belongs in the %s section" % (no, EXTRAS_HEADING))
        sections[current].append((no, cm.group(1), cells))
    return sections, extras, problems


def check(symbols, ledger_text):
    """Return the list of problems; empty when the ledger matches."""
    sections, _extras, problems = parse_ledger(ledger_text)
    for path in sorted(sections):
        if path not in symbols:
            problems.append("section %s: package not in scope (%s)" % (path, " ".join(SCOPE)))
    for path in sorted(symbols):
        if path not in sections:
            problems.append("package %s: no section '## `%s`'" % (path, path))
            continue
        want = {s.name for s in symbols[path]}
        seen = {}
        for no, name, _cells in sections[path]:
            if name in seen:
                problems.append("line %d: duplicate row for %s.%s (first at line %d)" % (no, path, name, seen[name]))
                continue
            seen[name] = no
            if name not in want:
                problems.append("line %d: stale row: %s does not export %s" % (no, path, name))
        for s in symbols[path]:
            if s.name not in seen:
                problems.append("missing row: %s %s.%s" % (s.kind, path, s.name))
    return problems


# ---------------------------------------------------------------------------
# Self-test


_SAMPLE = '''package sample // import "hop.top/pact-go/sample"

Package sample is a test input.

func Example() {
}

CONSTANTS

const Pattern = `^(a
|b{$`
    Pattern spans lines, with brackets that do not balance.

const (
	// A doc.
	One, Two = 1, 2
	three    = 3
)

VARIABLES

var ErrX = errors.New("x (y")

FUNCTIONS

func Long(
	a int,
) error

TYPES

type Kind string

const (
	KindA Kind = "a"
	KindB Kind = "b"
)

func ParseKind(s string) (Kind, error)

func (k Kind) Valid() bool

type Rec struct {
	Name string `json:"name"`
	A, B int
	Inner struct {
		Deep int
	}
	Embedded
	*pkg.Other
	hidden int
	// Has unexported fields.
}

type Iface interface {
	io.Reader
	Do(ctx context.Context) error
	~int | ~string
}

func (r *Rec) Run() error

type hiddenType int

type Alias = Rec
'''

_SAMPLE_WANT = [
    ("Pattern", "const", None),
    ("One", "const", None),
    ("Two", "const", None),
    ("ErrX", "var", None),
    ("Long", "func", None),
    ("Kind", "type", None),
    ("KindA", "const", "Kind"),
    ("KindB", "const", "Kind"),
    ("ParseKind", "func", "Kind"),
    ("Kind.Valid", "method", "Kind"),
    ("Rec", "type", None),
    ("Rec.Name", "field", "Rec"),
    ("Rec.A", "field", "Rec"),
    ("Rec.B", "field", "Rec"),
    ("Rec.Inner", "field", "Rec"),
    ("Rec.Embedded", "field", "Rec"),
    ("Rec.Other", "field", "Rec"),
    ("Iface", "type", None),
    ("Iface.Do", "method", "Iface"),
    ("Rec.Run", "method", "Rec"),
    ("Alias", "type", None),
]


def _sample_ledger(names, drop=None, extra_rows=(), status="planned"):
    rows = ["# Ledger", "", "## `sample`", "", "| Go symbol | TypeScript | Python | Status | Note |", "|---|---|---|---|---|"]
    for name in names:
        if name != drop:
            rows.append("| `%s` | `t` | `p` | %s | |" % (name, status))
    rows.extend(extra_rows)
    rows += ["", "## SDK extras", "", "| Go symbol | TypeScript | Python | Status | Note |", "|---|---|---|---|---|"]
    rows.append("| none | `core/schema` | `core.schema` | SDK extra | |")
    return "\n".join(rows) + "\n"


def selftest():
    failures = []

    def expect(label, cond):
        print("%s: %s" % ("ok" if cond else "FAIL", label))
        if not cond:
            failures.append(label)

    def parse(text):
        try:
            return parse_doc(text)
        except ToolError as e:
            print("  parser error: %s" % e)
            return []

    sample = parse(_SAMPLE)
    got = [(s.name, s.kind, s.owner) for s in sample]
    expect("parser reads the sample", got == _SAMPLE_WANT)
    if got != _SAMPLE_WANT:
        print("  got  %r\n  want %r" % (got, _SAMPLE_WANT))
    tags = {s.name: s.json for s in sample}
    expect("parser keeps json tag names", tags.get("Rec.Name") == "name" and tags.get("Rec.A", "") is None)
    for bad in ("TYPES\n\ttab outside\n", "TYPES\n\nconst (\n\tA = 1\n", "TYPES\n\nwhat is this\n"):
        try:
            parse_doc("package x\n\n" + bad)
            expect("parser rejects %r" % bad, False)
        except ToolError:
            expect("parser rejects %r" % bad, True)

    syms = {"sample": sample}
    names = [n for n, _k, _o in _SAMPLE_WANT]
    expect("complete ledger passes", check(syms, _sample_ledger(names)) == [])
    p = check(syms, _sample_ledger(names, drop="Rec.Run"))
    expect("removed row is reported", p == ["missing row: method sample.Rec.Run"])
    syms_new = {"sample": parse(_SAMPLE.replace("type hiddenType int", "type NewThing int"))}
    p = check(syms_new, _sample_ledger(names))
    expect("new exported symbol is reported", p == ["missing row: type sample.NewThing"])
    p = check(syms, _sample_ledger(names, extra_rows=["| `Gone` | `t` | `p` | planned | |"]))
    expect("stale row is reported", len(p) == 1 and "stale row" in p[0])
    p = check(syms, _sample_ledger(names, extra_rows=["| `Kind` | `t` | `p` | planned | |"]))
    expect("duplicate row is reported", len(p) == 1 and "duplicate row" in p[0])
    p = check(syms, _sample_ledger(names, status="later"))
    expect("unknown status is reported", len(p) == len(names) and all("status" in x for x in p))
    p = check(syms, _sample_ledger(names, extra_rows=["| `Kind.Bad` | | `p` | planned | |"]))
    expect("empty cell is reported", any("empty" in x for x in p))
    p = check(syms, _sample_ledger(names).replace("## `sample`", "## `other`"))
    expect("missing and foreign sections are reported", any("no section" in x for x in p) and any("not in scope" in x for x in p))
    p = check(syms, _sample_ledger(names).replace("| none |", "| `X` |"))
    expect("SDK extras row with a Go symbol is reported", any("SDK extras" in x for x in p))
    if failures:
        print("selftest: %d failure(s)" % len(failures))
        return 1
    print("selftest: ok")
    return 0


# ---------------------------------------------------------------------------


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--go-dir", default=os.path.join(REPO, "go"), help="Go library module directory (default: go/)")
    ap.add_argument("--ledger", default=os.path.join(REPO, "docs", "sdk", "parity-ledger.md"))
    ap.add_argument("--go", default="go", help="go command (default: go on PATH)")
    ap.add_argument("--list", action="store_true", help="print the symbols in scope and exit")
    ap.add_argument("--selftest", action="store_true", help="check the parser and the rules, without Go")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    try:
        symbols = go_symbols(args.go, args.go_dir)
    except ToolError as e:
        print("api_ledger: %s" % e, file=sys.stderr)
        return 2
    if args.list:
        for path in sorted(symbols):
            for s in symbols[path]:
                print("%s\t%s\t%s\t%s\t%s" % (path, s.name, s.kind, s.owner or "", s.json or ""))
        return 0
    try:
        with open(args.ledger, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        print("api_ledger: %s" % e, file=sys.stderr)
        return 2
    problems = check(symbols, text)
    total = sum(len(v) for v in symbols.values())
    if problems:
        for p in problems:
            print("api_ledger: %s" % p)
        print("api_ledger: FAIL: %d problem(s); %d symbols in %d packages" % (len(problems), total, len(symbols)))
        return 1
    print("api_ledger: ok: %d symbols in %d packages, each with one row" % (total, len(symbols)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
