#!/usr/bin/env python3
"""Check that spec/ is self-contained.

The read-only mirror carries only spec/ (as its root), so nothing in
spec/ may depend on a path outside it, and nothing language-specific may ride
along in the neutral conformance assets. Two checks:

1. Links. Every relative link in spec/**/*.md must resolve inside spec/,
   resolved from spec/ as its root: a path that leaves spec/ and re-enters it
   (../spec/v1.0/draft.md) is outside too. Exceptions are listed in spec/.links-allow.
2. Fixture neutrality. spec/v1.0/fixtures and spec/v1.0/profiles hold only the file
   types in NEUTRAL_EXTENSIONS, plus ADAPTER_EXTENSIONS under ADAPTER_DIR.

Run it from anywhere, isolated, standard library only (Python 3.9 and later):

    python3 -I scripts/check-spec-selfcontained.py

Exit status: 0 clean; 1 offenders listed on stderr; 2 cannot run (malformed
allow-list, unreadable file, no spec/ directory).
"""

import bisect
import html
import os
import posixpath
import re
import sys
import urllib.parse

SPEC_DIR = "spec"
ALLOW_FILE = "spec/.links-allow"

# Extension allowlist (compared in lower case). spec/v1.0/fixtures and spec/v1.0/profiles
# may contain only these.
FIXTURE_DIRS = ("spec/v1.0/fixtures", "spec/v1.0/profiles")
NEUTRAL_EXTENSIONS = frozenset(
    (".json", ".yaml", ".yml", ".md", ".jws", ".txt", ".pem")
)

# Exception: adapter fixtures are written in the native format of the system
# they adapt (SQL, OPA Rego, OpenFGA models, LDAP LDIF). These four extensions
# are allowed ONLY under ADAPTER_DIR. Everywhere else in spec/v1.0/fixtures and
# spec/v1.0/profiles they stay forbidden, like any other extension not listed above.
ADAPTER_DIR = "spec/v1.0/fixtures/adapters"
ADAPTER_EXTENSIONS = frozenset((".sql", ".rego", ".fga", ".ldif"))


class CheckError(Exception):
    """The check cannot run; reported with exit status 2."""


def read_text(path, label):
    # Explicit UTF-8 (a leading BOM is dropped) so the result never depends on
    # the locale. Universal newlines turn CRLF into LF.
    try:
        with open(path, encoding="utf-8-sig") as handle:
            return handle.read()
    except (OSError, UnicodeDecodeError) as exc:
        raise CheckError("%s: cannot read as UTF-8: %s" % (label, exc))


# ---------------------------------------------------------------------------
# Markdown link extraction (CommonMark subset, no third-party parser)
#
# Recognised: inline links and images [t](dest "title"), angle-bracket
# destinations [t](<dest with spaces>), reference definitions [ref]: dest, and
# href=/src= attributes of inline HTML. Not links: anything inside a fenced
# code block, a code span or an HTML comment. Reference uses ([t][ref]) need no
# handling because their destination is the definition. Indented code blocks are
# not recognised, so a link written in one is still checked.
# ---------------------------------------------------------------------------

_FENCE_OPEN = re.compile(r"^[ \t>]*(?:(?:[-*+]|\d{1,9}[.)])[ \t]+)?(`{3,}|~{3,})(.*)$")
_FENCE_CLOSE = re.compile(r"^[ \t>]*(`{3,}|~{3,})[ \t]*$")
_TICKS = re.compile(r"`+")
_BLANK_LINE = re.compile(r"[ \t]*(?:\n|\Z)")
_ESCAPE = re.compile(r"\\([!-/:-@\[-`{-~])")
_DEFINITION = re.compile(
    r"\[(?!\^)(?:[^\]\\\n]|\\.)+\]:[ \t]*\n?[ \t]*(<[^<>\n]*>|[^\s<]\S*)"
)
_HTML_TAG = re.compile(r"<[A-Za-z][^<>]*>")
_HTML_URL = re.compile(
    r"""\b(?:href|src)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))""", re.I
)
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")


def _blank_fences(lines):
    """Empty every line of a fenced code block, fences included."""
    out = []
    fence = None
    for line in lines:
        if fence is None:
            m = _FENCE_OPEN.match(line)
            # A backtick fence cannot carry a backtick in its info string:
            # that line is an inline code span.
            if m and not (m.group(1)[0] == "`" and "`" in m.group(2)):
                fence = m.group(1)
            else:
                out.append(line)
                continue
        else:
            m = _FENCE_CLOSE.match(line)
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence):
                fence = None
        out.append("")
    return out


def _boundaries(text):
    """Offsets a code span cannot cross: blank lines and table rows."""
    bounds = [m.start() for m in re.finditer(r"\n[ \t]*\n", text)]
    for m in re.finditer(r"^[ \t]*\|.*$", text, re.M):
        bounds.append(m.start())
        bounds.append(m.end())
    bounds.sort()
    return bounds


def _skip_ws(text, i):
    """Skip spaces, tabs and at most one line ending."""
    seen_newline = False
    while i < len(text) and (
        text[i] in " \t" or (text[i] == "\n" and not seen_newline)
    ):
        seen_newline = seen_newline or text[i] == "\n"
        i += 1
    return i


def _parse_inline_dest(text, i):
    """Parse `dest "title")` after `](`; return (dest, end) or None."""
    n = len(text)
    i = _skip_ws(text, i)
    if i < n and text[i] == "<":
        j = i + 1
        while j < n and text[j] != ">":
            if text[j] in "\n<":
                return None
            j += 2 if text[j] == "\\" else 1
        if j >= n:
            return None
        dest = text[i + 1 : j]
        j += 1
    else:
        depth = 0
        j = i
        while j < n and text[j] not in " \t\n" and ord(text[j]) >= 0x20:
            if text[j] == "\\" and j + 1 < n:
                j += 2
                continue
            if text[j] == "(":
                depth += 1
            elif text[j] == ")":
                if depth == 0:
                    break
                depth -= 1
            j += 1
        if depth != 0:
            return None
        dest = text[i:j]
    k = _skip_ws(text, j)
    if k > j and k < n and text[k] in "\"'(":
        close = ")" if text[k] == "(" else text[k]
        m = k + 1
        while m < n and text[m] != close:
            m += 2 if text[m] == "\\" else 1
        if m >= n:
            return None
        k = _skip_ws(text, m + 1)
    if k < n and text[k] == ")":
        return dest, k + 1
    return None


def extract_links(text):
    """Return [(line, destination)] for every link outside code, as written."""
    text = "\n".join(_blank_fences(text.split("\n")))
    n = len(text)
    bounds = _boundaries(text)
    newlines = [m.start() for m in re.finditer("\n", text)]
    found = []
    stack = []  # open `[` of the current paragraph

    def line_of(offset):
        return bisect.bisect_right(newlines, offset) + 1

    i = 0
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
        elif c == "`":
            run = _TICKS.match(text, i)
            k = bisect.bisect_left(bounds, run.end())
            limit = bounds[k] if k < len(bounds) else n
            for close in _TICKS.finditer(text, run.end(), limit):
                if len(close.group()) == len(run.group()):
                    i = close.end()
                    break
            else:
                i = run.end()
        elif text.startswith("<!--", i):
            end = text.find("-->", i + 4)
            i = i + 4 if end < 0 else end + 3
        elif c == "<":
            tag = _HTML_TAG.match(text, i)
            if tag:
                for attr in _HTML_URL.finditer(tag.group()):
                    found.append((line_of(i), "".join(g or "" for g in attr.groups())))
                i = tag.end()
            else:
                i += 1
        elif c == "[":
            start = text.rfind("\n", 0, i) + 1
            definition = (
                _DEFINITION.match(text, i)
                if i - start <= 3 and not text[start:i].strip(" ")
                else None
            )
            if definition:
                dest = definition.group(1)
                if dest.startswith("<"):
                    dest = dest[1:-1]
                found.append((line_of(i), dest))
                i = definition.end()
            else:
                stack.append(i)
                i += 1
        elif c == "]":
            parsed = None
            if stack:
                stack.pop()
                if text.startswith("(", i + 1):
                    parsed = _parse_inline_dest(text, i + 2)
            if parsed:
                found.append((line_of(i), parsed[0]))
                i = parsed[1]
            else:
                i += 1
        elif c == "\n":
            if _BLANK_LINE.match(text, i + 1):
                stack.clear()
            i += 1
        else:
            i += 1
    return found


def resolve(source, dest):
    """Resolve a link destination written in `source` (repo-relative POSIX path).

    Return None when it is not a local path (scheme, //host, pure #fragment or
    ?query). Otherwise (target, escapes): target is the repo-root-relative path
    the link points to (the form used in spec/.links-allow), escapes is True
    when it is not reachable inside spec/ taken as the root.
    """
    dest = html.unescape(_ESCAPE.sub(r"\1", dest)).strip()
    if _SCHEME.match(dest) or dest.startswith("//"):
        return None
    path = urllib.parse.unquote(re.split(r"[?#]", dest, maxsplit=1)[0])
    if not path:
        return None
    if path.startswith("/"):
        # Root-absolute: the root differs between source tree and mirror.
        norm = posixpath.normpath(path.lstrip("/"))
        return ("/" if norm == "." else "/" + norm), True
    inside = posixpath.normpath(
        posixpath.join(posixpath.dirname(source[len(SPEC_DIR) + 1 :]), path)
    )
    escapes = inside == ".." or inside.startswith("../")
    return posixpath.normpath(posixpath.join(SPEC_DIR, inside)), escapes


# ---------------------------------------------------------------------------
# Allow-list, walkers, checks
# ---------------------------------------------------------------------------


def _normalized(path):
    return posixpath.normpath(path) == path


def load_allowlist(root):
    """Parse spec/.links-allow into {(source, target): line}."""
    path = os.path.join(root, *ALLOW_FILE.split("/"))
    if not os.path.exists(path):
        return {}
    entries = {}
    errors = []
    for number, raw in enumerate(read_text(path, ALLOW_FILE).split("\n"), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(" -> ")]
        problem = None
        if len(parts) != 2 or not all(parts):
            problem = 'expected "<source> -> <target>"'
        else:
            source, target = parts
            if not source.startswith(SPEC_DIR + "/") or not _normalized(source):
                problem = "source must be a normalized path under spec/"
            elif "\\" in target or not _normalized(target.lstrip("/")):
                problem = "target must be a normalized repo-root-relative path"
        if problem:
            errors.append(
                "%s:%d: malformed entry %r: %s" % (ALLOW_FILE, number, line, problem)
            )
        else:
            entries[(source, target)] = number
    if errors:
        raise CheckError("\n".join(errors))
    return entries


def walk_files(root, top):
    """Yield (repo-relative POSIX path, absolute path) of files under top, sorted."""
    base = os.path.join(root, *top.split("/"))
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames.sort()
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            yield os.path.relpath(full, root).replace(os.sep, "/"), full


def check_links(root, allow):
    problems = []  # (path, line, message)
    used = set()
    files = links = allowed = 0
    for source, full in walk_files(root, SPEC_DIR):
        if not source.lower().endswith(".md"):
            continue
        files += 1
        for line, dest in extract_links(read_text(full, source)):
            resolved = resolve(source, dest)
            if resolved is None:
                continue
            links += 1
            target, escapes = resolved
            if not escapes:
                continue
            if (source, target) in allow:
                used.add((source, target))
                allowed += 1
                continue
            message = "%s:%d: link leaves spec/: %s (allow with: %s -> %s)"
            problems.append(
                (source, line, message % (source, line, dest, source, target))
            )
    for entry, number in allow.items():
        if entry not in used:
            message = "%s:%d: stale entry, no such link: %s -> %s"
            problems.append(
                (ALLOW_FILE, number, message % (ALLOW_FILE, number, *entry))
            )
    return problems, files, links, allowed


def check_fixtures(root):
    problems = []
    count = 0
    for top in FIXTURE_DIRS:
        for rel, _full in walk_files(root, top):
            count += 1
            ext = os.path.splitext(rel)[1].lower()
            if ext in NEUTRAL_EXTENSIONS:
                continue
            if ext in ADAPTER_EXTENSIONS and rel.startswith(ADAPTER_DIR + "/"):
                continue
            message = "%s: extension %s not allowed in %s (neutral: %s)" % (
                rel,
                repr(ext) if ext else "(none)",
                top,
                " ".join(sorted(NEUTRAL_EXTENSIONS)),
            )
            if ext in ADAPTER_EXTENSIONS:
                message += "; %s is allowed only under %s/" % (ext, ADAPTER_DIR)
            problems.append((rel, 0, message))
    return problems, count


def main():
    root = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    try:
        if not os.path.isdir(os.path.join(root, SPEC_DIR)):
            raise CheckError("%s/ not found under %s" % (SPEC_DIR, root))
        allow = load_allowlist(root)
        problems, files, links, allowed = check_links(root, allow)
        fixture_problems, fixtures = check_fixtures(root)
    except CheckError as exc:
        print("check-spec-selfcontained: %s" % exc, file=sys.stderr)
        return 2
    problems += fixture_problems
    if problems:
        print(
            "check-spec-selfcontained: %d problem(s)" % len(problems), file=sys.stderr
        )
        for _path, _line, message in sorted(problems):
            print("  " + message, file=sys.stderr)
        return 1
    print(
        "check-spec-selfcontained: ok (%d markdown files, %d local links, "
        "%d allow-listed, %d fixture and profile files)"
        % (files, links, allowed, fixtures)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
