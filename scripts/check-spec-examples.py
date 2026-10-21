#!/usr/bin/env python3
"""Check the JSON blocks in spec/v1.0/examples/*.md.

1. Every fenced block whose info string starts with `json` must parse
   strictly: duplicate property names, non-finite numbers and invalid Unicode
   are rejected (draft Section 7.1; see scripts/specjson.py).
2. A block directly preceded by a schema annotation, a one-line HTML comment
   with a JSON Pointer into spec/v1.0/schemas/pact.schema.json:

       <!-- schema: #/$defs/RequirementContract -->

   must also validate against that subschema. `#` names the root schema.
   Format keywords are not asserted: the schema treats them as annotations.
3. A block without an annotation is a partial illustration (spec/v1.0/examples/
   README.md: excerpts are not wire fixtures) and is only syntax-checked. The
   script lists each one as partial, so an excerpt that becomes a complete
   object can be annotated.

An annotation must be followed, after blank lines only, by a json fence. A
dangling annotation, a malformed one, or a pointer that resolves to nothing
fails the check, so a typo cannot silently turn validation off.

Needs the jsonschema and referencing packages from tools/spec/requirements.txt,
so run it with the interpreter of that environment, isolated:

    tools/spec/.venv/bin/python3 -I scripts/check-spec-examples.py

Exit status: 0 clean; 1 problems listed on stderr; 2 cannot run.
"""

import glob
import importlib.util
import os
import re
import sys
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
SCHEMA = "spec/v1.0/schemas/pact.schema.json"
EXAMPLES = "spec/v1.0/examples"
DIALECT = "https://json-schema.org/draft/2020-12/schema"
MAX_ERRORS = 5


class CheckError(Exception):
    """The check cannot run; reported with exit status 2."""


def _load_sibling(name):
    path = os.path.join(os.path.dirname(os.path.realpath(__file__)), name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True  # keep scripts/ free of __pycache__
    spec.loader.exec_module(module)
    return module


specjson = _load_sibling("specjson")

_FENCE_OPEN = re.compile(r"^([ \t]*(?:>[ \t]*)*)(`{3,}|~{3,})[ \t]*(.*?)[ \t]*$")
_FENCE_CLOSE = re.compile(r"^[ \t]*(?:>[ \t]*)*(`{3,}|~{3,})[ \t]*$")
_QUOTE_PREFIX = re.compile(r"^[ \t]*(?:>[ \t]?)+")
_ANNOTATION = re.compile(r"^[ \t]*<!--[ \t]*schema:[ \t]*(\S+)[ \t]*-->[ \t]*$")
_ANNOTATION_START = re.compile(r"^[ \t]*<!--[ \t]*schema\b")


def find_blocks(text, label):
    """Return (blocks, problems).

    A block is (line, annotation, body) for each json fence; `line` is the
    1-based line of the opening fence and `annotation` a (line, pointer) pair
    or None.
    """
    blocks = []
    problems = []
    pending = None  # annotation seen, waiting for the next non-blank line
    fence = None  # (char, length, is_json, open_line, annotation, quoted, body)

    def dangling(note):
        problems.append(
            "%s:%d: schema annotation %s is not followed by a json block"
            % (label, note[0], note[1])
        )

    for number, line in enumerate(text.split("\n"), 1):
        if fence is not None:
            close = _FENCE_CLOSE.match(line)
            if close and close.group(1)[0] == fence[0] and len(close.group(1)) >= fence[1]:
                if fence[2]:
                    blocks.append((fence[3], fence[4], "\n".join(fence[6])))
                fence = None
            else:
                body = line
                if fence[5]:
                    body = _QUOTE_PREFIX.sub("", body, count=1)
                fence[6].append(body)
            continue
        if not line.strip():
            continue
        annotation = _ANNOTATION.match(line)
        if annotation:
            if pending:
                dangling(pending)
            pending = (number, annotation.group(1))
            continue
        if _ANNOTATION_START.match(line):
            problems.append(
                "%s:%d: malformed schema annotation (expected "
                "<!-- schema: #/$defs/Name -->)" % (label, number)
            )
            continue
        opened = _FENCE_OPEN.match(line)
        if opened and not (opened.group(2)[0] == "`" and "`" in opened.group(3)):
            words = opened.group(3).split()
            is_json = bool(words) and words[0].lower() == "json"
            if pending and not is_json:
                dangling(pending)
            fence = (
                opened.group(2)[0],
                len(opened.group(2)),
                is_json,
                number,
                pending if is_json else None,
                ">" in opened.group(1),
                [],
            )
            pending = None
            continue
        if pending:
            dangling(pending)
            pending = None
    if pending:
        dangling(pending)
    if fence is not None:
        problems.append("%s:%d: unterminated code fence" % (label, fence[3]))
    return blocks, problems


def resolve_pointer(document, pointer):
    """Follow `#/a/b` (RFC 6901 in URI fragment form); raise KeyError if absent."""
    if not pointer.startswith("#"):
        raise KeyError(pointer)
    fragment = urllib.parse.unquote(pointer[1:])
    if fragment == "":
        return document
    if not fragment.startswith("/"):
        raise KeyError(pointer)
    node = document
    for part in fragment[1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            raise KeyError(pointer)
    return node


def load_validation():
    """Return (schema, make_validator) or raise CheckError."""
    try:
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
    except ImportError as exc:
        raise CheckError(
            "%s; install tools/spec/requirements.txt into a virtualenv and run "
            "this script with that interpreter" % exc
        )
    try:
        schema = specjson.load(os.path.join(ROOT, SCHEMA))
    except specjson.StrictJSONError as exc:
        raise CheckError("%s: %s" % (SCHEMA, exc))
    schema_id = schema.get("$id") if isinstance(schema, dict) else None
    if not schema_id:
        raise CheckError("%s declares no $id" % SCHEMA)
    registry = Registry().with_resource(schema_id, Resource.from_contents(schema))

    def make_validator(pointer):
        # A one-keyword wrapper schema lets $ref reach any subschema by pointer
        # with the root's $defs in scope.
        return Draft202012Validator(
            {"$schema": DIALECT, "$ref": schema_id + pointer}, registry=registry
        )

    return schema, make_validator


def main():
    problems = []
    partial = []
    validated = []
    try:
        schema, make_validator = load_validation()
        files = sorted(glob.glob(os.path.join(ROOT, EXAMPLES, "*.md")))
        if not files:
            raise CheckError("no %s/*.md files found" % EXAMPLES)
        for path in files:
            label = os.path.relpath(path, ROOT).replace(os.sep, "/")
            try:
                with open(path, encoding="utf-8-sig") as handle:
                    text = handle.read()
            except (OSError, UnicodeDecodeError) as exc:
                raise CheckError("%s: cannot read as UTF-8: %s" % (label, exc))
            blocks, found = find_blocks(text, label)
            problems += found
            for line, annotation, body in blocks:
                where = "%s:%d" % (label, line)
                try:
                    instance = specjson.loads(body)
                except specjson.StrictJSONError as exc:
                    problems.append("%s: json block does not parse strictly: %s" % (where, exc))
                    continue
                if annotation is None:
                    partial.append(where)
                    continue
                pointer = annotation[1]
                try:
                    resolve_pointer(schema, pointer)
                except KeyError:
                    problems.append(
                        "%s: schema annotation %s does not resolve in %s"
                        % (where, pointer, SCHEMA)
                    )
                    continue
                errors = sorted(
                    make_validator(pointer).iter_errors(instance),
                    key=lambda e: [str(p) for p in e.absolute_path],
                )
                for error in errors[:MAX_ERRORS]:
                    location = "/" + "/".join(str(p) for p in error.absolute_path)
                    problems.append(
                        "%s: invalid against %s at %s: %s"
                        % (where, pointer, location, error.message[:200])
                    )
                if len(errors) > MAX_ERRORS:
                    problems.append(
                        "%s: ... and %d more error(s) against %s"
                        % (where, len(errors) - MAX_ERRORS, pointer)
                    )
                if not errors:
                    validated.append((where, pointer))
    except CheckError as exc:
        print("check-spec-examples: %s" % exc, file=sys.stderr)
        return 2
    for where, pointer in validated:
        print("  schema   %s  %s" % (where, pointer))
    for where in partial:
        print("  partial  %s  (syntax only)" % where)
    if problems:
        print("check-spec-examples: %d problem(s)" % len(problems), file=sys.stderr)
        for message in problems:
            print("  " + message, file=sys.stderr)
        return 1
    print(
        "check-spec-examples: ok (%d json blocks: %d validated against the schema, "
        "%d partial and syntax-checked only)"
        % (len(validated) + len(partial), len(validated), len(partial))
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
