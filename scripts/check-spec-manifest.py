#!/usr/bin/env python3
"""Check spec/v1.0/fixtures/manifest.json against the rules of spec/v1.0/fixtures/README.md.

Every problem is printed as `[rule-id] where: message`, with the rule ids of
pactfix check manifest (go/runner/manifest), so the two checkers can be
compared; scripts/check-manifest-parity.py does that.

manifest-json        the file is unreadable, not strict JSON (draft Section
                     7.1, see scripts/specjson.py) or not one JSON object
manifest-shape       a top-level member or an entry member is missing, unknown
                     or of the wrong JSON type; manifest_version is not 1;
                     entries is not an array of objects
entry-id             an id is not two or three id segments, or a segment
                     starts with `_` or contains `.` although the entry is
                     neither an adapter case nor a source case (the id
                     patterns of manifest.schema.json)
entry-id-duplicate   two entries share an id
entry-order          the entries are not sorted by id (byte order)
entry-kind           kind is not one of the kinds of the README
entry-scope          scope is not core, runner or adapter, or an entry of
                     kind transport or profile is not scope runner, or one of
                     kind mcp or source-case not scope adapter
entry-path           path is not a relative, `/` separated path of ASCII
                     segments, none empty or starting with `.`
entry-expected       expected is not such a path, is null for a kind that has
                     an expected result, or is set for key, adapter-asset
                     and source-case
entry-outcome        outcome is not an outcome token, is null for a kind that
                     has one, or is set for key, adapter-asset and
                     source-case
entry-spec-map-row   spec_map_row is not a row id such as R01 or CL-11.3
entry-draft-section  draft_section is not a section number or appendix letter
entry-capabilities   the optional capabilities member is empty, repeats a
                     capability or names one that is not a capability token
                     (manifest-shape when it is not an array of strings)
entry-conformance-profile
                     the optional conformance_profile member is empty,
                     repeats a profile or names one that is not a
                     conformance profile id of spec/v1.0/profiles/registry.json
                     (manifest-shape when it is not an array of strings)
entry-transport      the optional transport member is empty, repeats a
                     transport profile or names one that is not https or
                     stdio-ipc (manifest-shape when it is not an array of
                     strings)
entry-layer          the optional layer member is not transcript or os, or
                     is set although transport, ["https"] when absent, has
                     no stdio-ipc (manifest-shape when it is not a string),
                     or is absent from an entry of kind transport
adapter-case-path    an adapter-case entry is not the file
                     adapters/<adapter>/<case>.json with the id
                     adapters/<adapter>/<case>: the id has another form, or
                     the path is not the id followed by .json
source-case-path     a source-case entry is not the file
                     sources/<source>/<case>.json with the id
                     sources/<source>/<case>: the id has another form, or
                     the path is not the id followed by .json
path-missing         a path does not exist, is a dangling symbolic link or
                     resolves outside spec/v1.0/fixtures
expected-missing     an expected file does not exist, resolves outside
                     spec/v1.0/fixtures or is not a file
file-uncovered       a file under spec/v1.0/fixtures is in no entry's path, is no
                     entry's expected file and is not under expected/<id>/
                     for the id of an entry (format v2); manifest.json and
                     manifest.schema.json at the top, files under testdata/
                     at the top, README.md files and files whose name starts
                     with LICENSE need no entry
file-extension       a file has an extension outside .json .yaml .md .jws, or
                     .sql .rego .fga .ldif outside the path of an
                     adapter-asset entry; extensions are lowercase, so .JSON
                     is on neither list

Whether each spec_map_row is a row of spec/v1.0/spec-map.md, and the group rules
of the map, are checked by scripts/check-spec-map.py.

Run it isolated, standard library only (Python 3.9 and later):

    python3 -I scripts/check-spec-manifest.py

Exit status: 0 clean; 1 problems listed on stderr; 2 cannot run.
"""

import importlib.util
import json
import os
import re
import stat
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
FIXTURES = "spec/v1.0/fixtures"
MANIFEST = "manifest.json"
SCHEMA = "manifest.schema.json"

# The patterns of spec/v1.0/fixtures/manifest.schema.json. An id segment is
# lowercase letters and digits joined by hyphens. The id of an adapter case,
# adapters/<adapter>/<case>, follows the name of its file
# adapters/<adapter>/<case>.json, so its last two segments may also start with
# `_` and join with `.`.
_SEGMENT = r"[a-z0-9]+(?:-[a-z0-9]+)*"
_FILE_SEGMENT = r"_?[a-z0-9]+(?:[-.][a-z0-9]+)*"
ID_RE = re.compile(r"{0}/{0}(?:/{0})?".format(_SEGMENT))
ADAPTER_CASE_ID_RE = re.compile(r"adapters/{0}/{0}".format(_FILE_SEGMENT))
# The id of a source case, sources/<source>/<case>: its case segment follows
# the name of its file and may join with `.`; no segment starts with `_`.
SOURCE_CASE_ID_RE = re.compile(r"sources/{0}/[a-z0-9]+(?:[-.][a-z0-9]+)*".format(_SEGMENT))
# The widest id form, of any kind: an id of another form is malformed.
FILE_ID_RE = re.compile(r"{0}/{0}(?:/{0})?".format(_FILE_SEGMENT))
PATH_RE = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]*(?:/[A-Za-z0-9_-][A-Za-z0-9._-]*)*")
SPEC_MAP_ROW_RE = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+(?:\.[0-9]+)*)?")
DRAFT_SECTION_RE = re.compile(r"(?:[1-9][0-9]*|[A-Z])(?:\.[1-9][0-9]*)*")

# The members of an entry and their values (spec/v1.0/fixtures/README.md).
MEMBERS = (
    "id", "kind", "scope", "path", "expected", "outcome", "spec_map_row", "draft_section",
)
# The members an entry may have.
OPTIONAL_MEMBERS = ("capabilities", "conformance_profile", "transport", "layer")
# The optional capabilities an entry may test (README, Optional capabilities).
CAPABILITIES = ("jws-ed25519",)
# The entry fields of README, Manifest entry fields. The conformance profile
# ids are the entries of kind conformance in spec/v1.0/profiles/registry.json.
CONFORMANCE_PROFILES = ("full", "single-owner")
DEFAULT_CONFORMANCE_PROFILE = "full"
# The transport profile ids of claim.transport in
# spec/v1.0/profiles/integration-profile.schema.json.
TRANSPORTS = ("https", "stdio-ipc")
DEFAULT_TRANSPORT = "https"
LOCAL_TRANSPORT = "stdio-ipc"
LAYERS = ("transcript", "os")
KINDS = (
    "key", "vector", "schema", "evaluate", "outcomes", "learning",
    "adapter-case", "adapter-asset", "source-case", "profile-invalid",
    "transport", "mcp", "profile",
)
# The one scope of each kind that has one; the other kinds take any scope.
KIND_SCOPE = {
    "transport": "runner", "profile": "runner", "mcp": "adapter", "source-case": "adapter",
}
# Kinds whose expected and outcome are null.
NO_EXPECTED = ("key", "adapter-asset", "source-case")
# The kind whose id segments may start with `_` and contain `.`, and whose
# id and path follow the layout adapters/<adapter>/<case>.json.
ADAPTER_CASE = "adapter-case"
# The kind whose case segment may contain `.`, and whose id and path follow
# the layout sources/<source>/<case>.json.
SOURCE_CASE = "source-case"
# The kind whose path may hold native-format files.
ADAPTER_ASSET = "adapter-asset"
SCOPES = ("core", "runner", "adapter")
# Test inputs of the checks themselves, not fixtures: no entry covers them.
TESTDATA = "testdata"
OUTCOMES = (
    "ADMISSIBLE", "INADMISSIBLE", "DEFERRED", "ACCEPTED", "REJECTED",
    "QUALIFIED", "UNQUALIFIED", "DISPUTED", "MATCH",
)
# Extensions, lowercase and compared as written.
NEUTRAL_EXTENSIONS = (".json", ".yaml", ".md", ".jws")
NATIVE_EXTENSIONS = (".sql", ".rego", ".fga", ".ldif")


def _load_sibling(name):
    path = os.path.join(os.path.dirname(os.path.realpath(__file__)), name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True  # keep scripts/ free of __pycache__
    spec.loader.exec_module(module)
    return module


specjson = _load_sibling("specjson")


class Problems(list):
    def add(self, rule, where, message):
        self.append((rule, where, message))


def json_type(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    return "array" if isinstance(value, list) else "object"


def quote(value):
    return json.dumps(value, ensure_ascii=False)


def entry_id(entry):
    """The id of an entry when it is a string, else ""."""
    if isinstance(entry, dict) and isinstance(entry.get("id"), str):
        return entry["id"]
    return ""


# Field rules.


def one_of(values):
    return lambda v: None if v in values else "is not one of %s" % " ".join(values)


def matches(pattern, problem):
    return lambda v: None if pattern.fullmatch(v) else problem


path_problem = matches(
    PATH_RE, "is not a relative path: / separated ASCII segments, none empty or starting with ."
)


def id_problem(value, kind):
    if not FILE_ID_RE.fullmatch(value):
        return "is not two or three id segments: lowercase letters, digits and hyphens"
    if kind in KINDS and kind not in (ADAPTER_CASE, SOURCE_CASE) and not ID_RE.fullmatch(value):
        return "starts a segment with _ or has a . in one; only %s and %s ids may" % (
            ADAPTER_CASE, SOURCE_CASE,
        )
    return None


def scope_problem(value, kind):
    if value not in SCOPES:
        return "is not one of %s" % " ".join(SCOPES)
    want = KIND_SCOPE.get(kind) if isinstance(kind, str) else None
    if want and value != want:
        return "is not %s, the scope of every %s entry" % (want, kind)
    return None


def adapter_case_problem(entry):
    """Why an adapter-case entry is not the file adapters/<adapter>/<case>.json
    with the id adapters/<adapter>/<case>, or None. An id or path that breaks
    its own field rule is left to that rule."""
    case_id, path = entry.get("id"), entry.get("path")
    if not (isinstance(case_id, str) and FILE_ID_RE.fullmatch(case_id)):
        return None
    if not (isinstance(path, str) and PATH_RE.fullmatch(path)):
        return None
    want = case_id + ".json"
    if not ADAPTER_CASE_ID_RE.fullmatch(case_id):
        return (
            "id %s is not adapters/<adapter>/<case>, the id of the case file "
            "adapters/<adapter>/<case>.json" % quote(case_id)
        )
    if path != want:
        return "path %s is not the case file %s, the id followed by .json" % (
            quote(path), quote(want),
        )
    return None


def source_case_problem(entry):
    """Why a source-case entry is not the file sources/<source>/<case>.json
    with the id sources/<source>/<case>, or None. An id or path that breaks
    its own field rule is left to that rule."""
    case_id, path = entry.get("id"), entry.get("path")
    if not (isinstance(case_id, str) and FILE_ID_RE.fullmatch(case_id)):
        return None
    if not (isinstance(path, str) and PATH_RE.fullmatch(path)):
        return None
    want = case_id + ".json"
    if not SOURCE_CASE_ID_RE.fullmatch(case_id):
        return (
            "id %s is not sources/<source>/<case>, the id of the case file "
            "sources/<source>/<case>.json" % quote(case_id)
        )
    if path != want:
        return "path %s is not the case file %s, the id followed by .json" % (
            quote(path), quote(want),
        )
    return None


def member_tests(kind):
    """(member, rule, nullable, test) for each string member of an entry."""
    return (
        ("id", "entry-id", False, lambda v: id_problem(v, kind)),
        ("kind", "entry-kind", False, one_of(KINDS)),
        ("scope", "entry-scope", False, lambda v: scope_problem(v, kind)),
        ("path", "entry-path", False, path_problem),
        ("spec_map_row", "entry-spec-map-row", False,
         matches(SPEC_MAP_ROW_RE, "is not a spec-map row id such as R01 or CL-11.3")),
        ("draft_section", "entry-draft-section", False,
         matches(DRAFT_SECTION_RE, 'is not a section number or appendix letter such as "11.3"')),
        ("expected", "entry-expected", True, path_problem),
        ("outcome", "entry-outcome", True, one_of(OUTCOMES)),
    )


def validate(manifest, problems):
    """Apply the field rules; return the entries, or [] when there are none."""
    for key in sorted(manifest):
        if key not in ("manifest_version", "entries"):
            problems.add("manifest-shape", MANIFEST, "unknown top-level member %s" % quote(key))
    if "manifest_version" not in manifest:
        problems.add("manifest-shape", MANIFEST, "no manifest_version")
    elif type(manifest["manifest_version"]) is not int or manifest["manifest_version"] != 1:
        problems.add(
            "manifest-shape", MANIFEST,
            "manifest_version is %s, want 1" % quote(manifest["manifest_version"]),
        )
    if "entries" not in manifest:
        problems.add("manifest-shape", MANIFEST, "no entries")
        return []
    entries = manifest["entries"]
    if not isinstance(entries, list):
        problems.add("manifest-shape", MANIFEST, "entries is %s, not an array" % json_type(entries))
        return []
    ids = [entry_id(entry) for entry in entries]
    first = {}
    for index, entry in enumerate(entries):
        validate_entry(index, entry, problems)
        this = ids[index]
        if not this:
            continue
        if this in first:
            problems.add(
                "entry-id-duplicate", this,
                "entries[%d] repeats the id of entries[%d]" % (index, first[this]),
            )
        else:
            first[this] = index
        if index > 0 and ids[index - 1] > this:
            problems.add(
                "entry-order", this,
                "entries[%d] sorts before entries[%d] %s; sort the entries by id"
                % (index, index - 1, ids[index - 1]),
            )
    return entries


def validate_entry(index, entry, problems):
    where = entry_id(entry) or "entries[%d]" % index
    if not isinstance(entry, dict):
        problems.add("manifest-shape", where, "not an object")
        return
    for key in sorted(entry):
        if key not in MEMBERS and key not in OPTIONAL_MEMBERS:
            problems.add("manifest-shape", where, "unknown member %s" % quote(key))
    for key in MEMBERS:
        if key not in entry:
            problems.add("manifest-shape", where, "no %s" % key)

    kind = entry.get("kind")
    for member, rule, nullable, test in member_tests(kind):
        if member not in entry:
            continue
        value = entry[member]
        found = json_type(value)
        if found == "null" and nullable:
            continue
        if found != "string":
            problems.add("manifest-shape", where, "%s is %s, not a string" % (member, found))
            continue
        message = test(value)
        if message:
            problems.add(rule, where, "%s %s %s" % (member, quote(value), message))

    if kind == ADAPTER_CASE:
        message = adapter_case_problem(entry)
        if message:
            problems.add("adapter-case-path", where, message)
    elif kind == SOURCE_CASE:
        message = source_case_problem(entry)
        if message:
            problems.add("source-case-path", where, message)
    for member, rule, known, empty in (
        ("capabilities", "entry-capabilities", CAPABILITIES,
         "leave the member out for an entry every implementation must pass"),
        ("conformance_profile", "entry-conformance-profile", CONFORMANCE_PROFILES,
         "leave the member out for an entry of the default profile %s"
         % DEFAULT_CONFORMANCE_PROFILE),
        ("transport", "entry-transport", TRANSPORTS,
         "leave the member out for an entry of the default transport %s" % DEFAULT_TRANSPORT),
    ):
        if member in entry:
            validate_tokens(member, rule, known, empty, entry[member], where, problems)
    if "layer" in entry:
        validate_layer(entry, where, problems)
    elif kind == "transport":
        problems.add(
            "entry-layer", where,
            "names no layer: an entry of kind transport says who executes it, %s"
            % " or ".join(LAYERS),
        )

    # expected and outcome are null exactly for the kinds without them.
    if not isinstance(kind, str) or kind not in KINDS:
        return
    needs = kind not in NO_EXPECTED
    for member, rule in (("expected", "entry-expected"), ("outcome", "entry-outcome")):
        value = entry.get(member)
        if member in entry and value is None and needs:
            problems.add(rule, where, "%s is null, but kind %s needs one" % (member, kind))
        elif isinstance(value, str) and not needs:
            problems.add(
                rule, where,
                "%s is %s, but kind %s has none: write null" % (member, quote(value), kind),
            )


def validate_tokens(member, rule, known, empty, value, where, problems):
    """An optional member that is one or more distinct tokens of known:
    capabilities, conformance_profile and transport."""
    if not isinstance(value, list):
        problems.add(
            "manifest-shape", where, "%s is %s, not an array" % (member, json_type(value))
        )
        return
    if not value:
        problems.add(rule, where, "%s is empty: %s" % (member, empty))
        return
    seen = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            problems.add(
                "manifest-shape", where,
                "%s[%d] is %s, not a string" % (member, index, json_type(item)),
            )
            continue
        if item not in known:
            problems.add(
                rule, where,
                "%s[%d] %s is not one of %s" % (member, index, quote(item), " ".join(known)),
            )
        elif item in seen:
            problems.add(
                rule, where, "%s[%d] %s repeats a token" % (member, index, quote(item)),
            )
        seen.append(item)


def validate_layer(entry, where, problems):
    """The optional member layer: transcript or os, and only on an entry
    whose transport, ["https"] when absent, has stdio-ipc. A malformed
    transport is left to its own rule."""
    value = entry["layer"]
    if not isinstance(value, str):
        problems.add("manifest-shape", where, "layer is %s, not a string" % json_type(value))
        return
    if value not in LAYERS:
        problems.add(
            "entry-layer", where, "layer %s is not one of %s" % (quote(value), " ".join(LAYERS))
        )
        return
    transport = entry.get("transport", [DEFAULT_TRANSPORT])
    if not (isinstance(transport, list) and all(isinstance(t, str) for t in transport)):
        return
    if LOCAL_TRANSPORT not in transport:
        problems.add(
            "entry-layer", where,
            "layer %s is set, but transport %s has no %s: a layer applies only to "
            "the local transport profile" % (quote(value), quote(transport), LOCAL_TRANSPORT),
        )


# Completeness: the manifest against the fixture directory.


def locate(fixtures_dir, real_root, rel):
    """Why rel is not an existing path inside the fixture directory, or None."""
    full = os.path.join(fixtures_dir, *rel.split("/"))
    if not os.path.lexists(full):
        return "does not exist"
    if not os.path.exists(full):
        return "is a dangling symbolic link"
    if not os.path.realpath(full).startswith(real_root + os.sep):
        return "resolves outside the fixture directory"
    return None


def extension(rel):
    """The extension of the last segment, from its last dot, as written."""
    name = rel.rsplit("/", 1)[-1]
    dot = name.rfind(".")
    return name[dot:] if dot >= 0 else ""


def exempt(rel):
    """Whether a fixture file needs no covering entry."""
    if rel in (MANIFEST, SCHEMA) or within(rel, TESTDATA):
        return True
    name = rel.rsplit("/", 1)[-1]
    return name == "README.md" or name.startswith("LICENSE")


def within(rel, path):
    return rel == path or rel.startswith(path + "/")


def fixture_files(fixtures_dir, problems):
    """Every non-directory under the fixture directory, as a / path.

    A symbolic link counts as a file and is not followed, also when it points
    to a directory.
    """
    found = []

    def failed(error):
        problems.add("path-missing", ".", "walk: %s" % error)

    for dirpath, dirnames, filenames in os.walk(fixtures_dir, onerror=failed):
        names = list(filenames)
        for name in list(dirnames):
            if os.path.islink(os.path.join(dirpath, name)):
                dirnames.remove(name)
                names.append(name)
        rel_dir = os.path.relpath(dirpath, fixtures_dir)
        for name in names:
            rel = name if rel_dir == "." else os.path.join(rel_dir, name)
            found.append(rel.replace(os.sep, "/"))
    return sorted(found, key=lambda rel: rel.split("/"))


def completeness(fixtures_dir, entries, problems):
    real_root = os.path.realpath(fixtures_dir)
    paths, assets, expected = [], [], set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        where = entry_id(entry) or "entries[%d]" % index
        # Format v2: every file under expected/<id>/ belongs to the entry.
        ident = entry_id(entry)
        if ident and PATH_RE.fullmatch("expected/" + ident):
            paths.append("expected/" + ident)
        path = entry.get("path")
        if isinstance(path, str) and PATH_RE.fullmatch(path):
            reason = locate(fixtures_dir, real_root, path)
            if reason:
                problems.add("path-missing", where, "path %s %s" % (quote(path), reason))
            paths.append(path)
            if entry.get("kind") == ADAPTER_ASSET:
                assets.append(path)
        value = entry.get("expected")
        if isinstance(value, str) and PATH_RE.fullmatch(value):
            reason = locate(fixtures_dir, real_root, value)
            full = os.path.join(fixtures_dir, *value.split("/"))
            if reason is None and not stat.S_ISREG(os.stat(full).st_mode):
                reason = "is not a file"
            if reason:
                problems.add("expected-missing", where, "expected %s %s" % (quote(value), reason))
            expected.add(value)

    for rel in fixture_files(fixtures_dir, problems):
        ext = extension(rel)
        if ext in NATIVE_EXTENSIONS and not any(within(rel, asset) for asset in assets):
            problems.add(
                "file-extension", rel,
                "extension %s is allowed only inside the path of an %s entry"
                % (ext, ADAPTER_ASSET),
            )
        elif ext not in NEUTRAL_EXTENSIONS + NATIVE_EXTENSIONS:
            problems.add(
                "file-extension", rel,
                "extension %s is not language-neutral; allowed: %s, and %s inside an %s entry"
                % (quote(ext), " ".join(NEUTRAL_EXTENSIONS), " ".join(NATIVE_EXTENSIONS),
                   ADAPTER_ASSET),
            )
        if not (exempt(rel) or rel in expected or any(within(rel, p) for p in paths)):
            problems.add(
                "file-uncovered", rel,
                "no manifest entry covers this file: add one, or put it inside an entry's path",
            )


def main():
    fixtures_dir = os.path.join(ROOT, *FIXTURES.split("/"))
    if not os.path.isdir(fixtures_dir):
        print("check-spec-manifest: %s is not a directory" % FIXTURES, file=sys.stderr)
        return 2
    problems = Problems()
    entries = []
    try:
        manifest = specjson.load(os.path.join(fixtures_dir, MANIFEST))
    except specjson.StrictJSONError as exc:
        problems.add("manifest-json", MANIFEST, str(exc))
    else:
        if isinstance(manifest, dict):
            entries = validate(manifest, problems)
            completeness(fixtures_dir, entries, problems)
        else:
            problems.add(
                "manifest-json", MANIFEST,
                "the top level is %s, not an object" % json_type(manifest),
            )
    if problems:
        print("check-spec-manifest: %d problem(s)" % len(problems), file=sys.stderr)
        for rule, where, message in problems:
            print("  [%s] %s: %s" % (rule, where, message), file=sys.stderr)
        return 1
    print("check-spec-manifest: ok (%d entries)" % len(entries))
    return 0


if __name__ == "__main__":
    sys.exit(main())
