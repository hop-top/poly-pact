"""Read the manifest-parity case table and apply its mutations.

tools/spec/README.md defines the table, tools/spec/manifest-parity-cases.json:
each case names the rule a broken copy of the spec tree must trigger (or
none, for a control) and the mutation, a list of steps, that breaks the
copy. load() reads and checks the table; Copy applies a mutation to one copy
of the tree. scripts/check-manifest-parity.py runs the checkers on the
copies.

The check scripts load this file by path (importlib), not by import name, so
they keep running under `python3 -I`. Standard library only (Python 3.9 and
later).
"""

import copy as copying
import importlib.util
import json
import os
import re
import string

__all__ = ["CaseError", "Copy", "load", "transform", "PYTHON_CHECKERS"]

PYTHON_CHECKERS = ("manifest", "map")

_GROUP_ROW = re.compile(r"^\| ([^|]+?) \|.*\| (planned|partial|landed) \|$")
_CASE_ID = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
_SELECTOR = re.compile(r"^\{([a-z][a-z-]*)(?:#([1-9][0-9]*))?\}$")
_INDEX = re.compile(r"^(0|[1-9][0-9]*)$")
_UPPER = str.maketrans(string.ascii_lowercase, string.ascii_uppercase)
_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)


class CaseError(Exception):
    """The table is malformed, or a mutation does not fit the current tree."""


def _load_sibling(name):
    path = os.path.join(os.path.dirname(os.path.realpath(__file__)), name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


specjson = _load_sibling("specjson")


# The case table. Each step names its op and the kind of each member; the
# members of OPTIONAL may be left out.
STEPS = {
    "add": {"path": "pointer", "value": "json"},
    "remove": {"path": "pointer"},
    "replace": {"path": "pointer", "value": "json"},
    "move": {"from": "pointer", "path": "pointer"},
    "copy": {"from": "pointer", "path": "pointer", "apply": "apply"},
    "insert-entry": {"like": "pointer", "set": "members"},
    "text": {"apply": "apply"},
    "write": {"file": "expr", "text": "str"},
    "copy-file": {"source": "expr", "file": "expr"},
    "delete": {"file": "expr"},
    "symlink": {"file": "expr", "target": "str"},
    "map-group": {"group": "expr", "status": "status", "set_status": "status", "drop": "true"},
    "map-line": {"line": "str", "text": "str"},
}
OPTIONAL = {
    "copy": {"apply"},
    "insert-entry": {"like"},
    "map-group": {"group", "status", "set_status", "drop"},
}
# Each transform with the types of its arguments.
TRANSFORMS = {
    "prepend": (str,),
    "append": (str,),
    "replace": (str, str),
    "replace-first": (str, str),
    "upper": (),
    "lower": (),
    "dirname": (),
    "segment": (int,),
}
STATUSES = ("planned", "partial", "landed")


def members(value, required, optional, where):
    if not isinstance(value, dict):
        raise CaseError("%s: not a JSON object" % where)
    missing = sorted(set(required) - set(value))
    if missing:
        raise CaseError("%s: missing %s" % (where, ", ".join(missing)))
    unknown = sorted(set(value) - set(required) - set(optional))
    if unknown:
        raise CaseError("%s: unknown %s" % (where, ", ".join(unknown)))


def check_apply(steps, where):
    if not isinstance(steps, list):
        raise CaseError("%s: apply is not an array" % where)
    for step in steps:
        if not (isinstance(step, list) and step and isinstance(step[0], str)) or (
            step[0] not in TRANSFORMS
        ):
            raise CaseError("%s: %s is not a transform" % (where, json.dumps(step)))
        types = TRANSFORMS[step[0]]
        args = step[1:]
        if len(args) != len(types) or any(
            type(arg) is not kind or (kind is int and arg < 0) for arg, kind in zip(args, types)
        ):
            raise CaseError("%s: wrong arguments for %s" % (where, step[0]))
        if step[0].startswith("replace") and not args[0]:
            raise CaseError("%s: %s of the empty string" % (where, step[0]))


def check_expr(value, where):
    if isinstance(value, str):
        return
    members(value, ("from",), ("apply",), where)
    check_member("pointer", value["from"], where)
    check_apply(value.get("apply", []), where)


def check_member(kind, value, where):
    if kind == "pointer":
        if not isinstance(value, str) or (value and not value.startswith("/")):
            raise CaseError("%s: %s is not a JSON pointer" % (where, json.dumps(value)))
    elif kind == "apply":
        check_apply(value, where)
    elif kind == "expr":
        check_expr(value, where)
    elif kind == "members":
        if not isinstance(value, dict):
            raise CaseError("%s: set is not a JSON object" % where)
        for item in value.values():
            if isinstance(item, (dict, list)):
                check_expr(item, where)
    elif kind == "str" and not isinstance(value, str):
        raise CaseError("%s: %s is not a string" % (where, json.dumps(value)))
    elif kind == "status" and value not in STATUSES:
        raise CaseError("%s: %s is not a group status" % (where, json.dumps(value)))
    elif kind == "true" and value is not True:
        raise CaseError("%s: drop is not true" % where)


def check_step(step, where):
    op = step.get("op") if isinstance(step, dict) else None
    if op not in STEPS:
        raise CaseError("%s: %s is not a step" % (where, json.dumps(step)))
    fields = STEPS[op]
    optional = OPTIONAL.get(op, set())
    members(step, ["op"] + [f for f in fields if f not in optional], optional, where)
    for name, value in step.items():
        if name != "op":
            check_member(fields[name], value, "%s: %s" % (where, name))
    if op == "map-group":
        if ("set_status" in step) == ("drop" in step):
            raise CaseError("%s: map-group needs one of set_status and drop" % where)
        if "group" not in step and "status" not in step:
            raise CaseError("%s: map-group needs group or status" % where)


def load(path, name):
    """The cases of the table at path, checked; name is the table's name in
    messages."""
    try:
        table = specjson.load(path)
    except specjson.StrictJSONError as exc:
        raise CaseError("%s: %s" % (name, exc))
    members(table, ("version", "cases"), (), name)
    if type(table["version"]) is not int or table["version"] != 1:
        raise CaseError("%s: version is not 1" % name)
    if not isinstance(table["cases"], list) or not table["cases"]:
        raise CaseError("%s: cases is not a non-empty array" % name)
    cases, seen = [], set()
    for number, item in enumerate(table["cases"], 1):
        where = "%s: case %d" % (name, number)
        case_id = item.get("id") if isinstance(item, dict) else None
        if not isinstance(case_id, str) or not _CASE_ID.match(case_id) or case_id in seen:
            raise CaseError("%s: id %s is not a new case id" % (where, json.dumps(case_id)))
        seen.add(case_id)
        where = "%s: case %s" % (name, case_id)
        rule = item.get("rule")
        extra = ("checker", "label", "forbid", "gap") if rule is not None else ()
        members(item, ("id", "rule", "mutation"), extra + ("note",), where)
        checker = item.get("checker", "manifest")
        if rule is not None and not (isinstance(rule, str) and rule):
            raise CaseError("%s: rule is not a rule id or null" % where)
        if checker not in PYTHON_CHECKERS:
            raise CaseError("%s: checker is not manifest or map" % where)
        if ("label" in item) != (checker == "map"):
            raise CaseError("%s: label goes with checker map, and only there" % where)
        label = item.get("label")
        if label is not None and not isinstance(label, str):
            raise CaseError("%s: label is not a string or null" % where)
        forbid = item.get("forbid", [])
        if not (isinstance(forbid, list) and all(isinstance(f, str) for f in forbid)):
            raise CaseError("%s: forbid is not an array of rule ids" % where)
        if not isinstance(item.get("gap", False), bool):
            raise CaseError("%s: gap is not true or false" % where)
        if "note" in item and not isinstance(item["note"], str):
            raise CaseError("%s: note is not a string" % where)
        mutation = item["mutation"]
        if not isinstance(mutation, list) or not mutation:
            raise CaseError("%s: mutation is not a non-empty array" % where)
        for index, step in enumerate(mutation, 1):
            check_step(step, "%s: step %d" % (where, index))
        cases.append(
            dict(
                name=case_id,
                rule=rule,
                checker=checker,
                label=label,
                forbid=tuple(forbid),
                gap=item.get("gap", False),
                mutation=mutation,
            )
        )
    return cases


def transform(text, steps):
    """Apply the transforms of an apply array to text."""
    for step in steps:
        name, args = step[0], step[1:]
        if name == "prepend":
            text = args[0] + text
        elif name == "append":
            text = text + args[0]
        elif name in ("replace", "replace-first"):
            if args[0] not in text:
                raise CaseError("%s: %s does not occur" % (name, json.dumps(args[0])))
            text = text.replace(args[0], args[1], 1 if name == "replace-first" else -1)
        elif name == "upper":
            text = text.translate(_UPPER)
        elif name == "lower":
            text = text.translate(_LOWER)
        elif name == "dirname":
            if "/" not in text:
                raise CaseError("dirname: %s has no /" % json.dumps(text))
            text = text.rsplit("/", 1)[0]
        else:  # segment
            parts = text.split("/")
            if args[0] >= len(parts):
                raise CaseError("segment: %s has no segment %d" % (json.dumps(text), args[0]))
            text = parts[args[0]]
    return text


class Copy:
    """One copy of the spec tree, and the steps a mutation applies to it."""

    def __init__(self, root):
        self.fixtures = os.path.join(root, "spec", "v1.0", "fixtures")
        self.map_path = os.path.join(root, "spec", "v1.0", "spec-map.md")
        self.manifest_path = os.path.join(self.fixtures, "manifest.json")
        self._doc = None
        self._loaded = False
        self.text = None  # manifest text once a text step ran
        self.dirty = False  # the parsed manifest changed

    @property
    def doc(self):
        if not self._loaded:
            with open(self.manifest_path, encoding="utf-8") as handle:
                self._doc = json.load(handle)
            self._loaded = True
        return self._doc

    def dump(self):
        return json.dumps(self.doc, indent=2, ensure_ascii=False) + "\n"

    def save(self):
        if self.text is not None:
            with open(self.manifest_path, "wb") as handle:
                handle.write(self.text.encode("utf-8"))
        elif self.dirty:
            with open(self.manifest_path, "w", encoding="utf-8") as handle:
                handle.write(self.dump())

    def apply(self, mutation):
        for step in mutation:
            getattr(self, "step_" + step["op"].replace("-", "_"))(step)
        self.save()

    # JSON pointers (RFC 6901) into the manifest, with entry selectors.

    def tokens(self, pointer):
        out = []
        for raw in pointer.split("/")[1:]:
            selector = _SELECTOR.match(raw)
            if selector:
                if out != ["entries"]:
                    raise CaseError("%s: an entry selector must follow /entries" % pointer)
                out.append(str(self.select(selector.group(1), int(selector.group(2) or 1))))
            else:
                out.append(raw.replace("~1", "/").replace("~0", "~"))
        return out

    def select(self, kind, n):
        entries = self.doc.get("entries") if isinstance(self.doc, dict) else None
        if not isinstance(entries, list):
            raise CaseError("the manifest has no entries array")
        found = [i for i, e in enumerate(entries) if isinstance(e, dict) and e.get("kind") == kind]
        if len(found) < n:
            raise CaseError("the manifest has fewer than %d %s entries" % (n, kind))
        return found[n - 1]

    def get(self, tokens):
        value = self.doc
        for token in tokens:
            if isinstance(value, dict) and token in value:
                value = value[token]
            elif isinstance(value, list) and _INDEX.match(token) and int(token) < len(value):
                value = value[int(token)]
            else:
                raise CaseError("the manifest has no /%s" % "/".join(tokens))
        return value

    def add(self, tokens, value):
        if not tokens:
            self._doc = value
            return
        into, last = self.get(tokens[:-1]), tokens[-1]
        if isinstance(into, dict):
            into[last] = value
        elif isinstance(into, list) and last == "-":
            into.append(value)
        elif isinstance(into, list) and _INDEX.match(last) and int(last) <= len(into):
            into.insert(int(last), value)
        else:
            raise CaseError("cannot add at /%s" % "/".join(tokens))

    def remove(self, tokens):
        if not tokens:
            raise CaseError("cannot remove the whole manifest")
        self.get(tokens)
        into, last = self.get(tokens[:-1]), tokens[-1]
        return into.pop(int(last) if isinstance(into, list) else last)

    def manifest_step(self, step):
        if self.text is not None:
            raise CaseError("the %s step comes after a text step" % step["op"])
        self.dirty = True

    def step_add(self, step):
        self.manifest_step(step)
        self.add(self.tokens(step["path"]), copying.deepcopy(step["value"]))

    def step_remove(self, step):
        self.manifest_step(step)
        self.remove(self.tokens(step["path"]))

    def step_replace(self, step):
        self.manifest_step(step)
        tokens = self.tokens(step["path"])
        self.get(tokens)
        value = copying.deepcopy(step["value"])
        if not tokens:
            self._doc = value
            return
        into, last = self.get(tokens[:-1]), tokens[-1]
        into[int(last) if isinstance(into, list) else last] = value

    def step_move(self, step):
        self.manifest_step(step)
        source, target = self.tokens(step["from"]), self.tokens(step["path"])
        self.add(target, self.remove(source))

    def step_copy(self, step):
        self.manifest_step(step)
        source, target = self.tokens(step["from"]), self.tokens(step["path"])
        value = copying.deepcopy(self.get(source))
        if "apply" in step:
            if not isinstance(value, str):
                raise CaseError("%s is not a string" % step["from"])
            value = transform(value, step["apply"])
        self.add(target, value)

    def step_insert_entry(self, step):
        self.manifest_step(step)
        entry = copying.deepcopy(self.get(self.tokens(step["like"]))) if "like" in step else {}
        if not isinstance(entry, dict):
            raise CaseError("%s is not an entry" % step["like"])
        for name, value in step["set"].items():
            entry[name] = self.string(value) if isinstance(value, dict) else value
        entries = self.get(["entries"])
        if not isinstance(entries, list) or not isinstance(entry.get("id"), str):
            raise CaseError("insert-entry needs an entries array and an id")
        later = (
            i
            for i, e in enumerate(entries)
            if isinstance(e, dict) and e.get("id", "") > entry["id"]
        )
        at = next(later, len(entries))
        entries.insert(at, entry)

    def step_text(self, step):
        if self.text is None:
            self.text = self.dump()
        self.text = transform(self.text, step["apply"])

    def string(self, expr):
        if isinstance(expr, str):
            return expr
        value = self.get(self.tokens(expr["from"]))
        if not isinstance(value, str):
            raise CaseError("%s is not a string" % expr["from"])
        return transform(value, expr.get("apply", []))

    # Files under spec/v1.0/fixtures.

    def path(self, expr):
        return os.path.join(self.fixtures, *self.string(expr).split("/"))

    def write(self, full, text):
        if os.path.lexists(full):
            raise CaseError("%s exists already" % os.path.relpath(full, self.fixtures))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as handle:
            handle.write(text)

    def step_write(self, step):
        self.write(self.path(step["file"]), step["text"])

    def step_copy_file(self, step):
        with open(self.path(step["source"]), encoding="utf-8") as handle:
            text = handle.read()
        self.write(self.path(step["file"]), text)

    def step_delete(self, step):
        os.remove(self.path(step["file"]))

    def step_symlink(self, step):
        full = self.path(step["file"])
        if os.path.lexists(full):
            raise CaseError("%s exists already" % self.string(step["file"]))
        os.symlink(step["target"], full)

    # spec/v1.0/spec-map.md.

    def map_lines(self):
        with open(self.map_path, encoding="utf-8") as handle:
            return handle.read().split("\n")

    def write_map(self, lines):
        with open(self.map_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines))

    def step_map_group(self, step):
        """Change the first row of the Fixture groups table that the step
        selects: give it set_status, or drop it."""
        group = self.string(step["group"]) if "group" in step else None
        lines, section = self.map_lines(), None
        for i, line in enumerate(lines):
            if line.startswith("## "):
                section = line[3:].strip()
                continue
            row = _GROUP_ROW.match(line) if section == "Fixture groups" else None
            if not row:
                continue
            name, status = row.group(1).strip("` "), row.group(2)
            if group not in (None, name) or step.get("status", status) != status:
                continue
            if step.get("drop"):
                del lines[i]
            else:
                lines[i] = line[: -len(status + " |")] + step["set_status"] + " |"
            return self.write_map(lines)
        raise CaseError("no row of the Fixture groups table fits the mutation")

    def step_map_line(self, step):
        lines = self.map_lines()
        if lines.count(step["line"]) != 1:
            raise CaseError("spec-map.md has no single line %s" % json.dumps(step["line"]))
        lines[lines.index(step["line"])] = step["text"]
        self.write_map(lines)
