#!/usr/bin/env python3
"""Check the publish map in .github/workflows/publish.yml against the
release-please config.

publish.yml routes a <component>/v<version> tag through its `ecosystems`
map; release-please decides which components exist and which directory each
one releases. The two must agree, or a tag publishes the wrong tree or
nothing at all. Rules:

  keys      ecosystems keys equal the release-please components minus the
            root component, when there is one (the umbrella tag has no
            publish target)
  dir       every dir is a release-please package path whose component is
            the entry's key, or the spec root <root> of the entry's spec
            package <root>/vX.Y (the spec mirror ships the whole spec tree,
            every version directory at its root)
  spec      an entry whose dir is a spec root has ecosystem none
  fields    every entry has a non-empty ecosystem (one the reusable
            workflow knows) and a non-empty mirror
  mirror    no two entries name the same mirror (the mirror push replaces
            the mirror's main with one directory, so a shared mirror keeps
            only the payload of the last tag)
  prefix    no entry has target-prefix: every payload lands at its mirror's
            root
  php       every php entry has a mirror (Packagist reads the mirror)
  tags      the tag filter includes '*/v*', and excludes '<root>/v*' when
            the config has a root package

Stdlib only, run with `python3 -I`. publish.yml is read with a small
line-based reader for the two constructs this check needs (the `on.push.tags`
sequence and the `ecosystems: |` block); anything it does not understand in
those two places is an error, never a silent pass.

Exit status: 0 when every rule holds, 1 when a rule fails, 2 when an input
cannot be read or parsed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"
CONFIG = ROOT / ".github" / "release-please-config.json"

# The ecosystems publish-on-tag.yml@v0 accepts (its `ecosystems` input).
ECOSYSTEMS = {"ts", "py", "rs", "php", "go", "none"}
# A spec package path: <root>/vX.Y (the shape the shared spec workflows use).
SPEC_PACKAGE = re.compile(r"^(?P<root>[A-Za-z0-9_.-]+)/v\d+\.\d+$")


class ParseError(Exception):
    pass


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def strip_comment(value: str) -> str:
    """Drop a trailing ` # comment` outside quotes."""
    quote = ""
    for i, ch in enumerate(value):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or value[i - 1] in " \t"):
            return value[:i].rstrip()
    return value.rstrip()


def scalar(raw: str, where: str) -> str:
    value = strip_comment(raw).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    if value[:1] in ("'", '"', "{", "[", "|", ">", "&", "*", "!"):
        raise ParseError(f"{where}: unsupported YAML value {value!r}")
    return value


def section(lines: list[str], start: int) -> list[tuple[int, str]]:
    """Lines nested under the key at lines[start], with their line numbers."""
    base = indent_of(lines[start])
    out = []
    for n in range(start + 1, len(lines)):
        line = lines[n]
        if line.strip() and indent_of(line) <= base:
            break
        out.append((n + 1, line))
    return out


def find_key(lines: list[tuple[int, str]], key: str, indent: int | None = None):
    pattern = re.compile(r"^( *)" + re.escape(key) + r":(.*)$")
    hits = []
    for n, line in lines:
        m = pattern.match(line)
        if m and (indent is None or len(m.group(1)) == indent):
            hits.append((n, line, m.group(2)))
    return hits


def parse_tags(text: str) -> list[str]:
    lines = text.splitlines()
    numbered = list(enumerate(lines, 1))
    on = [(n, l) for n, l in numbered if re.match(r"^(on|\"on\"|'on'):\s*$", l)]
    if len(on) != 1:
        raise ParseError("publish.yml: expected one top-level 'on:' block mapping")
    on_body = section(lines, on[0][0] - 1)
    push = find_key(on_body, "push")
    if len(push) != 1:
        raise ParseError("publish.yml: expected one 'push:' under 'on:'")
    push_body = section(lines, push[0][0] - 1)
    tags = find_key(push_body, "tags")
    if len(tags) != 1:
        raise ParseError("publish.yml: expected one 'tags:' under 'on.push'")
    n, line, rest = tags[0]
    rest = strip_comment(rest).strip()
    if rest.startswith("["):
        if not rest.endswith("]"):
            raise ParseError(f"publish.yml:{n}: tags flow sequence must fit on one line")
        items = [i.strip() for i in rest[1:-1].split(",") if i.strip()]
        return [scalar(i, f"publish.yml:{n}") for i in items]
    if rest:
        raise ParseError(f"publish.yml:{n}: unsupported tags value {rest!r}")
    out = []
    for m, item in section(lines, n - 1):
        body = item.strip()
        if not body or body.startswith("#"):
            continue
        if not body.startswith("- "):
            raise ParseError(f"publish.yml:{m}: expected a '- ' sequence item")
        out.append(scalar(body[2:], f"publish.yml:{m}"))
    return out


def parse_ecosystems(text: str) -> dict[str, dict[str, str]]:
    lines = text.splitlines()
    starts = [
        n for n, l in enumerate(lines) if re.match(r"^ +ecosystems:\s*\|[-+]?\s*$", l)
    ]
    if len(starts) != 1:
        raise ParseError("publish.yml: expected one 'ecosystems: |' block scalar")
    body = section(lines, starts[0])
    content = [(n, l) for n, l in body if l.strip()]
    if not content:
        raise ParseError("publish.yml: the ecosystems block is empty")
    base = indent_of(content[0][1])
    entries: dict[str, dict[str, str]] = {}
    current = None
    field_indent = None
    for n, raw in content:
        where = f"publish.yml:{n}"
        if raw.strip().startswith("#"):
            continue
        if "\t" in raw[: indent_of(raw) + 1]:
            raise ParseError(f"{where}: tab in indentation")
        depth = indent_of(raw)
        line = raw.strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*):(.*)$", line)
        if not m:
            raise ParseError(f"{where}: expected 'key: value', got {line!r}")
        key, rest = m.group(1), m.group(2)
        if depth == base:
            if strip_comment(rest).strip():
                raise ParseError(f"{where}: component {key!r} must be a block mapping")
            if key in entries:
                raise ParseError(f"{where}: duplicate component {key!r}")
            entries[key] = {}
            current, field_indent = key, None
            continue
        if current is None or depth < base:
            raise ParseError(f"{where}: field outside a component")
        if field_indent is None:
            field_indent = depth
        if depth != field_indent:
            raise ParseError(f"{where}: unexpected indentation (nested values are not supported)")
        if key in entries[current]:
            raise ParseError(f"{where}: duplicate field {key!r} in {current!r}")
        entries[current][key] = scalar(rest, where)
    return entries


def load(workflow: Path, config: Path):
    try:
        text = workflow.read_text(encoding="utf-8")
    except OSError as e:
        raise ParseError(f"{workflow}: {e.strerror}") from None
    try:
        cfg = json.loads(config.read_text(encoding="utf-8"))
    except OSError as e:
        raise ParseError(f"{config}: {e.strerror}") from None
    except json.JSONDecodeError as e:
        raise ParseError(f"{config}: {e}") from None
    packages = cfg.get("packages")
    if not isinstance(packages, dict) or not packages:
        raise ParseError(f"{config}: no 'packages' map")
    components = {}
    for path, pkg in packages.items():
        comp = pkg.get("component") if isinstance(pkg, dict) else None
        if not isinstance(comp, str) or not comp:
            raise ParseError(f"{config}: package {path!r} has no component")
        components[path] = comp
    return parse_tags(text), parse_ecosystems(text), components


def spec_roots(components) -> dict[str, set[str]]:
    """Spec root -> the components of its <root>/vX.Y packages."""
    roots: dict[str, set[str]] = {}
    for path, comp in components.items():
        m = SPEC_PACKAGE.match(path)
        if m:
            roots.setdefault(m.group("root"), set()).add(comp)
    return roots


def shared_mirrors(entries) -> list[str]:
    """One error per mirror that more than one entry names."""
    mirrors: dict[str, list[str]] = {}
    for key, entry in entries.items():
        if entry.get("mirror", ""):
            mirrors.setdefault(entry["mirror"], []).append(key)
    errors = []
    for mirror, keys in sorted(mirrors.items()):
        if len(keys) > 1:
            errors.append(f"mirror: {mirror} is the mirror of more than one entry: {', '.join(sorted(keys))}")
    return errors


def check(tags, entries, components) -> list[str]:
    errors = []
    root = components.get(".")
    expected = set(components.values()) - {root}
    roots = spec_roots(components)

    missing = sorted(expected - entries.keys())
    extra = sorted(entries.keys() - expected)
    if missing:
        errors.append(f"keys: release-please components without an entry: {', '.join(missing)}")
    if extra:
        what = f" (or are the root {root!r})" if root else ""
        errors.append(f"keys: entries that are not release-please components{what}: {', '.join(extra)}")
    errors += shared_mirrors(entries)

    for key, entry in sorted(entries.items()):
        d = entry.get("dir", "")
        eco = entry.get("ecosystem", "")
        if not d:
            errors.append(f"dir: {key}: no dir")
        elif d in roots and d not in components:
            if key not in roots[d]:
                errors.append(f"dir: {key}: {d!r} is the spec root of {', '.join(sorted(roots[d]))}, not of {key!r}")
            elif eco != "none":
                errors.append(f"spec: {key}: dir {d!r} is a spec root, so its ecosystem is 'none' (got {eco!r})")
        elif d == "." or d not in components:
            errors.append(f"dir: {key}: {d!r} is not a release-please package path")
        elif components[d] != key:
            errors.append(f"dir: {key}: {d!r} is the package of component {components[d]!r}")
        if not eco:
            errors.append(f"fields: {key}: no ecosystem (use 'none' for a payload without a registry)")
        elif eco not in ECOSYSTEMS:
            errors.append(f"fields: {key}: ecosystem {eco!r} is not one of {', '.join(sorted(ECOSYSTEMS))}")
        if not entry.get("mirror", ""):
            errors.append(f"fields: {key}: no mirror")
            if eco == "php":
                errors.append(f"php: {key}: a php entry needs a mirror (Packagist reads the mirror)")
        if "target-prefix" in entry:
            errors.append(f"prefix: {key}: no entry has target-prefix (every payload lands at its mirror's root)")

    if "*/v*" not in tags:
        errors.append(f"tags: the tag filter does not include '*/v*' (got {tags})")
    if root and f"!{root}/v*" not in tags:
        errors.append(f"tags: the tag filter does not exclude the root component ('!{root}/v*')")
    return errors


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--workflow", type=Path, default=WORKFLOW)
    ap.add_argument("--config", type=Path, default=CONFIG)
    args = ap.parse_args(argv)
    try:
        tags, entries, components = load(args.workflow, args.config)
    except ParseError as e:
        print(f"check-publish-map: {e}", file=sys.stderr)
        return 2
    errors = check(tags, entries, components)
    for e in errors:
        print(f"check-publish-map: {e}", file=sys.stderr)
    if errors:
        return 1
    root = components.get(".")
    note = f"root {root!r} excluded" if root else "no root package"
    print(f"check-publish-map: ok ({len(entries)} ecosystems entries, {note})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
