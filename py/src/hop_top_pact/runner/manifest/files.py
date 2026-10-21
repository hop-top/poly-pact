"""Completeness: the manifest against the fixture directory. Mirrors
go/runner/manifest/files.go."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator

from hop_top_pact.runner.manifest.entry import FILE_NAME, SCHEMA_FILE_NAME, Manifest
from hop_top_pact.runner.manifest.problem import (
    RULE_EXPECTED_MISSING,
    RULE_EXTENSION,
    RULE_PATH_MISSING,
    RULE_UNCOVERED,
    Problems,
    _Collector,
)
from hop_top_pact.runner.manifest.rules import (
    NATIVE_EXTENSIONS,
    NEUTRAL_EXTENSIONS,
    PATH_RE,
    TESTDATA_DIR,
    Kind,
    base_name,
    ext,
    go_quote,
    matches,
    within,
)


def _exempt(rel: str) -> bool:
    """Whether the fixture file rel needs no covering entry: manifest.json and
    manifest.schema.json at the top, files under testdata/ at the top, files named
    README.md, and files whose name starts with LICENSE."""
    if rel in (FILE_NAME, SCHEMA_FILE_NAME) or within(rel, TESTDATA_DIR):
        return True
    name = base_name(rel)
    return name == "README.md" or name.startswith("LICENSE")


def _real(p: str) -> str:
    """p with every symbolic link resolved; OSError when a component is missing."""
    return os.path.realpath(p, strict=True)


def _locate(root: str, real_root: str, rel: str) -> str:
    """Why rel is not an existing path inside root, or "" when it is. real_root is root
    with symbolic links resolved."""
    full = os.path.join(root, *rel.split("/"))
    try:
        os.lstat(full)
    except OSError:
        return "does not exist"
    try:
        real = _real(full)
    except FileNotFoundError:
        return "is a dangling symbolic link"
    except OSError as err:
        return f"cannot be resolved: {err}"
    if not real.startswith(real_root.rstrip(os.sep) + os.sep):
        return "resolves outside the fixture directory"
    return ""


def _walk(top: str, rel: str = "") -> Iterator[str]:
    """The slash-separated paths of every non-directory under top, in Go's WalkDir order
    (lexical, depth first). Symbolic links are not followed: a link to a directory is
    listed as a file."""
    with os.scandir(top) as it:
        names = sorted(it, key=lambda d: d.name)
    for d in names:
        r = rel + "/" + d.name if rel else d.name
        if d.is_dir(follow_symlinks=False):
            yield from _walk(d.path, r)
        else:
            yield r


def completeness(root: str | os.PathLike[str], m: Manifest) -> Problems:
    """Check m against the fixture directory root.

    - every entry path exists, is not a dangling symbolic link and resolves inside root
      (RULE_PATH_MISSING);
    - every expected file does too, and is a file (RULE_EXPECTED_MISSING);
    - every file under root, except manifest.json, manifest.schema.json, README.md files,
      files whose name starts with LICENSE and the files under testdata/, is inside an
      entry's path, is an entry's expected file, or is under expected/<id>/ for the id of
      an entry (RULE_UNCOVERED; fixture format v2);
    - every file has a neutral extension, or a native-asset extension inside the path of
      an adapter-asset entry, written in lower case (RULE_EXTENSION).

    A root that is itself a symbolic link is followed once, as a POSIX utility follows a
    link named on its command line (find -H). Symbolic links inside the tree are not
    followed. Entries whose path or expected file breaks a field rule are skipped here;
    validate reports them.
    """
    ps = _Collector()
    root_s = os.fspath(root)
    try:
        real_root = _real(root_s)
    except OSError as err:
        ps.add(RULE_PATH_MISSING, ".", f"fixture directory: {err}", err)
        return ps.done()

    paths: list[str] = []
    assets: list[str] = []
    expected: set[str] = set()
    for i, e in enumerate(m.entries):
        where = e.id or f"entries[{i}]"
        # Format v2: every file under expected/<id>/ belongs to the entry.
        if e.id and matches(PATH_RE, d := "expected/" + e.id):
            paths.append(d)
        if matches(PATH_RE, e.path):
            if msg := _locate(root_s, real_root, e.path):
                ps.add(RULE_PATH_MISSING, where, f"path {go_quote(e.path)} {msg}")
            paths.append(e.path)
            if e.kind == Kind.ADAPTER_ASSET:
                assets.append(e.path)
        if e.expected is not None and matches(PATH_RE, e.expected):
            x = e.expected
            msg = _locate(root_s, real_root, x)
            if not msg:
                try:
                    if not stat.S_ISREG(os.stat(os.path.join(root_s, *x.split("/"))).st_mode):
                        msg = "is not a file"
                except OSError:
                    pass
            if msg:
                ps.add(RULE_EXPECTED_MISSING, where, f"expected {go_quote(x)} {msg}")
            expected.add(x)

    try:
        _check_files(ps, _walk(real_root), paths, assets, expected)
    except OSError as err:
        ps.add(RULE_PATH_MISSING, ".", f"walk: {err}", err)
    return ps.done()


def _ancestors(rel: str) -> list[str]:
    """rel and each of its parent directories."""
    parts = rel.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]


def _check_files(
    ps: _Collector, files: Iterator[str], paths: list[str], assets: list[str], expected: set[str]
) -> None:
    neutral = " ".join(NEUTRAL_EXTENSIONS)
    native = " ".join(NATIVE_EXTENSIONS)
    covered = set(paths)
    asset_paths = set(assets)
    for rel in files:
        # within(rel, p) holds exactly when p is rel or one of its parent directories.
        ancestors = _ancestors(rel)
        in_asset = not asset_paths.isdisjoint(ancestors)
        x = ext(rel)
        if x in NEUTRAL_EXTENSIONS or (x in NATIVE_EXTENSIONS and in_asset):
            pass
        elif x in NATIVE_EXTENSIONS:
            ps.add(
                RULE_EXTENSION,
                rel,
                f"extension {x} is allowed only inside the path of an"
                f" {Kind.ADAPTER_ASSET.value} entry",
            )
        else:
            ps.add(
                RULE_EXTENSION,
                rel,
                f"extension {go_quote(x)} is not language-neutral; allowed: {neutral}, and {native}"
                f" inside an {Kind.ADAPTER_ASSET.value} entry",
            )
        if _exempt(rel) or rel in expected or not covered.isdisjoint(ancestors):
            continue
        ps.add(
            RULE_UNCOVERED,
            rel,
            "no manifest entry covers this file: add one, or put it inside an entry's path",
        )
