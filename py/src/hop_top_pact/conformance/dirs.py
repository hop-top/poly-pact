"""The signed directories of the fixture directory and sequence.json. Mirrors
go/runner/evalcase/dirs.go."""

from __future__ import annotations

import os
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from hop_top_pact.conformance.errors import CaseError, q, wrap
from hop_top_pact.conformance.signing import PATH_RE, Signing, parse_signing
from hop_top_pact.core import strictjson
from hop_top_pact.runner import manifest

__all__ = ["Dir", "dirs"]

# The manifest kinds whose case directories are signed.
_SIGNED_KINDS: Final = (manifest.Kind.EVALUATE, manifest.Kind.OUTCOMES, manifest.Kind.LEARNING)


@dataclass(frozen=True, slots=True)
class Dir:
    """One directory the generator signs: a case directory, or an exchange directory of
    a multi-exchange case."""

    entry: str
    """The manifest id."""
    id: str
    """Names the directory: the entry id or, for an exchange, the entry id and the
    exchange path."""
    path: str
    """The directory, slash-separated, relative to the fixture directory."""
    signing: Signing = field(default_factory=Signing)
    """The directory's signing.json."""


def load_manifest(fixtures: Path) -> manifest.Manifest:
    try:
        return manifest.load(fixtures)
    except manifest.Problems as e:
        raise wrap(manifest.FILE_NAME, e) from e


def dirs(fixtures: str | os.PathLike[str]) -> list[Dir]:
    """Every directory with a signing.json, in manifest order: the case directory of
    each entry of kind evaluate, outcomes or learning, or each exchange directory its
    sequence.json names. A directory that holds a signed file (a .jws file) but no
    signing.json, or a signed file its signing.json does not name, is an error. An
    entry whose path is not a directory is left to the manifest check. Raises
    CaseError."""
    root = Path(fixtures)
    out: list[Dir] = []
    for e in load_manifest(root).entries:
        if e.kind in _SIGNED_KINDS:
            out.extend(_entry_dirs(root, e))
    return out


def at(fixtures: Path, rel: str) -> Path:
    """The slash-separated path rel under fixtures."""
    return fixtures.joinpath(*rel.split("/"))


def _entry_dirs(fixtures: Path, e: manifest.Entry) -> list[Dir]:
    dir = at(fixtures, e.path)
    if not dir.is_dir():
        return []  # not a case directory: the manifest check reports it
    try:
        seq = read_sequence(dir)
    except CaseError as err:
        raise wrap(e.id, err) from err
    if seq is None:
        d = load_dir(fixtures, e.id, e.id, e.path)
        return [] if d is None else [d]
    no_signed_files(fixtures, e.path, seq.exchanges)
    out: list[Dir] = []
    for x in seq.exchanges:
        d = load_dir(fixtures, e.id, e.id + "/" + x, e.path + "/" + x)
        if d is not None:
            out.append(d)
    return out


@dataclass(frozen=True, slots=True)
class _Sequence:
    """sequence.json of a multi-exchange case."""

    exchanges: tuple[str, ...] = ()
    subject: str = ""


def read_sequence(dir: Path) -> _Sequence | None:
    """sequence.json of the case directory dir; None when there is none."""
    try:
        data = (dir / "sequence.json").read_bytes()
    except FileNotFoundError:
        return None
    except OSError as e:
        raise wrap("sequence.json", e) from e
    try:
        seq = strictjson.decode(data, _Sequence)
    except strictjson.StrictJSONError as e:
        raise wrap("sequence.json", e) from e
    if not seq.exchanges:
        raise CaseError("sequence.json: exchanges is empty")
    for x in seq.exchanges:
        if not PATH_RE.fullmatch(x):
            raise CaseError(f"sequence.json: exchange {q(x)} is not a relative path")
    return seq


def load_dir(fixtures: Path, entry: str, id: str, rel: str, skip: Sequence[str] = ()) -> Dir | None:
    """The directory rel with its signing.json; None when there is none and the
    directory holds no signed file outside skip."""
    try:
        data = (at(fixtures, rel) / "signing.json").read_bytes()
    except FileNotFoundError:
        no_signed_files(fixtures, rel, skip)
        return None
    except OSError as e:
        raise wrap(id + "/signing.json", e) from e
    try:
        signing = parse_signing(data)
    except (CaseError, strictjson.StrictJSONError) as e:
        raise wrap(id + "/signing.json", e) from e
    named = {a.signed for a in signing.artifacts} | {p.signed for p in signing.presentations}
    for f in signed_files_under(fixtures, rel, skip):
        if f not in named:
            raise CaseError(f"{id}: signed file {f} is named by no entry of signing.json")
    return Dir(entry=entry, id=id, path=rel, signing=signing)


def no_signed_files(fixtures: Path, rel: str, skip: Sequence[str] = ()) -> None:
    """Raise CaseError when the directory rel holds a signed file outside the
    subdirectories skip, since nothing names it."""
    files = signed_files_under(fixtures, rel, skip)
    if files:
        raise CaseError(f"{rel}: holds signed files ({', '.join(files)}) but no signing.json")


def signed_files_under(fixtures: Path, rel: str, skip: Sequence[str] = ()) -> list[str]:
    """The .jws files under the directory rel, as paths relative to it, in lexical walk
    order, leaving out the subdirectories skip."""
    return [r for r in walk_files(at(fixtures, rel), skip) if r.endswith(".jws")]


def walk_files(root: Path, skip: Sequence[str] = ()) -> Iterator[str]:
    """The files under root, slash-separated and relative to it, in the order of Go's
    filepath.WalkDir (entries by name, depth first, symbolic links not followed),
    leaving out the subdirectories skip."""

    def visit(dir: Path, prefix: str) -> Iterator[str]:
        try:
            entries = sorted(os.scandir(dir), key=lambda d: d.name)
        except OSError as e:
            raise wrap(str(dir), e) from e
        for d in entries:
            r = prefix + d.name
            if d.is_dir(follow_symlinks=False):
                if r not in skip:
                    yield from visit(Path(d.path), r + "/")
            else:
                yield r

    yield from visit(root, "")
