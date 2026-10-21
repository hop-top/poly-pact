"""Evaluation cases: a manifest entry of kind evaluate read with every file of its
directory, or of each exchange directory of a multi-exchange case. Mirrors
go/runner/evalcase/case.go."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import ClassVar, Final, TypeVar

from hop_top_pact.conformance._decode import (
    check_algorithms,
    check_authenticated,
    check_sources,
    decode_config,
    decode_native_context,
)
from hop_top_pact.conformance.dirs import (
    at,
    load_dir,
    load_manifest,
    no_signed_files,
    read_sequence,
    walk_files,
)
from hop_top_pact.conformance.errors import CaseError, q, wrap
from hop_top_pact.conformance.keys import Key, load_keys
from hop_top_pact.conformance.signing import Signing
from hop_top_pact.conformance.types import (
    Availability,
    Config,
    Decision,
    Evaluation,
    HandoffAttempt,
    NativeContext,
    Submission,
)
from hop_top_pact.conformance.verify import Signed, verify_dir
from hop_top_pact.core import strictjson
from hop_top_pact.core.types import Member
from hop_top_pact.errors import PactError
from hop_top_pact.runner import manifest

__all__ = ["Case", "Exchange", "load", "read"]

T = TypeVar("T")

# The files of a case directory that are not decoded objects.
_CONTROL_FILES: Final = (
    "config.json",
    "native_context.json",
    "signing.json",
    "exchange.json",
    "sequence.json",
)
_DEFAULT_OPERATION: Final = "actual_operation.json"
_DEFAULT_TRANSPORT: Final = "https"
_DEFAULT_PRESENTATION: Final = "signed/presentation.jws"


@dataclass(frozen=True, slots=True)
class Exchange:
    """One admission exchange: a case directory, or an exchange directory of a
    multi-exchange case."""

    name: str
    """The exchange path sequence.json names, such as "exchanges/1", or "" for a case
    of one exchange."""
    path: str
    """The directory relative to the fixture directory."""
    config: Config
    """config.json."""
    native_context: NativeContext
    """native_context.json."""
    signing: Signing
    """signing.json; empty when the directory has none."""
    submissions: tuple[Submission, ...]
    """exchange.json with its defaults: without the file, one submission of
    signed/presentation.jws."""
    availability: Availability
    """Without exchange.json, everything available."""
    handoff: tuple[HandoffAttempt, ...]
    """Without exchange.json, no handoff."""
    decoded: Mapping[str, bytes]
    """The bytes of every other JSON file of the directory, by path relative to it: the
    decoded artifacts, the profile, intent and operations. They are kept as bytes since
    a case may hold an object that a validator must reject."""
    signed: tuple[Signed, ...]
    """The committed signed files, verified (see verify); empty after read."""
    expected: Decision
    """The expected file expected_path."""
    expected_path: str
    """Relative to the fixture directory."""


@dataclass(frozen=True, slots=True)
class Case:
    """An evaluation case: a manifest entry of kind evaluate, read with every file of
    its directory, or of each exchange directory of a multi-exchange case."""

    id: str
    """The manifest id."""
    path: str
    """The case directory, relative to the fixture directory."""
    exchanges: tuple[Exchange, ...]
    """The case's one exchange, or the exchanges of its sequence.json in order."""
    subject: int = 0
    """The index in exchanges of the exchange whose expected file is the manifest
    entry's expected file."""


def load(fixtures: str | os.PathLike[str], id: str) -> Case:
    """Read the evaluation case id of the fixture directory fixtures (the directory of
    manifest.json) and verify its signed files.

    Raises CaseError when the manifest does not list id as an entry of kind evaluate,
    when a file is missing or is not strict JSON of its format, when the expected file
    does not have one response per submission and one entry per handoff attempt, or
    when a signed file is stale (verify). A signed file that fails its trust records
    is not an error: its Signed.trust says why.
    """
    return _load(Path(fixtures), id, True)


def read(fixtures: str | os.PathLike[str], id: str) -> Case:
    """Read the evaluation case id as load does, without verifying the signed files.

    It loads no test key, so a fixture directory without the private values of
    KEYS_FILE reads, and a stale signed file is not an error; Exchange.signed is
    empty. A consumer that judges an implementation against the case, not the case
    itself, reads with read; the generator and its checks use load.
    """
    return _load(Path(fixtures), id, False)


def _load(fixtures: Path, id: str, check: bool) -> Case:
    e = load_manifest(fixtures).lookup(id)
    if e is None:
        raise CaseError(f"{id}: no manifest entry")
    if e.kind != manifest.Kind.EVALUATE:
        raise CaseError(f"{id}: manifest kind {e.kind}, not {manifest.Kind.EVALUATE}")
    if e.expected is None:
        raise CaseError(f"{id}: the manifest entry names no expected file")
    keys = load_keys(fixtures) if check else None
    if not at(fixtures, e.path).is_dir():
        raise CaseError(f"{id}: path {e.path} is not a case directory")
    try:
        seq = read_sequence(at(fixtures, e.path))
    except CaseError as err:
        raise wrap(id, err) from err
    if seq is None:
        x = _load_exchange(fixtures, keys, e.id, "", e.path, e.expected)
        return Case(id=id, path=e.path, exchanges=(x,))
    no_signed_files(fixtures, e.path, seq.exchanges)
    if seq.subject not in seq.exchanges:
        raise CaseError(f"{id}/sequence.json: subject {q(seq.subject)} is not one of its exchanges")
    exchanges: list[Exchange] = []
    for name in seq.exchanges:
        exp = f"expected/{id}/{name}/decision.json"
        if name == seq.subject and exp != e.expected:
            raise CaseError(
                f"{id}: manifest expected {e.expected} is not {exp},"
                " the expected file of the subject exchange"
            )
        exchanges.append(_load_exchange(fixtures, keys, e.id, name, e.path + "/" + name, exp))
    return Case(
        id=id, path=e.path, exchanges=tuple(exchanges), subject=seq.exchanges.index(seq.subject)
    )


def _read(where: str, path: Path, decode: Callable[[bytes], T]) -> T:
    try:
        return decode(path.read_bytes())
    except (PactError, OSError) as e:
        raise wrap(where, e) from e


def _load_exchange(
    fixtures: Path,
    keys: dict[str, Key] | None,
    entry: str,
    name: str,
    rel: str,
    expected: str,
) -> Exchange:
    """The exchange directory rel of the entry."""
    id = entry + "/" + name if name else entry
    dir = at(fixtures, rel)
    if not dir.is_dir():
        raise CaseError(f"{id}: not a directory of the case")
    config = _read(id + "/config.json", dir / "config.json", decode_config)
    nc = _read(id + "/native_context.json", dir / "native_context.json", decode_native_context)
    _check(id + "/config.json", lambda: check_algorithms(config.gateway))
    _check(id + "/native_context.json", lambda: check_authenticated(nc.authenticated))
    _check(id + "/config.json", lambda: check_sources(config, nc))
    d = load_dir(fixtures, entry, id, rel)
    signing = d.signing if d is not None else Signing()
    signed: tuple[Signed, ...] = ()
    if d is not None and keys is not None:
        jkt = nc.authenticated.holder_jkt if nc.authenticated is not None else None
        signed = tuple(verify_dir(fixtures, d, keys, config.trust, jkt or ""))
    try:
        submissions, availability, handoff = _read_exchange(dir, config, signing)
    except (PactError, OSError) as e:
        raise wrap(id + "/exchange.json", e) from e
    decoded = _read_decoded(id, dir)
    decision = _read(
        f"{id}: expected file {expected}",
        at(fixtures, expected),
        lambda b: strictjson.decode(b, Decision),
    )
    if (n := len(decision.expected_responses())) != len(submissions):
        raise CaseError(
            f"{id}: expected file {expected}: {n} expected responses"
            f" for {len(submissions)} submissions"
        )
    if (n := len(decision.handoff)) != len(handoff):
        raise CaseError(
            f"{id}: expected file {expected}: {n} expected handoff results"
            f" for {len(handoff)} handoff attempts"
        )
    return Exchange(
        name=name,
        path=rel,
        config=config,
        native_context=nc,
        signing=signing,
        submissions=submissions,
        availability=availability,
        handoff=handoff,
        decoded=decoded,
        signed=signed,
        expected=decision,
        expected_path=expected,
    )


def _check(where: str, f: Callable[[], None]) -> None:
    try:
        f()
    except CaseError as e:
        raise wrap(where, e) from e


@dataclass(frozen=True, slots=True)
class _EvaluationFile:
    started_at: int | None = None
    native_reads_at: int | None = None
    cancelled_at: int | None = None


@dataclass(frozen=True, slots=True)
class _PresentationFile:
    signed: str = ""
    jti: str = ""
    replica: str | None = None
    concurrent: bool | None = None
    evict_replay_records: bool | None = None
    actual_operation: str | None = None
    transport: str | None = None
    evaluation: _EvaluationFile | None = None


@dataclass(frozen=True, slots=True)
class _AvailabilityFile:
    sources: tuple[str, ...] | None = None
    replay_store: str | None = None
    enrollment_source: str | None = None

    # sources tells absent from empty; null is refused, as for a Go slice.
    _MEMBERS: ClassVar[Mapping[str, Member]] = MappingProxyType(
        {"sources": Member("sources", "array", False, False, None)}
    )


@dataclass(frozen=True, slots=True)
class _HandoffFile:
    presentation: str | None = None
    actual_operation: str | None = None
    at: int | None = None


@dataclass(frozen=True, slots=True)
class _ExchangeFile:
    presentations: tuple[_PresentationFile, ...] | None = None
    availability: _AvailabilityFile | None = None
    handoff: tuple[_HandoffFile, ...] = field(default=())


def _read_exchange(
    dir: Path, config: Config, signing: Signing
) -> tuple[tuple[Submission, ...], Availability, tuple[HandoffAttempt, ...]]:
    """exchange.json, when there is one, with the defaults of README section
    exchange.json applied."""
    try:
        f = strictjson.decode((dir / "exchange.json").read_bytes(), _ExchangeFile)
    except FileNotFoundError:
        f = _ExchangeFile()
    submissions: list[Submission] = []
    if f.presentations is None:
        jti = next((p.jti for p in signing.presentations if p.signed == _DEFAULT_PRESENTATION), "")
        submissions.append(
            Submission(
                signed=_DEFAULT_PRESENTATION,
                jti=jti,
                replica="r1",
                actual_operation=_DEFAULT_OPERATION,
                transport=_DEFAULT_TRANSPORT,
                evaluation=Evaluation(started_at=config.now),
            )
        )
    elif not f.presentations:
        raise CaseError("presentations is empty")
    for i, p in enumerate(f.presentations or ()):
        if not p.signed or not p.jti:
            raise CaseError(f"presentations[{i}]: signed and jti are required")
        ev = Evaluation(started_at=config.now)
        if (e := p.evaluation) is not None:
            ev = Evaluation(
                started_at=config.now if e.started_at is None else e.started_at,
                native_reads_at=e.native_reads_at,
                cancelled_at=e.cancelled_at,
            )
        submissions.append(
            Submission(
                signed=p.signed,
                jti=p.jti,
                replica="r1" if p.replica is None else p.replica,
                concurrent=bool(p.concurrent),
                evict_replay_records=bool(p.evict_replay_records),
                actual_operation=_DEFAULT_OPERATION
                if p.actual_operation is None
                else p.actual_operation,
                transport=_DEFAULT_TRANSPORT if p.transport is None else p.transport,
                evaluation=ev,
            )
        )
        if (transport := submissions[-1].transport) not in ("https", "stdio-ipc"):
            raise CaseError(
                f"presentations[{i}]: transport {transport!r} is not https or stdio-ipc"
            )
    availability = Availability(sources=(), replay_store="available", enrollment_source="available")
    if (a := f.availability) is not None:
        availability = Availability(
            sources=() if a.sources is None else a.sources,
            replay_store="available" if a.replay_store is None else a.replay_store,
            enrollment_source="available" if a.enrollment_source is None else a.enrollment_source,
        )
        if availability.enrollment_source not in ("available", "unavailable"):
            raise CaseError(
                f"availability.enrollment_source {q(availability.enrollment_source)}"
                " is not available or unavailable"
            )
    handoff: list[HandoffAttempt] = []
    for i, h in enumerate(f.handoff):
        # The attempt's submission: the one its presentation jti names, by default the
        # first.
        s = submissions[0]
        if h.presentation is not None:
            named = next((s for s in submissions if s.jti == h.presentation), None)
            if named is None:
                raise CaseError(
                    f"handoff[{i}]: presentation {q(h.presentation)} is the jti of no submission"
                )
            s = named
        handoff.append(
            HandoffAttempt(
                presentation=s.jti,
                actual_operation=_DEFAULT_OPERATION
                if h.actual_operation is None
                else h.actual_operation,
                at=s.evaluation.started_at if h.at is None else h.at,
            )
        )
    return tuple(submissions), availability, tuple(handoff)


def _read_decoded(id: str, dir: Path) -> dict[str, bytes]:
    """Every JSON file under dir other than the control files at its top level."""
    out: dict[str, bytes] = {}
    for r in walk_files(dir):
        if not r.endswith(".json") or ("/" not in r and r in _CONTROL_FILES):
            continue
        try:
            out[r] = at(dir, r).read_bytes()
        except OSError as e:
            raise wrap(id, e) from e
    return out
