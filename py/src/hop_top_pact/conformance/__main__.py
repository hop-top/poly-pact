"""Evaluate skeleton: the ``tool evaluate {dir} {state}`` command of the conformance
runner's adapter contract (go/runner package documentation), for a validator not yet
written in Python.

It reads the case with the case loader (read: no private test key needed) and
prints, for each exchange in order, one line per submission and one per handoff
attempt: an RFC 9457 Problem (draft 13.4) with the code UNSUPPORTED_REQUIREMENT and
status 422. pactc therefore judges every admission case FAIL, line by line, and never
sees a crash.

Usage: ``python -m hop_top_pact.conformance evaluate DIR [STATE]``. Plain argv, no
command-line framework. DIR is the case directory, inside the fixture directory that
holds manifest.json; STATE, the scratch path of the runner, is accepted and unused.

With make, from the repository root::

    make conformance PACTC_ARGS='--fixture admission/ --evaluate-cmd \
"py/.venv/bin/python -m hop_top_pact.conformance evaluate {dir} {state}"'

Exit status: 0 after printing the lines; 2 on a usage error or a directory that is
not an evaluate case, with the reason on standard error and nothing on standard
output.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from hop_top_pact.conformance.case import read
from hop_top_pact.conformance.dirs import load_manifest
from hop_top_pact.conformance.errors import CaseError, message
from hop_top_pact.errors import PactError
from hop_top_pact.runner import manifest

EXIT_USAGE: Final = 2
USAGE: Final = "usage: python -m hop_top_pact.conformance evaluate DIR [STATE]\n"


def problem(n: int) -> str:
    """The Problem of line n: the skeleton supports no requirement."""
    return json.dumps(
        {
            "type": "about:blank",
            "title": "Unsupported requirement",
            "status": 422,
            "code": "UNSUPPORTED_REQUIREMENT",
            "request_id": f"skeleton-{n}",
        },
        separators=(",", ":"),
    )


def locate(dir: Path) -> tuple[Path, str]:
    """The fixture directory holding dir and the entry id of dir in its manifest."""
    fixtures = dir
    while not (fixtures / manifest.FILE_NAME).is_file():
        if fixtures.parent == fixtures:
            raise CaseError(f"{dir}: no {manifest.FILE_NAME} in it or above it")
        fixtures = fixtures.parent
    rel = dir.relative_to(fixtures).as_posix()
    for e in load_manifest(fixtures).entries:
        if e.kind == manifest.Kind.EVALUATE and e.path == rel:
            return fixtures, e.id
    raise CaseError(f"{dir}: no evaluate entry of {fixtures / manifest.FILE_NAME} has path {rel}")


def main(argv: Sequence[str]) -> int:
    if len(argv) not in (2, 3) or argv[0] != "evaluate":
        sys.stderr.write(USAGE)
        return EXIT_USAGE
    try:
        fixtures, id = locate(Path(argv[1]).resolve())
        lines: list[str] = []
        for x in read(fixtures, id).exchanges:
            for _ in range(len(x.submissions) + len(x.handoff)):
                lines.append(problem(len(lines) + 1))
    except (PactError, OSError) as e:
        sys.stderr.write(f"evaluate: {message(e)}\n")
        return EXIT_USAGE
    sys.stdout.write("".join(line + "\n" for line in lines))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
