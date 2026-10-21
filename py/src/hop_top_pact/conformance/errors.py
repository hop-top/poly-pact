"""The error of the evaluation-case loader."""

from __future__ import annotations

import json

from hop_top_pact.errors import PactError

__all__ = ["CaseError"]


class CaseError(PactError):
    """A case, signed file or test key the loader cannot read as spec/v1.0/fixtures/README.md
    defines it.

    The text names the file or case first, then what is wrong, as the wrapped
    errors of the Go package read. ``__cause__`` is the underlying error (a
    StrictJSONError, a JWSError, an OSError), when there is one.
    """


def wrap(prefix: str, err: BaseException) -> CaseError:
    """err as a CaseError with ``prefix: `` before its text, for ``raise wrap(prefix,
    err) from err``."""
    return CaseError(f"{prefix}: {message(err)}")


def message(err: BaseException) -> str:
    """The text of err; for an OSError the file and the reason, as Go's os errors read."""
    if isinstance(err, OSError) and err.strerror:
        return f"{err.filename}: {err.strerror}" if err.filename else err.strerror
    return str(err)


def q(s: str) -> str:
    """s in double quotes, as Go's %q writes a printable string."""
    return json.dumps(s, ensure_ascii=False)
