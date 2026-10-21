"""Entry point of ``python -m hop_top_pact.runner.manifest check ROOT SPECMAP``.

Runs check over the fixture directory ROOT and the spec map SPECMAP, as
``pactfix check manifest`` does. Plain argv, no command-line framework: make
and the manifest-parity check (scripts/check-manifest-parity.py --checker)
drive it.

On a clean tree it prints ``manifest check: ok (N entries)`` on standard
output and exits 0. Otherwise it prints the problem count, then one line per
problem that starts with ``[rule-id] ``, on standard error, and exits 1. A
usage error exits 2.
"""

from __future__ import annotations

import sys

from hop_top_pact.runner.manifest import Problems, check, load

USAGE = "usage: python -m hop_top_pact.runner.manifest check ROOT SPECMAP"


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[0] != "check" or any(a.startswith("-") for a in argv[1:]):
        print(USAGE, file=sys.stderr)
        return 2
    root, spec_map = argv[1], argv[2]
    ps = check(root, spec_map)
    if ps:
        print(f"manifest check: {len(ps)} problem(s)", file=sys.stderr)
        for p in ps:
            print(" ".join(str(p).splitlines()), file=sys.stderr)
        return 1
    try:
        m = load(root)
    except Problems as err:  # changed since check read it
        print(f"manifest check: {err}", file=sys.stderr)
        return 1
    print(f"manifest check: ok ({len(m.entries)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
