"""The Usage example of README.md: examples/sign_verify.py, run as a script, prints
the output the README shows, and the README's code block is the file verbatim."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "sign_verify.py"
README = ROOT / "README.md"

OUTPUT = [
    'requirement-publisher publisher-1 {"pact_version":"0.1","jti":"contract-1"}',
    "J0GfvClw7hrBhHyvkkriLn5ZbdWqmdwQtBHF_DZCYo4",
]


def _usage_blocks() -> tuple[str, str]:
    """The python block and the output block that follow the Usage heading."""
    usage = README.read_text(encoding="utf-8").split("\n## Usage\n", 1)[1].split("\n## ", 1)[0]
    blocks = re.findall(r"^```(\w*)\n(.*?)^```$", usage, flags=re.MULTILINE | re.DOTALL)
    code = [body for lang, body in blocks if lang == "python"]
    out = [body for lang, body in blocks if lang == "text"]
    assert len(code) == 1
    assert len(out) == 1
    return code[0], out[0]


def test_readme_example_output() -> None:
    out = subprocess.run(
        [sys.executable, str(EXAMPLE)],
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    ).stdout
    assert out.splitlines() == OUTPUT


def test_readme_shows_example() -> None:
    code, out = _usage_blocks()
    assert code == EXAMPLE.read_text(encoding="utf-8")
    assert out.splitlines() == OUTPUT
