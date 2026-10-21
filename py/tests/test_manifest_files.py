"""runner.manifest: completeness against the fixture directory. Port of
go/runner/manifest/files_test.go."""

from __future__ import annotations

import os
import sys
from typing import Any

import pytest

from hop_top_pact.runner import manifest

no_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="symbolic links need privileges on windows"
)


def test_completeness_accepts_base(mk: Any) -> None:
    tr = mk.new_tree()
    mk.want_clean(manifest.completeness(tr.root, tr.manifest()))


def test_completeness_path_missing(mk: Any) -> None:
    tr = mk.new_tree()
    tr.remove("keys/holder.jwk.json")
    mk.want_rule(
        manifest.completeness(tr.root, tr.manifest()), manifest.RULE_PATH_MISSING, "keys/holder"
    )


def test_completeness_expected_missing(mk: Any) -> None:
    tr = mk.new_tree()
    tr.remove("expected/admission/valid/decision.json")
    mk.want_rule(
        manifest.completeness(tr.root, tr.manifest()),
        manifest.RULE_EXPECTED_MISSING,
        "admission/valid",
    )


def test_completeness_expected_is_a_file(mk: Any) -> None:
    """An expected result is a file, never a directory."""
    es = mk.base_entries()
    es[1]["expected"] = "expected/admission/valid"
    tr = mk.new_tree(es)
    ps = manifest.completeness(tr.root, tr.manifest())
    mk.want_where(ps, manifest.RULE_EXPECTED_MISSING, "admission/valid")

    # A directory named as expected covers nothing inside it. (A file under
    # expected/<id>/ is covered by the entry <id> whatever its expected names,
    # so the directory here is outside that tree.)
    es = mk.base_entries()
    es[1]["expected"] = "admission/valid-results"
    tr = mk.new_tree(es)
    tr.write("admission/valid-results/decision.json", "{}")
    ps = manifest.completeness(tr.root, tr.manifest())
    mk.want_where(ps, manifest.RULE_EXPECTED_MISSING, "admission/valid")
    mk.want_where(ps, manifest.RULE_UNCOVERED, "admission/valid-results/decision.json")


@no_symlinks
def test_completeness_symlinks_escapes_the_fixtures_directory(mk: Any) -> None:
    tr = mk.new_tree()
    outside = tr.dir / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    tr.remove("keys/holder.jwk.json")
    os.symlink(outside, tr.root / "keys" / "holder.jwk.json")
    mk.want_rule(
        manifest.completeness(tr.root, tr.manifest()), manifest.RULE_PATH_MISSING, "keys/holder"
    )


@no_symlinks
def test_completeness_symlinks_dangling(mk: Any) -> None:
    tr = mk.new_tree()
    tr.remove("keys/holder.jwk.json")
    os.symlink("nowhere.json", tr.root / "keys" / "holder.jwk.json")
    mk.want_rule(
        manifest.completeness(tr.root, tr.manifest()), manifest.RULE_PATH_MISSING, "keys/holder"
    )


@no_symlinks
def test_completeness_symlinks_directory_link_inside_the_tree(mk: Any) -> None:
    """A link to a directory inside the tree is not followed: it is checked as a file."""
    tr = mk.new_tree()
    os.symlink(tr.root / "keys", tr.root / "vectors" / "keys-link")
    ps = manifest.completeness(tr.root, tr.manifest())
    assert mk.rules(ps) == sorted([manifest.RULE_EXTENSION, manifest.RULE_UNCOVERED]), str(ps)
    mk.want_where(ps, manifest.RULE_UNCOVERED, "vectors/keys-link")
    assert not [p for p in ps if p.where.startswith("vectors/keys-link/")], str(ps)


def link(tr: Any) -> str:
    lnk = tr.dir / "fixtures-link"
    os.symlink(tr.root, lnk)
    return str(lnk)


@no_symlinks
def test_completeness_symlinked_root_clean_tree(mk: Any) -> None:
    """A fixture directory given as a symbolic link to a directory is followed, as a POSIX
    utility follows a link named on its command line (find -H)."""
    tr = mk.new_tree()
    mk.want_clean(manifest.completeness(link(tr), tr.manifest()))


@no_symlinks
def test_completeness_symlinked_root_uncovered_file(mk: Any) -> None:
    tr = mk.new_tree()
    tr.write("keys/issuer.jwk.json", "{}")
    mk.want_rule(
        manifest.completeness(link(tr), tr.manifest()),
        manifest.RULE_UNCOVERED,
        "keys/issuer.jwk.json",
    )


@no_symlinks
def test_completeness_symlinked_root_extension(mk: Any) -> None:
    tr = mk.new_tree()
    tr.write("admission/valid/run.sh", "x")
    mk.want_rule(
        manifest.completeness(link(tr), tr.manifest()),
        manifest.RULE_EXTENSION,
        "admission/valid/run.sh",
    )


@no_symlinks
def test_completeness_symlinked_root_missing_path(mk: Any) -> None:
    tr = mk.new_tree()
    tr.remove("keys/holder.jwk.json")
    mk.want_rule(
        manifest.completeness(link(tr), tr.manifest()), manifest.RULE_PATH_MISSING, "keys/holder"
    )


def test_completeness_missing_root(mk: Any) -> None:
    tr = mk.new_tree()
    m = tr.manifest()
    mk.want_rule(manifest.completeness(tr.dir / "nowhere", m), manifest.RULE_PATH_MISSING, ".")


UNCOVERED = {
    "file in no entry": "keys/issuer.jwk.json",
    "file beside a file path": "vectors/jcs/input/french.json",
    "expected tree of no entry": "expected/admission/other/decision.json",
    "expected tree of a group": "expected/admission/decision.json",
    "beside an expected tree": "expected/admission/valid-2/decision.json",
    "nested manifest.json": "keys/manifest.json",
    "nested manifest.schema.json": "vectors/manifest.schema.json",
    "other markdown": "vectors/jcs/NOTES.md",
    "LICENSE inside a name": "vectors/jcs/MY-LICENSE.md",
    "lower-case license": "vectors/jcs/license.md",
    "directory named LICENSE": "vectors/LICENSE/notes.json",
    "prefix but not inside": "admission/valid-2/config.json",
}


@pytest.mark.parametrize("file", UNCOVERED.values(), ids=UNCOVERED)
def test_completeness_uncovered(mk: Any, file: str) -> None:
    tr = mk.new_tree()
    tr.write(file, "{}")
    mk.want_rule(manifest.completeness(tr.root, tr.manifest()), manifest.RULE_UNCOVERED, file)


def test_completeness_covered(mk: Any) -> None:
    """A file inside a directory path, a single-file path, an expected file, a file under
    expected/<id>/ of an entry <id>, a README.md anywhere and a file whose name starts with
    LICENSE are covered."""
    tr = mk.new_tree()
    tr.write("expected/admission/valid/snapshot.json", "{}")
    tr.write("expected/admission/valid/exchanges/1/decision.json", "{}")
    tr.write("expected/vectors/jcs/arrays/extra.json", "{}")
    tr.write("admission/valid/evidence/runtime.json", "{}")
    tr.write("admission/valid/signed/evidence/runtime.jws", "e30.e30.e30")
    tr.write("vectors/jcs/README.md", "# x")
    tr.write("expected/README.md", "# x")
    tr.write("vectors/jcs/LICENSE-NOTE.md", "# x")
    tr.write("LICENSE.md", "# x")
    tr.write("keys/LICENSE.json", "{}")
    mk.want_clean(manifest.completeness(tr.root, tr.manifest()))


EXT, UNC = manifest.RULE_EXTENSION, manifest.RULE_UNCOVERED
EXTENSIONS: dict[str, tuple[str, list[str]]] = {
    "go source inside a case": ("admission/valid/gen.go", [EXT]),
    "shell script inside a case": ("admission/valid/run.sh", [EXT]),
    "no extension": ("admission/valid/LICENSE", [EXT]),
    "LICENSE outside every entry": ("vectors/LICENSE", [EXT]),
    "yml is not in the neutral list": ("admission/valid/case.yml", [EXT]),
    "txt is not in the neutral list": ("admission/valid/notes.txt", [EXT]),
    "sql outside an asset entry": ("admission/valid/seed.sql", [EXT]),
    "rego outside an asset entry": ("admission/valid/policy.rego", [EXT]),
    "fga outside an asset entry": ("admission/valid/model.fga", [EXT]),
    "ldif outside an asset entry": ("admission/valid/tree.ldif", [EXT]),
    "uncovered sql": ("adapters/db/other.sql", [EXT, UNC]),
    # Extensions are lowercase, as listed.
    "upper-case json": ("admission/valid/E.JSON", [EXT]),
    "mixed-case yaml": ("admission/valid/case.Yaml", [EXT]),
    "upper-case jws": ("admission/valid/signed/x.JWS", [EXT]),
    "upper-case md": ("admission/valid/NOTES.MD", [EXT]),
    "upper-case sql inside an asset": ("adapters/db/assets/seed.SQL", [EXT]),
    # A name that starts with a dot has that name as its extension, as Go's
    # path.Ext reads it.
    "hidden file": ("admission/valid/.json", []),
    "dot file without a neutral name": ("admission/valid/.hidden", [EXT]),
}


@pytest.mark.parametrize(("file", "want"), EXTENSIONS.values(), ids=EXTENSIONS)
def test_completeness_extensions(mk: Any, file: str, want: list[str]) -> None:
    tr = mk.new_tree()
    tr.write(file, "x")
    ps = manifest.completeness(tr.root, tr.manifest())
    assert mk.rules(ps) == sorted(want), str(ps)
    for r in want:
        mk.want_where(ps, r, file)


def test_completeness_allowed_extensions(mk: Any) -> None:
    tr = mk.new_tree()
    for f in (
        "admission/valid/a.json",
        "admission/valid/b.yaml",
        "admission/valid/c.md",
        "admission/valid/d.jws",
        "admission/valid/E.json",
        "adapters/db/assets/policy.rego",
        "adapters/db/assets/model.fga",
        "adapters/db/assets/tree.ldif",
    ):
        tr.write(f, "x")
    mk.want_clean(manifest.completeness(tr.root, tr.manifest()))


def test_completeness_skips_malformed_entries(mk: Any) -> None:
    """An entry whose path breaks a field rule is reported by validate, not looked up on
    disk."""
    es = mk.base_entries()
    es[2]["path"] = "../outside.json"
    tr = mk.new_tree(es)
    for p in manifest.completeness(tr.root, tr.manifest()):
        assert p.rule == manifest.RULE_UNCOVERED, str(p)
        assert p.where == "keys/holder.jwk.json", str(p)
