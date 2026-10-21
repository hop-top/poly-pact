"""Tests for check-publish-map.py: each rule against a small config and
publish.yml written to a temporary directory.

Run: python3 -I tools/release/test_check_publish_map.py
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("check_publish_map", HERE / "check-publish-map.py")
cpm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cpm)

PACKAGES = {
    "go": {"component": "pact-go"},
    "ts": {"component": "pact-ts"},
    "spec/v1.0": {"component": "pact-spec"},
}

ENTRIES = {
    "pact-go": {"dir": "go", "ecosystem": "go", "mirror": "hop-top/pact-go"},
    "pact-ts": {"dir": "ts", "ecosystem": "ts", "mirror": "hop-top/pact-ts"},
    "pact-spec": {"dir": "spec", "ecosystem": "none", "mirror": "hop-top/spec-pact"},
}


def workflow(entries, tags):
    lines = ["name: publish", "on:", "  push:", f"    tags: [{', '.join(repr(t) for t in tags)}]",
             "jobs:", "  publish:", "    with:", "      ecosystems: |"]
    for key, fields in entries.items():
        lines.append(f"        {key}:")
        lines += [f"          {k}: {v}" for k, v in fields.items()]
    return "\n".join(lines) + "\n"


class CheckPublishMap(unittest.TestCase):
    def run_check(self, packages=None, entries=None, tags=("*/v*",)):
        packages = PACKAGES if packages is None else packages
        entries = ENTRIES if entries is None else entries
        with tempfile.TemporaryDirectory() as d:
            wf, cfg = Path(d, "publish.yml"), Path(d, "config.json")
            wf.write_text(workflow(entries, tags), encoding="utf-8")
            cfg.write_text(json.dumps({"packages": packages}), encoding="utf-8")
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                rc = cpm.main(["--workflow", str(wf), "--config", str(cfg)])
        return rc, err.getvalue()

    def with_entry(self, key, **fields):
        entries = {k: dict(v) for k, v in ENTRIES.items()}
        entries[key].update(fields)
        for k, v in list(entries[key].items()):
            if v is None:
                del entries[key][k]
        return entries

    def test_no_root_package_passes(self):
        self.assertEqual(self.run_check(), (0, ""))

    def test_root_package_is_excluded_from_keys_and_tags(self):
        packages = {".": {"component": "poly-pact"}, **PACKAGES}
        self.assertEqual(self.run_check(packages, tags=("*/v*", "!poly-pact/v*"))[0], 0)

    def test_root_package_without_tag_exclusion_fails(self):
        packages = {".": {"component": "poly-pact"}, **PACKAGES}
        rc, err = self.run_check(packages)
        self.assertEqual(rc, 1)
        self.assertIn("tags: the tag filter does not exclude the root component", err)

    def test_root_component_entry_fails(self):
        packages = {".": {"component": "poly-pact"}, **PACKAGES}
        entries = {**ENTRIES, "poly-pact": {"dir": "go", "ecosystem": "go", "mirror": "hop-top/x"}}
        rc, err = self.run_check(packages, entries, tags=("*/v*", "!poly-pact/v*"))
        self.assertEqual(rc, 1)
        self.assertIn("keys: entries that are not release-please components (or are the root 'poly-pact'): poly-pact", err)

    def test_missing_tag_glob_fails(self):
        rc, err = self.run_check(tags=("pact-go/v*",))
        self.assertEqual(rc, 1)
        self.assertIn("does not include '*/v*'", err)

    def test_spec_root_dir_passes_and_version_dir_too(self):
        self.assertEqual(self.run_check(entries=self.with_entry("pact-spec", dir="spec/v1.0"))[0], 0)

    def test_spec_root_of_another_component_fails(self):
        packages = {**PACKAGES, "spec/v1.0": {"component": "other-spec"}}
        entries = {k: v for k, v in ENTRIES.items() if k != "pact-spec"}
        entries["other-spec"] = {"dir": "go", "ecosystem": "go", "mirror": "hop-top/x"}
        entries["pact-spec"] = dict(ENTRIES["pact-spec"])
        packages["docs/v1.0"] = {"component": "pact-spec"}
        rc, err = self.run_check(packages, entries)
        self.assertEqual(rc, 1)
        self.assertIn("dir: pact-spec: 'spec' is the spec root of other-spec, not of 'pact-spec'", err)

    def test_spec_root_with_registry_ecosystem_fails(self):
        rc, err = self.run_check(entries=self.with_entry("pact-spec", ecosystem="py"))
        self.assertEqual(rc, 1)
        self.assertIn("spec: pact-spec: dir 'spec' is a spec root, so its ecosystem is 'none'", err)

    def test_dir_that_is_no_package_fails(self):
        rc, err = self.run_check(entries=self.with_entry("pact-ts", dir="docs"))
        self.assertEqual(rc, 1)
        self.assertIn("dir: pact-ts: 'docs' is not a release-please package path", err)

    def test_dir_of_another_component_fails(self):
        rc, err = self.run_check(entries=self.with_entry("pact-ts", dir="go"))
        self.assertEqual(rc, 1)
        self.assertIn("dir: pact-ts: 'go' is the package of component 'pact-go'", err)

    def test_target_prefix_fails_on_spec(self):
        rc, err = self.run_check(entries=self.with_entry("pact-spec", **{"target-prefix": "specs/v0.1"}))
        self.assertEqual(rc, 1)
        self.assertIn("prefix: pact-spec: no entry has target-prefix", err)

    def test_target_prefix_fails_on_package(self):
        rc, err = self.run_check(entries=self.with_entry("pact-go", **{"target-prefix": "lib"}))
        self.assertEqual(rc, 1)
        self.assertIn("prefix: pact-go: no entry has target-prefix", err)

    def test_missing_and_extra_keys_fail(self):
        entries = {k: v for k, v in ENTRIES.items() if k != "pact-ts"}
        entries["pact"] = {"dir": "go", "ecosystem": "go", "mirror": "hop-top/pact"}
        rc, err = self.run_check(entries=entries)
        self.assertEqual(rc, 1)
        self.assertIn("keys: release-please components without an entry: pact-ts", err)
        self.assertIn("keys: entries that are not release-please components: pact", err)

    def test_missing_ecosystem_fails(self):
        rc, err = self.run_check(entries=self.with_entry("pact-spec", ecosystem=None))
        self.assertEqual(rc, 1)
        self.assertIn("fields: pact-spec: no ecosystem", err)

    def test_two_go_components_with_own_mirrors_pass(self):
        packages = {**PACKAGES, "cli": {"component": "pact"}}
        entries = {**ENTRIES, "pact": {"dir": "cli", "ecosystem": "go", "mirror": "hop-top/pact"}}
        self.assertEqual(self.run_check(packages, entries), (0, ""))

    def test_shared_mirror_fails(self):
        packages = {**PACKAGES, "cli": {"component": "pact"}}
        entries = {**ENTRIES, "pact": {"dir": "cli", "ecosystem": "go", "mirror": "hop-top/pact-go"}}
        rc, err = self.run_check(packages, entries)
        self.assertEqual(rc, 1)
        self.assertIn("mirror: hop-top/pact-go is the mirror of more than one entry: pact, pact-go", err)

    def test_php_without_mirror_fails(self):
        packages = {**PACKAGES, "php": {"component": "pact-php"}}
        entries = {**ENTRIES, "pact-php": {"dir": "php", "ecosystem": "php"}}
        rc, err = self.run_check(packages, entries)
        self.assertEqual(rc, 1)
        self.assertIn("php: pact-php: a php entry needs a mirror", err)

    def test_empty_packages_is_a_parse_error(self):
        self.assertEqual(self.run_check(packages={})[0], 2)


if __name__ == "__main__":
    unittest.main()
