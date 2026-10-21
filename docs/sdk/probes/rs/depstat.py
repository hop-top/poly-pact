# Resolved dependency count of a scratch crate, from `cargo tree` (normal and build edges, host platform, root excluded),
# with the crates that carry a build script or are proc-macros looked up in `cargo metadata`. Nothing is built.
# usage: depstat.py <crate-dir>
import json, subprocess, sys
d = sys.argv[1]
tree = subprocess.check_output(["cargo", "tree", "--prefix", "none", "-e", "normal,build"], cwd=d, text=True).splitlines()[1:]
deps = {tuple(l.split()[:2]) for l in tree}
pk = json.loads(subprocess.check_output(["cargo", "metadata", "--format-version", "1", "--filter-platform", "aarch64-apple-darwin"], cwd=d))["packages"]
kinds = {(p["name"], "v" + p["version"]): {k for t in p["targets"] for k in t["kind"]} for p in pk}
pick = lambda kind: sorted(f"{n} {v[1:]}" for n, v in sorted(deps) if kind in kinds[(n, v)])
print(len(deps), "deps | build.rs:", len(pick("custom-build")), pick("custom-build"), "| proc-macro:", len(pick("proc-macro")), pick("proc-macro"))
