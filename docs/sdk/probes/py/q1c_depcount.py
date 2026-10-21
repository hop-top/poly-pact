# Q1 (dependency count): transitive dependencies per candidate from `pip install --dry-run --report` in a clean venv.
import json, subprocess, sys
py = sys.argv[1]  # interpreter of a clean venv that has only pip and setuptools
for pkg in sys.argv[2:]:
    cmd = [py, "-I", "-m", "pip", "install", "--dry-run", "--ignore-installed", "--quiet", "--disable-pip-version-check", "--report", "-", pkg]
    items = json.loads(subprocess.run(cmd, capture_output=True, text=True, check=True).stdout)["install"]
    named = [(i["metadata"]["name"], i["metadata"]["version"], i["download_info"]["url"].rsplit("/", 1)[-1]) for i in items]
    print(f"{pkg}: {len(named) - 1} transitive deps ->", [f"{n} {v}" for n, v, _ in named if n.lower() != pkg])
    print("   artifacts:", [a for _, _, a in named])
