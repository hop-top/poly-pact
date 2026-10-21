# Q6: is hop_top_pact free in this venv, and which top-level packages do pact-python wheels and the `pact` sdist ship?
import importlib.util, sys, tarfile, zipfile
for name in ("hop_top_pact", "pact"): print(f"{name!r} importable here: {importlib.util.find_spec(name) is not None}")
def names(path):  # read member names only; nothing is extracted or executed
    if path.endswith(".whl"): return zipfile.ZipFile(path).namelist()
    return [m.split("/", 1)[1] for m in tarfile.open(path).getnames() if "/" in m]
def top_packages(members):  # directories holding __init__.py at depth 1, or at depth 2 under src/
    parts = [m.split("/") for m in members if m.endswith("/__init__.py")]
    return sorted({p[0] for p in parts if len(p) == 2} | {p[1] for p in parts if len(p) == 3 and p[0] == "src"})
for path in sys.argv[1:]:
    print(path.rsplit("/", 1)[-1], "-> top-level packages:", top_packages(names(path)))
