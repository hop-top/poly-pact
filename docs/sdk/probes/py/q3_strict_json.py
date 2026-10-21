# Q3: strict JSON via json.loads hooks (duplicate keys, NaN/Infinity, 1e999, big ints, surrogates) and strict UTF-8.
import json, math
def pairs(p):
    d = dict(p)
    if len(d) != len(p): raise ValueError("duplicate key")
    return d
def const(c): raise ValueError("rejected " + c[:12])
def flt(s): return float(s) if math.isfinite(float(s)) else const(s)
def num(s): return int(s) if len(s) < 20 and abs(int(s)) < 2**53 else const("int " + s)
def strict(t):
    v = json.loads(t, object_pairs_hook=pairs, parse_constant=const, parse_float=flt, parse_int=num)
    json.dumps(v, ensure_ascii=False).encode("utf-8"); return v  # lone surrogate -> UnicodeEncodeError
def run(f, x):
    try: return repr(f(x))[:44]
    except Exception as e: return "REJECT " + type(e).__name__ + ": " + str(e)[:40]
T = ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', "[NaN]", "[Infinity]", "[-Infinity]", "[1e999]", '["\\ud800"]', '["\\ud83d\\ude00"]', "[9007199254740991]", "[9007199254740993]", "[9007199254740993.0]", "[0.1,333333333.33333329,5e-324,1e22]", "[1" + "0" * 4300 + "]", "[" * 2000 + "]" * 2000]
for t in T:
    for n, f in (("default", json.loads), ("strict", strict)): print(f"{len(t):5} {t[:30]!r:34} {n:8}", run(f, t))
for b in [b"\xff", b"\xc0\xaf", b"\xe2\x82", b'["\xed\xa0\x80"]', b"\xf4\x90\x80\x80", b"\xef\xbb\xbf{}", "{}".encode("utf-16")]: print(f"{b!r:24} decode={run(lambda x: x.decode('utf-8'), b)} | loads(bytes)={run(json.loads, b)}")
