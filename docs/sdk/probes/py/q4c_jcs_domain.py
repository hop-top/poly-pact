# Q4 (domain): how the stdlib-only canon and the rfc8785 package treat out-of-range ints, NaN, Infinity, lone surrogates, odd types.
import json, rfc8785
from decimal import Decimal
def es(x):  # same ECMA-262 number formatter as q4_jcs_numbers.py
    m, _, e = repr(abs(x)).partition("e")
    body = "0" if x == 0 else format(Decimal(repr(abs(x))), "f").removesuffix(".0") if 1e-6 <= abs(x) < 1e21 else m + "e" + ("+" if int(e) > 0 else "-") + str(abs(int(e)))
    return ("-" if x < 0 else "") + body
def canon(v):
    if isinstance(v, dict): return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canon(v[k]) for k in sorted(v, key=lambda k: k.encode("utf-16-be"))) + "}"
    if isinstance(v, list): return "[" + ",".join(map(canon, v)) + "]"
    if isinstance(v, float) and v - v != 0 or isinstance(v, int) and abs(v) >= 2**53: raise ValueError("outside I-JSON range")
    return es(v) if isinstance(v, float) else json.dumps(v, ensure_ascii=False)
def run(f, v):
    try: return f(v) if f is rfc8785.dumps else f(v).encode("utf-8")
    except Exception as e: return "raises " + type(e).__name__
for v in (2**53 - 1, 2**53, -(2**53) + 1, -(2**53), float(2**53), 1e999, float("nan"), chr(0xD800), {chr(0xD800): 1}, b"x", {1: 2}, True, 1.0):
    print(f"{v!r:24.24} in-house={run(canon, v)!s:34.34} rfc8785={run(rfc8785.dumps, v)!s}")
