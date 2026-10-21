# Q4 (document): stdlib-only JCS (UTF-16 key order, escapes, ES numbers) vs RFC 8785 3.2.2-3.2.4 samples, rfc8785, json.dumps.
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
J = lambda t: json.loads(t.replace("@u", "\\u"))  # "@u" stands for a JSON backslash-u escape
S = J(r'''{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001], "string": "@u20ac$@u000F@u000aA'@u0042@u0022@u005c\\\"\/", "literals": [null, true, false]}''')
O = J(r'''{"@u20ac": "Euro Sign", "\r": "Carriage Return", "@ufb33": "Hebrew Letter Dalet With Dagesh", "1": "One", "@ud83d@ude00": "Emoji: Grinning Face", "@u0080": "Control", "@u00f6": "Latin Small Letter O With Diaeresis"}''')
want = bytes.fromhex("7b226c69746572616c73223a5b6e756c6c2c747275652c66616c73655d2c226e756d62657273223a5b3333333333333333332e333333333333332c31652b33302c342e352c302e3030322c31652d32375d2c22737472696e67223a22e282ac245c75303030665c6e4127425c225c5c5c5c5c222f227d")
print("3.2.4 bytes equal: in-house", canon(S).encode() == want, "| rfc8785", rfc8785.dumps(S) == want, "| json.dumps(sort_keys)", json.dumps(S, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode() == want)
print("3.2.3 order, UTF-16:", [O[k] for k in sorted(O, key=lambda k: k.encode("utf-16-be"))], "\n          code point:", list(json.loads(json.dumps(O, sort_keys=True)).values()))
print("sorting sample: in-house == rfc8785", canon(O).encode() == rfc8785.dumps(O), "| rfc8785 order", list(json.loads(rfc8785.dumps(O)).values()) == [O[k] for k in sorted(O, key=lambda k: k.encode("utf-16-be"))])
