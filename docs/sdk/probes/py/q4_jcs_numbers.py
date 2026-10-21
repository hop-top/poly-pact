# Q4: repr(float) vs RFC 8785 number samples; in-house ECMA-262 formatting over repr digits vs the rfc8785 package.
import random, struct, rfc8785
from decimal import Decimal
def es(x):  # ECMA-262 7.1.12.1 on top of the shortest round-trip digits that repr() already yields
    m, _, e = repr(abs(x)).partition("e")
    body = "0" if x == 0 else format(Decimal(repr(abs(x))), "f").removesuffix(".0") if 1e-6 <= abs(x) < 1e21 else m + "e" + ("+" if int(e) > 0 else "-") + str(abs(int(e)))
    return ("-" if x < 0 else "") + body
bits = lambda h: struct.unpack(">d", bytes.fromhex(h))[0]
B = dict(zip("0000000000000000 8000000000000000 0000000000000001 8000000000000001 7fefffffffffffff ffefffffffffffff 4340000000000000 c340000000000000 4430000000000000 44b52d02c7e14af5 44b52d02c7e14af6 44b52d02c7e14af7 444b1ae4d6e2ef4e 444b1ae4d6e2ef4f 444b1ae4d6e2ef50 3eb0c6f7a0b5ed8c 3eb0c6f7a0b5ed8d 41b3de4355555553 41b3de4355555554 41b3de4355555555 41b3de4355555556 41b3de4355555557 becbf647612f3696 43143ff3c1cb0959".split(),
  "0 0 5e-324 -5e-324 1.7976931348623157e+308 -1.7976931348623157e+308 9007199254740992 -9007199254740992 295147905179352830000 9.999999999999997e+22 1e+23 1.0000000000000001e+23 999999999999999700000 999999999999999900000 1e+21 9.999999999999997e-7 0.000001 333333333.3333332 333333333.33333325 333333333.3333333 333333333.3333334 333333333.33333343 -0.0000033333333333333333 1424953923781206.2".split()))
rows = [(h, bits(h), w) for h, w in B.items()] + [("literal", x, w) for x, w in [(1e21, "1e+21"), (1e-7, "1e-7"), (-0.0, "0"), (4.5, "4.5"), (1e30, "1e+30"), (1.0, "1"), (100.0, "100"), (1e16, "10000000000000000")]]
for h, x, w in rows: print(f"{h:17} want={w:26} repr={x!r:26} es={es(x):26} rfc8785={rfc8785.dumps(x).decode():26}", "repr-ok" if repr(x) == w else "REPR-DIFF", "es-ok" if es(x) == w else "ES-DIFF", "pkg-ok" if rfc8785.dumps(x).decode() == w else "PKG-DIFF")
print("rows", len(rows), "repr mismatches", sum(repr(x) != w for _, x, w in rows), "es mismatches", sum(es(x) != w for _, x, w in rows), "pkg mismatches", sum(rfc8785.dumps(x).decode() != w for _, x, w in rows))
random.seed(0); rnd = [struct.unpack(">d", random.getrandbits(64).to_bytes(8, "big"))[0] for _ in range(300000)]
rnd = [x for x in rnd if x == x and abs(x) != float("inf")] + [random.uniform(-1e9, 1e9) for _ in range(100000)] + [float(random.randint(-2**53, 2**53)) for _ in range(100000)]
print("random doubles", len(rnd), "es==rfc8785", sum(es(x) == rfc8785.dumps(x).decode() for x in rnd), "float(es(x))==x", sum(float(es(x)) == x for x in rnd))
