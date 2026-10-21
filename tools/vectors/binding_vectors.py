#!/usr/bin/env python3
"""Independent cross-check of the binding vectors in spec/v1.0/fixtures/vectors/binding.

The vectors describe the baseline HTTP mapping of draft Section 10.2. Their
expected digests must not come from the implementation they test, so this
script computes every digest itself: SHA-256 from hashlib, base64url without
padding, and a small RFC 8785 (JCS) serializer for the flat objects an
operation context is (strings, arrays of strings, objects of strings). It
also derives each operation context from the vector's request on its own,
following draft 10.2 and spec/v1.0/profiles/request-binding.md, and compares it
with the context the vector expects.

For every manifest entry under vectors/binding/ it checks:

1. the entry: kind vector, scope adapter, outcome ACCEPTED or REJECTED as the
   vector expects, a BIND-NN spec_map_row, draft_section 10.2, and path and
   expected both equal to the id plus ".json";
2. the file: strict JSON (no duplicate member, no non-finite number), exactly
   the members of the format, and an id equal to the manifest id;
3. the result: the derived outcome equals the expected one; for an accepted
   vector the derived context equals expect.operation_context member for
   member, body_digest is the digest of the body, and expect_operation_digest
   is object_digest of the expected context; for a refused vector
   reject_reason is INVALID_MESSAGE (draft 13.4) and expect_operation_digest
   is null; for a configuration error config_error is true, the
   configuration fails a check of request-binding.md section 4.2, and
   expect_operation_digest is null;
4. that every .json file in the directory is listed in the manifest, that
   bind-01-appendix-b3 has the operation_digest printed in Appendix B.4, and
   that the vector pairs of RELATIONS have equal or different digests.

With --write it first replaces body_digest and expect_operation_digest in
each vector file by the values it computes, and touches nothing else.

Standard library only (Python 3.9 and later). Run it isolated:

    python3 -I tools/vectors/binding_vectors.py [--write] [--fixtures DIR]

Exit status: 0 when every vector agrees, 1 when one does not, 2 when the
script cannot run.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
PREFIX = "vectors/binding/"

# Appendix B.4 and B.7 print this operation_digest for the B.3 context.
APPENDIX_B3_ID = PREFIX + "bind-01-appendix-b3"
APPENDIX_B3_DIGEST = "R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0"

# Digest relations the vector pairs exist to show. Each holds because both
# vectors carry fixed expected digests; this script checks the relation once.
SAME, DIFFERENT = "same", "different"
RELATIONS = [
    ("bind-02-query-order-ab", "bind-02-query-order-ba", DIFFERENT),
    ("bind-03-space-percent-20", "bind-03-space-plus", DIFFERENT),
    ("bind-08-body-compact", "bind-08-body-spaced", DIFFERENT),
    ("bind-09-header-plain", "bind-09-header-case-and-whitespace", SAME),
    ("bind-01-appendix-b3", "bind-10-header-not-allowlisted", SAME),
    ("bind-01-appendix-b3", "bind-11-forwarding-headers", SAME),
    ("bind-01-appendix-b3", "bind-12-default-port", SAME),
]

VECTOR_MEMBERS = sorted([
    "id", "description", "config", "request", "operation_id", "principal_id",
    "action", "resources", "expect", "expect_operation_digest",
])
CONFIG_MEMBERS = sorted([
    "origin", "header_allowlist", "normalization_id", "mapping_version", "environment_id",
])
REQUEST_MEMBERS = sorted(["method", "raw_request_uri", "headers", "body_b64"])
CONTEXT_MEMBERS = sorted([
    "operation_id", "environment_id", "principal_id", "action", "resources",
    "method", "target_uri", "body_digest", "headers",
])

UNRESERVED = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
SUB_DELIMS = set(b"!$&'()*+,;=")
PCHAR = UNRESERVED | SUB_DELIMS | set(b":@")
HEX_UPPER = set(b"0123456789ABCDEF")
HEX_ANY = HEX_UPPER | set(b"abcdef")
NEVER_COVERED = {
    "authorization", "cookie", "set-cookie", "connection", "keep-alive", "te",
    "transfer-encoding", "upgrade", "signature", "signature-input", "host",
}


class Refused(Exception):
    """The baseline mapping refuses the request (INVALID_MESSAGE)."""


class ConfigError(ValueError):
    """The configuration fails a check (request-binding.md section 4.2)."""


# Digests (draft 7.4).

def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def bytes_digest(raw):
    return b64url(hashlib.sha256(raw).digest())


def jcs_string(s):
    out = ['"']
    for ch in s:
        c = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif c < 0x20:
            out.append("\\u%04x" % c)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs(value):
    """RFC 8785 for strings, arrays and objects. Numbers, booleans and null
    never occur in an operation context, so they are refused."""
    if isinstance(value, str):
        return jcs_string(value)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        # Members sorted by their names as UTF-16 code units (RFC 8785 3.2.3).
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(jcs_string(k) + ":" + jcs(value[k]) for k in keys) + "}"
    raise TypeError("not a flat JSON value: %r" % (value,))


def object_digest(obj):
    return bytes_digest(jcs(obj).encode("utf-8"))


# Strict JSON (draft 7.1): duplicate members and non-finite numbers refused.

def _pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate member %r" % k)
        out[k] = v
    return out


def _constant(name):
    raise ValueError("non-finite number %s" % name)


def load_json(path):
    with open(path, "rb") as f:
        data = f.read()
    return json.loads(data.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)


# The baseline HTTP mapping, derived from draft 10.2.

def normalize_origin(origin):
    scheme, sep, authority = origin.partition("://")
    if sep == "" or scheme.lower() != "https" or any(c in authority for c in "/?#@%"):
        raise ConfigError("not an https origin: %r" % origin)
    if not authority.isascii():
        raise ConfigError("non-ASCII origin host: %r" % origin)
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0 or authority[end + 1:] not in ("",) and not authority[end + 1:].startswith(":"):
            raise ConfigError("bad IP literal: %r" % origin)
        host, port = authority[:end + 1], authority[end + 2:]
    else:
        host, _, port = authority.partition(":")
    if host == "":
        raise ConfigError("empty origin host: %r" % origin)
    out = "https://" + host.lower()
    if port not in ("", "443"):
        out += ":" + port
    return out


def check_component(raw, is_path):
    """Allowed octets (RFC 3986 3.3, 3.4), pct-encoded triplets (2.1) and the
    ambiguous encodings of draft 10.2: lowercase hex digits, an encoded
    unreserved character, %2F in the path, decoded octets that are not UTF-8."""
    decoded = bytearray()
    i = 0
    while i < len(raw):
        c = raw[i]
        if c != 0x25:
            if c not in PCHAR and c != 0x2F and (is_path or c != 0x3F):
                raise Refused("octet 0x%02X not allowed" % c)
            decoded.append(c)
            i += 1
            continue
        pair = raw[i + 1:i + 3]
        if len(pair) != 2 or any(d not in HEX_ANY for d in pair):
            raise Refused("malformed escape")
        if any(d not in HEX_UPPER for d in pair):
            raise Refused("lowercase hex digit")
        octet = int(pair.decode("ascii"), 16)
        if octet in UNRESERVED:
            raise Refused("encoded unreserved character")
        if is_path and octet == 0x2F:
            raise Refused("encoded slash in the path")
        decoded.append(octet)
        i += 3
    try:
        bytes(decoded).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise Refused("decoded octets are not UTF-8")


def path_and_query(target):
    if b"#" in target:
        raise Refused("fragment")
    if target.startswith(b"/"):
        return target
    m = re.match(rb"(?i)https?://", target)
    if not m:
        raise Refused("not origin-form or http(s) absolute-form")
    rest = target[m.end():]
    end = len(rest)
    for sep in (b"/", b"?"):
        j = rest.find(sep)
        if 0 <= j < end:
            end = j
    authority, pq = rest[:end], rest[end:]
    if b"@" in authority:
        raise Refused("userinfo")
    if not authority.isascii() or b"%" in authority:
        raise Refused("non-ASCII host")
    if authority.split(b":", 1)[0] == b"":
        raise Refused("empty host")
    if not pq.startswith(b"/"):
        raise Refused("absolute-form without a path")
    return pq


IPV6 = re.compile(
    r"(?i)^(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}"
    r"|(?=(?:[0-9a-f]{0,4}:){0,7}[0-9a-f]{0,4}$)(?:(?:[0-9a-f]{1,4}:){1,7}|:)(?::[0-9a-f]{1,4}){0,7}:?"
    r"|(?:[0-9a-f]{1,4}:){6}(?:\d{1,3}\.){3}\d{1,3}"
    r"|::(?:ffff:)?(?:\d{1,3}\.){3}\d{1,3})$"
)


def valid_host(v):
    """Host = uri-host [ ":" port ] (RFC 9110 7.2; RFC 3986 3.2.2, 3.2.3),
    with a host that is not empty (RFC 9110 4.2.2). Only the forms the
    vectors use need to be right; the IPv6 check is a coarse one."""
    if v.startswith("["):
        end = v.find("]")
        if end < 0:
            return False
        lit, rest = v[1:end], v[end + 1:]
        future = re.fullmatch(r"[vV][0-9A-Fa-f]+\.[A-Za-z0-9\-._~!$&'()*+,;=:]+", lit)
        if not future and ("%" in lit or not IPV6.match(lit)):
            return False
        return rest == "" or (rest[0] == ":" and rest[1:].isascii() and (rest[1:] == "" or rest[1:].isdigit()))
    host, _, port = v.partition(":")
    if host == "" or not re.fullmatch(r"(?:[A-Za-z0-9\-._~!$&'()*+,;=]|%[0-9A-Fa-f]{2})+", host):
        return False
    return port == "" or (port.isascii() and port.isdigit())


def derive(vector):
    """The operation context the baseline mapping gives the vector's request,
    or Refused."""
    cfg, req = vector["config"], vector["request"]
    origin = normalize_origin(cfg["origin"])
    allow = [n.lower() for n in cfg["header_allowlist"]]
    if any(n in NEVER_COVERED or n.startswith(("pact-", "proxy-")) for n in allow):
        raise ConfigError("allowlist names a header that is never covered")

    method = req["method"]
    if method == "" or not all(c.isascii() and c.isalpha() for c in method):
        raise Refused("method")
    method = method.upper()

    pq = path_and_query(req["raw_request_uri"].encode("utf-8"))
    path, has_query, query = pq.partition(b"?")
    check_component(path, True)
    # A complete "." or ".." segment (RFC 3986 3.3) is removed by path
    # segment normalization (6.2.2.3, 5.2.4), so it is ambiguous too.
    if any(seg in (b".", b"..") for seg in path.split(b"/")):
        raise Refused("dot segment")
    if has_query:
        check_component(query, False)
    target = origin + pq.decode("ascii")
    if len(target) > 1024:
        raise Refused("target_uri too long")

    lines = [(h["name"], h["value"]) for h in req["headers"]]
    names = [n.lower() for n, _ in lines]
    # RFC 9112 3.2: a server answers 400 to more than one Host field line
    # (request-binding.md RB-65).
    if names.count("host") > 1:
        raise Refused("more than one Host field line")
    hosts = [v for n, v in lines if n.lower() == "host"]
    # RB-66: an origin-form target has no authority but Host; an absolute-form
    # target carries its own (RFC 9112 3.2.2).
    if not hosts and pq == req["raw_request_uri"].encode("utf-8"):
        raise Refused("no Host field line")
    for v in hosts:
        if not valid_host(v.strip(" \t")):
            raise Refused("invalid Host value")
    if "content-encoding" in names:
        raise Refused("content encoding")
    for n, v in lines:
        if n.lower() == "transfer-encoding" and v.strip(" \t").lower() != "chunked":
            raise Refused("transfer coding")
    body = base64.b64decode(req["body_b64"], validate=True)

    hop = set()
    for n, v in lines:
        if n.lower() == "connection":
            hop |= {t.strip(" \t").lower() for t in v.split(",") if t.strip(" \t")}
    covered = list(allow)
    if body and "content-type" not in covered:
        covered.append("content-type")
    headers = {}
    for name in covered:
        if name in hop:
            continue
        values = [v.strip(" \t") for n, v in lines if n.lower() == name]
        if not values:
            continue
        joined = ", ".join(values)
        if any((ord(c) < 0x20 and c != "\t") or ord(c) == 0x7F for c in joined) or len(joined) > 8192:
            raise Refused("header value")
        headers[name] = joined

    return {
        "operation_id": vector["operation_id"],
        "environment_id": cfg["environment_id"],
        "principal_id": vector["principal_id"],
        "action": vector["action"],
        "resources": list(vector["resources"]),
        "method": method,
        "target_uri": target,
        "body_digest": bytes_digest(body),
        "headers": headers,
    }


# The checks.

def members(obj, want, where, problems):
    if not isinstance(obj, dict) or sorted(obj) != want:
        got = sorted(obj) if isinstance(obj, dict) else type(obj).__name__
        problems.append("%s: members %s, want %s" % (where, got, want))
        return False
    return True


def check_vector(entry, vector, problems):
    vid = entry["id"]
    if not members(vector, VECTOR_MEMBERS, vid, problems):
        return
    members(vector["config"], CONFIG_MEMBERS, vid + " config", problems)
    members(vector["request"], REQUEST_MEMBERS, vid + " request", problems)
    if vector["id"] != vid:
        problems.append("%s: file id %r" % (vid, vector["id"]))
    expect = vector["expect"]
    if not isinstance(expect, dict) or len(expect) != 1 or not ({"operation_context", "reject_reason", "config_error"} & set(expect)):
        problems.append("%s: expect must hold operation_context, reject_reason or config_error" % vid)
        return

    config_error = None
    try:
        derived, refused = derive(vector), None
    except Refused as e:
        derived, refused = None, str(e)
    except ConfigError as e:
        derived, refused, config_error = None, None, str(e)
    except (KeyError, TypeError, ValueError) as e:
        problems.append("%s: cannot be run: %s" % (vid, e))
        return

    if "config_error" in expect:
        if expect["config_error"] is not True:
            problems.append("%s: config_error %r, want true" % (vid, expect["config_error"]))
        if entry["outcome"] != "REJECTED":
            problems.append("%s: outcome %s, the vector expects a configuration error" % (vid, entry["outcome"]))
        if vector["expect_operation_digest"] is not None:
            problems.append("%s: a configuration error has expect_operation_digest null" % vid)
        if config_error is None:
            problems.append("%s: the configuration passed, the vector expects a configuration error" % vid)
        return
    if config_error is not None:
        problems.append("%s: configuration error (%s), the vector expects a request result" % (vid, config_error))
        return

    if "reject_reason" in expect:
        if entry["outcome"] != "REJECTED":
            problems.append("%s: outcome %s, the vector expects a refusal" % (vid, entry["outcome"]))
        if expect["reject_reason"] != "INVALID_MESSAGE":
            problems.append("%s: reject_reason %r, want INVALID_MESSAGE" % (vid, expect["reject_reason"]))
        if vector["expect_operation_digest"] is not None:
            problems.append("%s: a refused vector has expect_operation_digest null" % vid)
        if refused is None:
            problems.append("%s: derived an operation context, the vector expects a refusal" % vid)
        return

    want = expect["operation_context"]
    if entry["outcome"] != "ACCEPTED":
        problems.append("%s: outcome %s, the vector expects an operation context" % (vid, entry["outcome"]))
    if not members(want, CONTEXT_MEMBERS, vid + " operation_context", problems):
        return
    if refused is not None:
        problems.append("%s: refused (%s), the vector expects an operation context" % (vid, refused))
        return
    for k in CONTEXT_MEMBERS:
        if derived[k] != want[k]:
            problems.append("%s: %s is %r, derived %r" % (vid, k, want[k], derived[k]))
    digest = object_digest(want)
    if vector["expect_operation_digest"] != digest:
        problems.append("%s: expect_operation_digest %r, computed %s" % (vid, vector["expect_operation_digest"], digest))
    if vid == APPENDIX_B3_ID and digest != APPENDIX_B3_DIGEST:
        problems.append("%s: digest %s is not the Appendix B.4 operation_digest %s" % (vid, digest, APPENDIX_B3_DIGEST))


def fill(path, vector):
    """Write the computed body_digest and expect_operation_digest."""
    want = vector["expect"].get("operation_context")
    if want is None:
        return False
    body = base64.b64decode(vector["request"]["body_b64"], validate=True)
    new = dict(vector)
    ctx = dict(want)
    ctx["body_digest"] = bytes_digest(body)
    new["expect"] = {"operation_context": ctx}
    new["expect_operation_digest"] = object_digest(ctx)
    if new == vector:
        return False
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(new, indent=2, ensure_ascii=False) + "\n")
    return True


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--write", action="store_true", help="fill in the computed digests first")
    ap.add_argument("--fixtures", default=os.path.join(ROOT, "spec", "v1.0", "fixtures"))
    args = ap.parse_args(argv)

    # Self-check of the digest code against values the draft prints.
    if bytes_digest(b"") != "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU":
        print("binding_vectors: SHA-256 of the empty string is wrong", file=sys.stderr)
        return 2

    try:
        manifest = load_json(os.path.join(args.fixtures, "manifest.json"))
    except (OSError, ValueError) as e:
        print("binding_vectors: manifest: %s" % e, file=sys.stderr)
        return 2
    entries = [e for e in manifest.get("entries", []) if e.get("id", "").startswith(PREFIX)]
    problems = []
    if not entries:
        problems.append("the manifest lists no %s entries" % PREFIX)

    listed = set()
    digests = {}
    for e in entries:
        vid = e["id"]
        if e.get("kind") != "vector" or e.get("scope") != "adapter":
            problems.append("%s: kind/scope %s/%s, want vector/adapter" % (vid, e.get("kind"), e.get("scope")))
        if e.get("path") != vid + ".json" or e.get("expected") != e.get("path"):
            problems.append("%s: path %r expected %r, want %s.json for both" % (vid, e.get("path"), e.get("expected"), vid))
        if not re.fullmatch(r"BIND-[0-9]{2}", e.get("spec_map_row", "")) or e.get("draft_section") != "10.2":
            problems.append("%s: spec_map_row/draft_section %r/%r" % (vid, e.get("spec_map_row"), e.get("draft_section")))
        listed.add(e.get("path"))
        path = os.path.join(args.fixtures, *e.get("path", "").split("/"))
        try:
            vector = load_json(path)
            if args.write and fill(path, vector):
                vector = load_json(path)
        except (OSError, ValueError) as err:
            problems.append("%s: %s" % (vid, err))
            continue
        check_vector(e, vector, problems)
        if isinstance(vector, dict):
            digests[vid[len(PREFIX):]] = vector.get("expect_operation_digest")

    directory = os.path.join(args.fixtures, *PREFIX.rstrip("/").split("/"))
    for name in sorted(os.listdir(directory)) if os.path.isdir(directory) else []:
        if name.endswith(".json") and PREFIX + name not in listed:
            problems.append("%s%s is not listed in the manifest" % (PREFIX, name))
    for a, b, rel in RELATIONS:
        da, db = digests.get(a), digests.get(b)
        if da is None or db is None:
            problems.append("relation %s %s: a vector is missing or refused" % (a, b))
        elif (da == db) != (rel == SAME):
            problems.append("relation %s %s: digests should be %s" % (a, b, rel))
    if APPENDIX_B3_ID not in {e["id"] for e in entries}:
        problems.append("the manifest lacks %s" % APPENDIX_B3_ID)

    for p in problems:
        print("binding_vectors: " + p, file=sys.stderr)
    if problems:
        return 1
    print("binding_vectors: ok (%d vectors, every digest computed independently)" % len(entries))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
