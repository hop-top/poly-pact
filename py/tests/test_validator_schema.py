"""The restricted schema keyword set of Appendix A.1, JSON Pointer lookup and the claim
comparison. Port of go/validator/schema_test.go."""

from __future__ import annotations

import pytest

from hop_top_pact.validator import _schema as s

SCHEMA = [
    ("true", '{"a":1}', True),
    ("false", "null", False),
    ('{"type":"string"}', '"x"', True),
    ('{"type":"string"}', "1", False),
    ('{"type":"integer"}', "9000", True),
    ('{"type":"integer"}', "9000.0", True),
    ('{"type":"integer"}', "9000.5", False),
    ('{"type":["string","null"]}', "null", True),
    ('{"const":"managed"}', '"managed"', True),
    ('{"const":"managed"}', '"unmanaged"', False),
    ('{"const":{"a":1,"b":[1,2]}}', '{"b":[1,2],"a":1.0}', True),
    ('{"const":[1,2]}', "[2,1]", False),
    ('{"enum":["a","b"]}', '"b"', True),
    ('{"enum":["a","b"]}', '"c"', False),
    ('{"minimum":9000,"type":"integer"}', "9259", True),
    ('{"minimum":9000,"type":"integer"}', "8800", False),
    ('{"minimum":9000}', "9000", True),
    ('{"exclusiveMinimum":9000}', "9000", False),
    ('{"maximum":1}', "1.0000000000000000001", False),
    ('{"exclusiveMaximum":10}', "9.99", True),
    ('{"minimum":5}', '"text"', True),
    ('{"minLength":1,"type":"string"}', '""', False),
    ('{"maxLength":2}', '"éé"', True),
    ('{"maxLength":2}', '"abc"', False),
    (
        '{"type":"array","items":{"type":"string"},"uniqueItems":true,'
        '"contains":{"const":"finance-reader"}}',
        '["finance-reader"]',
        True,
    ),
    (
        '{"type":"array","items":{"type":"string"},"uniqueItems":true,'
        '"contains":{"const":"finance-reader"}}',
        '["finance-approver"]',
        False,
    ),
    ('{"uniqueItems":true}', "[1,1.0]", False),
    ('{"contains":{"const":1},"minContains":2}', "[1,2,1]", True),
    ('{"contains":{"const":1},"maxContains":1}', "[1,2,1]", False),
    ('{"contains":{"const":1},"minContains":0}', "[2]", True),
    ('{"minItems":2}', "[1]", False),
    ('{"maxItems":1}', "[1]", True),
    ('{"properties":{"a":{"type":"string"}},"required":["a"]}', '{"a":"x"}', True),
    ('{"properties":{"a":{"type":"string"}},"required":["a"]}', "{}", False),
    (
        '{"properties":{"a":{"type":"string"}},"additionalProperties":false}',
        '{"a":"x","b":1}',
        False,
    ),
    (
        '{"properties":{"a":{"type":"string"}},"additionalProperties":false}',
        '{"a":"x"}',
        True,
    ),
    ('{"allOf":[{"type":"integer"},{"minimum":1}]}', "0", False),
    ('{"anyOf":[{"const":1},{"const":2}]}', "2", True),
    ('{"oneOf":[{"type":"integer"},{"minimum":0}]}', "5", False),
    ('{"not":{"const":"chat"}}', '"chat"', False),
]


@pytest.mark.parametrize(("schema", "instance", "want"), SCHEMA)
def test_schema(schema: str, instance: str, want: bool) -> None:
    # Instances whose verdict follows from JSON Schema Draft 2020-12.
    compiled = s.compile_schema(schema.encode())
    assert s.matches(compiled, s.decode_json(instance.encode())) is want


UNSUPPORTED = [
    '{"isolationLevel":"strict","const":"managed"}',
    '{"pattern":"^a"}',
    '{"$ref":"#/x"}',
    '{"format":"uri"}',
    '{"properties":{"a":{"pattern":"x"}}}',
    '{"allOf":[]}',
    '{"type":"decimal"}',
    '{"minLength":-1}',
    '{"minItems":1.5}',
    '{"uniqueItems":"yes"}',
    '"string"',
    "{" + '"not":{' * 17 + "true" + "}" * 17 + "}",
    "not json",
]


@pytest.mark.parametrize("schema", UNSUPPORTED)
def test_schema_unsupported(schema: str) -> None:
    # A keyword outside Appendix A.1, at any depth, or a malformed keyword value, is never
    # evaluated permissively (draft 22.2).
    with pytest.raises(s.UnsupportedSchemaError):
        s.compile_schema(schema.encode())


def test_pointer() -> None:
    doc = s.decode_json(b'{"a":{"b/c":[10,{"~d":true}]},"":1}')
    cases = {
        "/a/b~1c/0": True,
        "/a/b~1c/1/~0d": True,
        "/": True,
        "/a/x": False,
        "/a/b~1c/2": False,
        "/a/b~1c/01": False,
        "a": False,
    }
    for p, want in cases.items():
        assert (s.pointer(doc, p) is not s.NOT_FOUND) is want, p
    assert s.pointer(doc, "") is doc


COMPARE = [
    ("equal", '["a","b"]', '["a","b"]', True),  # equal arrays
    ("equal", '["a","b"]', '["b","a"]', False),  # array order is significant (8.4)
    ("equal", '{"x":1,"y":2}', '{"y":2,"x":1}', True),  # member order is ignored (8.4)
    ("subset", '["a"]', '["a","b"]', True),  # presented within authoritative
    ("subset", '["c"]', '["a","b"]', False),  # presented outside authoritative
    ("subset", '["a","a"]', '["a","b"]', False),  # values must be unique
    ("subset", '[{"a":1}]', '[{"a":1}]', False),  # values must be scalars
    ("other", "1", "1", False),  # unknown comparison never matches
]


@pytest.mark.parametrize(("cmp", "p", "a", "want"), COMPARE)
def test_compare(cmp: str, p: str, a: str, want: bool) -> None:
    got = s.compare(cmp, s.decode_json(p.encode()), s.decode_json(a.encode()))
    assert got is want
