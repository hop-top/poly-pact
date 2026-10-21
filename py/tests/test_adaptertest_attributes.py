"""The authenticated attributes of a principal (port of
go/adapter/adaptertest/attributes_test.go)."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from hop_top_pact.adapter import Principal
from hop_top_pact.adapter.adaptertest import ExpectPrincipal, LoadError, load_cases

JKT = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"


def test_principal_attributes(at: Any) -> None:
    def with_attrs(attrs: dict[str, Any]) -> Principal:
        p: Principal = at.good_principal()
        return replace(p, attributes=attrs)

    def want(attrs: object) -> ExpectPrincipal:
        return ExpectPrincipal(id=at.good_principal().id, attributes=attrs)

    cnf = {"jkt": JKT}
    at.run_rows(
        [
            (
                "equal",
                at.auth_fake(with_attrs({"cnf": cnf}), None),
                at.auth_case("authenticated", principal=want({"cnf": {"jkt": JKT}})),
                (),
            ),
            (
                "unnamed attribute not checked",
                at.auth_fake(with_attrs({"cnf": cnf, "groups": ("a",)}), None),
                at.auth_case("authenticated", principal=want({"cnf": {"jkt": JKT}})),
                (),
            ),
            (
                "member order ignored",
                at.auth_fake(with_attrs({"x": {"a": 1, "b": 2}}), None),
                at.auth_case("authenticated", principal=want({"x": {"b": 2, "a": 1}})),
                (),
            ),
            (
                "other value",
                at.auth_fake(with_attrs({"cnf": {"jkt": "other"}}), None),
                at.auth_case("authenticated", principal=want({"cnf": {"jkt": JKT}})),
                ("principal attribute 'cnf'",),
            ),
            (
                "missing attribute",
                at.auth_fake(with_attrs({}), None),
                at.auth_case("authenticated", principal=want({"cnf": {"jkt": "a"}})),
                ("principal has no attribute 'cnf'",),
            ),
            (
                "array order kept",
                at.auth_fake(with_attrs({"groups": ("b", "a")}), None),
                at.auth_case("authenticated", principal=want({"groups": ("a", "b")})),
                ("principal attribute 'groups'",),
            ),
            (
                "absent member not checked",
                at.auth_fake(with_attrs({"cnf": cnf}), None),
                at.auth_case("authenticated", principal=ExpectPrincipal(id=at.good_principal().id)),
                (),
            ),
            (
                "attribute that does not encode",
                at.auth_fake(with_attrs({"cnf": object()}), None),
                at.auth_case("authenticated", principal=want({"cnf": {"jkt": JKT}})),
                ("does not encode as JSON",),
            ),
        ]
    )


def test_principal_attributes_must_be_an_object(at: Any) -> None:
    c = at.MINIMAL_CASE.replace(
        '"outcome": "denied"}',
        '"outcome": "authenticated", "principal": {"id": "p", "attributes": ["cnf"]}}',
        1,
    )
    with pytest.raises(LoadError, match="attributes is not a JSON object"):
        load_cases(at.tree_of({"adapters/_common/a.json": c}))
