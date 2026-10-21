"""descriptors_of: one GatewayMetadata.adapters entry per pinned protocol revision.

Port of go/adapter/descriptors_test.go (draft 13.3).
"""

from __future__ import annotations

from dataclasses import replace

from hop_top_pact.adapter import Adapter, Descriptor, descriptors_of


class Single:
    """An adapter that publishes one descriptor; the seven functions are not called."""

    def __init__(self, d: Descriptor) -> None:
        self.d = d

    def describe(self) -> Descriptor:
        return self.d


class Multi(Single):
    """An adapter that serves several native protocol forms."""

    def __init__(self, d: Descriptor, ds: list[Descriptor]) -> None:
        super().__init__(d)
        self.ds = ds

    def descriptors(self) -> list[Descriptor]:
        return self.ds


def as_adapter(a: object) -> Adapter:
    return a  # type: ignore[return-value]


def test_descriptors_of() -> None:
    intro = Descriptor(
        protocol="oauth-introspection", version="rfc7662", mapping_revision="pact-oauth-1"
    )
    entra = Descriptor(
        protocol="entra-access-token", version="2.0", mapping_revision="pact-oauth-1"
    )
    assert descriptors_of(as_adapter(Single(intro))) == [intro]
    assert descriptors_of(as_adapter(Multi(intro, [intro, entra]))) == [intro, entra]
    ds = [intro]
    got = descriptors_of(as_adapter(Multi(intro, ds)))
    got[0] = replace(got[0], protocol="changed")
    got.append(entra)
    assert ds == [intro], "the result shares the adapter's list"
