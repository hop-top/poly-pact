"""The validator's keys and configuration, read from a case's config.json."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from datetime import timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, derive_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hop_top_pact import validator
from hop_top_pact.adapter import Realm
from hop_top_pact.conformance import Config
from hop_top_pact.core import jws, limits
from hop_top_pact.core.jws import base64url

KEYS_FILE = "keys/test-private-scalars.json"


@dataclass(frozen=True)
class PrivateKey:
    """One entry of keys/test-private-scalars.json: published test values, never production
    keys."""

    kid: str
    alg: str
    d: str
    public_jwk: str


def load_private_keys(fixtures: Path) -> dict[str, PrivateKey]:
    """The test private values by public JWK file name."""
    f = json.loads((fixtures / KEYS_FILE).read_bytes())
    return {
        k["public_jwk"]: PrivateKey(k["kid"], k["alg"], k["d"], k["public_jwk"]) for k in f["keys"]
    }


def signer_for(keys: dict[str, PrivateKey], key_file: str) -> validator.Signer:
    """The signer of the validator key file key_file (a path under the fixture directory)."""
    k = keys.get(Path(key_file).name)
    if k is None:
        raise ValueError(f"no private value for {key_file}")
    d = base64url.decode(k.d)
    if k.alg == jws.ALG_ES256:
        return validator.ES256Signer(
            kid=k.kid, key=derive_private_key(int.from_bytes(d, "big"), SECP256R1())
        )
    if k.alg == jws.ALG_ED25519:
        return validator.Ed25519Signer(kid=k.kid, key=Ed25519PrivateKey.from_private_bytes(d))
    raise ValueError(f"{key_file}: algorithm {k.alg!r}")


def key_set(fixtures: Path, algs: jws.Algorithms, files: tuple[str, ...]) -> jws.KeySet:
    """Public JWK files read into a key set of the algorithms algs."""
    return algs.new_key_set(*(algs.parse_jwk((fixtures / f).read_bytes()) for f in files))


def limits_of(m: Any) -> limits.Limits:
    """The metadata limits of draft 20.1 as the validator's; the evaluate transport bounds
    the presentation (draft 13.2)."""
    lim = limits.defaults()

    def lower(field_name: str, key: str) -> limits.Limits:
        v = m.get(key)
        if v is not None and v > 0 and v < getattr(lim, field_name):
            return replace(lim, **{field_name: v})
        return lim

    for field_name, key in (
        ("presentation_bytes", limits.KEY_MAX_PRESENTATION_BYTES),
        ("presentation_bytes", "max_evaluate_presentation_bytes"),
        ("artifact_payload_bytes", "max_artifact_payload_bytes"),
        ("profile_bytes", "max_profile_bytes"),
        ("evidence_artifacts", "max_evidence_artifacts"),
        ("field_rules", "max_field_rules"),
        ("depth", "max_json_depth"),
        ("resources", "max_resources"),
        ("description_bytes", "max_description_bytes"),
    ):
        lim = lower(field_name, key)
    return lim


def realm_of(c: Config) -> Realm:
    return Realm(tenant_id=c.gateway.tenant_id, environment_id=c.gateway.environment_id)


def validator_config(fixtures: Path, c: Config) -> validator.Config:
    """config.json as the validator's trusted configuration."""
    algs = jws.Algorithms(c.gateway.algorithms())
    publishers: dict[str, jws.KeySet] = {}
    issuers: list[validator.Issuer] = []
    services: list[validator.Issuer] = []
    for t in c.trust:
        ks = key_set(fixtures, algs, t.keys)
        if t.role == jws.Role.REQUIREMENT_PUBLISHER:
            publishers[t.iss] = ks
        elif t.role == jws.Role.ISSUER:
            issuers.append(validator.Issuer(id=t.iss, keys=ks, claim_paths=t.claim_paths))
        elif t.role == jws.Role.REPUTATION_SERVICE:
            services.append(validator.Issuer(id=t.iss, keys=ks, claim_paths=t.claim_paths))
    mappings = []
    for m in c.native_mappings:
        src = None
        if m.source is not None:
            src = validator.SourceCapability(
                source_id=m.source.source_id,
                best_max_age_seconds=m.source.best_max_age_seconds,
                best_status_max_age_seconds=m.source.best_status_max_age_seconds,
                live_check=m.source.live_check,
            )
        mappings.append(validator.NativeMapping(path=m.path, native_path=m.native_path, source=src))
    return validator.Config(
        audience=c.gateway.gateway_id,
        realm=realm_of(c),
        issuer=c.validator.iss,
        source_id=c.validator.source_id,
        publishers=publishers,
        issuers=issuers,
        reputation_services=services,
        algorithms=algs,
        skew=timedelta(seconds=c.clock_skew_seconds),
        limits=limits_of(c.limits),
        evaluation_time=timedelta(seconds=c.limits.get("evaluation_seconds", 0)),
        native_mappings=mappings,
        installed_checks=c.installed_checks,
        supported_extensions=c.gateway.extensions_supported,
    )
