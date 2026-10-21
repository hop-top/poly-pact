"""The credential scan of draft 19 (port of go/adapter/adaptertest/leak_test.go).

A returned value is scanned in its JSON form with its field names as members;
an error with the text of everything it wraps (__cause__, else __context__).
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from hop_top_pact.adapter import (
    CheckOutcome,
    ContextMismatch,
    Decision,
    Effect,
    NativeDenial,
    NoVisibility,
    Principal,
    Verdict,
)
from hop_top_pact.adapter.adaptertest import ExpectClaim, ExpectOperation, LeakScan
from hop_top_pact.adapter.adaptertest.leak import find_credentials
from hop_top_pact.core.enums import EventKind, OutcomeResult

FIND_CREDENTIALS: list[tuple[str, str, tuple[str, ...], tuple[str, ...]]] = [
    ("clean", '{"Result":"PASS","ReasonCode":"REQUIREMENT_SATISFIED"}', (), ()),
    (
        "prose that is not a credential",
        "basic authentication failed; the bearer is unknown",
        (),
        (),
    ),
    (
        "event kind is not a header",
        '{"event_kind":"AUTHORIZATION","details":"authorization denied"}',
        (),
        (),
    ),
    (
        "literal secret",
        "failed for tok-alice-7f3a",
        ("tok-alice-7f3a",),
        ("secret 'tok-alice-7f3a'",),
    ),
    ("empty secret is ignored", "anything", ("",), ()),
    ("bearer value", "Authorization: Bearer abcdefghijklmnop1234", (), ("authorization value",)),
    ("short bearer is not a value", "Bearer abc", (), ()),
    ("basic value", "Basic dXNlcjpwYXNzd29yZDEyMzQ1", (), ("authorization value",)),
    (
        "compact JWS",
        "token eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl",
        (),
        ("compact JWS",),
    ),
    (
        "authorization header member",
        '{"headers":{"authorization":"x"}}',
        (),
        ("credential header as a member name",),
    ),
    (
        "cookie header member, any case",
        '{"Cookie" :"x"}',
        (),
        ("credential header as a member name",),
    ),
    (
        "presentation header member",
        '{"pact-presentation":"x"}',
        (),
        ("credential header as a member name",),
    ),
    ("private JWK d", '{"kty":"EC","d":"abc"}', (), ("private JWK parameter",)),
    ("private JWK k", '{"kty":"oct","k":"abc"}', (), ("private JWK parameter",)),
    ("public JWK", '{"kty":"EC","x":"abc","y":"def"}', (), ()),
    (
        "access token in a URL",
        "https://e.example/a?access_token=tok-evidence-5c0e8b13",
        (),
        ("credential assignment",),
    ),
    ("session cookie value", "session=sess-cookie-93ab1f60", (), ("credential assignment",)),
    ("password", "password=hunter22", (), ("credential assignment",)),
    ("redaction mask in brackets", "access_token=[redacted]", (), ()),
    ("redaction mask in words", "session=REDACTED password=removed", (), ()),
    ("redaction mask in stars", "secret=****** api_key=xxxxxxxx", (), ()),
    (
        "mask followed by a credential",
        "access_token=[redacted] session=sess-cookie-93ab1f60",
        (),
        ("credential assignment",),
    ),
    ("short value is not a credential", "sid=abc", (), ()),
]


def test_find_credentials() -> None:
    for name, text, secrets, want in FIND_CREDENTIALS:
        got = find_credentials(text, secrets)
        if not want:
            assert not got, f"{name}: found {got} in {text!r}"
            continue
        for w in want:
            assert any(w in g for g in got), f"{name}: findings {got} lack {w!r}"


def leak_case(at: Any, *secrets: str) -> Any:
    """A leak scan of an authenticate_native case that the fake answers with an
    error."""
    return at.auth_case("denied", leak_scan=LeakScan(secrets=secrets))


def test_leak_scan_of_errors(at: Any) -> None:
    denial = NativeDenial("CREDENTIAL_REJECTED")
    fake = at.auth_fake
    at.run_rows(
        [
            ("clean denial", fake(None, denial), leak_case(at, "tok-forged-4e1d7a09"), ()),
            (
                "token in a wrapping error",
                fake(None, at.wrap("token tok-forged-4e1d7a09 rejected", denial)),
                leak_case(at, "tok-forged-4e1d7a09"),
                ("error carries a credential", "tok-forged-4e1d7a09"),
            ),
            (
                "bearer value in a wrapping error",
                fake(None, at.wrap("Bearer abcdefghijklmnop1234", denial)),
                leak_case(at),
                ("authorization value",),
            ),
            (
                "token in the context of an error",
                fake(None, _in_context("tok-forged-4e1d7a09", NativeDenial("CREDENTIAL_REJECTED"))),
                leak_case(at, "tok-forged-4e1d7a09"),
                ("error carries a credential",),
            ),
            (
                "no scan asked, no scan made",
                fake(None, at.wrap("token tok-forged-4e1d7a09 rejected", denial)),
                at.auth_case("denied"),
                (),
            ),
        ]
    )


def _in_context(secret: str, err: BaseException) -> BaseException:
    """err raised while handling an error that names secret: the secret is in
    err.__context__."""
    try:
        try:
            raise ValueError("lookup of " + secret + " failed")
        except ValueError:
            raise err  # noqa: B904
    except BaseException as e:
        return e


def test_leak_scan_of_values(at: Any) -> None:
    scan = LeakScan(secrets=("tok-secret-1234",))

    # operation
    leaky = replace(at.good_op(), headers={"authorization": "x"})
    c = at.map_case("mapped", operation=ExpectOperation(), leak_scan=scan)
    at.want_clean(at.run_fake(at.map_fake(at.good_op(), None), c))
    at.want_fails(at.run_fake(at.map_fake(leaky, None), c), "operation carries a credential")
    leaky = replace(at.good_op(), headers={"x-kind": "tok-secret-1234"})
    at.want_fails(at.run_fake(at.map_fake(leaky, None), c), "secret 'tok-secret-1234'")

    # operation error
    c = at.map_case("error", leak_scan=scan)
    at.want_clean(at.run_fake(at.map_fake(None, ContextMismatch()), c))
    at.want_fails(
        at.run_fake(at.map_fake(None, ContextMismatch("tok-secret-1234")), c),
        "map_operation error carries a credential",
    )

    # check outcome
    c = at.check_case("x", "PASS", leak_scan=scan)
    clean = CheckOutcome(result=Verdict.PASS, reason_code="R", source_ref="appr-42")
    leaky_out = replace(clean, source_ref="https://e.example/a?access_token=tok-secret-1234")
    at.want_clean(at.run_fake(at.check_fake(clean), c))
    at.want_fails(
        at.run_fake(at.check_fake(leaky_out), c), "check_context outcome carries a credential"
    )

    # claim
    c = at.claim_case("claim", claim=ExpectClaim(), leak_scan=scan)
    at.want_clean(at.run_fake(at.claim_fake(at.good_claim(), None), c))
    leaky_claim = replace(at.good_claim(), source_ref="tok-secret-1234")
    at.want_fails(at.run_fake(at.claim_fake(leaky_claim, None), c), "claim carries a credential")

    # decision
    c = at.authz_case("DENY", leak_scan=scan)
    at.want_clean(
        at.run_fake(at.authz_fake(Decision(effect=Effect.DENY, source_id="policy-1"), None), c)
    )
    leaky_decision = Decision(effect=Effect.DENY, reason="tok-secret-1234", source_id="policy-1")
    at.want_fails(
        at.run_fake(at.authz_fake(leaky_decision, None), c), "decision carries a credential"
    )

    # principal
    from hop_top_pact.adapter.adaptertest import ExpectPrincipal

    c = at.auth_case("authenticated", principal=ExpectPrincipal(), leak_scan=scan)
    p: Principal = at.good_principal()
    at.want_clean(at.run_fake(at.auth_fake(p, None), c))
    p = replace(p, attributes={"token": "tok-secret-1234"})
    at.want_fails(at.run_fake(at.auth_fake(p, None), c), "principal carries a credential")

    # signed outcome, decoded
    c = at.record_case("signed", EventKind.EXECUTION, OutcomeResult.SUCCESS, leak_scan=scan)
    at.want_clean(at.run_fake(at.signed_fake(), c))

    def details(text: str) -> Any:
        def mod(parts: Any) -> None:
            parts.rep["details"] = text

        return mod

    def refs(parts: Any) -> None:
        parts.rep["evidence_refs"] = ["https://e.example/x?access_token=abcdef123456"]

    # A credential in the payload is base64url in the JWS string, so only the
    # decoded payload shows it.
    at.want_fails(
        at.run_fake(at.signed_fake(details("rejected: tok-secret-1234")), c),
        "signed outcome segment 1 carries a credential",
    )
    at.want_fails(
        at.run_fake(at.signed_fake(details("Authorization: Bearer abcdefghijklmnop1234")), c),
        "authorization value",
    )
    at.want_fails(at.run_fake(at.signed_fake(refs), c), "credential assignment")
    # A masked value is not a credential.
    at.want_clean(
        at.run_fake(at.signed_fake(details("Authorization: [redacted] access_token=[redacted]")), c)
    )

    # no visibility declaration
    c = at.record_case("no_visibility", EventKind.EXECUTION, OutcomeResult.SUCCESS, leak_scan=scan)
    at.want_clean(at.run_fake(at.record_fake(NoVisibility(reason="cannot see"), None), c))
    at.want_fails(
        at.run_fake(at.record_fake(NoVisibility(reason="cannot see tok-secret-1234"), None), c),
        "declaration carries a credential",
    )


def test_leak_scan_runs_on_every_error(at: Any) -> None:
    """One error per function, each carrying the secret."""
    secret_err = at.Wrapped("tok-secret-1234")
    scan = LeakScan(secrets=("tok-secret-1234",))
    raise_it = at.result_of(None, secret_err)
    fake = at.FakeAdapter(
        auth=raise_it, bind=raise_it, claim=raise_it, authz=raise_it, record=raise_it
    )
    for name, c in {
        "authenticate": at.auth_case("error", leak_scan=scan),
        "binding": at.bind_case("error", leak_scan=scan),
        "claim": at.claim_case("error", leak_scan=scan),
        "authorize": at.authz_case("error", leak_scan=scan),
        "record": at.record_case(
            "error", EventKind.EXECUTION, OutcomeResult.SUCCESS, leak_scan=scan
        ),
    }.items():
        fails = at.run_fake(fake, c)
        assert any("error carries a credential" in f for f in fails), f"{name}: {fails}"
