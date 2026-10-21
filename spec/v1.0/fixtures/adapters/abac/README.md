# ABAC adapter cases

These are the cases of the ABAC adapter of the integration profile
[`profiles/abac`](../../../profiles/abac/profile.md): the decision client that
builds the policy input from authoritative facts and asks a policy decision
point (PDP), Open Policy Agent through its REST Data API, for the existing
decision. They run after the common cases, with the case file format, the
outcomes and the checks of [`../README.md`](../README.md). The profile
inherits authentication and agent binding from the mechanism that
authenticated the request (profile section 7), so these cases call
`authorize_native`, `read_native_claim` and `map_operation`; the common cases
cover the other functions. Section 10 of the profile says which case group
each file belongs to, which behaviour is tested outside these files, and
which common case the adapter replaces.

## Model `abac/1`

```
{
  "model": "abac/1",
  "gateway": {"tenant_id", "environment_id", "origin", "header_allowlist"},
  "pdp": {"source_id", "decision_path",
          "policy": "policy.rego", "decision_id",     // the PDP runs the policy
          "answer": {"status", "headers", "body"}     // or answers as stated
                  | {"timeout": true} | {"refused": true},
          "expect_input": {...}},                      // optional
  "entry": {"check_id", "policy_version", "obligations"},   // optional
  "zones": [{"prefix", "zone"}],
  "facts": [{"path", "principal" | "resource" | "device_id", "value",
             "observed_at", "status_checked_at", "source_id", "source_ref"}],
  "sightings": [{"source_id", "source_ref", "observed_at"}],   // optional
  "unavailable_sources": [...]                                  // optional
}
```

Times are Unix seconds.

- `gateway`: the realm the adapter serves, and the trusted configuration of
  the baseline HTTP mapping (draft 10.2), as in `common/1`. The installed
  mapping is revision `pact-abac-1` with the profile's route R1:
  `GET /api/documents/{document_id}` maps to the action `document.read` and
  the one resource `document:{document_id}`.
- `pdp`: the policy decision point. `source_id` is its configured identifier,
  which every decision names (profile section 17); `decision_path` is the
  slash-separated path of the decision document (ABAC-13). The PDP is a
  server reached over TLS; it accepts only the request of ABAC-13: `POST` to
  `/v1/data/{decision_path}` with the query parameter
  `strict-builtin-errors=true`, `Content-Type: application/json`, and a body
  whose only member is `input`. Any other request is answered with status 400,
  which the adapter must take as an outage. Exactly one of `policy` and
  `answer` is present:
  - `policy`: the PDP evaluates the policy of [`assets/policy.rego`](assets/policy.rego)
    on the input and answers 200 with `{"decision_id": <decision_id>,
    "result": <the document pact.abac.decision>}`. The policy is the
    illustrative rule of example I11: it allows a `document.read` when the
    subject's department equals the owning department, the clearance's rank
    in the chain `public`, `internal`, `confidential`, `restricted` is at
    least the classification's, the device is compliant and the zone is
    `corporate`; a document classified `confidential` or above is released
    with the obligations `filter_fields` (`keep` `/title`, `/supplier`,
    `/terms`) and `watermark` (`label` `supplier-review`); every other input
    gets the default denial with no obligation. Its `policy_version` is
    `abac-2026-10-01`.
  - `answer`: the PDP answers every request of the right form with this
    status, these response headers and this body text, octet for octet;
    `timeout`: it does not answer until the adapter gives up; `refused`: no
    connection can be opened.
  - `expect_input`: the PDP compares the `input` it receives with this value
    as JSON data, and answers 400 when they differ. A case that states it pins
    the input of profile section 11.
- `entry`: the installed ABAC check entry of profile ABAC-16 that
  `check_context` runs under `check_id`: the pinned `policy_version` and,
  optionally, the installed obligation set (`obligations`, default the three
  types of ABAC-25). The check runs on the `principal` and `operation` of the
  call and reads `device_id` and `peer_address` from the principal's
  attributes (ABAC-6, ABAC-7). Without `entry` no ABAC check is installed, and
  its id is `UNKNOWN` with `UNSUPPORTED_REQUIREMENT`.
- `zones`: the zone map of trusted gateway configuration: an IP prefix and
  the zone of the addresses in it (ABAC-7). An address in no prefix has no
  zone.
- `facts`: the authoritative fact sources of profile section 8. `path` is the
  approved native path of the fact, one of `/subject/principal_id` (F1),
  `/subject/department` (F2), `/subject/clearance` (F3),
  `/environment/device/compliant` (F4), `/resource/classification` (F5) and
  `/resource/owning_department` (F6). A subject fact names its `principal`, a
  resource fact its `resource`, a device fact the `device_id` it describes.
  `value` is the value as the source gives it, which may be outside the form
  of profile section 11. A time that is absent is a time the source does not
  give; a fact with no record is one the source does not hold. A source
  answers every fact of its `source_id`.
- `sightings`: the observation times that the adapter's guard against
  re-stamping already holds (freshness profile, section 7), as in `common/1`.
- `unavailable_sources`: the `source_id` of each fact source that cannot
  currently answer.

The facts the gateway observes itself are not stated: the network zone (F7)
is derived from the principal attribute `peer_address` with `zones`, and the
time (F8) is the case's `now`, both observed at `now` (ABAC-7). The device of
F4 is the principal attribute `device_id` (ABAC-6). The age limits are those
of profile section 8: `max_age` 30 and `status_max_age` 0 for F1, F3, F5 and
F6; 90 and 60 for F2; 300 and 30 for F4; 0 and 0 for F7 and F8; with the
baseline skew of 5 seconds.

## Hooks

Besides `execute`, an ABAC harness fires the hook `pdp-query` each time a
request reaches the PDP. A case with `must_not_call: ["pdp-query"]` requires
that the adapter made no PDP query, because a fact was not established
(ABAC-8).

## Common cases

A harness realizes the `common/1` state of a common case as well: the
inherited functions are those of the reference model, and for
`authorize_native` the PDP evaluates the `policy` rules of the state. A rule
that applies gives the document `{"allow": <effect is ALLOW>, "obligations":
[{"type": <id>, "params": <attributes>}], "policy_version": <policy_revision>}`
with the rule's `source_ref` as `decision_id`; an `UNKNOWN` rule gives no
`result`; no rule gives the denial with no obligation. The PDP's `source_id`
is that of the rules, and the harness gives the facts F1 to F6 for the
principal and the resource of the call, and a zone for its `peer_address`,
since the common policy reads none of them.

## Integration tier

The cases whose PDP runs `policy` also run against a real OPA server that
loads [`assets/policy.rego`](assets/policy.rego) with decision logging
enabled. OPA chooses the `decision_id`, so that tier checks that the decision
names one and compares the effect, the obligations and the policy revision.
The cases whose PDP states an `answer` run in the unit tier only.
