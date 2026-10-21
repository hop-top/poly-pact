# Adapter conformance cases

These files are the language-neutral cases of the native adapter conformance
suite. An adapter implements the seven functions of draft section 17.1; a case
calls one of them with a stated native state and says what the draft requires
back. A harness in any language reads the JSON, builds the adapter under test,
makes the call and compares. The Go harness is the package `adaptertest` in the
Go module of this repository; this document is what an implementer in another
language needs.

```
adapters/
  README.md            this file
  _common/*.json       cases every adapter must pass
  <name>/*.json        the cases of one adapter, named by its mechanism
```

Every case file is registered in `../manifest.json` with kind `adapter-case`
and scope `adapter`, under the id `adapters/<name>/<file name without .json>`,
such as `adapters/_common/common-03.fragment`; an adapter's cases sit directly
in its directory, as the common cases do, with no `cases/` subdirectory. The
manifest entry gives the case's path, cites the group (`COMMON-03`) in
`spec_map_row` and the first draft section in `draft_section`,
and records in `outcome` whether the case expects the adapter to let the
stimulus through or to refuse or withhold: `ACCEPTED` for the outcomes
`authenticated`, `bound`, `mapped`, `claim`, `signed`, `ALLOW` and `PASS`, and
`REJECTED` for every other.

## Running the suite

In Go:

```go
func TestConformance(t *testing.T) {
	adaptertest.Run(t, factory, adaptertest.Options{Adapter: "mymechanism"})
}
```

`Run` reads `_common` and then the case files of `adapters/<Adapter>` from a
fixture tree and runs one subtest per case. An adapter whose integration
profile supports workloads shared by several agents sets `SharedWorkloads: true`
in the options (see `workloads` below). An adapter whose mechanism cannot realize a common `authenticate_native` or `authorize_native` case declares it replaced, with the reason and the id of its own case that covers the same property (`Options.Replaced`); see "Replaced common cases". The default tree is `../spec/v1.0/fixtures` relative
to the directory that holds `go.mod`, which works inside the source repository.
A module that imports the package from the Go-only mirror passes the spec
mirror's fixture directory instead:

```go
adaptertest.Options{Fixtures: os.DirFS("path/to/spec-pact/v1.0/fixtures")}
```

Other languages implement the loop below.

1. Read every `*.json` file of `_common`, then of the adapter's own
   directory `adapters/<name>`. Parse each file with a strict parser:
   duplicate member names and unknown members are errors.
2. Skip a case whose `workloads` member does not match the adapter's profile:
   `shared` runs only for a profile that supports shared workloads,
   `dedicated` only for one that does not. For each other case, build a fresh
   adapter from `native_state`, with the clock held at `now`.
3. Build the request, call `expect.function`, and check the result against
   `expect`, as the sections below define.
4. A case passes when no check fails.

## Case file

A case file is one JSON object. Members not listed here are an error.

| Member | Type | Meaning |
|---|---|---|
| `case_version` | integer | Always `1`. |
| `id` | string | `FAMILY-NN` or `FAMILY-NN.variant`, for example `COMMON-03.fragment`. The family is capitals and digits, `NN` at least two digits, the variant lowercase words joined by hyphens. Ids are stable and unique. |
| `title` | string | One line, what the case shows. |
| `draft` | array of strings | Draft section numbers the case rests on. |
| `workloads` | string, optional | `shared`: the case applies only to an adapter whose integration profile supports workloads shared by several agents. `dedicated`: only to an adapter whose profile does not, the default of identity mapping rule IM-19. Absent: to every adapter. |
| `now` | integer, optional | The case's current time in Unix seconds. Default `1792080000`. |
| `native_state` | object | The native state the adapter starts from. The suite does not read it. |
| `request` | object | The HTTP request. Required for `authenticate_native` and `map_operation`, forbidden for the other functions. |
| `call` | object | The other arguments of the function. |
| `expect` | object | What the draft requires. |

The file name is the lowercase id followed by `.json`: `common-03.fragment.json`.

### request

| Member | Type | Meaning |
|---|---|---|
| `method`, `url` | string | Required. `url` is absolute and is kept exactly as written, so a fragment or userinfo reaches the adapter. It is also the request-target the gateway received, in absolute-form (RFC 9112 §3.2.2), octet for octet. |
| `headers` | object | Name to value, one value per name. A `Host` entry sets the request's host. |
| `body_b64` | string | The body, standard base64 with padding. Absent for no body. |
| `tls_peer` | object | A client certificate: `subject_cn`, `issuer_cn`, `dns_names`, `uris`. For mutual-TLS adapters. |
| `native_state_ref` | string | Names the identity of `native_state` whose credential the request presents. The harness attaches it in the form the adapter's mechanism reads. |
| `arrival` | string | `enforcement_point` (default) or `direct`. A direct request did not come through the enforcement point. |

### call

Which members a case sets depends on the function; setting another is an error.

| Function | Required | Optional |
|---|---|---|
| `authenticate_native` | none | |
| `resolve_agent_binding` | `realm`, `workload`, `agent_id` | |
| `map_operation` | `principal`, `mapping_version` | |
| `read_native_claim` | `principal`, `native_path` | `intent`, `operation` |
| `check_context` | `check_id`, `principal`, `operation` | `binding`, `intent`, `evidence_refs` |
| `authorize_native` | `principal`, `operation` | |
| `record_outcome` | `observation` | |

`realm` is `{tenant_id, environment_id}`. For `resolve_agent_binding`,
`realm` and `workload` are those of the authenticated principal and `agent_id`
is the agent ID the request names (draft 17.1). `principal` is `{id, realm,
workload, mechanism, authenticated_at, attributes}`; `mechanism` defaults to
`test` and `authenticated_at` to `now`. `attributes` are further authenticated
attributes of the request, as `authenticate_native` would have set them. Two
have fixed names that an adapter's profile may rely on: `device_id`, the
identifier of the device whose credential native authentication validated, and
`peer_address`, the transport-level peer address of the connection, as text.
An adapter whose profile reads neither ignores them; neither names the
principal. `operation` is an `OperationContext`,
`intent` an `Intent`, and `observation` has the members of an outcome report
that the observed system determines (draft 14.1: `event_id` through `details`).

For `read_native_claim`, `principal`, `intent` and `operation` are the context
of draft 17.1 ("approved native path and context"): the authenticated
principal, the declared intent and the actual operation. The approved mapping
decides which part a path uses: a subject path the principal, a resource path
the resources of the operation, a task path the `task_id` of the intent. An
absent `intent` or `operation` is passed as an empty one.

For `check_context`, `principal` is the authenticated principal the validator
established, as `authenticate_native` returned it, and its `id` equals
`operation.principal_id` (draft 12.1). `binding` is `{agent_id, operator_id,
holder_jkt, status}`, the binding of the agent the request names as
`resolve_agent_binding` returned it and the validator verified it (draft 11.3
step 2), with `status` `ACTIVE` unless the case says otherwise. A check that
compares the agent or the principal compares against these two, never against
the operation's text (draft 17.1). An absent `binding` is passed as an empty
binding: the caller established no agent, and a check that compares the agent
then fails its scope comparison and is never `PASS`.

### expect

| Member | Meaning |
|---|---|
| `function` | One of the seven function names of the draft 17.1 table. |
| `outcome` | One of the outcomes defined below for the function. |
| `reason_code` | The stable code the function reports, when the case pins one. The Go harness also requires the error to be, or to wrap, the sentinel of package `adapter` for that code, so that `errors.Is` matches it; the case file names the code string only. |
| `must_not_call` | Names of native hooks that must not have fired by the end of the case. |
| `leak_scan` | `{secrets: [...]}`. Requires that no credential appears in what the function returns. |
| `principal`, `binding`, `operation`, `claim`, `decision` | The values to compare, for the function that takes them. `principal.attributes`, when present, is compared as JSON data, member by member. |

A member of an `expect` object that is absent, or an empty string, is not
checked. Where `null` is meaningful it is stated.

## Outcomes and checks

Besides the outcome of the case, the suite checks what the draft requires of
every result of the function. A case cannot switch these off.

### authenticate_native

- `authenticated`: no error. `expect.principal` lists `id`, `realm`,
  `workload` and `mechanism` to compare, and `attributes`, an object whose
  members are compared as JSON data with the principal's authenticated
  attributes of the same names, when present: object member order is ignored,
  array order is not, and an attribute the object does not name is not
  checked. `AuthenticatedAt` is not later than `now` plus the skew.
- `denied`: a native denial, which is an `INVALID_PROOF`, with the public reason
  `NO_CREDENTIAL` or `CREDENTIAL_REJECTED`. `reason_code` names which.
  The reason follows the mechanism's own response class: `NO_CREDENTIAL`
  when the mechanism answers as it does to a request with no authentication
  information, which for a mechanism whose RFC says so (RFC 6750 §3.1)
  includes a credential of an unsupported scheme; `CREDENTIAL_REJECTED` when
  it reads a credential and refuses it. A profile states which a foreign
  scheme is. No
  principal comes back with it.
- `error`: any other error; `reason_code` is its draft 13.4 code.
- A nil error with a zero principal is always a failure.

### resolve_agent_binding

- `bound`: status `ACTIVE`, an absolute `agent_id`, a 43-character holder key
  thumbprint, a source, and `ObservedAt` and `StatusCheckedAt` not later than
  `now` plus the skew (draft A.2). `expect.binding` lists `agent_id`,
  `operator_id`, `holder_jkt`, `status`.
- `unknown`: no error, status `UNKNOWN`, and no agent, operator or holder key.
  This is the answer when the agent has no record on the workload in the
  realm, including an agent enrolled only for another workload or in another
  realm (see `enrollments` below). `expect.binding`, when present, holds only
  `enrolled_elsewhere`: whether the answer reports the agent ID enrolled for
  another workload of the realm, in any status (draft 17.1). An enrollment in
  another realm never sets it.
- `unusable`: no result a caller could use as an active binding, in the one
  form that identity mapping rule IM-11
  ([`identity-mapping.md`](../../profiles/identity-mapping.md)) gives: no
  error, and the binding with the status `REVOKED` or `COMPROMISED`, with the
  agent, operator and holder key of the record, so that a validator can state
  the reason (IM-29). The binding holds the invariants of `bound` other than
  its status, and `expect.binding`, which the outcome requires, lists
  `agent_id`, `operator_id`, `holder_jkt` and `status` as for `bound`. Never
  `ACTIVE`. An error fails the case: it hides the status, and an unavailable
  source is a deferral, not a refusal.
- `error`: an error and an empty binding. For an adapter whose profile does
  not support shared workloads, a workload with more than one enrollment in
  force is a configuration error, an `error` with `UNSUPPORTED_REQUIREMENT`
  (draft 17.1).
- Every result other than a nil-error `UNKNOWN` reports the agent ID as not
  enrolled for another workload: the report belongs to `UNKNOWN` only.
  `expect.binding.enrolled_elsewhere` may be `false` for `bound` and
  `unusable`, and `true` only for `unknown`.

### map_operation

- `mapped`: no error, and an operation context with a non-empty `operation_id`,
  `principal_id` equal to the principal given, an uppercase `method`, an
  `https` `target_uri` without a fragment, a valid `body_digest`, a non-null
  `resources` array and a non-null `headers` object with lowercase names.
  `expect.operation` lists the members to compare; `resources` and `headers`
  are compared whole, in order for `resources`.
- `error`: an error, and an empty operation context. `reason_code` is the error's draft 13.4 code. A request that the baseline mapping forbids, because its target has a fragment, userinfo or an ambiguous encoding or it carries an HTTP content encoding (draft 10.2), is `INVALID_MESSAGE`. The function that rejects it is `map_operation`: draft 10.2 states these rules for the `target_uri` and `body_digest` of the operation context, and draft 17.1 gives that context to `map_operation` alone.
- After every call the request body must read back as the original bytes.

### read_native_claim

- `claim`: no error. `expect.claim.value` is compared as JSON data: object
  member order is ignored, array order is not (draft 8.4). `observed_at` and
  `status_checked_at` are Unix seconds or `null` for the zero time.
- `error`: an error; `reason_code` is its code.
- Every claim returned, whatever the outcome: `ObservedAt` and
  `StatusCheckedAt` are each zero or not later than `now` plus the skew ("No
  source observation or status-check time may be later than now +
  clock_skew", draft A.2), and the source is named.

### check_context

The outcome is the verdict: `PASS`, `FAIL` or `UNKNOWN`. The result must be one
of the three and must carry a reason code; `reason_code` pins it.
`ObservedAt` is not later than `now` plus the skew.

The check receives the `principal` and the `binding` of the call as draft 17.1
lists them. A check that reads neither ignores them: a case whose check needs
no agent states no `binding`.

A check reports a draft 13.4 code or a code of its own (draft 17.1, 17.3.1).
The freshness profile ([`../../profiles/freshness.md`](../../profiles/freshness.md),
section 3.2) defines two such codes, `CLOCK_AHEAD` and `RESTAMPED`, which have
no draft 13.4 row. Every check code is compared as the string the case gives.

### authorize_native

- `ALLOW`, `DENY`, `UNKNOWN`: the decision has that effect. `expect.decision`
  may give the `obligations` that must come back, in order, and the provenance
  the policy source gave: `source_id`, `source_ref` (`null` for none: the
  source keeps no record of the decision, so the decision must carry an empty
  one; absent, or an empty string, is not checked), `decided_at` (Unix
  seconds, or `null` for the zero time) and `policy_revision`.
- `not_allowed`: an error, or a decision that is not `ALLOW`. Used where the
  draft requires only that the policy does not allow.
- `error`: an error; `reason_code` is its code.
- Every decision returned, whatever the outcome: the effect is one of the
  three, the decision names the policy source that decided, and its decision
  time is zero or not later than `now` plus the skew (draft 7.5, A.2).

### record_outcome

- `signed`: a compact JWS. The header has `typ` `pact-outcome+jwt`, `alg`
  `ES256` or `Ed25519`, a `kid`, and none of `jku`, `x5u`, `jwk`, `crit`. The
  payload strict-parses as an outcome report with every required member. Its
  `event_id`, `operation_id`, `task_id`, `event_kind`, `result`, `dimension`,
  `severity`, tenant, environment, agent, context and `observed_at` are those of
  the observation, and its window satisfies draft 7.5 and is at most 300 seconds.
  The harness may verify the signature as well.
- `no_visibility`: the declared absence of execution visibility, with a reason.
- `no_execution_success`: either of the above, but never a signed `EXECUTION`
  report with result `SUCCESS`.
- `error`: an error; `reason_code` is its code.
- The result is the `Signed` or `NoVisibility` value, never a pointer or
  another type.

## Credential scan

`leak_scan` applies to every value and error the function returns: the error
text, the JSON form of a returned value, and, for a signed outcome, its decoded
header and payload. It fails the case when it finds a literal secret from
`secrets`, or any of the credential shapes that draft 19 keeps out of receipts,
outcome reports and logs:

- an authorization value: `Bearer` or `Basic` followed by at least 16 token
  characters;
- a compact JWS or JWT;
- a member named `authorization`, `proxy-authorization`, `cookie`,
  `set-cookie`, `pact-presentation` or `pact-admission`;
- a private JWK parameter as a member name: `d`, `p`, `q`, `dp`, `dq`, `qi`, `k`;
- an assignment with a credential name, such as `access_token=`, `password=`,
  `session=`, with a value of at least 6 characters that is not a mask such as
  `[redacted]`.

## Native state

`native_state` is passed to the harness unread. A harness builds the adapter's
native systems from it: the identity store, the enrollment source, the claim
sources, the policy, the installed checks. Cases in an adapter's own
directory state it in whatever shape that adapter's harness reads. The common
cases state it in the neutral model below, which every adapter's harness must be
able to realize in its own mechanism.

### Model `common/1`

```
{
  "model": "common/1",
  "gateway": {
    "tenant_id", "environment_id",
    "origin",                    // the public HTTPS origin, trusted configuration
    "header_allowlist": [...]    // lowercase names covered by an operation context
  },
  "mappings": [{"version", "routes": [{"method", "path", "action", "resource"}]}],
  "identities": [{"ref", "id", "realm", "workload", "secret", "attributes"}],
  "enrollments": [{"realm", "workload", "agent_id", "operator_id", "holder_jkt",
                   "status", "observed_at", "status_checked_at",
                   "source_id", "source_ref"}],
  "approved_paths": [...],
  "claims": [{"realm", "principal", "path", "resource", "task_id", "value",
              "observed_at", "status_checked_at", "source_id", "source_ref"}],
  "checks": [{"id", "principal", "agent_id", "result", "reason_code", "source_id", "source_ref", "observed_at",
              "status_checked_at",
              "freshness": {"max_age_seconds", "status_max_age_seconds"},
              "pinned_revision", "revision"}],
  "policy": [{"realm", "principal", "action", "resource", "effect",
              "obligations": [{"id", "attributes"}], "reason",
              "source_id", "source_ref", "decided_at", "policy_revision"}],
  "sightings": [{"source_id", "source_ref", "observed_at"}],
  "unavailable_sources": [...],
  "visibility": "none" | "execution",
  "reporting": {"issuer", "audience", "kid"}
}
```

- `gateway`: the realm the adapter serves. `origin` may be written with an
  uppercase scheme or host and a default port; a target URI shows the normalized
  form. The allowlist never names a credential, presentation, hop-by-hop or
  signature header.
- `mappings`: an installed operation mapping. A route matches a method and a
  path template in which `{name}` stands for one path segment, and gives the
  action and the resource, with the same placeholders filled in.
- `identities`: whom each credential authenticates. `ref` is how a case names
  the identity in `request.native_state_ref`; `secret` is the credential the
  harness presents for it. Two identities may have the same local name under
  different issuers and realms. `attributes` are further authenticated
  attributes. A harness realizes two of them where its mechanism has them:
  `display_name`, the name the native system displays for the identity, and
  `cnf`, `{"jkt": <thumbprint>}`, the key that the identity's credential is
  bound to, as a token's confirmation claim (RFC 9449, section 6.1) or a
  certificate's own key binds it. Neither names the identity, and `cnf` enrolls
  no key.
- `enrollments`: the source of agent/key bindings. `status` is `ACTIVE`,
  `REVOKED`, `COMPROMISED` or `UNKNOWN`. A time that is absent is a time the
  source does not give. Several records may name one workload. For an adapter
  whose profile does not support shared workloads, more than one record in
  force, that is, not `REVOKED`, that names the call's realm and `workload` is
  a configuration error: the call fails with
  `UNSUPPORTED_REQUIREMENT` and no binding, whichever `agent_id` it names
  (draft 17.1, IM-19). Counting needs every record of the workload, so a
  record of the workload from an unavailable source fails the call with
  `DEPENDENCY_UNAVAILABLE`. Otherwise, and always for an adapter whose profile
  supports shared workloads, the records are those of the agents that share
  the workload: a call resolves only the records of its realm that
  name both its `workload` and its `agent_id`; a record of another agent or of
  another workload is never the answer. Of those records, the ones in force
  are those that are not `REVOKED`; the answer is the single record in force
  or, with none in force, the single revoked record, and any other set
  resolves to `UNKNOWN`, never to the first or the most recent record (rule
  IM-18 of [`identity-mapping.md`](../../profiles/identity-mapping.md)). An
  `UNKNOWN` answer reports the agent ID enrolled for another workload when the
  realm holds a record of that `agent_id`, in any status, that names another
  workload; a record in another realm does not count.
- `claims`: authoritative values behind approved native paths, per realm and
  principal. `value` is any JSON value. Times are as in `enrollments`.
  `resource` and `task_id` are optional. A record with `resource` is a fact of
  that resource and is read only in a call whose `operation` lists it; a record
  with `task_id` is a fact of that task and is read only in a call whose
  `intent` carries it. A record with both needs both.
- `checks`: installed checks, each with the verdict of its native state. A check
  that is not listed is not installed. The times are those of the record the
  check consults, as in `enrollments`. The other members are optional and say
  what the installed check requires of that record. A record with `principal`
  is the check's native state for that principal and applies only in a call
  whose `principal` has that `id`; one with `agent_id` applies only in a call
  whose `binding` names that agent; one with both needs both. The common
  checks are approval-class (draft 17.3.1): a call that no record of the
  check's id applies to, including a call with no `binding` against a record
  with `agent_id`, is `FAIL` with `APPROVAL_SCOPE_MISMATCH`, never `PASS`. A
  record with neither member applies to every call. The check reports the
  first of these findings, and the verdict of its native state only when there
  is none:
  1. Its `source_id` is in `unavailable_sources`: `UNKNOWN` with
     `DEPENDENCY_UNAVAILABLE`.
  2. With `freshness`, which needs both limits, the record's `observed_at` and
     `status_checked_at` are evaluated against `max_age_seconds` and
     `status_max_age_seconds` by the rules of section 3 of the freshness
     profile, with the baseline skew of 5 seconds and the guard of
     `sightings`. A result other than `PASS`, with its reason code, is the
     outcome: `FAIL` with `CLOCK_AHEAD`, `RESTAMPED` or `STALE_EVIDENCE`, or
     `UNKNOWN` with `UNSUPPORTED_REQUIREMENT`. With `CLOCK_AHEAD` the outcome
     carries no observation time.
  3. With `pinned_revision`, the revision of its source that the installed
     check is pinned to: a `revision` that is absent or differs by any octet
     is `FAIL` with `REQUIREMENTS_CHANGED`, because the policy now in force is
     not the one the contract was issued for (draft 13.4).
- `policy`: the native authorization policy. A rule applies to the principal of
  the realm it names, for the action and, when the rule names one, the resource.
  A deny wins over an unknown and an unknown over an allow; with no rule the
  principal is not allowed. `source_id`, `source_ref`, `decided_at` and
  `policy_revision` are optional: the provenance the policy source gives for a
  decision by the rule, which the decision carries unchanged. A rule without
  `source_id`, and the denial when no rule applies, come from the adapter's own
  policy source, which the decision names. A `decided_at` later than `now`
  plus the skew is a decision that did not happen yet; the adapter does not
  pass it on.
- A harness may give its mechanism facts that a case does not state, for the
  principals, workloads and resources the case names, when the mechanism needs
  them to decide and the expected result does not depend on them; it realizes
  `policy` so that the decision follows the rule's principal, action and
  resource and nothing else.
- `sightings`: the observation times that the adapter's guard against
  re-stamping already holds, one per source record, named by `source_id` and
  `source_ref` together (freshness profile, section 7). A check with
  `freshness` whose record has a later `observed_at` than its sighting is
  `RESTAMPED`. The guard keeps the earliest time it sees for a record, and it
  records the time of every record that a check with `freshness` evaluates,
  except a time ahead of the clock.
- `unavailable_sources`: the `source_id` of each configured source that cannot
  currently answer. A record of `enrollments`, `claims` or `checks` from such a
  source cannot be read: `resolve_agent_binding` and `read_native_claim` fail
  with `DEPENDENCY_UNAVAILABLE`, and the check is `UNKNOWN` with
  `DEPENDENCY_UNAVAILABLE`. The adapter has no copy to fall back on.
- `visibility`: whether the adapter observes the execution of operations.
  Absent means `none`.
- `reporting`: the issuer, audience and key id of the outcome reports the
  adapter signs.

## What the harness provides

The suite cannot know how an adapter keeps identities or reads credentials, so
the harness supplies four things besides the adapter.

- **Arrive**: marks a request as having come through the enforcement point, in
  whatever way the adapter's mechanism recognizes. The suite passes every
  request through it except one whose `arrival` is `direct`. An adapter that
  authenticates a direct request is open to a bypass of the enforcement point.
- **Credential**: attaches the credential of the identity that `native_state_ref`
  names, as the adapter's mechanism reads it: a header, a cookie, a peer
  certificate.
- **Clock**: the adapter's only source of the current time, held at `now`. An
  adapter that reads the wall clock fails every time assertion.
- **Hooks**: where the adapter would run the protected operation it fires the
  hook `execute`. A case with `must_not_call: ["execute"]` fails if it fired.
  An adapter with no execution path never fires it.

A harness may also verify the signature of a signed outcome.

## Common cases

| Group | What the group shows | Draft |
|---|---|---|
| `COMMON-01` | X-User, X-Principal, X-Forwarded-User, X-Client-Cert and a custom header are ignored by `authenticate_native`; the credential decides. | 8.5, 17.1 |
| `COMMON-02` | A request that did not come through the enforcement point is refused; the same request through it is accepted. | 4.4, 17.1 |
| `COMMON-03` | `map_operation` gives the method, the exact target URI built from the configured origin (Host, Forwarded and X-Forwarded-* ignored), the body digest, the allowlisted headers, and resources from the mapping; it rejects a fragment, userinfo, an ambiguous encoding and a content encoding with `INVALID_MESSAGE` and never normalizes the target. | 7.4, 10.2, 13.4, 17.1, 19 |
| `COMMON-04` | `read_native_claim` reports the source's own times, never the time of the read; a claim with an observation or a status check later than now plus the skew is refused with `DEPENDENCY_UNAVAILABLE`, never passed on with that time or a clamped one; a status check ahead of now by exactly the skew is passed on. | 7.5, 8.3, 13.4, 17.2, A.2 |
| `COMMON-05` | A check that is not installed is `UNKNOWN`, never `PASS`; ids match exactly. | 13.4, 17.1, 17.2 |
| `COMMON-06` | A native decision is returned unchanged, with its obligations and its provenance (source, decision record, decision time, policy revision), for the original principal and not a connector identity; no execution hook fires. The principal carries `device_id` and `peer_address` for a mechanism whose policy input needs them. | 4.3, 5, 17.1, 17.5, A.2 |
| `COMMON-07` | `record_outcome` never emits `EXECUTION` `SUCCESS` without execution visibility. | 7.2, 14.1, 14.2, 14.5, 17.1 |
| `COMMON-08` | A revoked or compromised binding is not usable: it comes back as its status, with its agent, operator and holder key, never as `ACTIVE` (IM-11); an unenrolled workload has status `UNKNOWN`. | 6.1, 6.2, 6.4, 17.1 |
| `COMMON-09` | A same-spelled identifier of another realm is not equal: authentication, binding, claim, policy and mapping keep the realm. | 6.1, 8.5, 13.4, 17.2 |
| `COMMON-10` | No credential appears in a returned outcome report, check outcome, operation context or error. | 10.2, 14.1, 19, 20.2 |
| `COMMON-11` | `read_native_claim` reads a fact of a resource for a resource of the actual operation and a fact of a task for the task of the declared intent, never for another. | 10.1, 10.2, 17.1 |
| `COMMON-12` | A check compares the agent and the principal against the inputs it receives, the authenticated principal and the agent binding; a record for another agent or another principal, or a call with no binding against a record bound to an agent, is `FAIL` with `APPROVAL_SCOPE_MISMATCH`, never `PASS`. | 17.1, 17.3.1, 17.5 |
| `IDENT-01` | Another user of the same tenant authenticates as itself, and its account has no binding to the agent enrolled for another account (IM-1, IM-3). | 6.1, 8.5, 17.1 |
| `IDENT-02` | The same subject under another tenant of the issuer is another principal and has no binding (IM-4). | 8.5, 17.2 |
| `IDENT-03` | A user acting through another client has that client as the workload, and that client has no binding (section 3.4). | 6.1, 8.5, 17.1 |
| `IDENT-04` | A certificate for another workload, or of another certificate authority, has no binding (IM-22). | 6.1, 8.5 |
| `IDENT-05` | An account with the same display name authenticates as itself, not as the enrolled account (IM-5). | 8.5, 17.1 |
| `IDENT-06` | A session of the enrolled role under another session policy has no binding (IM-24). | 8.5, 17.2 |
| `IDENT-07` | `resolve_agent_binding` reports the enrolled holder key, never a key that the workload's credential is bound to (IM-21). | 6.2, 17.1 |
| `IDENT-08` | A compromised binding stays unusable, and compromised, when the workload's credential proves possession of the old key (IM-28). | 6.4, 17.1 |
| `IDENT-09` | For an adapter whose profile supports shared workloads (`workloads` `shared`): on a workload that several agents share, the agent ID the request names selects that agent and its own key, whatever the other agent's status and the order of the records; a revoked or compromised agent gets its own unusable binding, and an agent ID with no record on the workload, enrolled only on another workload or only in another realm, gets `UNKNOWN`, which reports the agent ID enrolled for another workload of the realm only in the second case (IM-11, IM-16, IM-18). | 6.1, 17.1 |
| `IDENT-10` | For an adapter whose profile does not support shared workloads (`workloads` `dedicated`): a workload with more than one enrollment in force is a configuration error, and the agent ID the request names gets no binding and `UNSUPPORTED_REQUIREMENT`; a revoked record is not in force and does not count, so the agent of the one record in force binds, and a compromised record is in force and counts; an agent ID with no record on the workload gets the same error, not `UNKNOWN` (IM-18, IM-19). | 6.1, 17.1 |
| `FRESH-01` | A binding revoked after the contract was issued, while the contract is still valid, is not usable at evaluation. | 6.4, 9.1, 11.3, 18 |
| `FRESH-02` | A check whose record is older than its `max_age_seconds` is `FAIL` with `STALE_EVIDENCE`; an age equal to the limit passes. | 7.5, 9.2, 13.4, 17.1, 17.5 |
| `FRESH-03` | A source time later than now plus the 5-second skew is `FAIL` with `CLOCK_AHEAD`, not a deferral; a time ahead by exactly the skew passes. | 7.5, 17.1, A.2 |
| `FRESH-04` | A check pinned to a policy revision fails with `REQUIREMENTS_CHANGED` when the source reports another revision at validation. | 9.3, 11.3, 13.4 |
| `FRESH-05` | A required source that cannot answer gives `DEPENDENCY_UNAVAILABLE` for a binding, a claim and a check, never `PASS` and never the value it last held. | 13.4, 17.1, 18 |
| `FRESH-06` | A record seen before that comes back with a later observation time is `FAIL` with `RESTAMPED`: re-stamping never makes an old fact fresh. | 8.3, 17.2 |

The `IDENT` groups are the negative identity fixtures of
[`identity-mapping.md`](../../profiles/identity-mapping.md); the IM rules and
the section in parentheses are that document's, and the last column cites the
draft as for every group. They check what the adapter
returns. The admission decision a validator draws from it (section 8 of that
document) is not a function of the adapter and is not checked here.

The `FRESH` groups exercise the freshness profile
([`../../profiles/freshness.md`](../../profiles/freshness.md)) at the adapter.
Each case fixes `now`. The age limits a check applies, the guard against
re-stamping and the outages are stated in the native state, as `freshness`,
`sightings` and `unavailable_sources`. `FRESH-02.at-limit` and
`FRESH-03.at-skew` are the controls of their groups.

Where a group has controls, such as `COMMON-02.via-enforcement-point` and
`COMMON-05.installed-control`, they show that the adapter is not refusing
everything: a refusing adapter passes the refusal cases and fails the controls.

## Replaced common cases

Every common case runs against every adapter. An adapter may declare a common `authenticate_native` case replaced when its expected principal, or the denial reason it pins, is stated in an identifier or credential form that the adapter's mechanism cannot carry: for example, a mechanism whose profile derives the identifier from the credential cannot authenticate as `https://idp.acme.example/bob`, and a mechanism whose only credential is a certificate has no bearer token to reject. The declaration names the adapter's own case that shows the same property in the mechanism's own identifier grammar, with expected values taken from the draft and the profile, for the same function and the same outcome class. This is the rule of draft 22.2 for `replaced` rows: the replacement is no weaker than the original intent. An adapter may likewise declare a common `authorize_native` case replaced when its expected `decision` carries a member that the mechanism's decision answer cannot carry: an obligation, a decision record (`source_ref`), a decision time (`decided_at`) or a policy revision. A relationship check that answers allowed or not carries no obligation; a decision API without a decision time carries none. The replacement is a case of the same function and outcome class that pins every provenance member the mechanism carries, `source_id` always, and `null` or an empty array for each member it cannot, so that the property, a decision returned as the source gave it and no execution, is shown in the mechanism's own form. A case of any other function is never replaced: its native state is deployment-supplied and the harness realizes it. The suite runs a replaced case and requires it to fail, so that a declaration that is no longer needed does not stand, and it refuses a declaration whose replacement is missing or weaker in function or outcome. The profile's fixture index lists every replaced case with its reason and its replacement.

## Adding cases

1. Write the file in `_common` or in the adapter's directory, as
   `adapters/<name>/<lowercase id>.json`, with no `cases/` subdirectory. Take
   every expected value from the draft, not from the output of an
   implementation. Set `workloads` only when the expected result depends on
   whether the profile supports shared workloads.
2. Register it in `../manifest.json` under the id
   `adapters/<name>/<lowercase id>`. The entries are sorted by `id`.
3. Cite the group in `spec_map_row`, and list the manifest id in the group's
   row of `../../spec-map.md`; a new group gets its row in the same change.
4. In the Go repository, add a mutant of the reference adapter that the case
   catches. The mutant package fails its own test for a case that no defect
   targets, so that a case that cannot fail does not land.
