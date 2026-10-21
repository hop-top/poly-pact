# SAML SP-session broker cases

These are the cases of the SAML service provider session to agent broker
adapter of the integration profile
[`profiles/saml`](../../../profiles/saml/profile.md). They run after the
common cases, with the case file format, the outcomes and the checks of
[`../README.md`](../README.md). The profile does not support workloads shared
by several agents, so a harness runs the `dedicated` cases. Section 10 of the
profile says which planned case each file implements.

The adapter consumes no SAML message (profile SB-1). A case therefore states
the assertions that reach the SP and lets a fake SP, which stands in for the
SP's own SAML implementation, turn them into sessions; the adapter then sees
only the SP's session records and the broker's grants.

The common cases state their native state in the `common/1` model; a SAML
harness realizes it as well: an identity is an agent whose broker credential
is the identity's `secret`, presented as a bearer token, and whose workload is
the identity's. A common request names no task, so it reaches no grant and no
session, and the common `authenticate_native` cases that expect a principal
are replaced (profile section 10). The cases in this directory state their
native state in the model `saml/1` below.

## Model `saml/1`

```
{
  "model": "saml/1",
  "gateway": {"tenant_id", "environment_id", "origin", "header_allowlist"},
  "sp": {"entity_id", "trusted_idps": [...]},
  "agents": [{"ref", "token", "workload"}],
  "enrollments": [...],                       // optional
  "events": [{"kind": "sign_in", "assertion_id", "issuer", "audience",
              "subject", "authn_instant", "session_id",
              "session_credential", "expires_at"}
           | {"kind": "logout", "session_id"}],
  "grants": [{"task_id", "session_id", "user", "agent_id", "expires_at",
              "revoked",
              "scope": {"purposes": [...], "actions": [...],
                        "resources": [...]}}],   // scope optional
  "directory_paths": [...],                   // optional
  "claims": [...],                            // optional
  "checks": [...],                            // optional
  "sightings": [...],                         // optional
  "unavailable_sources": [...]                // optional
}
```

- `gateway`: as in `common/1`. The realm of every principal is the gateway's
  realm. The installed operation mapping is that of the profile, revision
  `pact-saml-1`: `GET /broker/v1/tasks/{task_id}/records/{record_id}` maps to
  `record.read` on `record:{record_id}`, and
  `GET /broker/v1/tasks/{task_id}/records` to `record.list` on
  `record-collection` (profile section 2). The `task_id` segment of either
  route is the request's task reference (SB-16).
- `sp`: the configuration of the SP's SAML implementation: its entity ID and
  the identity providers it trusts.
- `agents`: each agent's own broker credential (SB-15). The harness's
  credential hook attaches the agent that `native_state_ref` names as the
  `Authorization` header `Bearer` followed by `token` (RFC 6750, section 2.1),
  and the broker's agent authentication maps that token to `workload`, with
  the mechanism `broker-token`. An unknown token is a credential that is
  rejected. A request on a grant whose `agent_id` holds no enrollment in
  force on the credential's workload is rejected (SB-16), so every case with
  a grant lists the grantee's enrollment; a harness that realizes a common
  case gives each identity an enrollment on its workload.
- `enrollments`: the enrollment registry, records as in `common/1`.
- `events`: what reaches the SP, in order. The fake SP is an in-memory session
  store behind a minimal assertion gate. A `sign_in` creates the session
  `session_id` only when `audience` is `sp.entity_id`, `issuer` is one of
  `sp.trusted_idps`, and `assertion_id` was not seen before; the gate stands in
  for the SP's checks of the audience (SAML Profiles, section 4.1.4.2: a bearer
  assertion carries an `AudienceRestriction` naming the SP) and of replay
  (section 4.1.4.5: the SP keeps the set of used assertion IDs). The session's
  `principal` is `saml:{sp-id}:{idp-entity-id}:{subject}` from `sp.entity_id`,
  `issuer` and `subject`, each percent-encoded as identity mapping rule IM-2
  says, and its `idp_realm` is `issuer` (SB-4, A.1). `authn_instant` and
  `expires_at` are Unix seconds; `expires_at` is the end the SP enforces
  (SB-5). `session_credential` is the browser credential of the session; it
  never reaches the adapter except where a case copies it into a request. A
  `logout` sets `logged_out` of the session for good (SB-6). The session store
  is the source `sp-sessions`.
- `grants`: the broker's `TaskGrant` store, the source `task-grants` (A.2).
  `user` is a principal in the form above; `expires_at` is Unix seconds.
  `scope`, when present, lists the permitted `purpose_id` values, actions and
  resources, each compared exactly (SB-11, condition 7); a grant without it
  permits every purpose, action and resource of the mapping.
  `native-delegation-v1` compares `agent_id` with the `binding` of the call
  (SB-11, condition 5): a case that runs it states the grantee's binding, and
  one without a binding is `FAIL` with `CONTEXT_MISMATCH`.
- `directory_paths`, `claims`: the approved native paths that a directory
  adapter answers for membership facts (SB-22), and its records, as `claims`
  of `common/1`.
- `checks`, `sightings`, `unavailable_sources`: as in `common/1`. The
  installed check `native-delegation-v1` is the adapter's own (SB-11) and is
  not listed in `checks`.

## Hooks

The adapter has no execution path and never fires `execute`; the broker runs
the read after admission and native authorization (profile section 3).
