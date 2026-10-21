# ReBAC adapter cases

These are the cases of the ReBAC adapter of the integration profile
[`profiles/rebac`](../../../profiles/rebac/profile.md), whose native decision
is one OpenFGA Check per protected operation. They run after the common cases,
with the case file format, the outcomes and the checks of
[`../README.md`](../README.md). The profile does not support workloads shared
by several agents, so a harness runs the `dedicated` cases. Section 10 of the
profile says which closure item each file implements; the IDs `REBAC-01` to
`REBAC-12` are those of the profile.

The relationship store authenticates nobody: `authenticate_native`,
`resolve_agent_binding`, `read_native_claim`, `check_context` and
`record_outcome` are the deployment's own (profile section 3), and a harness
realizes them for the common cases as for any adapter. For `authorize_native`
a harness realizes the `policy` of `common/1` as tuples of a store under the
reference model of `assets/model.fga`: an `ALLOW` rule is a direct tuple on the
relation of the rule's action, a `DENY` or `UNKNOWN` rule and the absence of a
rule are no tuple, and a `DENY` rule removes the tuple an `ALLOW` rule of the
same principal, action and resource would give. The harness supplies the route,
the relation table row and the subject and object registry entries of each
principal, action and resource the case names. A Check answer carries no
obligation, no decision record and no decision time, so the profile replaces
three `COMMON-06` cases (profile section 10, "Replaced common cases").

The cases in this directory state their native state in the model `rebac/1`
below.

## Model `rebac/1`

```
{
  "model": "rebac/1",
  "gateway": {"tenant_id", "environment_id", "origin", "header_allowlist"},
  "mappings": [{"version", "routes": [{"method", "path", "action", "resource"}]}],
  "relations": [{"action", "relation", "object_type"}],
  "pin": {"store_id", "authorization_model_id", "mapping_revision"},
  "subjects": [{"realm", "principal", "subject_id"}],
  "objects": [{"realm", "resource", "object_id"}],
  "store_credential": "<key>",                          // optional
  "store": {
    "id",
    "credential": "<key>",                              // optional
    "models": [{"id", "file": "assets/<file>.fga"}],
    "tuples": [{"user", "relation", "object"}],
    "cached_tuples": [{"user", "relation", "object"}],  // optional
    "unreachable": true,                                // optional
    "hang": true,                                       // optional
    "answer": {"status", "body" | "body_text"}          // optional
  }
}
```

- `gateway` and `mappings`: as in `common/1`. The realm of the gateway is the
  realm of the pin record (profile RB-1).
- `relations`: the relation table of the pin's mapping revision (profile
  section 2.1, RB-5): the relation and the object type a Check uses for an
  action.
- `pin`: the pin record of the gateway's realm (RB-1): the store, the
  authorization model and the mapping revision. Every Check names the store
  and the model (RB-2).
- `subjects` and `objects`: the mapping registry (RB-6). A principal of a
  realm maps to the Check `user` `user:<subject_id>`; a resource of an
  operation in a realm maps to `<object_type>:<object_id>`. An entry belongs
  to one realm (RB-4).
- `store_credential`: the pre-shared key the gateway sends, as
  `Authorization: Bearer <key>` ([OF-6] of the profile); absent, it sends
  none.
- `store`: the OpenFGA server and the state of the store `id`.
  - `credential`: the key the server accepts; absent, the server requires
    none. A Check without it, or with another key, is answered `401`.
  - `models`: the authorization models of the store, in the order they were
    written, each in the FGA modeling language in a file of this directory.
    A Check that names no `authorization_model_id` is evaluated under the
    last of them, as OpenFGA uses the latest model of the store when the id is
    omitted ([OF-2], [OF-3]); one that names an id the store does not hold is
    answered `400`.
  - `tuples`: the relationship tuples of the datastore. A Check is evaluated
    under its model with these tuples and the contextual tuples of the
    request, which count as stored tuples for that request ([OF-4]).
  - `cached_tuples`: the tuples a Check is answered from when it does not ask
    for `HIGHER_CONSISTENCY`: a cache or a replica that lags behind the
    datastore ([OF-1], [OF-5]). Absent, every Check reads `tuples`.
  - `unreachable`: no connection to the server can be opened. `hang`: the
    server accepts the request and does not answer.
  - `answer`: the server answers every Check with this status and body,
    a JSON value in `body` or exact text in `body_text`, whatever it asks.

The bracketed source ids are the upstream pages of section 13 of the profile.

## Hooks

A harness fires these hooks where the store receives a request, and a case
lists those that must not fire in `expect.must_not_call`:

| Hook | Fired when |
|---|---|
| `check` | The store receives a Check. |
| `check-latest-model` | A Check names no `authorization_model_id`, so the store uses its latest model. |
| `check-cached` | A Check does not ask for `consistency` `HIGHER_CONSISTENCY`, so the store may answer from `cached_tuples`. |
| `contextual-tuples` | A Check carries contextual tuples. |

`execute` is the execution hook of [`../README.md`](../README.md); no
function of this adapter runs the document operation, so it never fires.

## Assets

| File | Content |
|---|---|
| `assets/model.fga` | The reference model of profile section 2.2: `user`; `project` with `member`; `document` with `parent`, `editor` assigned directly, and `viewer` assigned directly or derived from `member` of the parent ([OF-12]). It is the pinned model of every case. |
| `assets/model-next.fga` | A model written after the pin, in which an `editor` is also a `viewer`. It is the latest model of the `REBAC-02` cases, so a Check that does not name the pinned model decides under it. |

A harness that runs the cases against an OpenFGA server writes each model to a
new store with `POST /stores/{store_id}/authorization-models` ([OF-18]),
converting the modeling language to the JSON form that call takes, and writes
the tuples with `POST /stores/{store_id}/write` ([OF-8]). The ids the server
returns replace the case's store and model ids, and the harness puts the
case's ids back in the decision it compares. A server cannot be made to lag
on request, so the integration tier realizes `cached_tuples` by writing them
first, sending one Check without `HIGHER_CONSISTENCY`, and then changing the
store to `tuples`; it runs the cases that need no fixed answer, no outage and
no second model.
