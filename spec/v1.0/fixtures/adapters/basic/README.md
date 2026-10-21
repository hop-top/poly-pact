# HTTP Basic adapter cases

These are the cases of the HTTP Basic adapter of the integration profile
[`profiles/basic`](../../../profiles/basic/profile.md). They run after the
common cases, with the case file format, the outcomes and the checks of
[`../README.md`](../README.md). The profile does not support workloads shared
by several agents, so a harness runs the `dedicated` cases. Section 10 of the
profile says which planned case each file implements.

The common cases state their native state in the `common/1` model; a Basic
harness realizes it as well: an identity is an account of the gateway's
account database whose user-id is the identity's `ref`, whose password is its
`secret`, and whose principal, realm and workload are the identity's. The
cases in this directory state theirs in the model `basic/1` below.

## Model `basic/1`

```
{
  "model": "basic/1",
  "gateway": {"tenant_id", "environment_id", "origin", "header_allowlist"},
  "accounts": "assets/accounts.json",
  "accounts_answered_at": <Unix seconds>,          // optional
  "credentials": [{"ref", "user_id", "password"}],  // optional
  "role_map": {"<native role>": "<PACT role>"},     // optional
  "purposes": [{"purpose_id", "actions": [...]}],   // optional
  "enrollments": [...],                             // optional
  "invoices": [{"id", "department"}],               // optional
  "reporting": {"issuer", "audience", "kid"},       // optional
  "unavailable_sources": [...]                      // optional
}
```

- `gateway`: as in `common/1`. The realm of every account is the gateway's
  realm.
- `accounts`: the path, relative to this directory, of the account database.
  [`assets/accounts.json`](assets/accounts.json) is the one every case uses:
  `{"store_id", "accounts": [{"account_id", "user_id", "password", "roles",
  "department", "status"}]}`. `account_id` is the immutable key of the
  account, `user_id` its login, `status` is `active` or `disabled`, `roles`
  are the native role names. The store keeps no password, only its hash:
  `password` is `{"scheme": "pbkdf2-sha256", "iterations", "salt", "key"}`,
  PBKDF2 with HMAC-SHA-256 (RFC 8018, section 5.2) over the UTF-8 octets of the
  password, with the salt and the 32-octet derived key in base64url without
  padding. The iteration count suits a test, not a deployment. The principal
  and the workload of an account are both `basic:{store_id}:{account_id}`
  (profile section 7). `store_id` is also the source id of every value the
  store gives.
- `accounts_answered_at`: the time the account database gives for its
  answers. Absent, it gives none.
- `credentials`: what a client holds. The harness's credential hook attaches
  the identity `ref` names as the `Authorization` header `Basic` followed by
  the Base64 encoding of the UTF-8 octets of user-id, a colon, and password
  (RFC 7617, section 2).
- `role_map`: the administrator-approved translation of native role names to
  PACT role names of mapping revision `pact-basic-1` (draft 17.2). A native role
  that is not a key of the map has no PACT name.
- `purposes`: the installed purposes of the check `purpose-operation-v1`, each
  with the actions it allows.
- `enrollments`: the enrollment registry, records as in `common/1`.
- `invoices`: the department of each invoice. The native permission lookup,
  whose source id is `legacy-permissions`, allows `invoice.read` of
  `invoice:{id}` only to an active account of the invoice's department, and
  denies every other request.
- `reporting`, `unavailable_sources`: as in `common/1`; the account database
  is the source `store_id`.

The installed operation mapping is that of the profile, revision
`pact-basic-1`: `GET /invoices/{id}` maps to the action `invoice.read` and
the resource `invoice:{id}` (profile section 2).

## Hooks

Besides `execute`, a Basic harness fires the hook `account_lookup` each time
the adapter asks the account database for an account. A case with
`must_not_call: ["account_lookup"]` requires that the adapter refused the
request before it looked at any credential.
