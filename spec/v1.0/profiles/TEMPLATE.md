# PACT integration profile template

This template targets spec version 1.0 and wire version 0.1 and is a draft.

## Purpose

An integration profile is the document in which an adapter maintainer states, for one gateway or product integration, the exact conformance claim and the evidence behind it. It covers which routes and actions are protected, where each enforcement function runs, which native dependencies exist, which alternative paths exist and how each is handled, which forms are unsupported, how identity maps, how fresh each source is, which membership, role, and account-status facts and which other subject, resource, and environment attributes it supplies, which limits remain, and which negative fixtures demonstrate the claim. This template is informative and adds no protocol requirement. Where this template and the draft (`spec/v1.0/draft.md`) differ, the draft governs.

## Completeness

A profile is complete only when all ten numbered sections below are filled; every section is mandatory. A section that is empty, marked as a placeholder, or answered "not applicable" without a stated reason leaves the profile incomplete, and an incomplete profile cannot support an enforced-support claim (draft §4.4 and §22.1).

The draft sets these limits:

- Draft §4.4 bars an opaque legacy gateway that cannot authenticate the principal, expose a usable request mapping, or enforce an additional condition from claiming enforced PACT support merely because an agent profile has the right fields.
- Draft §2.3 requires enforced mode to apply `execute = native_authentication_valid AND pact_admission_admissible AND native_authorization_allows AND native_execution_conditions_satisfied` on every protected operation, so every claimed route must be listed.
- Draft §22.1 requires transport adapters to declare their exact native-protocol versions and mapping revisions, requires observation-mode deployments to disclose that native access is not conditioned on PACT admission, and requires an admission-only implementation to describe itself as a partial role implementation.

An incomplete profile may be shared as work in progress, but it must not be cited as support for an enforced claim.

## Language neutrality

Profiles and adapter fixtures must stay language-neutral so that adapter SDKs in other languages can reuse them. Describe behavior as inputs and expected results, using Markdown tables, JSON, or YAML. Do not include code in a specific programming language, SDK-specific API names, or test-framework code. Paths to files that do not exist yet, such as `spec/v1.0/profiles/identity-mapping.md` and `spec/v1.0/fixtures/`, are written as inline code, not as links, until the files exist.

## How to use this template

1. Copy this file and name the copy after the gateway or product.
2. Keep the ten section headings and their numbers; fill every section. Section 8 carries the subsections 8.1 and 8.2, which are filled as part of it.
3. Each section starts with a one-line "How to fill" note; keep or delete the notes in the finished profile, they carry no claim.
4. Replace every angle-bracket placeholder; the filled mini-example at the end of this file shows the expected level of detail for a fictional gateway.

## Profile header

| Field | Value |
|---|---|
| Profile name | `<gateway or product name>` |
| Target product and version | `<product, exact version>` |
| Spec version, wire version | `1.0`, `0.1` |
| Profile revision, date | `<revision, YYYY-MM-DD>` |
| Maintainer | `<name or handle>` |
| Reference documents | draft = `spec/v1.0/draft.md` |

## 1. Claim scope

**How to fill:** State the conformance roles from draft §22.1 (PACT Holder 0.1, PACT Gateway 0.1, PACT Validator 0.1, PACT Reputation 0.1, PACT Learning 0.1), the mode (`enforced` or `observe`), the transports (`header`, `gateway-evaluate`, `adapter-envelope`), and each adapter's protocol, version, and `mapping_revision` from `GatewayMetadata.adapters`. Also state the conformance profile(s) the claim holds under, with ids from `spec/v1.0/profiles/registry.json`, and the transport profile(s) the claim uses. Those two rows are mandatory and each takes one or more entries; the machine-readable form is the arrays `conformance_profile` and `transport` of `claim` in `integration-profile.schema.json`. A claim that lists `stdio-ipc` also applies the local-channel note in section 5.

| Item | Value |
|---|---|
| Deployment form (draft §4.4) | `<in-gateway, trusted sidecar/service, or observation>` |
| Roles claimed (draft §22.1) | `<one or more of: PACT Holder 0.1, PACT Gateway 0.1, PACT Validator 0.1, PACT Reputation 0.1, PACT Learning 0.1>` |
| Partial role statement (draft §22.1) | `<if the claim is admission-only, state that this is a partial role implementation>` |
| Mode (draft §2.3) | `<enforced or observe>` |
| Observation disclosure (draft §22.1) | `<if observe: native access is not conditioned on PACT admission>` |
| Presentation transports (draft §13.2) | `<header, gateway-evaluate, adapter-envelope: only those actually usable>` |
| Conformance profile(s) (draft §21, §22.1) | `<one or more ids of kind conformance from spec/v1.0/profiles/registry.json, each at version 0.1: full, single-owner>` |
| Transport profile(s) (draft §13, §13.3) | `<one or more of: https, stdio-ipc, each with version 0.1>` |

| Adapter `protocol` | Adapter `version` | Adapter `mapping_revision` (`GatewayMetadata.adapters`, draft Appendix A) |
|---|---|---|
| `<native protocol>` | `<exact protocol version>` | `<mapping revision as published>` |

## 2. Protected routes and actions

**How to fill:** List every route pattern, method, action, and resource mapping the claim covers; a route not listed is not claimed.

| ID | Route pattern | Method | Action | Resource mapping |
|---|---|---|---|---|
| R1 | `<route pattern>` | `<method>` | `<native action>` | `<how the actual request maps to the native resource>` |
| R2 | `<route pattern>` | `<method>` | `<native action>` | `<how the actual request maps to the native resource>` |

## 3. Enforcement points

**How to fill:** Name where `authenticate_native`, `map_operation`, PACT evaluation, `authorize_native`, and execution happen, in request order, and who runs each.

| Order | Function | Where it runs | Run by | Notes |
|---|---|---|---|---|
| 1 | `authenticate_native` | `<component and stage>` | `<owner>` | `<principal and workload context produced>` |
| 2 | `map_operation` | `<component and stage>` | `<owner>` | `<mapping revision; consequential request data covered>` |
| 3 | PACT evaluation | `<in the gateway request path, or a validator reached through the declared transport>` | `<owner>` | `<sidecar form: where the gateway checks issuer, binding, freshness and single-use status before authorize_native (draft §4.4, §11.5)>` |
| 4 | `authorize_native` | `<component and stage>` | `<owner>` | `<a native denial is final (draft §2.3)>` |
| 5 | Execution | `<component that performs the operation>` | `<owner>` | `<identity and restrictions the operation runs under>` |
| support | `resolve_agent_binding` | `<component and stage>` | `<owner>` | `<source of enrolled agent ID and holder key>` |
| support | `read_native_claim` | `<component and stage>` | `<owner>` | `<approved native paths>` |
| support | `check_context` | `<component and stage>` | `<owner>` | `<installed check IDs>` |
| support | `record_outcome` | `<component and stage>` | `<owner>` | `<outcome signed, or absence of execution visibility declared>` |

## 4. Native dependencies

**How to fill:** Map each native system the integration relies on to one of the components C01 to C16 below and name its owner.

The table below lists the sixteen components (C01 to C16) that a PACT integration draws on, each with the condition under which it is needed. These are logical responsibilities: an existing system can supply one or several of them, a single component can fulfil several responsibilities, and listing a component does not assert that it has been built.

| ID | Responsibility | Needed when | Provided by | Owner | Status or reason not used |
|---|---|---|---|---|---|
| C01 | PACT enforcement gateway/validator | baseline | `<system>` | `<owner>` | `<exists, to be supplied, or reason not used>` |
| C02 | Native authentication and claim adapters | baseline | `<system>` | `<owner>` | `<exists, to be supplied, or reason not used>` |
| C03 | Enrollment, issuer trust, and key lifecycle | baseline | `<system>` | `<owner>` | `<exists, to be supplied, or reason not used>` |
| C04 | Native delegation and task authority | delegated or task execution | `<system>` | `<owner>` | `<exists, to be supplied, or reason not used>` |
| C05 | Evidence and authoritative status sources | baseline | `<system>` | `<owner>` | `<exists, to be supplied, or reason not used>` |
| C06 | External approval, exception, or PIM workflow | required external authorization | `<system>` | `<owner>` | `<exists, to be supplied, or reason not used>` |
| C07 | Purpose and exact operation mapper | baseline | `<system>` | `<owner>` | `<exists, to be supplied, or reason not used>` |
| C08 | Native resource executor and authorization | the actual resource operation | `<system>` | `<owner>` | `<exists, to be supplied, or reason not used>` |
| C09 | Durable atomic exchange state | baseline | `<system>` | `<owner>` | `<exists, to be supplied, or reason not used>` |
| C10 | Task attribution and outcome qualification | baseline | `<system>` | `<owner>` | `<exists, to be supplied, or reason not used>` |
| C11 | Contextual reputation service | reputation | `<system>` | `<owner>` | `<exists, to be supplied, or reason not used>` |
| C12 | Policy/artifact registry and learning lifecycle | baseline: current authorized policy/artifact registry; adaptation: full lifecycle | `<system>` | `<owner>` | `<exists, to be supplied, or reason not used>` |
| C13 | Revocation and security holds | baseline | `<system>` | `<owner>` | `<exists, to be supplied, or reason not used>` |
| C14 | Protected evidence and audit storage | baseline | `<system>` | `<owner>` | `<exists, to be supplied, or reason not used>` |
| C15 | Native transactions, budgets, and side-effect control | relevant business transactions or limits | `<system>` | `<owner>` | `<exists, to be supplied, or reason not used>` |
| C16 | Runtime authority and containment | claimed runtime or data-use guarantees | `<system>` | `<owner>` | `<exists, to be supplied, or reason not used>` |

## 5. Alternative and bypass paths

**How to fill:** List every other way to reach the protected resources and assign each the disposition `closed`, `equivalently-enforced`, or `out-of-claim`, with the evidence for it. For a claim that lists the `stdio-ipc` transport profile, also apply the local-channel note below the table.

| ID | Path | Disposition | Evidence |
|---|---|---|---|
| B1 | `<other way to reach a protected resource>` | `<closed, equivalently-enforced, or out-of-claim>` | `<closed: the control and its negative fixture; equivalently-enforced: where the same enforcement points apply and the fixture; out-of-claim: the entry in section 1 or section 6 that excludes it>` |
| B2 | `<other way to reach a protected resource>` | `<closed, equivalently-enforced, or out-of-claim>` | `<evidence>` |

**Local channels (`stdio-ipc`).** Direct execution of the protected server by any process of the same operating-system user as the agent is a bypass path, and a profile that lists `stdio-ipc` lists it in this table. Its disposition is `out-of-claim`, unless an operating-system separation closes it, such as running the server under a different uid from the agent or inside a sandbox that denies the agent's processes the right to run or connect to it. The evidence for the declared disposition is mandatory in both cases; a path with no evidence, or a bare assertion that the path is closed, leaves the profile incomplete. The two rows below show the evidence each disposition needs.

| Case | Path | Disposition | Evidence |
|---|---|---|---|
| No separation | Direct execution of the protected server by any process of the same operating-system user | `out-of-claim` | The entry in section 1 or section 6 that excludes the path, and a statement that the agent and the server run as the same user. No negative fixture applies, because the path is not controlled. |
| Separation | Direct execution of the protected server by any process of the same operating-system user, where the server runs under a different uid or in a sandbox | `closed` | The separation itself (the server's uid and the agent's uid, or the sandbox rules, and the permissions on the server executable and its channel), and the negative fixture in which a process of the agent's user tries to run the server directly and fails. |

## 6. Unsupported forms

**How to fill:** State what the integration did not establish. Start from the integration's design choice and the wider claim that choice leaves out: a narrower form a reader could take as supported, such as enforcement on an unchanged server, a broader identity or delegation model, or other products and paths of the same kind. Each row names the form, its source (the sample or design choice it comes from, or the section of this profile where it was found), and what this integration does instead. Then add the forms found while filling sections 2 and 5.

| Unsupported form | Source | Why it is not established |
|---|---|---|
| `<wider claim not established>` | `<sample ID and the wider claim its design choice does not establish>` | `<what this integration does instead>` |
| `<form found while filling sections 2 and 5>` | `<section reference>` | `<reason>` |

## 7. Identity mapping

**How to fill:** Point to `spec/v1.0/profiles/identity-mapping.md` and record only the identity choices this profile makes or narrows.

| Item | This profile |
|---|---|
| Native identifier namespaces (user, client, workload) | `<namespaced identifier forms>` |
| Trusted enrollment actors | `<who may enroll an agent and bind its holder key>` |
| Shared-account handling | `<not supported, the default of identity-mapping §5 (IM-19), where more than one enrollment in force for a workload is a configuration error; or supported, with the reason IM-19 requires and the primary source that shows the native limit; or, for a profile that authenticates no request itself, inherited from the profile that does>` |
| Certificate, token, or role-session bindings | `<which native credential is bound to the holder key, and how>` |
| Lifecycle rules (rotation, compromise, recovery) | `<rules, or deferral to the shared document>` |
| Departures from `spec/v1.0/profiles/identity-mapping.md` | `<none, or each departure>` |

## 8. Freshness

**How to fill:** For each source, state how it is observed, the `max_age` and `status_max_age` it can actually achieve, and what happens when it is unavailable.

| Source | Observation semantics | Achievable `max_age` (s) | `status_max_age` (s) | Outage behavior |
|---|---|---|---|---|
| `<source>` | `<current authoritative state, or cached credential snapshot (draft §17.2); how the original observation time is obtained (draft §9.2)>` | `<seconds>` | `<seconds; 0 means a fresh authoritative check>` | `<DEFERRED, fail closed (draft §18)>` |

### 8.1 Membership and status sources

**How to fill:** For each native source that supplies membership, role, or account-status facts, state the facts it offers, whether a live check exists, how it announces changes, the best status freshness this integration can achieve, and whether its values are current authoritative state or cached snapshots (draft §17.2).

Every profile whose integration reads membership, role, or account-status facts MUST fill this subsection for each such source; this is a requirement on the profile, not on the protocol. An integration that reads no such fact writes `none` in the first cell, with the reason, and the machine-readable form is an empty array. The column headers are the field names of `membership_sources` in `integration-profile.schema.json`, and the cells use that schema's snake_case vocabulary.

| Source | `facts` | `live_check.available` | `live_check.endpoint_class` | `change_feed.mode` | `change_feed.mechanism` | `best_status_max_age_seconds` | `value_semantics` |
|---|---|---|---|---|---|---|---|
| `<source; same name as in the table above when it appears there>` | `<one or more of: identity, groups, roles, account_state>` | `<true or false>` | `<class of endpoint the live check calls; if false: not applicable, no live check>` | `<none, poll_delta, or push>` | `<mechanism and its cadence or delivery path; if none: not applicable, no change feed>` | `<seconds; 0 means a fresh authoritative check for each evaluation>` | `<authoritative_current or cached_snapshot>` |

- `facts` lists each fact the source offers: `identity` (the authenticated principal), `groups` (group memberships), `roles` (role assignments), `account_state` (whether the account is usable, such as enabled or disabled).
- `live_check.available` is `true` when the adapter can ask the source at evaluation time. `live_check.endpoint_class` is present only then; in the machine-readable form the key is absent when `available` is `false`.
- `change_feed.mode` is `none`, `poll_delta` (the adapter polls for changes since a token or time), or `push` (the source notifies the adapter, which includes an integration that operates the receiving end of a provisioning or signal protocol, such as a SCIM 2.0 service provider, a push notification channel or a Shared Signals receiver: the inbound messages are the feed, and `mechanism` names the protocol and the sender's cadence). `change_feed.mechanism` is present for `poll_delta` and `push` and absent for `none`.
- `best_status_max_age_seconds` is the lowest status bound this integration can honor, and it agrees with the `status_max_age` of the matching row of the table above. A requirement with a smaller `status_max_age_seconds` cannot be met by this source: the result is `DEFERRED`, or an authorized policy publisher changes the requirement (draft §17.2, §18).
- When `live_check.available` is `false`, `value_semantics` is `cached_snapshot` and `best_status_max_age_seconds` is at least 1: the adapter cannot claim a check it did not perform (draft §9.2, §17.2).
- A source that a source document describes, an entry of kind `source` in [`registry.json`](registry.json), is named in the Source cell with a link to that document, and its row takes the values of the document's row. The machine-readable form records the entry's `id` in the optional `source_document`.

### 8.2 Attribute sources

**How to fill:** For each native source of subject, resource, or environment attributes that the integration reads over approved native paths and that 8.1 does not cover, state the category, the paths it answers, and the row of the table above that bounds its freshness.

Every profile whose integration reads such an attribute MUST fill this subsection for each such source; this is a requirement on the profile, not on the protocol. An integration that reads no such attribute writes `none` in the first cell, with the reason, and the machine-readable form is an empty array. The column headers are the field names of `attribute_sources` in `integration-profile.schema.json`.

| Source | `category` | `attributes` | `freshness` |
|---|---|---|---|
| `<native source of the attributes>` | `<subject, resource, or environment>` | `<one or more approved native paths, such as /subject/clearance>` | `<the row of the table above that bounds this source>` |

- `category` is `subject` (an attribute of the authenticated principal), `resource` (an attribute of a resource of the operation), or `environment` (an attribute of the circumstances of the request, such as the device, the network, or the time). There is no `action` category: `OperationContext.action` carries the action.
- `attributes` lists the approved native paths of the installed mapping that the source answers (draft §9.2, §17.1, §17.2), each once. A path is a `/` followed by segments of letters, digits, `_`, `.`, and `-`, separated by `/`.
- `freshness` names the row of the table above that bounds the source; in the machine-readable form it is that row's `source` text, spelled exactly as there. An attribute the gateway observes itself, such as its clock reading, also has a row, with the gateway as its source.
- Membership, role, and account-status facts are listed in 8.1, not here.

## 9. Residual limits

**How to fill:** State what remains true after a successful admission, covering at least data already read (post-read) and how revocation propagates to each source.

| Limit | What remains true | Bound or disclosure |
|---|---|---|
| Post-read | `<data already returned to the agent; executed operations are not undone by revoking a receipt (draft §18); egress and data-use controls only if supplied and verified (draft §17.4)>` | `<disclosure>` |
| Revocation propagation | `<per source: time for a revocation to reach the gateway, and the consistency domain (draft §18)>` | `<seconds or consistency statement>` |
| `<additional limit>` | `<description>` | `<bound or disclosure>` |

## 10. Fixture index

**How to fill:** List the negative cases that demonstrate the claim and the expected result of each, covering every protected route and every `closed` or `equivalently-enforced` path. A case whose fixture file exists and is registered in `spec/v1.0/fixtures/manifest.json` is also listed in `fixtures` of the machine-readable form. A planned case is listed only under a "Planned" heading in this section, and joins `fixtures` in the change that adds its file.

| Fixture ID | Negative case (input) | Expected result | Covers |
|---|---|---|---|
| `<id; file under spec/v1.0/fixtures/ once it exists>` | `<input that must not be admitted or executed>` | `<expected result, using the draft §22.2 wording where a case applies>` | `<route, path, or freshness row IDs>` |

## Filled mini-example: Example Invoice Gateway

The example fills all ten sections for a fictional gateway, "Example Invoice Gateway", served at `https://invoice-gw.example` (a reserved `.example` hostname). It is a small read-only invoice service with two protected routes and a dedicated service account per agent. The gateway, routes, components, owners, numbers and fixtures are invented for illustration; none of them exists, and the numbers are illustrative policy choices, not recommended thresholds. The example shows the expected level of detail; it does not establish support for any real product.

### 1. Claim scope

The gateway evaluates PACT in-gateway (draft §4.4), claims `PACT Gateway 0.1` and `PACT Validator 0.1` in `enforced` mode over `header` transport, and is a partial role implementation (draft §22.1) because it claims neither Reputation nor Learning. It declares the `full` conformance profile and the `https` transport profile, both at version 0.1; the roles it does not claim are supplied by connected services of the deployment.

| Item | Value |
|---|---|
| Deployment form (draft §4.4) | in-gateway |
| Roles claimed (draft §22.1) | `PACT Gateway 0.1`, `PACT Validator 0.1` |
| Partial role statement (draft §22.1) | Partial role implementation: `PACT Reputation 0.1` and `PACT Learning 0.1` are not claimed |
| Mode (draft §2.3) | `enforced` |
| Observation disclosure (draft §22.1) | not applicable: mode is `enforced` |
| Presentation transports (draft §13.2) | `header` |
| Conformance profile(s) (draft §21, §22.1) | `full` 0.1 |
| Transport profile(s) (draft §13, §13.3) | `https` 0.1 |

| Adapter `protocol` | Adapter `version` | Adapter `mapping_revision` |
|---|---|---|
| `http` | `1.1` | `inv-map-r3` |

### 2. Protected routes and actions

Two read-only routes are protected, each with a route ID (R1, R2) that later sections use; any other route is not claimed.

| ID | Route pattern | Method | Action | Resource mapping |
|---|---|---|---|---|
| R1 | `/api/v1/invoices/{invoice_id}` | `GET` | `invoice.read` | `invoice:{invoice_id}`, from the path parameter |
| R2 | `/api/v1/invoices` | `GET` | `invoice.list` | `invoice-collection:{tenant}`, tenant taken from the authenticated account; query parameters `status` and `page_token` are part of the bound operation |

### 3. Enforcement points

The five required functions run in request order inside the gateway's own filter chain, and the other four adapter functions of draft §17.1 are listed as supporting rows.

| Order | Function | Where it runs | Run by | Notes |
|---|---|---|---|---|
| 1 | `authenticate_native` | Gateway login stage, before routing | Gateway implementer | Dedicated per-agent service account |
| 2 | `map_operation` | Gateway mapping stage, mapping revision `inv-map-r3` | Adapter owner | Builds the operation context for R1 and R2 |
| 3 | PACT evaluation | In-gateway validator in the same request path | Gateway implementer | Runs after mapping and before native authorization |
| 4 | `authorize_native` | Gateway's existing invoice access policy | Resource owner | A native denial is final (draft §2.3) |
| 5 | Execution | Call from the gateway to the invoice service under the account's native restrictions | Resource owner | Reached only after steps 1 to 4 pass |
| support | `resolve_agent_binding` | Enrollment registry lookup inside the gateway | Gateway implementer | Supplies the enrolled agent ID and holder key |
| support | `read_native_claim` | Directory lookup of the `groups` claim | Adapter owner | Returns value, original observation time, and source ID |
| support | `check_context` | Installed gateway checks | Gateway implementer | No named checks beyond the mandatory protocol checks |
| support | `record_outcome` | Gateway outcome writer, after execution | Gateway implementer | Outcome attributed to the admission decision |

### 4. Native dependencies

Eleven of the sixteen components are used, and each of the other five carries the reason it does not apply.

| ID | Responsibility | Needed when | Provided by | Owner | Status or reason not used |
|---|---|---|---|---|---|
| C01 | PACT enforcement gateway/validator | baseline | In-gateway validator and filter chain | Gateway implementer | Exists |
| C02 | Native authentication and claim adapters | baseline | Directory-backed login and `groups` lookup | IAM owner and adapter owner | Exists |
| C03 | Enrollment, issuer trust, and key lifecycle | baseline | Enrollment registry, administrator-run enrollment | IAM and security owner | Exists |
| C04 | Native delegation and task authority | delegated or task execution | none | none | Not used: each agent acts under its own dedicated account, no delegation |
| C05 | Evidence and authoritative status sources | baseline | Directory, enrollment registry, hold store | Adapter owner | Exists |
| C06 | External approval, exception, or PIM workflow | required external authorization | none | none | Not used: read-only routes need no external approval |
| C07 | Purpose and exact operation mapper | baseline | Mapper at revision `inv-map-r3` | Adapter owner | Exists |
| C08 | Native resource executor and authorization | the actual resource operation | Invoice service | Resource owner | Exists |
| C09 | Durable atomic exchange state | baseline | Replay and receipt store | Platform owner | Exists |
| C10 | Task attribution and outcome qualification | baseline | Gateway outcome writer and invoice service audit log | Resource owner | Exists |
| C11 | Contextual reputation service | reputation | none | none | Not used: `PACT Reputation 0.1` is not claimed |
| C12 | Policy/artifact registry and learning lifecycle | baseline: current authorized policy/artifact registry; adaptation: full lifecycle | Policy registry holding the base requirements | Platform owner | Exists; registry only, no adaptation lifecycle |
| C13 | Revocation and security holds | baseline | Revocation and hold store | Security and IAM owner | Exists |
| C14 | Protected evidence and audit storage | baseline | Access-controlled evidence and audit store | Security and data owner | Exists |
| C15 | Native transactions, budgets, and side-effect control | relevant business transactions or limits | none | none | Not used: read-only routes, no transactions or budgets |
| C16 | Runtime authority and containment | claimed runtime or data-use guarantees | none | none | Not used: no runtime attestation or data-use guarantee is claimed |

### 5. Alternative and bypass paths

Four other ways to reach invoices are listed, one `closed` by network policy, one `closed` by route removal, one `equivalently-enforced` through the same filter chain, and one `out-of-claim`.

| ID | Path | Disposition | Evidence |
|---|---|---|---|
| B1 | Direct request to the invoice service port `8443` | `closed` | Network policy admits only the gateway as a source; fixture `EXGW-N03` |
| B2 | Legacy routes under `/api/v0/invoices` | `closed` | Routes removed from the gateway; fixture `EXGW-N04` |
| B3 | Admin console routes under `/admin/invoices` | `equivalently-enforced` | Served through the same filter chain, so the five enforcement points of section 3 apply; fixture `EXGW-N05` |
| B4 | Nightly CSV export job | `out-of-claim` | Batch job with no agent-facing route; excluded in section 6 |

### 6. Unsupported forms

The first two rows are the wider claims that samples I01 and I06 do not establish, and the last two come from the routes and paths found while filling sections 2 and 5.

| Unsupported form | Source | Why it is not established |
|---|---|---|
| Telling agents apart when they share one account, or enforcement on an unchanged server | I01: "Shared-password agent distinction or enforcement on an unchanged server" | Only dedicated accounts behind this gateway are claimed |
| Employee delegation, and nested-group semantics of the directory | I06: "Employee delegation or universal schema/nested-group semantics" | No delegation exists; only the group lookup described in section 8 is claimed |
| Any route other than R1 and R2, including every write operation | Section 2 | Not listed in section 2, so not claimed |
| The nightly CSV export job | Section 5, B4 | Excluded by its `out-of-claim` disposition |

### 7. Identity mapping

Each agent has a dedicated service account, enrolled by identity administrators and bound to its holder key in the enrollment registry, with all other rules deferred to `spec/v1.0/profiles/identity-mapping.md`.

| Item | This profile |
|---|---|
| Native identifier namespaces (user, client, workload) | Agent accounts only: `acct:{account_id}` in realm `invoice-gw.example` |
| Trusted enrollment actors | Identity administrators |
| Shared-account handling | Not supported, the default of identity-mapping §5 (section 6). An account with more than one enrollment in force is a configuration error (IM-19) |
| Certificate, token, or role-session bindings | Account bound to the holder key in the enrollment registry; no certificate, token, or role-session binding |
| Lifecycle rules (rotation, compromise, recovery) | Deferred to `spec/v1.0/profiles/identity-mapping.md` |
| Departures from `spec/v1.0/profiles/identity-mapping.md` | None |

### 8. Freshness

Four sources are listed with `max_age` and `status_max_age` in seconds, and every outage ends in `DEFERRED`, which fails closed (draft §18).

| Source | Observation semantics | Achievable `max_age` (s) | `status_max_age` (s) | Outage behavior |
|---|---|---|---|---|
| F1 Directory `groups` lookup (`environment.roles`) | Cached credential snapshot; the gateway caches membership for up to 30 s and the original observation time is the directory read time | 30 | 30 | `DEFERRED` |
| F2 Directory account state (enabled or disabled) | Current authoritative state, read for each evaluation | 30 | 0 | `DEFERRED` |
| F3 Enrollment registry (agent and key binding status) | Current authoritative state, read for each evaluation | 30 | 0 | `DEFERRED` |
| F4 Security hold store | Current authoritative state, read for each evaluation | 30 | 0 | `DEFERRED` |

#### 8.1 Membership and status sources

F1 and F2 supply membership and account-status facts, so they are listed again here. The gateway has no on-demand group query: it reads a cache that a poll of the directory change-tracking cookie refreshes every 30 s, so F1 has no live check and its values are cached snapshots. F2 is a directory search made for each evaluation.

| Source | `facts` | `live_check.available` | `live_check.endpoint_class` | `change_feed.mode` | `change_feed.mechanism` | `best_status_max_age_seconds` | `value_semantics` |
|---|---|---|---|---|---|---|---|
| F1 Directory `groups` lookup (`environment.roles`) | `groups` | `false` | Not applicable: no live check | `poll_delta` | Directory change-tracking cookie polled every 30 seconds; a changed group evicts the cached membership | 30 | `cached_snapshot` |
| F2 Directory account state (enabled or disabled) | `identity`, `account_state` | `true` | Directory search | `none` | Not applicable: no change feed | 0 | `authoritative_current` |

#### 8.2 Attribute sources

The gateway reads the group membership and account state of 8.1 and the binding and hold status of F3 and F4, and no other attribute, so no attribute source is listed and the machine-readable form is an empty array.

| Source | `category` | `attributes` | `freshness` |
|---|---|---|---|
| none: the gateway reads no subject, resource, or environment attribute outside 8.1 | Not applicable | Not applicable | Not applicable |

### 9. Residual limits

The profile states two limits, that data already read by the agent cannot be recalled, and that a revocation reaches the gateway only within the stated status bound.

| Limit | What remains true | Bound or disclosure |
|---|---|---|
| Post-read | Invoice data already returned to the agent is not recalled by a later revocation; no egress or data-use control is claimed (draft §17.4, §18) | Disclosed here; no bound |
| Revocation propagation | Removal from a directory group reaches the gateway within the `status_max_age` of F1; a fresh check per evaluation applies to F2 to F4 within each source's own consistency; an operation already executed is not undone by revoking its receipt (draft §18) | 30 s for F1 |

### 10. Fixture index

Eight negative fixtures cover both routes, the three paths that are not `out-of-claim`, and the freshness and outage rows; the fixture IDs are fictional and point to no file, so all eight are listed under "Planned" and `fixtures` in the machine-readable form is empty.

#### Planned

| Fixture ID | Negative case (input) | Expected result | Covers |
|---|---|---|---|
| `EXGW-N01` | Valid PACT admission, native authorization denies the account access to the invoice | No execution (draft §22.2) | R1 |
| `EXGW-N02` | `invoice_id` in the path or the `status` query parameter changed after the contract was issued | Context mismatch (draft §22.2) | R1, R2 |
| `EXGW-N03` | Request to the invoice service port `8443` from a host other than the gateway | Connection refused; no invoice data returned | B1 |
| `EXGW-N04` | Request to a legacy route under `/api/v0/invoices` | Not served; no invoice data returned | B2 |
| `EXGW-N05` | Admin-console request under `/admin/invoices` without a valid presentation | Not `ADMISSIBLE`; no execution | B3 |
| `EXGW-N06` | Required source unavailable at evaluation, one case per source F1 to F4 | `DEFERRED`, never `ADMISSIBLE` (draft §18, §22.2) | F1, F2, F3, F4 |
| `EXGW-N07` | Signed profile containing a self-asserted privileged role | Does not satisfy the authoritative role requirement (draft §22.2) | R1, R2 |
| `EXGW-N08` | Group membership observation older than the 30 s `max_age` | Not `ADMISSIBLE` (draft §5, invariant 5) | F1 |
