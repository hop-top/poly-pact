# Integration 12 — Relationship-based access control (ReBAC)

**Status:** Informative integration example for PACT Protocol v1.0. Organizations, identifiers, routes, requirements, and thresholds are fictional deployment choices. Excerpts are incomplete illustrations, not signed wire fixtures or a tested implementation. The gateway needs the described installed adapter; the named platform is not claimed to support PACT natively.

**Readiness review (2026-10-15):** Conditional design only. This narrative does not establish a live integration, interoperability, or end-to-end security result. Read the assumptions, components, and unresolved items before interpreting the successful exchange.


## Assumptions, required components, and unresolved gaps

**Review ID:** I12. Finding and component IDs refer to the companion handoff.md. These are editorial identifiers, not new protocol fields or registered reason codes.

### Assumptions

- The application supplies trusted user/agent/task binding and configured relationship store/model.
- Its query/cache policy and relationship-write controls support the advertised consistency.

### Required components

The shared baseline requires C01–C03, C05, C07, C09–C10, C13–C14, and the current policy/artifact registry portion of C12. These cover the enforced gateway, trusted native/identity adapters, evidence, task/request mapping, atomic exchange state, attributable records, holds, and protected storage. This scenario additionally requires or makes explicit:

| Component ID | Scenario-specific responsibility |
|---|---|
| C04 | User/agent project-task authority. |
| C07 | Configured tenant/store/model/relation/object mapping. |
| C08 | Native relationship decision and document enforcement. |

C11 and the full C12 lifecycle are needed wherever reputation or adaptation is used; an authorized current conservative baseline is still required without adaptive relaxation. C16 actual containment is required for the runtime/data-use guarantees claimed, not merely because a profile includes a runtime label.

### Unresolved gaps

Shared open work: G01, G02, G04, G05, G07, G13, G24, G27. The draft already states many underlying security rules; profiles, implementations, and evidence still need to establish them. Specific issues exposed here:

| Finding | Issue to resolve | Classification |
|---|---|---|
| G03 | Actor binding and executor identity: see the Actor binding section below, Section 17.5, and the `execution-identity-v1` check. | Profile / clarification |
| G23 | Define consistency, contextual facts, updates, and legitimate alternative sharing paths. Specified for an OpenFGA relationship store by the integration profile [`rebac`](../profiles/rebac/profile.md), whose section 12 maps each G23 item to rules and cases. | Profile |

### Deliberate simplifications and limitations

- The OpenFGA server, store, and model are the deployment's and are assumed; the adapter that calls them is specified by the integration profile and has a reference implementation (`go/adapters/rebac`, source repository).
- Removing a membership may leave a direct share; instantaneous global revocation is not demonstrated.

### Profile and fixtures

The integration profile [`rebac`](../profiles/rebac/profile.md) states the conformance claim behind this sample: `authorize_native` is one OpenFGA Check per protected operation, against the store and model of a pin record in trusted configuration (rules RB-1 to RB-3), with the relation chosen by the action from a versioned table (rule RB-5), the subject and object produced by a registry that keeps tenants apart (rules RB-4 and RB-6), no contextual tuple from the agent (rules RB-7 and RB-8), `HIGHER_CONSISTENCY` on every Check and no adapter cache (rules RB-9 and RB-10), and the full model deciding, so that a remaining direct share legitimately keeps access (rule RB-14). It claims two routes, R1 (read, relation `viewer`) and R2 (edit, relation `editor`); this sample's model defines no `editor`, so the profile's reference model adds it as a direct assignment (open item O-5). The principal is the identifier of the mechanism that authenticated Maya; the relationship engine authenticates nobody (profile section 7). The adapter cases are in [`fixtures/adapters/rebac/`](../fixtures/adapters/rebac/README.md), registered in the fixture manifest, with this sample's model as the asset `adapters/rebac/model` and a later model of the same store as `adapters/rebac/model-next`; the decisions table below names the case group or case for each row. The cases run against a fake store that the harness builds; an integration tier runs the cases an OpenFGA server can realize only when one is configured.

### Validation still required

The cases cover other tenants and models, injected tuples, stale membership, outage, view-to-edit changes, and the removal of inherited access with and without a remaining direct share, at the adapter. These remain unvalidated:

- The probes of the profile against the deployment's pinned OpenFGA release and datastore: that the consistency preference is accepted and effective (P-1), that `HIGHER_CONSISTENCY` reaches the primary datastore when a replica exists (P-2), the cache defaults actually in force (P-3), and the identifier form of rule RB-6 (P-4). The profile's probe record of 2026-10-18, on OpenFGA v1.10.0 with an in-memory datastore, confirms the documented behaviour the cases rely on and closes none of them for a deployment.
- That one store credential can be limited to Check (P-5), that the adapter has no write path to the store, and that the agent has no route to the store API (open item O-1; bypass path B6, `out-of-claim`), or to the document service around the gateway (B5, `out-of-claim`).
- A principal with no registry entry, and a `user` that is a userset or a wildcard (open item O-2).
- The rollout time of a new pin record or mapping, and the gap between the Check and the document service's operation (profile section 9).
- The definitions of `native-principal-binding-v1`, `native-delegation-v1`, and `execution-identity-v1`, which the profile names and leaves to the delegation work of finding G03 (profile section 7.1).

No finding is closed by this narrative or by the fixture coverage above. Native IAM, approvals, resource policy, and execution remain responsibilities of the environment; the dependencies are not a proposal to move those subsystems into the PACT core.

## Situation

Maya belongs to the Orion project. A briefing document belongs to that project. Northstar's collaboration system authorizes document viewing through those relationships, with optional direct sharing to individual users.

A research assistant acts for Maya on an approved project-summary task. Its organizational role alone does not establish access: the native relationship model decides whether Maya may view this document.

## Native relationship model

This illustrative model has three object types and the following semantics:

| Type | Relationship or permission |
|---|---|
| User | A native collaboration principal |
| Project | A `member` relationship to users |
| Document | A `parent` project, optional direct viewers, and derived `viewer` permission from project membership |

The stored facts include Maya's membership in Orion and the briefing's parent project. Under the installed model, those relationships make Maya a viewer of the briefing. OpenFGA documents this style of user/object and object/object authorization, including parent-child inheritance; see [authorization concepts](https://openfga.dev/docs/authorization-concepts) and [parent-child models](https://openfga.dev/docs/modeling/parent-child).

PACT neither creates these tuples nor changes their meaning. Access through a direct share can also be legitimate if the native model permits it; the agent need not prove one particular relationship path when the installed model permits alternatives.

## Required agent context

| Fact | Source and purpose |
|---|---|
| `/attributes/environment/principal_id` | Native authenticated account mapped to the relationship subject; the identifier is that of the authenticating mechanism, never an OpenFGA label (integration profile section 7) |
| `/attributes/environment/tenant_id` | Current trusted collaboration tenant |
| `/attributes/delegation/authority_ref` | Native Maya-to-agent project-summary task authorization |
| Required runtime/capability facts | Trusted issuers under the selected PACT set |
| Document and purpose mapping | Gateway-derived actual target and recognized task |

The gateway maps the authenticated principal to the opaque subject `user:u-0042` inside the configured store, through its registry, and the briefing to `document:northstar.orion-brief`; the ids carry the realm namespace and no personal data (integration profile, rules RB-4 and RB-6). A profile value saying “Orion member” is not a tuple and cannot install membership. Even a correctly signed claim does not authorize its issuer to modify the native relationship graph (rule RB-8).

## Actor binding

This table applies Section 17.5 to this sample. It adds no field. Every actor transition is native: PACT records and checks it and never mints it.

| Actor | Binding field or check | Native source |
|---|---|---|
| Agent | `sub`, `holder_jkt` | Enrollment of the research assistant, resolved by the gateway (Sections 6.1 and 6.2) |
| Principal | `OperationContext.principal_id`; check `native-principal-binding-v1` | `authenticate_native`: the native authenticated account, which the gateway maps to the relationship subject `user:u-0042` in the configured store (Section 17.1) |
| Authorized task | `Intent.task_id`, reconciled with the authoritative task context | `task_attribution_source`: the approved project-summary task |
| Native delegation | `/attributes/delegation/authority_ref`; check `native-delegation-v1` | Native Maya-to-agent project-summary task authorization |
| Broker or gateway | `aud`, `environment_id` | Trusted configuration (Section 4.2): the collaboration gateway, with its configured tenant, store, and model |
| Downstream executor | Check `execution-identity-v1`; declared class `delegated-user` | The document service, which performs the read for Maya after the native relationship check |

The installed `execution-identity-v1` mapping declares the class `delegated-user` for Maya, the project-summary task, and the briefing-document read. The check returns `PASS` only when the executor that will run the read equals that class and binding. The relationship check is sent for `user:u-0042`, Maya's subject, so `authorize_native` is invoked with Maya as the principal, never with the executor's own authority (integration profile, rule RB-19).

Adversarial results (Section 17.5):

- A relationship subject from another tenant presented as Maya: `native-principal-binding-v1` returns `FAIL` with reason code `CONTEXT_MISMATCH`.
- The read presented under a task other than the approved project-summary task: `native-delegation-v1` returns `FAIL` with reason code `TASK_MISMATCH`.
- The user-to-agent delegation is stale or revoked: `native-delegation-v1` returns `FAIL` with reason code `STALE_EVIDENCE` or `REVOKED_EVIDENCE`.
- The read would run, or the relationship check would be made, under a broader service or administrator subject in place of `user:u-0042`: `execution-identity-v1` returns `FAIL` with reason code `EXECUTOR_MISMATCH`.
- The executor cannot be determined: `execution-identity-v1` returns `UNKNOWN`, which yields `DEFERRED`.

Executor evidence (Section 14.2): each `AUTHORIZATION` and `EXECUTION` report in this sample references, in `evidence_refs`, an immutable native record identifying the actual executor identity. Section 14.2 states this without exception for the denial of a missing relationship path. A report whose executor class differs from the declared `delegated-user` class is `UNQUALIFIED`.

## Successful exchange

1. The gateway authenticates the user/workload, resolves the enrolled agent/key, validates its native delegation, and maps the exact briefing-document read.
2. It issues a signed operation-bound PACT contract. The assistant supplies the required profile/evidence and signs a complete presentation.
3. The validator checks all required identity, provenance, request/purpose, nonce, status, and hold conditions. These pass and produce `ADMISSIBLE`.
4. The gateway separately sends an authenticated native authorization check to its configured OpenFGA store/model: `POST /stores/{store_id}/check` with the pinned store, naming the pinned model and asking for `HIGHER_CONSISTENCY` (integration profile, rules RB-2 and RB-9). A partial request body could be:

```json
{
  "authorization_model_id": "<pinned-model-id>",
  "tuple_key": {
    "user": "user:u-0042",
    "relation": "viewer",
    "object": "document:northstar.orion-brief"
  },
  "consistency": "HIGHER_CONSISTENCY"
}
```

5. The relationship service evaluates the installed model and stored relationships. With the stated facts it allows the view. The document service then performs the read subject to its remaining execution conditions.

The store, model version, subject mapping, relation, and object mapping come from installed configuration and actual request context. The agent cannot choose a permissive store/model or supply arbitrary contextual tuples. See the [OpenFGA Check API guide](https://openfga.dev/docs/getting-started/perform-check).

## Relationship changes and alternative paths

The check returns whether the native permission is established under the model, not a universal statement of trust. If Maya is removed from Orion, the inherited membership path disappears. A remaining direct share might still permit access; the gateway must evaluate the full native model instead of assuming that deleting one relationship removes every route. Under the integration profile, the decision is exactly the Check's `allowed` at the pinned model: the adapter neither denies because one path is absent nor looks for paths with Expand or Read (rules RB-14 and RB-15; `REBAC-05`).

The adapter documents relationship consistency and cache bounds; the integration profile does so in sections 8.2 and 9. Every Check asks `HIGHER_CONSISTENCY`, which skips the documented server caches, and the adapter caches no decision, so a tuple change reaches the next Check within the datastore's own consistency, subject to probes P-1 and P-2. Subsequent operations perform the required current checks. PACT freshness does not itself guarantee instantaneous propagation of tuple deletions.

## Decisions and failure variations

| Condition | Expected behavior | Profile case |
|---|---|---|
| Verified agent/delegation and native `viewer` relation established | Admit and execute | `adapters/rebac/rebac-10`, `adapters/rebac/rebac-12` |
| Valid organizational role, no native relationship path | Native authorization denies | `adapters/rebac/rebac-11` |
| Membership removed and no alternative share remains | Later current check denies | `adapters/rebac/rebac-05.no-remaining-path`; a store cache that still holds the removed membership is not used: `adapters/rebac/rebac-04.stale-membership` |
| User loses membership but retains a legitimate direct share | Native model may still allow; apply its actual semantics | `adapters/rebac/rebac-05.direct-share` |
| Agent names a relationship from another tenant | Namespace/store mapping prevents substitution: `CONTEXT_MISMATCH`, and no Check is sent | `REBAC-01`, `REBAC-09` |
| Agent names a store or model in the request | Not read; the Check names the pinned model | `adapters/rebac/rebac-02.query-model-id`, with the control `adapters/rebac/rebac-02.pinned-model` |
| Required relationship service unavailable | No native allow; no protected execution: `DEFERRED` with `DEPENDENCY_UNAVAILABLE` | `REBAC-06` |
| Agent offers a new “member” tuple in its profile | Treat as untrusted data, not an authorization update | `REBAC-03` |
| View permission exists but task asks for editing | Separate operation and native relation/action check required: the edit maps to `document.write` and relation `editor`, and a read-bound presentation is a context mismatch | `REBAC-07`, `REBAC-08` |

## Reputation, approval, and learning

Qualified research outcomes may update this agent's reputation in the correct project-document context. A missing relationship or ordinary denial is not automatically misconduct. A successful membership check is not task-performance evidence. Section 14.5 maps this exchange: the “PACT admission decision” (`ADMISSION`) carries zero weight, the “Native authorization allow” (`AUTHORIZATION`) is that membership check and also carries zero weight, a missing relationship path is a “Native denial” (`AUTHORIZATION`, `FAILURE`, `none`) with zero weight, and the permitted document read is “Execution completed with data returned” (`EXECUTION`, `SUCCESS`, `reliability`).

If a project owner grants a share through the existing application, a fresh PACT exchange and native check can reflect the new relationship. PACT does not contact the owner or create the share itself. Learning cannot manufacture membership, select another tenant's model, or transform `viewer` into `editor`.

## Boundary demonstrated

PACT establishes the verified actor and task context. The relationship engine retains the decision about how that principal is connected to the requested resource.

**PACT anchors:** §§2.3, 4, 8–12, 14–18.

## Primary references

- [OpenFGA authorization concepts](https://openfga.dev/docs/authorization-concepts)
- [OpenFGA parent-child objects](https://openfga.dev/docs/modeling/parent-child)
- [OpenFGA permission checks](https://openfga.dev/docs/getting-started/perform-check)
