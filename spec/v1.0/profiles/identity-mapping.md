# PACT identity mapping rules

This document targets spec version 1.0 and wire version 0.1 and is a draft.

## 1. Purpose and status

Every integration profile maps native identities to PACT identities (template section 7, [`TEMPLATE.md`](TEMPLATE.md)). This document is the part of that mapping that is the same for all of them, so that a profile states only the choices it makes or narrows. It is the profile deliverable for finding G02 of the specification review: namespaced native identifiers, trusted enrollment actors, shared-account handling, certificate, token, and role-session bindings, and lifecycle rules. The negative fixtures that complete the evidence for G02 are separate work and are not part of this document.

The document adds no wire field and no protocol requirement. It states how the identity rules of [`draft.md`](../draft.md) apply when an adapter binds a native workload to an `agent_id` and a holder key. Where this document and the draft differ, the draft governs. The uppercase requirement words have the meanings given in draft §3. Sections 1 to 9 are normative for a profile that claims enforced support, except where a passage is marked informative; section 10 is informative.

A profile can make a rule here stricter. It MUST NOT weaken one. Where the native system cannot satisfy a rule, the profile lists the form as unsupported (template section 6) or the mechanism as out of claim, and it records each departure in the last row of its section 7.

The rules carry the identifiers IM-1 to IM-29 so that profiles, fixtures, and reviews can cite them.

### 1.1 Draft anchors

| Draft section | What it fixes for identity |
|---|---|
| §4.2 | The gateway configures agent-to-native-identity and key-binding rules through its administrative controls. A profile, discovery response, or signed claim cannot install or broaden them. |
| §5, invariants 3, 5, and 8 | An agent cannot reuse another agent's identity; uncertainty never yields a positive result; time cannot clear a security hold. |
| §6.1 to §6.4 | Stable `agent_id`; holder key as an RFC 7638 thumbprint; rotation through an administrative workflow or authorized issuer; compromise is not recoverable with the old key. |
| §8.5 | Native values come from authenticated context or a configured authoritative lookup; mappings preserve issuer, tenant, and identity namespaces. |
| §11.2, §11.3 | The presentation key matches the current enrollment; no binding revocation or hold becomes effective during evaluation. |
| §15.4, §16.5 | Security holds are independent of decay and are cleared only by their configured authority or a preauthorized remediation workflow. |
| §17.1, §17.2, §17.5 | `resolve_agent_binding` takes the realm, the authenticated workload, and the agent ID the request names, and returns the enrolled binding of that agent to that workload: operator, holder key, and current status, or `UNKNOWN` when there is none, together with whether that agent ID is enrolled for another workload of the realm. The agent ID selects only among the enrollments of the workload, and a workload alone never names an agent. When the profile does not support workloads shared by several agents, a workload with more than one enrollment in force is a configuration error: no binding, and `UNSUPPORTED_REQUIREMENT`. Mappings are explicit and versioned, and same-spelled names from different issuers never match by accident. |
| §18 | The gateway tracks the current status of agent and key bindings; an unavailable required source fails closed with `DEFERRED`. |

## 2. Terms

| Term | Meaning in this document |
|---|---|
| Realm | A trust domain identified by `tenant_id` and `environment_id` (draft §3). |
| Native credential | What the native system verifies to authenticate a request: a password, client secret, certificate, bearer token, assertion, or role session. |
| Workload | The authenticated entity a request comes from, as the native system names it: an account, client, service account, role, certificate subject, or login role. |
| Principal | The user or workload whose native authority is relevant to the request (draft §3). Its identifier is the `principal_id` of the operation context (draft §17.5). |
| Enrollment record | The record that binds one agent in one realm to one workload, one operator, and one holder key (section 4). |
| Trusted enrollment actor | An actor allowed to create or change an enrollment record (section 4.2). |
| Holder key | The agent's public signing key, identified by its RFC 7638 thumbprint, `holder_jkt` (draft §6.2). |

## 3. Namespaced identifiers

### 3.1 Grammar

A native identifier is written as a namespace token followed by one or more components, separated by `:`. The grammar uses ABNF (RFC 5234, with the case-sensitive strings of RFC 7405).

```abnf
identifier   = namespace 1*( ":" component )
namespace    = %s"basic" / %s"oauth" / %s"saml" / %s"ldap" / %s"mtls"
             / %s"files" / %s"aws" / %s"k8s" / %s"db" / ext-namespace
ext-namespace = %s"x-" 1*( ALPHA / DIGIT / "-" )
component    = 1*( unreserved / pct-encoded )
unreserved   = ALPHA / DIGIT / "-" / "." / "_" / "~"
pct-encoded  = "%" UPHEX UPHEX
UPHEX        = DIGIT / %x41-46
```

The `:` inside a native value, such as the colons of an ARN or a URI, is therefore written `%3A`. A mechanism without a row in section 3.3, such as a Unix user id or an SMB share identity, uses a namespace token that starts with `x-` and that its profile defines with the same grammar. The `x-` prefix keeps such tokens from colliding with tokens this document adds later.

### 3.2 Rules

**IM-1. Native context only.** Every component comes from the authenticated native context or from a configured authoritative lookup (draft §8.5, §17.1). A header, query parameter, request body, AgentProfile attribute, or model output is never a component, even when it spells a plausible identifier.

**IM-2. One spelling.** A producer writes each component as the UTF-8 octets of the native value, in the canonical form given in section 3.3 where one is given, with every octet that is not `unreserved` written as `%XX` in upper-case hexadecimal and no `unreserved` octet encoded. A consumer rejects an identifier that does not match the grammar of section 3.1 instead of normalizing it, so that one native identity has exactly one spelling.

**IM-3. Exact comparison.** Two identifiers are equal only when they are equal octet for octet. Comparison does no case folding, Unicode normalization, trimming, prefix matching, or wildcard matching.

**IM-4. Full namespace.** An identifier carries the whole chain of issuing authorities that section 3.3 lists for its mechanism: store, issuer, tenant, directory, domain, cluster, certificate authority, or account. Equal local values from different authorities then never compare equal (draft §8.5, §17.2). A component is not dropped because the deployment has a single such authority today; the gateway's configuration supplies it.

**IM-5. Immutable local part.** The local part names the native object by an identifier that the native system keeps for the life of the object. A display name, login name, e-mail address, user principal name, distinguished name, file path, or certificate subject text is never the local part. When section 3.3 offers two sources for a component (`sub` or `oid`, `entryUUID` or `objectGUID`), the profile declares which one it uses and uses only that one.

**IM-6. Name reuse.** Some local parts are names that an administrator can delete and create again with the same text: a Kubernetes service account, an AWS role ARN, a database login role. For such a mechanism the profile MUST either (a) have the adapter compare an immutable object identifier that the native system reports with the one recorded at enrollment, or (b) treat deletion of the native object as a revocation event for every enrollment record bound to it (section 7.4). A profile that does neither lists name reuse as a residual limit (template section 9).

**IM-7. Realm separation.** An identifier is interpreted inside one realm. The same identifier in another tenant or environment names another principal and has its own enrollment (draft §3, §11.2).

### 3.3 Identifier forms per mechanism

| Namespace | Components after the token | Source and canonical form | Never used |
|---|---|---|---|
| `basic` | `store-id` : `account-id` | `store-id` is the configured identifier of the account store. `account-id` is the account's immutable key in that store: decimal digits without leading zeros, or a UUID in lower-case hyphenated form. | The user name or login text, the user-id of the `Authorization` header, a display name, an e-mail address. |
| `oauth` | `issuer-id` : `tenant` : `subject` | `issuer-id` is the configured identifier of the trusted issuer, exactly as its `iss` value is configured. `tenant` is the issuer's tenant identifier; an issuer with no tenant concept uses one constant that the profile declares. `subject` is the issuer's stable subject: `oid` where the issuer defines it as the per-tenant object identifier that is the same across applications, otherwise `sub`. | `email`, `preferred_username`, `upn`, `name`, `jti`, token text, any claim the client chose. |
| `saml` | `sp-id` : `idp-entity-id` : `subject` | `sp-id` is the entity ID of the relying service provider. `idp-entity-id` is the entity ID of the asserting identity provider, exactly as configured. `subject` is the persistent NameID value, or the identifier of the local account that the service provider mapped the assertion to. | A transient or e-mail-format NameID, the assertion ID, the session index, attribute display values. |
| `ldap` | `realm-id` : `unique-id` | `realm-id` is the configured identifier of the directory or domain. `unique-id` is `entryUUID` (RFC 4530) or `objectGUID`, written as a lower-case hyphenated UUID. | The distinguished name, `uid`, `cn`, `mail`, `sAMAccountName`. |
| `mtls` | `ca-id` : `san-kind` : `workload-id` | `ca-id` is the configured identifier of the trusted issuing certificate authority, not the text of its subject name. `san-kind` is `uri` or `dns`. `workload-id` is the value of the subject alternative name entry of that kind that names the workload, which does not depend on the certificate serial: a URI exactly as issued, or a DNS name in lower case, in A-label form, without a trailing dot. | The serial number, the fingerprint, the subject distinguished name, the common name, the validity dates. |
| `files` | `domain-sid` : `user-sid` | `domain-sid` is the SID of the domain, or of the machine for a local account. `user-sid` is the full SID of the user and begins with `domain-sid` followed by `-`. | `DOMAIN\user`, display names, SID history. |
| `aws` | `account-id` : `role-arn` : `session-policy-id` | `account-id` is the 12-digit account identifier. `role-arn` is the ARN of the role, not of the assumed-role session. `session-policy-id` identifies the session policy in force: a managed policy ARN, or the policy digest that the profile defines; `none` when the native system reports no session policy; `unreported` when it cannot report one. | The role session name, a source identity the caller chose, the session token, the part of the user identifier after the colon. |
| `k8s` | `cluster-id` : `system` : `serviceaccount` : `namespace` : `name` | `cluster-id` is the configured identifier of the cluster, not the text of its API server address. `system` and `serviceaccount` are literal; with `namespace` and `name` they spell the service account user name `system:serviceaccount:namespace:name` that the cluster reports for the authenticated token. | The token text, the pod name, the node name, the token audience. A user authenticated through OpenID Connect uses `oauth`. |
| `db` | `cluster-id` : `login-role` | `cluster-id` is the configured identifier of the database cluster or instance. `login-role` is the role the connection authenticated as. | A role assumed after authentication (`SET ROLE`, `SET SESSION AUTHORIZATION`), a value the application sets in the session. |
| ABAC, ReBAC | The identifier of the mechanism that authenticated the request | An attribute or relationship engine decides on facts about a principal and does not authenticate one. The principal is the identifier that the authenticating mechanism produced, in that mechanism's namespace. The engine's own subject label, such as the user of a relationship tuple, is a mapped fact (draft §17.2), not the identifier. | The engine's subject label, taken as the identifier. |

Informative examples, with reserved `.example` names:

| Namespace | Example |
|---|---|
| `basic` | `basic:legacy-accounts:20417` |
| `oauth` | `oauth:https%3A%2F%2Fidp.example%2Ftenant-a%2Fv2.0:7c1d0b3a-5e7f-4a53-9a43-2f7d1f0e9b11:3f2a9d54-0c1e-4d7e-8f1a-5b6c7d8e9f01` |
| `saml` | `saml:https%3A%2F%2Fsp.example%2Fmetadata:https%3A%2F%2Fidp.example%2Fsaml:8f3e1c5a2b` |
| `ldap` | `ldap:corp-directory:4f6c2a1e-9b3d-4c85-a2f0-1d7e6b5a4c39` |
| `mtls` | `mtls:internal-ca-2026:uri:spiffe%3A%2F%2Fexample.org%2Fns%2Fprod%2Fsa%2Frunner` |
| `files` | `files:S-1-5-21-1004336348-1177238915-682003330:S-1-5-21-1004336348-1177238915-682003330-1105` |
| `aws` | `aws:123456789012:arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fagent-runner:none` |
| `k8s` | `k8s:prod-eu-1:system:serviceaccount:payments:agent-runner` |
| `db` | `db:pg-prod-1:agent_ro` |

### 3.4 Principal and workload

Both the principal and the workload are written in this grammar. The enrollment record names the workload, and `resolve_agent_binding` selects it by the realm, the workload, and the `agent_id` that the request names, together (section 4.1, IM-18). Where the authenticated entity is itself the principal, as for an account, a service account, a role, a login role, or a certificate subject, the workload identifier equals the principal identifier. Where a user principal acts through a registered client, such as an OAuth client or a SAML relying party, the principal identifies the user and the workload identifies the client. The profile states the client's identifier form in this grammar. It does not bind an agent to the user alone, because two agents acting for one user would then be indistinguishable (section 5).

## 4. Enrollment

### 4.1 The enrollment record

The record has the fields that draft §17.1 lists for `resolve_agent_binding`, plus its realm and the workload it binds the agent to. `resolve_agent_binding` selects it by the realm, the authenticated workload, and the `agent_id` that the request names, together (IM-18); the workload alone selects no record.

| Field | Meaning |
|---|---|
| Realm | `tenant_id` and `environment_id` of the record. |
| Workload | The identifier, in the grammar of section 3, of the workload the agent runs as. |
| `agent_id` | The stable absolute URI of the agent (draft §6.1). |
| Operator | The accountable operator, verified through native administration (draft §6.1). |
| `holder_jkt` | The RFC 7638 thumbprint of the enrolled public key (draft §6.2). |
| Status | `ACTIVE`, `REVOKED`, `COMPROMISED`, or `UNKNOWN` (section 7.1). |
| Observation time | When the enrollment source last recorded a change to the record. |
| Status check time | When the source last confirmed the status. |
| Source ID, source reference | The configured enrollment source and an opaque reference into it; the reference is empty when there is none. |

**IM-8. One record per agent.** The pair (realm, `agent_id`) identifies one record. A record names exactly one workload and exactly one holder key. An `agent_id` is enrolled once per realm, in any status; a replacement identity is a new `agent_id` (section 7.3).

**IM-9. One key, one agent.** A `holder_jkt` is enrolled for at most one agent in a realm. A thumbprint that was ever enrolled in a realm, whether current or retired by rotation or revocation, is not enrolled again there, for the same agent or another (draft §5 invariant 3; §6.4, old key bindings become invalid).

**IM-10. Observation is not refreshed.** The observation time is the time of the last change to the record: enrollment, rotation, revocation, or compromise mark. A read does not change it. The status check time is the time of the read, because the source answered from its own current state. An adapter never refreshes a stale fact by stamping it with the time of the read and never claims a check it did not perform (draft §8.3, §17.2).

**IM-11. Resolution results.** `resolve_agent_binding` takes the realm, the authenticated workload, and the `agent_id` that the request names (draft §17.1), and resolves the record of that agent on that workload in that realm (IM-18). It returns the record's status, with the agent, operator, and holder key, for a binding that is `ACTIVE`, `REVOKED`, or `COMPROMISED`. It returns `UNKNOWN` with no agent and no key when the agent has no record on the workload in the realm, including an agent enrolled only for another workload, and when its records select none (IM-18). With `UNKNOWN` it reports whether the `agent_id` is enrolled for another workload of the realm, that is, whether the realm holds a record of that `agent_id`, in any status (IM-8), that names another workload. A record in another realm never sets the report, and a result that returns a binding never carries it. The report is the condition that separates `INVALID_PROOF` from `CONTEXT_MISMATCH` in section 8. "Not enrolled" is an answer, not an error. A source that cannot answer returns `DEPENDENCY_UNAVAILABLE` (draft §13.4, §18).

### 4.2 Trusted enrollment actors

Only two kinds of actor may create or change an enrollment record.

| Actor | Meaning | Anchor |
|---|---|---|
| Native administrative workflow | An administrator, authenticated by the environment's existing administrative controls and authorized for the realm, acting through the native enrollment workflow. | Draft §6.1, §6.4 |
| Authorized identity-binding issuer | An issuer that the gateway's administrators configured as trusted to bind identifiers to keys, or to rotate keys, for the realm and for the namespaces of section 3.3 that the configuration names. A generic issuer allowlist is not enough (compare draft §8.3). | Draft §4.2, §6.1, §6.4 |

The following are not trusted enrollment actors: the agent itself or anyone presenting its key, including the holder of the old key; an AgentProfile, discovery response, or signed claim; a reputation service or outcome reporter; a learning controller. Draft §16.2 keeps key recovery authority and trusted-issuer enrollment out of every adaptive field.

**IM-12. Authority is scoped and attributable.** An actor's authority covers one realm. Each change records who made it. A change by an actor without authority for the realm of the record is refused before the record is examined, so a refusal does not disclose whether an agent is enrolled.

**IM-13. No self-registration.** Creating a key, presenting a profile, publishing a discovery document, or signing a claim never creates or widens a binding. An unknown agent does not obtain trusted status that way (draft §6.1), and none of these installs or broadens a trusted actor (draft §4.2).

**IM-14. Enrollment inputs.** The workload identifier comes from the authenticated native context or from an administrator's verified choice (IM-1). The operator is verified through native administration. The enrolling actor SHOULD verify that the agent can prove possession of the key whose thumbprint it records, so that a mistyped or foreign thumbprint is not bound.

**IM-15. Audit.** Every attempt to enroll, rotate, revoke, or mark an agent compromised is retained with the actor, the time, the agent, the old and the new thumbprint, and the result, whether it was applied, refused, or denied for lack of authority. The record of a rotation is the rotation event that draft §6.4 requires a reputation service to retain.

## 5. Shared accounts

An account, client secret, role, or certificate may be used by several agents. Its credential then names the account and nothing more. By default a profile does not support such sharing; IM-19 states the default and the only conditions under which a profile may support it.

**IM-16. A shared credential never names an agent.** Possession of a shared credential distinguishes no agent from another (draft §5 invariant 3, §6.1). The workload that native authentication produces selects no agent by itself: the agent is the one whose `agent_id` the request names, and the workload only limits the records that this `agent_id` can select (draft §17.1, IM-18).

**IM-17. One record per agent.** Each agent that uses a shared account has its own enrollment record, with its own `agent_id` and its own holder key. The records name the same workload.

**IM-18. Selection by the presented agent.** For every request, on a shared workload or not, the record is selected by the `agent_id` that the presentation names, which `resolve_agent_binding` receives with the realm and the authenticated workload (draft §17.1). Only the records of the realm that name both that `agent_id` and the authenticated workload are considered: the `agent_id` never selects a record of another workload, and the workload never selects a record of another agent. The presentation key must equal the selected record's `holder_jkt` (draft §6.2). A record that is `REVOKED` is not in force; a record that is `COMPROMISED` is. Of the records considered, a single record in force is the answer; more than one in force answers `UNKNOWN`, never the first, the last, or the most recent record. When none is in force, a single revoked record is the answer and several revoked records answer `UNKNOWN`. No record considered answers `UNKNOWN`.

**IM-19. Dedicated workloads by default.** By default a profile does not support shared accounts: each workload serves one agent, the profile lists shared accounts as an unsupported form (template section 6), and the shared-account row of its section 7 says that they are not supported. For a workload of such a profile, more than one enrollment in force is a configuration error. Only the records in force count, as IM-18 defines them: a record is in force unless its status is `REVOKED`, so an `ACTIVE`, a `COMPROMISED`, and an `UNKNOWN` record each count toward "more than one", and a `REVOKED` record does not. A workload whose other records are all revoked is therefore not in error, and its records are selected by IM-18. A compromised record keeps counting, so that a compromise is never hidden behind a newer record, and it keeps its workload closed to any new agent: the creation of a record for the workload is refused while it is in force (first item below). The remediation is the native administrative workflow of draft §6.4, which retires the record (`REVOKED`) in the enrollment source (IM-28). The record then no longer counts, and the workload can be enrolled again.

- A request by a trusted enrollment actor to create a record for the workload while a record in force names it is refused.
- If the realm holds more than one record in force for the workload anyway, `resolve_agent_binding` returns no binding for a request authenticated as that workload, whichever `agent_id` the request names: it never selects one of the records, and it reports `UNSUPPORTED_REQUIREMENT` (draft §17.1). The decision is `INADMISSIBLE` with `UNSUPPORTED_REQUIREMENT`, never `DEFERRED`, and the gateway raises an operator alert for the administrators of the enrollment source. For that workload this result is the last row of section 8.

A profile MAY instead support shared accounts, under IM-16 to IM-20, only when its section 7 states a reason that meets both of these conditions:

1. The native mechanism cannot reasonably give each agent its own workload identity, and the profile cites the primary source, an RFC or a vendor document, that shows this limit.
2. PACT still tells the agents apart: each agent has its own record and holder key (IM-17), and the record is selected by the `agent_id` that the presentation names (IM-18).

A profile that authenticates no request itself, such as an attribute or relationship engine (section 3.3) or a broker whose front door another profile authenticates, makes no choice of its own. It inherits the choice of the profile that authenticated the request, with its consequence, and its section 7 says so.

**IM-20. Independence.** Changing or re-issuing the shared credential changes no record. Marking one agent's key compromised changes no other record of the account. A compromise of the credential itself is handled by the native system's credential reset; it does not by itself mark any holder key compromised.

Expected results, in a profile that supports shared accounts, for an account shared by agents A (key KA) and B (key KB), where agent C is not enrolled:

| Request | Binding result | Admission |
|---|---|---|
| Account authenticated, presentation by A signed with KA | Record of A, workload matches | Continues to the other checks |
| Account authenticated, presentation by A signed with KB | Record of A, key differs | Not admissible (section 8) |
| Account authenticated, presentation by C | No record for C | Not admissible (section 8) |
| Account authenticated, no agent named | No record selected: the workload alone names no agent, `UNKNOWN` (IM-16, IM-18) | Not admissible |

In a profile that does not support shared accounts, the records of A and B on one account, both in force, are the configuration error of IM-19, and every request authenticated as that account, whichever agent it names, gets the result that IM-19 states.

## 6. Certificate, token, and role-session bindings

Three things are kept apart: the native credential authenticates the workload; the enrollment record binds that workload to an agent and its holder key; each presentation proves possession of the holder key. None of the three substitutes for another (draft §6.2).

**IM-21. The holder key is bound only by enrollment.** A holder key is not accepted because a native credential carries or certifies it: a certificate that contains the same public key, a token constrained to that key (for example by a `cnf` claim, RFC 7800, or DPoP, RFC 9449), or a credential issued in the same workflow. Such a constraint binds the credential to its client and does not enroll the key. The binding exists only through an enrollment record that names the key.

### 6.1 Certificates

A certificate is mapped only after the native system validated its chain to a configured trust anchor.

**IM-22. Bind to the stable workload identifier.** The binding is to the (`ca-id`, `san-kind`, `workload-id`) of section 3.3. A renewed certificate from the same authority with the same subject alternative name is the same workload under a new serial. The serial number, the fingerprint, and the subject text are not part of the identity. A certificate from a different authority is a different identity and needs its own enrollment. Expiry or revocation of a certificate is a failure of native authentication, not a change to the record. A certificate with several subject alternative name entries of the profile's kind is refused unless the profile names the selection rule.

### 6.2 Tokens and assertions

**IM-23. Bind to the issuer-scoped subject.** The binding is to the issuer, tenant, and stable subject of section 3.3. The token text, its `jti`, and its lifetime are properties of the credential: issuing a new token to the same subject keeps the binding, and a token that carries a different subject is a different identity. Claims are read only after the native system validated the token, or only from an introspection result for an opaque token. A user name, e-mail address, or display claim is a display attribute and never part of the identity. A subject that the issuer deleted and created again with a new stable identifier is a new identity.

### 6.3 Role sessions

**IM-24. Bind to the role, not to the session.** The binding is to the role or service account (and to the session policy where section 3.3 lists one). The session name, the session identifier, a caller-chosen source identity, and a pod or node name are not identity: a new session of the same role keeps the binding, and a caller cannot choose a session name to become another principal. Two sessions of one role with different session policies are different identifiers; when the native system cannot report the session policy, the profile uses `unreported` and lists, as a residual limit, that such sessions are not distinguished. Deleting and recreating the role falls under IM-6.

## 7. Lifecycle

### 7.1 Statuses and transitions

| Status | Meaning |
|---|---|
| `ACTIVE` | Enrolled and in force. |
| `REVOKED` | The binding was withdrawn: the agent was retired, the operator off-boarded, or the native object deleted. The record still names the agent and the key. |
| `COMPROMISED` | An authority marked the identity compromised. The record still names the agent and the key. |
| `UNKNOWN` | No current binding can be established, including a workload that is not enrolled (IM-11). It is never treated as `ACTIVE`. |

The operations a trusted enrollment actor can apply to a record, by status:

| Operation | `ACTIVE` | `REVOKED` | `COMPROMISED` |
|---|---|---|---|
| Rotate the holder key | `ACTIVE` with the new key | Refused | Refused |
| Revoke | `REVOKED` | No change | Refused |
| Mark compromised | `COMPROMISED` | `COMPROMISED` | No change |
| Enroll the same `agent_id` again | Refused | Refused | Refused |

Any of these operations by an actor that is not trusted (section 4.2) is refused in every status.

### 7.2 Rotation

**IM-25. Rotation is an administrative act.** Routine rotation uses a native authenticated administrative workflow or an authorized issuer (draft §6.4). A signature by the old key proves possession of the old key and is not authority to rotate. The new thumbprint satisfies IM-9. Rotation applies to an `ACTIVE` record and leaves its status `ACTIVE`.

**IM-26. Effects of rotation.** The old key stops being the enrolled key as soon as the source records the rotation, and everywhere after the propagation bound of section 7.5. The agent needs a new AgentProfile and fresh key-bound evidence: a profile or evidence that names the old `holder_jkt` fails the holder-binding check (draft §6.4, §11.2). The rotation event is retained (IM-15). A reputation service MAY keep an agent's history across a verified routine rotation and MUST NOT carry a trusted score to a different `agent_id` (draft §6.4). An `agent_id` that is a `did:key` changes when its key changes (draft §6.3), so rotating the key of such an agent is a new enrollment under a new `agent_id`, and continuity of history is established separately, never by the identifier.

### 7.3 Compromise

**IM-27. Only an authority marks compromise.** The mark is made by a trusted enrollment actor. An agent that suspects its own key is compromised reports it through any channel, and it takes effect only when an authority marks it. The mark triggers the configured security hold and the re-evaluation of affected evidence and outcomes (draft §6.4).

**IM-28. Compromise is terminal.** Nothing in this document returns a `COMPROMISED` record to `ACTIVE` or `REVOKED`. It is not recovered by proof with the old key, by proof with a new key, by rotation, by enrolling the same `agent_id` again, by the agent's own assertion, or by the passage of time (draft §5 invariant 8, §6.4, §15.4). This document defines no transition out of `COMPROMISED`, and the operations of section 7.1 refuse to revoke such a record. Under the default of IM-19 it keeps its workload closed to any new agent, and the remediation is the native administrative workflow of draft §6.4, run in the enrollment source outside those operations, which retires the record (`REVOKED`). Once the record is retired the workload can be enrolled again. A deployment that recovers a compromised agent clears the hold through the remediation process that draft §16.5 describes, and enrolls the agent as a new identity with a new `agent_id` and a new key. The new identity starts with the conservative requirement set (draft §15.4).

### 7.4 Revocation

**IM-29. Revocation is withdrawal.** A trusted enrollment actor revokes a record when the agent is retired, the operator no longer vouches for it, or the native object it was bound to was deleted (IM-6). `resolve_agent_binding` then returns `REVOKED` with the agent and key, so that a validator can state the reason. A revoked record is not rotated or enrolled back to life, and it can still be marked compromised.

### 7.5 Propagation bound

Draft §6.4 makes old key bindings invalid "according to the configured propagation bound" and sets no value. The bound is the longest time between a change at the enrollment source (rotation, revocation, or compromise mark) and its effect at every validator and cache of the gateway.

- Each profile declares its bound in the revocation propagation row of its section 9, for the enrollment source, and the status age that source can achieve in its section 8, and it states whether the source's answers are current authoritative state or cached snapshots (draft §17.2).
- A cached binding whose status check time is older than the bound is not used.
- A binding status that gates admission SHOULD use zero staleness, as draft §18 asks for hold checks and sensitive native authority.
- A source with eventual consistency declares its worst-case replication delay as the bound. PACT does not promise instantaneous revocation (draft §18).
- When the source is unavailable, the decision is `DEFERRED` (draft §18). A cached `ACTIVE` older than the bound does not stand in for the source.
- A revocation or hold that becomes effective while an evaluation is running prevents a positive result (draft §11.3, step 10).

## 8. What a validator concludes

The draft fixes the decision classes (§11.4) and the meaning of each code (§13.4). The mapping of identity conditions to them below is derived from draft §6.1, §6.2, §6.4, §11.2, §11.3, and §18, and the negative fixtures pin the exact results. The table is informative. Its last column says whether the condition is found before an authenticated evaluation, as a transport error with no receipt (draft §12.2), or during one, in a receipt: a receipt exists exactly when the binding is in force (IM-18) and the presentation key is its `holder_jkt`, or when the source that would say so cannot answer.

| Condition | Decision | Code | Form |
|---|---|---|---|
| The binding of the presented `agent_id` on the authenticated workload is `ACTIVE`, and the presentation key matches | Continues to the other checks | None | Authenticated evaluation; the receipt records the binding check as `PASS` |
| The presented `agent_id` is not enrolled in the authenticated realm, including an agent enrolled only in another realm, because the adapter searches only the authenticated realm (IM-7), or the authenticated workload has no record of it and no other workload of the realm has one: `resolve_agent_binding` returns `UNKNOWN` without the report (IM-11) | `INADMISSIBLE` | `INVALID_PROOF` | Transport error, no receipt (draft §11.3 step 2, §12.2). This row is found before the realm of the presentation (step 3): an agent with no binding in the authenticated realm gets `INVALID_PROOF` whatever tenant or environment its presentation names |
| The presentation key is not the enrolled `holder_jkt`, including a retired key after rotation | `INADMISSIBLE` | `INVALID_PROOF` | Transport error, no receipt |
| Binding `REVOKED` | `INADMISSIBLE` | `INVALID_PROOF` | Transport error, no receipt: a revoked record is not in force (IM-18) |
| Binding `COMPROMISED`, presentation key matches | `INADMISSIBLE` | `SECURITY_HOLD` | Authenticated evaluation and receipt: the record is in force (IM-18) and the presenter is the enrolled agent, and the mark is a hold on it (draft §6.4, §13.4). The binding check is `FAIL` with `SECURITY_HOLD`, whether or not the hold store already lists the hold (section 7.5) |
| The agent is enrolled in the authenticated realm for a workload other than the authenticated one, which `resolve_agent_binding` reports with `UNKNOWN` (IM-11) | `INADMISSIBLE` | `CONTEXT_MISMATCH` | Transport error, no receipt |
| The presentation names a tenant or environment other than the authenticated realm, and the binding resolves in that realm | `INADMISSIBLE` | `CONTEXT_MISMATCH` | Authenticated evaluation and receipt: the contract check fails (draft §11.3 step 3) |
| The enrollment source cannot answer | `DEFERRED` | `DEPENDENCY_UNAVAILABLE` | Authenticated evaluation and receipt: the binding check is `UNKNOWN` (draft §12.2, §18), with retry guidance |
| More than one enrollment in force for the workload, in a profile without shared workloads (IM-19) | `INADMISSIBLE` | `UNSUPPORTED_REQUIREMENT` | Transport error, no receipt; operator alert |

## 9. Using this document in a profile

Section 7 of a profile answers the rows below by pointing to this document and recording only its own choices.

| Template row | Where to look |
|---|---|
| Native identifier namespaces | Section 3: the namespace tokens and component sources the profile uses, and any `x-` namespace it defines. |
| Trusted enrollment actors | Section 4.2: which of the two actors the profile uses, and for which namespaces an issuer is authorized. |
| Shared-account handling | Section 5: not supported, the default of IM-19, where more than one enrollment in force for a workload is a configuration error; or supported, with the reason IM-19 requires and the rules IM-16 to IM-20; or, for a profile that authenticates no request itself, inherited from the profile that authenticated the request. |
| Certificate, token, or role-session bindings | Section 6: which credential is bound, and which stable identifier it is bound to. |
| Lifecycle rules | Section 7: the propagation bound (template section 9, revocation propagation) and the status age of the enrollment source (template section 8). |
| Departures | Section 1: each place the profile is stricter, and any rule the native system cannot meet. |

## 10. Limits of this document

This section is informative.

- The remediation process that clears a hold and the re-enrollment of a recovered agent are not defined here (IM-28). Draft §16.5 names the authority and the evidence; the workflow belongs to the deployment.
- The draft sets no baseline propagation bound for binding status (section 7.5). A profile states its own.
- Whether a native system reports a session policy, an immutable object identifier for IM-6, or a stable subject depends on the product. A profile that cannot obtain one records the limit instead of substituting a mutable value.
- Identifier forms for mechanisms without a row in section 3.3 are left to their profiles under an `x-` namespace until a row is added here.
