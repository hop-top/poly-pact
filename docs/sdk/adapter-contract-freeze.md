# Adapter contract freeze

Status: recorded 2026-10-19 against `main` at `9e2a7af`. Plan: [ports-plan.md](ports-plan.md), section 5.5. Names in the ports: [parity-ledger.md](parity-ledger.md).

This note fixes the Go adapter contract that the TypeScript and Python ports implement in phase 3: the exported symbols of `go/adapter`, `go/adapter/enroll`, `go/adapter/enroll/memory` and `go/adapter/freshness`, and the case model of `go/adapter/adaptertest`. It records the decisions those symbols rest on and the rule for changing them.

## 1. Change rule

From this note on, a change to a listed symbol (added, removed, renamed, a changed signature, field type or constant value, or a changed documented behaviour) does three things in the same change:

1. it updates the symbol's rows in [parity-ledger.md](parity-ledger.md); a `done` row whose ports no longer match the Go symbol goes back to `planned`, since `done` means both ports have it under those names with its tests ported;
2. it updates the tables of section 3 of this note;
3. it opens one port task per language (TypeScript, Python) that brings the port back to the Go symbol.

An exported symbol added to a listed package is listed from the change that adds it. `tools/parity/api_ledger.py` fails when a symbol has no ledger row; it does not check this note, so the reviewer of a change to these packages checks section 3.

The language-neutral adapter case files (`spec/v1.0/fixtures/adapters/`) are not frozen here. A change to their members follows section 5.4 of the plan; where it adds a member, the `adaptertest` field that reads it is a listed symbol and the rule above applies to it.

## 2. Decisions the contract rests on

| Decision | Source | Where it shows in the contract |
|---|---|---|
| The seven logical functions and their inputs; behavioural contracts, not new REST APIs | draft [17.1](../../spec/v1.0/draft.md#171-required-adapter-capabilities) | the seven interfaces of section 3.1 |
| `resolve_agent_binding` takes the realm, the authenticated workload and the agent ID the request names; it returns that agent's enrollment on that workload, `UNKNOWN` when there is none, together with whether the agent ID is enrolled for another workload of the realm; a workload alone never names an agent | draft [17.1](../../spec/v1.0/draft.md#171-required-adapter-capabilities) | `BindingResolver.ResolveAgentBinding(ctx, realm, workload, agent)`; `AgentBinding.EnrolledElsewhere`; `BindingUnknown`; `enroll.Resolver` |
| A workload with more than one enrollment in force, under a profile without shared workloads, is a configuration error: no binding, `UNSUPPORTED_REQUIREMENT` | draft [17.1](../../spec/v1.0/draft.md#171-required-adapter-capabilities) | `ErrUnsupportedRequirement`; `enroll/memory` `WithSharedWorkloads`; `adaptertest` `Options.SharedWorkloads` |
| `read_native_claim` reads an approved native path in its context: principal, intent (task scope) and operation (resource scope); an adapter reads nothing else from the request | [adapter inputs](../design/adapter-inputs-and-attribute-sources.md), D2; draft [17.1](../../spec/v1.0/draft.md#171-required-adapter-capabilities) | `ClaimContext{Principal, Intent, Operation}`; `ClaimReader.ReadNativeClaim(ctx, nativePath, c)` |
| `check_context` receives the installed check ID, the authenticated principal with its attributes, the binding the validator verified, the intent, the operation and the evidence references; a check that compares the agent or the principal compares against these inputs, never against a value the presentation, the profile or an evidence artifact carries, and does not re-judge the binding's status; `native-principal-binding-v1` is not run through `check_context` | draft [17.1](../../spec/v1.0/draft.md#171-required-adapter-capabilities); [adapter inputs](../design/adapter-inputs-and-attribute-sources.md), D2 | `CheckInput{Principal, Binding, Intent, Operation, EvidenceRefs}`; `ContextChecker.CheckContext(ctx, checkID, in)` |
| The agent and the principal of the approval scope comparison are the `check_context` inputs; the approval-class result table maps native state to `CheckResult.result` and `reason_code` | draft [17.3.1](../../spec/v1.0/draft.md#1731-approval-exception-and-activation-check-results) | `CheckOutcome{Result, ReasonCode, ...}`; `Verdict` and `Verdict.CheckStatus` |
| `authorize_native` sees the original principal and the actual operation, never the PACT contract; PACT cannot rewrite a denial | draft [17.1](../../spec/v1.0/draft.md#171-required-adapter-capabilities); [adapter inputs](../design/adapter-inputs-and-attribute-sources.md), D2 | `NativeAuthorizer.AuthorizeNative(ctx, p, op)` unchanged |
| A decision carries its provenance: the native policy source (required), the immutable decision record, the decision time, the policy revision; obligations keep their shape, typed by the native policy and never interpreted by PACT | [adapter inputs](../design/adapter-inputs-and-attribute-sources.md), D1 | `Decision.SourceID`, `SourceRef`, `DecidedAt`, `PolicyRevision`; `Obligation{ID, Attributes}`; `adaptertest` `ExpectDecision` |
| A request that violates the baseline HTTP mapping, an ambiguous encoding among them, is rejected with `INVALID_MESSAGE` | draft [10.2](../../spec/v1.0/draft.md#102-actual-operation), [13.4](../../spec/v1.0/draft.md#134-errors) | `ErrInvalidMessage`, `CodeInvalidMessage`, returned by `OperationMapper.MapOperation` |
| Adapter calls are synchronous with `context.Context` in Go, `Promise` with `AbortSignal` in TypeScript, synchronous `Protocol` in Python; instants have nanosecond, millisecond and microsecond precision | [ports-plan.md](ports-plan.md), section 2 | ledger rows with status `deviation` |

The attribute-source schema and the planned-fixtures convention of the same design note (D3, D4) concern the integration-profile files, not the Go API, and are not part of this freeze.

## 3. Frozen symbols

369 symbols: every exported symbol of the four contract packages (147, 46, 18 and 20) and 138 of `adaptertest`. The tables group them as `go doc` does: a constant, function or method sits on the row of its type. `python3 -I tools/parity/api_ledger.py --list` prints the same symbols, one per line.

### 3.1 The seven functions

| Draft 17.1 function | Go interface and method | TypeScript | Python |
|---|---|---|---|
| `authenticate_native` | `NativeAuthenticator.AuthenticateNative(ctx context.Context, r *http.Request) (Principal, error)` | `authenticateNative(req: RawRequest, signal?)` | `authenticate_native(req: RawRequest)` |
| `resolve_agent_binding` | `BindingResolver.ResolveAgentBinding(ctx context.Context, realm Realm, workload Workload, agent AgentID) (AgentBinding, error)` | `resolveAgentBinding` | `resolve_agent_binding` |
| `map_operation` | `OperationMapper.MapOperation(ctx context.Context, r *http.Request, p Principal, mappingVersion string) (core.OperationContext, error)` | `mapOperation` | `map_operation` |
| `read_native_claim` | `ClaimReader.ReadNativeClaim(ctx context.Context, nativePath string, c ClaimContext) (NativeClaim, error)` | `readNativeClaim` | `read_native_claim` |
| `check_context` | `ContextChecker.CheckContext(ctx context.Context, checkID string, in CheckInput) CheckOutcome` | `checkContext(checkId, input, signal?)` | `check_context(check_id, input)` |
| `authorize_native` | `NativeAuthorizer.AuthorizeNative(ctx context.Context, p Principal, op core.OperationContext) (Decision, error)` | `authorizeNative` | `authorize_native` |
| `record_outcome` | `OutcomeRecorder.RecordOutcome(ctx context.Context, o Observation) (Recorded, error)` | `recordOutcome` | `record_outcome` |

Every adapter also implements `Adapter.Describe() Descriptor`; one that serves more than one native protocol form also implements `MultiDescriber.Descriptors() []Descriptor`, one descriptor per form, the primary form first.

`RawRequest` is a port type with no Go symbol: Go passes the `*http.Request`, the ports pass the method, the raw request-target, the ordered header pairs, the body and an optional TLS peer ([ports-plan-ts.md](ports-plan-ts.md), section 3; [ports-plan-py.md](ports-plan-py.md), section 2, row `binding.FromRequest`). It is frozen with the contract: the same rule of section 1 applies to it. Its TLS peer has the attributes of `adaptertest.TLSPeer`: `subjectCN`, `issuerCN`, `dnsNames`, `uris` in TypeScript and `subject_cn`, `issuer_cn`, `dns_names`, `uris` in Python; the case files spell them `subject_cn`, `issuer_cn`, `dns_names`, `uris`.

There are seven sentinel errors and seven codes; the seventh, `ErrMissingField` (`MISSING_FIELD`), is `AdapterError` code `MISSING_FIELD` in TypeScript and `MissingField(AdapterError)` in Python.

### 3.2 Contract packages

#### `adapter`

| Symbol | Kind | Members |
|---|---|---|
| `ErrInvalidMessage` | var |  |
| `ErrInvalidProof` | var |  |
| `ErrContextMismatch` | var |  |
| `ErrDependencyUnavailable` | var |  |
| `ErrUnsupportedRequirement` | var |  |
| `ErrUnsupportedPurpose` | var |  |
| `ErrMissingField` | var |  |
| `Adapter` | type | methods: `Describe` |
| `AgentBinding` | type | fields: `AgentID`, `OperatorID`, `HolderJKT`, `Status`, `ObservedAt`, `StatusCheckedAt`, `SourceID`, `SourceRef`, `EnrolledElsewhere` |
| `AgentID` | type |  |
| `BindingResolver` | type | methods: `ResolveAgentBinding` |
| `BindingStatus` | type | constants: `BindingActive`, `BindingRevoked`, `BindingCompromised`, `BindingUnknown`; methods: `Valid` |
| `CheckInput` | type | fields: `Principal`, `Binding`, `Intent`, `Operation`, `EvidenceRefs` |
| `CheckOutcome` | type | fields: `Result`, `ReasonCode`, `SourceID`, `SourceRef`, `ObservedAt` |
| `ClaimContext` | type | fields: `Principal`, `Intent`, `Operation` |
| `ClaimReader` | type | methods: `ReadNativeClaim` |
| `Code` | type | constants: `CodeInvalidMessage`, `CodeInvalidProof`, `CodeContextMismatch`, `CodeDependencyUnavailable`, `CodeUnsupportedRequirement`, `CodeUnsupportedPurpose`, `CodeMissingField`; functions: `CodeOf` |
| `ContextChecker` | type | methods: `CheckContext` |
| `Decision` | type | fields: `Effect`, `Obligations`, `Reason`, `SourceID`, `SourceRef`, `DecidedAt`, `PolicyRevision`; methods: `Permits` |
| `DenialReason` | type | constants: `DenialNoCredential`, `DenialCredentialRejected`; methods: `Valid` |
| `Descriptor` | type | functions: `DescriptorsOf`; fields: `Protocol`, `Version`, `MappingRevision`; methods: `NativeAdapter` |
| `Effect` | type | constants: `EffectAllow`, `EffectDeny`, `EffectUnknown`; methods: `Valid` |
| `Mechanism` | type |  |
| `MultiDescriber` | type | methods: `Descriptors` |
| `NativeAuthenticator` | type | methods: `AuthenticateNative` |
| `NativeAuthorizer` | type | methods: `AuthorizeNative` |
| `NativeClaim` | type | fields: `Value`, `ObservedAt`, `StatusCheckedAt`, `SourceID`, `SourceRef` |
| `NativeDenial` | type | fields: `Reason`; methods: `Code`, `Error`, `Is`, `PublicReason` |
| `NoVisibility` | type | fields: `Reason`; methods: `Validate` |
| `Obligation` | type | fields: `ID`, `Attributes` |
| `Observation` | type | fields: `EventID`, `EventKind`, `Context`, `TaskID`, `OperationID`, `AdmissionReceiptID`, `ObservedAt`, `Result`, `Dimension`, `Severity`, `EvidenceRefs`, `Attribution`, `Supersedes`, `Details` |
| `OperationMapper` | type | methods: `MapOperation` |
| `OutcomeRecorder` | type | methods: `RecordOutcome` |
| `Principal` | type | fields: `ID`, `Realm`, `Workload`, `Mechanism`, `AuthenticatedAt`, `Attributes` |
| `Realm` | type | fields: `TenantID`, `EnvironmentID` |
| `Recorded` | type | methods: `Validate` |
| `Signed` | type | fields: `JWS`; methods: `Validate` |
| `Verdict` | type | constants: `VerdictPass`, `VerdictFail`, `VerdictUnknown`; methods: `CheckStatus`, `Valid` |
| `Workload` | type |  |

#### `adapter/enroll`

| Symbol | Kind | Members |
|---|---|---|
| `ErrNotAuthorized` | var |  |
| `ErrNotFound` | var |  |
| `ErrAlreadyEnrolled` | var |  |
| `ErrCompromised` | var |  |
| `ErrRevoked` | var |  |
| `ErrKeyReuse` | var |  |
| `ErrInvalid` | var |  |
| `ErrWorkloadInUse` | var |  |
| `Actor` | type | fields: `Kind`, `ID`, `Realm`; methods: `CheckAuthority` |
| `ActorKind` | type | constants: `Admin`, `AuthorizedIssuer`, `Agent`; methods: `Valid` |
| `AuditAction` | type | constants: `ActionEnroll`, `ActionRotate`, `ActionRevoke`, `ActionMarkCompromised` |
| `AuditEntry` | type | fields: `Seq`, `At`, `Action`, `Actor`, `AgentID`, `Workload`, `OldJKT`, `NewJKT`, `Result`, `Reason` |
| `AuditResult` | type | constants: `ResultApplied`, `ResultUnchanged`, `ResultDenied`, `ResultRejected` |
| `Registry` | type | methods: `Lookup`, `Rotate`, `MarkCompromised` |
| `Resolver` | type | fields: `Registry`; methods: `ResolveAgentBinding` |

#### `adapter/enroll/memory`

| Symbol | Kind | Members |
|---|---|---|
| `DefaultSourceID` | const |  |
| `Enrollment` | type | fields: `AgentID`, `OperatorID`, `Workload`, `HolderJKT` |
| `Option` | type | functions: `WithClock`, `WithSharedWorkloads`, `WithSourceID` |
| `Registry` | type | functions: `New`; methods: `Audit`, `Enroll`, `Lookup`, `MarkCompromised`, `Revoke`, `Rotate` |

#### `adapter/freshness`

| Symbol | Kind | Members |
|---|---|---|
| `Evaluate` | func |  |
| `Evaluator` | type | fields: `Skew`, `Start`, `Guard`; methods: `Evaluate` |
| `Monotonic` | type | functions: `NewMonotonic`; methods: `Check`, `Forget`, `Len` |
| `ReasonCode` | type | constants: `Satisfied`, `StaleEvidence`, `ClockAhead`, `Restamped`, `UnsupportedRequirement`, `DependencyUnavailable`; methods: `TreatedAs` |
| `Result` | type |  |

### 3.3 `adaptertest` case model

The types the plan names (`Request`, `TLSPeer`, `Subject`, `Env`, `Options`, `Case`, the `Expect*` types), the types their fields reach (`Call`, `RealmJSON`, `PrincipalJSON`, `BindingJSON`, `ObservationJSON`, `ObligationJSON`, `LeakScan`, `Hooks`, `Replacement`), `Factory`, which turns an `Env` into a `Subject`, and `Load`, which reads the cases. A field with a `json` tag reads the case-file member of that name.

| Symbol | Kind | Members |
|---|---|---|
| `BindingJSON` | type | fields: `AgentID`, `OperatorID`, `HolderJKT`, `Status` |
| `Call` | type | fields: `Realm`, `Workload`, `AgentID`, `MappingVersion`, `Principal`, `Binding`, `NativePath`, `CheckID`, `Intent`, `Operation`, `EvidenceRefs`, `Observation` |
| `Case` | type | functions: `Load`; fields: `CaseVersion`, `ID`, `Title`, `Draft`, `Workloads`, `Now`, `NativeState`, `Request`, `Call`, `Expect` |
| `Env` | type | fields: `State`, `Clock`, `Hooks` |
| `Expect` | type | fields: `Function`, `Outcome`, `ReasonCode`, `MustNotCall`, `LeakScan`, `Principal`, `Binding`, `Operation`, `Claim`, `Decision` |
| `ExpectBinding` | type | fields: `AgentID`, `OperatorID`, `HolderJKT`, `Status`, `EnrolledElsewhere` |
| `ExpectClaim` | type | fields: `Value`, `ObservedAt`, `StatusCheckedAt`, `SourceID`, `SourceRef` |
| `ExpectDecision` | type | fields: `Obligations`, `SourceID`, `SourceRef`, `DecidedAt`, `PolicyRevision` |
| `ExpectOperation` | type | fields: `EnvironmentID`, `PrincipalID`, `Action`, `Resources`, `Method`, `TargetURI`, `BodyDigest`, `Headers` |
| `ExpectPrincipal` | type | fields: `ID`, `Realm`, `Workload`, `Mechanism`, `Attributes` |
| `Factory` | type |  |
| `Hooks` | type | methods: `Fire`, `Fired` |
| `LeakScan` | type | fields: `Secrets` |
| `ObligationJSON` | type | fields: `ID`, `Attributes` |
| `ObservationJSON` | type | fields: `EventID`, `EventKind`, `Context`, `TaskID`, `OperationID`, `AdmissionReceiptID`, `ObservedAt`, `Result`, `Dimension`, `Severity`, `EvidenceRefs`, `Attribution`, `Supersedes`, `Details` |
| `Options` | type | fields: `Fixtures`, `Adapter`, `SharedWorkloads`, `Replaced` |
| `PrincipalJSON` | type | fields: `ID`, `Realm`, `Workload`, `Mechanism`, `AuthenticatedAt`, `Attributes` |
| `RealmJSON` | type | fields: `TenantID`, `EnvironmentID` |
| `Replacement` | type | fields: `By`, `Reason` |
| `Request` | type | fields: `Method`, `URL`, `Headers`, `BodyB64`, `TLSPeer`, `NativeStateRef`, `Arrival` |
| `Subject` | type | fields: `Adapter`, `Arrive`, `Credential`, `VerifyOutcome` |
| `TLSPeer` | type | fields: `SubjectCN`, `IssuerCN`, `DNSNames`, `URIs` |

## 4. Out of this freeze

- `adaptertest` suite entry points: `DefaultFixtures`, `Run`, `Evaluate`, `Result` (`ID`, `Failures`, `Passed`). Their port shapes differ from Go by design (`runConformance` and `evaluateConformance` in TypeScript; `run_case`, `conformance_cases` and `evaluate_conformance` in Python), so the ledger, not this note, tracks them.
- Membership sources: `go/adapter/source`, `go/adapter/source/googledir`, `go/adapter/source/scim`, `go/adapter/source/ssf`, `go/adapter/sourcetest`.
- `go/adapter/installed` and `go/adapter/task`.
- `go/adapters/memory` and the native adapters; `go/adapters/internal/broken`.

Every package of this list that is in the ledger's scope keeps its ledger rows and the ledger's own change rule.
