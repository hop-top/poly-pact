/**
 * The catalogue of the broken adapter (Go hop.top/pact-go/adapters/internal/broken,
 * catalogue.go): every defect with the cases that exist to catch it.
 *
 * @module
 */
import { Defect } from './defects.ts';

/** Describes a defect and names the cases that exist to catch it. */
export interface Spec {
  readonly defect: Defect;
  /** Says in one line what the defect gets wrong. */
  readonly what: string;
  /** The ids of the cases that must fail when only this defect is on. */
  readonly targets: readonly string[];
}

/**
 * Every defect with the cases that exist to catch it. A case appears under
 * each defect that breaks the behavior it asserts; every common case appears
 * under at least one.
 */
export const CATALOGUE: readonly Spec[] = Object.freeze([
  {
    defect: Defect.TRUST_HEADER_IDENTITY,
    what: 'names an identity from client-supplied headers when no credential is presented',
    targets: ['COMMON-01.headers-only'],
  },
  {
    defect: Defect.HEADER_OVERRIDES_CREDENTIAL,
    what: 'lets a client-supplied identity header override the authenticated credential',
    targets: ['COMMON-01.credential-wins'],
  },
  {
    defect: Defect.ACCEPT_BYPASS,
    what: 'authenticates a request that bypassed the enforcement point',
    targets: ['COMMON-02.direct'],
  },
  {
    defect: Defect.REJECT_ENFORCEMENT_POINT,
    what: 'refuses a request that came through the enforcement point',
    targets: ['COMMON-02.via-enforcement-point'],
  },
  {
    defect: Defect.CONFLATE_ISSUERS,
    what: 'resolves identities by local name and conflates same-named identities of different issuers',
    targets: ['COMMON-09.authenticate-realm'],
  },
  {
    defect: Defect.LEAK_TOKEN_IN_DENIAL,
    what: 'echoes the presented token and cookie in the denial',
    targets: ['COMMON-10.authenticate-error'],
  },

  {
    defect: Defect.FORWARDED_HOST_ORIGIN,
    what: 'takes the host of the target URI from X-Forwarded-Host or Host',
    targets: ['COMMON-03.target-uri', 'COMMON-03.baseline'],
  },
  {
    defect: Defect.NORMALIZE_QUERY,
    what: 'sorts and re-encodes the query of the target URI',
    targets: ['COMMON-03.target-uri'],
  },
  {
    defect: Defect.BODY_NOT_COVERED,
    what: 'digests the empty string whatever the body is',
    targets: ['COMMON-03.body-digest', 'COMMON-03.baseline'],
  },
  {
    defect: Defect.BODY_NOT_RESTORED,
    what: 'consumes the request body and does not restore it',
    targets: ['COMMON-03.body-digest'],
  },
  {
    defect: Defect.BLANK_EMPTY_DIGEST,
    what: 'gives an empty body no digest',
    targets: ['COMMON-03.empty-body'],
  },
  {
    defect: Defect.ECHO_ALL_HEADERS,
    what: 'covers every request header, credentials included',
    targets: ['COMMON-03.headers', 'COMMON-03.baseline', 'COMMON-10.map-operation'],
  },
  {
    defect: Defect.TRUST_CLIENT_RESOURCES,
    what: 'takes the resources from a client-supplied header',
    targets: ['COMMON-03.resources'],
  },
  {
    defect: Defect.ACCEPT_FRAGMENT,
    what: 'maps a request target that has a fragment',
    targets: ['COMMON-03.fragment', 'COMMON-10.map-error'],
  },
  {
    defect: Defect.ACCEPT_USERINFO,
    what: 'maps a request target that has userinfo',
    targets: ['COMMON-03.userinfo'],
  },
  {
    defect: Defect.ACCEPT_CONTENT_ENCODING,
    what: 'maps a request with a content encoding',
    targets: ['COMMON-03.content-encoding'],
  },
  {
    defect: Defect.NORMALIZE_AMBIGUOUS_ENCODING,
    what: 'normalizes an ambiguous encoding of the request target instead of rejecting it',
    targets: [
      'COMMON-03.ambiguous-query',
      'COMMON-03.encoded-slash',
      'COMMON-03.invalid-utf8',
      'COMMON-03.dot-segment',
    ],
  },
  {
    defect: Defect.WRONG_MALFORMED_CODE,
    what: 'rejects a malformed request with the code of another error',
    targets: [
      'COMMON-03.fragment',
      'COMMON-03.userinfo',
      'COMMON-03.content-encoding',
      'COMMON-03.ambiguous-query',
      'COMMON-03.encoded-slash',
      'COMMON-03.invalid-utf8',
      'COMMON-03.dot-segment',
    ],
  },
  {
    defect: Defect.PRINCIPAL_FROM_HEADER,
    what: 'takes principal_id from a client-supplied header',
    targets: ['COMMON-03.baseline'],
  },
  {
    defect: Defect.IGNORE_REALM_MAPPING,
    what: 'maps the operation of a principal from another realm',
    targets: ['COMMON-09.map-realm'],
  },
  {
    defect: Defect.LEAK_CREDENTIAL_IN_MAP_ERROR,
    what: 'echoes the request credentials in the mapping error',
    targets: ['COMMON-10.map-error'],
  },

  {
    defect: Defect.RESTAMP_OBSERVED_AT,
    what: "replaces the source's observation time with the time of the read",
    targets: ['COMMON-04.original-time', 'COMMON-04.no-source-time'],
  },
  {
    defect: Defect.STAMP_MISSING_TIMES,
    what: 'supplies the time of the read where the source gives no time',
    targets: ['COMMON-04.no-source-time'],
  },
  {
    defect: Defect.PASS_FUTURE_OBSERVED_AT,
    what: 'passes on an observation time in the future',
    targets: ['COMMON-04.future-observed-at'],
  },
  {
    defect: Defect.PASS_FUTURE_STATUS_CHECKED,
    what: 'passes on a status check time later than now plus the skew',
    targets: ['COMMON-04.future-status-checked'],
  },
  {
    defect: Defect.NO_STATUS_SKEW_ALLOWANCE,
    what: 'refuses a status check time ahead of now by no more than the skew',
    targets: ['COMMON-04.status-checked-at-skew'],
  },
  {
    defect: Defect.CLAMP_FUTURE_CLAIM_TIMES,
    what: 'clamps a claim time later than now plus the skew to the bound and passes the claim on',
    targets: ['COMMON-04.future-observed-at', 'COMMON-04.future-status-checked'],
  },
  {
    defect: Defect.CONFLATE_CLAIM_REALMS,
    what: 'reads the claim of a same-spelled principal of another realm',
    targets: ['COMMON-09.claim-realm'],
  },
  {
    defect: Defect.IGNORE_CLAIM_RESOURCE,
    what: 'reads the fact of a resource that the operation does not list',
    targets: ['COMMON-11.resource-scoped'],
  },
  {
    defect: Defect.IGNORE_CLAIM_TASK,
    what: 'reads the fact of a task that the intent does not carry',
    targets: ['COMMON-11.task-scoped'],
  },

  {
    defect: Defect.FAIL_OPEN_UNKNOWN_CHECK,
    what: 'reports PASS for a check that is not installed',
    targets: ['COMMON-05.unknown-id'],
  },
  {
    defect: Defect.PREFIX_MATCH_CHECK,
    what: 'matches a check id by prefix',
    targets: ['COMMON-05.empty-id'],
  },
  {
    defect: Defect.FOLD_CASE_CHECK,
    what: 'matches a check id ignoring case',
    targets: ['COMMON-05.near-miss-id'],
  },
  {
    defect: Defect.NEVER_EVALUATE_CHECKS,
    what: 'reports FAIL for every installed check without consulting it',
    targets: ['COMMON-05.installed-control', 'COMMON-12.agent-bound'],
  },
  {
    defect: Defect.ECHO_REFS_IN_SOURCE,
    what: 'copies the evidence references into the source of the check outcome',
    targets: ['COMMON-10.check-outcome'],
  },
  {
    defect: Defect.IGNORE_CHECK_SCOPE,
    what: 'matches an installed check by its id alone, for any agent and any principal',
    targets: ['COMMON-12.no-binding', 'COMMON-12.other-agent', 'COMMON-12.other-principal'],
  },
  {
    defect: Defect.TRUST_EMPTY_BINDING,
    what: 'lets a call with no agent binding match a check whose state is for an agent',
    targets: ['COMMON-12.no-binding'],
  },

  {
    defect: Defect.EXECUTE_ON_DENY,
    what: 'runs the execution hook although the decision is a denial',
    targets: ['COMMON-06.deny-unchanged'],
  },
  {
    defect: Defect.REWRITE_READ_DENY,
    what: 'turns the denial of a read into an allow',
    targets: ['COMMON-06.deny-unchanged'],
  },
  {
    defect: Defect.CONNECTOR_SUBSTITUTION,
    what: 'evaluates the policy as a broader identity the policy allows',
    targets: ['COMMON-06.no-connector-substitution'],
  },
  {
    defect: Defect.DEFAULT_ALLOW,
    what: 'allows a principal that no rule mentions',
    targets: ['COMMON-06.no-policy-not-allowed'],
  },
  {
    defect: Defect.EXECUTE_ON_ALLOW,
    what: 'runs the execution hook while authorizing',
    targets: ['COMMON-06.allow-no-execution'],
  },
  {
    defect: Defect.DROP_OBLIGATIONS,
    what: 'strips the obligations from the decision',
    targets: ['COMMON-06.allow-no-execution', 'COMMON-06.deny-unchanged'],
  },
  {
    defect: Defect.CONFLATE_POLICY_REALMS,
    what: 'applies the rule of a same-spelled principal of another realm',
    targets: ['COMMON-09.authorize-realm'],
  },
  {
    defect: Defect.DECISION_WITHOUT_SOURCE,
    what: 'returns a decision that names no policy source',
    targets: ['COMMON-06.decision-provenance', 'COMMON-06.no-policy-not-allowed'],
  },
  {
    defect: Defect.FUTURE_DECIDED_AT,
    what: 'stamps a decision with a time after now plus the skew',
    targets: ['COMMON-06.decision-provenance', 'COMMON-06.deny-unchanged'],
  },

  {
    defect: Defect.ASSUME_EXECUTION_SUCCESS,
    what: 'signs EXECUTION SUCCESS without execution visibility',
    targets: ['COMMON-07.no-visibility'],
  },
  {
    defect: Defect.NO_VISIBILITY_FOR_ADMISSION,
    what: 'declares no visibility for its own admission decision',
    targets: ['COMMON-07.admission-without-execution-visibility'],
  },
  {
    defect: Defect.NO_VISIBILITY_DESPITE_VISIBILITY,
    what: 'declares no visibility for an execution it observes',
    targets: ['COMMON-07.visible-execution-success', 'COMMON-10.record-outcome'],
  },
  {
    defect: Defect.LEAK_DETAILS_IN_REPORT,
    what: "signs the observation's free text and references unchanged",
    targets: ['COMMON-10.record-outcome'],
  },

  {
    defect: Defect.REVIVE_REVOKED_BINDING,
    what: 'reports a revoked binding as active',
    targets: ['COMMON-08.revoked'],
  },
  {
    defect: Defect.REVIVE_COMPROMISED_BINDING,
    what: 'reports a compromised binding as active',
    targets: ['COMMON-08.compromised'],
  },
  {
    defect: Defect.LOSE_ACTIVE_BINDING,
    what: 'reports an active binding as unknown',
    targets: ['COMMON-08.active-control'],
  },
  {
    defect: Defect.TRUST_UNENROLLED,
    what: 'gives a workload that is not enrolled an active binding',
    targets: ['COMMON-08.unenrolled'],
  },
  {
    defect: Defect.UNUSABLE_AS_ERROR,
    what: 'reports a revoked or compromised binding as an error instead of its status, agent, operator and holder key',
    targets: [
      'COMMON-08.revoked',
      'COMMON-08.compromised',
      'IDENT-08.old-key-proof',
      'IDENT-09.revoked-pair',
      'IDENT-09.compromised-in-force',
      'FRESH-01.revoked-after-issuance',
    ],
  },
  {
    defect: Defect.STATUS_WITHOUT_RECORD,
    what: 'reports a revoked or compromised status without the agent, operator and holder key of the record',
    targets: [
      'COMMON-08.revoked',
      'COMMON-08.compromised',
      'IDENT-08.old-key-proof',
      'IDENT-09.revoked-pair',
      'IDENT-09.compromised-in-force',
      'FRESH-01.revoked-after-issuance',
    ],
  },
  {
    defect: Defect.CONFLATE_BINDING_REALMS,
    what: 'resolves a workload in whichever realm enrolls it',
    targets: ['COMMON-09.binding-realm'],
  },

  {
    defect: Defect.REALM_WORKLOAD,
    what: 'gives every principal of a realm the workload that the realm enrolls',
    targets: ['IDENT-01.authenticate'],
  },
  {
    defect: Defect.CONFLATE_TENANTS,
    what: 'resolves identities by the last component of the id, dropping issuer and tenant',
    targets: ['IDENT-02.authenticate'],
  },
  {
    defect: Defect.USER_WORKLOAD,
    what: 'gives a principal the workload of its first identity, not of the client it came through',
    targets: ['IDENT-03.authenticate'],
  },
  {
    defect: Defect.IDENTITY_BY_DISPLAY_NAME,
    what: 'resolves identities by display name',
    targets: ['IDENT-05.authenticate'],
  },
  {
    defect: Defect.BINDING_BY_REALM,
    what: 'resolves a workload with no enrollment to an enrollment of its realm',
    targets: [
      'IDENT-01.binding',
      'IDENT-02.binding',
      'IDENT-03.binding',
      'IDENT-04.other-ca',
      'IDENT-04.other-workload',
      'IDENT-06.session-policy',
    ],
  },
  {
    defect: Defect.MATCH_LOCAL_PART,
    what: 'matches a workload by its last component',
    targets: ['IDENT-02.binding', 'IDENT-04.other-ca'],
  },
  {
    defect: Defect.DROP_LAST_COMPONENT,
    what: 'matches a workload without its last component',
    targets: [
      'IDENT-01.binding',
      'IDENT-03.binding',
      'IDENT-04.other-workload',
      'IDENT-06.session-policy',
    ],
  },
  {
    defect: Defect.HOLDER_KEY_FROM_CREDENTIAL,
    what: 'takes the holder key from the credential instead of the enrollment',
    targets: ['IDENT-07.credential-key'],
  },
  {
    defect: Defect.RECOVER_BY_OLD_KEY,
    what: 'reports a compromised binding active when the credential proves the old key',
    targets: ['IDENT-08.old-key-proof'],
  },
  {
    defect: Defect.FIRST_OF_SHARED,
    what: 'resolves a shared workload to the first agent enrolled on it, whatever agent the request names',
    targets: [
      'IDENT-09.shared-workload',
      'IDENT-09.other-agent',
      'IDENT-09.one-in-force',
      'IDENT-09.compromised-in-force',
      'IDENT-09.unenrolled-agent',
      'IDENT-09.other-workload-agent',
    ],
  },
  {
    defect: Defect.REVOKED_IN_FORCE,
    what: 'resolves a shared workload by the workload alone and counts a revoked record as in force',
    targets: ['IDENT-09.one-in-force'],
  },
  {
    defect: Defect.COMPROMISED_NOT_IN_FORCE,
    what: 'resolves a shared workload by the workload alone and leaves the compromised record out',
    targets: ['IDENT-09.compromised-in-force'],
  },
  {
    defect: Defect.IGNORE_AGENT_ID,
    what: 'ignores the agent ID and resolves the workload alone, so any agent of the workload may answer',
    targets: [
      'IDENT-09.shared-workload',
      'IDENT-09.other-agent',
      'IDENT-09.compromised-in-force',
      'IDENT-09.revoked-pair',
      'IDENT-09.unenrolled-agent',
    ],
  },
  {
    defect: Defect.CROSS_WORKLOAD_AGENT,
    what: "selects the agent's record on another workload of the realm",
    targets: ['IDENT-09.other-workload-agent', 'IDENT-04.other-workload'],
  },
  {
    defect: Defect.NEVER_SET_ELSEWHERE,
    what: 'never reports an agent ID enrolled for another workload of the realm',
    targets: ['IDENT-09.other-workload-agent'],
  },
  {
    defect: Defect.ELSEWHERE_ACROSS_REALMS,
    what: 'reports an agent ID enrolled in another realm as enrolled for another workload of the realm',
    targets: ['IDENT-09.other-realm-agent'],
  },
  {
    defect: Defect.SELECT_DESPITE_DEDICATED,
    what: 'selects by the agent ID on a dedicated workload with more than one enrollment in force',
    targets: [
      'IDENT-10.two-in-force',
      'IDENT-10.compromised-and-active',
      'IDENT-10.unenrolled-agent',
    ],
  },
  {
    defect: Defect.REVOKED_COUNTS_AS_IN_FORCE,
    what: 'counts a revoked record toward the enrollments in force of a dedicated workload',
    targets: ['IDENT-10.revoked-and-active'],
  },
  {
    defect: Defect.CACHE_BINDING_FOR_CONTRACT,
    what: "keeps the binding status read at contract issuance for the contract's lifetime",
    targets: ['FRESH-01.revoked-after-issuance'],
  },
  {
    defect: Defect.IGNORE_CHECK_LIMITS,
    what: "reports a check's native verdict without applying its age limits",
    targets: ['FRESH-02.stale-snapshot', 'FRESH-03.observed-ahead', 'FRESH-06.restamped'],
  },
  {
    defect: Defect.STALE_AT_LIMIT,
    what: 'treats an age equal to its limit as stale',
    targets: ['FRESH-02.at-limit'],
  },
  {
    defect: Defect.DEFER_CLOCK_AHEAD,
    what: 'reports a source clock that runs ahead as a source that cannot answer',
    targets: ['FRESH-03.observed-ahead'],
  },
  {
    defect: Defect.NO_SKEW_ALLOWANCE,
    what: 'allows a source clock no skew',
    targets: ['FRESH-03.at-skew'],
  },
  {
    defect: Defect.IGNORE_PINNED_REVISION,
    what: "reports a pinned check's native verdict whatever revision its source reports",
    targets: ['FRESH-04.pinned-revision-changed'],
  },
  {
    defect: Defect.READ_THROUGH_OUTAGE,
    what: 'reads the records of a source that cannot answer as if it could',
    targets: [
      'FRESH-05.binding-source-down',
      'FRESH-05.claim-source-down',
      'FRESH-05.check-source-down',
    ],
  },
  {
    defect: Defect.FORGET_SIGHTINGS,
    what: 'evaluates a check without the observation times its guard already holds',
    targets: ['FRESH-06.restamped'],
  },
]);
