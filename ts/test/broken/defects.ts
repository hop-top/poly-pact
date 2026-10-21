/**
 * The defects of the broken adapter (Go hop.top/pact-go/adapters/internal/broken,
 * the constants of broken.go and freshness.go): each one way of getting the
 * contract of draft 17.1 wrong, and each the violation that one or more
 * common conformance cases exist to catch.
 *
 * @module
 */

/** Names one way of getting the contract wrong. Each comment says what the adapter does wrong. */
export const Defect = Object.freeze({
  /**
   * Authenticates the identity that X-User, X-Principal, X-Forwarded-User, X-Client-Cert or
   * X-Acme-Identity names, when the request presents no credential.
   */
  TRUST_HEADER_IDENTITY: 'trust-header-identity',
  /** Lets an identity header win over the credential. */
  HEADER_OVERRIDES_CREDENTIAL: 'header-overrides-credential',
  /** Authenticates requests that did not arrive through the enforcement point. */
  ACCEPT_BYPASS: 'accept-bypass',
  /** Refuses requests that did arrive through it. */
  REJECT_ENFORCEMENT_POINT: 'reject-enforcement-point',
  /**
   * Resolves an authenticated identity by its local name, so same-named identities of different
   * issuers become one.
   */
  CONFLATE_ISSUERS: 'conflate-issuers',
  /** Puts the presented token and cookie in the denial. */
  LEAK_TOKEN_IN_DENIAL: 'leak-token-in-denial',

  /**
   * Takes the host of the target URI from X-Forwarded-Host or the Host header instead of the
   * configured origin.
   */
  FORWARDED_HOST_ORIGIN: 'forwarded-host-origin',
  /** Sorts and re-encodes the query of the target URI. */
  NORMALIZE_QUERY: 'normalize-query',
  /** Digests the empty string whatever the body is. */
  BODY_NOT_COVERED: 'body-not-covered',
  /** Consumes the request body and leaves it empty. */
  BODY_NOT_RESTORED: 'body-not-restored',
  /** Gives a request without a body an empty body digest. */
  BLANK_EMPTY_DIGEST: 'blank-empty-digest',
  /** Covers every request header, credentials included. */
  ECHO_ALL_HEADERS: 'echo-all-headers',
  /** Takes the resources from a client-supplied header. */
  TRUST_CLIENT_RESOURCES: 'trust-client-resources',
  /** Maps a request target that has a fragment. */
  ACCEPT_FRAGMENT: 'accept-fragment',
  /** Maps a request target that has userinfo. */
  ACCEPT_USERINFO: 'accept-userinfo',
  /** Maps a request with a content encoding. */
  ACCEPT_CONTENT_ENCODING: 'accept-content-encoding',
  /**
   * Normalizes the request-target before it maps it: escapes of unreserved characters and of "/" in
   * the path, and overlong two-octet forms, are decoded, lowercase hex digits are uppercased, and
   * dot segments are removed from the path.
   */
  NORMALIZE_AMBIGUOUS_ENCODING: 'normalize-ambiguous-encoding',
  /**
   * Rejects a malformed request, as it should, but with the code of another error
   * (UNSUPPORTED_REQUIREMENT) instead of INVALID_MESSAGE.
   */
  WRONG_MALFORMED_CODE: 'wrong-malformed-code',
  /** Takes principal_id from the X-Principal header. */
  PRINCIPAL_FROM_HEADER: 'principal-from-header',
  /** Maps the operation of a principal of another realm. */
  IGNORE_REALM_MAPPING: 'ignore-realm-mapping',
  /** Puts the request credentials in the mapping error. */
  LEAK_CREDENTIAL_IN_MAP_ERROR: 'leak-credential-in-map-error',

  /** Replaces the source's observation time with the time of the read. */
  RESTAMP_OBSERVED_AT: 'restamp-observed-at',
  /** Supplies the time of the read where the source gives no time. */
  STAMP_MISSING_TIMES: 'stamp-missing-times',
  /** Passes on an observation time in the future. */
  PASS_FUTURE_OBSERVED_AT: 'pass-future-observed-at',
  /** Passes on a status check time later than now plus the skew. */
  PASS_FUTURE_STATUS_CHECKED: 'pass-future-status-checked',
  /**
   * Refuses a claim whose status check time is ahead of now by no more than the skew, which draft
   * A.2 allows.
   */
  NO_STATUS_SKEW_ALLOWANCE: 'no-status-skew-allowance',
  /**
   * Passes on a claim whose observation or status check time is later than now plus the skew, with
   * that time clamped to now plus the skew, instead of refusing it with DEPENDENCY_UNAVAILABLE.
   */
  CLAMP_FUTURE_CLAIM_TIMES: 'clamp-future-claim-times',
  /** Reads the claim of a same-spelled principal of another realm. */
  CONFLATE_CLAIM_REALMS: 'conflate-claim-realms',
  /** Reads the fact of a resource whatever the resources of the operation are. */
  IGNORE_CLAIM_RESOURCE: 'ignore-claim-resource',
  /** Reads the fact of a task whatever the task of the intent is. */
  IGNORE_CLAIM_TASK: 'ignore-claim-task',

  /** Passes a check that is not installed. */
  FAIL_OPEN_UNKNOWN_CHECK: 'fail-open-unknown-check',
  /** Matches a check id by prefix, so the empty id matches. */
  PREFIX_MATCH_CHECK: 'prefix-match-check',
  /** Matches a check id ignoring case. */
  FOLD_CASE_CHECK: 'fold-case-check',
  /** Reports FAIL for every installed check without consulting its native state. */
  NEVER_EVALUATE_CHECKS: 'never-evaluate-checks',
  /** Copies the evidence references into the check source. */
  ECHO_REFS_IN_SOURCE: 'echo-refs-in-source',
  /**
   * Matches an installed check by its id alone, whatever agent or principal its native state is
   * for.
   */
  IGNORE_CHECK_SCOPE: 'ignore-check-scope',
  /** Lets a call that established no agent match a check whose native state is for an agent. */
  TRUST_EMPTY_BINDING: 'trust-empty-binding',

  /** Runs the execution hook although the decision is a denial. */
  EXECUTE_ON_DENY: 'execute-on-deny',
  /** Turns the denial of a read into an allow. */
  REWRITE_READ_DENY: 'rewrite-read-deny',
  /** Evaluates the policy as a broader identity that the policy allows. */
  CONNECTOR_SUBSTITUTION: 'connector-substitution',
  /** Allows a principal that no rule mentions. */
  DEFAULT_ALLOW: 'default-allow',
  /** Runs the execution hook while authorizing. */
  EXECUTE_ON_ALLOW: 'execute-on-allow',
  /** Strips the obligations from the decision. */
  DROP_OBLIGATIONS: 'drop-obligations',
  /** Applies the rule of a same-spelled principal of another realm. */
  CONFLATE_POLICY_REALMS: 'conflate-policy-realms',
  /** Returns decisions that name no policy source. */
  DECISION_WITHOUT_SOURCE: 'decision-without-source',
  /** Stamps each decision with a time an hour after now. */
  FUTURE_DECIDED_AT: 'future-decided-at',

  /** Signs EXECUTION SUCCESS although the adapter has no execution visibility. */
  ASSUME_EXECUTION_SUCCESS: 'assume-execution-success',
  /** Declares no visibility for an admission event. */
  NO_VISIBILITY_FOR_ADMISSION: 'no-visibility-for-admission',
  /** Declares no visibility for an execution the adapter does see. */
  NO_VISIBILITY_DESPITE_VISIBILITY: 'no-visibility-despite-visibility',
  /** Signs the observation's free text and references unchanged. */
  LEAK_DETAILS_IN_REPORT: 'leak-details-in-report',

  /** Reports a revoked binding as active. */
  REVIVE_REVOKED_BINDING: 'revive-revoked-binding',
  /** Reports a compromised binding as active. */
  REVIVE_COMPROMISED_BINDING: 'revive-compromised-binding',
  /** Reports an active binding as unknown. */
  LOSE_ACTIVE_BINDING: 'lose-active-binding',
  /** Gives a workload that is not enrolled an active binding. */
  TRUST_UNENROLLED: 'trust-unenrolled',
  /**
   * Reports a revoked or compromised binding as an error with no binding, instead of its status
   * with the agent, operator and holder key of the record (identity mapping IM-11).
   */
  UNUSABLE_AS_ERROR: 'unusable-as-error',
  /**
   * Reports the REVOKED or COMPROMISED status of a binding without the agent, operator and holder
   * key of the record.
   */
  STATUS_WITHOUT_RECORD: 'status-without-record',
  /** Resolves a workload in whichever realm enrolls it. */
  CONFLATE_BINDING_REALMS: 'conflate-binding-realms',

  /**
   * Gives every principal of a realm the workload that the realm enrolls, so another user becomes
   * the enrolled account.
   */
  REALM_WORKLOAD: 'realm-workload',
  /**
   * Resolves an authenticated identity by the last component of its id, dropping the issuer and
   * tenant that come before it.
   */
  CONFLATE_TENANTS: 'conflate-tenants',
  /**
   * Gives a principal the workload of its first identity, so a user acting through another client
   * gets the enrolled client.
   */
  USER_WORKLOAD: 'user-workload',
  /** Resolves an authenticated identity by its display name. */
  IDENTITY_BY_DISPLAY_NAME: 'identity-by-display-name',
  /** Resolves a workload with no enrollment to the first enrollment of its realm. */
  BINDING_BY_REALM: 'binding-by-realm',
  /**
   * Matches a workload with no enrollment to one with the same last component: the same subject of
   * another tenant or authority.
   */
  MATCH_LOCAL_PART: 'match-local-part',
  /**
   * Matches a workload with no enrollment to one that is equal without its last component: a role
   * whatever its session policy, another client of the issuer, another certificate of the
   * authority.
   */
  DROP_LAST_COMPONENT: 'drop-last-component',
  /**
   * Reports the key that the credential of the workload is bound to as the holder key, instead of
   * the enrolled key.
   */
  HOLDER_KEY_FROM_CREDENTIAL: 'holder-key-from-credential',
  /**
   * Reports a compromised binding as active when the credential of the workload is bound to the
   * enrolled key.
   */
  RECOVER_BY_OLD_KEY: 'recover-by-old-key',
  /**
   * Resolves a workload that several agents share to the first agent enrolled on it, whatever agent
   * the request names.
   */
  FIRST_OF_SHARED: 'first-of-shared',
  /**
   * Resolves a workload that several agents share by the workload alone and counts its revoked
   * records as in force.
   */
  REVOKED_IN_FORCE: 'revoked-in-force',
  /**
   * Resolves a workload that several agents share by the workload alone and leaves its compromised
   * record out, so that the other agent resolves.
   */
  COMPROMISED_NOT_IN_FORCE: 'compromised-not-in-force',
  /**
   * Drops the agent ID the request names and resolves the workload alone: the one agent in force on
   * it answers, whichever agent the request names, and several in force answer UNKNOWN.
   */
  IGNORE_AGENT_ID: 'ignore-agent-id',
  /**
   * Resolves an agent with no record on the workload to its record on another workload of the
   * realm.
   */
  CROSS_WORKLOAD_AGENT: 'cross-workload-agent',
  /**
   * Never reports that the agent ID is enrolled for another workload of the realm: every UNKNOWN
   * answer says it is not.
   */
  NEVER_SET_ELSEWHERE: 'never-set-elsewhere',
  /**
   * Reports an agent ID enrolled in another realm as enrolled for another workload of the realm.
   */
  ELSEWHERE_ACROSS_REALMS: 'elsewhere-across-realms',
  /**
   * Selects by the agent ID on a workload with more than one enrollment in force, as an adapter
   * whose workloads may be shared does, although its workloads are dedicated.
   */
  SELECT_DESPITE_DEDICATED: 'select-despite-dedicated',
  /**
   * Counts the revoked records of a dedicated workload toward its enrollments in force, so a
   * workload whose other agent was revoked is a configuration error.
   */
  REVOKED_COUNTS_AS_IN_FORCE: 'revoked-counts-as-in-force',

  // The freshness defects (Go freshness.go).
  /**
   * Keeps the binding status it read when the contract was issued for the contract's lifetime, so a
   * revocation the source confirmed less than a contract lifetime ago is not seen.
   */
  CACHE_BINDING_FOR_CONTRACT: 'cache-binding-for-contract',
  /** Reports the native verdict of a check without applying the check's age limits. */
  IGNORE_CHECK_LIMITS: 'ignore-check-limits',
  /** Treats an age equal to its limit as stale. */
  STALE_AT_LIMIT: 'stale-at-limit',
  /**
   * Reports a source clock that runs ahead as a source that cannot answer, which defers instead of
   * refusing.
   */
  DEFER_CLOCK_AHEAD: 'defer-clock-ahead',
  /** Allows a source clock no skew: a time even a second ahead of now is CLOCK_AHEAD. */
  NO_SKEW_ALLOWANCE: 'no-skew-allowance',
  /** Reports the native verdict of a pinned check whatever revision its source reports. */
  IGNORE_PINNED_REVISION: 'ignore-pinned-revision',
  /**
   * Reads the records of a source that cannot answer as if it could: the last value it held stands
   * in for an answer.
   */
  READ_THROUGH_OUTAGE: 'read-through-outage',
  /**
   * Evaluates a check without the observation times its guard already holds, so a re-stamped record
   * reads as fresh.
   */
  FORGET_SIGHTINGS: 'forget-sightings',
} as const);

/** One way of getting the contract wrong: a value of {@link Defect}. */
export type Defect = (typeof Defect)[keyof typeof Defect];
