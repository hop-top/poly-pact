"""The defects of the broken adapter and the record that names the cases each one
exists to catch (Go adapters/internal/broken, broken.go and freshness.go)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

__all__ = ["Defect", "Spec"]


class Defect(StrEnum):
    """One way of getting the contract wrong. Each docstring says what the adapter
    does wrong."""

    TRUST_HEADER_IDENTITY = "trust-header-identity"
    """Authenticates the identity that X-User, X-Principal, X-Forwarded-User,
    X-Client-Cert or X-Acme-Identity names, when the request presents no
    credential."""
    HEADER_OVERRIDES_CREDENTIAL = "header-overrides-credential"
    """Lets an identity header win over the credential."""
    ACCEPT_BYPASS = "accept-bypass"
    """Authenticates requests that did not arrive through the enforcement point."""
    REJECT_ENFORCEMENT_POINT = "reject-enforcement-point"
    """Refuses requests that did arrive through it."""
    CONFLATE_ISSUERS = "conflate-issuers"
    """Resolves an authenticated identity by its local name, so same-named
    identities of different issuers become one."""
    LEAK_TOKEN_IN_DENIAL = "leak-token-in-denial"
    """Puts the presented token and cookie in the denial."""

    FORWARDED_HOST_ORIGIN = "forwarded-host-origin"
    """Takes the host of the target URI from X-Forwarded-Host or the Host header
    instead of the configured origin."""
    NORMALIZE_QUERY = "normalize-query"
    """Sorts and re-encodes the query of the target URI."""
    BODY_NOT_COVERED = "body-not-covered"
    """Digests the empty string whatever the body is."""
    BODY_NOT_RESTORED = "body-not-restored"
    """Consumes the request body and leaves it empty."""
    BLANK_EMPTY_DIGEST = "blank-empty-digest"
    """Gives a request without a body an empty body digest."""
    ECHO_ALL_HEADERS = "echo-all-headers"
    """Covers every request header, credentials included."""
    TRUST_CLIENT_RESOURCES = "trust-client-resources"
    """Takes the resources from a client-supplied header."""
    ACCEPT_FRAGMENT = "accept-fragment"
    """Maps a request target that has a fragment."""
    ACCEPT_USERINFO = "accept-userinfo"
    """Maps a request target that has userinfo."""
    ACCEPT_CONTENT_ENCODING = "accept-content-encoding"
    """Maps a request with a content encoding."""
    NORMALIZE_AMBIGUOUS_ENCODING = "normalize-ambiguous-encoding"
    """Normalizes the request-target before it maps it: escapes of unreserved
    characters and of "/" in the path, and overlong two-octet forms, are decoded,
    lowercase hex digits are uppercased, and dot segments are removed from the
    path."""
    WRONG_MALFORMED_CODE = "wrong-malformed-code"
    """Rejects a malformed request, as it should, but with the code of another error
    (UNSUPPORTED_REQUIREMENT) instead of INVALID_MESSAGE."""
    PRINCIPAL_FROM_HEADER = "principal-from-header"
    """Takes principal_id from the X-Principal header."""
    IGNORE_REALM_MAPPING = "ignore-realm-mapping"
    """Maps the operation of a principal of another realm."""
    LEAK_CREDENTIAL_IN_MAP_ERROR = "leak-credential-in-map-error"
    """Puts the request credentials in the mapping error."""

    RESTAMP_OBSERVED_AT = "restamp-observed-at"
    """Replaces the source's observation time with the time of the read."""
    STAMP_MISSING_TIMES = "stamp-missing-times"
    """Supplies the time of the read where the source gives no time."""
    PASS_FUTURE_OBSERVED_AT = "pass-future-observed-at"
    """Passes on an observation time in the future."""
    PASS_FUTURE_STATUS_CHECKED = "pass-future-status-checked"
    """Passes on a status check time later than now plus the skew."""
    NO_STATUS_SKEW_ALLOWANCE = "no-status-skew-allowance"
    """Refuses a claim whose status check time is ahead of now by no more than the
    skew, which draft A.2 allows."""
    CLAMP_FUTURE_CLAIM_TIMES = "clamp-future-claim-times"
    """Passes on a claim whose observation or status check time is later than now
    plus the skew, with that time clamped to now plus the skew, instead of
    refusing it with DEPENDENCY_UNAVAILABLE."""
    CONFLATE_CLAIM_REALMS = "conflate-claim-realms"
    """Reads the claim of a same-spelled principal of another realm."""
    IGNORE_CLAIM_RESOURCE = "ignore-claim-resource"
    """Reads the fact of a resource whatever the resources of the operation are."""
    IGNORE_CLAIM_TASK = "ignore-claim-task"
    """Reads the fact of a task whatever the task of the intent is."""

    FAIL_OPEN_UNKNOWN_CHECK = "fail-open-unknown-check"
    """Passes a check that is not installed."""
    PREFIX_MATCH_CHECK = "prefix-match-check"
    """Matches a check id by prefix, so the empty id matches."""
    FOLD_CASE_CHECK = "fold-case-check"
    """Matches a check id ignoring case."""
    NEVER_EVALUATE_CHECKS = "never-evaluate-checks"
    """Reports FAIL for every installed check without consulting its native state."""
    ECHO_REFS_IN_SOURCE = "echo-refs-in-source"
    """Copies the evidence references into the check source."""
    IGNORE_CHECK_SCOPE = "ignore-check-scope"
    """Matches an installed check by its id alone, whatever agent or principal its
    native state is for."""
    TRUST_EMPTY_BINDING = "trust-empty-binding"
    """Lets a call that established no agent match a check whose native state is for
    an agent."""

    EXECUTE_ON_DENY = "execute-on-deny"
    """Runs the execution hook although the decision is a denial."""
    REWRITE_READ_DENY = "rewrite-read-deny"
    """Turns the denial of a read into an allow."""
    CONNECTOR_SUBSTITUTION = "connector-substitution"
    """Evaluates the policy as a broader identity that the policy allows."""
    DEFAULT_ALLOW = "default-allow"
    """Allows a principal that no rule mentions."""
    EXECUTE_ON_ALLOW = "execute-on-allow"
    """Runs the execution hook while authorizing."""
    DROP_OBLIGATIONS = "drop-obligations"
    """Strips the obligations from the decision."""
    CONFLATE_POLICY_REALMS = "conflate-policy-realms"
    """Applies the rule of a same-spelled principal of another realm."""
    DECISION_WITHOUT_SOURCE = "decision-without-source"
    """Returns decisions that name no policy source."""
    FUTURE_DECIDED_AT = "future-decided-at"
    """Stamps each decision with a time an hour after now."""

    ASSUME_EXECUTION_SUCCESS = "assume-execution-success"
    """Signs EXECUTION SUCCESS although the adapter has no execution visibility."""
    NO_VISIBILITY_FOR_ADMISSION = "no-visibility-for-admission"
    """Declares no visibility for an admission event."""
    NO_VISIBILITY_DESPITE_VISIBILITY = "no-visibility-despite-visibility"
    """Declares no visibility for an execution the adapter does see."""
    LEAK_DETAILS_IN_REPORT = "leak-details-in-report"
    """Signs the observation's free text and references unchanged."""

    REVIVE_REVOKED_BINDING = "revive-revoked-binding"
    """Reports a revoked binding as active."""
    REVIVE_COMPROMISED_BINDING = "revive-compromised-binding"
    """Reports a compromised binding as active."""
    LOSE_ACTIVE_BINDING = "lose-active-binding"
    """Reports an active binding as unknown."""
    TRUST_UNENROLLED = "trust-unenrolled"
    """Gives a workload that is not enrolled an active binding."""
    UNUSABLE_AS_ERROR = "unusable-as-error"
    """Reports a revoked or compromised binding as an error with no binding, instead
    of its status with the agent, operator and holder key of the record (identity
    mapping IM-11)."""
    STATUS_WITHOUT_RECORD = "status-without-record"
    """Reports the REVOKED or COMPROMISED status of a binding without the agent,
    operator and holder key of the record."""
    CONFLATE_BINDING_REALMS = "conflate-binding-realms"
    """Resolves a workload in whichever realm enrolls it."""

    REALM_WORKLOAD = "realm-workload"
    """Gives every principal of a realm the workload that the realm enrolls, so
    another user becomes the enrolled account."""
    CONFLATE_TENANTS = "conflate-tenants"
    """Resolves an authenticated identity by the last component of its id, dropping
    the issuer and tenant that come before it."""
    USER_WORKLOAD = "user-workload"
    """Gives a principal the workload of its first identity, so a user acting
    through another client gets the enrolled client."""
    IDENTITY_BY_DISPLAY_NAME = "identity-by-display-name"
    """Resolves an authenticated identity by its display name."""
    BINDING_BY_REALM = "binding-by-realm"
    """Resolves a workload with no enrollment to the first enrollment of its realm."""
    MATCH_LOCAL_PART = "match-local-part"
    """Matches a workload with no enrollment to one with the same last component:
    the same subject of another tenant or authority."""
    DROP_LAST_COMPONENT = "drop-last-component"
    """Matches a workload with no enrollment to one that is equal without its last
    component: a role whatever its session policy, another client of the issuer,
    another certificate of the authority."""
    HOLDER_KEY_FROM_CREDENTIAL = "holder-key-from-credential"
    """Reports the key that the credential of the workload is bound to as the holder
    key, instead of the enrolled key."""
    RECOVER_BY_OLD_KEY = "recover-by-old-key"
    """Reports a compromised binding as active when the credential of the workload
    is bound to the enrolled key."""
    FIRST_OF_SHARED = "first-of-shared"
    """Resolves a workload that several agents share to the first agent enrolled on
    it, whatever agent the request names."""
    REVOKED_IN_FORCE = "revoked-in-force"
    """Resolves a workload that several agents share by the workload alone and
    counts its revoked records as in force."""
    COMPROMISED_NOT_IN_FORCE = "compromised-not-in-force"
    """Resolves a workload that several agents share by the workload alone and
    leaves its compromised record out, so that the other agent resolves."""
    IGNORE_AGENT_ID = "ignore-agent-id"
    """Drops the agent ID the request names and resolves the workload alone: the one
    agent in force on it answers, whichever agent the request names, and several
    in force answer UNKNOWN."""
    CROSS_WORKLOAD_AGENT = "cross-workload-agent"
    """Resolves an agent with no record on the workload to its record on another
    workload of the realm."""
    NEVER_SET_ELSEWHERE = "never-set-elsewhere"
    """Never reports that the agent ID is enrolled for another workload of the
    realm: every UNKNOWN answer says it is not."""
    ELSEWHERE_ACROSS_REALMS = "elsewhere-across-realms"
    """Reports an agent ID enrolled in another realm as enrolled for another
    workload of the realm."""
    SELECT_DESPITE_DEDICATED = "select-despite-dedicated"
    """Selects by the agent ID on a workload with more than one enrollment in force,
    as an adapter whose workloads may be shared does, although its workloads are
    dedicated."""
    REVOKED_COUNTS_AS_IN_FORCE = "revoked-counts-as-in-force"
    """Counts the revoked records of a dedicated workload toward its enrollments in
    force, so a workload whose other agent was revoked is a configuration error."""

    CACHE_BINDING_FOR_CONTRACT = "cache-binding-for-contract"
    """Keeps the binding status it read when the contract was issued for the
    contract's lifetime, so a revocation the source confirmed less than a contract
    lifetime ago is not seen."""
    IGNORE_CHECK_LIMITS = "ignore-check-limits"
    """Reports the native verdict of a check without applying the check's age
    limits."""
    STALE_AT_LIMIT = "stale-at-limit"
    """Treats an age equal to its limit as stale."""
    DEFER_CLOCK_AHEAD = "defer-clock-ahead"
    """Reports a source clock that runs ahead as a source that cannot answer, which
    defers instead of refusing."""
    NO_SKEW_ALLOWANCE = "no-skew-allowance"
    """Allows a source clock no skew: a time even a second ahead of now is
    CLOCK_AHEAD."""
    IGNORE_PINNED_REVISION = "ignore-pinned-revision"
    """Reports the native verdict of a pinned check whatever revision its source
    reports."""
    READ_THROUGH_OUTAGE = "read-through-outage"
    """Reads the records of a source that cannot answer as if it could: the last
    value it held stands in for an answer."""
    FORGET_SIGHTINGS = "forget-sightings"
    """Evaluates a check without the observation times its guard already holds, so a
    re-stamped record reads as fresh."""


@dataclass(frozen=True, slots=True)
class Spec:
    """A defect and the cases that exist to catch it. what says in one line what the
    defect gets wrong; targets are the ids of the cases that must fail when only
    this defect is on."""

    defect: Defect
    what: str
    targets: tuple[str, ...]
