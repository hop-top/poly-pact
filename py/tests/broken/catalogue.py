"""The catalogue of defects with the cases that exist to catch each one (Go
adapters/internal/broken, catalogue.go).

A case appears under each defect that breaks the behaviour it asserts; every
common case appears under at least one.
"""

from __future__ import annotations

from broken.defects import Defect, Spec

__all__ = ["CATALOGUE"]

CATALOGUE: tuple[Spec, ...] = (
    Spec(
        Defect.TRUST_HEADER_IDENTITY,
        "names an identity from client-supplied headers when no credential is presented",
        ("COMMON-01.headers-only",),
    ),
    Spec(
        Defect.HEADER_OVERRIDES_CREDENTIAL,
        "lets a client-supplied identity header override the authenticated credential",
        ("COMMON-01.credential-wins",),
    ),
    Spec(
        Defect.ACCEPT_BYPASS,
        "authenticates a request that bypassed the enforcement point",
        ("COMMON-02.direct",),
    ),
    Spec(
        Defect.REJECT_ENFORCEMENT_POINT,
        "refuses a request that came through the enforcement point",
        ("COMMON-02.via-enforcement-point",),
    ),
    Spec(
        Defect.CONFLATE_ISSUERS,
        "resolves identities by local name and conflates same-named identities of different"
        " issuers",
        ("COMMON-09.authenticate-realm",),
    ),
    Spec(
        Defect.LEAK_TOKEN_IN_DENIAL,
        "echoes the presented token and cookie in the denial",
        ("COMMON-10.authenticate-error",),
    ),
    Spec(
        Defect.FORWARDED_HOST_ORIGIN,
        "takes the host of the target URI from X-Forwarded-Host or Host",
        ("COMMON-03.target-uri", "COMMON-03.baseline"),
    ),
    Spec(
        Defect.NORMALIZE_QUERY,
        "sorts and re-encodes the query of the target URI",
        ("COMMON-03.target-uri",),
    ),
    Spec(
        Defect.BODY_NOT_COVERED,
        "digests the empty string whatever the body is",
        ("COMMON-03.body-digest", "COMMON-03.baseline"),
    ),
    Spec(
        Defect.BODY_NOT_RESTORED,
        "consumes the request body and does not restore it",
        ("COMMON-03.body-digest",),
    ),
    Spec(
        Defect.BLANK_EMPTY_DIGEST,
        "gives an empty body no digest",
        ("COMMON-03.empty-body",),
    ),
    Spec(
        Defect.ECHO_ALL_HEADERS,
        "covers every request header, credentials included",
        ("COMMON-03.headers", "COMMON-03.baseline", "COMMON-10.map-operation"),
    ),
    Spec(
        Defect.TRUST_CLIENT_RESOURCES,
        "takes the resources from a client-supplied header",
        ("COMMON-03.resources",),
    ),
    Spec(
        Defect.ACCEPT_FRAGMENT,
        "maps a request target that has a fragment",
        ("COMMON-03.fragment", "COMMON-10.map-error"),
    ),
    Spec(
        Defect.ACCEPT_USERINFO,
        "maps a request target that has userinfo",
        ("COMMON-03.userinfo",),
    ),
    Spec(
        Defect.ACCEPT_CONTENT_ENCODING,
        "maps a request with a content encoding",
        ("COMMON-03.content-encoding",),
    ),
    Spec(
        Defect.NORMALIZE_AMBIGUOUS_ENCODING,
        "normalizes an ambiguous encoding of the request target instead of rejecting it",
        (
            "COMMON-03.ambiguous-query",
            "COMMON-03.encoded-slash",
            "COMMON-03.invalid-utf8",
            "COMMON-03.dot-segment",
        ),
    ),
    Spec(
        Defect.WRONG_MALFORMED_CODE,
        "rejects a malformed request with the code of another error",
        (
            "COMMON-03.fragment",
            "COMMON-03.userinfo",
            "COMMON-03.content-encoding",
            "COMMON-03.ambiguous-query",
            "COMMON-03.encoded-slash",
            "COMMON-03.invalid-utf8",
            "COMMON-03.dot-segment",
        ),
    ),
    Spec(
        Defect.PRINCIPAL_FROM_HEADER,
        "takes principal_id from a client-supplied header",
        ("COMMON-03.baseline",),
    ),
    Spec(
        Defect.IGNORE_REALM_MAPPING,
        "maps the operation of a principal from another realm",
        ("COMMON-09.map-realm",),
    ),
    Spec(
        Defect.LEAK_CREDENTIAL_IN_MAP_ERROR,
        "echoes the request credentials in the mapping error",
        ("COMMON-10.map-error",),
    ),
    Spec(
        Defect.RESTAMP_OBSERVED_AT,
        "replaces the source's observation time with the time of the read",
        ("COMMON-04.original-time", "COMMON-04.no-source-time"),
    ),
    Spec(
        Defect.STAMP_MISSING_TIMES,
        "supplies the time of the read where the source gives no time",
        ("COMMON-04.no-source-time",),
    ),
    Spec(
        Defect.PASS_FUTURE_OBSERVED_AT,
        "passes on an observation time in the future",
        ("COMMON-04.future-observed-at",),
    ),
    Spec(
        Defect.PASS_FUTURE_STATUS_CHECKED,
        "passes on a status check time later than now plus the skew",
        ("COMMON-04.future-status-checked",),
    ),
    Spec(
        Defect.NO_STATUS_SKEW_ALLOWANCE,
        "refuses a status check time ahead of now by no more than the skew",
        ("COMMON-04.status-checked-at-skew",),
    ),
    Spec(
        Defect.CLAMP_FUTURE_CLAIM_TIMES,
        "clamps a claim time later than now plus the skew to the bound and passes the claim on",
        ("COMMON-04.future-observed-at", "COMMON-04.future-status-checked"),
    ),
    Spec(
        Defect.CONFLATE_CLAIM_REALMS,
        "reads the claim of a same-spelled principal of another realm",
        ("COMMON-09.claim-realm",),
    ),
    Spec(
        Defect.IGNORE_CLAIM_RESOURCE,
        "reads the fact of a resource that the operation does not list",
        ("COMMON-11.resource-scoped",),
    ),
    Spec(
        Defect.IGNORE_CLAIM_TASK,
        "reads the fact of a task that the intent does not carry",
        ("COMMON-11.task-scoped",),
    ),
    Spec(
        Defect.FAIL_OPEN_UNKNOWN_CHECK,
        "reports PASS for a check that is not installed",
        ("COMMON-05.unknown-id",),
    ),
    Spec(
        Defect.PREFIX_MATCH_CHECK,
        "matches a check id by prefix",
        ("COMMON-05.empty-id",),
    ),
    Spec(
        Defect.FOLD_CASE_CHECK,
        "matches a check id ignoring case",
        ("COMMON-05.near-miss-id",),
    ),
    Spec(
        Defect.NEVER_EVALUATE_CHECKS,
        "reports FAIL for every installed check without consulting it",
        ("COMMON-05.installed-control", "COMMON-12.agent-bound"),
    ),
    Spec(
        Defect.ECHO_REFS_IN_SOURCE,
        "copies the evidence references into the source of the check outcome",
        ("COMMON-10.check-outcome",),
    ),
    Spec(
        Defect.IGNORE_CHECK_SCOPE,
        "matches an installed check by its id alone, for any agent and any principal",
        ("COMMON-12.no-binding", "COMMON-12.other-agent", "COMMON-12.other-principal"),
    ),
    Spec(
        Defect.TRUST_EMPTY_BINDING,
        "lets a call with no agent binding match a check whose state is for an agent",
        ("COMMON-12.no-binding",),
    ),
    Spec(
        Defect.EXECUTE_ON_DENY,
        "runs the execution hook although the decision is a denial",
        ("COMMON-06.deny-unchanged",),
    ),
    Spec(
        Defect.REWRITE_READ_DENY,
        "turns the denial of a read into an allow",
        ("COMMON-06.deny-unchanged",),
    ),
    Spec(
        Defect.CONNECTOR_SUBSTITUTION,
        "evaluates the policy as a broader identity the policy allows",
        ("COMMON-06.no-connector-substitution",),
    ),
    Spec(
        Defect.DEFAULT_ALLOW,
        "allows a principal that no rule mentions",
        ("COMMON-06.no-policy-not-allowed",),
    ),
    Spec(
        Defect.EXECUTE_ON_ALLOW,
        "runs the execution hook while authorizing",
        ("COMMON-06.allow-no-execution",),
    ),
    Spec(
        Defect.DROP_OBLIGATIONS,
        "strips the obligations from the decision",
        ("COMMON-06.allow-no-execution", "COMMON-06.deny-unchanged"),
    ),
    Spec(
        Defect.CONFLATE_POLICY_REALMS,
        "applies the rule of a same-spelled principal of another realm",
        ("COMMON-09.authorize-realm",),
    ),
    Spec(
        Defect.DECISION_WITHOUT_SOURCE,
        "returns a decision that names no policy source",
        ("COMMON-06.decision-provenance", "COMMON-06.no-policy-not-allowed"),
    ),
    Spec(
        Defect.FUTURE_DECIDED_AT,
        "stamps a decision with a time after now plus the skew",
        ("COMMON-06.decision-provenance", "COMMON-06.deny-unchanged"),
    ),
    Spec(
        Defect.ASSUME_EXECUTION_SUCCESS,
        "signs EXECUTION SUCCESS without execution visibility",
        ("COMMON-07.no-visibility",),
    ),
    Spec(
        Defect.NO_VISIBILITY_FOR_ADMISSION,
        "declares no visibility for its own admission decision",
        ("COMMON-07.admission-without-execution-visibility",),
    ),
    Spec(
        Defect.NO_VISIBILITY_DESPITE_VISIBILITY,
        "declares no visibility for an execution it observes",
        ("COMMON-07.visible-execution-success", "COMMON-10.record-outcome"),
    ),
    Spec(
        Defect.LEAK_DETAILS_IN_REPORT,
        "signs the observation's free text and references unchanged",
        ("COMMON-10.record-outcome",),
    ),
    Spec(
        Defect.REVIVE_REVOKED_BINDING,
        "reports a revoked binding as active",
        ("COMMON-08.revoked",),
    ),
    Spec(
        Defect.REVIVE_COMPROMISED_BINDING,
        "reports a compromised binding as active",
        ("COMMON-08.compromised",),
    ),
    Spec(
        Defect.LOSE_ACTIVE_BINDING,
        "reports an active binding as unknown",
        ("COMMON-08.active-control",),
    ),
    Spec(
        Defect.TRUST_UNENROLLED,
        "gives a workload that is not enrolled an active binding",
        ("COMMON-08.unenrolled",),
    ),
    Spec(
        Defect.UNUSABLE_AS_ERROR,
        "reports a revoked or compromised binding as an error instead of its status, agent,"
        " operator and holder key",
        (
            "COMMON-08.revoked",
            "COMMON-08.compromised",
            "IDENT-08.old-key-proof",
            "IDENT-09.revoked-pair",
            "IDENT-09.compromised-in-force",
            "FRESH-01.revoked-after-issuance",
        ),
    ),
    Spec(
        Defect.STATUS_WITHOUT_RECORD,
        "reports a revoked or compromised status without the agent, operator and holder key of"
        " the record",
        (
            "COMMON-08.revoked",
            "COMMON-08.compromised",
            "IDENT-08.old-key-proof",
            "IDENT-09.revoked-pair",
            "IDENT-09.compromised-in-force",
            "FRESH-01.revoked-after-issuance",
        ),
    ),
    Spec(
        Defect.CONFLATE_BINDING_REALMS,
        "resolves a workload in whichever realm enrolls it",
        ("COMMON-09.binding-realm",),
    ),
    Spec(
        Defect.REALM_WORKLOAD,
        "gives every principal of a realm the workload that the realm enrolls",
        ("IDENT-01.authenticate",),
    ),
    Spec(
        Defect.CONFLATE_TENANTS,
        "resolves identities by the last component of the id, dropping issuer and tenant",
        ("IDENT-02.authenticate",),
    ),
    Spec(
        Defect.USER_WORKLOAD,
        "gives a principal the workload of its first identity, not of the client it came through",
        ("IDENT-03.authenticate",),
    ),
    Spec(
        Defect.IDENTITY_BY_DISPLAY_NAME,
        "resolves identities by display name",
        ("IDENT-05.authenticate",),
    ),
    Spec(
        Defect.BINDING_BY_REALM,
        "resolves a workload with no enrollment to an enrollment of its realm",
        (
            "IDENT-01.binding",
            "IDENT-02.binding",
            "IDENT-03.binding",
            "IDENT-04.other-ca",
            "IDENT-04.other-workload",
            "IDENT-06.session-policy",
        ),
    ),
    Spec(
        Defect.MATCH_LOCAL_PART,
        "matches a workload by its last component",
        ("IDENT-02.binding", "IDENT-04.other-ca"),
    ),
    Spec(
        Defect.DROP_LAST_COMPONENT,
        "matches a workload without its last component",
        (
            "IDENT-01.binding",
            "IDENT-03.binding",
            "IDENT-04.other-workload",
            "IDENT-06.session-policy",
        ),
    ),
    Spec(
        Defect.HOLDER_KEY_FROM_CREDENTIAL,
        "takes the holder key from the credential instead of the enrollment",
        ("IDENT-07.credential-key",),
    ),
    Spec(
        Defect.RECOVER_BY_OLD_KEY,
        "reports a compromised binding active when the credential proves the old key",
        ("IDENT-08.old-key-proof",),
    ),
    Spec(
        Defect.FIRST_OF_SHARED,
        "resolves a shared workload to the first agent enrolled on it, whatever agent the"
        " request names",
        (
            "IDENT-09.shared-workload",
            "IDENT-09.other-agent",
            "IDENT-09.one-in-force",
            "IDENT-09.compromised-in-force",
            "IDENT-09.unenrolled-agent",
            "IDENT-09.other-workload-agent",
        ),
    ),
    Spec(
        Defect.REVOKED_IN_FORCE,
        "resolves a shared workload by the workload alone and counts a revoked record as in force",
        ("IDENT-09.one-in-force",),
    ),
    Spec(
        Defect.COMPROMISED_NOT_IN_FORCE,
        "resolves a shared workload by the workload alone and leaves the compromised record out",
        ("IDENT-09.compromised-in-force",),
    ),
    Spec(
        Defect.IGNORE_AGENT_ID,
        "ignores the agent ID and resolves the workload alone, so any agent of the workload may"
        " answer",
        (
            "IDENT-09.shared-workload",
            "IDENT-09.other-agent",
            "IDENT-09.compromised-in-force",
            "IDENT-09.revoked-pair",
            "IDENT-09.unenrolled-agent",
        ),
    ),
    Spec(
        Defect.CROSS_WORKLOAD_AGENT,
        "selects the agent's record on another workload of the realm",
        ("IDENT-09.other-workload-agent", "IDENT-04.other-workload"),
    ),
    Spec(
        Defect.NEVER_SET_ELSEWHERE,
        "never reports an agent ID enrolled for another workload of the realm",
        ("IDENT-09.other-workload-agent",),
    ),
    Spec(
        Defect.ELSEWHERE_ACROSS_REALMS,
        "reports an agent ID enrolled in another realm as enrolled for another workload of the"
        " realm",
        ("IDENT-09.other-realm-agent",),
    ),
    Spec(
        Defect.SELECT_DESPITE_DEDICATED,
        "selects by the agent ID on a dedicated workload with more than one enrollment in force",
        ("IDENT-10.two-in-force", "IDENT-10.compromised-and-active", "IDENT-10.unenrolled-agent"),
    ),
    Spec(
        Defect.REVOKED_COUNTS_AS_IN_FORCE,
        "counts a revoked record toward the enrollments in force of a dedicated workload",
        ("IDENT-10.revoked-and-active",),
    ),
    Spec(
        Defect.CACHE_BINDING_FOR_CONTRACT,
        "keeps the binding status read at contract issuance for the contract's lifetime",
        ("FRESH-01.revoked-after-issuance",),
    ),
    Spec(
        Defect.IGNORE_CHECK_LIMITS,
        "reports a check's native verdict without applying its age limits",
        ("FRESH-02.stale-snapshot", "FRESH-03.observed-ahead", "FRESH-06.restamped"),
    ),
    Spec(
        Defect.STALE_AT_LIMIT,
        "treats an age equal to its limit as stale",
        ("FRESH-02.at-limit",),
    ),
    Spec(
        Defect.DEFER_CLOCK_AHEAD,
        "reports a source clock that runs ahead as a source that cannot answer",
        ("FRESH-03.observed-ahead",),
    ),
    Spec(
        Defect.NO_SKEW_ALLOWANCE,
        "allows a source clock no skew",
        ("FRESH-03.at-skew",),
    ),
    Spec(
        Defect.IGNORE_PINNED_REVISION,
        "reports a pinned check's native verdict whatever revision its source reports",
        ("FRESH-04.pinned-revision-changed",),
    ),
    Spec(
        Defect.READ_THROUGH_OUTAGE,
        "reads the records of a source that cannot answer as if it could",
        (
            "FRESH-05.binding-source-down",
            "FRESH-05.claim-source-down",
            "FRESH-05.check-source-down",
        ),
    ),
    Spec(
        Defect.FORGET_SIGHTINGS,
        "evaluates a check without the observation times its guard already holds",
        ("FRESH-06.restamped",),
    ),
)
