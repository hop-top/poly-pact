// Package broken is a deliberately wrong adapter: the memory adapter with
// switchable defects, each a violation of draft 17.1 and of the invariants it
// cites that one common conformance case exists to catch.
//
// The conformance suite is only evidence if it can fail. This package is the
// proof: its test runs the suite against the adapter with each defect on and
// requires the cases the defect targets to fail, against the adapter with all
// defects on and requires every case to fail, and against the adapter with none
// and requires every case to pass. A case that no defect targets fails a test
// of its own, so a new case cannot land without a mutant that it catches.
//
// The package is internal to the adapters tree. Do not use it as an example
// of anything.
package broken

import (
	"net/http"
	"slices"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core/clock"
)

// Defect names one way of getting the contract wrong.
type Defect string

// The defects. Each comment says what the adapter does wrong.
const (
	// TrustHeaderIdentity authenticates the identity that X-User, X-Principal,
	// X-Forwarded-User, X-Client-Cert or X-Acme-Identity names, when the
	// request presents no credential.
	TrustHeaderIdentity Defect = "trust-header-identity"
	// HeaderOverridesCredential lets an identity header win over the credential.
	HeaderOverridesCredential Defect = "header-overrides-credential"
	// AcceptBypass authenticates requests that did not arrive through the
	// enforcement point.
	AcceptBypass Defect = "accept-bypass"
	// RejectEnforcementPoint refuses requests that did arrive through it.
	RejectEnforcementPoint Defect = "reject-enforcement-point"
	// ConflateIssuers resolves an authenticated identity by its local name, so
	// same-named identities of different issuers become one.
	ConflateIssuers Defect = "conflate-issuers"
	// LeakTokenInDenial puts the presented token and cookie in the denial.
	LeakTokenInDenial Defect = "leak-token-in-denial"

	// ForwardedHostOrigin takes the host of the target URI from X-Forwarded-Host
	// or the Host header instead of the configured origin.
	ForwardedHostOrigin Defect = "forwarded-host-origin"
	// NormalizeQuery sorts and re-encodes the query of the target URI.
	NormalizeQuery Defect = "normalize-query"
	// BodyNotCovered digests the empty string whatever the body is.
	BodyNotCovered Defect = "body-not-covered"
	// BodyNotRestored consumes the request body and leaves it empty.
	BodyNotRestored Defect = "body-not-restored"
	// BlankEmptyDigest gives a request without a body an empty body digest.
	BlankEmptyDigest Defect = "blank-empty-digest"
	// EchoAllHeaders covers every request header, credentials included.
	EchoAllHeaders Defect = "echo-all-headers"
	// TrustClientResources takes the resources from a client-supplied header.
	TrustClientResources Defect = "trust-client-resources"
	// AcceptFragment maps a request target that has a fragment.
	AcceptFragment Defect = "accept-fragment"
	// AcceptUserinfo maps a request target that has userinfo.
	AcceptUserinfo Defect = "accept-userinfo"
	// AcceptContentEncoding maps a request with a content encoding.
	AcceptContentEncoding Defect = "accept-content-encoding"
	// NormalizeAmbiguousEncoding normalizes the request-target before it maps
	// it: escapes of unreserved characters and of "/" in the path, and overlong
	// two-octet forms, are decoded, lowercase hex digits are uppercased, and
	// dot segments are removed from the path.
	NormalizeAmbiguousEncoding Defect = "normalize-ambiguous-encoding"
	// WrongMalformedCode rejects a malformed request, as it should, but with the
	// code of another error (UNSUPPORTED_REQUIREMENT) instead of INVALID_MESSAGE.
	WrongMalformedCode Defect = "wrong-malformed-code"
	// PrincipalFromHeader takes principal_id from the X-Principal header.
	PrincipalFromHeader Defect = "principal-from-header"
	// IgnoreRealmMapping maps the operation of a principal of another realm.
	IgnoreRealmMapping Defect = "ignore-realm-mapping"
	// LeakCredentialInMapError puts the request credentials in the mapping error.
	LeakCredentialInMapError Defect = "leak-credential-in-map-error"

	// RestampObservedAt replaces the source's observation time with the time of
	// the read.
	RestampObservedAt Defect = "restamp-observed-at"
	// StampMissingTimes supplies the time of the read where the source gives
	// no time.
	StampMissingTimes Defect = "stamp-missing-times"
	// PassFutureObservedAt passes on an observation time in the future.
	PassFutureObservedAt Defect = "pass-future-observed-at"
	// PassFutureStatusChecked passes on a status check time later than now
	// plus the skew.
	PassFutureStatusChecked Defect = "pass-future-status-checked"
	// NoStatusSkewAllowance refuses a claim whose status check time is ahead
	// of now by no more than the skew, which draft A.2 allows.
	NoStatusSkewAllowance Defect = "no-status-skew-allowance"
	// ClampFutureClaimTimes passes on a claim whose observation or status
	// check time is later than now plus the skew, with that time clamped to
	// now plus the skew, instead of refusing it with DEPENDENCY_UNAVAILABLE.
	ClampFutureClaimTimes Defect = "clamp-future-claim-times"
	// ConflateClaimRealms reads the claim of a same-spelled principal of
	// another realm.
	ConflateClaimRealms Defect = "conflate-claim-realms"
	// IgnoreClaimResource reads the fact of a resource whatever the resources
	// of the operation are.
	IgnoreClaimResource Defect = "ignore-claim-resource"
	// IgnoreClaimTask reads the fact of a task whatever the task of the intent
	// is.
	IgnoreClaimTask Defect = "ignore-claim-task"

	// FailOpenUnknownCheck passes a check that is not installed.
	FailOpenUnknownCheck Defect = "fail-open-unknown-check"
	// PrefixMatchCheck matches a check id by prefix, so the empty id matches.
	PrefixMatchCheck Defect = "prefix-match-check"
	// FoldCaseCheck matches a check id ignoring case.
	FoldCaseCheck Defect = "fold-case-check"
	// NeverEvaluateChecks reports FAIL for every installed check without
	// consulting its native state.
	NeverEvaluateChecks Defect = "never-evaluate-checks"
	// EchoRefsInSource copies the evidence references into the check source.
	EchoRefsInSource Defect = "echo-refs-in-source"
	// IgnoreCheckScope matches an installed check by its id alone, whatever
	// agent or principal its native state is for.
	IgnoreCheckScope Defect = "ignore-check-scope"
	// TrustEmptyBinding lets a call that established no agent match a check
	// whose native state is for an agent.
	TrustEmptyBinding Defect = "trust-empty-binding"

	// ExecuteOnDeny runs the execution hook although the decision is a denial.
	ExecuteOnDeny Defect = "execute-on-deny"
	// RewriteReadDeny turns the denial of a read into an allow.
	RewriteReadDeny Defect = "rewrite-read-deny"
	// ConnectorSubstitution evaluates the policy as a broader identity that the
	// policy allows.
	ConnectorSubstitution Defect = "connector-substitution"
	// DefaultAllow allows a principal that no rule mentions.
	DefaultAllow Defect = "default-allow"
	// ExecuteOnAllow runs the execution hook while authorizing.
	ExecuteOnAllow Defect = "execute-on-allow"
	// DropObligations strips the obligations from the decision.
	DropObligations Defect = "drop-obligations"
	// ConflatePolicyRealms applies the rule of a same-spelled principal of
	// another realm.
	ConflatePolicyRealms Defect = "conflate-policy-realms"
	// DecisionWithoutSource returns decisions that name no policy source.
	DecisionWithoutSource Defect = "decision-without-source"
	// FutureDecidedAt stamps each decision with a time an hour after now.
	FutureDecidedAt Defect = "future-decided-at"

	// AssumeExecutionSuccess signs EXECUTION SUCCESS although the adapter has
	// no execution visibility.
	AssumeExecutionSuccess Defect = "assume-execution-success"
	// NoVisibilityForAdmission declares no visibility for an admission event.
	NoVisibilityForAdmission Defect = "no-visibility-for-admission"
	// NoVisibilityDespiteVisibility declares no visibility for an execution
	// the adapter does see.
	NoVisibilityDespiteVisibility Defect = "no-visibility-despite-visibility"
	// LeakDetailsInReport signs the observation's free text and references
	// unchanged.
	LeakDetailsInReport Defect = "leak-details-in-report"

	// ReviveRevokedBinding reports a revoked binding as active.
	ReviveRevokedBinding Defect = "revive-revoked-binding"
	// ReviveCompromisedBinding reports a compromised binding as active.
	ReviveCompromisedBinding Defect = "revive-compromised-binding"
	// LoseActiveBinding reports an active binding as unknown.
	LoseActiveBinding Defect = "lose-active-binding"
	// TrustUnenrolled gives a workload that is not enrolled an active binding.
	TrustUnenrolled Defect = "trust-unenrolled"
	// UnusableAsError reports a revoked or compromised binding as an error
	// with no binding, instead of its status with the agent, operator and
	// holder key of the record (identity mapping IM-11).
	UnusableAsError Defect = "unusable-as-error"
	// StatusWithoutRecord reports the REVOKED or COMPROMISED status of a
	// binding without the agent, operator and holder key of the record.
	StatusWithoutRecord Defect = "status-without-record"
	// ConflateBindingRealms resolves a workload in whichever realm enrolls it.
	ConflateBindingRealms Defect = "conflate-binding-realms"

	// RealmWorkload gives every principal of a realm the workload that the
	// realm enrolls, so another user becomes the enrolled account.
	RealmWorkload Defect = "realm-workload"
	// ConflateTenants resolves an authenticated identity by the last component
	// of its id, dropping the issuer and tenant that come before it.
	ConflateTenants Defect = "conflate-tenants"
	// UserWorkload gives a principal the workload of its first identity, so a
	// user acting through another client gets the enrolled client.
	UserWorkload Defect = "user-workload"
	// IdentityByDisplayName resolves an authenticated identity by its display
	// name.
	IdentityByDisplayName Defect = "identity-by-display-name"
	// BindingByRealm resolves a workload with no enrollment to the first
	// enrollment of its realm.
	BindingByRealm Defect = "binding-by-realm"
	// MatchLocalPart matches a workload with no enrollment to one with the
	// same last component: the same subject of another tenant or authority.
	MatchLocalPart Defect = "match-local-part"
	// DropLastComponent matches a workload with no enrollment to one that is
	// equal without its last component: a role whatever its session policy,
	// another client of the issuer, another certificate of the authority.
	DropLastComponent Defect = "drop-last-component"
	// HolderKeyFromCredential reports the key that the credential of the
	// workload is bound to as the holder key, instead of the enrolled key.
	HolderKeyFromCredential Defect = "holder-key-from-credential"
	// RecoverByOldKey reports a compromised binding as active when the
	// credential of the workload is bound to the enrolled key.
	RecoverByOldKey Defect = "recover-by-old-key"
	// FirstOfShared resolves a workload that several agents share to the first
	// agent enrolled on it, whatever agent the request names.
	FirstOfShared Defect = "first-of-shared"
	// RevokedInForce resolves a workload that several agents share by the
	// workload alone and counts its revoked records as in force.
	RevokedInForce Defect = "revoked-in-force"
	// CompromisedNotInForce resolves a workload that several agents share by
	// the workload alone and leaves its compromised record out, so that the
	// other agent resolves.
	CompromisedNotInForce Defect = "compromised-not-in-force"
	// IgnoreAgentID drops the agent ID the request names and resolves the
	// workload alone: the one agent in force on it answers, whichever agent
	// the request names, and several in force answer UNKNOWN.
	IgnoreAgentID Defect = "ignore-agent-id"
	// CrossWorkloadAgent resolves an agent with no record on the workload to
	// its record on another workload of the realm.
	CrossWorkloadAgent Defect = "cross-workload-agent"
	// NeverSetElsewhere never reports that the agent ID is enrolled for
	// another workload of the realm: every UNKNOWN answer says it is not.
	NeverSetElsewhere Defect = "never-set-elsewhere"
	// ElsewhereAcrossRealms reports an agent ID enrolled in another realm as
	// enrolled for another workload of the realm.
	ElsewhereAcrossRealms Defect = "elsewhere-across-realms"
	// SelectDespiteDedicated selects by the agent ID on a workload with more
	// than one enrollment in force, as an adapter whose workloads may be
	// shared does, although its workloads are dedicated.
	SelectDespiteDedicated Defect = "select-despite-dedicated"
	// RevokedCountsAsInForce counts the revoked records of a dedicated
	// workload toward its enrollments in force, so a workload whose other
	// agent was revoked is a configuration error.
	RevokedCountsAsInForce Defect = "revoked-counts-as-in-force"
)

// Spec describes a defect and names the cases that exist to catch it.
type Spec struct {
	Defect Defect
	// What says in one line what the defect gets wrong.
	What string
	// Targets are the ids of the cases that must fail when only this defect is
	// on.
	Targets []string
}

// Adapter is the memory adapter with the defects that are switched on.
type Adapter struct {
	*memory.Adapter
	// shared says that the adapter's workloads may be shared by several
	// agents, as for memory.WithSharedWorkloads.
	shared bool
	on     map[Defect]bool
	clk    clock.Clock
	hooks  *adaptertest.Hooks
	// executing is a memory adapter with execution visibility, whose reports
	// stand in for the success that AssumeExecutionSuccess invents.
	executing *memory.Adapter
	// leaky signs reports with the unredacted text of the observation.
	leaky *leakySigner
}

// New returns the memory adapter over st with the given defects switched on,
// with workloads that several agents may share when shared is true and
// dedicated ones otherwise. hooks receives the execution hook calls of the
// defects that make them.
func New(st memory.State, clk clock.Clock, hooks *adaptertest.Hooks, shared bool, defects ...Defect) (*Adapter, error) {
	var opts []memory.Option
	if shared || slices.Contains(defects, SelectDespiteDedicated) {
		opts = append(opts, memory.WithSharedWorkloads())
	}
	base, err := memory.New(freshnessState(st, defects), clk, opts...)
	if err != nil {
		return nil, err
	}
	b := &Adapter{Adapter: base, shared: shared, on: map[Defect]bool{}, clk: clk, hooks: hooks}
	for _, d := range defects {
		b.on[d] = true
	}
	if st.Reporting != nil {
		exec := st
		exec.Visibility = "execution"
		if b.executing, err = memory.New(exec, clk, opts...); err != nil {
			return nil, err
		}
		if b.leaky, err = newLeakySigner(st); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// Factory returns an adaptertest.Factory for the adapter with the given
// defects on and dedicated workloads, the default.
func Factory(defects ...Defect) adaptertest.Factory { return factory(false, defects) }

// SharedFactory is Factory for the adapter whose workloads several agents may
// share. The suite runs it with adaptertest.Options.SharedWorkloads set.
func SharedFactory(defects ...Defect) adaptertest.Factory { return factory(true, defects) }

func factory(shared bool, defects []Defect) adaptertest.Factory {
	return func(_ testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
		st, err := memory.ParseState(env.State)
		if err != nil {
			return adaptertest.Subject{}, err
		}
		b, err := New(st, env.Clock, env.Hooks, shared, defects...)
		if err != nil {
			return adaptertest.Subject{}, err
		}
		return adaptertest.Subject{
			Adapter:       b,
			Arrive:        memory.Arrive,
			Credential:    b.Credential,
			VerifyOutcome: b.VerifyOutcome,
		}, nil
	}
}

// Describe returns a descriptor that says what this is.
func (b *Adapter) Describe() adapter.Descriptor {
	return adapter.Descriptor{Protocol: "broken", Version: "0", MappingRevision: "broken-map-0"}
}

// VerifyOutcome verifies a report signed by the adapter, by the adapter that
// stands in for a visible execution, or by the leaky signer.
func (b *Adapter) VerifyOutcome(jws string) error {
	err := b.Adapter.VerifyOutcome(jws)
	if err == nil {
		return nil
	}
	if b.executing != nil && b.executing.VerifyOutcome(jws) == nil {
		return nil
	}
	if b.leaky != nil && b.leaky.verify(jws) == nil {
		return nil
	}
	return err
}

func (b *Adapter) now() time.Time { return b.clk.Now() }

func (b *Adapter) fire(name string) {
	b.hooks.Fire(name)
}

// Defects lists every defect of the catalogue.
func Defects() []Defect {
	out := make([]Defect, len(Catalogue))
	for i, s := range Catalogue {
		out[i] = s.Defect
	}
	return out
}

// header returns the first non-empty value of the named headers.
func header(r *http.Request, names ...string) string {
	for _, n := range names {
		if v := r.Header.Get(n); v != "" {
			return v
		}
	}
	return ""
}
