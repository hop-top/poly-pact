package abac

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/installed"
)

// The obligation types of profile ABAC-25, the installed obligation set of
// an entry that names none.
const (
	ObligationFilterFields = "filter_fields"
	ObligationRedact       = "redact"
	ObligationWatermark    = "watermark"
)

// Reason codes of the ABAC check. A check reports a draft 13.4 code or a code
// of its own (draft 17.1, 17.3.1).
const (
	CodeRequirementSatisfied = installed.CodeRequirementSatisfied
	CodeRequirementsChanged  = installed.CodeRequirementsChanged
)

// Entry is the installed ABAC check entry of profile ABAC-16 that a contract
// names: the identifier, the pinned policy version and the installed
// obligation set. The PDP endpoint, the decision path, the limits and the
// mapping revision of the entry are the adapter's [Config]. An entry never
// changes; a change is a new entry under a new identifier.
type Entry struct {
	// CheckID is the identifier the administrators chose (open item O4).
	CheckID string
	// PinnedVersion is the policy_version the contract was issued for.
	PinnedVersion string
	// Obligations is the installed obligation set. Nil means the three types
	// of ABAC-25.
	Obligations []string
}

func (e *Entry) validate() error {
	if e == nil {
		return nil
	}
	if e.CheckID == "" || e.PinnedVersion == "" {
		return errors.New("the installed ABAC check entry needs an id and a pinned policy version")
	}
	return nil
}

// installedSet returns the installed obligation set.
func (e Entry) installedSet() []string {
	if e.Obligations == nil {
		return []string{ObligationFilterFields, ObligationRedact, ObligationWatermark}
	}
	return e.Obligations
}

// gateError is an error of the gateway's use of a decision, with its draft
// 13.4 code.
type gateError struct {
	code adapter.Code
	text string
}

func (e *gateError) Error() string      { return "abac: " + e.text }
func (e *gateError) Code() adapter.Code { return e.code }

// Errors of [Gate].
var (
	// ErrRequirementsChanged is a decision of a policy version other than the
	// pinned one: the contract is no longer active; obtain a new contract
	// (draft 13.4, profile ABAC-16). It is the gateway's answer, not an error
	// kind of package adapter.
	ErrRequirementsChanged error = &gateError{code: CodeRequirementsChanged, text: "the decision is of another policy version than the contract's"}
	// ErrObligationUnsupported is an allow with an obligation type outside
	// the installed set: the allow is not used, and the response is the
	// gateway's generic denial (profile ABAC-28).
	ErrObligationUnsupported = fmt.Errorf("abac: an obligation type is outside the installed set: %w", adapter.ErrUnsupportedRequirement)
	// ErrNotPermitted is a decision other than an allow.
	ErrNotPermitted = errors.New("abac: the decision does not permit the operation")
)

// Gate is the gateway's use of a decision of [Adapter.AuthorizeNative] before
// the executor is involved (profile section 17, ABAC-28): only an allow whose
// PolicyRevision equals the entry's pinned version by exact octets, and whose
// every obligation type is in the installed set, is used. It returns
// [ErrNotPermitted], [ErrRequirementsChanged] or [ErrObligationUnsupported]
// otherwise, in that order.
func Gate(d adapter.Decision, e Entry) error {
	if !d.Permits() {
		return ErrNotPermitted
	}
	if e.PinnedVersion == "" || d.PolicyRevision != e.PinnedVersion {
		return ErrRequirementsChanged
	}
	set := e.installedSet()
	for _, o := range d.Obligations {
		if !slices.Contains(set, o.ID) {
			return ErrObligationUnsupported
		}
	}
	return nil
}

// check runs the installed ABAC check of the configured [Entry] for the
// authenticated principal and the actual operation of in: the procedure of
// [Adapter.Decide], reported as a check result by the third column of
// profile ABAC-8 and ABAC-14 (draft 17.1, 17.3.1). It never reports the
// decision: an allow and a denial with a well-formed, version-pinned,
// attributable document whose obligations are installed are both PASS. The
// device and the peer address are attributes of the principal of in. The
// check reads no agent, intent or evidence reference (ABAC-2).
func (a *Adapter) check(ctx context.Context, in adapter.CheckInput) adapter.CheckOutcome {
	p, op := in.Principal, in.Operation
	src := a.cfg.PDP.SourceID
	out := func(v adapter.Verdict, code string) adapter.CheckOutcome {
		return adapter.CheckOutcome{Result: v, ReasonCode: code, SourceID: src}
	}
	unknown := func(code adapter.Code) adapter.CheckOutcome { return out(adapter.VerdictUnknown, string(code)) }
	if a.cfg.Entry == nil {
		return unknown(adapter.CodeUnsupportedRequirement)
	}
	if live(ctx, "check") != nil {
		return unknown(adapter.CodeDependencyUnavailable)
	}
	if err := a.subjectOf(p, op); err != nil {
		code, _ := adapter.CodeOf(err)
		return unknown(code)
	}
	start := a.cfg.Clock.Now()
	f := a.readFacts(ctx, p, op, factPaths, start)
	switch worst, _ := f.worst(); worst.status {
	case factOutage:
		return unknown(adapter.CodeDependencyUnavailable)
	case factUnsupported:
		return unknown(adapter.CodeUnsupportedRequirement)
	case factStale:
		return out(adapter.VerdictFail, worst.code)
	}
	ans := a.pdp.query(ctx, input(f, op))
	res := a.checkOf(ans)
	res.SourceRef = ans.decisionID
	if ans.status != answerTransport {
		res.ObservedAt = a.cfg.Clock.Now()
	}
	return res
}

// checkOf maps a classified answer to the check result.
func (a *Adapter) checkOf(ans answer) adapter.CheckOutcome {
	out := adapter.CheckOutcome{SourceID: a.cfg.PDP.SourceID}
	set := func(v adapter.Verdict, code string) adapter.CheckOutcome {
		out.Result, out.ReasonCode = v, code
		return out
	}
	e := a.cfg.Entry
	switch ans.status {
	case answerTransport, answerUndefined, answerUnattributed:
		return set(adapter.VerdictUnknown, string(adapter.CodeDependencyUnavailable))
	case answerMalformed, answerNotObject:
		return set(adapter.VerdictUnknown, string(adapter.CodeUnsupportedRequirement))
	case answerNoVersion:
		return set(adapter.VerdictFail, CodeRequirementsChanged)
	}
	if ans.version != e.PinnedVersion {
		return set(adapter.VerdictFail, CodeRequirementsChanged)
	}
	if ans.status == answerBadDocument {
		return set(adapter.VerdictUnknown, string(adapter.CodeUnsupportedRequirement))
	}
	if ans.allow {
		for _, o := range ans.obligations {
			if !slices.Contains(e.installedSet(), o.ID) {
				return set(adapter.VerdictUnknown, string(adapter.CodeUnsupportedRequirement))
			}
		}
	}
	return set(adapter.VerdictPass, CodeRequirementSatisfied)
}
