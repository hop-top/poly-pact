package installed

import (
	"context"
	"fmt"
	"slices"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// Reason codes of check outcomes. A check reports a draft 13.4 code or a code
// of its own (draft 17.1, 17.3.1).
const (
	// CodeRequirementSatisfied is the reason of a PASS.
	CodeRequirementSatisfied = "REQUIREMENT_SATISFIED"
	// CodeRequirementsChanged is the reason of a check pinned to a revision
	// of its source when the source reports another (draft 13.4).
	CodeRequirementsChanged = "REQUIREMENTS_CHANGED"
)

// Check is the native implementation of an installed context check: it
// consults its source and gives the record it found.
type Check interface {
	// Consult returns the verdict of the check's native state for the
	// authenticated principal, the agent binding, the intent, the operation
	// and the evidence references of in, with the source record it consulted.
	// An error means the source could not answer; the record may still name
	// the source.
	Consult(ctx context.Context, in adapter.CheckInput) (CheckRecord, error)
}

// CheckRecord is what a [Check] found.
type CheckRecord struct {
	Result     adapter.Verdict
	ReasonCode string
	SourceID   string
	SourceRef  string
	// ObservedAt and StatusCheckedAt are the times of the consulted record;
	// zero when the source gives none.
	ObservedAt      time.Time
	StatusCheckedAt time.Time
	// Revision is the revision of the source's policy that the record was
	// read under; empty when the source reports none.
	Revision string
}

// InstalledCheck is a check as the gateway installed it.
type InstalledCheck struct {
	Check Check
	// Freshness, when set, holds the age limits the check requires of the
	// record it consults (draft 9.2).
	Freshness *Freshness
	// PinnedRevision, when set, is the revision of the source the check is
	// pinned to.
	PinnedRevision string
}

// Freshness is a pair of age limits in seconds.
type Freshness struct {
	MaxAgeSeconds       int64
	StatusMaxAgeSeconds int64
}

// ValidateChecks refuses an installed check without an id or an
// implementation and one with a negative age limit.
func ValidateChecks(checks map[string]InstalledCheck) error {
	for id, c := range checks {
		if id == "" || c.Check == nil {
			return fmt.Errorf("installed check %q has no id or no implementation", id)
		}
		if f := c.Freshness; f != nil && (f.MaxAgeSeconds < 0 || f.StatusMaxAgeSeconds < 0) {
			return fmt.Errorf("installed check %q has a negative age limit", id)
		}
	}
	return nil
}

// RunCheck runs the check of checks whose id equals checkID exactly, at the
// instant clk gives, with the guard against re-stamping guard.
//
// A check that is not installed is UNKNOWN with UNSUPPORTED_REQUIREMENT: the
// adapter did not perform it, so it cannot report that it passed (draft
// 17.2); there is no prefix or case-insensitive match. An installed check
// reports, in order: UNKNOWN with DEPENDENCY_UNAVAILABLE when its source
// cannot answer; with freshness limits, the result of the freshness profile's
// rules for the record (CLOCK_AHEAD, RESTAMPED, STALE_EVIDENCE, with the
// baseline skew and the shared guard), or, without them,
// DEPENDENCY_UNAVAILABLE for a source time later than now plus the skew;
// REQUIREMENTS_CHANGED when it is pinned to a revision its source no longer
// reports; and otherwise the verdict of its native state. The evidence
// references are passed to the check and never copied into the outcome. The
// principal and the binding are passed as the validator established them.
func RunCheck(ctx context.Context, checks map[string]InstalledCheck, guard *freshness.Monotonic, clk clock.Clock, checkID string, in adapter.CheckInput) adapter.CheckOutcome {
	unknown := func(code adapter.Code, source string) adapter.CheckOutcome {
		return adapter.CheckOutcome{Result: adapter.VerdictUnknown, ReasonCode: string(code), SourceID: source}
	}
	if Live(ctx) != nil {
		return unknown(adapter.CodeDependencyUnavailable, "")
	}
	ic, ok := checks[checkID]
	if !ok {
		return unknown(adapter.CodeUnsupportedRequirement, "")
	}
	in.EvidenceRefs = slices.Clone(in.EvidenceRefs)
	rec, err := ic.Check.Consult(ctx, in)
	if err != nil {
		return unknown(adapter.CodeDependencyUnavailable, rec.SourceID)
	}
	out := adapter.CheckOutcome{SourceID: rec.SourceID, SourceRef: rec.SourceRef}
	if f := ic.Freshness; f != nil {
		rule := core.FieldRule{MaxAgeSeconds: f.MaxAgeSeconds, StatusMaxAgeSeconds: f.StatusMaxAgeSeconds}
		claim := adapter.NativeClaim{ObservedAt: rec.ObservedAt, StatusCheckedAt: rec.StatusCheckedAt, SourceID: rec.SourceID, SourceRef: rec.SourceRef}
		ev := freshness.Evaluator{Skew: clock.BaselineSkew, Guard: guard}
		result, code := ev.Evaluate(rule, claim, clk.Now())
		switch {
		case code == freshness.ClockAhead:
			out.Result, out.ReasonCode = adapter.VerdictFail, string(code)
			return out
		case result != core.CheckPass:
			out.Result, out.ReasonCode, out.ObservedAt = verdictOf(result), string(code), rec.ObservedAt
			return out
		}
	} else if SourceTimes(clk.Now(), rec.ObservedAt, rec.StatusCheckedAt) != nil {
		return unknown(adapter.CodeDependencyUnavailable, rec.SourceID)
	}
	out.ObservedAt = rec.ObservedAt
	if ic.PinnedRevision != "" && rec.Revision != ic.PinnedRevision {
		out.Result, out.ReasonCode = adapter.VerdictFail, CodeRequirementsChanged
		return out
	}
	if !rec.Result.Valid() || rec.ReasonCode == "" {
		return unknown(adapter.CodeDependencyUnavailable, rec.SourceID)
	}
	out.Result, out.ReasonCode = rec.Result, rec.ReasonCode
	return out
}

// verdictOf maps a check status to the verdict of the same name; anything
// but PASS and FAIL established nothing, so it is UNKNOWN.
func verdictOf(s core.CheckStatus) adapter.Verdict {
	switch s {
	case core.CheckPass:
		return adapter.VerdictPass
	case core.CheckFail:
		return adapter.VerdictFail
	}
	return adapter.VerdictUnknown
}
