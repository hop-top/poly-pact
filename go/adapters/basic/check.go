package basic

import (
	"context"
	"slices"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core/clock"
)

// Reason codes of check outcomes. A check reports a draft 13.4 code or a code
// of its own (draft 17.1, 17.3.1).
const (
	// CodeRequirementSatisfied is the reason of a PASS.
	CodeRequirementSatisfied = installed.CodeRequirementSatisfied
	// CodeRequirementsChanged is the reason of a check pinned to a revision
	// of its source when the source reports another (draft 13.4).
	CodeRequirementsChanged = installed.CodeRequirementsChanged
)

// CheckIDPurposeOperation is the id of the installed check of the profile.
const CheckIDPurposeOperation = "purpose-operation-v1"

// Check is the native implementation of an installed context check: it
// consults its source and gives the record it found.
type Check = installed.Check

// CheckRecord is what a [Check] found.
type CheckRecord = installed.CheckRecord

// InstalledCheck is a check as the gateway installed it.
type InstalledCheck = installed.InstalledCheck

// Freshness is a pair of age limits in seconds.
type Freshness = installed.Freshness

// CheckContext runs the installed check whose id equals checkID exactly.
//
// A check that is not installed is UNKNOWN with UNSUPPORTED_REQUIREMENT: the
// adapter did not perform it, so it cannot report that it passed (draft
// 17.2); there is no prefix or case-insensitive match. An installed check
// reports, in order: UNKNOWN with DEPENDENCY_UNAVAILABLE when its source
// cannot answer; with freshness limits, the result of the freshness profile's
// rules for the record (CLOCK_AHEAD, RESTAMPED, STALE_EVIDENCE, with the
// baseline skew and the shared guard against re-stamping), or, without them,
// DEPENDENCY_UNAVAILABLE for a source time later than now plus the skew;
// REQUIREMENTS_CHANGED when it is pinned to a revision its source no longer
// reports; and otherwise the verdict of its native state. The evidence
// references are passed to the check and never copied into the outcome.
func (a *Adapter) CheckContext(ctx context.Context, checkID string, in adapter.CheckInput) adapter.CheckOutcome {
	return installed.RunCheck(ctx, a.cfg.Checks, a.cfg.Guard, a.cfg.Clock, checkID, in)
}

// PurposeOperation returns the check purpose-operation-v1 over the installed
// purposes, each with the actions it allows (draft 10.1). The check passes
// when the declared purpose is installed and allows the action of the actual
// operation. An unrecognized purpose is FAIL with UNSUPPORTED_PURPOSE, and an
// action the purpose does not allow is FAIL with CONTEXT_MISMATCH. The
// purposes are gateway configuration, consulted at the time of the check on
// clk; sourceID names them.
func PurposeOperation(sourceID string, purposes map[string][]string, clk clock.Clock) Check {
	return purposeCheck{sourceID: sourceID, purposes: purposes, clk: clk}
}

type purposeCheck struct {
	sourceID string
	purposes map[string][]string
	clk      clock.Clock
}

func (p purposeCheck) Consult(_ context.Context, in adapter.CheckInput) (CheckRecord, error) {
	intent, op := in.Intent, in.Operation
	rec := CheckRecord{SourceID: p.sourceID, ObservedAt: p.clk.Now(), StatusCheckedAt: p.clk.Now()}
	actions, ok := p.purposes[intent.PurposeID]
	switch {
	case intent.PurposeID == "" || !ok:
		rec.Result, rec.ReasonCode = adapter.VerdictFail, string(adapter.CodeUnsupportedPurpose)
	case op.Action == "" || !slices.Contains(actions, op.Action):
		rec.Result, rec.ReasonCode = adapter.VerdictFail, string(adapter.CodeContextMismatch)
	default:
		rec.Result, rec.ReasonCode = adapter.VerdictPass, CodeRequirementSatisfied
	}
	return rec, nil
}
