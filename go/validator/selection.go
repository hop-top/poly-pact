package validator

import (
	"encoding/json"
	"slices"

	"hop.top/pact-go/core"
)

// selectionConsistency is the check selection-consistency-v1 of draft 11.3
// step 9: the contract's pinned selector re-derives the set from (i) the
// presented snapshot and (ii) the gateway's own current trusted selection
// input, with the holds in force. A set stricter than the contract's is
// FAIL with SELECTION_INPUT_CHANGED, which defers: the contract is stale.
// Equal or weaker leaves the contract's set as it is.
func (e *evaluation) selectionConsistency() outcome {
	o := e.selectionResult()
	if e.snapshotJTI != "" {
		o.evidence = []string{e.snapshotJTI}
	}
	if e.selErr == nil && e.sel.RecordRef != "" {
		ref := e.sel.RecordRef
		o.sourceRef = &ref
	}
	return o
}

func (e *evaluation) selectionResult() outcome {
	switch {
	case !slices.Contains(e.v.Config.InstalledChecks, CheckSelectionConsistency):
		return unknown(reasonUnsupported)
	case e.selErr != nil || e.holdsErr != nil:
		return unknown(reasonUnavailable)
	case e.sel.Selector == nil:
		return unknown(reasonUnsupported)
	}
	s := e.sel.Selector
	order := s.Order()
	rank := func(set string) int { return slices.Index(order, set) }
	selected := rank(e.c.Claims.SelectedSet)
	if selected < 0 {
		return unknown(reasonUnsupported)
	}
	var presented *core.ReputationValue
	if e.snapshot != nil {
		presented = &e.snapshot.Value
	}
	current := e.sel.Current
	if current == nil {
		current = presented
	}
	for _, in := range []*core.ReputationValue{presented, current} {
		set, err := s.Select(SelectionInput{Snapshot: in, Holds: slices.Clone(e.holds)})
		if err != nil {
			return unknown(reasonUnavailable)
		}
		r := rank(set)
		if r < 0 {
			return unknown(reasonUnsupported)
		}
		if r < selected {
			return fail(reasonSelectionInputChanged)
		}
	}
	return pass().at(e.v.Clock.Now())
}

func toJSONBytes(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}
