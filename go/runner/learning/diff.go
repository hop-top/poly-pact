package learning

import (
	"fmt"
	"maps"
	"slices"

	"hop.top/pact-go/core"
	"hop.top/pact-go/runner/evalcase"
)

// Diff compares two registries and returns one detail per difference, in a
// fixed order: artifact states, the active artifact of each context,
// acknowledgments, rejections, holds and the artifacts that require
// re-evaluation. It compares the registry as README section registry.json
// defines it, and not its serialization: the artifacts are keys of the same
// kind in both (a path, or a digest), the entries of active, acknowledgments
// and rejections are matched by context or step in any order, and the reason
// codes of a rejection, the holds and the re-evaluation list are sets.
func Diff(want, got evalcase.Registry) []string {
	var d []string
	d = append(d, diffArtifacts(want.Artifacts, got.Artifacts)...)
	d = append(d, diffActive(want.Active, got.Active)...)
	d = append(d, diffAcks(want.Acknowledgments, got.Acknowledgments)...)
	d = append(d, diffRejections(want.Rejections, got.Rejections)...)
	d = append(d, diffSet("holds", want.Holds, got.Holds)...)
	d = append(d, diffSet("reevaluation_required", want.ReevaluationRequired, got.ReevaluationRequired)...)
	return d
}

func diffArtifacts(want, got map[string]core.LifecycleState) []string {
	var d []string
	for _, k := range slices.Sorted(maps.Keys(want)) {
		g, ok := got[k]
		switch {
		case !ok:
			d = append(d, fmt.Sprintf("artifacts[%s]: absent, want %s", k, want[k]))
		case g != want[k]:
			d = append(d, fmt.Sprintf("artifacts[%s]: state %s, want %s", k, g, want[k]))
		}
	}
	for _, k := range slices.Sorted(maps.Keys(got)) {
		if _, ok := want[k]; !ok {
			d = append(d, fmt.Sprintf("artifacts[%s]: unexpected artifact in state %s", k, got[k]))
		}
	}
	return d
}

func describeContext(c core.ReputationContext) string {
	return c.ActionClass + " on " + c.ResourceClass
}

func describeActive(a *string) string {
	if a == nil {
		return "the conservative set (null)"
	}
	return *a
}

func diffActive(want, got []evalcase.ActiveEntry) []string {
	index := func(es []evalcase.ActiveEntry) (map[string][]evalcase.ActiveEntry, []string) {
		m := map[string][]evalcase.ActiveEntry{}
		var keys []string
		for _, e := range es {
			k := ctxKey(e.Context)
			if _, ok := m[k]; !ok {
				keys = append(keys, k)
			}
			m[k] = append(m[k], e)
		}
		slices.Sort(keys)
		return m, keys
	}
	w, wk := index(want)
	g, gk := index(got)
	var d []string
	for _, k := range wk {
		we := w[k][0]
		ge, ok := g[k]
		switch {
		case !ok:
			d = append(d, fmt.Sprintf("active[%s]: no entry, want %s", describeContext(we.Context), describeActive(we.Artifact)))
		case len(ge) > 1:
			d = append(d, fmt.Sprintf("active[%s]: %d entries for one context", describeContext(we.Context), len(ge)))
		case (ge[0].Artifact == nil) != (we.Artifact == nil) || ge[0].Artifact != nil && *ge[0].Artifact != *we.Artifact:
			d = append(d, fmt.Sprintf("active[%s]: %s, want %s", describeContext(we.Context), describeActive(ge[0].Artifact), describeActive(we.Artifact)))
		}
	}
	for _, k := range gk {
		if _, ok := w[k]; !ok {
			d = append(d, fmt.Sprintf("active[%s]: unexpected entry, %s", describeContext(g[k][0].Context), describeActive(g[k][0].Artifact)))
		}
	}
	return d
}

func diffAcks(want, got []evalcase.AckEntry) []string {
	count := map[int]int{}
	status := map[int]core.AckStatus{}
	for _, a := range got {
		count[a.Step]++
		status[a.Step] = a.Status
	}
	steps := map[int]bool{}
	wantStatus := map[int]core.AckStatus{}
	for _, a := range want {
		steps[a.Step] = true
		wantStatus[a.Step] = a.Status
	}
	var d []string
	for _, s := range slices.Sorted(maps.Keys(steps)) {
		switch {
		case count[s] == 0:
			d = append(d, fmt.Sprintf("acknowledgments: step %d missing, want %s", s, wantStatus[s]))
		case count[s] > 1:
			d = append(d, fmt.Sprintf("acknowledgments: step %d acknowledged twice", s))
		case status[s] != wantStatus[s]:
			d = append(d, fmt.Sprintf("acknowledgments: step %d status %s, want %s", s, status[s], wantStatus[s]))
		}
	}
	for _, s := range slices.Sorted(maps.Keys(count)) {
		if !steps[s] {
			d = append(d, fmt.Sprintf("acknowledgments: step %d unexpected, acknowledged %s", s, status[s]))
		}
	}
	return d
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

func diffRejections(want, got []evalcase.RejectionEntry) []string {
	byStep := func(es []evalcase.RejectionEntry) map[int][]evalcase.RejectionEntry {
		m := map[int][]evalcase.RejectionEntry{}
		for _, e := range es {
			m[e.Step] = append(m[e.Step], e)
		}
		return m
	}
	w, g := byStep(want), byStep(got)
	var d []string
	for _, s := range slices.Sorted(maps.Keys(w)) {
		we := w[s][0]
		ge := g[s]
		switch {
		case len(ge) == 0:
			d = append(d, fmt.Sprintf("rejections: step %d missing, want %s %v", s, we.Code, sortedCopy(we.ReasonCodes)))
		case len(ge) > 1:
			d = append(d, fmt.Sprintf("rejections: step %d rejected twice", s))
		case ge[0].Code != we.Code:
			d = append(d, fmt.Sprintf("rejections: step %d code %s, want %s", s, ge[0].Code, we.Code))
		case !slices.Equal(sortedCopy(ge[0].ReasonCodes), sortedCopy(we.ReasonCodes)):
			d = append(d, fmt.Sprintf("rejections: step %d reason codes %v, want %v", s, sortedCopy(ge[0].ReasonCodes), sortedCopy(we.ReasonCodes)))
		}
	}
	for _, s := range slices.Sorted(maps.Keys(g)) {
		if _, ok := w[s]; !ok {
			d = append(d, fmt.Sprintf("rejections: step %d unexpected, rejected %s %v", s, g[s][0].Code, sortedCopy(g[s][0].ReasonCodes)))
		}
	}
	return d
}

func diffSet(name string, want, got []string) []string {
	var d []string
	for _, w := range sortedCopy(want) {
		if !slices.Contains(got, w) {
			d = append(d, fmt.Sprintf("%s: %s missing", name, w))
		}
	}
	for _, g := range sortedCopy(got) {
		if !slices.Contains(want, g) {
			d = append(d, fmt.Sprintf("%s: %s unexpected", name, g))
		}
	}
	return d
}
