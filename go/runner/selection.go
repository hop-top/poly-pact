package runner

import (
	"fmt"
	"slices"
	"strings"

	"hop.top/pact-go/core"
	"hop.top/pact-go/runner/evalcase"
)

const (
	selectionCheck  = "selection-consistency-v1"
	reputationCheck = "reputation-context"
	// reputationTyp is the JWS typ of a reputation snapshot (draft 7.3).
	reputationTyp = "pact-reputation+jwt"
	// appendixBRecord is the record_ref of the selection record of the
	// Appendix B exchange (draft B.7): the conservative selection of an
	// exchange whose config.json names no selection (draft 9.4).
	appendixBRecord = "configured-selection-record:example-selection"
)

// selectionCase reports whether the gateway of an exchange of the case
// installs selection-consistency-v1 or performed a requirement-set selection
// (draft 9.4).
func selectionCase(plans []exchangePlan) bool {
	return slices.ContainsFunc(plans, func(p exchangePlan) bool {
		c := p.x.Config
		return c.Selection != nil || slices.Contains(c.InstalledChecks, selectionCheck)
	})
}

// selectionDiffs applies the rules of requirement-set selection that the
// expected results do not state check by check. The checks
// reputation-context and selection-consistency-v1 of every receipt name the
// presented snapshot in evidence_ids and the exchange's selection record in
// source_ref (draft A.2), whatever the case: every contract's set is
// selected and recorded (draft 9.4). And the validator's re-derivation of
// the set is deterministic (draft 11.3 step 9), so a selection case is
// evaluated a second time with the same inputs and a fresh state, and its
// decision and check results must be those of the first.
func selectionDiffs(plans []exchangePlan, printed []printedExchange, rerun func() ([]string, string)) []string {
	var diffs []string
	for _, x := range printed {
		diffs = append(diffs, snapshotAudit(x)...)
	}
	if !selectionCase(plans) {
		return diffs
	}
	second, problem := rerun()
	if problem != "" {
		return append(diffs, "second evaluation with the same inputs: "+problem)
	}
	var first []string
	for _, x := range printed {
		first = append(first, x.lines...)
	}
	return append(diffs, determinismDiffs(first, second)...)
}

// snapshotAudit checks the checks reputation-context and
// selection-consistency-v1 of the receipts of one exchange. Their source_ref
// is the record_ref of the exchange's selection record: that of config.json,
// or the Appendix B record when config.json names no selection. What the
// expected response of the exchange already pins, by evidence_ids_include
// or source_ref, is compared by checkDiffs and not reported twice.
func snapshotAudit(x printedExchange) []string {
	jti := presentedSnapshot(x.plan.x)
	record := appendixBRecord
	if sel := x.plan.x.Config.Selection; sel != nil {
		record = sel.Record.RecordRef
	}
	if len(x.plan.responses) != len(x.lines)-len(x.plan.handoff) || slices.Contains(x.plan.concurrent, true) {
		return nil
	}
	var diffs []string
	for i, want := range x.plan.responses {
		resp, err := parseResponse([]byte(x.lines[i]))
		if err != nil || resp.attestation == nil {
			continue
		}
		for _, c := range resp.attestation.Checks {
			if c.CheckID != selectionCheck && c.CheckID != reputationCheck {
				continue
			}
			pinned := pins(want, c.CheckID)
			if jti != "" && !pinned.jti && !slices.Contains(c.EvidenceIDs, jti) {
				diffs = append(diffs, fmt.Sprintf("%scheck %s: evidence_ids %q lack the presented snapshot jti %s (draft A.2)", label(x, i, len(x.plan.responses)), c.CheckID, c.EvidenceIDs, jti))
			}
			if !pinned.ref && !namesRecord(c.SourceRef, record) {
				got := "null"
				if c.SourceRef != nil {
					got = fmt.Sprintf("%q", *c.SourceRef)
				}
				diffs = append(diffs, fmt.Sprintf("%scheck %s: source_ref %s; it must identify the gateway's selection record %s (draft A.2)", label(x, i, len(x.plan.responses)), c.CheckID, got, record))
			}
		}
	}
	return diffs
}

// namesRecord reports whether a source_ref identifies the selection record
// whose record_ref is record: it is that reference exactly.
func namesRecord(ref *string, record string) bool {
	return ref != nil && *ref == record
}

// label prefixes a detail with the exchange and the response, as the
// comparison does.
func label(x printedExchange, i, n int) string {
	s := ""
	if x.plan.name() != "" {
		s = x.plan.name() + ": "
	}
	if n > 1 {
		s += fmt.Sprintf("response %d: ", i+1)
	}
	return s
}

// pinned says what an expected response states for a check.
type pinned struct{ jti, ref bool }

// pins returns what the expected response w states for the check id:
// an evidence_ids_include entry, and a source_ref.
func pins(w evalcase.Response, id string) pinned {
	var p pinned
	for _, c := range w.Checks {
		if c.CheckID == id {
			p.jti = p.jti || len(c.EvidenceIDsInclude) > 0
			p.ref = p.ref || c.SourceRef != nil
		}
	}
	return p
}

// presentedSnapshot returns the jti of the reputation snapshot the exchange
// presents: the one reputation artifact of its signing.json. It is "" when
// the exchange signs none, or more than one.
func presentedSnapshot(x *evalcase.Exchange) string {
	jti := ""
	for _, a := range x.Signing.Artifacts {
		if a.Typ != reputationTyp {
			continue
		}
		if jti != "" {
			return ""
		}
		jti = a.JTI
	}
	return jti
}

// verdict is what two evaluations of the same inputs must agree on.
type verdict struct {
	// problem is the code of a Problem, "" for a receipt.
	problem, raw string
	decision     core.Decision
	terminal     core.TerminalReason
	checks       []string
}

// verdictOf reads the verdict of one printed line. A line that is neither a
// receipt nor a Problem is its own verdict.
func verdictOf(line string) verdict {
	r, err := parseResponse([]byte(line))
	switch {
	case err != nil:
		return verdict{raw: strings.TrimSpace(line)}
	case r.problem != nil:
		return verdict{problem: r.problem.Code}
	}
	v := verdict{decision: r.attestation.Decision, terminal: r.attestation.TerminalReason}
	for _, c := range r.attestation.Checks {
		v.checks = append(v.checks, fmt.Sprintf("%s=%s/%s", c.CheckID, c.Result, c.ReasonCode))
	}
	return v
}

// differences lists how b differs from a, "" members aside.
func (a verdict) differences(b verdict) []string {
	var out []string
	switch {
	case a.raw != "" || b.raw != "":
		if a.raw != b.raw {
			out = append(out, fmt.Sprintf("line %q, then %q", a.raw, b.raw))
		}
		return out
	case a.problem != b.problem:
		return []string{fmt.Sprintf("%s, then %s", a.kind(), b.kind())}
	case a.problem != "":
		return nil
	}
	if a.decision != b.decision {
		out = append(out, fmt.Sprintf("decision %s, then %s", a.decision, b.decision))
	}
	if a.terminal != b.terminal {
		out = append(out, fmt.Sprintf("terminal_reason %s, then %s", a.terminal, b.terminal))
	}
	index := func(v verdict) map[string]string {
		m := map[string]string{}
		for _, c := range v.checks {
			id, res, _ := strings.Cut(c, "=")
			m[id] += res + ","
		}
		return m
	}
	am, bm := index(a), index(b)
	for _, c := range a.checks {
		id, _, _ := strings.Cut(c, "=")
		if am[id] != bm[id] {
			out = append(out, fmt.Sprintf("check %s %s, then %s", id, strings.TrimSuffix(am[id], ","), orNone(strings.TrimSuffix(bm[id], ","))))
			delete(am, id)
			delete(bm, id)
		}
	}
	for id, res := range bm {
		if _, ok := am[id]; !ok && res != "" {
			out = append(out, fmt.Sprintf("check %s none, then %s", id, strings.TrimSuffix(res, ",")))
		}
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func (v verdict) kind() string {
	if v.problem != "" {
		return "Problem " + v.problem
	}
	return "decision " + string(v.decision)
}

// determinismDiffs compares the lines of the second evaluation with those of
// the first, line by line.
func determinismDiffs(first, second []string) []string {
	const lead = "second evaluation with the same inputs differs from the first (draft 11.3 step 9: the same inputs yield the same result): "
	if len(first) != len(second) {
		return []string{fmt.Sprintf("%sprinted %s, then %s", lead, plural(len(first), "line"), plural(len(second), "line"))}
	}
	var diffs []string
	for i := range first {
		ds := verdictOf(first[i]).differences(verdictOf(second[i]))
		if len(ds) == 0 {
			continue
		}
		pre := ""
		if len(first) > 1 {
			pre = fmt.Sprintf("line %d: ", i+1)
		}
		diffs = append(diffs, lead+pre+strings.Join(ds, "; "))
	}
	return diffs
}

// rerunEvaluate runs the evaluate command a second time on the case
// directory dir with a fresh state, and returns the lines it printed, or why
// it printed none.
func rerunEvaluate(tmpl, dir string) (lines []string, problem string) {
	state, remove, err := newState()
	if err != nil {
		return nil, err.Error()
	}
	defer remove()
	res := runCmd(BuildArgv(tmpl, map[string]string{"dir": dir, "state": state}))
	if res.Err != nil {
		return nil, "cannot run the evaluate command: " + res.summary()
	}
	out := strings.TrimSpace(string(res.Stdout))
	if out == "" {
		return nil, "no receipt or Problem on stdout (" + res.summary() + ")"
	}
	lines = strings.Split(out, "\n")
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	return lines, ""
}
