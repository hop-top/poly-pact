package runner

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/runner/manifest"
)

// exchangePlan is what one exchange must print: its responses, in the order
// of exchange.json, then its handoff lines.
type exchangePlan struct {
	x          *evalcase.Exchange
	responses  []evalcase.Response
	concurrent []bool
	handoff    []evalcase.Handoff
}

// name is the exchange directory of a multi-exchange case, "" otherwise.
func (p exchangePlan) name() string { return p.x.Name }

func (p exchangePlan) lines() int { return len(p.responses) + len(p.handoff) }

// loadPlan reads the case of the entry e with package evalcase and returns
// the expected output of each exchange. A case that format v2 does not allow
// is an error naming the file.
func loadPlan(root string, e manifest.Entry) ([]exchangePlan, error) {
	c, err := evalcase.Read(root, e.ID)
	if err != nil {
		return nil, err
	}
	var plans []exchangePlan
	for _, x := range c.Exchanges {
		p := exchangePlan{x: x, responses: x.Expected.ExpectedResponses(), handoff: x.Expected.Handoff}
		for _, s := range x.Submissions {
			p.concurrent = append(p.concurrent, s.Concurrent)
		}
		if err := validExpected(x.Expected); err != nil {
			return nil, fmt.Errorf("expected file %s: %w", x.ExpectedPath, err)
		}
		plans = append(plans, p)
	}
	return plans, nil
}

// validExpected checks an expected decision.json beyond its types: the
// members of a response, and the subject pointer.
func validExpected(d evalcase.Decision) error {
	if d.Responses != nil {
		top := evalcase.Decision{TransportCode: d.TransportCode, Decision: d.Decision, Checks: d.Checks, Receipt: d.Receipt,
			Executed: d.Executed, AbsentChecks: d.AbsentChecks, RejectedBeforeCrypto: d.RejectedBeforeCrypto, Reason: d.Reason}
		if top.TransportCode != nil || top.Decision != nil || top.Checks != nil || top.Receipt != nil ||
			top.Executed != nil || top.AbsentChecks != nil || top.RejectedBeforeCrypto != nil || top.Reason != nil {
			return errors.New("names responses and also response members at the top level")
		}
	}
	for i, r := range d.ExpectedResponses() {
		if err := validResponse(r); err != nil {
			if d.Responses != nil {
				err = fmt.Errorf("responses[%d]: %w", i, err)
			}
			return err
		}
	}
	if d.Subject != nil {
		return checkSubject(*d.Subject, d.Responses != nil, len(d.ExpectedResponses()), len(d.Handoff))
	}
	return nil
}

func validResponse(r evalcase.Response) error {
	switch {
	case r.TransportCode == nil && r.Decision == nil:
		return errors.New("names neither a transport_code nor a decision")
	case r.TransportCode != nil && r.Decision != nil:
		return errors.New("names both a transport_code and a decision; a rejected request has no decision")
	case r.Decision != nil && !r.Decision.Valid():
		return fmt.Errorf("decision %q is not ADMISSIBLE, INADMISSIBLE or DEFERRED", *r.Decision)
	}
	return nil
}

// checkSubject checks the subject pointer: "" for the top level, or
// /responses/<i> or /handoff/<i> naming an expected entry.
func checkSubject(s string, responses bool, nResponses, nHandoff int) error {
	if s == "" {
		if responses {
			return errors.New(`subject "" names the top level, which holds no response beside responses`)
		}
		return nil
	}
	for _, m := range []struct {
		prefix string
		n      int
		ok     bool
	}{{"/responses/", nResponses, responses}, {"/handoff/", nHandoff, true}} {
		rest, found := strings.CutPrefix(s, m.prefix)
		if !found {
			continue
		}
		i, err := strconv.Atoi(rest)
		if err == nil && m.ok && i >= 0 && i < m.n && strconv.Itoa(i) == rest {
			return nil
		}
		break
	}
	return fmt.Errorf("subject %q names no expected response or handoff entry", s)
}

// checkEvaluate runs the evaluate command on the case directory and compares
// what it prints, one response per line, with the expected results: the
// responses of each exchange in submission order (those of a concurrent batch
// in any order), then its handoff lines. Every difference is a detail.
func checkEvaluate(root string, e manifest.Entry, tmpl, receiptCmd string, r Result) Result {
	dir, err := filepath.Abs(filepath.Join(root, filepath.FromSlash(e.Path)))
	if err != nil {
		return r.with(StatusFail, err.Error())
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return r.with(StatusFail, fmt.Sprintf("path %s is not a case directory", e.Path))
	}
	plans, err := loadPlan(root, e)
	if err != nil {
		return r.with(StatusFail, err.Error())
	}
	want := 0
	for _, p := range plans {
		want += p.lines()
	}

	state, removeState, err := newState()
	if err != nil {
		return r.with(StatusFail, err.Error())
	}
	defer removeState()
	res := runCmd(BuildArgv(tmpl, map[string]string{"dir": dir, "state": state}))
	if res.Err != nil {
		return r.with(StatusFail, "cannot run the evaluate command: "+res.summary())
	}
	out := strings.TrimSpace(string(res.Stdout))
	if out == "" {
		return r.with(StatusFail, "no receipt or Problem on stdout", res.summary())
	}
	lines := strings.Split(out, "\n")
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	if len(lines) != want {
		return r.with(StatusFail, fmt.Sprintf("printed %s, want %d: one per response and per handoff attempt (spec/v1.0/fixtures/README.md, Evaluate output)", plural(len(lines), "line"), want), res.summary())
	}
	multi := want > 1 || len(plans) > 1
	var diffs []string
	var printed []printedExchange
	for _, p := range plans {
		n, d := p.check(judge{root: root, x: p.x}, lines, multi)
		diffs = append(diffs, d...)
		printed = append(printed, printedExchange{plan: p, lines: lines[:n]})
		lines = lines[n:]
	}
	d, skipped := sequenceDiffs(receiptCmd, state, printed)
	diffs = append(diffs, d...)
	diffs = append(diffs, selectionDiffs(plans, printed, func() ([]string, string) { return rerunEvaluate(tmpl, dir) })...)
	r.Skipped = skipped
	if len(diffs) > 0 {
		return r.with(StatusFail, append(diffs, res.summary())...)
	}
	return r.with(StatusPass)
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}

// check compares the first lines with the exchange's expected responses and
// handoff results. It returns the number of lines it read and the
// differences it found; label numbers responses when the case prints more
// than one line.
func (p exchangePlan) check(j judge, lines []string, label bool) (int, []string) {
	prefix := func(kind string, i int) string {
		s := ""
		if p.name() != "" {
			s = p.name() + ": "
		}
		if label {
			s += fmt.Sprintf("%s %d: ", kind, i+1)
		}
		return s
	}
	var diffs []string
	add := func(pre string, ds []string) {
		for _, d := range ds {
			diffs = append(diffs, pre+d)
		}
	}
	k := 0
	batchDone := false
	for i := range p.responses {
		if !p.concurrent[i] {
			add(prefix("response", i), j.at(i).compareResponse(p.responses[i], lines[k]))
			k++
			continue
		}
		if batchDone {
			continue
		}
		// Every concurrent submission goes in one batch, at the place of the
		// first: its responses match the expected entries in any order.
		batchDone = true
		var batch []int
		for b := range p.responses {
			if p.concurrent[b] {
				batch = append(batch, b)
			}
		}
		add(prefix("response", i), j.matchBatch(p.responses, batch, lines[k:k+len(batch)]))
		k += len(batch)
	}
	for i, h := range p.handoff {
		if d := compareHandoff(h, lines[k]); d != "" {
			add(prefix("handoff", i), []string{d})
		}
		k++
	}
	return k, diffs
}

// judge compares printed responses with the expected results of one
// exchange of a case under the fixture directory root.
type judge struct {
	root string
	x    *evalcase.Exchange
	// sub is the submission whose response is judged; nil when unknown.
	sub *evalcase.Submission
}

// at returns the judge of the response to submission i of the exchange.
func (j judge) at(i int) judge {
	if i >= 0 && i < len(j.x.Submissions) {
		j.sub = &j.x.Submissions[i]
	}
	return j
}

// compareResponse compares one printed line with an expected response: a
// receipt that matches the expected receipt, or a Problem with the expected
// code and no receipt.
func (j judge) compareResponse(want evalcase.Response, line string) []string {
	resp, err := parseResponse([]byte(line))
	if err != nil {
		return []string{err.Error()}
	}
	if want.TransportCode != nil {
		code := *want.TransportCode
		switch {
		case resp.attestation != nil:
			return []string{fmt.Sprintf("a receipt (decision %s) for a request rejected before an authenticated evaluation; want Problem code %s and no receipt (draft 12.2)", resp.attestation.Decision, code)}
		case resp.problem.Code != code:
			return []string{fmt.Sprintf("Problem code %s, want %s", resp.problem.Code, code)}
		}
		return nil
	}
	if resp.problem != nil {
		return []string{fmt.Sprintf("no receipt: Problem code %s; want a pact-admission+jwt receipt with decision %s", resp.problem.Code, *want.Decision)}
	}
	var diffs []string
	if got := resp.attestation.Decision; got != *want.Decision {
		diffs = append(diffs, fmt.Sprintf("decision %s, want %s", got, *want.Decision))
	}
	return append(diffs, j.receiptDiffs(want, resp)...)
}

// responseKey summarizes a response by its kind: a Problem and its code, or
// a decision.
func responseKey(r evalcase.Response) string {
	if r.TransportCode != nil {
		return "Problem " + *r.TransportCode
	}
	return "decision " + string(*r.Decision)
}

// matchBatch matches the printed lines of a concurrent batch with the
// expected responses at the indexes batch, in any order. Each line must
// match an expected response in full, and each expected response one line.
func (j judge) matchBatch(want []evalcase.Response, batch []int, lines []string) []string {
	var wantKeys []string
	for _, b := range batch {
		wantKeys = append(wantKeys, responseKey(want[b]))
	}
	var gotKeys []string
	for _, line := range lines {
		resp, err := parseResponse([]byte(line))
		if err != nil {
			return []string{"concurrent batch: " + err.Error()}
		}
		k := "decision " + string(resp.decision())
		if resp.problem != nil {
			k = "Problem " + resp.problem.Code
		}
		gotKeys = append(gotKeys, k)
	}

	// diffs[l][b]: the differences of line l against expected response b.
	diffs := make([][][]string, len(lines))
	for l, line := range lines {
		diffs[l] = make([][]string, len(batch))
		for b, w := range batch {
			diffs[l][b] = j.at(w).compareResponse(want[w], line)
		}
	}
	taken := make([]bool, len(batch))
	var assign func(l int) bool
	assign = func(l int) bool {
		if l == len(lines) {
			return true
		}
		for b := range batch {
			if !taken[b] && len(diffs[l][b]) == 0 {
				taken[b] = true
				if assign(l + 1) {
					return true
				}
				taken[b] = false
			}
		}
		return false
	}
	if assign(0) {
		return nil
	}
	// No assignment: say so when the kinds of the responses differ from the
	// expected ones, then compare each line with the first expected response
	// of its kind.
	summary := fmt.Sprintf("concurrent batch: %s; want %s in any order", strings.Join(gotKeys, ", "), strings.Join(wantKeys, ", "))
	var out []string
	if !sameKinds(gotKeys, wantKeys) {
		out = append(out, summary)
	}
	for l := range lines {
		for b, w := range batch {
			if responseKey(want[w]) == gotKeys[l] {
				for _, d := range diffs[l][b] {
					out = append(out, fmt.Sprintf("concurrent batch: line %d: %s", l+1, d))
				}
				break
			}
		}
	}
	if len(out) == 0 {
		out = append(out, summary)
	}
	return out
}

// sameKinds reports whether a and b hold the same strings, in any order.
func sameKinds(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// compareHandoff compares one printed line with the expected result of a
// handoff attempt: {"handoff":"accepted"} or a Problem with the code. It
// returns "" when they agree.
func compareHandoff(want evalcase.Handoff, line string) string {
	accepted := false
	var m map[string]json.RawMessage
	if strictjson.Unmarshal([]byte(line), strictjson.Limits{}, &m) == nil {
		if v, ok := m["handoff"]; ok {
			if len(m) != 1 || string(v) != `"accepted"` {
				return `a handoff line other than {"handoff":"accepted"} or a Problem`
			}
			accepted = true
		}
	}
	if want.TransportCode == nil {
		if accepted {
			return ""
		}
		got := "neither a Problem nor a handoff line"
		if resp, err := parseResponse([]byte(line)); err == nil && resp.problem != nil {
			got = "Problem code " + resp.problem.Code
		} else if err == nil {
			got = "a receipt"
		}
		return got + `; want {"handoff":"accepted"}: the gateway accepts the attestation`
	}
	code := *want.TransportCode
	if accepted {
		return fmt.Sprintf(`{"handoff":"accepted"}; want Problem code %s`, code)
	}
	resp, err := parseResponse([]byte(line))
	switch {
	case err != nil:
		return err.Error()
	case resp.problem == nil:
		return fmt.Sprintf("a receipt; want Problem code %s", code)
	case resp.problem.Code != code:
		return fmt.Sprintf("Problem code %s, want %s", resp.problem.Code, code)
	}
	return ""
}

// decision returns the decision of the response's receipt, "" for a Problem.
func (r response) decision() core.Decision {
	if r.attestation == nil {
		return ""
	}
	return r.attestation.Decision
}
