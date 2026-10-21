package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// newState returns a {state} path that does not exist yet, inside a fresh
// scratch directory, and the function that removes the directory.
func newState() (state string, remove func(), err error) {
	dir, err := os.MkdirTemp("", "pactc-state-")
	if err != nil {
		return "", nil, err
	}
	return filepath.Join(dir, "state"), func() { _ = os.RemoveAll(dir) }, nil
}

// printedExchange is one exchange of a case with the lines it printed.
type printedExchange struct {
	plan  exchangePlan
	lines []string
}

// name labels the exchange in a detail.
func (p printedExchange) name() string {
	if n := p.plan.name(); n != "" {
		return n
	}
	return "the exchange"
}

// receipts returns the receipts among the response lines of the exchange,
// not among its handoff lines.
func (p printedExchange) receipts() []response {
	var out []response
	for _, l := range p.lines[:len(p.plan.responses)] {
		if r, err := parseResponse([]byte(l)); err == nil && r.attestation != nil {
			out = append(out, r)
		}
	}
	return out
}

// sequenceDiffs applies the rules that hold between the exchanges of a case
// of several exchanges, which run in order against one gateway state: each
// exchange produces its own receipt, with its own jti, and an earlier
// receipt is never reopened, amended or converted (draft 12.2). The second
// is checked by asking for each receipt of an earlier exchange again, with
// receiptCmd, once every exchange has run: the receipt printed must come
// back as it was. Without receiptCmd that sub-check is skipped, and the
// reason is returned in skipped.
func sequenceDiffs(receiptCmd, state string, xs []printedExchange) (diffs, skipped []string) {
	if len(xs) < 2 {
		return nil, nil
	}
	seen := map[string][]string{}
	var order []string
	for _, x := range xs {
		for _, r := range x.receipts() {
			jti := r.attestation.JTI
			if jti == "" {
				diffs = append(diffs, x.name()+": a receipt has no jti (draft 7.3)")
				continue
			}
			if _, ok := seen[jti]; !ok {
				order = append(order, jti)
			}
			if !slices.Contains(seen[jti], x.name()) {
				seen[jti] = append(seen[jti], x.name())
			}
		}
	}
	for _, jti := range order {
		if names := seen[jti]; len(names) > 1 {
			diffs = append(diffs, fmt.Sprintf("jti %s is carried by the receipts of %s: each exchange produces its own receipt (draft 12.2)", jti, strings.Join(names, " and ")))
		}
	}

	var earlier []printedExchange
	for _, x := range xs[:len(xs)-1] {
		if len(x.receipts()) > 0 {
			earlier = append(earlier, x)
		}
	}
	if len(earlier) == 0 {
		return diffs, nil
	}
	if strings.TrimSpace(receiptCmd) == "" {
		return diffs, []string{"receipt query of the receipts of earlier exchanges: no --receipt-cmd; not checked that they are returned unchanged (draft 12.2)"}
	}
	for _, x := range earlier {
		for _, l := range x.lines[:len(x.plan.responses)] {
			r, err := parseResponse([]byte(l))
			if err != nil || r.attestation == nil || r.attestation.JTI == "" {
				continue
			}
			diffs = append(diffs, queryDiffs(receiptCmd, state, x.name(), r)...)
		}
	}
	return diffs, nil
}

// queryDiffs asks receiptCmd for the receipt printed, by its jti, and
// reports how the answer differs from it.
func queryDiffs(receiptCmd, state, where string, printed response) []string {
	jti := printed.attestation.JTI
	res := runCmd(BuildArgv(receiptCmd, map[string]string{"state": state, "id": jti}))
	if res.Err != nil {
		return []string{fmt.Sprintf("%s: receipt query for %s: cannot run: %s", where, jti, res.summary())}
	}
	out := strings.TrimSpace(string(res.Stdout))
	if out == "" {
		return []string{fmt.Sprintf("%s: receipt query for %s: no receipt on stdout (%s)", where, jti, res.summary())}
	}
	if out == printed.compact {
		return nil
	}
	got := "not a receipt"
	if r, err := parseResponse([]byte(out)); err == nil {
		switch {
		case r.problem != nil:
			got = "Problem code " + r.problem.Code
		case r.attestation.JTI != jti:
			got = fmt.Sprintf("the receipt %s, decision %s", r.attestation.JTI, r.attestation.Decision)
		default:
			got = fmt.Sprintf("decision %s", r.attestation.Decision)
		}
	}
	return []string{fmt.Sprintf("%s: receipt query for %s returns a different response (%s; printed decision %s): a sealed receipt is never reopened, amended or converted (draft 12.2)", where, jti, got, printed.attestation.Decision)}
}
