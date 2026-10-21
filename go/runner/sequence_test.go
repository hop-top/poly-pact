package runner

// Tests of the checks that span the exchanges of a case: the receipts of a
// multi-exchange case have distinct jti values, and a receipt that an
// earlier exchange printed is returned unchanged by the receipt query after
// the later exchanges (draft 12.2: a sealed receipt is never reopened,
// amended or converted). The approval group is the committed evidence; the
// bad implementations are the modes of testdata/fakeimpl.

import (
	"path/filepath"
	"strings"
	"testing"

	"hop.top/pact-go/runner/evalcase"
)

// approvalIDs returns the committed approval cases, all of them: the bad
// modes are run against the whole group.
func approvalIDs(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, e := range repoEntries(t) {
		if id, _ := e["id"].(string); strings.HasPrefix(id, "approval/") && kindOf(e) == "evaluate" {
			out = append(out, id)
		}
	}
	if len(out) < 13 {
		t.Fatalf("approval cases %v, want at least the 13 of the group", out)
	}
	return out
}

// receiptCfg is fakeImplCfg with the receipt query.
func receiptCfg(t *testing.T, mode, root string) Config {
	t.Helper()
	cfg := fakeImplCfg(t, mode, root)
	if cfg.ReceiptCmd == "" {
		t.Fatal("fakeImplCfg sets no ReceiptCmd")
	}
	return cfg
}

func TestApprovalGoodImplPasses(t *testing.T) {
	rep, err := Run(receiptCfg(t, "good", subsetRoot(t, approvalIDs(t)...)))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range approvalIDs(t) {
		if r := result(t, rep, id); r.Status != StatusPass || len(r.Skipped) > 0 {
			t.Errorf("%s = %+v, want PASS with nothing skipped", id, r)
		}
	}
}

// TestApprovalBadModes: each bad implementation fails the one case it
// breaks and no other, naming the difference.
func TestApprovalBadModes(t *testing.T) {
	tests := []struct {
		mode, id string
		details  [][]string
	}{
		// An undecided approval is turned into a failed one.
		{"pending-inadmissible", "approval/pending-established-request", [][]string{
			{"decision INADMISSIBLE", "want DEFERRED"},
			{"check native-approval-v1", "result FAIL", "want UNKNOWN"},
		}},
		// A statement in the conversation is honored as an approval.
		{"chat-approval-honored", "approval/chat-says-approved", [][]string{
			{"decision ADMISSIBLE", "want INADMISSIBLE"},
			{"check native-approval-v1", "result PASS", "want FAIL"},
			{"check native-approval-v1", "REQUIREMENT_SATISFIED", "MISSING_FIELD"},
		}},
		// A high reputation waives a mandatory approval.
		{"reputation-waives-approval", "approval/mandatory-survives-high-reputation", [][]string{
			{"decision ADMISSIBLE", "want DEFERRED"},
			{"check native-approval-v1", "result PASS", "want UNKNOWN"},
			{"check native-approval-v1", "REQUIREMENT_SATISFIED", "APPROVAL_PENDING"},
		}},
		// The fresh evaluation carries the jti of the earlier receipt.
		{"reused-jti", "approval/approved-fresh-exchange", [][]string{
			{"jti", "exchanges/1", "exchanges/2", "draft 12.2"},
		}},
		// The query for the first receipt returns the converted one.
		{"reopen-first-receipt", "approval/approved-fresh-exchange", [][]string{
			{"exchanges/1", "receipt query", "different", "DEFERRED", "ADMISSIBLE", "draft 12.2"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			rep, err := Run(receiptCfg(t, tt.mode, subsetRoot(t, approvalIDs(t)...)))
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range approvalIDs(t) {
				r := result(t, rep, id)
				if id != tt.id {
					if r.Status != StatusPass {
						t.Errorf("%s = %+v, want PASS: the mode does not touch it", id, r)
					}
					continue
				}
				if r.Status != StatusFail {
					t.Fatalf("%s = %+v, want FAIL", id, r)
				}
				diffs := r.Details
				if n := len(diffs); n > 0 && strings.HasPrefix(diffs[n-1], "[") {
					diffs = diffs[:n-1]
				}
				if len(diffs) != len(tt.details) {
					t.Fatalf("%s details %q, want %d difference lines", id, r.Details, len(tt.details))
				}
				for i, subs := range tt.details {
					if !detailsContain(diffs[i:i+1], subs...) {
						t.Errorf("%s detail %d = %q, want it to name %q", id, i+1, diffs[i], subs)
					}
				}
			}
		})
	}
}

// TestReceiptQueryIsOptional: without a receipt command the case still
// passes, and the sub-check is reported as skipped with its reason. A case
// of one exchange has no earlier receipt to query.
func TestReceiptQueryIsOptional(t *testing.T) {
	cfg := receiptCfg(t, "good", subsetRoot(t, approvalIDs(t)...))
	cfg.ReceiptCmd = ""
	rep, err := Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range approvalIDs(t) {
		r := result(t, rep, id)
		if r.Status != StatusPass {
			t.Errorf("%s = %+v, want PASS", id, r)
		}
		multi := strings.HasSuffix(id, "approved-fresh-exchange") || strings.HasSuffix(id, "exception-recognized-natively")
		switch {
		case multi && !detailsContain(r.Skipped, "receipt query", "--receipt-cmd"):
			t.Errorf("%s skipped %q, want the receipt query skipped for want of --receipt-cmd", id, r.Skipped)
		case !multi && len(r.Skipped) > 0:
			t.Errorf("%s skipped %q, want nothing", id, r.Skipped)
		}
	}
	// A bad receipt query is not seen without the command, and the case
	// that it breaks passes with its sub-check skipped.
	t.Setenv("FAKEIMPL_MODE", "reopen-first-receipt")
	rep, err = Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if r := result(t, rep, "approval/approved-fresh-exchange"); r.Status != StatusPass || len(r.Skipped) == 0 {
		t.Errorf("= %+v, want PASS with the receipt query skipped", r)
	}
}

// TestReceiptQueryFailures: a receipt query that cannot be run, prints
// nothing or prints another receipt is a FAIL naming the exchange.
func TestReceiptQueryFailures(t *testing.T) {
	const id = "approval/approved-fresh-exchange"
	tests := []struct {
		name, body string
		subs       []string
	}{
		{"exits without output", `exit 3`, []string{"exchanges/1", "receipt query", "no receipt", "exited 3"}},
		{"prints a Problem", `echo '{"type":"about:blank","title":"Not found","status":404,"code":"NOT_FOUND","request_id":"r"}'`, []string{"exchanges/1", "receipt query", "different"}},
		{"cannot be started", ``, []string{"exchanges/1", "receipt query", "cannot run"}},
		{"prints a receipt of another exchange", `sed -n 2p "$1/receipts"`, []string{"exchanges/1", "receipt query", "different"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := receiptCfg(t, "good", subsetRoot(t, id))
			cfg.ReceiptCmd = script(t, tt.body) + " {state} {id}"
			if tt.body == "" {
				cfg.ReceiptCmd = filepath.Join(t.TempDir(), "no-such-tool") + " {state} {id}"
			}
			rep, err := Run(cfg)
			if err != nil {
				t.Fatal(err)
			}
			r := result(t, rep, id)
			if r.Status != StatusFail || !detailsContain(r.Details, tt.subs...) {
				t.Errorf("= %+v, want FAIL naming %q", r, tt.subs)
			}
		})
	}
}

// TestSequenceReceiptIDs: the receipts of a multi-exchange case have
// distinct jti values, each exchange's receipt being its own (draft 12.2). A
// receipt without a jti is no receipt of a sequence either. The receipts of a
// case of one exchange, such as a concurrent batch, are not compared.
func TestSequenceReceiptIDs(t *testing.T) {
	const id = "approval/approved-fresh-exchange"
	keys, err := evalcase.LoadKeys(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	m := mutator{keys: keys}
	good := readLines(t, filepath.Join(goldenDir, filepath.FromSlash(id), "evaluate.out"))
	_, first := decodeJWS(t, good[0])
	root := subsetRoot(t, id)
	tests := []struct {
		name  string
		lines []string
		want  Status
		subs  []string
	}{
		{"as printed", good, StatusPass, nil},
		{"jti of the first receipt reused", []string{good[0], m.resign(t, good[1], "", nil, set("jti", first["jti"]))}, StatusFail, []string{"jti " + first["jti"].(string), "exchanges/1", "exchanges/2"}},
		{"second receipt without a jti", []string{good[0], m.resign(t, good[1], "", nil, func(p map[string]any) { delete(p, "jti") })}, StatusFail, []string{"jti", "exchanges/2"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runPrinted(t, root, id, tt.lines)
			if r.Status != tt.want || (tt.subs != nil && !detailsContain(r.Details, tt.subs...)) {
				t.Errorf("= %+v, want %s naming %q", r, tt.want, tt.subs)
			}
		})
	}
}

// TestReceiptQueryAmendedInPlace: the answer must be the receipt printed,
// byte for byte, not only a receipt with the same jti: a receipt converted in
// place keeps its jti and changes its decision.
func TestReceiptQueryAmendedInPlace(t *testing.T) {
	const id = "approval/approved-fresh-exchange"
	keys, err := evalcase.LoadKeys(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	good := readLines(t, filepath.Join(goldenDir, filepath.FromSlash(id), "evaluate.out"))
	converted := mutator{keys: keys}.resign(t, good[0], "", nil, set("decision", "ADMISSIBLE"))
	answer := filepath.Join(t.TempDir(), "answer")
	writeFile(t, answer, converted+"\n")
	cfg := receiptCfg(t, "good", subsetRoot(t, id))
	cfg.ReceiptCmd = script(t, `cat "`+answer+`"`) + " {state} {id}"
	rep, err := Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := result(t, rep, id)
	if r.Status != StatusFail || !detailsContain(r.Details, "exchanges/1", "receipt query", "different", "decision ADMISSIBLE", "printed decision DEFERRED") {
		t.Errorf("= %+v, want FAIL naming the converted decision", r)
	}
	// The same receipt, written with a trailing newline or none, is the same.
	writeFile(t, answer, good[0])
	rep, err = Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if r := result(t, rep, id); r.Status != StatusPass {
		t.Errorf("unchanged receipt = %+v, want PASS", r)
	}
}
