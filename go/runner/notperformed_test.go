package runner

// A check whose native reads were still outstanding when the evaluation
// ended was not performed, so the receipt never records it PASS (draft
// 12.1; spec/v1.0/fixtures/README.md, Runner contract). The R24 cases end the
// evaluation before their native_reads_at: admission/cancelled-evaluation
// at cancelled_at 1792080010 (native_reads_at 1792080020), and
// admission/expired-authenticated-evaluation at the Section 12.2 deadline
// 1792080030, started_at 1792080000 plus 30 (native_reads_at 1792080040).
// The native field rules principal, roles and supervisor-approval read
// through read_native_claim, and the context checks other than
// native-principal-binding-v1 through check_context (Section 17.1);
// native-principal-binding-v1 is evaluated from inputs the validator holds
// (Section 17.5).

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hop.top/pact-go/runner/evalcase"
)

const (
	cancelledCase = "admission/cancelled-evaluation"
	expiredCase   = "admission/expired-authenticated-evaluation"
)

// passed sets the check to PASS REQUIREMENT_SATISFIED.
func passed(t *testing.T, id string) func(map[string]any) {
	return func(p map[string]any) {
		c := check(t, p, id)
		c["result"], c["reason_code"] = "PASS", "REQUIREMENT_SATISFIED"
	}
}

func TestEvaluateOutstandingNativeReads(t *testing.T) {
	tests := []struct {
		name, id string
		edit     func(map[string]any)
		want     Status
		subs     [][]string
	}{
		{"cancelled as printed", cancelledCase, func(map[string]any) {}, StatusPass, nil},
		{"expired as printed", expiredCase, func(map[string]any) {}, StatusPass, nil},
		{"cancelled: native field rule passed", cancelledCase, passed(t, "roles"), StatusFail, [][]string{{"check roles", "PASS", "not performed", "native_reads_at 1792080020", "1792080010", "12.1"}}},
		{"expired: native field rule passed", expiredCase, passed(t, "supervisor-approval"), StatusFail, [][]string{{"check supervisor-approval", "PASS", "native_reads_at 1792080040", "1792080030", "12.1"}}},
		{"expired: principal passed", expiredCase, passed(t, "principal"), StatusFail, [][]string{{"check principal", "PASS", "not performed"}}},
		// A listed check is judged by its expected result alone: one
		// difference, not two.
		{"listed context check passed", cancelledCase, passed(t, "security-hold-v1"), StatusFail, [][]string{{"check security-hold-v1", "result PASS", "want UNKNOWN"}, {"check security-hold-v1", "reason_code REQUIREMENT_SATISFIED", "want NOT_EVALUATED"}}},
		{"check without a native read passed", cancelledCase, passed(t, "native-principal-binding-v1"), StatusPass, nil},
		{"unperformed check left out", cancelledCase, func(p map[string]any) {
			var kept []any
			for _, c := range p["checks"].([]any) {
				if c.(map[string]any)["check_id"] != "roles" {
					kept = append(kept, c)
				}
			}
			p["checks"] = kept
		}, StatusPass, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := customRun(t, tt.id, 0, "", nil, tt.edit)
			wantDiffs(t, r, tt.want, tt.subs)
		})
	}
}

// TestEvaluateNativeReadsDeadline: the reads are outstanding when
// native_reads_at is later than the end of the evaluation: cancelled_at, or
// the Section 12.2 deadline, the earliest of the contract exp, the
// presentation exp and started_at plus limits.evaluation_seconds, at most 30
// (README, exchange.json). A receipt that passes roles is then judged by the
// rule; at the deadline the reads have completed and it is not.
func TestEvaluateNativeReadsDeadline(t *testing.T) {
	exchange := func(evaluation string) string {
		return `{"presentations":[{"signed":"signed/presentation.jws","jti":"Zxp3RCJdgrB7zJVt6LJ11w","evaluation":` + evaluation + `}]}`
	}
	tests := []struct {
		name, evaluation string
		limits           string
		want             Status
	}{
		{"reads at the deadline", `{"native_reads_at":1792080030}`, "", StatusPass},
		{"reads one second after", `{"native_reads_at":1792080031}`, "", StatusFail},
		{"evaluation_seconds above 30 is 30", `{"native_reads_at":1792080031}`, `{"evaluation_seconds":60}`, StatusFail},
		{"evaluation_seconds 10", `{"native_reads_at":1792080011}`, `{"evaluation_seconds":10}`, StatusFail},
		{"evaluation_seconds 10, reads at it", `{"native_reads_at":1792080010}`, `{"evaluation_seconds":10}`, StatusPass},
		// Started late: the contract and presentation exp, 1792080060, come
		// before started_at plus 30.
		{"exp before started_at plus 30", `{"started_at":1792080040,"native_reads_at":1792080061}`, "", StatusFail},
		{"reads at exp", `{"started_at":1792080040,"native_reads_at":1792080060}`, "", StatusPass},
		{"cancelled before the reads", `{"native_reads_at":1792080020,"cancelled_at":1792080010}`, "", StatusFail},
		{"no native_reads_at", `{}`, "", StatusPass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := subsetRoot(t, expiredCase)
			dir := filepath.Join(root, filepath.FromSlash(expiredCase))
			writeFile(t, filepath.Join(dir, "exchange.json"), exchange(tt.evaluation))
			if tt.limits != "" {
				editJSONFile(t, filepath.Join(dir, "config.json"), func(m map[string]any) { m["limits"] = rawJSON(t, tt.limits) })
			}
			keys := loadKeys(t)
			lines := readLines(t, filepath.Join(goldenDir, filepath.FromSlash(expiredCase), "evaluate.out"))
			lines[0] = mutator{keys: keys}.resign(t, lines[0], "", nil, passed(t, "roles"))
			r := runPrinted(t, root, expiredCase, lines)
			if r.Status != tt.want {
				t.Fatalf("= %+v, want %s", r, tt.want)
			}
			if tt.want == StatusFail && !detailsContain(r.Details, "check roles", "not performed") {
				t.Errorf("details %q, want one naming roles as not performed", r.Details)
			}
		})
	}
}

// wantDiffs checks the status of r and, for a failure, that its difference
// lines name subs, one entry per line, in order.
func wantDiffs(t *testing.T, r Result, want Status, subs [][]string) {
	t.Helper()
	if r.Status != want {
		t.Fatalf("= %+v, want %s", r, want)
	}
	diffs := r.Details
	if n := len(diffs); n > 0 && strings.HasPrefix(diffs[n-1], "[") {
		diffs = diffs[:n-1]
	}
	if want == StatusFail && len(diffs) != len(subs) {
		t.Fatalf("details %q, want %d difference lines", r.Details, len(subs))
	}
	for i, s := range subs {
		if !detailsContain(diffs[i:i+1], s...) {
			t.Errorf("detail %d = %q, want it to name %q", i+1, diffs[i], s)
		}
	}
}

func loadKeys(t *testing.T) map[string]evalcase.Key {
	t.Helper()
	keys, err := evalcase.LoadKeys(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func rawJSON(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// editJSONFile rewrites the JSON object file p through f.
func editJSONFile(t *testing.T, p string, f func(map[string]any)) {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	if b, err = json.Marshal(m); err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, string(b))
}

// TestEvaluateOutstandingContextCheck: a context check read through
// check_context that the expected result does not list is judged by the
// rule too.
func TestEvaluateOutstandingContextCheck(t *testing.T) {
	root := subsetRoot(t, cancelledCase)
	editExpected(t, root, cancelledCase, func(d map[string]any) { d["checks"] = []any{} })
	lines := readLines(t, filepath.Join(goldenDir, filepath.FromSlash(cancelledCase), "evaluate.out"))
	if r := runPrinted(t, root, cancelledCase, lines); r.Status != StatusPass {
		t.Fatalf("good = %+v, want PASS", r)
	}
	lines[0] = mutator{keys: loadKeys(t)}.resign(t, lines[0], "", nil, passed(t, "native-delegation-v1"))
	wantDiffs(t, runPrinted(t, root, cancelledCase, lines), StatusFail, [][]string{{"check native-delegation-v1", "PASS", "not performed", "cancelled_at"}})
}

// TestEvaluateNativeReadsDeadlineExp: the contract exp and the presentation
// exp each bound the deadline on their own. The case's signed file is
// rewritten with an earlier exp; the runner reads the payload and does not
// verify it.
func TestEvaluateNativeReadsDeadlineExp(t *testing.T) {
	setExp := func(t *testing.T, p string, exp int64) {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		seg := strings.Split(strings.TrimSpace(string(b)), ".")
		var m map[string]any
		if err := json.Unmarshal(decodePart(t, seg[1]), &m); err != nil {
			t.Fatal(err)
		}
		m["exp"] = exp
		pb, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		seg[1] = base64.RawURLEncoding.EncodeToString(pb)
		writeFile(t, p, strings.Join(seg, "."))
	}
	// started_at 1792080040: started_at plus 30 is 1792080070, both exp
	// 1792080060; one of them lowered to 1792080050, reads at 1792080055.
	for _, file := range []string{"signed/contract.jws", "signed/presentation.jws"} {
		for _, tc := range []struct {
			reads int64
			want  Status
		}{{1792080055, StatusFail}, {1792080050, StatusPass}} {
			t.Run(fmt.Sprintf("%s reads %d", file, tc.reads), func(t *testing.T) {
				root := subsetRoot(t, expiredCase)
				dir := filepath.Join(root, filepath.FromSlash(expiredCase))
				writeFile(t, filepath.Join(dir, "exchange.json"), fmt.Sprintf(`{"presentations":[{"signed":"signed/presentation.jws","jti":"Zxp3RCJdgrB7zJVt6LJ11w","evaluation":{"started_at":1792080040,"native_reads_at":%d}}]}`, tc.reads))
				setExp(t, filepath.Join(dir, filepath.FromSlash(file)), 1792080050)
				lines := readLines(t, filepath.Join(goldenDir, filepath.FromSlash(expiredCase), "evaluate.out"))
				lines[0] = mutator{keys: loadKeys(t)}.resign(t, lines[0], "", nil, passed(t, "roles"))
				r := runPrinted(t, root, expiredCase, lines)
				if r.Status != tc.want {
					t.Fatalf("= %+v, want %s", r, tc.want)
				}
				if tc.want == StatusFail && !detailsContain(r.Details, "check roles", "1792080050") {
					t.Errorf("details %q, want roles and the end 1792080050", r.Details)
				}
			})
		}
	}
}
