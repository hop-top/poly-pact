package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
	score "hop.top/pact-go/reputation"
	"hop.top/pact-go/runner/evalcase"
)

// outcomesRoot is subsetRoot of the ids with every committed test key, which
// an outcomes case names in its trust records and as its snapshot key.
func outcomesRoot(t *testing.T, ids ...string) string {
	t.Helper()
	for _, e := range repoEntries(t) {
		if id := e["id"].(string); strings.HasPrefix(id, "keys/") {
			ids = append(ids, id)
		}
	}
	root := subsetRoot(t, ids...)
	for _, id := range ids {
		rel := filepath.Join("expected", filepath.FromSlash(id))
		if _, err := os.Stat(filepath.Join(repoFixtures, rel)); err == nil {
			copyTree(t, filepath.Join(repoFixtures, rel), filepath.Join(root, rel))
		}
	}
	return root
}

// outcomesCfg is fakeImplCfg for the outcomes entries alone.
func outcomesCfg(t *testing.T, mode string) Config {
	t.Helper()
	cfg := fakeImplCfg(t, mode, repoFixtures)
	cfg.Fixtures = outcomesIDs(t)
	return cfg
}

// outcomesRun runs the outcomes verb on case id of root with a command that
// prints output, and returns the result.
func outcomesRun(t *testing.T, root, id, output string) Result {
	t.Helper()
	p := filepath.Join(t.TempDir(), "out.json")
	if err := os.WriteFile(p, []byte(output), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(Config{FixturesRoot: root, Fixtures: []string{id}, OutcomesCmd: script(t, `cat `+p) + " {dir} {state}"})
	if err != nil {
		t.Fatal(err)
	}
	return result(t, rep, id)
}

func outcomesLine(t testing.TB, o outcomesResult) string {
	t.Helper()
	b, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

// TestOutcomesGoodImplPasses: the good fake implementation passes every
// committed outcomes entry, with every sub-check run.
func TestOutcomesGoodImplPasses(t *testing.T) {
	rep, err := Run(outcomesCfg(t, "good"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range rep.Fixtures {
		if r.Verb != VerbOutcomes {
			continue
		}
		n++
		if r.Status != StatusPass || len(r.Skipped) > 0 {
			t.Errorf("%s = %s %q, skipped %q; want PASS with every sub-check", r.ID, r.Status, r.Details, r.Skipped)
		}
	}
	if n != len(outcomesIDs(t)) || n != 29 {
		t.Errorf("%d outcomes results, want the 29 outcomes entries", n)
	}
}

// TestOutcomesBadModes: each bad mode of the fake implementation fails
// exactly the case it breaks, with a detail that names the defect; the
// modes within tolerance or without classifications pass.
func TestOutcomesBadModes(t *testing.T) {
	for _, m := range outcomesMutants() {
		t.Run(m.mode, func(t *testing.T) {
			rep, err := Run(outcomesCfg(t, m.mode))
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range rep.Fixtures {
				if r.Verb != VerbOutcomes {
					continue
				}
				if r.ID != m.id || m.fails == "" {
					if r.Status != StatusPass {
						t.Errorf("%s = %s %q, want PASS", r.ID, r.Status, r.Details)
					}
					continue
				}
				if r.Status != StatusFail || !detailsContain(r.Details, m.fails) {
					t.Errorf("%s = %s %q, want FAIL mentioning %q", r.ID, r.Status, r.Details, m.fails)
				}
			}
			if m.mode == "no-classifications" {
				r := result(t, rep, m.id)
				if !slices.Contains(r.Skipped, SkipQualification) {
					t.Errorf("%s skipped %q, want the qualification sub-check", m.id, r.Skipped)
				}
			}
		})
	}
}

// TestOutcomesInvocation: the command gets the absolute case directory and
// a fresh state path that does not exist yet.
func TestOutcomesInvocation(t *testing.T) {
	const id = "outcomes/qualification/correction-recompute"
	root := outcomesRoot(t, id)
	good := filepath.Join(t.TempDir(), "good.json")
	if err := os.WriteFile(good, []byte(outcomesLine(t, goodOutcomes(t, root, id))), 0o644); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(t.TempDir(), "args")
	cmd := script(t, `printf '%s\n' "$@" > `+log+`; [ -e "$2" ] && exit 9; cat `+good)
	rep, err := Run(Config{FixturesRoot: root, OutcomesCmd: cmd + " {dir} {state}"})
	if err != nil {
		t.Fatal(err)
	}
	if r := result(t, rep, id); r.Status != StatusPass {
		t.Fatalf("%+v, want PASS", r)
	}
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSpace(string(b)), "\n")
	abs, _ := filepath.Abs(filepath.Join(root, filepath.FromSlash(id)))
	if len(args) != 2 || args[0] != abs || !filepath.IsAbs(args[1]) {
		t.Errorf("args %q, want the case directory %s and a state path", args, abs)
	}
	// Without the command, the entry is SKIP.
	rep, err = Run(Config{FixturesRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if r := result(t, rep, id); r.Status != StatusSkip || !detailsContain(r.Details, "no --outcomes-cmd") {
		t.Errorf("%+v, want SKIP: no --outcomes-cmd", r)
	}
}

// TestOutcomesOutputShape: an output that is not the outcomes result object
// fails, whatever it says.
func TestOutcomesOutputShape(t *testing.T) {
	const id = "outcomes/qualification/correction-recompute"
	root := outcomesRoot(t, id)
	keys, err := evalcase.LoadKeys(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		raw  string
		edit func(o outcomesResult)
		want string
	}{
		{name: "nothing printed", raw: "", want: "no outcomes result"},
		{name: "not JSON", raw: "fine\n", want: "not the outcomes result object"},
		{name: "unknown member", edit: func(o outcomesResult) { o["acks"] = []any{} }, want: "not the outcomes result object"},
		{name: "steps missing", edit: func(o outcomesResult) { delete(o, "steps") }, want: "steps has 0 entries"},
		{name: "a step short", edit: func(o outcomesResult) { o["steps"] = o["steps"].([]any)[:3] }, want: "steps has 3 entries, want one per step of steps.json: 4"},
		{name: "a step too many", edit: func(o outcomesResult) { o["steps"] = append(o["steps"].([]any), stepAt(o, 0)) }, want: "steps has 5 entries"},
		{name: "ack beside another member", edit: func(o outcomesResult) { stepAt(o, 0)["note"] = "x" }, want: "an ingest step's entry is"},
		{name: "another pact_version", edit: func(o outcomesResult) {
			editSnapshot(t, keys, o, 1, func(p map[string]any) { p["pact_version"] = "0.2" })
		}, want: `pact_version "0.2"`},
		{name: "ack and problem", edit: func(o outcomesResult) {
			stepAt(o, 0)["problem"] = map[string]any{"type": "about:blank", "title": "x", "status": 400, "code": "INVALID_MESSAGE", "request_id": "r"}
		}, want: "step 0 (ingest execution-event-0001)"},
		{name: "ack without artifact_id", edit: func(o outcomesResult) { delete(stepAt(o, 0)["ack"].(map[string]any), "artifact_id") }, want: "ack needs"},
		{name: "ack with an unknown member", edit: func(o outcomesResult) { stepAt(o, 0)["ack"].(map[string]any)["note"] = "x" }, want: "not an Acknowledgment"},
		{name: "problem without request_id", edit: func(o outcomesResult) {
			stepAt(o, 0)["problem"] = map[string]any{"type": "about:blank", "title": "x", "status": 400, "code": "INVALID_MESSAGE", "request_id": ""}
			delete(stepAt(o, 0), "ack")
		}, want: "problem needs"},
		{name: "query answered with a problem", edit: func(o outcomesResult) {
			o["steps"].([]any)[1] = map[string]any{"problem": map[string]any{"type": "about:blank", "title": "x", "status": 403, "code": "CONTEXT_MISMATCH", "request_id": "r"}}
		}, want: "a query step's entry is"},
		{name: "snapshot without provenance", edit: func(o outcomesResult) { delete(stepAt(o, 1), "provenance") }, want: "a query step's entry is"},
		{name: "provenance member missing", edit: func(o outcomesResult) {
			delete(stepAt(o, 1)["provenance"].(map[string]any), "evidence_cutoff")
		}, want: "provenance needs"},
		{name: "unsorted provenance", edit: func(o outcomesResult) {
			m := stepAt(o, 3)["provenance"].(map[string]any)
			m["qualified_event_ids"] = []any{[]any{"https://z.example", "jti-jti-jti-jti-jti-jti-z"}, []any{"https://a.example", "jti-jti-jti-jti-jti-jti-a"}}
		}, want: "is not sorted"},
		{name: "provenance names a report not ingested", edit: func(o outcomesResult) {
			c, _ := evalcase.ReadOutcomes(root, id)
			r := c.Reports["correction-event-0002"]
			stepAt(o, 1)["provenance"].(map[string]any)["qualified_event_ids"] = []any{[]any{r.Issuer, r.JTI}}
		}, want: "which no earlier step ingested"},
		{name: "provenance lists other reports", edit: func(o outcomesResult) {
			m := stepAt(o, 3)["provenance"].(map[string]any)
			m["qualified_event_ids"], m["superseded_event_ids"] = m["superseded_event_ids"], m["qualified_event_ids"]
			editSnapshot(t, keys, o, 3, redigest(t, o, 3))
		}, want: "provenance qualified_event_ids [[https://executor.example/finance w46P9OrhZ5qRRPcgp_ErpA]], want"},
		{name: "manifest cutoff is not the value's", edit: func(o outcomesResult) {
			stepAt(o, 1)["provenance"].(map[string]any)["evidence_cutoff"] = 1792079999
			editSnapshot(t, keys, o, 1, redigest(t, o, 1))
		}, want: "provenance scoring_policy_revision and evidence_cutoff are the value's"},
		{name: "another qualification policy", edit: func(o outcomesResult) {
			stepAt(o, 1)["provenance"].(map[string]any)["qualification_policy_id"] = "other-policy"
		}, want: "qualification_policy_id other-policy"},
		{name: "counts disagree with the provenance", edit: func(o outcomesResult) {
			editSnapshot(t, keys, o, 1, func(p map[string]any) { dims(p, "task_quality")["qualified_events"] = 1 })
		}, want: "task_quality qualified_events 1, but the provenance lists 0"},
		{name: "another audience", edit: func(o outcomesResult) {
			editSnapshot(t, keys, o, 1, func(p map[string]any) { p["aud"] = "https://gateway.example/hr" })
		}, want: "want the query's"},
		{name: "another context", edit: func(o outcomesResult) {
			editSnapshot(t, keys, o, 1, func(p map[string]any) {
				p["value"].(map[string]any)["context"].(map[string]any)["action_class"] = "payment.approve"
			})
		}, want: "value.context is not the queried context"},
		{name: "another issuer", edit: func(o outcomesResult) {
			editSnapshot(t, keys, o, 1, func(p map[string]any) { p["iss"] = "https://reputation.example/other" })
		}, want: "want the reputation service's"},
		{name: "valid too long", edit: func(o outcomesResult) {
			editSnapshot(t, keys, o, 1, func(p map[string]any) { p["exp"] = 1792080000 + 301 })
		}, want: "for at most 300 seconds"},
		{name: "expired at the query", edit: func(o outcomesResult) {
			editSnapshot(t, keys, o, 1, func(p map[string]any) { p["iat"], p["nbf"], p["exp"] = 1792079000, 1792079000, 1792079100 })
		}, want: "valid at the query's time"},
		{name: "issued in the future", edit: func(o outcomesResult) {
			editSnapshot(t, keys, o, 1, func(p map[string]any) { p["iat"], p["nbf"], p["exp"] = 1792080006, 1792080006, 1792080100 })
		}, want: "after the query's time"},
		{name: "cutoff after issuance", edit: func(o outcomesResult) {
			editSnapshot(t, keys, o, 1, func(p map[string]any) { p["value"].(map[string]any)["evidence_cutoff"] = 1792080001 })
		}, want: "evidence_cutoff 1792080001 after"},
		{name: "short jti", edit: func(o outcomesResult) {
			editSnapshot(t, keys, o, 1, func(p map[string]any) { p["jti"] = "short" })
		}, want: `jti "short"`},
		{name: "other scoring pins", edit: func(o outcomesResult) {
			editSnapshot(t, keys, o, 1, func(p map[string]any) { p["value"].(map[string]any)["scoring_policy_revision"] = "other-scoring" })
		}, want: "scoring pins"},
		{name: "hold without hold_refs", edit: func(o outcomesResult) {
			editSnapshot(t, keys, o, 1, func(p map[string]any) { p["value"].(map[string]any)["security_status"] = "HOLD" })
		}, want: "HOLD exactly while hold_refs"},
		{name: "unknown snapshot member", edit: func(o outcomesResult) {
			editSnapshot(t, keys, o, 1, func(p map[string]any) { p["note"] = "x" })
		}, want: "not a ReputationSnapshot"},
		{name: "wrong typ", edit: func(o outcomesResult) {
			st := stepAt(o, 1)
			b, _ := json.Marshal(payloadMap(t, st["snapshot"].(string)))
			st["snapshot"], _ = signWith(keys, "pact-evidence+jwt", b)
		}, want: "does not verify"},
		{name: "classification of no report", edit: func(o outcomesResult) {
			o["classifications"].(map[string]any)["execution-event-0009"] = "QUALIFIED"
		}, want: "classifications names execution-event-0009"},
		{name: "classification not a qualification", edit: func(o outcomesResult) {
			o["classifications"].(map[string]any)["execution-event-0001"] = "MAYBE"
		}, want: `"MAYBE" is not QUALIFIED`},
		{name: "classification missing", edit: func(o outcomesResult) {
			delete(o["classifications"].(map[string]any), "correction-event-0002")
		}, want: "classifications has no correction-event-0002"},
		{name: "classification null for an acknowledged report", edit: func(o outcomesResult) {
			o["classifications"].(map[string]any)["correction-event-0002"] = nil
		}, want: "classifications[correction-event-0002] is null"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.raw
			if tc.edit != nil {
				o := toJSONValue(t, goodOutcomes(t, root, id)).(map[string]any)
				tc.edit(o)
				raw = outcomesLine(t, o)
			}
			r := outcomesRun(t, root, id, raw)
			if r.Status != StatusFail || !detailsContain(r.Details, tc.want) {
				t.Errorf("%s %q, want FAIL mentioning %q", r.Status, r.Details, tc.want)
			}
		})
	}
}

func signWith(keys map[string]evalcase.Key, typ string, payload []byte) (string, error) {
	k := keys["reputation-service"]
	return jws.Sign(jws.Header{Typ: typ, Kid: k.Public.Kid}, payload, k.Private)
}

// TestOutcomesRefusedInvalidReport: the receiver refuses a report that
// breaks an A.2 dimension rule, so a refusal with qualification null meets
// the expected UNQUALIFIED invalid-report; null for another expected
// UNQUALIFIED, or a refusal there, does not.
func TestOutcomesRefusedInvalidReport(t *testing.T) {
	const id = "outcomes/mapping/admission-as-task-success"
	root := outcomesRoot(t, id)
	good := goodOutcomes(t, root, id)
	if _, ok := stepAt(good, 1)["problem"]; !ok || good["classifications"].(map[string]any)["admission-event-0002"] != nil {
		t.Fatalf("the good output does not refuse the invalid report: %v", good)
	}
	if r := outcomesRun(t, root, id, outcomesLine(t, good)); r.Status != StatusPass {
		t.Fatalf("refused invalid report: %+v, want PASS", r)
	}
	acked := toJSONValue(t, good).(map[string]any)
	acked["steps"].([]any)[1] = map[string]any{"ack": map[string]any{"request_id": "a", "status": "ACCEPTED", "artifact_id": "admission-event-0002", "received_at": 1792080000}}
	acked["classifications"].(map[string]any)["admission-event-0002"] = "UNQUALIFIED"
	if r := outcomesRun(t, root, id, outcomesLine(t, acked)); r.Status != StatusPass {
		t.Errorf("acknowledged and UNQUALIFIED: %+v, want PASS", r)
	}
	acked["classifications"].(map[string]any)["admission-event-0002"] = nil
	if r := outcomesRun(t, root, id, outcomesLine(t, acked)); r.Status != StatusFail || !detailsContain(r.Details, "is null, want UNQUALIFIED") {
		t.Errorf("acknowledged and null: %+v, want FAIL", r)
	}

	const other = "outcomes/mapping/visibility-unavailable"
	root = outcomesRoot(t, other)
	o := toJSONValue(t, goodOutcomes(t, root, other)).(map[string]any)
	o["steps"].([]any)[1] = map[string]any{"problem": map[string]any{"type": "about:blank", "title": "x", "status": 400, "code": "INVALID_MESSAGE", "request_id": "r"}}
	o["classifications"].(map[string]any)["execution-event-0002"] = nil
	if r := outcomesRun(t, root, other, outcomesLine(t, o)); r.Status != StatusFail || !detailsContain(r.Details, "is null, want UNQUALIFIED (no-executor-record)") {
		t.Errorf("a refused report that is not invalid: %+v, want FAIL", r)
	}
}

// TestOutcomesIdenticalRetry: a case that submits the same signed report
// twice needs, for the second, the original acknowledgment or DUPLICATE,
// whatever its expected files say (draft Section 7.5).
func TestOutcomesIdenticalRetry(t *testing.T) {
	const id = "outcomes/qualification/duplicate-reports-same-tuple"
	root := outcomesRoot(t, id)
	dir := filepath.Join(root, filepath.FromSlash(id))
	exp := filepath.Join(root, "expected", filepath.FromSlash(id))
	b, err := os.ReadFile(filepath.Join(dir, "steps.json"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "steps.json"), strings.Replace(string(b), `"ingest":"execution-event-0002"`, `"ingest":"execution-event-0001"`, 1))
	for _, f := range []string{"acks.json", "classifications.json"} {
		if err := os.Remove(filepath.Join(exp, f)); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"reports/execution-event-0002.json", "signed/execution-event-0002.jws"} {
		if err := os.Remove(filepath.Join(dir, filepath.FromSlash(f))); err != nil {
			t.Fatal(err)
		}
	}
	var mf struct {
		Entries []entry `json:"entries"`
	}
	b, err = os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &mf); err != nil {
		t.Fatal(err)
	}
	for _, e := range mf.Entries {
		if e["id"] == id {
			e["expected"], e["outcome"] = "expected/"+id+"/snapshot.json", "MATCH"
		}
	}
	writeManifest(t, root, mf.Entries)
	c, err := evalcase.ReadOutcomes(root, id)
	if err != nil {
		t.Fatalf("the edited case: %v", err)
	}
	if c.Steps[1].Ingest != "execution-event-0001" || c.Acks != nil {
		t.Fatalf("steps %+v acks %+v", c.Steps, c.Acks)
	}
	good := goodOutcomes(t, root, id)
	if got := stepAt(good, 1)["ack"].(map[string]any)["status"]; got != "DUPLICATE" {
		t.Fatalf("the oracle answers the retry %v", got)
	}
	if r := outcomesRun(t, root, id, outcomesLine(t, good)); r.Status != StatusPass {
		t.Fatalf("%+v, want PASS", r)
	}
	bad := toJSONValue(t, good).(map[string]any)
	stepAt(bad, 1)["ack"].(map[string]any)["status"] = "ACCEPTED"
	if r := outcomesRun(t, root, id, outcomesLine(t, bad)); r.Status != StatusFail || !detailsContain(r.Details, "an identical retry of an (iss, jti) gets the original acknowledgment or DUPLICATE") {
		t.Errorf("%+v, want FAIL: identical retry", r)
	}
	// The original acknowledgment again passes too (draft Section 7.5).
	original := toJSONValue(t, good).(map[string]any)
	original["steps"].([]any)[1] = original["steps"].([]any)[0]
	if r := outcomesRun(t, root, id, outcomesLine(t, original)); r.Status != StatusPass {
		t.Errorf("the original acknowledgment: %+v, want PASS", r)
	}
	// A refused first submission does not make the retry a duplicate.
	refused := toJSONValue(t, good).(map[string]any)
	refused["steps"].([]any)[0] = map[string]any{"problem": map[string]any{"type": "about:blank", "title": "x", "status": 503, "code": "DEPENDENCY_UNAVAILABLE", "request_id": "r"}}
	stepAt(refused, 1)["ack"].(map[string]any)["status"] = "ACCEPTED"
	r := outcomesRun(t, root, id, outcomesLine(t, refused))
	if detailsContain(r.Details, "identical retry") {
		t.Errorf("%q: a retry after a refusal is no duplicate", r.Details)
	}
}

// TestOutcomesExpectedClaims: every claim snapshot.json names is in the
// snapshot payload with that value.
func TestOutcomesExpectedClaims(t *testing.T) {
	const id = "outcomes/qualification/correction-recompute"
	root := outcomesRoot(t, id)
	good := outcomesLine(t, goodOutcomes(t, root, id))
	p := filepath.Join(root, "expected", filepath.FromSlash(id), "snapshot.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, strings.Replace(string(b), `"claims":{`, `"claims":{"tenant_id":"globex",`, 1))
	if r := outcomesRun(t, root, id, good); r.Status != StatusFail || !detailsContain(r.Details, `step 1 (query): snapshot claim tenant_id is "acme", want "globex"`) {
		t.Errorf("%+v, want FAIL on the claim", r)
	}
}

// TestProvenanceAtAnySize: a printed manifest beyond the 256 KiB decode
// limit of draft Section 20.1 is judged, digest included: the manifest is
// not a wire object.
func TestProvenanceAtAnySize(t *testing.T) {
	c := &evalcase.OutcomesCase{Config: evalcase.OutcomesConfig{DataPolicy: core.DataPolicy{QualificationPolicyID: "pact-qualification-v1"}}}
	ingested := map[[2]string]core.OutcomeReport{}
	m := score.ProvenanceManifest{SupersededEventIDs: [][2]string{}, QualificationPolicyID: "pact-qualification-v1", ScoringPolicyRevision: "r", EvidenceCutoff: 1792080000}
	for i := range 5000 {
		id := [2]string{"https://executor.example/finance", fmt.Sprintf("jti-%022d", i)}
		m.QualifiedEventIDs = append(m.QualifiedEventIDs, id)
		ingested[id] = core.OutcomeReport{Dimension: core.DimensionReliability}
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= 256<<10 {
		t.Fatalf("manifest of %d bytes", len(raw))
	}
	d, err := m.Digest()
	if err != nil {
		t.Fatal(err)
	}
	snap := core.ReputationSnapshot{Value: core.ReputationValue{ProvenanceDigest: d, ScoringPolicyRevision: "r", EvidenceCutoff: 1792080000,
		Dimensions: core.ReputationDimensions{Reliability: core.DimensionStats{QualifiedEvents: 5000}}}}
	want := evalcase.ExpectedSnapshot{Provenance: evalcase.ProvenanceIDs{QualifiedEventIDs: m.QualifiedEventIDs, SupersededEventIDs: [][2]string{}}}
	if ps := provenanceProblems(c, want, snap, raw, ingested); len(ps) > 0 {
		t.Errorf("problems %q, want none", ps)
	}
	snap.Value.ProvenanceDigest = "Is5hAn87tiTQEbsbEPbL7oeEZWa74Gxmr4Xrp0SQUQ0"
	if ps := provenanceProblems(c, want, snap, raw, ingested); len(ps) != 1 || !strings.Contains(ps[0], "is not the object_digest") {
		t.Errorf("problems %q, want the digest", ps)
	}
	var big struct {
		Steps []json.RawMessage `json:"steps"`
	}
	text := []byte(`{"steps":[` + strings.Repeat(`{"provenance":`+string(raw)+`},`, 1) + `{}]}`)
	if err := strictjson.Unmarshal(text, outputLimits, &big); err != nil || len(big.Steps) != 2 {
		t.Errorf("an outcomes result over 256 KiB: %v", err)
	}
}
