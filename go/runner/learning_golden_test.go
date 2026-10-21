package runner

// The goldens of the fake implementation for the learning verb. The good
// golden of a case is the registry state that the case's expected
// registry.json describes, written in the format of the learning command's
// output (spec/v1.0/fixtures/README.md, section Learning output); each bad mode
// is that state with one defect. This file states every defect as code.
// TestLearningGoldens checks the committed files against it, so a golden
// cannot drift from the case or from the defect it is named for; `go test
// -run TestLearningGoldens -update-learning` writes them again.

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/runner/evalcase"
)

var updateLearning = flag.Bool("update-learning", false, "write the learning goldens of testdata/fakeimpl again")

// out is a learning command's output as a generic JSON value, so that a
// mutant can break it in ways the typed form cannot express.
type out = map[string]any

// payloadOf decodes the payload of a compact JWS.
func payloadOf(t testing.TB, compact string) map[string]any {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %.40s", compact)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// artifactDigests maps the signed file of each step to its artifact_digest.
func artifactDigests(t testing.TB, c *evalcase.LearningCase) map[string]string {
	t.Helper()
	m := map[string]string{}
	for p, compact := range c.Signed {
		d, err := digest.ArtifactDigest(compact)
		if err != nil {
			t.Fatal(err)
		}
		m[p] = string(d)
	}
	return m
}

var problemStatus = map[string]int{
	"INVALID_MESSAGE": 400, "INVALID_PROOF": 401, "CONTEXT_MISMATCH": 403, "EXPIRED": 410, "ID_CONFLICT": 409, "LEARNING_REJECTED": 409,
}

// goodOutput is the output of a conforming implementation for the case,
// computed from its expected registry.json and its signed files.
func goodOutput(t testing.TB, c *evalcase.LearningCase) out {
	t.Helper()
	dig := artifactDigests(t, c)
	exp := c.Expected
	o := out{"artifacts": map[string]any{}, "holds": toAny(exp.Holds), "reevaluation_required": []any{}}
	for p, st := range exp.Artifacts {
		o["artifacts"].(map[string]any)[dig[p]] = string(st)
	}
	act := []any{}
	for _, a := range exp.Active {
		var ref any
		if a.Artifact != nil {
			ref = dig[*a.Artifact]
		}
		act = append(act, map[string]any{"context": ctxMap(t, a.Context), "artifact": ref})
	}
	o["active"] = act
	re := []any{}
	for _, p := range exp.ReevaluationRequired {
		re = append(re, dig[p])
	}
	o["reevaluation_required"] = re
	acks := []any{}
	for _, a := range exp.Acknowledgments {
		s := c.Steps[a.Step]
		p := payloadOf(t, c.Signed[s.File])
		id := ""
		switch s.Kind {
		case evalcase.StepArtifact:
			id, _ = p["artifact_id"].(string)
		case evalcase.StepEvent:
			id, _ = p["sub"].(string)
		default:
			id, _ = p["event_id"].(string)
		}
		acks = append(acks, map[string]any{"step": a.Step, "status": string(a.Status), "ack": map[string]any{
			"request_id": fmt.Sprintf("ack-%d", a.Step), "status": string(a.Status), "artifact_id": id, "received_at": s.ReceivedAt,
		}})
	}
	o["acknowledgments"] = acks
	rej := []any{}
	for _, r := range exp.Rejections {
		problem := map[string]any{
			"type": "about:blank", "title": r.Code, "status": problemStatus[r.Code], "code": r.Code, "request_id": fmt.Sprintf("rej-%d", r.Step),
		}
		if len(r.ReasonCodes) > 0 {
			problem["extensions"] = map[string]any{"reason_codes": toAny(r.ReasonCodes)}
		}
		rej = append(rej, map[string]any{"step": r.Step, "code": r.Code, "reason_codes": toAny(r.ReasonCodes), "problem": problem})
	}
	o["rejections"] = rej
	return o
}

func toAny(s []string) []any {
	out := []any{}
	for _, v := range s {
		out = append(out, v)
	}
	return out
}

func ctxMap(t testing.TB, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// learningMutant is a defect of the fake implementation: the good output of
// the case id with edit applied. detail is a part of the FAIL detail that
// names the defect.
type learningMutant struct {
	id, mode string
	edit     func(t testing.TB, c *evalcase.LearningCase, o out)
	detail   []string
}

func list(o out, key string) []any { return o[key].([]any) }

// entryAt returns the index and the entry of the step in the array key of a
// decoded output.
func entryAt(o out, key string, step int) (int, map[string]any) {
	for i, e := range list(o, key) {
		if e := e.(map[string]any); int(e["step"].(float64)) == step {
			return i, e
		}
	}
	return -1, nil
}

func drop(o out, key string, i int) { o[key] = slices.Delete(list(o, key), i, i+1) }

// accept turns the rejection of a step into an acknowledgment ACCEPTED, as an
// implementation that applies the message would answer.
func accept(t testing.TB, c *evalcase.LearningCase, o out, step int) {
	t.Helper()
	i, _ := entryAt(o, "rejections", step)
	if i < 0 {
		t.Fatalf("step %d is not rejected", step)
	}
	drop(o, "rejections", i)
	s := c.Steps[step]
	p := payloadOf(t, c.Signed[s.File])
	id, _ := p["artifact_id"].(string)
	if s.Kind == evalcase.StepEvent {
		id, _ = p["sub"].(string)
	}
	o["acknowledgments"] = append(list(o, "acknowledgments"), map[string]any{"step": step, "status": "ACCEPTED", "ack": map[string]any{
		"request_id": fmt.Sprintf("ack-%d", step), "status": "ACCEPTED", "artifact_id": id, "received_at": s.ReceivedAt,
	}})
}

func setState(o out, dig, state string) { o["artifacts"].(map[string]any)[dig] = state }

func setActive(o out, ctxIndex int, ref any) {
	list(o, "active")[ctxIndex].(map[string]any)["artifact"] = ref
}

func learningMutants() []learningMutant {
	d := func(t testing.TB, c *evalcase.LearningCase, name string) string {
		return artifactDigests(t, c)["signed/artifacts/"+name+".jws"]
	}
	return []learningMutant{
		// The promotion is applied but the artifact stays in SHADOW.
		{id: "learning/happy-path", mode: "wrong-state", edit: func(t testing.TB, c *evalcase.LearningCase, o out) {
			setState(o, d(t, c, "baseline-v1"), "SHADOW")
		}, detail: []string{"artifacts[signed/artifacts/baseline-v1.jws]", "SHADOW", "ACTIVE"}},
		// The artifact is ACTIVE but the context still runs the conservative set.
		{id: "learning/happy-path", mode: "context-not-activated", edit: func(t testing.TB, c *evalcase.LearningCase, o out) {
			setActive(o, 0, nil)
		}, detail: []string{"active[invoice.read on department-finance-invoice]", "conservative", "signed/artifacts/baseline-v1.jws"}},
		// A shadow phase of one hour satisfies minimum_shadow_seconds.
		{id: "learning/gate-not-met", mode: "accepts-gate-not-met", edit: func(t testing.TB, c *evalcase.LearningCase, o out) {
			accept(t, c, o, 4)
		}, detail: []string{"acknowledgments: step 4 unexpected", "rejections: step 4 missing", "GATE_NOT_MET"}},
		// The rejection carries the wrong reason code.
		{id: "learning/gate-not-met", mode: "wrong-reason-code", edit: func(t testing.TB, c *evalcase.LearningCase, o out) {
			_, e := entryAt(o, "rejections", 4)
			e["reason_codes"] = []any{"POLICY_EXPIRED"}
			e["problem"].(map[string]any)["extensions"] = map[string]any{"reason_codes": []any{"POLICY_EXPIRED"}}
		}, detail: []string{"rejections: step 4 reason codes [POLICY_EXPIRED]", "[GATE_NOT_MET]"}},
		// The controller's own evaluation is accepted as independent evidence.
		{id: "learning/candidate-self-evaluated", mode: "accepts-self-evaluated", edit: func(t testing.TB, c *evalcase.LearningCase, o out) {
			accept(t, c, o, 2)
			setState(o, d(t, c, "baseline-v1"), "EVALUATED")
		}, detail: []string{"artifacts[signed/artifacts/baseline-v1.jws]", "EVALUATED", "CANDIDATE", "SELF_EVALUATED"}},
		// Both controllers promote from the same previous version: the second
		// promotion is applied and replaces the first in the context.
		{id: "learning/concurrent-promotion-conflict", mode: "accepts-concurrent-promotion", edit: func(t testing.TB, c *evalcase.LearningCase, o out) {
			accept(t, c, o, 8)
			setState(o, d(t, c, "baseline-replica-v1"), "ACTIVE")
			setActive(o, 0, d(t, c, "baseline-replica-v1"))
		}, detail: []string{"rejections: step 8 missing", "VERSION_CONFLICT", "artifacts[signed/artifacts/baseline-replica-v1.jws]", "active[invoice.read on department-finance-invoice]"}},
		// A re-registered identical manifest is registered again.
		{id: "learning/mutated-accepted-manifest", mode: "duplicate-as-new", edit: func(t testing.TB, c *evalcase.LearningCase, o out) {
			_, e := entryAt(o, "acknowledgments", 2)
			e["status"] = "ACCEPTED"
			e["ack"].(map[string]any)["status"] = "ACCEPTED"
		}, detail: []string{"acknowledgments: step 2 status ACCEPTED", "DUPLICATE"}},
		// A second manifest under the same artifact_id and version replaces the first.
		{id: "learning/mutated-accepted-manifest", mode: "accepts-mutated-manifest", edit: func(t testing.TB, c *evalcase.LearningCase, o out) {
			accept(t, c, o, 3)
		}, detail: []string{"acknowledgments: step 3 unexpected", "rejections: step 3 missing", "ID_CONFLICT"}},
		// ID_CONFLICT is answered as a generic rejection.
		{id: "learning/mutated-accepted-manifest", mode: "wrong-conflict-code", edit: func(t testing.TB, c *evalcase.LearningCase, o out) {
			_, e := entryAt(o, "rejections", 3)
			e["code"] = "LEARNING_REJECTED"
			e["problem"].(map[string]any)["code"] = "LEARNING_REJECTED"
		}, detail: []string{"rejections: step 3 code LEARNING_REJECTED", "ID_CONFLICT"}},
		// An expired policy still authorizes promotion.
		{id: "learning/expired-policy", mode: "accepts-expired-policy", edit: func(t testing.TB, c *evalcase.LearningCase, o out) {
			accept(t, c, o, 8)
			setState(o, d(t, c, "summary-baseline-v1"), "ACTIVE")
			setActive(o, 1, d(t, c, "summary-baseline-v1"))
		}, detail: []string{"rejections: step 8 missing", "POLICY_EXPIRED"}},
		// After expiry nothing is accepted, not even a freeze.
		{id: "learning/expired-policy", mode: "refuses-freeze-after-expiry", edit: func(t testing.TB, c *evalcase.LearningCase, o out) {
			i, _ := entryAt(o, "acknowledgments", 9)
			drop(o, "acknowledgments", i)
			o["rejections"] = append(list(o, "rejections"), map[string]any{"step": 9, "code": "LEARNING_REJECTED", "reason_codes": []any{"POLICY_EXPIRED"}, "problem": map[string]any{
				"type": "about:blank", "title": "x", "status": 409, "code": "LEARNING_REJECTED", "request_id": "r9", "extensions": map[string]any{"reason_codes": []any{"POLICY_EXPIRED"}}}})
			setState(o, d(t, c, "baseline-v1"), "ACTIVE")
			setActive(o, 0, d(t, c, "baseline-v1"))
		}, detail: []string{"acknowledgments: step 9 missing", "rejections: step 9 unexpected"}},
		// A rollback to an artifact of another base revision is applied.
		{id: "learning/incompatible-fallback", mode: "accepts-incompatible-fallback", edit: func(t testing.TB, c *evalcase.LearningCase, o out) {
			accept(t, c, o, 8)
			setState(o, d(t, c, "baseline-base2-v1"), "ACTIVE")
			setActive(o, 0, d(t, c, "baseline-base2-v1"))
		}, detail: []string{"rejections: step 8 missing", "FALLBACK_INCOMPATIBLE"}},
		// A rollback erases the security hold.
		{id: "learning/rollback-preserves-hold", mode: "rollback-clears-hold", edit: func(t testing.TB, c *evalcase.LearningCase, o out) {
			o["holds"] = []any{}
		}, detail: []string{"holds: security-event-0001 missing"}},
		// A correction does not flag the shadowed artifact.
		{id: "learning/correction-triggers-recompute", mode: "no-reevaluation", edit: func(t testing.TB, c *evalcase.LearningCase, o out) {
			o["reevaluation_required"] = []any{}
		}, detail: []string{"reevaluation_required: signed/artifacts/baseline-v1.jws missing"}},
		// A correction resets the artifact to CANDIDATE instead of flagging it.
		{id: "learning/correction-triggers-recompute", mode: "correction-resets-state", edit: func(t testing.TB, c *evalcase.LearningCase, o out) {
			o["reevaluation_required"] = []any{}
			setState(o, d(t, c, "baseline-v1"), "CANDIDATE")
		}, detail: []string{"artifacts[signed/artifacts/baseline-v1.jws]", "CANDIDATE", "SHADOW"}},
		// A policy without a release gate is installed.
		{id: "learning/missing-gate", mode: "installs-policy-without-gate", edit: func(t testing.TB, c *evalcase.LearningCase, o out) {
			o["rejections"] = []any{}
		}, detail: []string{"rejections: step 0 missing", "INVALID_MESSAGE"}},
		// A manifest with a control outside adaptive_fields is registered.
		{id: "learning/out-of-envelope-change", mode: "accepts-out-of-envelope", edit: func(t testing.TB, c *evalcase.LearningCase, o out) {
			accept(t, c, o, 1)
			setState(o, d(t, c, "baseline-v1"), "CANDIDATE")
			intended := payloadOf(t, c.Signed["signed/artifacts/baseline-v1.jws"])["intended_contexts"].([]any)
			o["active"] = append(list(o, "active"), map[string]any{"context": intended[0], "artifact": nil})
		}, detail: []string{"rejections: step 1 missing", "CONTROL_NOT_ADAPTIVE"}},
		// Observe mode lets a controller activate.
		{id: "learning/observe-mode-no-activation", mode: "observe-activates", edit: func(t testing.TB, c *evalcase.LearningCase, o out) {
			accept(t, c, o, 4)
			setState(o, d(t, c, "baseline-v1"), "ACTIVE")
			setActive(o, 0, d(t, c, "baseline-v1"))
		}, detail: []string{"rejections: step 4 missing", "OBSERVE_MODE"}},
		// The assessment's instruction is followed.
		{id: "learning/llm-assessment-injection", mode: "obeys-assessment", edit: func(t testing.TB, c *evalcase.LearningCase, o out) {
			setState(o, d(t, c, "baseline-v1"), "ACTIVE")
			setActive(o, 0, d(t, c, "baseline-v1"))
		}, detail: []string{"artifacts[signed/artifacts/baseline-v1.jws]", "ACTIVE", "EVALUATED"}},
		// A frozen artifact goes straight back to SHADOW and a retired one stays in force.
		{id: "learning/retirement-and-reactivation", mode: "retired-stays-active", edit: func(t testing.TB, c *evalcase.LearningCase, o out) {
			setState(o, d(t, c, "baseline-a-v1"), "ACTIVE")
			setActive(o, 1, d(t, c, "baseline-a-v1"))
		}, detail: []string{"artifacts[signed/artifacts/baseline-a-v1.jws]", "ACTIVE", "RETIRED", "active[invoice.read on department-finance-ledger]"}},
		{id: "learning/retirement-and-reactivation", mode: "frozen-cannot-reevaluate", edit: func(t testing.TB, c *evalcase.LearningCase, o out) {
			i, _ := entryAt(o, "acknowledgments", 30)
			drop(o, "acknowledgments", i)
			setState(o, d(t, c, "baseline-f-v1"), "FROZEN")
		}, detail: []string{"acknowledgments: step 30 missing", "artifacts[signed/artifacts/baseline-f-v1.jws]", "FROZEN", "EVALUATED"}},
		// The retired candidate of a revised manifest is not retired.
		{id: "learning/revised-candidate-new-manifest", mode: "revision-keeps-parent", edit: func(t testing.TB, c *evalcase.LearningCase, o out) {
			setState(o, d(t, c, "baseline-v1"), "CANDIDATE")
		}, detail: []string{"artifacts[signed/artifacts/baseline-v1.jws]", "CANDIDATE", "RETIRED"}},
	}
}

func marshalLine(t testing.TB, o out) string {
	t.Helper()
	b, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

// TestLearningGoldens: the committed goldens of the fake implementation are
// what this file computes, for every learning case and every bad mode, and
// no file is left over.
func TestLearningGoldens(t *testing.T) {
	want := map[string]string{} // relative path under goldenDir -> content
	for _, e := range repoEntries(t) {
		if kindOf(e) != "learning" {
			continue
		}
		id := e["id"].(string)
		c, err := evalcase.ReadLearning(repoFixtures, id)
		if err != nil {
			t.Fatal(err)
		}
		want[id+"/learning.out"] = marshalLine(t, goodOutput(t, c))
	}
	seen := map[string]bool{}
	for _, mu := range learningMutants() {
		name := mu.id + " " + mu.mode
		if seen[name] {
			t.Fatalf("mutant %s twice", name)
		}
		seen[name] = true
		c, err := evalcase.ReadLearning(repoFixtures, mu.id)
		if err != nil {
			t.Fatal(err)
		}
		o := goodOutput(t, c)
		// goodOutput holds Go values; round-trip through JSON so that numbers
		// are float64 as a decoded file has them.
		var rt out
		if err := json.Unmarshal([]byte(marshalLine(t, o)), &rt); err != nil {
			t.Fatal(err)
		}
		mu.edit(t, c, rt)
		want[mu.id+"/learning."+mu.mode+".out"] = marshalLine(t, rt)
	}
	dir := filepath.Join(goldenDir, "learning")
	if *updateLearning {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		for rel, content := range want {
			p := filepath.Join(goldenDir, filepath.FromSlash(strings.Replace(rel, "learning/", "learning/", 1)))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	have := map[string]bool{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(goldenDir, p)
		have[filepath.ToSlash(rel)] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for rel, content := range want {
		b, err := os.ReadFile(filepath.Join(goldenDir, filepath.FromSlash(rel)))
		if err != nil {
			t.Errorf("%s: %v (run -update-learning)", rel, err)
			continue
		}
		if string(b) != content {
			t.Errorf("%s differs from what testdata states (run -update-learning)", rel)
		}
		delete(have, rel)
	}
	for rel := range have {
		t.Errorf("%s: no learning case or mutant states it", rel)
	}
}
