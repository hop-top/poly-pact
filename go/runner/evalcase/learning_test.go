package evalcase_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/runner/manifest"
)

func learningEntries(t testing.TB) []manifest.Entry {
	t.Helper()
	m, err := manifest.Load(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	var out []manifest.Entry
	for _, e := range m.Entries {
		if e.Kind == manifest.KindLearning {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		t.Fatal("no learning entry in the manifest")
	}
	return out
}

// TestReadLearningEveryCommittedCase: every learning entry of the manifest
// reads, with its configuration, its steps, the signed file of every step
// that has one and its expected registry.
func TestReadLearningEveryCommittedCase(t *testing.T) {
	for _, e := range learningEntries(t) {
		t.Run(e.ID, func(t *testing.T) {
			c, err := evalcase.ReadLearning(repoFixtures, e.ID)
			if err != nil {
				t.Fatal(err)
			}
			if c.ID != e.ID || c.Path != e.Path || c.ExpectedPath != *e.Expected {
				t.Errorf("case %q path %q expected %q", c.ID, c.Path, c.ExpectedPath)
			}
			if c.Config.Now != 1792080000 || c.Config.ClockSkewSeconds != 5 ||
				c.Config.LearningService.ServiceID != "https://learning.example/finance" || len(c.Config.Trust) < 2 {
				t.Errorf("config not read: %+v", c.Config)
			}
			if len(c.Steps) == 0 {
				t.Fatal("no steps")
			}
			for i, s := range c.Steps {
				switch s.Kind {
				case evalcase.StepAssessment:
					if len(c.Assessments[s.File]) == 0 {
						t.Errorf("step %d: assessment %s not read", i, s.File)
					}
				case evalcase.StepPolicy, evalcase.StepArtifact, evalcase.StepEvent, evalcase.StepOutcome:
					if !strings.Contains(c.Signed[s.File], ".") {
						t.Errorf("step %d: signed file %s not read", i, s.File)
					}
				default:
					t.Errorf("step %d: kind %q", i, s.Kind)
				}
				if s.ReceivedAt < c.Config.Now {
					t.Errorf("step %d: received_at %d before now", i, s.ReceivedAt)
				}
			}
			// Every artifact path of the expected registry is a signed file the
			// case reads.
			for p := range c.Expected.Artifacts {
				if c.Signed[p] == "" {
					t.Errorf("expected artifact %s is no signed file of the case", p)
				}
			}
			if c.Expected.Active == nil || c.Expected.Acknowledgments == nil || c.Expected.Rejections == nil {
				t.Errorf("required registry members read as absent: %+v", c.Expected)
			}
			// The optional lists read as empty, not absent.
			if c.Expected.Holds == nil || c.Expected.ReevaluationRequired == nil {
				t.Errorf("holds %v and reevaluation_required %v read as absent", c.Expected.Holds, c.Expected.ReevaluationRequired)
			}
		})
	}
}

// TestReadLearningDefaults: received_at defaults to now.
func TestReadLearningDefaults(t *testing.T) {
	c, err := evalcase.ReadLearning(repoFixtures, "learning/happy-path")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Steps) != 5 || c.Steps[0].Kind != evalcase.StepPolicy || c.Steps[4].ReceivedAt != 1792166580 {
		t.Errorf("steps %+v", c.Steps)
	}
	root := caseTree(t, "learning/happy-path")
	writeFile(t, filepath.Join(root, "learning/happy-path/steps.json"),
		[]byte(`[{"file":"signed/policies/finance.jws","kind":"policy"},{"file":"signed/artifacts/baseline-v1.jws","kind":"artifact"},
{"file":"signed/events/learning-evaluated-event-0001.jws","kind":"event","received_at":1792080060},
{"file":"signed/events/learning-shadow-event-0001.jws","kind":"event","received_at":1792080120},
{"file":"signed/events/learning-active-event-0001.jws","kind":"event","received_at":1792166580}]`))
	c, err = evalcase.ReadLearning(root, "learning/happy-path")
	if err != nil {
		t.Fatal(err)
	}
	if c.Steps[0].ReceivedAt != c.Config.Now || c.Steps[1].ReceivedAt != c.Config.Now {
		t.Errorf("default received_at: %+v", c.Steps[:2])
	}
	// holds and reevaluation_required default to empty lists.
	editJSON(t, root, "expected/learning/happy-path/registry.json", func(m map[string]any) {
		delete(m, "holds")
		delete(m, "reevaluation_required")
	})
	c, err = evalcase.ReadLearning(root, "learning/happy-path")
	if err != nil {
		t.Fatal(err)
	}
	if c.Expected.Holds == nil || len(c.Expected.Holds) != 0 || c.Expected.ReevaluationRequired == nil || len(c.Expected.ReevaluationRequired) != 0 {
		t.Errorf("holds %#v, reevaluation_required %#v, want empty lists", c.Expected.Holds, c.Expected.ReevaluationRequired)
	}
}

func TestReadLearningSubjects(t *testing.T) {
	for _, tc := range []struct {
		id      string
		subject string
	}{
		{"learning/happy-path", "/acknowledgments/3"},
		{"learning/gate-not-met", "/rejections/0"},
		{"learning/llm-assessment-injection", ""},
	} {
		c, err := evalcase.ReadLearning(repoFixtures, tc.id)
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		if c.Expected.Subject != nil {
			got = *c.Expected.Subject
		}
		if got != tc.subject {
			t.Errorf("%s subject %q, want %q", tc.id, got, tc.subject)
		}
	}
}

func TestReadLearningErrors(t *testing.T) {
	const id = "learning/gate-not-met"
	const steps = id + "/steps.json"
	const expected = "expected/" + id + "/registry.json"
	tests := []struct {
		name  string
		id    string
		setup func(t *testing.T, root string)
		want  []string
	}{
		{"no manifest entry", "learning/nope", nil, []string{"no manifest entry"}},
		{"other kind", "admission/valid", nil, []string{"manifest kind", "not learning"}},
		{"unknown config member", id, func(t *testing.T, r string) {
			edit(t, r, id+"/config.json", `"now":`, `"bogus":1,"now":`)
		}, []string{"config.json", "bogus"}},
		{"config without now", id, func(t *testing.T, r string) {
			editJSON(t, r, id+"/config.json", func(m map[string]any) { delete(m, "now") })
		}, []string{"config.json", "now is required"}},
		{"config without clock_skew_seconds", id, func(t *testing.T, r string) {
			editJSON(t, r, id+"/config.json", func(m map[string]any) { delete(m, "clock_skew_seconds") })
		}, []string{"config.json", "clock_skew_seconds is required"}},
		{"config without learning_service", id, func(t *testing.T, r string) {
			editJSON(t, r, id+"/config.json", func(m map[string]any) { delete(m, "learning_service") })
		}, []string{"config.json", "learning_service"}},
		{"config without trust", id, func(t *testing.T, r string) {
			editJSON(t, r, id+"/config.json", func(m map[string]any) { delete(m, "trust") })
		}, []string{"config.json", "trust is required"}},
		{"step names a file that is a directory", id, func(t *testing.T, r string) {
			edit(t, r, steps, `signed/policies/finance.jws`, `signed/policies`)
		}, []string{"steps[0]"}},
		{"acknowledged step out of range", id, func(t *testing.T, r string) {
			editJSON(t, r, expected, func(m map[string]any) { m["acknowledgments"].([]any)[0].(map[string]any)["step"] = 42 })
		}, []string{"acknowledgments[0]", "step 42"}},
		{"policy step acknowledged", id, func(t *testing.T, r string) {
			editJSON(t, r, expected, func(m map[string]any) { m["acknowledgments"].([]any)[0].(map[string]any)["step"] = 0 })
		}, []string{"acknowledgments[0]", "policy"}},
		{"step answered twice", id, func(t *testing.T, r string) {
			editJSON(t, r, expected, func(m map[string]any) { m["acknowledgments"].([]any)[1].(map[string]any)["step"] = 1 })
		}, []string{"acknowledgments[1]", "twice"}},
		{"unknown acknowledgment status", id, func(t *testing.T, r string) {
			editJSON(t, r, expected, func(m map[string]any) { m["acknowledgments"].([]any)[0].(map[string]any)["status"] = "DONE" })
		}, []string{"acknowledgments[0]", "DONE"}},
		{"rejection without a code", id, func(t *testing.T, r string) {
			editJSON(t, r, expected, func(m map[string]any) { m["rejections"].([]any)[0].(map[string]any)["code"] = "" })
		}, []string{"rejections[0]", "code"}},
		{"active names a file that is no step", id, func(t *testing.T, r string) {
			editJSON(t, r, expected, func(m map[string]any) {
				m["active"].([]any)[0].(map[string]any)["artifact"] = "signed/artifacts/none.jws"
			})
		}, []string{"none.jws"}},
		{"reevaluation names a file that is no step", id, func(t *testing.T, r string) {
			editJSON(t, r, expected, func(m map[string]any) { m["reevaluation_required"] = []any{"signed/artifacts/none.jws"} })
		}, []string{"none.jws"}},
		{"no subject but outcome REJECTED", id, func(t *testing.T, r string) {
			editJSON(t, r, expected, func(m map[string]any) { delete(m, "subject") })
		}, []string{"no subject", "REJECTED"}},
		{"assessment step rejected", "learning/llm-assessment-injection", func(t *testing.T, r string) {
			editJSON(t, r, "expected/learning/llm-assessment-injection/registry.json", func(m map[string]any) {
				m["rejections"] = []any{map[string]any{"step": 3, "code": "LEARNING_REJECTED", "reason_codes": []any{}}}
			})
		}, []string{"rejections[0]", "assessment"}},
		{"subject index not canonical", id, func(t *testing.T, r string) {
			editJSON(t, r, expected, func(m map[string]any) { m["subject"] = "/rejections/00" })
		}, []string{"subject", "/rejections/00"}},
		{"subject index negative", id, func(t *testing.T, r string) {
			editJSON(t, r, expected, func(m map[string]any) { m["subject"] = "/rejections/-1" })
		}, []string{"subject", "/rejections/-1"}},
		{"assessment is not JSON", "learning/llm-assessment-injection", func(t *testing.T, r string) {
			writeFile(t, filepath.Join(r, "learning/llm-assessment-injection/assessments/capability-exercise-0001.json"), []byte("not json"))
		}, []string{"steps[3]", "not JSON"}},
		{"null array in the expected registry", id, func(t *testing.T, r string) {
			editJSON(t, r, expected, func(m map[string]any) { m["rejections"] = nil })
		}, []string{"registry.json", "rejections"}},
		{"no steps.json", id, func(t *testing.T, r string) {
			removeFile(t, filepath.Join(r, id, "steps.json"))
		}, []string{"steps.json"}},
		{"empty steps", id, func(t *testing.T, r string) {
			writeFile(t, filepath.Join(r, id, "steps.json"), []byte(`[]`))
		}, []string{"steps.json", "empty"}},
		{"unknown step kind", id, func(t *testing.T, r string) {
			edit(t, r, steps, `"kind":"policy"`, `"kind":"poke"`)
		}, []string{"steps[0]", "poke"}},
		{"step file missing", id, func(t *testing.T, r string) {
			removeFile(t, filepath.Join(r, id, "signed", "artifacts", "baseline-v1.jws"))
		}, []string{"steps[1]", "baseline-v1.jws"}},
		{"step file escapes the case", id, func(t *testing.T, r string) {
			edit(t, r, steps, `signed/policies/finance.jws`, `../x.jws`)
		}, []string{"steps[0]", "../x.jws"}},
		{"step without file", id, func(t *testing.T, r string) {
			edit(t, r, steps, `"file":"signed/policies/finance.jws",`, ``)
		}, []string{"steps[0]", "file"}},
		{"no expected registry", id, func(t *testing.T, r string) {
			removeFile(t, filepath.Join(r, expected))
		}, []string{"registry.json"}},
		{"expected registry misses artifacts", id, func(t *testing.T, r string) {
			editJSON(t, r, expected, func(m map[string]any) { delete(m, "artifacts") })
		}, []string{"registry.json", "artifacts is required"}},
		{"expected registry misses active", id, func(t *testing.T, r string) {
			editJSON(t, r, expected, func(m map[string]any) { delete(m, "active") })
		}, []string{"registry.json", "active is required"}},
		{"expected registry misses acknowledgments", id, func(t *testing.T, r string) {
			editJSON(t, r, expected, func(m map[string]any) { delete(m, "acknowledgments") })
		}, []string{"registry.json", "acknowledgments is required"}},
		{"expected registry misses a member", id, func(t *testing.T, r string) {
			editJSON(t, r, expected, func(m map[string]any) { delete(m, "rejections") })
		}, []string{"registry.json", "rejections is required"}},
		{"expected registry unknown member", id, func(t *testing.T, r string) {
			editJSON(t, r, expected, func(m map[string]any) { m["bogus"] = 1 })
		}, []string{"registry.json", "bogus"}},
		{"unknown state", id, func(t *testing.T, r string) {
			editJSON(t, r, expected, func(m map[string]any) { m["artifacts"].(map[string]any)["signed/artifacts/baseline-v1.jws"] = "LIVE" })
		}, []string{"registry.json", "LIVE"}},
		{"expected artifact is no signed file", id, func(t *testing.T, r string) {
			editJSON(t, r, expected, func(m map[string]any) { m["artifacts"] = map[string]any{"signed/artifacts/other.jws": "ACTIVE"} })
		}, []string{"registry.json", "other.jws"}},
		{"subject names nothing", id, func(t *testing.T, r string) {
			editJSON(t, r, expected, func(m map[string]any) { m["subject"] = "/rejections/3" })
		}, []string{"subject", "/rejections/3"}},
		{"subject is not the outcome's kind", id, func(t *testing.T, r string) {
			editJSON(t, r, expected, func(m map[string]any) { m["subject"] = "/acknowledgments/0" })
		}, []string{"subject", "REJECTED"}},
		{"outcome MATCH with a subject", id, func(t *testing.T, r string) {
			editJSON(t, r, "manifest.json", func(m map[string]any) {
				for _, e := range m["entries"].([]any) {
					if e := e.(map[string]any); e["id"] == id {
						e["outcome"] = "MATCH"
					}
				}
			})
		}, []string{"subject", "MATCH"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := caseTree(t, id, "learning/llm-assessment-injection")
			if tc.setup != nil {
				tc.setup(t, root)
			}
			_, err := evalcase.ReadLearning(root, tc.id)
			wantErr(t, err, tc.want...)
		})
	}
}

// TestReadLearningNeedsNoPrivateKeys: reading a case does not load the test
// private values, so a fixture directory without them reads.
func TestReadLearningNeedsNoPrivateKeys(t *testing.T) {
	root := caseTree(t, "learning/happy-path")
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(evalcase.KeysFile))); err != nil {
		t.Fatal(err)
	}
	if _, err := evalcase.ReadLearning(root, "learning/happy-path"); err != nil {
		t.Fatal(err)
	}
}

func TestLearningPublicKeys(t *testing.T) {
	c, err := evalcase.ReadLearning(repoFixtures, "learning/happy-path")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range c.Config.Trust {
		if len(r.Keys) == 0 {
			t.Errorf("trust record %s has no keys", r.Iss)
		}
	}
	if !slices.ContainsFunc(c.Config.Trust, func(r evalcase.TrustRecord) bool { return r.Role == "learning-controller" }) {
		t.Error("no learning controller trust record")
	}
}
