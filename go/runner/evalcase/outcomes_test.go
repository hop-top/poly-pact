package evalcase_test

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/runner/manifest"
)

func outcomesEntries(t testing.TB) []manifest.Entry {
	t.Helper()
	m, err := manifest.Load(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	var out []manifest.Entry
	for _, e := range m.Entries {
		if e.Kind == manifest.KindOutcomes {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		t.Fatal("no outcomes entry in the manifest")
	}
	return out
}

// TestReadOutcomesEveryCommittedCase: every outcomes entry of the manifest
// reads, with its configuration, its task records, every report decoded and
// signed, its steps and its expected files.
func TestReadOutcomesEveryCommittedCase(t *testing.T) {
	for _, e := range outcomesEntries(t) {
		t.Run(e.ID, func(t *testing.T) {
			c, err := evalcase.ReadOutcomes(repoFixtures, e.ID)
			if err != nil {
				t.Fatal(err)
			}
			if c.ID != e.ID || c.Path != e.Path || c.ExpectedPath != *e.Expected || c.Outcome != *e.Outcome {
				t.Errorf("case %q path %q expected %q outcome %q", c.ID, c.Path, c.ExpectedPath, c.Outcome)
			}
			cfg := c.Config
			if cfg.Now != 1792080000 || cfg.ClockSkewSeconds != 5 || cfg.ReputationService.ServiceID != "https://reputation.example/finance" ||
				cfg.ReputationService.Key != "keys/reputation-service.jwk.json" || cfg.DataPolicy.QualificationPolicyID != "pact-qualification-v1" ||
				cfg.DataPolicy.IngestionWindowSeconds != 604800 || len(cfg.Trust) == 0 {
				t.Errorf("config not read: %+v", cfg)
			}
			// The B.6 scoring pins are the default.
			if cfg.Scoring.ScoringArtifactDigest != "Is5hAn87tiTQEbsbEPbL7oeEZWa74Gxmr4Xrp0SQUQ0" || cfg.Scoring.ScoringPolicyRevision != "finance-scoring-1" {
				t.Errorf("scoring %+v, want the B.6 pins", cfg.Scoring)
			}
			if len(c.Native.Tasks) == 0 {
				t.Error("no task record")
			}
			for _, task := range c.Native.Tasks {
				if task.HolderJKT != "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M" {
					t.Errorf("task %s holder_jkt %q, want the holder test key's", task.TaskID, task.HolderJKT)
				}
			}
			queries := 0
			for i, s := range c.Steps {
				switch {
				case s.Ingest != "":
					r, ok := c.Reports[s.Ingest]
					if !ok || r.EventID != s.Ingest || !strings.Contains(c.Signed[s.Ingest], ".") {
						t.Errorf("step %d: report %s not read", i, s.Ingest)
					}
					if s.ReceivedAt < cfg.Now {
						t.Errorf("step %d: received_at %d before now", i, s.ReceivedAt)
					}
				case s.Query != nil:
					queries++
					if s.Now < cfg.Now || s.Query.AgentID == "" {
						t.Errorf("step %d: query %+v at %d", i, s.Query, s.Now)
					}
				default:
					t.Errorf("step %d is neither an ingestion nor a query", i)
				}
			}
			if len(c.Snapshots) != queries {
				t.Errorf("%d expected snapshots for %d queries", len(c.Snapshots), queries)
			}
			for _, s := range c.Snapshots {
				if s.ExpMax != c.Steps[s.Step].Now+300 {
					t.Errorf("step %d: exp_max %d, want the default now + 300", s.Step, s.ExpMax)
				}
				if s.Provenance.QualifiedEventIDs == nil || s.Provenance.SupersededEventIDs == nil || len(s.Value) == 0 {
					t.Errorf("step %d: snapshot not read: %+v", s.Step, s)
				}
			}
			if c.Classifications != nil {
				if c.ExpectedPath != "expected/"+e.ID+"/classifications.json" || len(c.Classifications.Events) == 0 {
					t.Errorf("classifications %+v at %s", c.Classifications, c.ExpectedPath)
				}
			} else if c.ExpectedPath != "expected/"+e.ID+"/snapshot.json" || c.Outcome != "MATCH" {
				t.Errorf("no classifications, expected %s outcome %s", c.ExpectedPath, c.Outcome)
			}
		})
	}
}

// TestReadOutcomesValues spot-checks the decoded members of two cases.
func TestReadOutcomesValues(t *testing.T) {
	c, err := evalcase.ReadOutcomes(repoFixtures, "reputation/security-hold-no-decay")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Steps) != 18 || c.Steps[13].Now != 1826640000 || c.Steps[16].ReceivedAt != 1826640060 || c.Steps[16].Ingest != "remediation-event-0002" {
		t.Errorf("steps %+v", c.Steps)
	}
	if len(c.Config.HoldClearanceAuthorities) != 1 || c.Config.HoldClearanceAuthorities[0] != "https://security.example/finance" {
		t.Errorf("hold_clearance_authorities %v", c.Config.HoldClearanceAuthorities)
	}
	rec, ok := c.Native.Records["native-incident-record:finance-0001"]
	if !ok || rec.Kind != "incident" || rec.State != "confirmed" || rec.Executor != nil || rec.Returned != nil {
		t.Errorf("incident record %+v", rec)
	}
	if c.Classifications != nil || c.Acks != nil {
		t.Error("the case has no classifications.json and no acks.json")
	}
	if c.Reports["security-event-0001"].EventKind != core.EventSecurity {
		t.Error("security report not decoded")
	}

	c, err = evalcase.ReadOutcomes(repoFixtures, "outcomes/qualification/duplicate-reports-same-tuple")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Acks) != 2 || c.Acks[1].Status == nil || *c.Acks[1].Status != core.AckDuplicate || c.Acks[1].TransportCode != nil {
		t.Errorf("acks %+v", c.Acks)
	}
	cl := c.Classifications
	if cl == nil || cl.SubjectEventID != "execution-event-0001" || len(cl.Events) != 2 || cl.Events[1].Qualification != nil || cl.Events[1].Reason != "duplicate" {
		t.Errorf("classifications %+v", cl)
	}
	rec, ok = c.Native.Records["native-execution-log:finance-read-0001"]
	if !ok || rec.Executor == nil || rec.Executor.Class != "delegated-user" || rec.Returned == nil || *rec.Returned != "data" {
		t.Errorf("execution record %+v", rec)
	}

	c, err = evalcase.ReadOutcomes(repoFixtures, "outcomes/qualification/reciprocal-endorsements")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Config.EvaluatorAgents) != 2 || c.Config.EvaluatorAgents[0].AgentID != "https://identity.example/agents/ledger-reviewer" || c.Config.Affiliations == nil {
		t.Errorf("evaluator_agents %+v, affiliations %+v", c.Config.EvaluatorAgents, c.Config.Affiliations)
	}
}

// TestReadOutcomesRejects: a case that breaks the format does not read.
func TestReadOutcomesRejects(t *testing.T) {
	const id = "outcomes/qualification/correction-recompute"
	dir := id + "/"
	exp := "expected/" + id + "/"
	for _, tc := range []struct {
		name   string
		break_ func(t *testing.T, root string)
		want   []string
	}{
		{"unknown config member", func(t *testing.T, root string) {
			editJSON(t, root, dir+"config.json", func(m map[string]any) { m["surprise"] = true })
		}, []string{"config.json", "surprise"}},
		{"no data_policy", func(t *testing.T, root string) {
			editJSON(t, root, dir+"config.json", func(m map[string]any) { delete(m, "data_policy") })
		}, []string{"config.json", "data_policy is required"}},
		{"maximum_failure_weight above 5", func(t *testing.T, root string) {
			editJSON(t, root, dir+"config.json", func(m map[string]any) { m["data_policy"].(map[string]any)["maximum_failure_weight"] = 6 })
		}, []string{"config.json", "maximum_failure_weight 6", "15.3"}},
		{"maximum_failure_weight 0", func(t *testing.T, root string) {
			editJSON(t, root, dir+"config.json", func(m map[string]any) { m["data_policy"].(map[string]any)["maximum_failure_weight"] = 0 })
		}, []string{"config.json", "maximum_failure_weight 0"}},
		// Every other bound of the data policy (Appendix A.3; draft 14.3, 15.3).
		{"ingestion_window_seconds 0", func(t *testing.T, root string) {
			editJSON(t, root, dir+"config.json", func(m map[string]any) { m["data_policy"].(map[string]any)["ingestion_window_seconds"] = 0 })
		}, []string{"config.json", "ingestion_window_seconds 0"}},
		{"positive_weight_cap_per_task 2", func(t *testing.T, root string) {
			editJSON(t, root, dir+"config.json", func(m map[string]any) { m["data_policy"].(map[string]any)["positive_weight_cap_per_task"] = 2 })
		}, []string{"config.json", "positive_weight_cap_per_task 2"}},
		{"positive_weight_cap_per_task 0", func(t *testing.T, root string) {
			editJSON(t, root, dir+"config.json", func(m map[string]any) { m["data_policy"].(map[string]any)["positive_weight_cap_per_task"] = 0 })
		}, []string{"config.json", "positive_weight_cap_per_task 0"}},
		{"no task_attribution_source", func(t *testing.T, root string) {
			editJSON(t, root, dir+"config.json", func(m map[string]any) { m["data_policy"].(map[string]any)["task_attribution_source"] = "" })
		}, []string{"config.json", "task_attribution_source"}},
		{"qualification_policy_id of 1025", func(t *testing.T, root string) {
			editJSON(t, root, dir+"config.json", func(m map[string]any) {
				m["data_policy"].(map[string]any)["qualification_policy_id"] = strings.Repeat("x", 1025)
			})
		}, []string{"config.json", "qualification_policy_id"}},
		{"no reporter_independence_policy_id", func(t *testing.T, root string) {
			editJSON(t, root, dir+"config.json", func(m map[string]any) { m["data_policy"].(map[string]any)["reporter_independence_policy_id"] = "" })
		}, []string{"config.json", "reporter_independence_policy_id"}},
		{"129 data_policy extensions", func(t *testing.T, root string) {
			editJSON(t, root, dir+"config.json", func(m map[string]any) {
				ext := map[string]any{}
				for i := range 129 {
					ext[fmt.Sprintf("https://ext.example/%d", i)] = true
				}
				m["data_policy"].(map[string]any)["extensions"] = ext
			})
		}, []string{"config.json", "extensions"}},
		{"visibility", func(t *testing.T, root string) {
			editJSON(t, root, dir+"config.json", func(m map[string]any) { m["visibility"] = "partial" })
		}, []string{"visibility"}},
		{"step with both members", func(t *testing.T, root string) {
			edit(t, root, dir+"steps.json", `{"ingest":"execution-event-0001","received_at":1792080000}`,
				`{"ingest":"execution-event-0001","received_at":1792080000,"query":{"agent_id":"a","holder_jkt":"b","context":{"tenant_id":"t","environment_id":"e","agent_id":"a","purpose_id":"p","action_class":"x","resource_class":"y","runtime_class":"z"},"audience":"u"}}`)
		}, []string{"steps.json", "exactly one of ingest and query"}},
		{"ingest of an unknown report", func(t *testing.T, root string) {
			edit(t, root, dir+"steps.json", `"ingest":"execution-event-0001"`, `"ingest":"execution-event-0009"`)
		}, []string{"steps.json", "execution-event-0009"}},
		{"report named after another event", func(t *testing.T, root string) {
			editJSON(t, root, dir+"reports/execution-event-0001.json", func(m map[string]any) { m["event_id"] = "execution-event-0003" })
		}, []string{"execution-event-0001", "event_id"}},
		{"missing signed report", func(t *testing.T, root string) {
			removeFile(t, filepath.Join(root, filepath.FromSlash(dir+"signed/execution-event-0001.jws")))
		}, []string{"signed/execution-event-0001.jws"}},
		{"snapshot of an ingest step", func(t *testing.T, root string) {
			edit(t, root, exp+"snapshot.json", `{"step":1,`, `{"step":0,`)
		}, []string{"snapshot.json", "step 0", "query"}},
		{"query without snapshot", func(t *testing.T, root string) {
			edit(t, root, exp+"snapshot.json", `{"step":3,`, `{"step":1,`)
		}, []string{"snapshot.json"}},
		{"subject without a qualification", func(t *testing.T, root string) {
			edit(t, root, exp+"classifications.json", `"qualification": "QUALIFIED",
      "reason": "correction"`, `"qualification": null,
      "reason": "correction"`)
		}, []string{"classifications.json", "subject_event_id"}},
		{"subject is not a report", func(t *testing.T, root string) {
			edit(t, root, exp+"classifications.json", `"subject_event_id": "correction-event-0002"`, `"subject_event_id": "correction-event-0007"`)
		}, []string{"classifications.json", "correction-event-0007"}},
		{"outcome is not the subject's", func(t *testing.T, root string) {
			edit(t, root, "manifest.json", `"expected": "expected/outcomes/qualification/correction-recompute/classifications.json",
      "outcome": "QUALIFIED"`, `"expected": "expected/outcomes/qualification/correction-recompute/classifications.json",
      "outcome": "DISPUTED"`)
		}, []string{"DISPUTED", "QUALIFIED"}},
		{"one snapshot short", func(t *testing.T, root string) {
			b := string(readFile(t, filepath.Join(root, filepath.FromSlash(exp+"snapshot.json"))))
			i := strings.Index(b, ",\n {\"step\":3,")
			if i < 0 {
				t.Fatal("snapshot.json has no second entry")
			}
			writeFile(t, filepath.Join(root, filepath.FromSlash(exp+"snapshot.json")), []byte(b[:i]+"]"))
		}, []string{"snapshot.json", "1 entries for 2 query steps"}},
		{"classified event that is no report", func(t *testing.T, root string) {
			edit(t, root, exp+"classifications.json", `"event_id": "execution-event-0001"`, `"event_id": "execution-event-0005"`)
		}, []string{"classifications.json", "execution-event-0005"}},
		{"no snapshot.json", func(t *testing.T, root string) {
			removeFile(t, filepath.Join(root, filepath.FromSlash(exp+"snapshot.json")))
		}, []string{"snapshot.json is required"}},
		{"bad qualification", func(t *testing.T, root string) {
			edit(t, root, exp+"classifications.json", `"qualification": "QUALIFIED",
      "reason": "mapped"`, `"qualification": "MAYBE",
      "reason": "mapped"`)
		}, []string{"classifications.json", "MAYBE"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := caseTree(t, id)
			if _, err := evalcase.ReadOutcomes(root, id); err != nil {
				t.Fatalf("control: %v", err)
			}
			tc.break_(t, root)
			_, err := evalcase.ReadOutcomes(root, id)
			wantErr(t, err, tc.want...)
		})
	}
	// A case judged by its snapshots alone has the outcome MATCH.
	const match = "outcomes/qualification/repeated-admissions"
	root := caseTree(t, match)
	edit(t, root, "manifest.json", `"expected": "expected/outcomes/qualification/repeated-admissions/snapshot.json",
      "outcome": "MATCH"`, `"expected": "expected/outcomes/qualification/repeated-admissions/snapshot.json",
      "outcome": "QUALIFIED"`)
	_, err := evalcase.ReadOutcomes(root, match)
	wantErr(t, err, "QUALIFIED", "MATCH")
	if _, err := evalcase.ReadOutcomes(repoFixtures, "admission/valid"); err == nil || !strings.Contains(err.Error(), "outcomes") {
		t.Errorf("an evaluate entry read as an outcomes case: %v", err)
	}
	if _, err := evalcase.ReadOutcomes(repoFixtures, "outcomes/none"); err == nil {
		t.Error("an unknown id read")
	}
}

// TestReadOutcomesAcks: acks.json names every ingest step, in order, and
// either a status or a transport code.
func TestReadOutcomesAcks(t *testing.T) {
	const id = "outcomes/qualification/duplicate-reports-same-tuple"
	exp := "expected/" + id + "/acks.json"
	for name, tc := range map[string]struct{ old, repl string }{
		"query step": {`{"step":1,"status":"DUPLICATE"`, `{"step":2,"status":"DUPLICATE"`},
		"both":       {`"status":"DUPLICATE","transport_code":null`, `"status":"DUPLICATE","transport_code":"INVALID_MESSAGE"`},
		"neither":    {`"status":"DUPLICATE","transport_code":null`, `"status":null,"transport_code":null`},
		"bad status": {`"status":"DUPLICATE"`, `"status":"REPEATED"`},
	} {
		t.Run(name, func(t *testing.T) {
			root := caseTree(t, id)
			b := string(readFile(t, filepath.Join(root, filepath.FromSlash(exp))))
			if !strings.Contains(b, tc.old) {
				t.Fatalf("acks.json does not hold %q:\n%s", tc.old, b)
			}
			edit(t, root, exp, tc.old, tc.repl)
			_, err := evalcase.ReadOutcomes(root, id)
			wantErr(t, err, "acks.json")
		})
	}
}
