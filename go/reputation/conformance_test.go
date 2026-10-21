package reputation_test

// The library as an implementation under test: the test binary doubles as
// an outcomes command (spec/v1.0/fixtures/README.md, Runner contract) that drives
// a Service over a MemoryStore through the steps of a case, and the
// conformance runner judges what it prints against every committed outcomes
// entry. The adapter reads only the case's inputs, never its expected
// files.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/reputation"
	"hop.top/pact-go/runner"
	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/runner/manifest"
)

const adapterEnv = "PACT_REPUTATION_ADAPTER"

func TestMain(m *testing.M) {
	if os.Getenv(adapterEnv) == "1" {
		os.Exit(adapter(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// adapter is "outcomes <dir> <state>".
func adapter(args []string) int {
	if len(args) != 3 || args[0] != "outcomes" {
		fmt.Fprintln(os.Stderr, "usage: outcomes <dir> <state>")
		return 2
	}
	out, err := runCase(args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	b, err := json.Marshal(out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(string(b))
	return 0
}

// The case inputs as the adapter reads them (spec/v1.0/fixtures/README.md,
// section Outcomes cases).
type caseConfig struct {
	Now               int64 `json:"now"`
	ClockSkewSeconds  int64 `json:"clock_skew_seconds"`
	ReputationService struct {
		ServiceID     string `json:"service_id"`
		TenantID      string `json:"tenant_id"`
		EnvironmentID string `json:"environment_id"`
		Key           string `json:"key"`
	} `json:"reputation_service"`
	DataPolicy core.DataPolicy `json:"data_policy"`
	Scoring    *struct {
		ScoringArtifactDigest core.Digest `json:"scoring_artifact_digest"`
		ScoringPolicyRevision string      `json:"scoring_policy_revision"`
	} `json:"scoring"`
	Visibility string `json:"visibility"`
	Trust      []struct {
		Iss          string            `json:"iss"`
		Role         string            `json:"role"`
		ReporterRole core.ReporterRole `json:"reporter_role"`
		Keys         []string          `json:"keys"`
	} `json:"trust"`
	ExecutorClasses []struct {
		PrincipalID string  `json:"principal_id"`
		TaskID      string  `json:"task_id"`
		OperationID string  `json:"operation_id"`
		Class       string  `json:"class"`
		ExecutorID  *string `json:"executor_id"`
	} `json:"executor_classes"`
	Affiliations []struct {
		EvaluatorIss string `json:"evaluator_iss"`
		OperatorID   string `json:"operator_id"`
	} `json:"affiliations"`
	EvaluatorAgents []struct {
		EvaluatorIss string `json:"evaluator_iss"`
		AgentID      string `json:"agent_id"`
		OperatorID   string `json:"operator_id"`
	} `json:"evaluator_agents"`
	HoldClearanceAuthorities []string `json:"hold_clearance_authorities"`
}

type caseNative struct {
	Tasks []struct {
		TaskID            string      `json:"task_id"`
		AgentID           string      `json:"agent_id"`
		OperatorID        string      `json:"operator_id"`
		PrincipalID       string      `json:"principal_id"`
		IndependenceGroup string      `json:"independence_group"`
		HolderJKT         core.Digest `json:"holder_jkt"`
	} `json:"tasks"`
	Records map[string]struct {
		Kind        string `json:"kind"`
		State       string `json:"state"`
		TaskID      string `json:"task_id"`
		OperationID string `json:"operation_id"`
		Executor    *struct {
			Class       string `json:"class"`
			PrincipalID string `json:"principal_id"`
		} `json:"executor"`
		ObservedAt int64 `json:"observed_at"`
	} `json:"records"`
}

type caseStep struct {
	Ingest     string                `json:"ingest"`
	ReceivedAt *int64                `json:"received_at"`
	Query      *core.ReputationQuery `json:"query"`
	Now        *int64                `json:"now"`
}

func readJSON(p string, v any) error {
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// fixturesRoot is the directory above dir that holds manifest.json.
func fixturesRoot(dir string) (string, error) {
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "manifest.json")); err == nil {
			return d, nil
		}
		if filepath.Dir(d) == d {
			return "", errors.New("no manifest.json above " + dir)
		}
	}
}

// runCase builds a Service from the case's configuration and records, runs
// its steps and returns the outcomes result object.
func runCase(dir string) (map[string]any, error) {
	root, err := fixturesRoot(dir)
	if err != nil {
		return nil, err
	}
	var cfg caseConfig
	var native caseNative
	var steps []caseStep
	for name, v := range map[string]any{"config.json": &cfg, "native_context.json": &native, "steps.json": &steps} {
		if err := readJSON(filepath.Join(dir, name), v); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	svc, err := service(root, cfg, native)
	if err != nil {
		return nil, err
	}
	outSteps := []any{}
	// A refused report has the qualification null (Outcomes output).
	qualifications := map[string]any{}
	for _, st := range steps {
		if st.Query != nil {
			now := cfg.Now
			if st.Now != nil {
				now = *st.Now
			}
			snap, prob := svc.Query(*st.Query, now)
			if prob != nil {
				outSteps = append(outSteps, map[string]any{"problem": prob})
				continue
			}
			outSteps = append(outSteps, map[string]any{"snapshot": snap.Compact, "provenance": snap.Provenance})
			continue
		}
		at := cfg.Now
		if st.ReceivedAt != nil {
			at = *st.ReceivedAt
		}
		b, err := os.ReadFile(filepath.Join(dir, "signed", st.Ingest+".jws"))
		if err != nil {
			return nil, err
		}
		ack, prob := svc.Ingest(string(b), at)
		if prob != nil {
			outSteps = append(outSteps, map[string]any{"problem": prob})
			qualifications[st.Ingest] = nil
		} else {
			outSteps = append(outSteps, map[string]any{"ack": ack})
		}
	}
	cls, err := svc.Classifications()
	if err != nil {
		return nil, err
	}
	for id, v := range cls {
		qualifications[id] = string(v.Qualification)
	}
	return map[string]any{"steps": outSteps, "classifications": qualifications}, nil
}

func service(root string, cfg caseConfig, native caseNative) (*reputation.Service, error) {
	var reg reputation.StaticRegistry
	for _, t := range cfg.Trust {
		if t.Role != "reporter" {
			continue
		}
		r := reputation.Reporter{Iss: t.Iss, Role: t.ReporterRole}
		for _, k := range t.Keys {
			b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(k)))
			if err != nil {
				return nil, err
			}
			jwk, err := jws.ParseJWK(b)
			if err != nil {
				return nil, err
			}
			r.Keys = append(r.Keys, jwk)
		}
		reg = append(reg, r)
	}
	var tasks reputation.StaticTasks
	for _, t := range native.Tasks {
		jkt := t.HolderJKT
		if jkt == "" {
			jkt = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
		}
		tasks = append(tasks, reputation.Task{TaskID: t.TaskID, AgentID: t.AgentID, OperatorID: t.OperatorID, PrincipalID: t.PrincipalID,
			IndependenceGroup: t.IndependenceGroup, HolderJKT: jkt})
	}
	records := reputation.StaticRecords{}
	for ref, r := range native.Records {
		rec := reputation.Record{Kind: reputation.RecordKind(r.Kind), State: r.State, TaskID: r.TaskID, OperationID: r.OperationID, ObservedAt: r.ObservedAt}
		if r.Executor != nil {
			rec.Executor = &reputation.Executor{Class: r.Executor.Class, PrincipalID: r.Executor.PrincipalID}
		}
		records[ref] = rec
	}
	c := reputation.Config{
		ServiceID: cfg.ReputationService.ServiceID, TenantID: cfg.ReputationService.TenantID, EnvironmentID: cfg.ReputationService.EnvironmentID,
		ClockSkewSeconds: cfg.ClockSkewSeconds, DataPolicy: cfg.DataPolicy,
		ScoringArtifactDigest: "Is5hAn87tiTQEbsbEPbL7oeEZWa74Gxmr4Xrp0SQUQ0", ScoringPolicyRevision: "finance-scoring-1",
		ExecutionVisible: cfg.Visibility != "none", HoldClearanceAuthorities: cfg.HoldClearanceAuthorities,
	}
	if cfg.Scoring != nil {
		c.ScoringArtifactDigest, c.ScoringPolicyRevision = cfg.Scoring.ScoringArtifactDigest, cfg.Scoring.ScoringPolicyRevision
	}
	for _, e := range cfg.ExecutorClasses {
		c.ExecutorClasses = append(c.ExecutorClasses, reputation.ExecutorClass{TaskID: e.TaskID, OperationID: e.OperationID, Class: e.Class, ExecutorID: e.ExecutorID})
	}
	for _, a := range cfg.Affiliations {
		c.Affiliations = append(c.Affiliations, reputation.Affiliation{EvaluatorIss: a.EvaluatorIss, OperatorID: a.OperatorID})
	}
	for _, e := range cfg.EvaluatorAgents {
		c.EvaluatorAgents = append(c.EvaluatorAgents, reputation.EvaluatorAgent{EvaluatorIss: e.EvaluatorIss, AgentID: e.AgentID, OperatorID: e.OperatorID})
	}
	signer, err := snapshotSigner(root, cfg.ReputationService.Key)
	if err != nil {
		return nil, err
	}
	return reputation.New(c, reputation.Deps{Registry: reg, Tasks: tasks, Records: records, Store: &reputation.MemoryStore{}, Signer: signer})
}

// snapshotSigner is the private test key whose public key is the case's
// snapshot key.
func snapshotSigner(root, key string) (reputation.ES256Signer, error) {
	if key == "" {
		key = "keys/reputation-service.jwk.json"
	}
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(key)))
	if err != nil {
		return reputation.ES256Signer{}, err
	}
	pub, err := jws.ParseJWK(b)
	if err != nil {
		return reputation.ES256Signer{}, err
	}
	keys, err := evalcase.LoadKeys(root)
	if err != nil {
		return reputation.ES256Signer{}, err
	}
	for _, k := range keys {
		if k.Public.Kid == pub.Kid {
			return reputation.ES256Signer{Kid: k.Public.Kid, Key: k.Private}, nil
		}
	}
	return reputation.ES256Signer{}, errors.New("no private test key for " + key)
}

// TestLibraryPassesEveryOutcomesEntry: driven through the outcomes command
// contract, the library passes every committed outcomes entry, every
// sub-check run.
func TestLibraryPassesEveryOutcomesEntry(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(exe, " \t") {
		t.Skipf("test binary path %q has white space", exe)
	}
	m, err := manifest.Load(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, e := range m.Entries {
		if e.Kind == manifest.KindOutcomes {
			ids = append(ids, e.ID)
		}
	}
	t.Setenv(adapterEnv, "1")
	rep, err := runner.Run(runner.Config{FixturesRoot: repoFixtures, Fixtures: ids, OutcomesCmd: exe + " outcomes {dir} {state}"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Fixtures) != len(ids) || len(ids) != 29 {
		t.Errorf("%d results for %d outcomes entries, want 29", len(rep.Fixtures), len(ids))
	}
	for _, r := range rep.Fixtures {
		if r.Status != runner.StatusPass || len(r.Skipped) > 0 {
			t.Errorf("%s: %s %q, skipped %q", r.ID, r.Status, r.Details, r.Skipped)
		}
	}
}
