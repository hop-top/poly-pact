package evalcase

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/strictjson"
	score "hop.top/pact-go/reputation"
	"hop.top/pact-go/runner/manifest"
)

// Defaults of an outcomes case (spec/v1.0/fixtures/README.md, section Outcomes
// cases).
const (
	// DefaultReputationKey is the public JWK file snapshots verify under
	// when reputation_service.key is absent.
	DefaultReputationKey = "keys/reputation-service.jwk.json"
	// DefaultHolderJKT is the RFC 7638 thumbprint of the holder test key,
	// the holder_jkt of a task record that names none.
	DefaultHolderJKT core.Digest = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
	// DefaultScoringArtifactDigest and DefaultScoringPolicyRevision are the
	// scoring pins of Appendix B.6.
	DefaultScoringArtifactDigest core.Digest = "Is5hAn87tiTQEbsbEPbL7oeEZWa74Gxmr4Xrp0SQUQ0"
	DefaultScoringPolicyRevision string      = "finance-scoring-1"
	// SnapshotLifetime is the baseline expiry bound of a snapshot (draft
	// Section 15.2): exp_max defaults to the query's now plus it.
	SnapshotLifetime int64 = 300
)

// The qualifications of draft Section 14.3.
const (
	Qualified   = "QUALIFIED"
	Unqualified = "UNQUALIFIED"
	Disputed    = "DISPUTED"
)

// ReputationService is the reputation_service member of an outcomes
// config.json: the audience of every report and the iss of every snapshot,
// its tenant and environment, and the public JWK file its snapshots verify
// under.
type ReputationService struct {
	ServiceID     string `json:"service_id"`
	TenantID      string `json:"tenant_id"`
	EnvironmentID string `json:"environment_id"`
	Key           string `json:"key"`
}

// Scoring is the scorer the snapshots pin.
type Scoring struct {
	ScoringArtifactDigest core.Digest `json:"scoring_artifact_digest"`
	ScoringPolicyRevision string      `json:"scoring_policy_revision"`
}

// Affiliation is one entry of the configured affiliation registry (draft
// Section 14.6 rule 6).
type Affiliation struct {
	EvaluatorIss string `json:"evaluator_iss"`
	OperatorID   string `json:"operator_id"`
}

// EvaluatorAgent is the agent an evaluator operates (Section 14.6 rule 7).
type EvaluatorAgent struct {
	EvaluatorIss string `json:"evaluator_iss"`
	AgentID      string `json:"agent_id"`
	OperatorID   string `json:"operator_id"`
}

// OutcomesConfig is the config.json of an outcomes case: the trusted
// configuration of the reputation service. Absent optional members are
// their defaults: empty lists, the default key and the B.6 scoring pins.
type OutcomesConfig struct {
	Now                      int64
	ClockSkewSeconds         int64
	ReputationService        ReputationService
	DataPolicy               core.DataPolicy
	Scoring                  Scoring
	Visibility               string
	Trust                    []TrustRecord
	ExecutorClasses          []ExecutorClass
	Affiliations             []Affiliation
	EvaluatorAgents          []EvaluatorAgent
	HoldClearanceAuthorities []string
}

// NativeTask is an authoritative task record. HolderJKT is the holder key
// the task's admission bound, DefaultHolderJKT when the record names none.
type NativeTask struct {
	TaskID            string      `json:"task_id"`
	AgentID           string      `json:"agent_id"`
	OperatorID        string      `json:"operator_id"`
	PrincipalID       string      `json:"principal_id"`
	IndependenceGroup string      `json:"independence_group"`
	HolderJKT         core.Digest `json:"holder_jkt"`
}

// RecordExecutor is the executor identity a native record names (draft
// Section 17.5).
type RecordExecutor struct {
	Class       string `json:"class"`
	PrincipalID string `json:"principal_id"`
}

// NativeRecord is an immutable native record an evidence_refs entry may
// cite. Returned is data or empty for a completed execution and nil
// otherwise; Executor may be nil for a kind other than execution and
// authorization.
type NativeRecord struct {
	Kind        string          `json:"kind"`
	State       string          `json:"state"`
	Returned    *string         `json:"returned"`
	TaskID      string          `json:"task_id"`
	OperationID string          `json:"operation_id"`
	Executor    *RecordExecutor `json:"executor"`
	ObservedAt  int64           `json:"observed_at"`
}

// OutcomesNative is the native_context.json of an outcomes case.
type OutcomesNative struct {
	Tasks   []NativeTask
	Records map[string]NativeRecord
}

// Task returns the task record of id.
func (n OutcomesNative) Task(id string) (NativeTask, bool) {
	i := slices.IndexFunc(n.Tasks, func(t NativeTask) bool { return t.TaskID == id })
	if i < 0 {
		return NativeTask{}, false
	}
	return n.Tasks[i], true
}

// OutcomeStep is one step of steps.json: an ingestion of the report whose
// event_id is Ingest at the service clock ReceivedAt, or a Query at the
// service clock Now. Both clocks default to the config's now.
type OutcomeStep struct {
	Ingest     string
	ReceivedAt int64
	Query      *core.ReputationQuery
	Now        int64
}

// Contribution is what a report adds to a dimension, in weight units.
type Contribution struct {
	Dimension core.Dimension `json:"dimension"`
	Positive  int64          `json:"positive"`
	Negative  int64          `json:"negative"`
}

// ClassifiedEvent is one entry of classifications.json. Qualification is
// nil for a report whose qualification the draft does not fix, which is
// not judged.
type ClassifiedEvent struct {
	EventID       string       `json:"event_id"`
	Report        string       `json:"report"`
	Signed        string       `json:"signed"`
	Qualification *string      `json:"qualification"`
	Reason        string       `json:"reason"`
	Contribution  Contribution `json:"contribution"`
	Rationale     string       `json:"rationale"`
}

// Classifications is the expected classifications.json.
type Classifications struct {
	Case             string                  `json:"case"`
	AdversarialClaim string                  `json:"adversarial_claim"`
	SubjectEventID   string                  `json:"subject_event_id"`
	Events           []ClassifiedEvent       `json:"events"`
	DimensionDeltas  map[string]Contribution `json:"dimension_deltas"`
}

// Event returns the entry of id.
func (c *Classifications) Event(id string) (ClassifiedEvent, bool) {
	i := slices.IndexFunc(c.Events, func(e ClassifiedEvent) bool { return e.EventID == id })
	if i < 0 {
		return ClassifiedEvent{}, false
	}
	return c.Events[i], true
}

// ProvenanceIDs are the report lists of a ProvenanceManifest (draft Section
// 15.2): [iss, jti] pairs.
type ProvenanceIDs struct {
	QualifiedEventIDs  [][2]string `json:"qualified_event_ids"`
	SupersededEventIDs [][2]string `json:"superseded_event_ids"`
}

// ExpectedSnapshot is one entry of snapshot.json. Value is the subset of
// ReputationValue the snapshot must carry, as JSON; Claims the payload
// members it must carry; ExpMax the latest permitted exp, the query's now
// plus SnapshotLifetime when absent.
type ExpectedSnapshot struct {
	Step       int
	Value      json.RawMessage
	Provenance ProvenanceIDs
	Claims     map[string]json.RawMessage
	ExpMax     int64
}

// ExpectedAck is one entry of acks.json: the Acknowledgment status, or nil
// and the Section 13.4 code of a refusal.
type ExpectedAck struct {
	Step          int             `json:"step"`
	Status        *core.AckStatus `json:"status"`
	TransportCode *string         `json:"transport_code"`
}

// OutcomesCase is an outcomes case: a manifest entry of kind outcomes, read
// with its configuration, task and native records, reports, steps and
// expected files (spec/v1.0/fixtures/README.md, section Outcomes cases).
type OutcomesCase struct {
	// ID is the manifest id; Path the case directory, relative to the
	// fixture directory.
	ID, Path string
	Config   OutcomesConfig
	Native   OutcomesNative
	Steps    []OutcomeStep
	// Reports holds every decoded report of reports/ by event_id, and Signed
	// the compact JWS of signed/<event_id>.jws of each.
	Reports map[string]core.OutcomeReport
	Signed  map[string]string
	// Classifications, Snapshots and Acks are the expected files under
	// expected/<id>/, nil when the case has none.
	Classifications *Classifications
	Snapshots       []ExpectedSnapshot
	Acks            []ExpectedAck
	// ExpectedPath is the manifest expected file, relative to the fixture
	// directory, and Outcome the manifest outcome.
	ExpectedPath string
	Outcome      string
}

// ReadOutcomes reads the outcomes case id of the fixture directory fixtures
// (the directory of manifest.json). It does not verify the signed reports
// and loads no private key: a signature is the reputation service's to
// check. It fails when the manifest does not list id as an entry of kind
// outcomes, when a file is missing or is not strict JSON of its format, when
// a step names a report the case lacks, or when the expected files are
// inconsistent with the steps or the manifest: a snapshot that is not one per
// query step in order, an acknowledgment that is not one per ingest step in
// order, or a manifest expected and outcome other than the subject report's
// qualification in classifications.json, or snapshot.json and MATCH without
// it.
func ReadOutcomes(fixtures, id string) (*OutcomesCase, error) {
	m, err := manifest.Load(fixtures)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", manifest.FileName, err)
	}
	i := slices.IndexFunc(m.Entries, func(e manifest.Entry) bool { return e.ID == id })
	if i < 0 {
		return nil, fmt.Errorf("%s: no manifest entry", id)
	}
	e := m.Entries[i]
	if e.Kind != manifest.KindOutcomes {
		return nil, fmt.Errorf("%s: manifest kind %s, not %s", id, e.Kind, manifest.KindOutcomes)
	}
	if e.Expected == nil || e.Outcome == nil {
		return nil, fmt.Errorf("%s: the manifest entry names no expected file or outcome", id)
	}
	dir := filepath.Join(fixtures, filepath.FromSlash(e.Path))
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("%s: path %s is not a case directory", id, e.Path)
	}
	c := &OutcomesCase{ID: id, Path: e.Path, ExpectedPath: *e.Expected, Outcome: *e.Outcome,
		Reports: map[string]core.OutcomeReport{}, Signed: map[string]string{}}
	if err := c.readConfig(filepath.Join(dir, "config.json")); err != nil {
		return nil, fmt.Errorf("%s/config.json: %w", id, err)
	}
	if err := c.readNative(filepath.Join(dir, "native_context.json")); err != nil {
		return nil, fmt.Errorf("%s/native_context.json: %w", id, err)
	}
	if err := c.readSteps(dir); err != nil {
		return nil, fmt.Errorf("%s/steps.json: %w", id, err)
	}
	if err := c.readExpected(filepath.Join(fixtures, "expected", filepath.FromSlash(id))); err != nil {
		return nil, fmt.Errorf("%s: %w", id, err)
	}
	return c, nil
}

func (c *OutcomesCase) readConfig(p string) error {
	var f struct {
		Now                      *int64             `json:"now"`
		ClockSkewSeconds         *int64             `json:"clock_skew_seconds"`
		ReputationService        *ReputationService `json:"reputation_service"`
		DataPolicy               *core.DataPolicy   `json:"data_policy"`
		Scoring                  *Scoring           `json:"scoring"`
		Visibility               *string            `json:"visibility"`
		Trust                    *[]TrustRecord     `json:"trust"`
		ExecutorClasses          []ExecutorClass    `json:"executor_classes"`
		Affiliations             []Affiliation      `json:"affiliations"`
		EvaluatorAgents          []EvaluatorAgent   `json:"evaluator_agents"`
		HoldClearanceAuthorities []string           `json:"hold_clearance_authorities"`
	}
	if err := readStrict(p, &f); err != nil {
		return err
	}
	switch {
	case f.Now == nil:
		return errors.New("now is required")
	case f.ClockSkewSeconds == nil:
		return errors.New("clock_skew_seconds is required")
	case f.ReputationService == nil || f.ReputationService.ServiceID == "":
		return errors.New("reputation_service.service_id is required")
	case f.DataPolicy == nil:
		return errors.New("data_policy is required")
	case f.Visibility == nil || *f.Visibility != "execution" && *f.Visibility != "none":
		return errors.New("visibility is required: execution or none")
	case f.Trust == nil:
		return errors.New("trust is required")
	}
	if err := score.CheckDataPolicy(*f.DataPolicy); err != nil {
		return fmt.Errorf("data_policy: %w", err)
	}
	cfg := OutcomesConfig{
		Now: *f.Now, ClockSkewSeconds: *f.ClockSkewSeconds, ReputationService: *f.ReputationService, DataPolicy: *f.DataPolicy,
		Scoring:    Scoring{ScoringArtifactDigest: DefaultScoringArtifactDigest, ScoringPolicyRevision: DefaultScoringPolicyRevision},
		Visibility: *f.Visibility, Trust: *f.Trust, ExecutorClasses: nonNilSlice(f.ExecutorClasses), Affiliations: nonNilSlice(f.Affiliations),
		EvaluatorAgents: nonNilSlice(f.EvaluatorAgents), HoldClearanceAuthorities: nonNilSlice(f.HoldClearanceAuthorities),
	}
	if f.Scoring != nil {
		cfg.Scoring = *f.Scoring
	}
	if cfg.ReputationService.Key == "" {
		cfg.ReputationService.Key = DefaultReputationKey
	}
	for i, t := range cfg.Trust {
		if t.ReporterRole == nil || !core.ReporterRole(*t.ReporterRole).Valid() {
			return fmt.Errorf("trust[%d]: reporter_role is required, an OutcomeReport.reporter_role value", i)
		}
	}
	c.Config = cfg
	return nil
}

func nonNilSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func (c *OutcomesCase) readNative(p string) error {
	var f struct {
		Tasks   *[]NativeTask            `json:"tasks"`
		Records *map[string]NativeRecord `json:"records"`
	}
	if err := readStrict(p, &f); err != nil {
		return err
	}
	if f.Tasks == nil || f.Records == nil {
		return errors.New("tasks and records are required")
	}
	c.Native = OutcomesNative{Tasks: *f.Tasks, Records: *f.Records}
	for i := range c.Native.Tasks {
		t := &c.Native.Tasks[i]
		if t.TaskID == "" || t.AgentID == "" || t.IndependenceGroup == "" {
			return fmt.Errorf("tasks[%d]: task_id, agent_id and independence_group are required", i)
		}
		if t.HolderJKT == "" {
			t.HolderJKT = DefaultHolderJKT
		}
	}
	return nil
}

func (c *OutcomesCase) readSteps(dir string) error {
	var raw []struct {
		Ingest     *string               `json:"ingest"`
		ReceivedAt *int64                `json:"received_at"`
		Query      *core.ReputationQuery `json:"query"`
		Now        *int64                `json:"now"`
	}
	if err := readStrict(filepath.Join(dir, "steps.json"), &raw); err != nil {
		return err
	}
	if len(raw) == 0 {
		return errors.New("empty: a case has at least one step")
	}
	for i, r := range raw {
		where := fmt.Sprintf("steps[%d]", i)
		if (r.Ingest == nil) == (r.Query == nil) {
			return fmt.Errorf("%s: a step has exactly one of ingest and query", where)
		}
		s := OutcomeStep{ReceivedAt: c.Config.Now, Now: c.Config.Now, Query: r.Query}
		if r.Ingest != nil {
			if r.Now != nil {
				return fmt.Errorf("%s: now belongs to a query step; an ingestion has received_at", where)
			}
			s.Ingest = *r.Ingest
			if r.ReceivedAt != nil {
				s.ReceivedAt = *r.ReceivedAt
			}
			if err := c.readReport(dir, s.Ingest); err != nil {
				return fmt.Errorf("%s: %w", where, err)
			}
		} else {
			if r.ReceivedAt != nil {
				return fmt.Errorf("%s: received_at belongs to an ingest step; a query has now", where)
			}
			if r.Now != nil {
				s.Now = *r.Now
			}
		}
		c.Steps = append(c.Steps, s)
	}
	return nil
}

// readReport reads reports/<event>.json and signed/<event>.jws once.
func (c *OutcomesCase) readReport(dir, event string) error {
	if _, ok := c.Reports[event]; ok {
		return nil
	}
	if !relPath.MatchString(event) || filepath.Base(event) != event {
		return fmt.Errorf("ingest %q is not an event_id file name", event)
	}
	var r core.OutcomeReport
	rel := "reports/" + event + ".json"
	if err := readStrict(filepath.Join(dir, "reports", event+".json"), &r); err != nil {
		return fmt.Errorf("%s: %w", rel, err)
	}
	if r.EventID != event {
		return fmt.Errorf("%s: event_id %q, but a report file is named by its event_id", rel, r.EventID)
	}
	b, err := os.ReadFile(filepath.Join(dir, "signed", event+".jws"))
	if err != nil {
		return fmt.Errorf("signed/%s.jws: %w", event, err)
	}
	c.Reports[event] = r
	c.Signed[event] = string(b)
	return nil
}

func (c *OutcomesCase) readExpected(dir string) error {
	rel := "expected/" + c.ID + "/"
	cl, err := readOptional(filepath.Join(dir, "classifications.json"), func(b []byte) (*Classifications, error) { return c.parseClassifications(b) })
	if err != nil {
		return fmt.Errorf("%sclassifications.json: %w", rel, err)
	}
	snaps, err := readOptional(filepath.Join(dir, "snapshot.json"), c.parseSnapshots)
	if err != nil {
		return fmt.Errorf("%ssnapshot.json: %w", rel, err)
	}
	acks, err := readOptional(filepath.Join(dir, "acks.json"), c.parseAcks)
	if err != nil {
		return fmt.Errorf("%sacks.json: %w", rel, err)
	}
	c.Classifications = cl
	if snaps != nil {
		c.Snapshots = *snaps
	}
	if acks != nil {
		c.Acks = *acks
	}
	queries := slices.ContainsFunc(c.Steps, func(s OutcomeStep) bool { return s.Query != nil })
	if queries && snaps == nil {
		return fmt.Errorf("%ssnapshot.json is required: the steps have a query", rel)
	}
	switch {
	case cl != nil:
		subject, _ := cl.Event(cl.SubjectEventID)
		if c.ExpectedPath != rel+"classifications.json" || *subject.Qualification != c.Outcome {
			return fmt.Errorf("manifest expected %s, outcome %s; want %sclassifications.json and the subject report's qualification %s",
				c.ExpectedPath, c.Outcome, rel, *subject.Qualification)
		}
	case snaps != nil:
		if c.ExpectedPath != rel+"snapshot.json" || c.Outcome != "MATCH" {
			return fmt.Errorf("manifest expected %s, outcome %s; a case without classifications.json wants %ssnapshot.json and MATCH",
				c.ExpectedPath, c.Outcome, rel)
		}
	default:
		return fmt.Errorf("%s has neither classifications.json nor snapshot.json", rel)
	}
	return nil
}

// readOptional parses the file p, or returns nil when it does not exist.
func readOptional[T any](p string, parse func([]byte) (T, error)) (T, error) {
	var zero T
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return zero, nil
	}
	if err != nil {
		return zero, err
	}
	return parse(b)
}

func (c *OutcomesCase) parseClassifications(b []byte) (*Classifications, error) {
	var cl Classifications
	if err := strictjson.Unmarshal(b, strictjson.Limits{}, &cl); err != nil {
		return nil, err
	}
	if cl.Case != c.ID {
		return nil, fmt.Errorf("case %q, want %q", cl.Case, c.ID)
	}
	seen := map[string]bool{}
	for i, e := range cl.Events {
		if _, ok := c.Reports[e.EventID]; !ok {
			return nil, fmt.Errorf("events[%d]: %s is not a report the steps ingest", i, e.EventID)
		}
		if seen[e.EventID] {
			return nil, fmt.Errorf("events[%d]: %s is classified twice", i, e.EventID)
		}
		seen[e.EventID] = true
		if q := e.Qualification; q != nil && *q != Qualified && *q != Unqualified && *q != Disputed {
			return nil, fmt.Errorf("events[%d]: qualification %q is not QUALIFIED, UNQUALIFIED, DISPUTED or null", i, *q)
		}
	}
	subject, ok := cl.Event(cl.SubjectEventID)
	if !ok || subject.Qualification == nil {
		return nil, fmt.Errorf("subject_event_id %q names no event with a qualification", cl.SubjectEventID)
	}
	return &cl, nil
}

func (c *OutcomesCase) parseSnapshots(b []byte) (*[]ExpectedSnapshot, error) {
	var raw []struct {
		Step       *int                       `json:"step"`
		Value      json.RawMessage            `json:"value"`
		Provenance *ProvenanceIDs             `json:"provenance"`
		Claims     map[string]json.RawMessage `json:"claims"`
		ExpMax     *int64                     `json:"exp_max"`
	}
	if err := strictjson.Unmarshal(b, strictjson.Limits{}, &raw); err != nil {
		return nil, err
	}
	var queries []int
	for i, s := range c.Steps {
		if s.Query != nil {
			queries = append(queries, i)
		}
	}
	if len(raw) != len(queries) {
		return nil, fmt.Errorf("%d entries for %d query steps: one per query step, in order", len(raw), len(queries))
	}
	out := []ExpectedSnapshot{}
	for i, r := range raw {
		where := fmt.Sprintf("[%d]", i)
		if r.Step == nil || r.Provenance == nil || len(r.Value) == 0 || r.Value[0] != '{' {
			return nil, fmt.Errorf("%s: step, an object value and provenance are required", where)
		}
		if *r.Step != queries[i] {
			return nil, fmt.Errorf("%s: step %d, but the query step in that place is %d: one entry per query step, in order", where, *r.Step, queries[i])
		}
		p := *r.Provenance
		if p.QualifiedEventIDs == nil || p.SupersededEventIDs == nil {
			return nil, fmt.Errorf("%s: provenance needs qualified_event_ids and superseded_event_ids", where)
		}
		s := ExpectedSnapshot{Step: *r.Step, Value: r.Value, Provenance: p, Claims: r.Claims, ExpMax: c.Steps[*r.Step].Now + SnapshotLifetime}
		if s.Claims == nil {
			s.Claims = map[string]json.RawMessage{}
		}
		if r.ExpMax != nil {
			s.ExpMax = *r.ExpMax
		}
		out = append(out, s)
	}
	return &out, nil
}

func (c *OutcomesCase) parseAcks(b []byte) (*[]ExpectedAck, error) {
	var acks []ExpectedAck
	if err := strictjson.Unmarshal(b, strictjson.Limits{}, &acks); err != nil {
		return nil, err
	}
	var ingests []int
	for i, s := range c.Steps {
		if s.Ingest != "" {
			ingests = append(ingests, i)
		}
	}
	if len(acks) != len(ingests) {
		return nil, fmt.Errorf("%d entries for %d ingest steps: one per ingest step, in order", len(acks), len(ingests))
	}
	for i, a := range acks {
		switch {
		case a.Step != ingests[i]:
			return nil, fmt.Errorf("[%d]: step %d, but the ingest step in that place is %d", i, a.Step, ingests[i])
		case (a.Status == nil) == (a.TransportCode == nil):
			return nil, fmt.Errorf("[%d]: exactly one of status and transport_code is null", i)
		case a.Status != nil && !a.Status.Valid():
			return nil, fmt.Errorf("[%d]: status %q is not ACCEPTED or DUPLICATE", i, *a.Status)
		case a.TransportCode != nil && *a.TransportCode == "":
			return nil, fmt.Errorf("[%d]: empty transport_code", i)
		}
	}
	return &acks, nil
}
