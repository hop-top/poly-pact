package evalcase

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
	"hop.top/pact-go/runner/manifest"
)

// StepKind is the kind of a learning step (spec/v1.0/fixtures/README.md, section
// steps.json).
type StepKind string

// Step kinds.
const (
	// StepPolicy installs a learning policy; StepArtifact registers a
	// manifest; StepEvent submits a lifecycle event; StepOutcome submits an
	// outcome report; StepAssessment hands the service an LLM assessment as
	// data.
	StepPolicy     StepKind = "policy"
	StepArtifact   StepKind = "artifact"
	StepEvent      StepKind = "event"
	StepOutcome    StepKind = "outcome"
	StepAssessment StepKind = "assessment"
)

// Valid reports whether k is a step kind.
func (k StepKind) Valid() bool {
	return slices.Contains([]StepKind{StepPolicy, StepArtifact, StepEvent, StepOutcome, StepAssessment}, k)
}

// LearningService is a service object of a learning config.json:
// learning_service, and reputation_service in a case with reports.
type LearningService struct {
	ServiceID     string `json:"service_id"`
	TenantID      string `json:"tenant_id"`
	EnvironmentID string `json:"environment_id"`
}

// Evaluator is what an evaluation reference resolves to.
type Evaluator struct {
	EvaluatorID string `json:"evaluator_id"`
}

// Gate is what the service observes for one artifact (config.json gates).
type Gate struct {
	ArtifactID         string             `json:"artifact_id"`
	Version            string             `json:"version"`
	IndependentTasks   int64              `json:"independent_tasks"`
	ObservationSeconds int64              `json:"observation_seconds"`
	TestSuitesPassed   []core.Digest      `json:"test_suites_passed"`
	Metrics            map[string]float64 `json:"metrics"`
}

// LearningConfig is the config.json of a learning case: the trusted
// configuration of the learning service (spec/v1.0/fixtures/README.md, section
// Learning cases, config.json). Absent optional members are zero.
type LearningConfig struct {
	Now                 int64
	ClockSkewSeconds    int64
	LearningService     LearningService
	Trust               []TrustRecord
	Evaluations         map[string]Evaluator
	SourceDataManifests map[string][]string
	Gates               []Gate
	// ReputationService is nil in a case without reports; Visibility and
	// ExecutorClasses are the outcomes-case members a case with reports
	// carries.
	ReputationService *LearningService
	Visibility        string
	ExecutorClasses   []ExecutorClass
}

// LearningStep is one step of steps.json. File is the signed file of the
// input, or the decoded file of an assessment, relative to the case
// directory; ReceivedAt is the service clock, by default the config's now.
type LearningStep struct {
	File       string
	Kind       StepKind
	ReceivedAt int64
}

// ActiveEntry is one entry of a registry's active array: a context and the
// artifact in force there, nil for the conservative set.
type ActiveEntry struct {
	Context  core.ReputationContext `json:"context"`
	Artifact *string                `json:"artifact"`
}

// AckEntry is an acknowledged step.
type AckEntry struct {
	Step   int            `json:"step"`
	Status core.AckStatus `json:"status"`
}

// RejectionEntry is a rejected step: the Section 13.4 code and the Section
// 16.5 reason codes.
type RejectionEntry struct {
	Step        int      `json:"step"`
	Code        string   `json:"code"`
	ReasonCodes []string `json:"reason_codes"`
}

// Registry is the registry state at the end of a case (README section
// registry.json). Artifacts and the artifact members name the signed
// manifest by its path; a consumer that compares with an implementation's
// output maps paths to artifact digests first.
type Registry struct {
	Artifacts            map[string]core.LifecycleState `json:"artifacts"`
	Active               []ActiveEntry                  `json:"active"`
	Acknowledgments      []AckEntry                     `json:"acknowledgments"`
	Rejections           []RejectionEntry               `json:"rejections"`
	Holds                []string                       `json:"holds"`
	ReevaluationRequired []string                       `json:"reevaluation_required"`
	// Subject is the RFC 6901 pointer to the entry the manifest outcome
	// summarizes; nil when the case is judged by the registry state alone.
	Subject *string `json:"subject"`
}

// LearningCase is a learning case: a manifest entry of kind learning, read
// with its configuration, steps, inputs and expected registry.
type LearningCase struct {
	// ID is the manifest id; Path the case directory, relative to the
	// fixture directory.
	ID, Path string
	Config   LearningConfig
	Steps    []LearningStep
	// Signed holds, by path relative to the case directory, the compact JWS
	// of every step that has a signed file. Assessments holds the decoded
	// assessment files the same way.
	Signed      map[string]string
	Assessments map[string]json.RawMessage
	// Expected is the expected registry.json at ExpectedPath, relative to
	// the fixture directory. Outcome is the manifest outcome.
	Expected     Registry
	ExpectedPath string
	Outcome      string
}

// ReadLearning reads the learning case id of the fixture directory fixtures
// (the directory of manifest.json). It does not verify the signed files and
// loads no private test key; a signature is the learning service's to check.
// It fails when the manifest does not list id as an entry of kind learning,
// when a file is missing or is not strict JSON of its format, when a step
// names a file that is not a path inside the case or does not exist, or when
// the expected registry is inconsistent with the steps and with the manifest
// outcome: a step that is not a service input acknowledged, a rejection of
// an assessment, or a subject that does not name an entry of the kind the
// outcome says.
func ReadLearning(fixtures, id string) (*LearningCase, error) {
	m, err := manifest.Load(fixtures)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", manifest.FileName, err)
	}
	i := slices.IndexFunc(m.Entries, func(e manifest.Entry) bool { return e.ID == id })
	if i < 0 {
		return nil, fmt.Errorf("%s: no manifest entry", id)
	}
	e := m.Entries[i]
	if e.Kind != manifest.KindLearning {
		return nil, fmt.Errorf("%s: manifest kind %s, not %s", id, e.Kind, manifest.KindLearning)
	}
	if e.Expected == nil || e.Outcome == nil {
		return nil, fmt.Errorf("%s: the manifest entry names no expected file or outcome", id)
	}
	dir := filepath.Join(fixtures, filepath.FromSlash(e.Path))
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("%s: path %s is not a case directory", id, e.Path)
	}
	c := &LearningCase{ID: id, Path: e.Path, ExpectedPath: *e.Expected, Outcome: *e.Outcome,
		Signed: map[string]string{}, Assessments: map[string]json.RawMessage{}}
	if err := c.readConfig(filepath.Join(dir, "config.json")); err != nil {
		return nil, fmt.Errorf("%s/config.json: %w", id, err)
	}
	if err := c.readSteps(dir); err != nil {
		return nil, fmt.Errorf("%s/steps.json: %w", id, err)
	}
	if err := c.readExpected(filepath.Join(fixtures, filepath.FromSlash(*e.Expected))); err != nil {
		return nil, fmt.Errorf("%s: expected file %s: %w", id, *e.Expected, err)
	}
	return c, nil
}

func (c *LearningCase) readConfig(p string) error {
	var f struct {
		Now                 *int64               `json:"now"`
		ClockSkewSeconds    *int64               `json:"clock_skew_seconds"`
		LearningService     *LearningService     `json:"learning_service"`
		Trust               *[]TrustRecord       `json:"trust"`
		Evaluations         map[string]Evaluator `json:"evaluations"`
		SourceDataManifests map[string][]string  `json:"source_data_manifests"`
		Gates               []Gate               `json:"gates"`
		ReputationService   *LearningService     `json:"reputation_service"`
		Visibility          string               `json:"visibility"`
		ExecutorClasses     []ExecutorClass      `json:"executor_classes"`
	}
	if err := readStrict(p, &f); err != nil {
		return err
	}
	switch {
	case f.Now == nil:
		return errors.New("now is required")
	case f.ClockSkewSeconds == nil:
		return errors.New("clock_skew_seconds is required")
	case f.LearningService == nil || f.LearningService.ServiceID == "":
		return errors.New("learning_service.service_id is required")
	case f.Trust == nil:
		return errors.New("trust is required")
	}
	c.Config = LearningConfig{
		Now: *f.Now, ClockSkewSeconds: *f.ClockSkewSeconds, LearningService: *f.LearningService, Trust: *f.Trust,
		Evaluations: f.Evaluations, SourceDataManifests: f.SourceDataManifests, Gates: f.Gates,
		ReputationService: f.ReputationService, Visibility: f.Visibility, ExecutorClasses: f.ExecutorClasses,
	}
	return nil
}

func (c *LearningCase) readSteps(dir string) error {
	var raw []struct {
		File       *string `json:"file"`
		Kind       *string `json:"kind"`
		ReceivedAt *int64  `json:"received_at"`
	}
	if err := readStrict(filepath.Join(dir, "steps.json"), &raw); err != nil {
		return err
	}
	if len(raw) == 0 {
		return errors.New("empty: a case has at least one step")
	}
	for i, r := range raw {
		where := fmt.Sprintf("steps[%d]", i)
		if r.File == nil || r.Kind == nil {
			return fmt.Errorf("%s: file and kind are required", where)
		}
		s := LearningStep{File: *r.File, Kind: StepKind(*r.Kind), ReceivedAt: c.Config.Now}
		if r.ReceivedAt != nil {
			s.ReceivedAt = *r.ReceivedAt
		}
		if !s.Kind.Valid() {
			return fmt.Errorf("%s: kind %q is not policy, artifact, event, outcome or assessment", where, s.Kind)
		}
		if !relPath.MatchString(s.File) {
			return fmt.Errorf("%s: %q is not a relative path inside the case", where, s.File)
		}
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(s.File)))
		if err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		if s.Kind == StepAssessment {
			if !json.Valid(b) {
				return fmt.Errorf("%s: %s is not JSON", where, s.File)
			}
			c.Assessments[s.File] = b
		} else {
			c.Signed[s.File] = string(b)
		}
		c.Steps = append(c.Steps, s)
	}
	return nil
}

func (c *LearningCase) readExpected(p string) error {
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	if err := strictjson.Unmarshal(b, strictjson.Limits{}, &c.Expected); err != nil {
		return err
	}
	r := &c.Expected
	// A required member that is absent decodes to nil; strict decoding
	// rejects a null.
	for _, m := range []struct {
		name    string
		missing bool
	}{{"artifacts", r.Artifacts == nil}, {"active", r.Active == nil}, {"acknowledgments", r.Acknowledgments == nil}, {"rejections", r.Rejections == nil}} {
		if m.missing {
			return fmt.Errorf("%s is required", m.name)
		}
	}
	r.Holds = nonNil(r.Holds)
	r.ReevaluationRequired = nonNil(r.ReevaluationRequired)
	for path, st := range r.Artifacts {
		if !st.Valid() {
			return fmt.Errorf("artifacts: %s has state %q, not a lifecycle state of draft Section 16.5", path, st)
		}
		if _, ok := c.Signed[path]; !ok {
			return fmt.Errorf("artifacts: %s is not the signed file of a step", path)
		}
	}
	for _, p := range append(slices.Clone(r.ReevaluationRequired), activePaths(r.Active)...) {
		if _, ok := c.Signed[p]; !ok {
			return fmt.Errorf("%s is not the signed file of a step", p)
		}
	}
	seen := map[int]bool{}
	for i, a := range r.Acknowledgments {
		if err := c.checkStep(seen, a.Step, "acknowledgments", i, StepArtifact, StepEvent, StepOutcome); err != nil {
			return err
		}
		if !a.Status.Valid() {
			return fmt.Errorf("acknowledgments[%d]: status %q is not ACCEPTED or DUPLICATE", i, a.Status)
		}
	}
	for i, x := range r.Rejections {
		if err := c.checkStep(seen, x.Step, "rejections", i, StepPolicy, StepArtifact, StepEvent, StepOutcome); err != nil {
			return err
		}
		if x.Code == "" {
			return fmt.Errorf("rejections[%d]: code is required", i)
		}
	}
	return c.checkSubject()
}

func activePaths(a []ActiveEntry) []string {
	var out []string
	for _, e := range a {
		if e.Artifact != nil {
			out = append(out, *e.Artifact)
		}
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// checkStep checks that step names a step of one of the kinds and is not
// named twice among the acknowledgments and rejections.
func (c *LearningCase) checkStep(seen map[int]bool, step int, member string, i int, kinds ...StepKind) error {
	if step < 0 || step >= len(c.Steps) {
		return fmt.Errorf("%s[%d]: step %d is not a step of the case (%d steps)", member, i, step, len(c.Steps))
	}
	if !slices.Contains(kinds, c.Steps[step].Kind) {
		return fmt.Errorf("%s[%d]: step %d is a %s step, which the service does not answer that way", member, i, step, c.Steps[step].Kind)
	}
	if seen[step] {
		return fmt.Errorf("%s[%d]: step %d is acknowledged or rejected twice", member, i, step)
	}
	seen[step] = true
	return nil
}

// checkSubject checks the subject pointer against the registry and the
// manifest outcome: ACCEPTED names an acknowledgment, REJECTED a rejection
// and MATCH none.
func (c *LearningCase) checkSubject() error {
	r := c.Expected
	if r.Subject == nil {
		if c.Outcome != "MATCH" {
			return fmt.Errorf("no subject, but the manifest outcome is %s, not MATCH", c.Outcome)
		}
		return nil
	}
	var member string
	var n int
	switch c.Outcome {
	case "ACCEPTED":
		member, n = "acknowledgments", len(r.Acknowledgments)
	case "REJECTED":
		member, n = "rejections", len(r.Rejections)
	default:
		return fmt.Errorf("subject %q, but the manifest outcome is %s: a subject goes with ACCEPTED or REJECTED, and MATCH has none", *r.Subject, c.Outcome)
	}
	rest, ok := strings.CutPrefix(*r.Subject, "/"+member+"/")
	i, err := strconv.Atoi(rest)
	if !ok || err != nil || i < 0 || i >= n || strconv.Itoa(i) != rest {
		return fmt.Errorf("subject %q names no entry of %s (%d entries); the manifest outcome %s needs one", *r.Subject, member, n, c.Outcome)
	}
	return nil
}
