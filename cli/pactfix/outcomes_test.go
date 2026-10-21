package main

import (
	"bytes"
	"fmt"
	"maps"
	"math"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/runner/manifest"
)

// mappingCases are the outcome mapping cases of draft Section 14.5, the
// fixture ids of spec-map row CL-14.1.
var mappingCases = []string{
	"outcomes/mapping/accepted-restart-as-completed",
	"outcomes/mapping/admission-as-task-success",
	"outcomes/mapping/assessment-as-reliability",
	"outcomes/mapping/async-accept-then-complete",
	"outcomes/mapping/denial-as-misconduct",
	"outcomes/mapping/denial-as-policy-violation",
	"outcomes/mapping/execution-as-policy-adherence",
	"outcomes/mapping/hidden-row-read-as-task-success",
	"outcomes/mapping/incident-without-record",
	"outcomes/mapping/policy-violation-as-adherence-failure",
	"outcomes/mapping/visibility-unavailable",
}

// outcomeConfig is config.json of an outcome mapping case.
type outcomeConfig struct {
	Now              int64 `json:"now"`
	ClockSkewSeconds int64 `json:"clock_skew_seconds"`
	DataPolicy       struct {
		QualificationPolicyID    string `json:"qualification_policy_id"`
		IngestionWindowSeconds   int64  `json:"ingestion_window_seconds"`
		PositiveWeightCapPerTask int64  `json:"positive_weight_cap_per_task"`
		MaximumFailureWeight     int64  `json:"maximum_failure_weight"`
		TaskAttributionSource    string `json:"task_attribution_source"`
		IndependencePolicyID     string `json:"reporter_independence_policy_id"`
	} `json:"data_policy"`
	Visibility        string `json:"visibility"`
	ReputationService struct {
		ServiceID     string `json:"service_id"`
		TenantID      string `json:"tenant_id"`
		EnvironmentID string `json:"environment_id"`
	} `json:"reputation_service"`
	Trust []struct {
		Iss          string            `json:"iss"`
		Role         string            `json:"role"`
		ReporterRole core.ReporterRole `json:"reporter_role"`
		Keys         []string          `json:"keys"`
	} `json:"trust"`
	ExecutorClasses []struct {
		PrincipalID string `json:"principal_id"`
		TaskID      string `json:"task_id"`
		OperationID string `json:"operation_id"`
		Class       string `json:"class"`
	} `json:"executor_classes"`
}

// nativeRecord is one immutable native record of native_context.json.
type nativeRecord struct {
	Kind        string  `json:"kind"`
	State       string  `json:"state"`
	Returned    *string `json:"returned"`
	TaskID      string  `json:"task_id"`
	OperationID string  `json:"operation_id"`
	// Executor is null for a record that names no executor, such as a
	// violation record (spec/v1.0/fixtures/README.md, native_context.json).
	Executor *struct {
		Class       string `json:"class"`
		PrincipalID string `json:"principal_id"`
	} `json:"executor"`
	ObservedAt int64 `json:"observed_at"`
}

// outcomeNative is native_context.json of an outcome mapping case.
type outcomeNative struct {
	Tasks []struct {
		TaskID            string `json:"task_id"`
		AgentID           string `json:"agent_id"`
		OperatorID        string `json:"operator_id"`
		PrincipalID       string `json:"principal_id"`
		IndependenceGroup string `json:"independence_group"`
	} `json:"tasks"`
	Records map[string]nativeRecord `json:"records"`
}

// weight is a contribution in weight units of draft Section 15.3.
type weight struct {
	Positive int `json:"positive"`
	Negative int `json:"negative"`
}

// qualificationFile is expected/<case>/classifications.json.
type qualificationFile struct {
	Case             string `json:"case"`
	AdversarialClaim string `json:"adversarial_claim"`
	SubjectEventID   string `json:"subject_event_id"`
	Events           []struct {
		EventID       string `json:"event_id"`
		Report        string `json:"report"`
		Signed        string `json:"signed"`
		Qualification string `json:"qualification"`
		Reason        string `json:"reason"`
		Contribution  struct {
			Dimension core.Dimension `json:"dimension"`
			weight
		} `json:"contribution"`
		Rationale string `json:"rationale"`
	} `json:"events"`
	DimensionDeltas map[core.Dimension]weight `json:"dimension_deltas"`
}

// reasons are the reason tokens of outcomes/mapping/README.md.
var reasons = map[string]string{
	"mapped":                  "QUALIFIED",
	"invalid-report":          "UNQUALIFIED",
	"no-executor-record":      "UNQUALIFIED",
	"no-completion-record":    "UNQUALIFIED",
	"reporter-not-authorized": "UNQUALIFIED",
	"record-mismatch":         "UNQUALIFIED",
	"no-assessment-record":    "UNQUALIFIED",
}

var mandatoryDimensions = []core.Dimension{core.DimensionReliability, core.DimensionTaskQuality, core.DimensionPolicyAdherence}

func strictFile(t testing.TB, p string, v any) {
	t.Helper()
	if err := strictjson.Unmarshal(readFile(t, p), strictjson.Limits{}, v); err != nil {
		t.Fatalf("%s: %v", p, err)
	}
}

// loadOutcomeCase reads a mapping case from the fixture directory root: its
// configuration, native context, decoded reports by file name, and expected
// qualification.
func loadOutcomeCase(t testing.TB, root, id string) (outcomeConfig, outcomeNative, map[string]core.OutcomeReport, qualificationFile) {
	t.Helper()
	dir := filepath.Join(root, filepath.FromSlash(id))
	var cfg outcomeConfig
	strictFile(t, filepath.Join(dir, "config.json"), &cfg)
	var nat outcomeNative
	strictFile(t, filepath.Join(dir, "native_context.json"), &nat)
	files, err := filepath.Glob(filepath.Join(dir, "reports", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("%s: no reports (%v)", id, err)
	}
	reports := map[string]core.OutcomeReport{}
	for _, f := range files {
		var r core.OutcomeReport
		strictFile(t, f, &r)
		reports["reports/"+filepath.Base(f)] = r
	}
	var q qualificationFile
	strictFile(t, filepath.Join(root, "expected", filepath.FromSlash(id), "classifications.json"), &q)
	return cfg, nat, reports, q
}

// TestOutcomeMappingCasesAreGenerated: generate signs exactly the mapping
// cases; each signs every decoded report with the reporter stand-in key
// (vectors/jws/README.md) as pact-outcome+jwt and builds no presentation.
func TestOutcomeMappingCasesAreGenerated(t *testing.T) {
	runs := repoRuns(t, "outcomes/mapping/")
	var known []string
	for _, r := range runs {
		known = append(known, r.Entry)
	}
	if !slices.Equal(known, mappingCases) {
		t.Fatalf("generate knows %v, want %v", known, mappingCases)
	}
	for _, r := range runs {
		if len(r.Signing.Presentations) != 0 {
			t.Errorf("%s: an outcome case has no presentation", r.Entry)
		}
		files, _ := filepath.Glob(filepath.Join(repoFixtures, filepath.FromSlash(r.Path), "reports", "*.json"))
		var want, got []string
		for _, f := range files {
			want = append(want, "reports/"+filepath.Base(f))
		}
		for _, a := range r.Signing.Artifacts {
			got = append(got, a.Decoded)
			name := strings.TrimSuffix(path.Base(a.Decoded), ".json")
			if a.Signed != "signed/"+name+".jws" || a.Typ != jws.TypOutcome || a.Signer != "issuer" ||
				a.Iat != nil || a.Nbf != nil || a.Exp != nil || a.Digests != nil || a.PayloadSigned != nil {
				t.Errorf("%s: %+v", r.Entry, a)
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: generate signs %v, the case holds %v", r.Entry, got, want)
		}
	}
}

// TestGenerateSignsOutcomeReports: on a tree without signed files, every
// report is signed; each signed file verifies as pact-outcome+jwt under the
// issuer test key and its payload is the decoded report byte for byte.
func TestGenerateSignsOutcomeReports(t *testing.T) {
	root := unsignedTree(t)
	res := mustGenerate(t, root, false)
	written := map[string]bool{}
	for _, r := range res {
		written[r.File] = r.Changed
	}
	for _, id := range mappingCases {
		dir := filepath.Join(root, filepath.FromSlash(id))
		files, _ := filepath.Glob(filepath.Join(dir, "reports", "*.json"))
		if len(files) == 0 {
			t.Fatalf("%s: no reports in the unsigned tree", id)
		}
		for _, f := range files {
			name := strings.TrimSuffix(filepath.Base(f), ".json")
			if !written[id+"/signed/"+name+".jws"] {
				t.Errorf("%s: signed/%s.jws not written", id, name)
			}
			p := verifyAs(t, string(readFile(t, filepath.Join(dir, "signed", name+".jws"))), jws.TypOutcome, "issuer")
			if !bytes.Equal(p.Payload, readFile(t, f)) {
				t.Errorf("%s: signed/%s.jws payload is not reports/%s.json", id, name, name)
			}
		}
		if _, err := os.Stat(filepath.Join(dir, "signed", "presentation.jws")); err == nil {
			t.Errorf("%s: a presentation was written", id)
		}
	}
}

// TestOutcomeReportsAreBound: every report decodes strictly as an
// OutcomeReport and is bound to its case as draft Sections 14.1 to 14.3 and
// A.2 require of a report the receiver verifies: a registered reporter of
// that role, the reputation service as audience, the recorded task and its
// agent, a lifetime of at most 300 seconds, an observation inside the
// ingestion window, and evidence references that name native records of
// its task and operation, except in a report the case classifies
// record-mismatch for citing the record of another operation.
func TestOutcomeReportsAreBound(t *testing.T) {
	for _, id := range mappingCases {
		cfg, nat, reports, q := loadOutcomeCase(t, repoFixtures, id)
		mismatch := map[string]bool{}
		for _, e := range q.Events {
			mismatch[e.EventID] = e.Reason == "record-mismatch"
		}
		dp := cfg.DataPolicy
		if dp.QualificationPolicyID != "pact-qualification-v1" || dp.IndependencePolicyID != "pact-reporter-independence-v1" {
			t.Errorf("%s: policies %q %q, want the baselines of 14.6", id, dp.QualificationPolicyID, dp.IndependencePolicyID)
		}
		if dp.IngestionWindowSeconds != 7*86400 {
			t.Errorf("%s: ingestion window %d, want the 7-day baseline of 14.3", id, dp.IngestionWindowSeconds)
		}
		// The other members are those of the B.9 data policy.
		if dp.PositiveWeightCapPerTask != 1 || dp.MaximumFailureWeight != 5 || dp.TaskAttributionSource != "native-task-registry" {
			t.Errorf("%s: data policy %+v, want the B.9 values", id, dp)
		}
		if cfg.Visibility != "execution" && cfg.Visibility != "none" {
			t.Errorf("%s: visibility %q", id, cfg.Visibility)
		}
		events := map[string]bool{}
		for file, r := range reports {
			where := id + "/" + file
			if "reports/"+r.EventID+".json" != file {
				t.Errorf("%s: event_id %q does not name the file", where, r.EventID)
			}
			if events[r.EventID] {
				t.Errorf("%s: event_id %q repeated", where, r.EventID)
			}
			events[r.EventID] = true
			if r.PactVersion != "0.1" || !r.EventKind.Valid() || !r.Result.Valid() || !r.Dimension.Valid() ||
				!r.Severity.Valid() || !r.ReporterRole.Valid() || !r.Attribution.CausalAssessment.Valid() {
				t.Errorf("%s: a member has an undefined value", where)
			}
			if r.IssuedAt != evalcase.FixedTime || r.NotBefore != evalcase.FixedTime || r.Expiry <= r.IssuedAt || r.Expiry-r.IssuedAt > 300 {
				t.Errorf("%s: iat %d nbf %d exp %d", where, r.IssuedAt, r.NotBefore, r.Expiry)
			}
			if len(r.JTI) < 22 {
				t.Errorf("%s: jti %q has under 128 bits", where, r.JTI)
			}
			if r.Audience != cfg.ReputationService.ServiceID || r.TenantID != cfg.ReputationService.TenantID ||
				r.EnvironmentID != cfg.ReputationService.EnvironmentID ||
				r.Context.TenantID != r.TenantID || r.Context.EnvironmentID != r.EnvironmentID || r.Context.AgentID != r.Subject {
				t.Errorf("%s: audience, realm or context does not match the reputation service", where)
			}
			if !slices.ContainsFunc(cfg.Trust, func(tr struct {
				Iss          string            `json:"iss"`
				Role         string            `json:"role"`
				ReporterRole core.ReporterRole `json:"reporter_role"`
				Keys         []string          `json:"keys"`
			}) bool {
				return tr.Iss == r.Issuer && tr.Role == "reporter" && tr.ReporterRole == r.ReporterRole && slices.Equal(tr.Keys, []string{"keys/issuer.jwk.json"})
			}) {
				t.Errorf("%s: %s is not registered as reporter %s", where, r.Issuer, r.ReporterRole)
			}
			i := slices.IndexFunc(nat.Tasks, func(task struct {
				TaskID            string `json:"task_id"`
				AgentID           string `json:"agent_id"`
				OperatorID        string `json:"operator_id"`
				PrincipalID       string `json:"principal_id"`
				IndependenceGroup string `json:"independence_group"`
			}) bool {
				return task.TaskID == r.TaskID
			})
			if i < 0 {
				t.Errorf("%s: task %s is not recorded", where, r.TaskID)
			} else if task := nat.Tasks[i]; task.AgentID != r.Subject || task.IndependenceGroup != r.Attribution.IndependenceGroup || r.Attribution.NativeTaskRef != r.TaskID {
				t.Errorf("%s: subject or attribution does not match the recorded task", where)
			}
			if r.ObservedAt < cfg.Now-cfg.DataPolicy.IngestionWindowSeconds || r.ObservedAt > cfg.Now+cfg.ClockSkewSeconds {
				t.Errorf("%s: observed_at %d outside the ingestion window", where, r.ObservedAt)
			}
			if r.EventKind == core.EventCorrection || len(r.Supersedes) != 0 {
				t.Errorf("%s: a mapping case holds no correction", where)
			}
			for _, ref := range r.EvidenceRefs {
				rec, ok := nat.Records[ref]
				if !ok {
					t.Errorf("%s: evidence_ref %s names no native record", where, ref)
				} else if rec.TaskID != r.TaskID || rec.OperationID != r.OperationID && !mismatch[r.EventID] {
					t.Errorf("%s: evidence_ref %s is a record of another task or operation", where, ref)
				}
			}
		}
	}
}

// mappingRow is a row of the draft Section 14.5 table that yields a report.
type mappingRow struct {
	observation string
	kinds       []core.EventKind
	// reporter is the only reporter_role the row admits ("reported by `x`
	// only"), or "" when the row names none.
	reporter  core.ReporterRole
	results   []core.OutcomeResult
	dimension core.Dimension
	counts    bool // "Counts toward" the dimension, else "Zero weight"
	// violation: the row's evidence is "the gateway's immutable record of
	// the violating request" (Section 14.2).
	violation bool
	// incident: the row's evidence is "the confirmed incident record of its
	// task and operation" (Section 15.4).
	incident bool
	// assessment: the row's evidence is "the completed assessment", except
	// for the agent's own diagnostic.
	assessment bool
}

// draftMapping parses the table of draft Section 14.5.
func draftMapping(t testing.TB) []mappingRow {
	t.Helper()
	draft := string(readFile(t, filepath.Join(repoSpec, "draft.md")))
	start := strings.Index(draft, "\n### 14.5 ")
	end := strings.Index(draft, "\n### 14.6 ")
	if start < 0 || end < start {
		t.Fatal("draft has no Section 14.5")
	}
	tick := regexp.MustCompile("`([A-Za-z_]+)`")
	var rows []mappingRow
	for _, line := range strings.Split(draft[start:end], "\n") {
		cells := strings.Split(strings.Trim(line, "| "), " | ")
		if !strings.HasPrefix(line, "| ") || len(cells) != 5 {
			continue
		}
		row := mappingRow{observation: cells[0]}
		for _, m := range tick.FindAllStringSubmatch(cells[1], -1) {
			switch k, role := core.EventKind(m[1]), core.ReporterRole(m[1]); {
			case k.Valid():
				row.kinds = append(row.kinds, k)
			case role.Valid() && strings.Contains(cells[1], "reported by `"+m[1]+"` only"):
				row.reporter = role
			}
		}
		dims := tick.FindAllStringSubmatch(cells[3], -1)
		if len(row.kinds) == 0 || len(dims) != 1 {
			continue // header, separator, or a row that fixes no report
		}
		row.dimension = core.Dimension(dims[0][1])
		row.violation = strings.Contains(cells[4], "record of the violating request")
		row.incident = strings.Contains(cells[4], "confirmed incident record of its task and operation")
		row.assessment = strings.Contains(cells[4], "cites the completed assessment")
		for _, m := range tick.FindAllStringSubmatch(cells[2], -1) {
			row.results = append(row.results, core.OutcomeResult(m[1]))
		}
		switch {
		case strings.HasPrefix(cells[4], "Counts toward"):
			row.counts = true
		case strings.HasPrefix(cells[4], "Zero weight"):
		default:
			t.Fatalf("14.5 row %q: effect %q is neither zero weight nor counted", cells[0], cells[4])
		}
		rows = append(rows, row)
	}
	if len(rows) != 16 {
		t.Fatalf("14.5 table: %d report rows, want 16", len(rows))
	}
	return rows
}

// a2Rules are the A.2 dimension rules, each with its sentence in the draft.
var a2Rules = []struct {
	text    string
	invalid func(core.OutcomeReport) bool
}{
	{"`ADMISSION` and `AUTHORIZATION` events MUST use dimension `none`.", func(r core.OutcomeReport) bool {
		return (r.EventKind == core.EventAdmission || r.EventKind == core.EventAuthorization) && r.Dimension != core.DimensionNone
	}},
	{"An `OutcomeReport` with `result` `UNKNOWN` MUST use dimension `none`, except a `CORRECTION`, which carries the `dimension` of the events it supersedes whatever its `result` (Section 14.6, rule 10).", func(r core.OutcomeReport) bool {
		return r.Result == core.OutcomeUnknown && r.Dimension != core.DimensionNone && r.EventKind != core.EventCorrection
	}},
	{"An `OutcomeReport` uses a `dimension` that Section 14.5 gives its `event_kind`: `EXECUTION` uses `reliability` or `none`; `QUALITY` and `FEEDBACK` use `task_quality` or `policy_adherence`; `SECURITY` uses `policy_adherence` or `none`; `REMEDIATION` uses `none`; a `CORRECTION` carries the `dimension` of the events it supersedes (Section 14.6, rule 10). Any other pair is invalid: an `EXECUTION` report on `task_quality` or `policy_adherence` is not an assessment, and a `QUALITY` or `FEEDBACK` report on `reliability` is not an execution record.", func(r core.OutcomeReport) bool {
		allowed := map[core.EventKind][]core.Dimension{
			core.EventAdmission:     {core.DimensionNone},
			core.EventAuthorization: {core.DimensionNone},
			core.EventExecution:     {core.DimensionReliability, core.DimensionNone},
			core.EventQuality:       {core.DimensionTaskQuality, core.DimensionPolicyAdherence},
			core.EventFeedback:      {core.DimensionTaskQuality, core.DimensionPolicyAdherence},
			core.EventSecurity:      {core.DimensionPolicyAdherence, core.DimensionNone},
			core.EventRemediation:   {core.DimensionNone},
		}
		dims, ok := allowed[r.EventKind]
		return ok && !slices.Contains(dims, r.Dimension)
	}},
}

func violatesA2(r core.OutcomeReport) bool {
	return slices.ContainsFunc(a2Rules, func(rule struct {
		text    string
		invalid func(core.OutcomeReport) bool
	}) bool {
		return rule.invalid(r)
	})
}

// TestOutcomeMappingExpectedFollowsDraft: the expected qualification of every
// report is derived from the draft, independently of the expected file:
// "mapped" reports match a 14.5 row and break no A.2 rule, "invalid-report"
// reports break an A.2 rule, "no-executor-record" and "no-completion-record"
// reports lack the native record that 14.2 and 14.5 require, and the weight
// follows the row's effect, capped at one positive unit per task group and
// dimension (15.3).
func TestOutcomeMappingExpectedFollowsDraft(t *testing.T) {
	draft := string(readFile(t, filepath.Join(repoSpec, "draft.md")))
	for _, rule := range a2Rules {
		if !strings.Contains(draft, "- "+rule.text+"\n") {
			t.Fatalf("draft A.2 no longer says %q", rule.text)
		}
	}
	rows := draftMapping(t)
	for _, id := range mappingCases {
		cfg, nat, reports, q := loadOutcomeCase(t, repoFixtures, id)
		byEvent := map[string]core.OutcomeReport{}
		for _, r := range reports {
			byEvent[r.EventID] = r
		}
		positives := map[string]int{}
		for _, e := range q.Events {
			where := id + " " + e.EventID
			r, ok := byEvent[e.EventID]
			if !ok {
				t.Errorf("%s: no report", where)
				continue
			}
			executorOK := len(r.EvidenceRefs) > 0
			completed := false
			for _, ref := range r.EvidenceRefs {
				rec := nat.Records[ref]
				declared := slices.ContainsFunc(cfg.ExecutorClasses, func(m struct {
					PrincipalID string `json:"principal_id"`
					TaskID      string `json:"task_id"`
					OperationID string `json:"operation_id"`
					Class       string `json:"class"`
				}) bool {
					return rec.Executor != nil && m.TaskID == r.TaskID && m.OperationID == r.OperationID && m.Class == rec.Executor.Class && m.PrincipalID == rec.Executor.PrincipalID
				})
				executorOK = executorOK && declared
				completed = completed || (rec.Kind == "execution" && (rec.State == "completed" || rec.State == "failed"))
			}
			needsExecutor := r.EventKind == core.EventExecution || r.EventKind == core.EventAuthorization
			// The 14.5 row for absent visibility fixes evidence_refs empty.
			declaredAbsence := r.EventKind == core.EventExecution && r.Result == core.OutcomeUnknown &&
				len(r.EvidenceRefs) == 0 && cfg.Visibility == "none"
			// A report matches the first row with its kind, result and
			// dimension; the absent-visibility row matches only a declared
			// absence, and a declared absence matches only that row.
			var row *mappingRow
			// restricted: a row of the report's kind admits only its
			// reporter_role, and so any other report of that kind from it
			// is UNQUALIFIED (the detected policy violation row).
			restricted := false
			for i := range rows {
				absenceRow := strings.Contains(rows[i].observation, "visibility unavailable")
				if !slices.Contains(rows[i].kinds, r.EventKind) || rows[i].reporter != "" && rows[i].reporter != r.ReporterRole {
					continue
				}
				restricted = restricted || rows[i].reporter == r.ReporterRole
				if rows[i].dimension == r.Dimension && slices.Contains(rows[i].results, r.Result) && absenceRow == declaredAbsence {
					row = &rows[i]
					break
				}
			}
			citesViolation := slices.ContainsFunc(r.EvidenceRefs, func(ref string) bool {
				rec, ok := nat.Records[ref]
				return ok && rec.Kind == "violation" && rec.State == "recorded" && rec.TaskID == r.TaskID && rec.OperationID == r.OperationID
			})
			citesRecord := func(kind, state string, sameOperation bool) bool {
				return slices.ContainsFunc(r.EvidenceRefs, func(ref string) bool {
					rec, ok := nat.Records[ref]
					return ok && rec.Kind == kind && rec.State == state && rec.TaskID == r.TaskID && (!sameOperation || rec.OperationID == r.OperationID)
				})
			}
			var want string
			switch {
			case violatesA2(r):
				want = "invalid-report"
			case needsExecutor && !executorOK && !declaredAbsence:
				want = "no-executor-record"
			case r.EventKind == core.EventExecution && (r.Result == core.OutcomeSuccess || r.Result == core.OutcomeFailure) && !completed:
				want = "no-completion-record"
			case row != nil && row.violation && !citesViolation:
				want = "record-mismatch"
			case row != nil && row.incident && !citesRecord("incident", "confirmed", true):
				want = "record-mismatch"
			case row != nil && row.assessment && r.ReporterRole != core.ReporterAgent && !citesRecord("assessment", "completed", false):
				want = "no-assessment-record"
			case row != nil:
				want = "mapped"
			case restricted:
				want = "reporter-not-authorized"
			default:
				t.Errorf("%s: %s %s %s matches no 14.5 row", where, r.EventKind, r.Result, r.Dimension)
				continue
			}
			if e.Reason != want || e.Qualification != reasons[want] {
				t.Errorf("%s: %s with reason %s, want %s with reason %s", where, e.Qualification, e.Reason, reasons[want], want)
			}
			var w weight
			if want == "mapped" && row.counts {
				switch r.Result {
				case core.OutcomeSuccess:
					if positives[r.Attribution.IndependenceGroup+"|"+string(r.Dimension)] == 0 {
						w.Positive = 1
					}
					positives[r.Attribution.IndependenceGroup+"|"+string(r.Dimension)]++
				case core.OutcomeFailure:
					if r.Attribution.CausalAssessment == core.CausalAgent {
						w.Negative = 1
					}
				}
			}
			if e.Contribution.weight != w || e.Contribution.Dimension != r.Dimension {
				t.Errorf("%s: contribution %+v, want %s %+v", where, e.Contribution, r.Dimension, w)
			}
		}
	}
}

// TestOutcomeMappingExpectedIsComplete: each expected file covers every
// report of its case once, uses the reason tokens of the README, sums the
// contributions into the dimension deltas, and its subject event carries the
// manifest outcome of the case.
func TestOutcomeMappingExpectedIsComplete(t *testing.T) {
	m, err := manifest.Load(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range mappingCases {
		_, _, reports, q := loadOutcomeCase(t, repoFixtures, id)
		if q.Case != id || q.AdversarialClaim == "" {
			t.Errorf("%s: case %q, adversarial claim %q", id, q.Case, q.AdversarialClaim)
		}
		var listed []string
		sum := map[core.Dimension]weight{}
		subject := ""
		for _, e := range q.Events {
			listed = append(listed, e.Report)
			r, ok := reports[e.Report]
			if !ok || r.EventID != e.EventID || e.Signed != "signed/"+e.EventID+".jws" {
				t.Errorf("%s: event %s names report %s and %s", id, e.EventID, e.Report, e.Signed)
			}
			if _, err := os.Stat(filepath.Join(repoFixtures, filepath.FromSlash(id), filepath.FromSlash(e.Signed))); err != nil {
				t.Errorf("%s: %v", id, err)
			}
			if q, ok := reasons[e.Reason]; !ok || q != e.Qualification {
				t.Errorf("%s: event %s: %s with reason %q", id, e.EventID, e.Qualification, e.Reason)
			}
			if e.Qualification != "QUALIFIED" && e.Contribution.weight != (weight{}) {
				t.Errorf("%s: event %s is %s but contributes %+v", id, e.EventID, e.Qualification, e.Contribution.weight)
			}
			if e.Contribution.Dimension == core.DimensionNone && e.Contribution.weight != (weight{}) {
				t.Errorf("%s: event %s contributes to dimension none", id, e.EventID)
			}
			if e.Rationale == "" {
				t.Errorf("%s: event %s has no rationale", id, e.EventID)
			}
			if e.Contribution.Dimension != core.DimensionNone {
				s := sum[e.Contribution.Dimension]
				s.Positive += e.Contribution.Positive
				s.Negative += e.Contribution.Negative
				sum[e.Contribution.Dimension] = s
			}
			if e.EventID == q.SubjectEventID {
				subject = e.Qualification
			}
		}
		var files []string
		for f := range reports {
			files = append(files, f)
		}
		slices.Sort(files)
		slices.Sort(listed)
		if !slices.Equal(listed, files) {
			t.Errorf("%s: expected lists %v, the case holds %v", id, listed, files)
		}
		if len(q.DimensionDeltas) != len(mandatoryDimensions) {
			t.Errorf("%s: deltas %v, want the three mandatory dimensions", id, q.DimensionDeltas)
		}
		for _, d := range mandatoryDimensions {
			if q.DimensionDeltas[d] != sum[d] {
				t.Errorf("%s: delta %s %+v, contributions sum to %+v", id, d, q.DimensionDeltas[d], sum[d])
			}
		}
		i := slices.IndexFunc(m.Entries, func(e manifest.Entry) bool { return e.ID == id })
		if i < 0 {
			t.Errorf("%s: not in the manifest", id)
			continue
		}
		e := m.Entries[i]
		want := fmt.Sprintf("outcomes runner %s expected/%s/classifications.json %s CL-14.1 14.5", id, id, subject)
		got := fmt.Sprintf("%s %s %s %s %s %s %s", e.Kind, e.Scope, e.Path, deref(e.Expected), deref(e.Outcome), e.SpecMapRow, e.DraftSection)
		if subject == "" || got != want {
			t.Errorf("%s: manifest entry %q, want %q", id, got, want)
		}
	}
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// mappingStep is one step of steps.json (spec/v1.0/fixtures/README.md, section
// Outcomes cases).
type mappingStep struct {
	Ingest     *string `json:"ingest"`
	ReceivedAt *int64  `json:"received_at"`
	Query      *struct {
		AgentID   string                 `json:"agent_id"`
		HolderJKT string                 `json:"holder_jkt"`
		Context   core.ReputationContext `json:"context"`
		Audience  string                 `json:"audience"`
	} `json:"query"`
	Now *int64 `json:"now"`
}

// TestOutcomeMappingSteps: each mapping case ingests its reports in file-name
// order at config.json's now, then queries, at now, the context of its task
// for its agent under the holder test key (format v2 migration item 4).
func TestOutcomeMappingSteps(t *testing.T) {
	holder, err := jws.Thumbprint(fixtureJWK(t, "holder"))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range mappingCases {
		cfg, nat, reports, _ := loadOutcomeCase(t, repoFixtures, id)
		var steps []mappingStep
		strictFile(t, filepath.Join(repoFixtures, filepath.FromSlash(id), "steps.json"), &steps)
		var files []string
		for f := range reports {
			files = append(files, f)
		}
		slices.Sort(files)
		if len(steps) != len(files)+1 {
			t.Fatalf("%s: %d steps, want %d ingestions and one query", id, len(steps), len(files))
		}
		for i, f := range files {
			s := steps[i]
			if s.Ingest == nil || s.Query != nil || "reports/"+*s.Ingest+".json" != f || s.ReceivedAt == nil || *s.ReceivedAt != cfg.Now {
				t.Errorf("%s: step %d %+v, want the ingestion of %s at %d", id, i, s, f, cfg.Now)
			}
		}
		q := steps[len(files)]
		if q.Query == nil || q.Ingest != nil || q.Now == nil || *q.Now != cfg.Now {
			t.Fatalf("%s: last step %+v, want a query at %d", id, q, cfg.Now)
		}
		r := reports[files[0]]
		if q.Query.AgentID != nat.Tasks[0].AgentID || q.Query.HolderJKT != string(holder) ||
			!reflect.DeepEqual(q.Query.Context, r.Context) || q.Query.Audience != "https://gateway.example/finance" {
			t.Errorf("%s: query %+v, want the task's agent and context, the holder key and the B.6 audience", id, q.Query)
		}
	}
}

// mappingSnapshot is one entry of expected/<case>/snapshot.json.
type mappingSnapshot struct {
	Step  int `json:"step"`
	Value struct {
		Context    core.ReputationContext `json:"context"`
		Dimensions map[core.Dimension]struct {
			ScoreBps         int `json:"score_bps"`
			ConfidenceBps    int `json:"confidence_bps"`
			IndependentTasks int `json:"independent_tasks"`
			QualifiedEvents  int `json:"qualified_events"`
		} `json:"dimensions"`
		ScoringArtifactDigest string               `json:"scoring_artifact_digest"`
		ScoringPolicyRevision string               `json:"scoring_policy_revision"`
		SecurityStatus        *core.SecurityStatus `json:"security_status"`
		HoldRefs              []string             `json:"hold_refs"`
	} `json:"value"`
	Provenance struct {
		QualifiedEventIDs  [][2]string `json:"qualified_event_ids"`
		SupersededEventIDs [][2]string `json:"superseded_event_ids"`
	} `json:"provenance"`
	Claims map[string]string `json:"claims"`
}

// TestOutcomeMappingSnapshots: the expected snapshot of each mapping case's
// query agrees, within the one basis point of Section 15.3, with
// beta-decay-v1 applied to the weight units of its classifications.json: the
// listed reports are the qualified ones with a nonzero weight (15.2), each
// dimension's counts are theirs, and the claims bind the query.
func TestOutcomeMappingSnapshots(t *testing.T) {
	for _, id := range mappingCases {
		cfg, _, reports, q := loadOutcomeCase(t, repoFixtures, id)
		var steps []mappingStep
		strictFile(t, filepath.Join(repoFixtures, filepath.FromSlash(id), "steps.json"), &steps)
		var snaps []mappingSnapshot
		strictFile(t, filepath.Join(repoFixtures, "expected", filepath.FromSlash(id), "snapshot.json"), &snaps)
		if len(snaps) != 1 || snaps[0].Step != len(steps)-1 || steps[snaps[0].Step].Query == nil {
			t.Fatalf("%s: snapshots %+v, want one for the query step %d", id, snaps, len(steps)-1)
		}
		s, query := snaps[0], steps[snaps[0].Step]
		tNow := float64(*query.Now)
		alpha := map[core.Dimension]float64{}
		beta := map[core.Dimension]float64{}
		groups := map[core.Dimension]map[string]bool{}
		events := map[core.Dimension]int{}
		var listed [][2]string
		byEvent := map[string]core.OutcomeReport{}
		for _, r := range reports {
			byEvent[r.EventID] = r
		}
		for _, e := range q.Events {
			c := e.Contribution
			if e.Qualification != "QUALIFIED" || c.Positive+c.Negative == 0 {
				continue
			}
			r := byEvent[e.EventID]
			decay := math.Pow(2, -(tNow-float64(r.ObservedAt))/2592000)
			alpha[c.Dimension] += float64(c.Positive) * decay
			beta[c.Dimension] += float64(c.Negative) * decay
			if groups[c.Dimension] == nil {
				groups[c.Dimension] = map[string]bool{}
			}
			groups[c.Dimension][r.Attribution.IndependenceGroup] = true
			events[c.Dimension]++
			listed = append(listed, [2]string{r.Issuer, r.JTI})
		}
		slices.SortFunc(listed, func(a, b [2]string) int { return strings.Compare(a[0]+"\x00"+a[1], b[0]+"\x00"+b[1]) })
		if !slices.Equal(s.Provenance.QualifiedEventIDs, listed) {
			t.Errorf("%s: qualified_event_ids %v, want %v", id, s.Provenance.QualifiedEventIDs, listed)
		}
		if s.Provenance.SupersededEventIDs == nil || len(s.Provenance.SupersededEventIDs) != 0 {
			t.Errorf("%s: superseded_event_ids %v, want []", id, s.Provenance.SupersededEventIDs)
		}
		if len(s.Value.Dimensions) != len(mandatoryDimensions) {
			t.Errorf("%s: dimensions %v, want the three mandatory ones", id, s.Value.Dimensions)
		}
		for _, d := range mandatoryDimensions {
			a, b := 1+alpha[d], 1+beta[d]
			eff := a + b - 2
			score, conf := int(math.Floor(10000*a/(a+b))), int(math.Floor(10000*eff/(eff+20)))
			got := s.Value.Dimensions[d]
			if abs(got.ScoreBps-score) > 1 || abs(got.ConfidenceBps-conf) > 1 ||
				got.IndependentTasks != len(groups[d]) || got.QualifiedEvents != events[d] {
				t.Errorf("%s %s: %+v, want score %d confidence %d (1 bp), %d tasks, %d events", id, d, got, score, conf, len(groups[d]), events[d])
			}
		}
		if !reflect.DeepEqual(s.Value.Context, query.Query.Context) ||
			s.Value.ScoringArtifactDigest != "Is5hAn87tiTQEbsbEPbL7oeEZWa74Gxmr4Xrp0SQUQ0" || s.Value.ScoringPolicyRevision != "finance-scoring-1" {
			t.Errorf("%s: context or scoring pins differ from the query and B.6", id)
		}
		// No mapping case has a security authority, so none holds; a
		// gateway's policy violation places no hold (Section 15.4).
		if st := s.Value.SecurityStatus; st != nil && (*st != core.SecurityClear || s.Value.HoldRefs == nil || len(s.Value.HoldRefs) != 0) {
			t.Errorf("%s: security_status %s, hold_refs %v, want CLEAR and []", id, *st, s.Value.HoldRefs)
		}
		want := map[string]string{"iss": cfg.ReputationService.ServiceID, "sub": query.Query.AgentID, "aud": query.Query.Audience, "holder_jkt": query.Query.HolderJKT}
		if !maps.Equal(s.Claims, want) {
			t.Errorf("%s: claims %v, want %v", id, s.Claims, want)
		}
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
