package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/runner/learning"
	"hop.top/pact-go/runner/manifest"
)

// learningOutput is what the learning command prints (spec/v1.0/fixtures/README.md,
// section Learning output): the members of registry.json except subject,
// with artifacts named by the artifact_digest of their signed manifest, each
// acknowledgment's Acknowledgment object as ack and each rejection's Problem
// as problem.
type learningOutput struct {
	Artifacts       map[string]core.LifecycleState `json:"artifacts"`
	Active          []learningActive               `json:"active"`
	Acknowledgments []learningAck                  `json:"acknowledgments"`
	Rejections      []learningRejection            `json:"rejections"`
	Holds           []string                       `json:"holds"`
	Reevaluation    []string                       `json:"reevaluation_required"`
}

type learningActive struct {
	Context  core.ReputationContext `json:"context"`
	Artifact *string                `json:"artifact"`
}

type learningAck struct {
	Step   *int                 `json:"step"`
	Status core.AckStatus       `json:"status"`
	Ack    *core.Acknowledgment `json:"ack"`
}

type learningRejection struct {
	Step        *int          `json:"step"`
	Code        string        `json:"code"`
	ReasonCodes []string      `json:"reason_codes"`
	Problem     *core.Problem `json:"problem"`
}

// checkLearning runs the learning command on the case directory and compares
// the registry state it prints with the entry's expected registry.json: the
// state of every artifact, the artifact in force in each context, the
// acknowledgment or rejection of each step with its code and reason codes,
// the holds and the artifacts that require re-evaluation. Every difference
// is a detail. The exit status of the command is informational, as the state
// on standard output is what is judged.
func checkLearning(root string, e manifest.Entry, tmpl string, r Result) Result {
	dir, err := filepath.Abs(filepath.Join(root, filepath.FromSlash(e.Path)))
	if err != nil {
		return r.with(StatusFail, err.Error())
	}
	c, err := evalcase.ReadLearning(root, e.ID)
	if err != nil {
		return r.with(StatusFail, err.Error())
	}
	scratch, err := os.MkdirTemp("", "pactc-learning-")
	if err != nil {
		return r.with(StatusFail, "cannot make the scratch state: "+err.Error())
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	res := runCmd(BuildArgv(tmpl, map[string]string{"dir": dir, "state": filepath.Join(scratch, "state")}))
	if res.Err != nil {
		return r.with(StatusFail, "cannot run the learning command: "+res.summary())
	}
	text := strings.TrimSpace(string(res.Stdout))
	if text == "" {
		return r.with(StatusFail, "no registry state on stdout", res.summary())
	}
	got, problems := parseLearningOutput(text, c)
	if len(problems) == 0 {
		problems = learning.Diff(c.Expected, got)
	}
	if len(problems) > 0 {
		return r.with(StatusFail, append(problems, res.summary())...)
	}
	return r.with(StatusPass)
}

// parseLearningOutput reads the command's output into a registry in the form
// of registry.json, mapping each artifact digest to the path of the
// committed signed manifest that has it; a digest no committed file has stays
// a digest, which the comparison reports as unexpected. It returns the
// problems with the output's own form: a member that is missing, an
// acknowledgment without its Acknowledgment, a rejection without its Problem
// or a Problem that does not carry the rejection's code and reason codes.
func parseLearningOutput(text string, c *evalcase.LearningCase) (evalcase.Registry, []string) {
	var members map[string]json.RawMessage
	if err := strictjson.Unmarshal([]byte(text), strictjson.Limits{}, &members); err != nil {
		return evalcase.Registry{}, []string{"stdout is not the registry state JSON object (spec/v1.0/fixtures/README.md, Learning output): " + err.Error()}
	}
	var out learningOutput
	if err := strictjson.Unmarshal([]byte(text), strictjson.Limits{}, &out); err != nil {
		return evalcase.Registry{}, []string{"stdout is not the registry state JSON object (spec/v1.0/fixtures/README.md, Learning output): " + err.Error()}
	}
	var problems []string
	for _, m := range []string{"artifacts", "active", "acknowledgments", "rejections"} {
		if _, ok := members[m]; !ok {
			problems = append(problems, m+" is required in the registry state")
		}
	}
	if len(problems) > 0 {
		return evalcase.Registry{}, problems
	}
	toPath := map[string]string{}
	for p, compact := range c.Signed {
		d, err := digest.ArtifactDigest(compact)
		if err != nil {
			continue
		}
		if prev, ok := toPath[string(d)]; !ok || p < prev {
			toPath[string(d)] = p
		}
	}
	name := func(d string) string {
		if p, ok := toPath[d]; ok {
			return p
		}
		return d
	}
	reg := evalcase.Registry{
		Artifacts: map[string]core.LifecycleState{}, Active: []evalcase.ActiveEntry{}, Acknowledgments: []evalcase.AckEntry{},
		Rejections: []evalcase.RejectionEntry{}, Holds: nonNilStrings(out.Holds), ReevaluationRequired: []string{},
	}
	for d, st := range out.Artifacts {
		if !st.Valid() {
			problems = append(problems, fmt.Sprintf("artifacts[%s]: state %q is not a lifecycle state of draft Section 16.5", name(d), st))
		}
		reg.Artifacts[name(d)] = st
	}
	for _, a := range out.Active {
		e := evalcase.ActiveEntry{Context: a.Context}
		if a.Artifact != nil {
			n := name(*a.Artifact)
			e.Artifact = &n
		}
		reg.Active = append(reg.Active, e)
	}
	for _, d := range out.Reevaluation {
		reg.ReevaluationRequired = append(reg.ReevaluationRequired, name(d))
	}
	for i, a := range out.Acknowledgments {
		where := fmt.Sprintf("acknowledgments[%d]", i)
		if a.Step == nil {
			problems = append(problems, where+": step is required")
			continue
		}
		problems = append(problems, ackProblems(where, a)...)
		reg.Acknowledgments = append(reg.Acknowledgments, evalcase.AckEntry{Step: *a.Step, Status: a.Status})
	}
	for i, x := range out.Rejections {
		where := fmt.Sprintf("rejections[%d]", i)
		if x.Step == nil {
			problems = append(problems, where+": step is required")
			continue
		}
		problems = append(problems, rejectionProblems(where, x)...)
		reg.Rejections = append(reg.Rejections, evalcase.RejectionEntry{Step: *x.Step, Code: x.Code, ReasonCodes: nonNilStrings(x.ReasonCodes)})
	}
	return reg, problems
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ackProblems checks the Acknowledgment object (draft Appendix A.3) of an
// acknowledged step against the step's entry.
func ackProblems(where string, a learningAck) []string {
	switch {
	case a.Ack == nil:
		return []string{where + ": ack, the Acknowledgment object, is required"}
	case a.Ack.Status != a.Status:
		return []string{fmt.Sprintf("%s: ack.status %s, but the step is acknowledged %s", where, a.Ack.Status, a.Status)}
	case a.Ack.RequestID == "" || a.Ack.ArtifactID == "":
		return []string{where + ": ack needs a request_id and an artifact_id (draft Appendix A.3)"}
	}
	return nil
}

// rejectionProblems checks the Problem (draft Section 13.4 and Appendix A.3)
// of a rejected step against the step's entry: it carries the code, and in
// extensions.reason_codes the reason codes.
func rejectionProblems(where string, x learningRejection) []string {
	p := x.Problem
	switch {
	case p == nil:
		return []string{where + ": problem, the RFC 9457 Problem, is required"}
	case p.Type == "" || p.Title == "" || p.RequestID == "":
		return []string{where + ": problem needs a type, a title and a request_id (draft Section 13.4)"}
	case p.Status < 400 || p.Status > 599:
		return []string{fmt.Sprintf("%s: problem.status %d is not an HTTP error status", where, p.Status)}
	case p.Code != x.Code:
		return []string{fmt.Sprintf("%s: problem.code %s, but the step is rejected %s", where, p.Code, x.Code)}
	}
	var reasons []string
	if raw, ok := p.Extensions["reason_codes"]; ok {
		if err := strictjson.Unmarshal(raw, strictjson.Limits{}, &reasons); err != nil {
			return []string{where + ": problem.extensions.reason_codes is not an array of strings"}
		}
	}
	got, want := slices.Clone(reasons), slices.Clone(x.ReasonCodes)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		return []string{fmt.Sprintf("%s: problem.extensions.reason_codes %v, but reason_codes is %v (draft Section 13.4)", where, got, want)}
	}
	return nil
}
