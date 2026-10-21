package reputation_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/reputation"
)

// The bounds of a data policy: Appendix A.3 DataPolicy, with draft Sections
// 14.3 (the ingestion window) and 15.3 (one positive unit per task group, a
// failure weight up to 5). The control is the data policy of Appendix B.9.

func b9DataPolicy() core.DataPolicy {
	return core.DataPolicy{QualificationPolicyID: reputation.QualificationPolicyID, IngestionWindowSeconds: 604800, PositiveWeightCapPerTask: 1,
		MaximumFailureWeight: 5, TaskAttributionSource: "native-task-registry", ReporterIndependencePolicyID: reputation.ReporterIndependencePolicyID}
}

// members returns n distinct extension members.
func members(n int) core.Object {
	o := core.Object{}
	for i := range n {
		o[fmt.Sprintf("https://ext.example/%d", i)] = json.RawMessage("true")
	}
	return o
}

type bound struct {
	name string
	edit func(*core.DataPolicy)
	// member is the data policy member an invalid edit names; "" for a
	// valid one.
	member string
}

func dataPolicyBounds() []bound {
	long := strings.Repeat("x", 1024)
	return []bound{
		{"B.9 policy", func(*core.DataPolicy) {}, ""},
		{"window 1", func(d *core.DataPolicy) { d.IngestionWindowSeconds = 1 }, ""},
		{"window 2^53-1", func(d *core.DataPolicy) { d.IngestionWindowSeconds = 1<<53 - 1 }, ""},
		{"window 0", func(d *core.DataPolicy) { d.IngestionWindowSeconds = 0 }, "ingestion_window_seconds"},
		{"window -1", func(d *core.DataPolicy) { d.IngestionWindowSeconds = -1 }, "ingestion_window_seconds"},
		{"window 2^53", func(d *core.DataPolicy) { d.IngestionWindowSeconds = 1 << 53 }, "ingestion_window_seconds"},
		{"positive cap 0", func(d *core.DataPolicy) { d.PositiveWeightCapPerTask = 0 }, "positive_weight_cap_per_task"},
		{"positive cap 2", func(d *core.DataPolicy) { d.PositiveWeightCapPerTask = 2 }, "positive_weight_cap_per_task"},
		{"failure weight 1", func(d *core.DataPolicy) { d.MaximumFailureWeight = 1 }, ""},
		{"failure weight 0", func(d *core.DataPolicy) { d.MaximumFailureWeight = 0 }, "maximum_failure_weight"},
		{"failure weight 6", func(d *core.DataPolicy) { d.MaximumFailureWeight = 6 }, "maximum_failure_weight"},
		{"attribution source of 1024", func(d *core.DataPolicy) { d.TaskAttributionSource = long }, ""},
		{"no attribution source", func(d *core.DataPolicy) { d.TaskAttributionSource = "" }, "task_attribution_source"},
		{"attribution source of 1025", func(d *core.DataPolicy) { d.TaskAttributionSource = long + "x" }, "task_attribution_source"},
		{"qualification policy of 1025", func(d *core.DataPolicy) { d.QualificationPolicyID = long + "x" }, "qualification_policy_id"},
		{"no qualification policy", func(d *core.DataPolicy) { d.QualificationPolicyID = "" }, "qualification_policy_id"},
		{"independence policy of 1025", func(d *core.DataPolicy) { d.ReporterIndependencePolicyID = long + "x" }, "reporter_independence_policy_id"},
		{"no independence policy", func(d *core.DataPolicy) { d.ReporterIndependencePolicyID = "" }, "reporter_independence_policy_id"},
		{"128 extensions", func(d *core.DataPolicy) { d.Extensions = members(128) }, ""},
		{"129 extensions", func(d *core.DataPolicy) { d.Extensions = members(129) }, "extensions"},
	}
}

func TestCheckDataPolicy(t *testing.T) {
	for _, b := range dataPolicyBounds() {
		d := b9DataPolicy()
		b.edit(&d)
		err := reputation.CheckDataPolicy(d)
		switch {
		case b.member == "" && err != nil:
			t.Errorf("%s: %v, want valid", b.name, err)
		case b.member != "" && (err == nil || !strings.Contains(err.Error(), b.member)):
			t.Errorf("%s: %v, want an error naming %s", b.name, err, b.member)
		}
	}
	// maxLength counts characters, not bytes (JSON Schema 2020-12
	// validation, Section 6.3.1).
	d := b9DataPolicy()
	d.TaskAttributionSource = strings.Repeat("é", 1024)
	if err := reputation.CheckDataPolicy(d); err != nil {
		t.Errorf("1024 two-byte characters: %v, want valid", err)
	}
	d.TaskAttributionSource += "é"
	if err := reputation.CheckDataPolicy(d); err == nil {
		t.Error("1025 two-byte characters: valid, want an error")
	}
}

// TestNewChecksTheDataPolicy: New applies every bound of the data policy.
// The policy identifiers must also be the baselines this package
// implements, so the identifier bounds are checked by their invalid edits
// only.
func TestNewChecksTheDataPolicy(t *testing.T) {
	deps := reputation.Deps{Registry: reputation.StaticRegistry{}, Tasks: reputation.StaticTasks{}, Records: reputation.StaticRecords{},
		Store: &reputation.MemoryStore{}, Signer: failingSigner{}}
	for _, b := range dataPolicyBounds() {
		if b.member == "" && strings.Contains(b.name, "policy of") {
			continue
		}
		c := reputation.Config{ServiceID: "s", TenantID: "t", EnvironmentID: "e", ScoringArtifactDigest: "d", ScoringPolicyRevision: "r", DataPolicy: b9DataPolicy()}
		b.edit(&c.DataPolicy)
		_, err := reputation.New(c, deps)
		switch {
		case b.member == "" && err != nil:
			t.Errorf("%s: New = %v, want a service", b.name, err)
		case b.member != "" && (err == nil || !strings.Contains(err.Error(), b.member)):
			t.Errorf("%s: New = %v, want an error naming %s", b.name, err, b.member)
		}
	}
}
