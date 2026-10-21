package contract_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
)

// selfRule is a self rule on path, in the form Appendix A.2 gives a self
// rule: no issuers, native_path null, comparison equal, both ages zero.
func selfRule(id, path string) core.FieldRule {
	return core.FieldRule{
		RuleID: id, Path: path, Schema: json.RawMessage(`true`), Source: core.RuleSourceSelf,
		AllowedIssuers: []string{}, Comparison: core.ComparisonEqual,
	}
}

// TestSelfRuleReservedPaths: a self rule on the principal, delegation or
// reputation paths is invalid (draft 9.2, Appendix A.2), for the verifier as
// for the publisher: INVALID_MESSAGE.
func TestSelfRuleReservedPaths(t *testing.T) {
	compact := compactOf(t, validContract)
	v := b4Verifier(t)
	key := scalarKey(t, 2)
	header := segment(t, compact, 0)
	self := func(path string) func(m map[string]any) {
		return func(m map[string]any) {
			r := m["field_rules"].([]any)[3].(map[string]any)
			r["source"], r["allowed_issuers"], r["max_age_seconds"], r["status_max_age_seconds"] = "self", []any{}, json.Number("0"), json.Number("0")
			r["path"] = path
		}
	}
	reserved := []string{
		"/attributes/environment/principal_id",
		"/attributes/delegation",
		"/attributes/delegation/authority_ref",
		"/attributes/delegation/principal_id",
		"/attributes/reputation",
		"/attributes/reputation/security_status",
		"/attributes/reputation/dimensions/reliability/score_bps",
	}
	for _, path := range reserved {
		t.Run("verify "+path, func(t *testing.T) {
			_, err := v.Verify(resign(t, header, editPayload(t, compact, self(path)), key), at(b4Time))
			wantErr(t, err, contract.ErrInvalidMessage)
		})
		t.Run("issue "+path, func(t *testing.T) {
			r := b4Requirements(t)
			r.FieldRules[3] = selfRule(r.FieldRules[3].RuleID, path)
			_, err := newPublisher(t, contract.NewMemoryReplay(0)).Issue(bg, b4Request(t), b4Auth(), r, at(b4Time))
			wantErr(t, err, contract.ErrInvalidMessage)
		})
	}
	// Paths that only share a prefix of characters are not descendants.
	for _, path := range []string{
		"/attributes/environment/principal_id_hint", "/attributes/delegations",
		"/attributes/reputationx", "/attributes/runtime/isolation",
	} {
		t.Run("accepted "+path, func(t *testing.T) {
			if _, err := v.Verify(resign(t, header, editPayload(t, compact, self(path)), key), at(b4Time)); err != nil {
				t.Fatalf("verify: %v", err)
			}
			r := b4Requirements(t)
			r.FieldRules[3] = selfRule(r.FieldRules[3].RuleID, path)
			if _, err := newPublisher(t, contract.NewMemoryReplay(0)).Issue(bg, b4Request(t), b4Auth(), r, at(b4Time)); err != nil {
				t.Fatalf("issue: %v", err)
			}
		})
	}
}

// TestIssueProtectedPaths: the publisher also refuses a self rule on a path
// its installed mapping classifies as identity, tenant or role membership,
// delegation or approval, and on its descendants (Appendix A.2).
func TestIssueProtectedPaths(t *testing.T) {
	for _, path := range []string{"/attributes/environment/roles", "/attributes/environment/roles/0"} {
		t.Run(path, func(t *testing.T) {
			p := newPublisher(t, contract.NewMemoryReplay(0))
			p.ProtectedPaths = []string{"/attributes/environment/roles"}
			r := b4Requirements(t)
			r.FieldRules[3] = selfRule(r.FieldRules[3].RuleID, path)
			_, err := p.Issue(bg, b4Request(t), b4Auth(), r, at(b4Time))
			wantErr(t, err, contract.ErrInvalidMessage)
		})
	}
	// The native rule on the protected path is not refused, nor is a self
	// rule on another path.
	p := newPublisher(t, contract.NewMemoryReplay(0))
	p.ProtectedPaths = []string{"/attributes/environment/roles"}
	r := b4Requirements(t)
	r.FieldRules[3] = selfRule(r.FieldRules[3].RuleID, "/attributes/environment/rolesx")
	if _, err := p.Issue(bg, b4Request(t), b4Auth(), r, at(b4Time)); err != nil {
		t.Fatalf("self rule outside the protected paths: %v", err)
	}
}

// thresholdRule is a field rule in the canonical form of draft 9.4 (b).
func thresholdRule(id, path, schema string) core.FieldRule {
	return core.FieldRule{
		RuleID: id, Path: path, Schema: json.RawMessage(schema), Source: core.RuleSourceEvidence,
		AllowedIssuers: []string{"https://reputation.example/finance"}, Comparison: core.ComparisonEqual,
		MaxAgeSeconds: 30,
	}
}

// establishedRequirements selects the weaker set "established" on the
// thresholds of the selection fixtures: reliability score_bps 9000,
// confidence_bps 5000, independent_tasks 20 and security status CLEAR.
func establishedRequirements(t *testing.T) contract.Requirements {
	t.Helper()
	r := b4Requirements(t)
	r.SelectedSet = "established"
	r.ContextChecks = append(r.ContextChecks, contract.SelectionConsistencyCheck)
	r.Thresholds = []contract.ThresholdRule{
		{Dimension: "reliability", Statistic: "score_bps", Minimum: 9000},
		{Dimension: "reliability", Statistic: "confidence_bps", Minimum: 5000},
		{Dimension: "reliability", Statistic: "independent_tasks", Minimum: 20},
		{SecurityStatus: core.SecurityClear},
	}
	r.FieldRules = append(r.FieldRules,
		thresholdRule("reputation-reliability-score", "/attributes/reputation/dimensions/reliability/score_bps", `{"type":"integer","minimum":9000}`),
		thresholdRule("reputation-reliability-confidence", "/attributes/reputation/dimensions/reliability/confidence_bps", `{"type":"integer","minimum":5000}`),
		thresholdRule("reputation-reliability-tasks", "/attributes/reputation/dimensions/reliability/independent_tasks", `{"minimum":2e1,"type":"integer"}`),
	)
	return r
}

// TestIssueThresholdRules: a contract whose selected set is not the
// conservative one expresses every threshold the selector relied on as an
// evidence field rule of the canonical form; a publisher does not issue one
// that lacks one of them (draft 9.4 (b)): INVALID_MESSAGE.
func TestIssueThresholdRules(t *testing.T) {
	issue := func(r contract.Requirements) error {
		_, err := newPublisher(t, contract.NewMemoryReplay(0)).Issue(bg, b4Request(t), b4Auth(), r, at(b4Time))
		return err
	}
	if err := issue(establishedRequirements(t)); err != nil {
		t.Fatalf("every threshold a rule: %v", err)
	}
	ruleIndex := func(r contract.Requirements, id string) int {
		for i, fr := range r.FieldRules {
			if fr.RuleID == id {
				return i
			}
		}
		t.Fatalf("no rule %q", id)
		return -1
	}
	for _, tc := range []struct {
		name string
		edit func(r *contract.Requirements)
	}{
		{"minimum rule missing", func(r *contract.Requirements) {
			i := ruleIndex(*r, "reputation-reliability-score")
			r.FieldRules = append(r.FieldRules[:i], r.FieldRules[i+1:]...)
		}},
		{"minimum differs", func(r *contract.Requirements) {
			r.FieldRules[ruleIndex(*r, "reputation-reliability-confidence")].Schema = json.RawMessage(`{"type":"integer","minimum":4999}`)
		}},
		{"no minimum keyword", func(r *contract.Requirements) {
			r.FieldRules[ruleIndex(*r, "reputation-reliability-tasks")].Schema = json.RawMessage(`{"type":"integer","exclusiveMinimum":20}`)
		}},
		{"minimum on another path", func(r *contract.Requirements) {
			r.FieldRules[ruleIndex(*r, "reputation-reliability-score")].Path = "/attributes/reputation/dimensions/task_quality/score_bps"
		}},
		{"minimum not an evidence rule", func(r *contract.Requirements) {
			i := ruleIndex(*r, "reputation-reliability-score")
			native := "/reputation/reliability/score_bps"
			r.FieldRules[i].Source, r.FieldRules[i].AllowedIssuers, r.FieldRules[i].NativePath = core.RuleSourceNative, []string{}, &native
		}},
		{"status rule missing", func(r *contract.Requirements) {
			i := ruleIndex(*r, "reputation-status")
			r.FieldRules = append(r.FieldRules[:i], r.FieldRules[i+1:]...)
		}},
		{"status differs", func(r *contract.Requirements) {
			r.FieldRules[ruleIndex(*r, "reputation-status")].Schema = json.RawMessage(`{"const":"CAUTION"}`)
		}},
		{"threshold names nothing", func(r *contract.Requirements) {
			r.Thresholds = append(r.Thresholds, contract.ThresholdRule{})
		}},
		{"threshold names a statistic and a status", func(r *contract.Requirements) {
			r.Thresholds = append(r.Thresholds, contract.ThresholdRule{Dimension: "reliability", Statistic: "score_bps", Minimum: 9000, SecurityStatus: core.SecurityClear})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := establishedRequirements(t)
			tc.edit(&r)
			wantErr(t, issue(r), contract.ErrInvalidMessage)
		})
	}
	// The conservative set is selected on no threshold: draft 9.4 (b) does
	// not apply to it.
	r := establishedRequirements(t)
	r.SelectedSet = r.ConservativeSet
	r.FieldRules = b4Requirements(t).FieldRules
	r.FieldRules = r.FieldRules[:len(r.FieldRules)-1]
	if err := issue(r); err != nil {
		t.Fatalf("conservative set: %v", err)
	}
}

// TestIssueRefusalCodes: the issuance refusals of draft 9.1 and 10.1: a
// compromised binding is SECURITY_HOLD, an unrecognized purpose
// UNSUPPORTED_PURPOSE, each a transport error that issues no contract and
// registers no nonce.
func TestIssueRefusalCodes(t *testing.T) {
	store := &countingReplay{MemoryReplay: contract.NewMemoryReplay(0)}
	auth := b4Auth()
	auth.Binding.Status = adapter.BindingCompromised
	c, err := newPublisher(t, store).Issue(bg, b4Request(t), auth, b4Requirements(t), at(b4Time))
	wantErr(t, err, contract.ErrSecurityHold)
	if code, _ := adapter.CodeOf(err); code != "SECURITY_HOLD" {
		t.Errorf("code %q, want SECURITY_HOLD", code)
	}
	if c.Compact != "" {
		t.Fatal("a contract was returned with the error")
	}

	p := newPublisher(t, store)
	p.Purposes = []string{"https://policies.example/purposes/other/v1"}
	c, err = p.Issue(bg, b4Request(t), b4Auth(), b4Requirements(t), at(b4Time))
	wantErr(t, err, contract.ErrUnsupportedPurpose)
	if code, _ := adapter.CodeOf(err); code != adapter.CodeUnsupportedPurpose {
		t.Errorf("code %q, want UNSUPPORTED_PURPOSE", code)
	}
	if c.Compact != "" {
		t.Fatal("a contract was returned with the error")
	}
	if n := store.registered; n != 0 {
		t.Fatalf("%d nonces registered by refused requests", n)
	}

	// The installed purpose of B.2 is issued for.
	p.Purposes = append(p.Purposes, "https://policies.example/purposes/invoice-summary/v1")
	if _, err := p.Issue(bg, b4Request(t), b4Auth(), b4Requirements(t), at(b4Time)); err != nil {
		t.Fatalf("installed purpose: %v", err)
	}
}

// countingReplay counts the nonces registered.
type countingReplay struct {
	*contract.MemoryReplay
	registered int
}

func (c *countingReplay) Register(ctx context.Context, r contract.NonceRecord, now, until time.Time) error {
	c.registered++
	return c.MemoryReplay.Register(ctx, r, now, until)
}
