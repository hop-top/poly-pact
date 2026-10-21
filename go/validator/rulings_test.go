package validator_test

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
	"hop.top/pact-go/validator"
	"hop.top/pact-go/validator/conformance"
)

// TestReputationRuleAges: for a field rule under /attributes/reputation,
// max_age_seconds bounds the age of the snapshot's iat and
// status_max_age_seconds the age of the validator's own security-hold
// check; the result records the snapshot's iat as source_observed_at and
// the time of the hold check as status_checked_at (draft 9.2, Appendix A.2).
func TestReputationRuleAges(t *testing.T) {
	f := prepare(t, "admission/valid")
	// Ten seconds after the snapshot's issuance, within its 30 s bound.
	f.Clock.Advance(10 * time.Second)
	res := evaluate(t, f)
	snap := check(t, res, "reputation-context")
	rule := check(t, res, "reputation-status")
	now := f.Clock.Now().Unix()
	if snap.SourceObservedAt == nil || *snap.SourceObservedAt == now {
		t.Fatalf("the case must present a snapshot issued before now (iat %v, now %d)", snap.SourceObservedAt, now)
	}
	if rule.Result != core.CheckPass {
		t.Fatalf("reputation-status = %s %s", rule.Result, rule.ReasonCode)
	}
	if rule.SourceObservedAt == nil || *rule.SourceObservedAt != *snap.SourceObservedAt {
		t.Errorf("source_observed_at %v, want the snapshot's iat %d", rule.SourceObservedAt, *snap.SourceObservedAt)
	}
	if rule.StatusCheckedAt == nil || *rule.StatusCheckedAt != now {
		t.Errorf("status_checked_at %v, want the hold check at %d", rule.StatusCheckedAt, now)
	}
}

// TestReputationRuleHoldOutage: when the hold check cannot be made, the
// status of a reputation rule is not established: UNKNOWN
// DEPENDENCY_UNAVAILABLE, whatever the snapshot says.
func TestReputationRuleHoldOutage(t *testing.T) {
	f := prepare(t, "admission/valid")
	f.Validator.Holds = failingHolds{}
	res := evaluate(t, f)
	wantCheck(t, res, "reputation-status", core.CheckUnknown, "DEPENDENCY_UNAVAILABLE")
	if res.Attestation.Decision != core.DecisionDeferred {
		t.Errorf("decision %s, want DEFERRED", res.Attestation.Decision)
	}
}

// checksSelector is a selector whose table lists checks as the authorized
// context_checks of every set, or no entry when ok is false.
type checksSelector struct {
	validator.Selector
	checks []string
	ok     bool
}

func (s checksSelector) Checks(string) ([]string, bool) { return slices.Clone(s.checks), s.ok }

type checksRegistry struct {
	validator.PolicyRegistry
	checks []string
	ok     bool
}

func (r checksRegistry) Selection(ctx context.Context, c contract.Contract) (validator.Selection, error) {
	s, err := r.PolicyRegistry.Selection(ctx, c)
	if s.Selector != nil {
		s.Selector = checksSelector{s.Selector, r.checks, r.ok}
	}
	return s, err
}

// TestContractChecksAuthorized: a validator holding the table compares the
// contract's context_checks with the entry of its selected set, as JSON
// data with array order significant; a difference is contract-validity
// FAIL CONTEXT_MISMATCH (draft 11.3 step 3).
func TestContractChecksAuthorized(t *testing.T) {
	const id = "selection/same-snapshot"
	issued := []string{"native-principal-binding-v1", "purpose-operation-v1", "native-delegation-v1", "security-hold-v1", "selection-consistency-v1"}
	for _, tc := range []struct {
		name   string
		checks []string
		ok     bool
		want   core.CheckStatus
	}{
		{"the table's entry", issued, true, core.CheckPass},
		{"another order", []string{"purpose-operation-v1", "native-principal-binding-v1", "native-delegation-v1", "security-hold-v1", "selection-consistency-v1"}, true, core.CheckFail},
		{"one check fewer", issued[:4], true, core.CheckFail},
		{"one check more", append(slices.Clone(issued), "native-approval-v1"), true, core.CheckFail},
		{"no entry for the set", issued, false, core.CheckFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := prepare(t, id)
			f.Validator.Policies = checksRegistry{f.Validator.Policies, tc.checks, tc.ok}
			res := evaluate(t, f)
			c := check(t, res, "contract-validity")
			switch {
			case tc.want == core.CheckPass && (c.Result != core.CheckPass || res.Attestation.Decision != core.DecisionAdmissible):
				t.Errorf("contract-validity %s %s, decision %s; want PASS, ADMISSIBLE", c.Result, c.ReasonCode, res.Attestation.Decision)
			case tc.want == core.CheckFail && (c.Result != core.CheckFail || c.ReasonCode != "CONTEXT_MISMATCH"):
				t.Errorf("contract-validity %s %s, want FAIL CONTEXT_MISMATCH", c.Result, c.ReasonCode)
			}
		})
	}
}

// TestReceiptStoreCheckOrder: receipt-store is a protocol check, listed
// after active-policy and before the field rules (draft 12.1).
func TestReceiptStoreCheckOrder(t *testing.T) {
	f := prepare(t, "admission/valid")
	f.Validator.Receipts = failingReceipts{f.Validator.Receipts}
	res, _ := f.Validator.Evaluate(context.Background(), f.Request)
	var ids []string
	for _, c := range res.Attestation.Checks {
		ids = append(ids, c.CheckID)
	}
	want := slices.Concat(b7Checks[:11], []string{"receipt-store"}, b7Checks[11:])
	if !slices.Equal(ids, want) {
		t.Errorf("checks %v\nwant %v", ids, want)
	}
}

// caseCopy copies the manifest, the test keys and the case and expected
// directories of id into a fresh fixture tree, applies edit to the case's
// config.json, and prepares the case from the copy.
func caseCopy(t *testing.T, id string, edit func(cfg map[string]any)) *conformance.Fixture {
	t.Helper()
	root := t.TempDir()
	for _, rel := range []string{"manifest.json", "keys", id, "expected/" + id} {
		src := filepath.Join(fixtures, filepath.FromSlash(rel))
		err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			r, err := filepath.Rel(fixtures, p)
			if err != nil {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			dst := filepath.Join(root, r)
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			return os.WriteFile(dst, b, 0o644)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(root, filepath.FromSlash(id), "config.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	edit(cfg)
	if b, err = json.Marshal(cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := conformance.Prepare(filepath.Join(root, filepath.FromSlash(id)))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

const b2Purpose = "https://policies.example/purposes/invoice-summary/v1"

// TestConfiguredGateway: the conformance gateway takes its purpose mapping,
// reputation-context mapping, accepted scoring revisions and authorized
// context checks from config.json (spec/v1.0/fixtures/README.md, config.json
// additions and selection.selector), not from the Appendix B values.
func TestConfiguredGateway(t *testing.T) {
	for _, tc := range []struct {
		name   string
		id     string
		edit   func(cfg map[string]any)
		check  string
		result core.CheckStatus
		reason string
	}{
		{"same purposes", "admission/valid", func(c map[string]any) {
			c["purposes"] = map[string]any{b2Purpose: []any{"invoice.read"}}
		}, "purpose-operation-v1", core.CheckPass, "REQUIREMENT_SATISFIED"},
		{"purpose not installed", "admission/valid", func(c map[string]any) {
			c["purposes"] = map[string]any{"https://policies.example/purposes/other/v1": []any{"invoice.read"}}
		}, "purpose-operation-v1", core.CheckUnknown, "UNSUPPORTED_PURPOSE"},
		{"action outside the purpose", "admission/valid", func(c map[string]any) {
			c["purposes"] = map[string]any{b2Purpose: []any{"invoice.export"}}
		}, "purpose-operation-v1", core.CheckFail, "CONTEXT_MISMATCH"},
		{"same reputation context", "admission/valid", func(c map[string]any) {
			c["reputation_context"] = map[string]any{
				"resource_classes": []any{map[string]any{"prefix": "https://invoices.example/invoices/", "class": "department-finance-invoice"}},
				"runtime_class":    "managed-v1",
			}
		}, "reputation-context", core.CheckPass, "REQUIREMENT_SATISFIED"},
		{"resource with no class", "admission/valid", func(c map[string]any) {
			c["reputation_context"] = map[string]any{
				"resource_classes": []any{map[string]any{"prefix": "https://invoices.example/archive/", "class": "department-finance-invoice"}},
				"runtime_class":    "managed-v1",
			}
		}, "reputation-context", core.CheckUnknown, "UNSUPPORTED_REQUIREMENT"},
		{"other resource class", "admission/valid", func(c map[string]any) {
			c["reputation_context"] = map[string]any{
				"resource_classes": []any{map[string]any{"prefix": "https://invoices.example/", "class": "any-invoice"}},
				"runtime_class":    "managed-v1",
			}
		}, "reputation-context", core.CheckFail, "CONTEXT_MISMATCH"},
		{"other runtime class", "admission/valid", func(c map[string]any) {
			c["reputation_context"] = map[string]any{
				"resource_classes": []any{map[string]any{"prefix": "https://invoices.example/invoices/", "class": "department-finance-invoice"}},
				"runtime_class":    "managed-v2",
			}
		}, "reputation-context", core.CheckFail, "CONTEXT_MISMATCH"},
		{"scoring revision accepted", "admission/valid", func(c map[string]any) {
			c["active_policy"].(map[string]any)["scoring_policy_revisions"] = []any{"finance-scoring-2", "finance-scoring-1"}
		}, "reputation-context", core.CheckPass, "REQUIREMENT_SATISFIED"},
		{"scoring revision not accepted", "admission/valid", func(c map[string]any) {
			c["active_policy"].(map[string]any)["scoring_policy_revisions"] = []any{"finance-scoring-2"}
		}, "reputation-context", core.CheckFail, "CONTEXT_MISMATCH"},
		{"authorized checks", "selection/same-snapshot", func(c map[string]any) {
			c["selection"].(map[string]any)["selector"].(map[string]any)["checks"] = map[string]any{"established": []any{
				"native-principal-binding-v1", "purpose-operation-v1", "native-delegation-v1", "security-hold-v1", "selection-consistency-v1",
			}}
		}, "contract-validity", core.CheckPass, "REQUIREMENT_SATISFIED"},
		{"checks not authorized", "selection/same-snapshot", func(c map[string]any) {
			c["selection"].(map[string]any)["selector"].(map[string]any)["checks"] = map[string]any{"established": []any{
				"native-principal-binding-v1", "purpose-operation-v1", "security-hold-v1", "selection-consistency-v1",
			}}
		}, "contract-validity", core.CheckFail, "CONTEXT_MISMATCH"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := evaluate(t, caseCopy(t, tc.id, tc.edit))
			wantCheck(t, res, tc.check, tc.result, tc.reason)
		})
	}
}
