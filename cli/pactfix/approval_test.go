package main

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jws"
)

// approvalCheck is the approval-class check (draft Section 17.3.1) that the
// approval cases install and name in their contracts.
const approvalCheck = "native-approval-v1"

// approvalStates is the table of draft Section 17.3.1, keyed by the native
// state the approval-class check establishes: the lower-case state of
// native_context.json's approval, "" for a null approval (the required
// reference being absent), and, for an approval in state approved,
// "authority-mismatch" and "scope-mismatch" (approvalEstablishes).
var approvalStates = map[string]struct{ result, decision, reason string }{
	"approved":           {"PASS", "ADMISSIBLE", "REQUIREMENT_SATISFIED"},
	"pending":            {"UNKNOWN", "DEFERRED", "APPROVAL_PENDING"},
	"":                   {"FAIL", "INADMISSIBLE", "MISSING_FIELD"},
	"rejected":           {"FAIL", "INADMISSIBLE", "APPROVAL_REJECTED"},
	"expired":            {"FAIL", "INADMISSIBLE", "APPROVAL_EXPIRED"},
	"revoked":            {"FAIL", "INADMISSIBLE", "APPROVAL_REVOKED"},
	"authority-mismatch": {"FAIL", "INADMISSIBLE", "APPROVAL_AUTHORITY_MISMATCH"},
	"scope-mismatch":     {"FAIL", "INADMISSIBLE", "APPROVAL_SCOPE_MISMATCH"},
	"unavailable":        {"UNKNOWN", "DEFERRED", "DEPENDENCY_UNAVAILABLE"},
}

// approvalCases are the committed approval cases and the native state each
// of their exchanges establishes, in order: one for a single-exchange case.
var approvalCases = map[string][]string{
	"approval/approved-fresh-exchange":            {"pending", "approved"},
	"approval/chat-says-approved":                 {""},
	"approval/exception-recognized-natively":      {"approved", "approved"},
	"approval/expired":                            {"expired"},
	"approval/mandatory-survives-high-reputation": {"pending"},
	"approval/missing-reference":                  {""},
	"approval/pending-established-request":        {"pending"},
	"approval/rejected":                           {"rejected"},
	"approval/revoked":                            {"revoked"},
	"approval/status-unavailable":                 {"unavailable"},
	"approval/wrong-approver-authority":           {"authority-mismatch"},
	"approval/wrong-scope-amount":                 {"scope-mismatch"},
	"approval/wrong-scope-resource":               {"scope-mismatch"},
}

// nativeApproval is native_context.json's approval with the format v2
// members (spec/v1.0/fixtures/README.md, section native_context.json additions).
type nativeApproval struct {
	State             string `json:"state"`
	AgentID           string `json:"agent_id"`
	PrincipalID       string `json:"principal_id"`
	PurposeID         string `json:"purpose_id"`
	TaskID            string `json:"task_id"`
	ApproverAuthority *struct {
		RequiredRole  string   `json:"required_role"`
		ApproverRoles []string `json:"approver_roles"`
	} `json:"approver_authority"`
	Amount *struct {
		Approved  string `json:"approved"`
		Requested string `json:"requested"`
		Currency  string `json:"currency"`
	} `json:"amount"`
	Resources []string `json:"resources"`
}

// approvalEstablishes is the native state the approval-class check
// establishes for one exchange directory: the approval's state, or, for an
// approved one, whether its approver lacks authority or its scope (agent,
// principal, purpose, task, amount or resource) misses the request (draft
// Section 17.3.1).
func approvalEstablishes(t *testing.T, dir string) string {
	t.Helper()
	var native struct {
		Authenticated struct {
			AgentID     string `json:"agent_id"`
			PrincipalID string `json:"principal_id"`
		} `json:"authenticated"`
		Approval *nativeApproval `json:"approval"`
	}
	var intent struct {
		PurposeID string `json:"purpose_id"`
		TaskID    string `json:"task_id"`
	}
	var op struct {
		Resources []string `json:"resources"`
	}
	for f, v := range map[string]any{"native_context.json": &native, "intent.json": &intent, "actual_operation.json": &op} {
		if err := json.Unmarshal(readFile(t, filepath.Join(dir, f)), v); err != nil {
			t.Fatal(err)
		}
	}
	a := native.Approval
	switch {
	case a == nil:
		return ""
	case a.State != "approved":
		return a.State
	case a.ApproverAuthority != nil && !slices.Contains(a.ApproverAuthority.ApproverRoles, a.ApproverAuthority.RequiredRole):
		return "authority-mismatch"
	case a.AgentID != native.Authenticated.AgentID || a.PrincipalID != native.Authenticated.PrincipalID ||
		a.PurposeID != intent.PurposeID || a.TaskID != intent.TaskID:
		return "scope-mismatch"
	}
	if a.Amount != nil {
		approved, ok1 := new(big.Rat).SetString(a.Amount.Approved)
		requested, ok2 := new(big.Rat).SetString(a.Amount.Requested)
		if !ok1 || !ok2 || a.Amount.Currency == "" {
			t.Fatalf("approval amount %+v is not two decimal strings and a currency", *a.Amount)
		}
		if requested.Cmp(approved) > 0 {
			return "scope-mismatch"
		}
	}
	if a.Resources != nil {
		for _, r := range op.Resources {
			if !slices.Contains(a.Resources, r) {
				return "scope-mismatch"
			}
		}
	}
	return "approved"
}

// caseExchanges returns the exchange directories of the case id, relative to
// the case, from its sequence.json, and the subject; ["."] and "." for a
// single-exchange case.
func caseExchanges(t *testing.T, id string) ([]string, string) {
	t.Helper()
	p := filepath.Join(repoFixtures, filepath.FromSlash(id), "sequence.json")
	if _, err := os.Stat(p); os.IsNotExist(err) {
		return []string{"."}, "."
	}
	var seq struct {
		Exchanges []string `json:"exchanges"`
		Subject   string   `json:"subject"`
	}
	if err := json.Unmarshal(readFile(t, p), &seq); err != nil {
		t.Fatal(err)
	}
	return seq.Exchanges, seq.Subject
}

// TestApprovalCasesFollow1731: every approval case is registered, installs and
// requires the approval-class check in each exchange, and expects the check
// result, decision and reason code that draft Section 17.3.1 assigns to the
// native state of that exchange, with every other B.7 check passing,
// execution only for ADMISSIBLE under a native allow, and receipt digests and
// times of the exchange's own files. The exchanges of a multi-exchange case
// are fresh: each has its own contract, nonce and presentation, later in time
// (draft Section 12.2, B.12).
func TestApprovalCasesFollow1731(t *testing.T) {
	var manifest struct {
		Entries []struct {
			ID           string  `json:"id"`
			Kind         string  `json:"kind"`
			Scope        string  `json:"scope"`
			Path         string  `json:"path"`
			Expected     *string `json:"expected"`
			Outcome      *string `json:"outcome"`
			SpecMapRow   string  `json:"spec_map_row"`
			DraftSection string  `json:"draft_section"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(repoFixtures, "manifest.json")), &manifest); err != nil {
		t.Fatal(err)
	}
	var b7 struct {
		Checks []struct {
			CheckID string `json:"check_id"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(appendixB(t)["B.7"], &b7); err != nil {
		t.Fatal(err)
	}
	var baseChecks []string
	for _, c := range b7.Checks {
		baseChecks = append(baseChecks, c.CheckID)
	}
	seen := map[string]bool{}
	for _, e := range manifest.Entries {
		if !strings.HasPrefix(e.ID, "approval/") {
			continue
		}
		seen[e.ID] = true
		states, known := approvalCases[e.ID]
		if !known {
			t.Errorf("%s: not a known approval case", e.ID)
			continue
		}
		t.Run(e.ID, func(t *testing.T) {
			exchanges, subject := caseExchanges(t, e.ID)
			if len(exchanges) != len(states) || !slices.Contains(exchanges, subject) {
				t.Fatalf("exchanges %v subject %q for %d native states", exchanges, subject, len(states))
			}
			subjectExpected := filepath.ToSlash(filepath.Join("expected", e.ID, subject, "decision.json"))
			if e.Kind != "evaluate" || e.Scope != "runner" || e.Path != e.ID ||
				e.Expected == nil || *e.Expected != subjectExpected || e.Outcome == nil ||
				*e.Outcome != approvalStates[states[slices.Index(exchanges, subject)]].decision ||
				e.SpecMapRow != "CL-17.3.1" || e.DraftSection != "17.3.1" {
				t.Errorf("manifest entry %+v", e)
			}
			fresh := map[string]map[string]bool{"contract jti": {}, "nonce": {}, "presentation jti": {}}
			var lastNow int64
			for i, x := range exchanges {
				state := states[i]
				want := approvalStates[state]
				dir := filepath.Join(repoFixtures, filepath.FromSlash(e.ID), filepath.FromSlash(x))
				file := func(rel string) []byte { return readFile(t, filepath.Join(dir, filepath.FromSlash(rel))) }
				if got := approvalEstablishes(t, dir); got != state {
					t.Errorf("%s: native approval establishes %q, want %q", x, got, state)
				}
				var config struct {
					Now             int64    `json:"now"`
					InstalledChecks []string `json:"installed_checks"`
				}
				var contract struct {
					JTI           string   `json:"jti"`
					Nonce         string   `json:"nonce"`
					ContextChecks []string `json:"context_checks"`
				}
				var native struct {
					Authorize bool `json:"authorize"`
				}
				for f, v := range map[string]any{"config.json": &config, "contract.json": &contract, "native_context.json": &native} {
					if err := json.Unmarshal(file(f), v); err != nil {
						t.Fatal(err)
					}
				}
				if !slices.Contains(config.InstalledChecks, approvalCheck) || !slices.Contains(contract.ContextChecks, approvalCheck) {
					t.Errorf("%s: %s is not installed and required: %v, %v", x, approvalCheck, config.InstalledChecks, contract.ContextChecks)
				}
				if i > 0 && config.Now <= lastNow {
					t.Errorf("%s: now %d is not after the previous exchange's %d", x, config.Now, lastNow)
				}
				lastNow = config.Now

				raw := readFile(t, filepath.Join(repoFixtures, "expected", filepath.FromSlash(e.ID), filepath.FromSlash(x), "decision.json"))
				strictObject(t, raw)
				var dec struct {
					Decision      string  `json:"decision"`
					TransportCode *string `json:"transport_code"`
					Checks        []struct {
						CheckID    string `json:"check_id"`
						Result     string `json:"result"`
						ReasonCode string `json:"reason_code"`
					} `json:"checks"`
					Receipt struct {
						Typ    string         `json:"typ"`
						Signer string         `json:"signer"`
						Claims map[string]any `json:"claims"`
						ExpMax int64          `json:"exp_max"`
					} `json:"receipt"`
					Executed *bool `json:"executed"`
				}
				if err := json.Unmarshal(raw, &dec); err != nil {
					t.Fatal(err)
				}
				if dec.Decision != want.decision || dec.TransportCode != nil {
					t.Errorf("%s: decision %q transport %v, want %s", x, dec.Decision, dec.TransportCode, want.decision)
				}
				// Execution needs both admission and native authorization
				// (draft Sections 11.4 and 17.3: a native exception changes
				// only the authorize_native result).
				if wantRun := want.decision == "ADMISSIBLE" && native.Authorize; dec.Executed == nil || *dec.Executed != wantRun {
					t.Errorf("%s: executed is not %v with decision %s and authorize %v", x, wantRun, want.decision, native.Authorize)
				}
				var ids []string
				for _, c := range dec.Checks {
					ids = append(ids, c.CheckID)
					wr, wc := "PASS", "REQUIREMENT_SATISFIED"
					if c.CheckID == approvalCheck {
						wr, wc = want.result, want.reason
					}
					if c.Result != wr || c.ReasonCode != wc {
						t.Errorf("%s: check %s = %s %s, want %s %s", x, c.CheckID, c.Result, c.ReasonCode, wr, wc)
					}
				}
				if wantIDs := append(slices.Clone(baseChecks), approvalCheck); !slices.Equal(ids, wantIDs) {
					t.Errorf("%s: check ids %v, want %v", x, ids, wantIDs)
				}

				r := dec.Receipt
				if r.Typ != jws.TypAdmission || r.Signer != "keys/validator.jwk.json" || r.ExpMax != config.Now+60 {
					t.Errorf("%s: receipt typ %q signer %q exp_max %d", x, r.Typ, r.Signer, r.ExpMax)
				}
				if iat, ok := r.Claims["iat"].(float64); !ok || int64(iat) != config.Now {
					t.Errorf("%s: receipt iat %v, want %d", x, r.Claims["iat"], config.Now)
				}
				presentation := verifyAs(t, string(file("signed/presentation.jws")), jws.TypPresentation, "holder")
				var pres struct {
					JTI string `json:"jti"`
				}
				if err := json.Unmarshal(presentation.Payload, &pres); err != nil {
					t.Fatal(err)
				}
				for k, v := range map[string]string{"contract jti": contract.JTI, "nonce": contract.Nonce, "presentation jti": pres.JTI} {
					if fresh[k][v] {
						t.Errorf("%s: %s %s is reused from an earlier exchange", x, k, v)
					}
					fresh[k][v] = true
				}
				reqDigest, err := digest.ArtifactDigest(string(file("signed/contract.jws")))
				if err != nil {
					t.Fatal(err)
				}
				claims := map[string]string{
					"decision":            want.decision,
					"terminal_reason":     "COMPLETED",
					"presentation_id":     pres.JTI,
					"requirements_digest": string(reqDigest),
				}
				for k, f := range map[string]string{"profile_digest": "profile.json", "intent_digest": "intent.json", "operation_digest": "operation.json"} {
					d, err := digest.ObjectDigest(json.RawMessage(file(f)))
					if err != nil {
						t.Fatal(err)
					}
					claims[k] = string(d)
				}
				for k, v := range claims {
					if r.Claims[k] != v {
						t.Errorf("%s: receipt claim %s = %v, want %s", x, k, r.Claims[k], v)
					}
				}
			}
		})
	}
	for id := range approvalCases {
		if !seen[id] {
			t.Errorf("%s is not in the manifest", id)
		}
	}
}

// TestMandatoryApprovalSurvivesHighReputation: the case presents a snapshot
// of score_bps 9900 and confidence_bps 9000 in every dimension, which the
// profile mirrors and the reputation-context check accepts with that
// snapshot's jti, while the approval stays pending and the contract keeps the
// approval-class check: the decision is DEFERRED (draft Sections 15.5, 16.2
// and 17.3.1).
func TestMandatoryApprovalSurvivesHighReputation(t *testing.T) {
	const id = "approval/mandatory-survives-high-reputation"
	dir := filepath.Join(repoFixtures, filepath.FromSlash(id))
	var snapshot struct {
		JTI   string `json:"jti"`
		Value struct {
			Dimensions map[string]struct {
				ScoreBPS      int `json:"score_bps"`
				ConfidenceBPS int `json:"confidence_bps"`
			} `json:"dimensions"`
		} `json:"value"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(dir, "reputation.json")), &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Value.Dimensions) == 0 {
		t.Fatal("snapshot has no dimensions")
	}
	for name, d := range snapshot.Value.Dimensions {
		if d.ScoreBPS != 9900 || d.ConfidenceBPS != 9000 {
			t.Errorf("dimension %s = %d/%d, want 9900/9000", name, d.ScoreBPS, d.ConfidenceBPS)
		}
	}
	var profile struct {
		Attributes struct {
			Reputation json.RawMessage `json:"reputation"`
		} `json:"attributes"`
	}
	var rep struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(dir, "profile.json")), &profile); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(dir, "reputation.json")), &rep); err != nil {
		t.Fatal(err)
	}
	if string(profile.Attributes.Reputation) != string(rep.Value) {
		t.Error("the profile's reputation is not the presented snapshot's value")
	}
	if got := approvalEstablishes(t, dir); got != "pending" {
		t.Errorf("native approval establishes %q, want pending", got)
	}
	type check struct {
		CheckID            string   `json:"check_id"`
		Result             string   `json:"result"`
		EvidenceIDsInclude []string `json:"evidence_ids_include"`
	}
	var dec struct {
		Checks []check `json:"checks"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(repoFixtures, "expected", filepath.FromSlash(id), "decision.json")), &dec); err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(dec.Checks, func(c check) bool { return c.CheckID == "reputation-context" })
	if i < 0 || dec.Checks[i].Result != "PASS" || !slices.Equal(dec.Checks[i].EvidenceIDsInclude, []string{snapshot.JTI}) {
		t.Errorf("reputation-context does not pass with the snapshot %s: %+v", snapshot.JTI, dec.Checks)
	}
}
