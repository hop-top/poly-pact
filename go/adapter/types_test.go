package adapter

import (
	"reflect"
	"slices"
	"testing"

	"hop.top/pact-go/core"
)

// fields lists "Name type" for every field of struct type t, in order.
func fields(t reflect.Type) []string {
	var out []string
	for f := range t.Fields() {
		out = append(out, f.Name+" "+f.Type.String())
	}
	return out
}

// TestStructFields pins the shape of every exported value type. The lists are
// written from the contract of the section 17.1 functions; adding, dropping or
// retyping a field is a contract change and must change this table.
func TestStructFields(t *testing.T) {
	tests := []struct {
		typ  reflect.Type
		want []string
	}{
		{reflect.TypeFor[Realm](), []string{
			"TenantID string", "EnvironmentID string",
		}},
		{reflect.TypeFor[Principal](), []string{
			"ID string", "Realm adapter.Realm", "Workload adapter.Workload",
			"Mechanism adapter.Mechanism", "AuthenticatedAt time.Time",
			"Attributes map[string]interface {}",
		}},
		{reflect.TypeFor[NativeDenial](), []string{
			"Reason adapter.DenialReason",
		}},
		{reflect.TypeFor[AgentBinding](), []string{
			"AgentID string", "OperatorID string", "HolderJKT core.Digest",
			"Status adapter.BindingStatus", "ObservedAt time.Time",
			"StatusCheckedAt time.Time", "SourceID string", "SourceRef string",
			"EnrolledElsewhere bool",
		}},
		{reflect.TypeFor[NativeClaim](), []string{
			"Value interface {}", "ObservedAt time.Time",
			"StatusCheckedAt time.Time", "SourceID string", "SourceRef string",
		}},
		{reflect.TypeFor[CheckOutcome](), []string{
			"Result adapter.Verdict", "ReasonCode string", "SourceID string",
			"SourceRef string", "ObservedAt time.Time",
		}},
		{reflect.TypeFor[ClaimContext](), []string{
			"Principal adapter.Principal", "Intent core.Intent",
			"Operation core.OperationContext",
		}},
		{reflect.TypeFor[Decision](), []string{
			"Effect adapter.Effect", "Obligations []adapter.Obligation",
			"Reason string", "SourceID string", "SourceRef string",
			"DecidedAt time.Time", "PolicyRevision string",
		}},
		{reflect.TypeFor[Obligation](), []string{
			"ID string", "Attributes map[string]interface {}",
		}},
		{reflect.TypeFor[Observation](), []string{
			"EventID string", "EventKind core.EventKind",
			"Context core.ReputationContext", "TaskID string",
			"OperationID string", "AdmissionReceiptID *string",
			"ObservedAt time.Time", "Result core.OutcomeResult",
			"Dimension core.Dimension", "Severity core.Severity",
			"EvidenceRefs []string", "Attribution core.Attribution",
			"Supersedes []string", "Details string",
		}},
		{reflect.TypeFor[Signed](), []string{"JWS string"}},
		{reflect.TypeFor[NoVisibility](), []string{"Reason string"}},
		{reflect.TypeFor[Descriptor](), []string{
			"Protocol string", "Version string", "MappingRevision string",
		}},
	}
	for _, tc := range tests {
		t.Run(tc.typ.Name(), func(t *testing.T) {
			if got := fields(tc.typ); !slices.Equal(got, tc.want) {
				t.Errorf("fields\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

// TestDecisionHasNoOverride: a denial is final by construction because the
// type has nothing a caller could set to turn it into an allow. Besides the
// effect, the obligations and the reason, a decision carries only its
// provenance: the source, the record, the time and the policy revision.
func TestDecisionHasNoOverride(t *testing.T) {
	for f := range reflect.TypeFor[Decision]().Fields() {
		switch f.Name {
		case "Effect", "Obligations", "Reason",
			"SourceID", "SourceRef", "DecidedAt", "PolicyRevision":
		default:
			t.Errorf("Decision has unexpected field %s", f.Name)
		}
	}
}

func TestEnums(t *testing.T) {
	type enum interface{ Valid() bool }
	tests := []struct {
		name  string
		valid map[string]enum
		bogus []enum
	}{
		{"BindingStatus", map[string]enum{
			"ACTIVE": BindingActive, "REVOKED": BindingRevoked,
			"COMPROMISED": BindingCompromised, "UNKNOWN": BindingUnknown,
		}, []enum{BindingStatus(""), BindingStatus("active"), BindingStatus("SUSPENDED")}},
		{"Verdict", map[string]enum{
			"PASS": VerdictPass, "FAIL": VerdictFail, "UNKNOWN": VerdictUnknown,
		}, []enum{Verdict(""), Verdict("pass"), Verdict("NOT_APPLICABLE")}},
		{"Effect", map[string]enum{
			"ALLOW": EffectAllow, "DENY": EffectDeny, "UNKNOWN": EffectUnknown,
		}, []enum{Effect(""), Effect("allow"), Effect("PERMIT")}},
		{"DenialReason", map[string]enum{
			"NO_CREDENTIAL": DenialNoCredential, "CREDENTIAL_REJECTED": DenialCredentialRejected,
		}, []enum{DenialReason(""), DenialReason("user alice not found")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for lit, v := range tc.valid {
				if got := reflect.ValueOf(v).String(); got != lit {
					t.Errorf("constant = %q, want %q", got, lit)
				}
				if !v.Valid() {
					t.Errorf("%q.Valid() = false", lit)
				}
			}
			for _, v := range tc.bogus {
				if v.Valid() {
					t.Errorf("%q.Valid() = true", reflect.ValueOf(v).String())
				}
			}
		})
	}
}

// TestVerdictMatchesDraftAndCore: 17.1 names exactly PASS, FAIL and UNKNOWN
// for check_context, and each maps to the CheckResult status of the same name.
func TestVerdictMatchesDraftAndCore(t *testing.T) {
	tests := []struct {
		in   Verdict
		want core.CheckStatus
	}{
		{VerdictPass, core.CheckPass},
		{VerdictFail, core.CheckFail},
		{VerdictUnknown, core.CheckUnknown},
		// A check that reported nothing valid established nothing.
		{Verdict(""), core.CheckUnknown},
		{Verdict("NOT_APPLICABLE"), core.CheckUnknown},
	}
	for _, tc := range tests {
		if got := tc.in.CheckStatus(); got != tc.want {
			t.Errorf("Verdict(%q).CheckStatus() = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestDecisionPermits: only an explicit allow permits. A deny, an unknown, the
// zero value and a mis-spelled effect all fail closed.
func TestDecisionPermits(t *testing.T) {
	tests := []struct {
		d    Decision
		want bool
	}{
		{Decision{Effect: EffectAllow}, true},
		{Decision{Effect: EffectAllow, Obligations: []Obligation{{ID: "redact"}}}, true},
		{Decision{Effect: EffectDeny}, false},
		{Decision{Effect: EffectDeny, Reason: "allow"}, false},
		{Decision{Effect: EffectUnknown}, false},
		{Decision{}, false},
		{Decision{Effect: Effect("allow")}, false},
	}
	for _, tc := range tests {
		if got := tc.d.Permits(); got != tc.want {
			t.Errorf("%+v.Permits() = %v, want %v", tc.d, got, tc.want)
		}
	}
}
