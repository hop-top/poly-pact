package evalcase_test

import (
	"path/filepath"
	"testing"

	"hop.top/pact-go/runner/evalcase"
)

// unknownBinding edits the authenticated member of native_context.json into
// the result of resolve_agent_binding for an agent with no record on the
// authenticated workload (identity mapping IM-11): binding_status unknown
// and no agent, operator or key.
func unknownBinding(a map[string]any) {
	a["binding_status"] = "unknown"
	a["agent_id"], a["operator_id"], a["holder_jkt"] = nil, nil, nil
}

// editAuthenticated applies f to the authenticated member of the case's
// native_context.json.
func editAuthenticated(t *testing.T, root, id string, f func(map[string]any)) {
	t.Helper()
	editJSON(t, root, id+"/native_context.json", func(n map[string]any) {
		f(n["authenticated"].(map[string]any))
	})
}

// TestBindingResult: native_context.json's authenticated member carries the
// binding results of identity mapping section 8 (spec/v1.0/fixtures/README.md,
// native_context.json): a status of the four, enrolled_elsewhere and
// binding_error with their defaults, and null agent, operator and key
// exactly when the status is unknown.
func TestBindingResult(t *testing.T) {
	const id = "admission/valid"
	t.Run("defaults", func(t *testing.T) {
		c, err := evalcase.Load(repoFixtures, id)
		if err != nil {
			t.Fatal(err)
		}
		a := c.Exchanges[0].NativeContext.Authenticated
		if a.AgentID == nil || *a.AgentID != "https://identity.example/agents/invoice-assistant" ||
			a.OperatorID == nil || *a.OperatorID != "https://identity.example/operators/acme" ||
			a.HolderJKT == nil || *a.HolderJKT != "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M" {
			t.Errorf("authenticated %+v: agent, operator and key not read", a)
		}
		if a.BindingStatus != "active" || a.EnrolledElsewhere || a.BindingError != nil {
			t.Errorf("status %q, enrolled_elsewhere %v, binding_error %v; want active, false, null",
				a.BindingStatus, a.EnrolledElsewhere, a.BindingError)
		}
		if got := c.Exchanges[0].Availability.EnrollmentSource; got != "available" {
			t.Errorf("enrollment_source %q, want the default available", got)
		}
	})

	accepted := []struct {
		name  string
		edit  func(map[string]any)
		check func(t *testing.T, a *evalcase.Authenticated)
	}{
		{"unknown, not enrolled elsewhere", unknownBinding, func(t *testing.T, a *evalcase.Authenticated) {
			if a.AgentID != nil || a.OperatorID != nil || a.HolderJKT != nil || a.EnrolledElsewhere || a.BindingError != nil {
				t.Errorf("authenticated %+v", a)
			}
		}},
		{"unknown, enrolled elsewhere", func(a map[string]any) {
			unknownBinding(a)
			a["enrolled_elsewhere"] = true
		}, func(t *testing.T, a *evalcase.Authenticated) {
			if !a.EnrolledElsewhere {
				t.Error("enrolled_elsewhere not read")
			}
		}},
		{"unknown, two enrollments", func(a map[string]any) {
			unknownBinding(a)
			a["binding_error"] = "UNSUPPORTED_REQUIREMENT"
		}, func(t *testing.T, a *evalcase.Authenticated) {
			if a.BindingError == nil || *a.BindingError != "UNSUPPORTED_REQUIREMENT" {
				t.Errorf("binding_error %v", a.BindingError)
			}
		}},
		{"explicit defaults", func(a map[string]any) {
			a["enrolled_elsewhere"], a["binding_error"] = false, nil
		}, func(t *testing.T, a *evalcase.Authenticated) {
			if a.EnrolledElsewhere || a.BindingError != nil || a.AgentID == nil {
				t.Errorf("authenticated %+v", a)
			}
		}},
		{"compromised", func(a map[string]any) { a["binding_status"] = "compromised" }, func(t *testing.T, a *evalcase.Authenticated) {
			if a.BindingStatus != "compromised" || a.HolderJKT == nil {
				t.Errorf("authenticated %+v", a)
			}
		}},
		{"revoked", func(a map[string]any) { a["binding_status"] = "revoked" }, func(t *testing.T, a *evalcase.Authenticated) {
			if a.BindingStatus != "revoked" {
				t.Errorf("authenticated %+v", a)
			}
		}},
	}
	for _, tc := range accepted {
		t.Run("accepts "+tc.name, func(t *testing.T) {
			root := caseTree(t, id)
			editAuthenticated(t, root, id, tc.edit)
			c, err := evalcase.Load(root, id)
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, c.Exchanges[0].NativeContext.Authenticated)
		})
	}

	rejected := []struct {
		name string
		edit func(map[string]any)
		want string
	}{
		{"a status outside the four", func(a map[string]any) { a["binding_status"] = "suspended" }, "binding_status"},
		{"an upper-case status", func(a map[string]any) { a["binding_status"] = "ACTIVE" }, "binding_status"},
		{"unknown with an agent", func(a map[string]any) {
			unknownBinding(a)
			a["agent_id"] = "https://identity.example/agents/invoice-assistant"
		}, "agent_id"},
		{"unknown with an operator", func(a map[string]any) {
			unknownBinding(a)
			a["operator_id"] = "https://identity.example/operators/acme"
		}, "operator_id"},
		{"unknown with a key", func(a map[string]any) {
			unknownBinding(a)
			a["holder_jkt"] = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
		}, "holder_jkt"},
		{"active with no agent", func(a map[string]any) { a["agent_id"] = nil }, "agent_id"},
		{"active with no operator", func(a map[string]any) { a["operator_id"] = nil }, "operator_id"},
		{"compromised with no key", func(a map[string]any) {
			a["binding_status"] = "compromised"
			a["holder_jkt"] = nil
		}, "holder_jkt"},
		{"active with an empty agent", func(a map[string]any) { a["agent_id"] = "" }, "agent_id"},
		{"enrolled elsewhere with an active binding", func(a map[string]any) { a["enrolled_elsewhere"] = true }, "enrolled_elsewhere"},
		{"enrolled elsewhere null", func(a map[string]any) {
			unknownBinding(a)
			a["enrolled_elsewhere"] = nil
		}, "enrolled_elsewhere"},
		{"binding error with an active binding", func(a map[string]any) { a["binding_error"] = "UNSUPPORTED_REQUIREMENT" }, "binding_error"},
		{"binding error of another code", func(a map[string]any) {
			unknownBinding(a)
			a["binding_error"] = "CONTEXT_MISMATCH"
		}, "binding_error"},
		{"a renamed member", func(a map[string]any) {
			unknownBinding(a)
			a["enrolled_for_another_workload"] = true
		}, "enrolled_for_another_workload"},
	}
	for _, tc := range rejected {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			root := caseTree(t, id)
			editAuthenticated(t, root, id, tc.edit)
			_, err := evalcase.Load(root, id)
			wantErr(t, err, "native_context.json", tc.want)
			_, err = evalcase.Read(root, id)
			wantErr(t, err, "native_context.json", tc.want)
		})
	}
}

// TestEnrollmentSource: exchange.json's availability.enrollment_source is
// available or unavailable (spec/v1.0/fixtures/README.md, availability).
func TestEnrollmentSource(t *testing.T) {
	const id = "admission/valid"
	for _, tc := range []struct {
		body, want string
	}{
		{`{"availability":{"enrollment_source":"unavailable"}}`, "unavailable"},
		{`{"availability":{"enrollment_source":"available"}}`, "available"},
		{`{"availability":{"replay_store":"unavailable"}}`, "available"},
		{`{"availability":{}}`, "available"},
	} {
		root := caseTree(t, id)
		writeFile(t, filepath.Join(root, id, "exchange.json"), []byte(tc.body))
		c, err := evalcase.Load(root, id)
		if err != nil {
			t.Fatalf("%s: %v", tc.body, err)
		}
		if got := c.Exchanges[0].Availability.EnrollmentSource; got != tc.want {
			t.Errorf("%s: enrollment_source %q, want %q", tc.body, got, tc.want)
		}
	}
	for _, body := range []string{
		`{"availability":{"enrollment_source":"down"}}`,
		`{"availability":{"enrollment_source":"full"}}`,
	} {
		root := caseTree(t, id)
		writeFile(t, filepath.Join(root, id, "exchange.json"), []byte(body))
		_, err := evalcase.Load(root, id)
		wantErr(t, err, "exchange.json", "enrollment_source")
	}
}
