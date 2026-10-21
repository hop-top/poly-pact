package abac_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapters/abac"
)

// The tests of this file are the executor's enforcement of profile ABAC-25
// to ABAC-29 (cases ABAC-28 to ABAC-34 of profile section 10).

// contract is the document the executor holds before release.
const contract = `{"title":"Supplier contract C-2041","supplier":{"name":"Fabrikam","iban":"DE89370400440532013000"},` +
	`"terms":"net 30","price":125000,"items":[{"sku":"A-1","cost":10},{"sku":"B-2","cost":20}],"notes":"internal only"}`

func envelope(obl ...adapter.Obligation) abac.Envelope {
	if obl == nil {
		obl = []adapter.Obligation{}
	}
	return abac.Envelope{OperationID: "op-document-read-0001", DecisionID: "d-1", PolicyVersion: entryVersion, Obligations: obl}
}

func ob(id string, params map[string]any) adapter.Obligation {
	return adapter.Obligation{ID: id, Attributes: params}
}

func keep(ptrs ...string) adapter.Obligation {
	return ob("filter_fields", map[string]any{"keep": toAny(ptrs)})
}

func redactOb(ptrs ...string) adapter.Obligation {
	return ob("redact", map[string]any{"paths": toAny(ptrs)})
}

func toAny(s []string) []any {
	out := []any{}
	for _, v := range s {
		out = append(out, v)
	}
	return out
}

var enforcer = abac.Enforcer{Watermarks: map[string]abac.Watermark{"application/json": abac.JSONMemberWatermark("_watermark")}}

func release(t *testing.T, env abac.Envelope, ct, content string) map[string]any {
	t.Helper()
	out, err := enforcer.Release(env, ct, []byte(content))
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("released %q: %v", out, err)
	}
	return v
}

func TestReleaseWithoutObligations(t *testing.T) {
	out, err := enforcer.Release(envelope(), "application/json", []byte(contract))
	if err != nil || string(out) != contract {
		t.Errorf("Release = %q, %v; want the content unchanged", out, err)
	}
}

// TestFilterFields is ABAC-30: nothing outside keep is released.
func TestFilterFields(t *testing.T) {
	v := release(t, envelope(keep("/title", "/supplier/name", "/items/1/sku", "/absent")), "application/json", contract)
	want := map[string]any{"title": "Supplier contract C-2041", "supplier": map[string]any{"name": "Fabrikam"},
		"items": []any{map[string]any{"sku": "B-2"}}}
	got, _ := json.Marshal(v)
	exp, _ := json.Marshal(want)
	if !bytes.Equal(got, exp) {
		t.Errorf("released %s, want %s", got, exp)
	}
	for _, secret := range []string{"DE89370400440532013000", "net 30", "125000", "internal only", "A-1"} {
		if strings.Contains(string(got), secret) {
			t.Errorf("released %s holds %q", got, secret)
		}
	}
}

// TestRedact is ABAC-31: the original value appears nowhere and the marker is
// present; a pointer is resolved after filtering (ABAC-26).
func TestRedact(t *testing.T) {
	env := envelope(redactOb("/supplier/iban", "/items/0/cost", "/missing"), keep("/supplier", "/items", "/title"))
	out, err := enforcer.Release(env, "application/json", []byte(contract))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "DE89370400440532013000") || !strings.Contains(string(out), abac.DefaultRedactionMarker) {
		t.Errorf("released %s", out)
	}
	var v map[string]any
	_ = json.Unmarshal(out, &v)
	if v["supplier"].(map[string]any)["iban"] != abac.DefaultRedactionMarker || v["items"].([]any)[0].(map[string]any)["cost"] != abac.DefaultRedactionMarker {
		t.Errorf("released %s", out)
	}
	if _, ok := v["terms"]; ok {
		t.Errorf("released %s holds a filtered member", out)
	}
}

// TestWatermark: the label is carried by the means of the content type.
func TestWatermark(t *testing.T) {
	v := release(t, envelope(ob("watermark", map[string]any{"label": "supplier-review"})), "application/json; charset=utf-8", contract)
	if v["_watermark"] != "supplier-review" {
		t.Errorf("watermark %v", v["_watermark"])
	}
}

// TestUnmetObligations is ABAC-28, ABAC-29, ABAC-32 and ABAC-33: an unknown
// type, malformed params, content the executor cannot treat, and a failure
// while applying release nothing.
func TestUnmetObligations(t *testing.T) {
	failing := abac.Enforcer{Watermarks: map[string]abac.Watermark{"application/json": {
		Apply:   func([]byte, string) ([]byte, error) { return nil, errors.New("disk full") },
		Present: func([]byte, string) bool { return true },
	}}}
	lying := abac.Enforcer{Watermarks: map[string]abac.Watermark{"application/json": {
		Apply:   func(b []byte, _ string) ([]byte, error) { return b, nil },
		Present: func([]byte, string) bool { return false },
	}}}
	panicking := abac.Enforcer{Watermarks: map[string]abac.Watermark{"application/json": {
		Apply:   func([]byte, string) ([]byte, error) { panic("boom") },
		Present: func([]byte, string) bool { return true },
	}}}
	wm := ob("watermark", map[string]any{"label": "x"})
	tests := []struct {
		name string
		e    abac.Enforcer
		env  abac.Envelope
		ct   string
		body string
		want error
	}{
		{"unknown type", enforcer, envelope(ob("encrypt_at_rest", map[string]any{})), "application/json", contract, abac.ErrObligationUnmet},
		{"type outside a narrower set", abac.Enforcer{Installed: []string{"redact"}}, envelope(keep("/title")), "application/json", contract, abac.ErrObligationUnmet},
		{"repeated type", enforcer, envelope(keep("/title"), keep("/terms")), "application/json", contract, abac.ErrObligationUnmet},
		{"filter without keep", enforcer, envelope(ob("filter_fields", map[string]any{})), "application/json", contract, abac.ErrObligationUnmet},
		{"filter with an extra param", enforcer, envelope(ob("filter_fields", map[string]any{"keep": []any{"/title"}, "deny": []any{}})), "application/json", contract, abac.ErrObligationUnmet},
		{"keep not an array", enforcer, envelope(ob("filter_fields", map[string]any{"keep": "/title"})), "application/json", contract, abac.ErrObligationUnmet},
		{"keep holds a number", enforcer, envelope(ob("filter_fields", map[string]any{"keep": []any{json.Number("1")}})), "application/json", contract, abac.ErrObligationUnmet},
		{"pointer without slash", enforcer, envelope(keep("title")), "application/json", contract, abac.ErrObligationUnmet},
		{"pointer with -", enforcer, envelope(redactOb("/items/-")), "application/json", contract, abac.ErrObligationUnmet},
		{"pointer with a bad escape", enforcer, envelope(redactOb("/a~2")), "application/json", contract, abac.ErrObligationUnmet},
		{"watermark without label", enforcer, envelope(ob("watermark", map[string]any{})), "application/json", contract, abac.ErrObligationUnmet},
		{"watermark with empty label", enforcer, envelope(ob("watermark", map[string]any{"label": ""})), "application/json", contract, abac.ErrObligationUnmet},
		{"watermark on a type with no means", enforcer, envelope(wm), "application/pdf", "%PDF-1.7", abac.ErrObligationUnmet},
		{"filter on content that is not JSON", enforcer, envelope(keep("/title")), "text/plain", contract, abac.ErrObligationUnmet},
		{"filter on malformed JSON", enforcer, envelope(keep("/title")), "application/json", `{"title":"a","title":"b"}`, abac.ErrObligationUnmet},
		{"filter on a scalar document", enforcer, envelope(keep("/title")), "application/json", `"title"`, abac.ErrObligationUnmet},
		{"watermark fails while applied", failing, envelope(wm), "application/json", contract, abac.ErrObligationUnmet},
		{"watermark not verified", lying, envelope(wm), "application/json", contract, abac.ErrObligationUnmet},
		{"watermark panics", panicking, envelope(wm), "application/json", contract, abac.ErrObligationUnmet},
		{"obligations absent", enforcer, abac.Envelope{OperationID: "op", DecisionID: "d"}, "application/json", contract, abac.ErrNoEnvelope},
		{"no decision id", enforcer, abac.Envelope{OperationID: "op", Obligations: []adapter.Obligation{}}, "application/json", contract, abac.ErrNoEnvelope},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.e.Release(tc.env, tc.ct, []byte(tc.body))
			if !errors.Is(err, tc.want) || out != nil {
				t.Errorf("Release = %q, %v; want no content and %v", out, err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), "Fabrikam") {
				t.Errorf("the error names content: %v", err)
			}
		})
	}
}

// TestParseEnvelope is ABAC-29 on the wire: absence is never "no
// obligations".
func TestParseEnvelope(t *testing.T) {
	env, err := abac.ParseEnvelope([]byte(`{"operation_id":"op","decision_id":"d","policy_version":"v","obligations":[{"type":"redact","params":{"paths":["/a"]}}]}`))
	if err != nil || len(env.Obligations) != 1 || env.Obligations[0].ID != "redact" {
		t.Fatalf("ParseEnvelope = %+v, %v", env, err)
	}
	if env, err := abac.ParseEnvelope([]byte(`{"operation_id":"op","decision_id":"d","policy_version":"v","obligations":[]}`)); err != nil || env.Obligations == nil {
		t.Errorf("an empty array: %+v, %v", env, err)
	}
	for _, raw := range []string{
		`{"operation_id":"op","decision_id":"d","policy_version":"v"}`,
		`{"operation_id":"op","decision_id":"d","policy_version":"v","obligations":null}`,
		`{"operation_id":"op","decision_id":"d","policy_version":"v","obligations":{}}`,
		`{"operation_id":"op","decision_id":"d","policy_version":"v","obligations":[{"type":"redact"}]}`,
		`{"decision_id":"d","policy_version":"v","obligations":[]}`,
		`not json`,
	} {
		if _, err := abac.ParseEnvelope([]byte(raw)); !errors.Is(err, abac.ErrNoEnvelope) {
			t.Errorf("ParseEnvelope(%s) = %v, want ErrNoEnvelope", raw, err)
		}
	}
	d := adapter.Decision{Effect: adapter.EffectAllow, SourceRef: "d-9", PolicyRevision: "v", Obligations: nil}
	if e := abac.EnvelopeFor("op", d); e.Obligations == nil || e.DecisionID != "d-9" {
		t.Errorf("EnvelopeFor = %+v: a decision with no obligation gives an empty array", e)
	}
}
