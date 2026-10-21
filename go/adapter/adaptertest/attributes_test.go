package adaptertest

import (
	"encoding/json"
	"strings"
	"testing"

	"hop.top/pact-go/adapter"
)

func TestPrincipalAttributes(t *testing.T) {
	with := func(attrs map[string]any) adapter.Principal {
		p := goodPrincipal()
		p.Attributes = attrs
		return p
	}
	want := func(raw string) Expect {
		return Expect{Principal: &ExpectPrincipal{ID: goodPrincipal().ID, Attributes: json.RawMessage(raw)}}
	}
	cnf := map[string]any{"jkt": "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"}
	runRows(t, []row{
		{"equal", authFake(with(map[string]any{"cnf": cnf}), nil),
			authCase(outAuthenticated, want(`{"cnf": {"jkt": "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"}}`)), nil},
		{"unnamed attribute not checked", authFake(with(map[string]any{"cnf": cnf, "groups": []any{"a"}}), nil),
			authCase(outAuthenticated, want(`{"cnf": {"jkt": "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"}}`)), nil},
		{"member order ignored", authFake(with(map[string]any{"x": map[string]any{"a": 1, "b": 2}}), nil),
			authCase(outAuthenticated, want(`{"x": {"b": 2, "a": 1}}`)), nil},
		{"other value", authFake(with(map[string]any{"cnf": map[string]any{"jkt": "other"}}), nil),
			authCase(outAuthenticated, want(`{"cnf": {"jkt": "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"}}`)),
			[]string{`principal attribute "cnf"`}},
		{"missing attribute", authFake(with(nil), nil),
			authCase(outAuthenticated, want(`{"cnf": {"jkt": "a"}}`)), []string{`principal has no attribute "cnf"`}},
		{"array order kept", authFake(with(map[string]any{"groups": []any{"b", "a"}}), nil),
			authCase(outAuthenticated, want(`{"groups": ["a", "b"]}`)), []string{`principal attribute "groups"`}},
		{"absent member not checked", authFake(with(map[string]any{"cnf": cnf}), nil),
			authCase(outAuthenticated, Expect{Principal: &ExpectPrincipal{ID: goodPrincipal().ID}}), nil},
	})
}

func TestPrincipalAttributesMustBeAnObject(t *testing.T) {
	c := strings.Replace(minimalCase, `"outcome": "denied"}`,
		`"outcome": "authenticated", "principal": {"id": "p", "attributes": ["cnf"]}}`, 1)
	_, err := Load(treeOf(map[string]string{"adapters/_common/a.json": c}), "")
	if err == nil || !strings.Contains(err.Error(), "attributes is not a JSON object") {
		t.Errorf("Load = %v, want the attributes member refused", err)
	}
}
