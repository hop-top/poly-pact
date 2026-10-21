package enroll_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/core"
)

var realm = adapter.Realm{TenantID: "tenant-1", EnvironmentID: "prod"}

func TestActorKindValid(t *testing.T) {
	tests := []struct {
		kind enroll.ActorKind
		want bool
	}{
		{enroll.Admin, true},
		{enroll.AuthorizedIssuer, true},
		{enroll.Agent, true},
		{"", false},
		{"admin", false},
		{"ROOT", false},
	}
	for _, tc := range tests {
		if got := tc.kind.Valid(); got != tc.want {
			t.Errorf("ActorKind(%q).Valid() = %v, want %v", tc.kind, got, tc.want)
		}
	}
}

// TestCheckAuthority pins who may change an enrollment: the draft 6.1 and 6.4
// actors (a native authenticated administrative workflow and an authorized
// identity-binding or rotation issuer), scoped to one realm and attributable.
func TestCheckAuthority(t *testing.T) {
	tests := []struct {
		name  string
		actor enroll.Actor
		ok    bool
	}{
		{"admin", enroll.Actor{Kind: enroll.Admin, ID: "a1", Realm: realm}, true},
		{"authorized issuer", enroll.Actor{Kind: enroll.AuthorizedIssuer, ID: "i1", Realm: realm}, true},
		{"agent itself", enroll.Actor{Kind: enroll.Agent, ID: "https://agents.example/a", Realm: realm}, false},
		{"empty kind", enroll.Actor{ID: "a1", Realm: realm}, false},
		{"undefined kind", enroll.Actor{Kind: "OWNER", ID: "a1", Realm: realm}, false},
		{"lower-case kind", enroll.Actor{Kind: "admin", ID: "a1", Realm: realm}, false},
		{"admin without id", enroll.Actor{Kind: enroll.Admin, Realm: realm}, false},
		{"admin without realm", enroll.Actor{Kind: enroll.Admin, ID: "a1"}, false},
		{"admin without tenant", enroll.Actor{Kind: enroll.Admin, ID: "a1", Realm: adapter.Realm{EnvironmentID: "prod"}}, false},
		{"admin without environment", enroll.Actor{Kind: enroll.Admin, ID: "a1", Realm: adapter.Realm{TenantID: "tenant-1"}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.actor.CheckAuthority()
			if tc.ok && err != nil {
				t.Fatalf("CheckAuthority() = %v, want nil", err)
			}
			if !tc.ok && !errors.Is(err, enroll.ErrNotAuthorized) {
				t.Fatalf("CheckAuthority() = %v, want ErrNotAuthorized", err)
			}
		})
	}
}

// stubRegistry records the arguments of Lookup and returns canned results.
type stubRegistry struct {
	enroll.Registry
	gotRealm    adapter.Realm
	gotWorkload adapter.Workload
	gotAgent    adapter.AgentID
	binding     adapter.AgentBinding
	err         error
}

func (s *stubRegistry) Lookup(_ context.Context, r adapter.Realm, w adapter.Workload, a adapter.AgentID) (adapter.AgentBinding, error) {
	s.gotRealm, s.gotWorkload, s.gotAgent = r, w, a
	return s.binding, s.err
}

var _ adapter.BindingResolver = enroll.Resolver{}

func TestResolverDelegatesToLookup(t *testing.T) {
	want := adapter.AgentBinding{
		AgentID:    "https://agents.example/a",
		OperatorID: "op-1",
		HolderJKT:  core.Digest("0123456789012345678901234567890123456789012"),
		Status:     adapter.BindingCompromised,
	}
	stub := &stubRegistry{binding: want}
	var r adapter.BindingResolver = enroll.Resolver{Registry: stub}

	got, err := r.ResolveAgentBinding(t.Context(), realm, "acct:1", "https://agents.example/a")
	if err != nil {
		t.Fatalf("ResolveAgentBinding() error = %v", err)
	}
	if got != want {
		t.Errorf("binding = %+v, want %+v", got, want)
	}
	if stub.gotRealm != realm || stub.gotWorkload != "acct:1" || stub.gotAgent != "https://agents.example/a" {
		t.Errorf("Lookup got (%v, %q, %q), want (%v, %q, %q)", stub.gotRealm, stub.gotWorkload, stub.gotAgent,
			realm, "acct:1", "https://agents.example/a")
	}
}

func TestResolverKeepsDependencyError(t *testing.T) {
	stub := &stubRegistry{err: fmt.Errorf("store down: %w", adapter.ErrDependencyUnavailable)}
	_, err := enroll.Resolver{Registry: stub}.ResolveAgentBinding(t.Context(), realm, "acct:1", "https://agents.example/a")
	if !errors.Is(err, adapter.ErrDependencyUnavailable) {
		t.Fatalf("error = %v, want one that wraps ErrDependencyUnavailable", err)
	}
	if code, ok := adapter.CodeOf(err); !ok || code != adapter.CodeDependencyUnavailable {
		t.Errorf("CodeOf = (%q, %v), want DEPENDENCY_UNAVAILABLE", code, ok)
	}
}
