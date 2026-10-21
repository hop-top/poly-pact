package memory_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/enroll/memory"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

var (
	_ enroll.Registry         = (*memory.Registry)(nil)
	_ adapter.BindingResolver = enroll.Resolver{Registry: (*memory.Registry)(nil)}
)

var (
	realm       = adapter.Realm{TenantID: "tenant-1", EnvironmentID: "prod"}
	otherTenant = adapter.Realm{TenantID: "tenant-2", EnvironmentID: "prod"}
	otherEnv    = adapter.Realm{TenantID: "tenant-1", EnvironmentID: "staging"}

	admin  = enroll.Actor{Kind: enroll.Admin, ID: "admin-1", Realm: realm}
	issuer = enroll.Actor{Kind: enroll.AuthorizedIssuer, ID: "issuer-1", Realm: realm}
)

const (
	agentA = "https://agents.example/a"
	agentB = "https://agents.example/b"

	workloadA adapter.Workload = "acct:1001"
	workloadB adapter.Workload = "acct:1002"
	shared    adapter.Workload = "acct:shared"
)

var start = time.Unix(1_700_000_000, 0)

// jkt returns a valid 43-character thumbprint derived from label.
func jkt(label string) core.Digest {
	sum := sha256.Sum256([]byte(label))
	return core.Digest(base64.RawURLEncoding.EncodeToString(sum[:]))
}

type fixture struct {
	reg *memory.Registry
	clk *clock.Fake
}

func newFixture(opts ...memory.Option) *fixture {
	clk := clock.NewFake(start)
	return &fixture{
		reg: memory.New(append([]memory.Option{memory.WithClock(clk), memory.WithSourceID("test-source")}, opts...)...),
		clk: clk,
	}
}

func (f *fixture) enroll(t *testing.T, agent string, wl adapter.Workload, key core.Digest) {
	t.Helper()
	err := f.reg.Enroll(t.Context(), admin, memory.Enrollment{
		AgentID: agent, OperatorID: "op-1", Workload: wl, HolderJKT: key,
	})
	if err != nil {
		t.Fatalf("Enroll(%s) = %v", agent, err)
	}
}

func (f *fixture) lookup(t *testing.T, r adapter.Realm, wl adapter.Workload, agent adapter.AgentID) adapter.AgentBinding {
	t.Helper()
	b, err := f.reg.Lookup(t.Context(), r, wl, agent)
	if err != nil {
		t.Fatalf("Lookup(%v, %q, %q) = %v", r, wl, agent, err)
	}
	return b
}

// wantBinding fails unless Lookup of the agent on the workload reports status
// and holder key.
func (f *fixture) wantBinding(t *testing.T, wl adapter.Workload, agent adapter.AgentID, status adapter.BindingStatus, key core.Digest) {
	t.Helper()
	b := f.lookup(t, realm, wl, agent)
	if b.Status != status || b.HolderJKT != key {
		t.Fatalf("Lookup(%q, %q) = status %s key %q, want status %s key %q", wl, agent, b.Status, b.HolderJKT, status, key)
	}
}

func TestLookupActive(t *testing.T) {
	f := newFixture()
	f.enroll(t, agentA, workloadA, jkt("a1"))

	got := f.lookup(t, realm, workloadA, agentA)
	if got.AgentID != agentA || got.OperatorID != "op-1" || got.HolderJKT != jkt("a1") {
		t.Errorf("binding identity = (%q, %q, %q)", got.AgentID, got.OperatorID, got.HolderJKT)
	}
	if got.Status != adapter.BindingActive {
		t.Errorf("Status = %s, want ACTIVE", got.Status)
	}
	if !got.ObservedAt.Equal(start) || !got.StatusCheckedAt.Equal(start) {
		t.Errorf("times = (%v, %v), want both %v", got.ObservedAt, got.StatusCheckedAt, start)
	}
	if got.SourceID != "test-source" {
		t.Errorf("SourceID = %q, want test-source", got.SourceID)
	}
	if got.SourceRef == "" {
		t.Error("SourceRef is empty, want an opaque row reference")
	}
}

// TestLookupKeepsObservationTime: draft 17.1 invariant 2. A read confirms the
// status now; it never restamps the original observation.
func TestLookupKeepsObservationTime(t *testing.T) {
	f := newFixture()
	f.enroll(t, agentA, workloadA, jkt("a1"))
	f.clk.Advance(90 * time.Second)

	got := f.lookup(t, realm, workloadA, agentA)
	if !got.ObservedAt.Equal(start) {
		t.Errorf("ObservedAt = %v, want the enrollment time %v", got.ObservedAt, start)
	}
	if want := start.Add(90 * time.Second); !got.StatusCheckedAt.Equal(want) {
		t.Errorf("StatusCheckedAt = %v, want the read time %v", got.StatusCheckedAt, want)
	}
}

func TestSourceRefIsStablePerEnrollment(t *testing.T) {
	f := newFixture()
	f.enroll(t, agentA, workloadA, jkt("a1"))
	f.enroll(t, agentB, workloadB, jkt("b1"))

	before := f.lookup(t, realm, workloadA, agentA).SourceRef
	if err := f.reg.Rotate(t.Context(), admin, agentA, jkt("a2")); err != nil {
		t.Fatal(err)
	}
	if after := f.lookup(t, realm, workloadA, agentA).SourceRef; after != before {
		t.Errorf("SourceRef changed across rotation: %q -> %q", before, after)
	}
	if other := f.lookup(t, realm, workloadB, agentB).SourceRef; other == before {
		t.Errorf("two enrollments share SourceRef %q", other)
	}
}

func TestLookupNotEnrolled(t *testing.T) {
	f := newFixture()
	f.enroll(t, agentA, workloadA, jkt("a1"))
	f.clk.Advance(time.Minute)

	got, err := f.reg.Lookup(t.Context(), realm, "acct:9999", agentA)
	if err != nil {
		t.Fatalf("Lookup() error = %v, want nil: an absent binding is UNKNOWN, not an error", err)
	}
	if got.Status != adapter.BindingUnknown {
		t.Errorf("Status = %s, want UNKNOWN", got.Status)
	}
	if got.AgentID != "" || got.OperatorID != "" || got.HolderJKT != "" {
		t.Errorf("UNKNOWN binding carries an identity: %+v", got)
	}
	if !got.ObservedAt.IsZero() {
		t.Errorf("ObservedAt = %v, want zero: nothing was observed", got.ObservedAt)
	}
	if want := f.clk.Now(); !got.StatusCheckedAt.Equal(want) || got.SourceID != "test-source" {
		t.Errorf("StatusCheckedAt/SourceID = %v/%q, want %v/test-source", got.StatusCheckedAt, got.SourceID, want)
	}
}

// TestLookupDistinguishesRealmAndWorkload: the same workload text in another
// tenant or environment, and a near-miss spelling of the workload or of the
// agent ID, is another identity (draft 8.5, 17.2).
func TestLookupDistinguishesRealmAndWorkload(t *testing.T) {
	f := newFixture()
	f.enroll(t, agentA, "User:Alice", jkt("a1"))

	tests := []struct {
		name  string
		r     adapter.Realm
		wl    adapter.Workload
		agent adapter.AgentID
	}{
		{"other tenant", otherTenant, "User:Alice", agentA},
		{"other environment", otherEnv, "User:Alice", agentA},
		{"zero realm", adapter.Realm{}, "User:Alice", agentA},
		{"other case", realm, "user:alice", agentA},
		{"trailing space", realm, "User:Alice ", agentA},
		{"empty workload", realm, "", agentA},
		{"agent in other case", realm, "User:Alice", "https://agents.example/A"},
		{"agent with trailing slash", realm, "User:Alice", agentA + "/"},
		{"empty agent", realm, "User:Alice", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := f.lookup(t, tc.r, tc.wl, tc.agent); got.Status != adapter.BindingUnknown || got.AgentID != "" {
				t.Fatalf("Lookup(%v, %q, %q) = %+v, want UNKNOWN without identity", tc.r, tc.wl, tc.agent, got)
			}
		})
	}
	f.wantBinding(t, "User:Alice", agentA, adapter.BindingActive, jkt("a1"))
}

// TestLookupEnrolledElsewhere: an UNKNOWN answer reports whether the agent ID
// is enrolled for another workload of the realm, in any status (draft 17.1). A
// binding on the workload never carries the report, and an enrollment in
// another tenant or environment never sets it.
func TestLookupEnrolledElsewhere(t *testing.T) {
	const agentD = "https://agents.example/d"
	f := newFixture()
	f.enroll(t, agentA, shared, jkt("a1"))
	f.enroll(t, agentB, workloadB, jkt("b1"))
	if err := f.reg.Revoke(t.Context(), admin, agentB); err != nil {
		t.Fatal(err)
	}
	other := enroll.Actor{Kind: enroll.Admin, ID: "admin-2", Realm: otherEnv}
	if err := f.reg.Enroll(t.Context(), other, memory.Enrollment{AgentID: agentD, OperatorID: "op-1", Workload: workloadA, HolderJKT: jkt("d1")}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name      string
		r         adapter.Realm
		wl        adapter.Workload
		agent     adapter.AgentID
		status    adapter.BindingStatus
		elsewhere bool
	}{
		{"binding on the workload", realm, shared, agentA, adapter.BindingActive, false},
		{"revoked binding on the workload", realm, workloadB, agentB, adapter.BindingRevoked, false},
		{"agent of another workload", realm, workloadA, agentA, adapter.BindingUnknown, true},
		{"revoked agent of another workload", realm, shared, agentB, adapter.BindingUnknown, true},
		{"agent not enrolled", realm, shared, "https://agents.example/c", adapter.BindingUnknown, false},
		{"agent of another environment only", realm, shared, agentD, adapter.BindingUnknown, false},
		{"agent of another environment, same workload text", realm, workloadA, agentD, adapter.BindingUnknown, false},
		{"agent of the realm, asked in another tenant", otherTenant, workloadA, agentA, adapter.BindingUnknown, false},
		{"no agent named", realm, shared, "", adapter.BindingUnknown, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := f.lookup(t, tc.r, tc.wl, tc.agent)
			if got.Status != tc.status || got.EnrolledElsewhere != tc.elsewhere {
				t.Errorf("Lookup(%v, %q, %q) = status %s, enrolled elsewhere %t; want %s, %t",
					tc.r, tc.wl, tc.agent, got.Status, got.EnrolledElsewhere, tc.status, tc.elsewhere)
			}
		})
	}
	if err := f.reg.MarkCompromised(t.Context(), admin, agentA); err != nil {
		t.Fatal(err)
	}
	if got := f.lookup(t, realm, workloadA, agentA); got.Status != adapter.BindingUnknown || !got.EnrolledElsewhere {
		t.Errorf("compromised agent of another workload: %+v, want UNKNOWN, enrolled elsewhere", got)
	}
}

func TestEnrollRequiresAuthorityAndValidInput(t *testing.T) {
	good := memory.Enrollment{AgentID: agentA, OperatorID: "op-1", Workload: workloadA, HolderJKT: jkt("a1")}
	with := func(mod func(*memory.Enrollment)) memory.Enrollment { e := good; mod(&e); return e }

	tests := []struct {
		name  string
		actor enroll.Actor
		e     memory.Enrollment
		want  error
	}{
		{"agent enrolling itself", enroll.Actor{Kind: enroll.Agent, ID: agentA, Realm: realm}, good, enroll.ErrNotAuthorized},
		{"empty actor", enroll.Actor{}, good, enroll.ErrNotAuthorized},
		{"relative agent id", admin, with(func(e *memory.Enrollment) { e.AgentID = "agent-a" }), enroll.ErrInvalid},
		{"empty agent id", admin, with(func(e *memory.Enrollment) { e.AgentID = "" }), enroll.ErrInvalid},
		{"agent id with fragment", admin, with(func(e *memory.Enrollment) { e.AgentID = agentA + "#x" }), enroll.ErrInvalid},
		{"agent id with empty fragment", admin, with(func(e *memory.Enrollment) { e.AgentID = agentA + "#" }), enroll.ErrInvalid},
		{"agent id with space", admin, with(func(e *memory.Enrollment) { e.AgentID = "https://agents.example/a b" }), enroll.ErrInvalid},
		{"empty operator", admin, with(func(e *memory.Enrollment) { e.OperatorID = "" }), enroll.ErrInvalid},
		{"empty workload", admin, with(func(e *memory.Enrollment) { e.Workload = "" }), enroll.ErrInvalid},
		{"short key", admin, with(func(e *memory.Enrollment) { e.HolderJKT = "abc" }), enroll.ErrInvalid},
		{"padded key", admin, with(func(e *memory.Enrollment) { e.HolderJKT = jkt("a1") + "=" }), enroll.ErrInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			err := f.reg.Enroll(t.Context(), tc.actor, tc.e)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Enroll() = %v, want %v", err, tc.want)
			}
			if got := f.lookup(t, realm, workloadA, agentA); got.Status != adapter.BindingUnknown {
				t.Fatalf("a failed enrollment left a binding: %+v", got)
			}
		})
	}
}

func TestEnrollConflicts(t *testing.T) {
	f := newFixture()
	f.enroll(t, agentA, workloadA, jkt("a1"))

	// Same agent_id again, even with a new key and workload.
	err := f.reg.Enroll(t.Context(), admin, memory.Enrollment{
		AgentID: agentA, OperatorID: "op-2", Workload: workloadB, HolderJKT: jkt("a9"),
	})
	if !errors.Is(err, enroll.ErrAlreadyEnrolled) {
		t.Errorf("duplicate agent_id: Enroll() = %v, want ErrAlreadyEnrolled", err)
	}

	// A holder key already bound to another agent of the realm.
	err = f.reg.Enroll(t.Context(), admin, memory.Enrollment{
		AgentID: agentB, OperatorID: "op-1", Workload: workloadB, HolderJKT: jkt("a1"),
	})
	if !errors.Is(err, enroll.ErrKeyReuse) {
		t.Errorf("shared holder key: Enroll() = %v, want ErrKeyReuse", err)
	}

	f.wantBinding(t, workloadA, agentA, adapter.BindingActive, jkt("a1"))
	if got := f.lookup(t, realm, workloadB, agentB); got.Status != adapter.BindingUnknown {
		t.Errorf("a refused enrollment left a binding: %+v", got)
	}
}

// TestEnrollIsRealmScoped: the same agent_id and the same key in another realm
// are separate enrollments, and an admin acts only in its own realm.
func TestEnrollIsRealmScoped(t *testing.T) {
	f := newFixture()
	f.enroll(t, agentA, workloadA, jkt("a1"))
	other := enroll.Actor{Kind: enroll.Admin, ID: "admin-2", Realm: otherTenant}
	err := f.reg.Enroll(t.Context(), other, memory.Enrollment{
		AgentID: agentA, OperatorID: "op-9", Workload: workloadA, HolderJKT: jkt("a1"),
	})
	if err != nil {
		t.Fatalf("Enroll in another tenant = %v, want nil", err)
	}
	if got := f.lookup(t, otherTenant, workloadA, agentA); got.OperatorID != "op-9" || got.Status != adapter.BindingActive {
		t.Errorf("other tenant binding = %+v", got)
	}
	if got := f.lookup(t, realm, workloadA, agentA); got.OperatorID != "op-1" {
		t.Errorf("first tenant binding changed: %+v", got)
	}
}

// TestRotateRequiresAdminOrIssuer is the first required case: rotation by a
// non-admin is rejected and leaves the binding untouched (draft 6.4).
func TestRotateRequiresAdminOrIssuer(t *testing.T) {
	tests := []struct {
		name  string
		actor enroll.Actor
	}{
		{"agent with the old key", enroll.Actor{Kind: enroll.Agent, ID: agentA, Realm: realm}},
		{"agent claiming admin id", enroll.Actor{Kind: enroll.Agent, ID: "admin-1", Realm: realm}},
		{"zero actor", enroll.Actor{}},
		{"undefined kind", enroll.Actor{Kind: "OPERATOR", ID: "op-1", Realm: realm}},
		{"admin without id", enroll.Actor{Kind: enroll.Admin, Realm: realm}},
		{"admin without realm", enroll.Actor{Kind: enroll.Admin, ID: "admin-1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			f.enroll(t, agentA, workloadA, jkt("a1"))

			err := f.reg.Rotate(t.Context(), tc.actor, agentA, jkt("a2"))
			if !errors.Is(err, enroll.ErrNotAuthorized) {
				t.Fatalf("Rotate() = %v, want ErrNotAuthorized", err)
			}
			f.wantBinding(t, workloadA, agentA, adapter.BindingActive, jkt("a1"))
		})
	}
}

func TestRotateByAdminAndIssuer(t *testing.T) {
	for name, actor := range map[string]enroll.Actor{"admin": admin, "authorized issuer": issuer} {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			f.enroll(t, agentA, workloadA, jkt("a1"))
			f.clk.Advance(time.Hour + time.Minute)

			if err := f.reg.Rotate(t.Context(), actor, agentA, jkt("a2")); err != nil {
				t.Fatalf("Rotate() = %v", err)
			}
			got := f.lookup(t, realm, workloadA, agentA)
			if got.HolderJKT != jkt("a2") || got.Status != adapter.BindingActive || got.AgentID != agentA || got.OperatorID != "op-1" {
				t.Fatalf("after rotation binding = %+v", got)
			}
			if want := start.Add(time.Hour + time.Minute); !got.ObservedAt.Equal(want) {
				t.Errorf("ObservedAt = %v, want the rotation time %v", got.ObservedAt, want)
			}
		})
	}
}

func TestRotateRejectsBadKeys(t *testing.T) {
	f := newFixture()
	f.enroll(t, agentA, workloadA, jkt("a1"))
	f.enroll(t, agentB, workloadB, jkt("b1"))
	if err := f.reg.Rotate(t.Context(), admin, agentA, jkt("a2")); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		key  core.Digest
		want error
	}{
		{"malformed", "not-a-thumbprint", enroll.ErrInvalid},
		{"empty", "", enroll.ErrInvalid},
		{"current key", jkt("a2"), enroll.ErrKeyReuse},
		{"retired key", jkt("a1"), enroll.ErrKeyReuse},
		{"another agent's key", jkt("b1"), enroll.ErrKeyReuse},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := f.reg.Rotate(t.Context(), admin, agentA, tc.key); !errors.Is(err, tc.want) {
				t.Fatalf("Rotate() = %v, want %v", err, tc.want)
			}
			f.wantBinding(t, workloadA, agentA, adapter.BindingActive, jkt("a2"))
		})
	}
}

func TestRotateUnknownAgent(t *testing.T) {
	f := newFixture()
	f.enroll(t, agentA, workloadA, jkt("a1"))

	if err := f.reg.Rotate(t.Context(), admin, agentB, jkt("b1")); !errors.Is(err, enroll.ErrNotFound) {
		t.Errorf("unknown agent: Rotate() = %v, want ErrNotFound", err)
	}
	// An admin of another tenant has no authority over this realm's agent.
	foreign := enroll.Actor{Kind: enroll.Admin, ID: "admin-2", Realm: otherTenant}
	if err := f.reg.Rotate(t.Context(), foreign, agentA, jkt("a2")); !errors.Is(err, enroll.ErrNotFound) {
		t.Errorf("foreign admin: Rotate() = %v, want ErrNotFound", err)
	}
	f.wantBinding(t, workloadA, agentA, adapter.BindingActive, jkt("a1"))
}

func TestMarkCompromised(t *testing.T) {
	for name, actor := range map[string]enroll.Actor{"admin": admin, "authorized issuer": issuer} {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			f.enroll(t, agentA, workloadA, jkt("a1"))
			f.clk.Advance(time.Hour)

			if err := f.reg.MarkCompromised(t.Context(), actor, agentA); err != nil {
				t.Fatalf("MarkCompromised() = %v", err)
			}
			got := f.lookup(t, realm, workloadA, agentA)
			if got.Status != adapter.BindingCompromised {
				t.Fatalf("Status = %s, want COMPROMISED", got.Status)
			}
			if got.AgentID != agentA || got.HolderJKT != jkt("a1") {
				t.Errorf("a compromised binding must still name the agent and key: %+v", got)
			}
			if want := start.Add(time.Hour); !got.ObservedAt.Equal(want) {
				t.Errorf("ObservedAt = %v, want the marking time %v", got.ObservedAt, want)
			}
		})
	}
}

func TestMarkCompromisedRequiresAuthority(t *testing.T) {
	for name, actor := range map[string]enroll.Actor{
		"agent":          {Kind: enroll.Agent, ID: agentA, Realm: realm},
		"zero":           {},
		"admin no id":    {Kind: enroll.Admin, Realm: realm},
		"admin no realm": {Kind: enroll.Admin, ID: "admin-1"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			f.enroll(t, agentA, workloadA, jkt("a1"))
			if err := f.reg.MarkCompromised(t.Context(), actor, agentA); !errors.Is(err, enroll.ErrNotAuthorized) {
				t.Fatalf("MarkCompromised() = %v, want ErrNotAuthorized", err)
			}
			f.wantBinding(t, workloadA, agentA, adapter.BindingActive, jkt("a1"))
		})
	}
}

func TestMarkCompromisedUnknownAgent(t *testing.T) {
	f := newFixture()
	f.enroll(t, agentA, workloadA, jkt("a1"))
	foreign := enroll.Actor{Kind: enroll.Admin, ID: "admin-2", Realm: otherTenant}
	tests := []struct {
		name  string
		actor enroll.Actor
		agent string
	}{
		{"unknown agent", admin, agentB},
		{"admin of another tenant", foreign, agentA},
	}
	for _, tc := range tests {
		if err := f.reg.MarkCompromised(t.Context(), tc.actor, tc.agent); !errors.Is(err, enroll.ErrNotFound) {
			t.Errorf("%s: MarkCompromised() = %v, want ErrNotFound", tc.name, err)
		}
	}
	f.wantBinding(t, workloadA, agentA, adapter.BindingActive, jkt("a1"))
}

// TestCompromisedNeverRecovers is the second required case (draft 6.4): no
// call sequence, whoever makes it, returns a compromised binding to ACTIVE
// through Lookup, and the original observation time of the marking survives.
func TestCompromisedNeverRecovers(t *testing.T) {
	f := newFixture()
	f.enroll(t, agentA, workloadA, jkt("a1"))
	f.clk.Advance(time.Hour)
	markedAt := f.clk.Now()
	if err := f.reg.MarkCompromised(t.Context(), admin, agentA); err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(time.Hour)

	steps := []struct {
		name string
		do   func() error
		want error // nil: the call may succeed, anything else must be this error
	}{
		{"rotate by admin", func() error { return f.reg.Rotate(t.Context(), admin, agentA, jkt("a2")) }, enroll.ErrCompromised},
		{"rotate by issuer", func() error { return f.reg.Rotate(t.Context(), issuer, agentA, jkt("a3")) }, enroll.ErrCompromised},
		{"rotate by the agent", func() error {
			return f.reg.Rotate(t.Context(), enroll.Actor{Kind: enroll.Agent, ID: agentA, Realm: realm}, agentA, jkt("a4"))
		}, enroll.ErrNotAuthorized},
		{"revoke", func() error { return f.reg.Revoke(t.Context(), admin, agentA) }, enroll.ErrCompromised},
		{"enroll again, new key", func() error {
			return f.reg.Enroll(t.Context(), admin, memory.Enrollment{AgentID: agentA, OperatorID: "op-1", Workload: workloadA, HolderJKT: jkt("a5")})
		}, enroll.ErrAlreadyEnrolled},
		{"enroll again, same key", func() error {
			return f.reg.Enroll(t.Context(), admin, memory.Enrollment{AgentID: agentA, OperatorID: "op-1", Workload: workloadA, HolderJKT: jkt("a1")})
		}, enroll.ErrAlreadyEnrolled},
		{"mark again", func() error { return f.reg.MarkCompromised(t.Context(), admin, agentA) }, nil},
	}
	for _, s := range steps {
		err := s.do()
		switch {
		case s.want == nil && err != nil:
			t.Errorf("%s: error = %v, want nil", s.name, err)
		case s.want != nil && !errors.Is(err, s.want):
			t.Errorf("%s: error = %v, want %v", s.name, err, s.want)
		}
		got := f.lookup(t, realm, workloadA, agentA)
		if got.Status != adapter.BindingCompromised || got.HolderJKT != jkt("a1") || got.AgentID != agentA {
			t.Fatalf("after %q Lookup = %+v, want COMPROMISED with the original key", s.name, got)
		}
		if !got.ObservedAt.Equal(markedAt) {
			t.Fatalf("after %q ObservedAt = %v, want the first marking time %v", s.name, got.ObservedAt, markedAt)
		}
	}
}

func TestRevoke(t *testing.T) {
	f := newFixture()
	f.enroll(t, agentA, workloadA, jkt("a1"))
	f.clk.Advance(time.Hour)

	if err := f.reg.Revoke(t.Context(), enroll.Actor{Kind: enroll.Agent, ID: agentA, Realm: realm}, agentA); !errors.Is(err, enroll.ErrNotAuthorized) {
		t.Fatalf("Revoke by the agent = %v, want ErrNotAuthorized", err)
	}
	f.wantBinding(t, workloadA, agentA, adapter.BindingActive, jkt("a1"))

	if err := f.reg.Revoke(t.Context(), admin, agentA); err != nil {
		t.Fatalf("Revoke() = %v", err)
	}
	got := f.lookup(t, realm, workloadA, agentA)
	if got.Status != adapter.BindingRevoked || got.AgentID != agentA || got.HolderJKT != jkt("a1") {
		t.Fatalf("after revoke Lookup = %+v, want REVOKED naming the agent and key", got)
	}

	// A revoked binding is not rotated back to life, and revoking again is a no-op.
	if err := f.reg.Rotate(t.Context(), admin, agentA, jkt("a2")); !errors.Is(err, enroll.ErrRevoked) {
		t.Errorf("Rotate on revoked = %v, want ErrRevoked", err)
	}
	if err := f.reg.Revoke(t.Context(), admin, agentA); err != nil {
		t.Errorf("second Revoke() = %v, want nil", err)
	}
	if err := f.reg.Enroll(t.Context(), admin, memory.Enrollment{AgentID: agentA, OperatorID: "op-1", Workload: workloadA, HolderJKT: jkt("a3")}); !errors.Is(err, enroll.ErrAlreadyEnrolled) {
		t.Errorf("re-enroll a revoked agent_id = %v, want ErrAlreadyEnrolled", err)
	}
	f.wantBinding(t, workloadA, agentA, adapter.BindingRevoked, jkt("a1"))

	// A revoked binding can still be found compromised, and then stays so.
	if err := f.reg.MarkCompromised(t.Context(), admin, agentA); err != nil {
		t.Fatalf("MarkCompromised on revoked = %v", err)
	}
	f.wantBinding(t, workloadA, agentA, adapter.BindingCompromised, jkt("a1"))
}

func TestRevokeUnknownAgent(t *testing.T) {
	f := newFixture()
	if err := f.reg.Revoke(t.Context(), admin, agentA); !errors.Is(err, enroll.ErrNotFound) {
		t.Fatalf("Revoke() = %v, want ErrNotFound", err)
	}
}

// TestSharedWorkload: draft 5 invariant 3, 6.1 and 17.1. A credential shared
// by two agents names the account, never an agent; each agent has its own row,
// and Lookup selects the row of the agent the request names among the rows of
// the workload, never a row of another workload or of another agent.
func TestSharedWorkload(t *testing.T) {
	const agentD = "https://agents.example/d"
	f := newFixture(memory.WithSharedWorkloads())
	f.enroll(t, agentA, shared, jkt("a1"))
	f.enroll(t, agentB, shared, jkt("b1"))
	f.enroll(t, agentD, workloadA, jkt("d1"))

	for _, tc := range []struct {
		agent adapter.AgentID
		key   core.Digest
	}{{agentA, jkt("a1")}, {agentB, jkt("b1")}} {
		got := f.lookup(t, realm, shared, tc.agent)
		if got.Status != adapter.BindingActive || got.AgentID != string(tc.agent) || got.HolderJKT != tc.key {
			t.Errorf("Lookup(shared, %s) = %+v, want ACTIVE with its own key %q", tc.agent, got, tc.key)
		}
	}

	// The agent ID selects only among the rows of the workload; the workload
	// alone names no agent.
	for name, got := range map[string]adapter.AgentBinding{
		"agent enrolled only on another workload": f.lookup(t, realm, shared, agentD),
		"agent of the shared workload, other one": f.lookup(t, realm, workloadA, agentA),
		"agent not enrolled":                      f.lookup(t, realm, shared, "https://agents.example/c"),
		"no agent named":                          f.lookup(t, realm, shared, ""),
	} {
		if got.Status != adapter.BindingUnknown || got.AgentID != "" || got.HolderJKT != "" {
			t.Errorf("%s: Lookup = %+v, want UNKNOWN without identity", name, got)
		}
	}

	// Compromise of one agent does not touch the other.
	if err := f.reg.MarkCompromised(t.Context(), admin, agentA); err != nil {
		t.Fatal(err)
	}
	if got := f.lookup(t, realm, shared, agentA); got.Status != adapter.BindingCompromised || got.HolderJKT != jkt("a1") {
		t.Errorf("Lookup(A) after compromise = %+v, want COMPROMISED with A's key", got)
	}
	if got := f.lookup(t, realm, shared, agentB); got.Status != adapter.BindingActive || got.HolderJKT != jkt("b1") {
		t.Errorf("Lookup(B) after A's compromise = %+v, want ACTIVE", got)
	}

	// Revoking B answers REVOKED for B, and A stays COMPROMISED.
	if err := f.reg.Revoke(t.Context(), admin, agentB); err != nil {
		t.Fatal(err)
	}
	if got := f.lookup(t, realm, shared, agentB); got.Status != adapter.BindingRevoked || got.AgentID != agentB {
		t.Errorf("Lookup(B) after revocation = %+v, want REVOKED agent B", got)
	}
	if got := f.lookup(t, realm, shared, agentA); got.Status != adapter.BindingCompromised || got.AgentID != agentA {
		t.Errorf("Lookup(A) after B's revocation = %+v, want COMPROMISED agent A", got)
	}
}

// TestRevokedRowsDoNotShadowTheBinding: on an account whose first agent was
// revoked, the agent enrolled after it resolves ACTIVE and the revoked agent
// stays REVOKED; neither answers for the other.
func TestRevokedRowsDoNotShadowTheBinding(t *testing.T) {
	f := newFixture()
	f.enroll(t, agentA, workloadA, jkt("a1"))
	if err := f.reg.Revoke(t.Context(), admin, agentA); err != nil {
		t.Fatal(err)
	}
	f.enroll(t, agentB, workloadA, jkt("b1"))

	if got := f.lookup(t, realm, workloadA, agentB); got.AgentID != agentB || got.Status != adapter.BindingActive || got.HolderJKT != jkt("b1") {
		t.Fatalf("Lookup(B) = %+v, want agent B ACTIVE", got)
	}
	if got := f.lookup(t, realm, workloadA, agentA); got.AgentID != agentA || got.Status != adapter.BindingRevoked || got.HolderJKT != jkt("a1") {
		t.Fatalf("Lookup(A) = %+v, want agent A REVOKED", got)
	}
}

// TestDedicatedWorkloadRefusesASecondEnrollment: by default a workload serves
// one agent, so Enroll refuses a record for a workload that a record in force
// already names (identity mapping IM-19). Only records in force count: a
// revoked record does not, a compromised one does. The refusal is audited, and
// the workload of another realm is another workload.
func TestDedicatedWorkloadRefusesASecondEnrollment(t *testing.T) {
	const agentC = "https://agents.example/c"
	f := newFixture()
	f.enroll(t, agentA, workloadA, jkt("a1"))

	err := f.reg.Enroll(t.Context(), admin, memory.Enrollment{AgentID: agentB, OperatorID: "op-1", Workload: workloadA, HolderJKT: jkt("b1")})
	if !errors.Is(err, enroll.ErrWorkloadInUse) {
		t.Fatalf("second agent on the workload: Enroll() = %v, want ErrWorkloadInUse", err)
	}
	audit := f.reg.Audit()
	if last := audit[len(audit)-1]; last.Result != enroll.ResultRejected || last.AgentID != agentB || last.Workload != workloadA {
		t.Errorf("refusal audited as %+v, want a REJECTED entry for agent B on the workload", last)
	}
	f.wantBinding(t, workloadA, agentA, adapter.BindingActive, jkt("a1"))
	if got := f.lookup(t, realm, workloadA, agentB); got.Status != adapter.BindingUnknown || got.AgentID != "" {
		t.Errorf("a refused enrollment left a binding: %+v", got)
	}

	// The key of the refused request was not used, so a later enrollment may
	// take it; another workload of the realm is free.
	f.enroll(t, agentB, workloadB, jkt("b1"))
	// The same workload text in another realm is another workload.
	other := enroll.Actor{Kind: enroll.Admin, ID: "admin-2", Realm: otherEnv}
	if err := f.reg.Enroll(t.Context(), other, memory.Enrollment{AgentID: agentC, OperatorID: "op-1", Workload: workloadA, HolderJKT: jkt("c1")}); err != nil {
		t.Errorf("same workload text in another realm: Enroll() = %v", err)
	}

	// A compromised record stays in force.
	if err := f.reg.MarkCompromised(t.Context(), admin, agentA); err != nil {
		t.Fatal(err)
	}
	err = f.reg.Enroll(t.Context(), admin, memory.Enrollment{AgentID: agentC, OperatorID: "op-1", Workload: workloadA, HolderJKT: jkt("c2")})
	if !errors.Is(err, enroll.ErrWorkloadInUse) {
		t.Errorf("workload with a compromised record: Enroll() = %v, want ErrWorkloadInUse", err)
	}

	// A revoked record does not count.
	if err := f.reg.Revoke(t.Context(), admin, agentB); err != nil {
		t.Fatal(err)
	}
	f.enroll(t, agentC, workloadB, jkt("c3"))
	f.wantBinding(t, workloadB, agentC, adapter.BindingActive, jkt("c3"))
}

// TestDedicatedWorkloadConfigurationError: a workload whose agent was revoked
// takes a new agent, and the old record becomes in force again when it is
// marked compromised. The workload then has two records in force, the
// configuration error of IM-19: whichever agent ID the request names, Lookup
// returns no binding and an error that wraps ErrUnsupportedRequirement
// (draft 17.1). A registry that supports shared workloads selects instead.
func TestDedicatedWorkloadConfigurationError(t *testing.T) {
	for _, tc := range []struct {
		name   string
		opts   []memory.Option
		shared bool
	}{{"dedicated", nil, false}, {"shared", []memory.Option{memory.WithSharedWorkloads()}, true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(tc.opts...)
			f.enroll(t, agentA, workloadA, jkt("a1"))
			if err := f.reg.Revoke(t.Context(), admin, agentA); err != nil {
				t.Fatal(err)
			}
			f.enroll(t, agentB, workloadA, jkt("b1"))
			f.wantBinding(t, workloadA, agentB, adapter.BindingActive, jkt("b1"))
			f.wantBinding(t, workloadA, agentA, adapter.BindingRevoked, jkt("a1"))

			if err := f.reg.MarkCompromised(t.Context(), admin, agentA); err != nil {
				t.Fatal(err)
			}
			if tc.shared {
				f.wantBinding(t, workloadA, agentB, adapter.BindingActive, jkt("b1"))
				f.wantBinding(t, workloadA, agentA, adapter.BindingCompromised, jkt("a1"))
				return
			}
			var r adapter.BindingResolver = enroll.Resolver{Registry: f.reg}
			for _, agent := range []adapter.AgentID{agentA, agentB, "https://agents.example/c", ""} {
				b, err := r.ResolveAgentBinding(t.Context(), realm, workloadA, agent)
				if !errors.Is(err, adapter.ErrUnsupportedRequirement) || b != (adapter.AgentBinding{}) {
					t.Errorf("%q: %+v, %v; want UNSUPPORTED_REQUIREMENT and no binding", agent, b, err)
				}
			}
			// Another workload of the realm is not affected.
			f.enroll(t, "https://agents.example/c", workloadB, jkt("c1"))
			f.wantBinding(t, workloadB, "https://agents.example/c", adapter.BindingActive, jkt("c1"))
		})
	}
}

func TestAuditLog(t *testing.T) {
	f := newFixture()
	if got := f.reg.Audit(); len(got) != 0 {
		t.Fatalf("new registry has %d audit entries", len(got))
	}
	agentActor := enroll.Actor{Kind: enroll.Agent, ID: agentA, Realm: realm}

	f.enroll(t, agentA, workloadA, jkt("a1"))                    // 1 applied
	f.clk.Advance(time.Minute)                                   //
	_ = f.reg.Rotate(t.Context(), agentActor, agentA, jkt("a2")) // 2 denied: no authority
	_ = f.reg.Rotate(t.Context(), admin, agentA, jkt("a2"))      // 3 applied
	_ = f.reg.Rotate(t.Context(), issuer, agentA, jkt("a1"))     // 4 rejected: retired key
	_ = f.reg.MarkCompromised(t.Context(), issuer, agentA)       // 5 applied
	_ = f.reg.MarkCompromised(t.Context(), admin, agentA)        // 6 unchanged: already compromised
	_ = f.reg.Rotate(t.Context(), admin, agentA, jkt("a3"))      // 7 rejected: compromised
	_ = f.reg.Revoke(t.Context(), admin, agentB)                 // 8 rejected: not enrolled

	log := f.reg.Audit()
	type row struct {
		action enroll.AuditAction
		kind   enroll.ActorKind
		result enroll.AuditResult
	}
	want := []row{
		{enroll.ActionEnroll, enroll.Admin, enroll.ResultApplied},
		{enroll.ActionRotate, enroll.Agent, enroll.ResultDenied},
		{enroll.ActionRotate, enroll.Admin, enroll.ResultApplied},
		{enroll.ActionRotate, enroll.AuthorizedIssuer, enroll.ResultRejected},
		{enroll.ActionMarkCompromised, enroll.AuthorizedIssuer, enroll.ResultApplied},
		{enroll.ActionMarkCompromised, enroll.Admin, enroll.ResultUnchanged},
		{enroll.ActionRotate, enroll.Admin, enroll.ResultRejected},
		{enroll.ActionRevoke, enroll.Admin, enroll.ResultRejected},
	}
	if len(log) != len(want) {
		t.Fatalf("audit has %d entries, want %d: %+v", len(log), len(want), log)
	}
	for i, w := range want {
		e := log[i]
		if e.Seq != uint64(i+1) {
			t.Errorf("entry %d: Seq = %d, want %d", i, e.Seq, i+1)
		}
		if e.Action != w.action || e.Actor.Kind != w.kind || e.Result != w.result {
			t.Errorf("entry %d = (%s, %s, %s), want (%s, %s, %s)", i, e.Action, e.Actor.Kind, e.Result, w.action, w.kind, w.result)
		}
		if e.Actor.Realm != realm {
			t.Errorf("entry %d: Actor.Realm = %v", i, e.Actor.Realm)
		}
		refused := e.Result == enroll.ResultDenied || e.Result == enroll.ResultRejected
		if refused != (e.Reason != "") {
			t.Errorf("entry %d: Result %s with Reason %q", i, e.Result, e.Reason)
		}
	}

	// Details of the entries that carry a key.
	if e := log[0]; e.AgentID != agentA || e.Workload != workloadA || e.NewJKT != jkt("a1") || e.OldJKT != "" || !e.At.Equal(start) {
		t.Errorf("enroll entry = %+v", e)
	}
	if e := log[2]; e.AgentID != agentA || e.OldJKT != jkt("a1") || e.NewJKT != jkt("a2") || e.Actor.ID != "admin-1" || !e.At.Equal(start.Add(time.Minute)) {
		t.Errorf("rotate entry = %+v", e)
	}
	if e := log[1]; e.OldJKT != "" || e.NewJKT != jkt("a2") {
		// a denied rotation records what was asked for, not what the binding held
		t.Errorf("denied rotate entry = %+v", e)
	}

	// The returned log is a copy.
	log[0].AgentID = "tampered"
	if f.reg.Audit()[0].AgentID != agentA {
		t.Error("mutating the returned audit slice changed the registry's log")
	}
}

func TestAuditLogRecordsNothingForReads(t *testing.T) {
	f := newFixture()
	f.enroll(t, agentA, workloadA, jkt("a1"))
	f.lookup(t, realm, workloadA, agentA)
	f.lookup(t, realm, workloadA, agentB)
	if n := len(f.reg.Audit()); n != 1 {
		t.Fatalf("audit has %d entries, want only the enrollment", n)
	}
}

func TestCanceledContext(t *testing.T) {
	f := newFixture()
	f.enroll(t, agentA, workloadA, jkt("a1"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	calls := map[string]func() error{
		"Lookup":          func() error { _, err := f.reg.Lookup(ctx, realm, workloadA, agentA); return err },
		"Rotate":          func() error { return f.reg.Rotate(ctx, admin, agentA, jkt("a2")) },
		"MarkCompromised": func() error { return f.reg.MarkCompromised(ctx, admin, agentA) },
		"Revoke":          func() error { return f.reg.Revoke(ctx, admin, agentA) },
		"Enroll": func() error {
			return f.reg.Enroll(ctx, admin, memory.Enrollment{AgentID: agentB, OperatorID: "op-1", Workload: workloadB, HolderJKT: jkt("b1")})
		},
	}
	for name, call := range calls {
		err := call()
		if !errors.Is(err, adapter.ErrDependencyUnavailable) || !errors.Is(err, context.Canceled) {
			t.Errorf("%s with a canceled context = %v, want ErrDependencyUnavailable wrapping context.Canceled", name, err)
		}
	}
	f.wantBinding(t, workloadA, agentA, adapter.BindingActive, jkt("a1"))
	if n := len(f.reg.Audit()); n != 1 {
		t.Errorf("a canceled call was audited: %d entries", n)
	}
}

func TestConcurrentUse(t *testing.T) {
	f := newFixture()
	f.enroll(t, agentA, workloadA, jkt("a0"))

	const rotations = 40
	var wg sync.WaitGroup
	for i := range rotations {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := f.reg.Rotate(t.Context(), admin, agentA, jkt(fmt.Sprintf("a-%d", i))); err != nil && !errors.Is(err, enroll.ErrCompromised) {
				t.Errorf("Rotate: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := f.reg.Lookup(t.Context(), realm, workloadA, agentA); err != nil {
				t.Errorf("Lookup: %v", err)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := f.reg.MarkCompromised(t.Context(), issuer, agentA); err != nil {
			t.Errorf("MarkCompromised: %v", err)
		}
	}()
	wg.Wait()

	// Whatever the interleaving, the end state is COMPROMISED, and every
	// attempt is in the log.
	if got := f.lookup(t, realm, workloadA, agentA); got.Status != adapter.BindingCompromised {
		t.Fatalf("final Status = %s, want COMPROMISED", got.Status)
	}
	if n := len(f.reg.Audit()); n != 1+rotations+1 {
		t.Errorf("audit has %d entries, want %d", n, 1+rotations+1)
	}
}

// TestEnrollAgentIDForms: agent_id is an absolute URI (draft 6.1); a native
// workload identifier, a gateway-assigned URI and a DID are all valid.
func TestEnrollAgentIDForms(t *testing.T) {
	tests := []struct {
		id string
		ok bool
	}{
		{"https://agents.example/a", true},
		{"https://agents.example/a%20b?x=1", true},
		{"urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66", true},
		{"did:web:example.com", true},
		{"spiffe://example.org/ns/prod/sa/runner", true},
		{"agent-a", false},
		{"/agents/a", false},
		{"1http://agents.example/a", false},
		{"://agents.example/a", false},
		{"https:", false},
		{"https://agents.example/a%2", false},
		{"https://agents.example/a%zz", false},
		{"https://agents.example/é", false},
		{"https://agents.example/a b", false},
		{"https://agents.example/a#frag", false},
		{" https://agents.example/a", false},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			f := newFixture()
			err := f.reg.Enroll(t.Context(), admin, memory.Enrollment{
				AgentID: tc.id, OperatorID: "op-1", Workload: workloadA, HolderJKT: jkt("k"),
			})
			if tc.ok && err != nil {
				t.Fatalf("Enroll() = %v, want nil", err)
			}
			if !tc.ok && !errors.Is(err, enroll.ErrInvalid) {
				t.Fatalf("Enroll() = %v, want ErrInvalid", err)
			}
		})
	}
}
