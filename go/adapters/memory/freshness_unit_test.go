package memory_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapters/memory"
)

// at returns a pointer to the Unix seconds d seconds after t0.
func at(d int64) *int64 {
	v := t0.Unix() + d
	return &v
}

func limits(maxAge, statusMaxAge int64) *memory.CheckFreshness {
	return &memory.CheckFreshness{MaxAgeSeconds: &maxAge, StatusMaxAgeSeconds: &statusMaxAge}
}

func runCheck(a *memory.Adapter, id string) adapter.CheckOutcome {
	return a.CheckContext(context.Background(), id, adapter.CheckInput{})
}

// TestBoundedCheckEvaluation: a check with freshness limits applies them to the
// record it consults before it reports the native verdict. The rows are the
// worked evaluations of section 3.3 of the freshness profile, with the
// baseline skew of 5 seconds; times are seconds relative to now, and nil is a
// time the source does not give.
func TestBoundedCheckEvaluation(t *testing.T) {
	type row struct {
		observed, checked    *int64
		maxAge, statusMaxAge int64
		result               adapter.Verdict
		code                 string
	}
	pass, fail, unknown := adapter.VerdictPass, adapter.VerdictFail, adapter.VerdictUnknown
	rows := []row{
		{at(-10), at(0), 30, 0, pass, "REQUIREMENT_SATISFIED"},
		{at(-30), at(0), 30, 0, pass, "REQUIREMENT_SATISFIED"},
		{at(-31), at(0), 30, 0, fail, "STALE_EVIDENCE"},
		{at(-5), at(-1), 30, 0, fail, "STALE_EVIDENCE"},
		{at(-5), at(-25), 30, 30, pass, "REQUIREMENT_SATISFIED"},
		{at(-5), at(-31), 30, 30, fail, "STALE_EVIDENCE"},
		{at(5), at(0), 30, 0, pass, "REQUIREMENT_SATISFIED"},
		{at(6), at(0), 30, 0, fail, "CLOCK_AHEAD"},
		{at(0), at(6), 30, 0, fail, "CLOCK_AHEAD"},
		{at(6), at(-31), 30, 30, fail, "CLOCK_AHEAD"},
		{nil, at(0), 30, 0, unknown, "UNSUPPORTED_REQUIREMENT"},
		{at(-5), nil, 30, 30, unknown, "UNSUPPORTED_REQUIREMENT"},
		{at(-31), nil, 30, 30, fail, "STALE_EVIDENCE"},
		{at(-5), at(0), 0, 0, fail, "STALE_EVIDENCE"},
		{at(0), at(0), 0, 0, pass, "REQUIREMENT_SATISFIED"},
	}
	for i, r := range rows {
		a, _ := newAdapter(t, func(st *memory.State) {
			st.Checks = []memory.CheckRecord{{
				ID: "bounded-v1", Result: "PASS", ReasonCode: "REQUIREMENT_SATISFIED",
				SourceID: "delegation", SourceRef: "d-1", ObservedAt: r.observed, StatusCheckedAt: r.checked,
				Freshness: limits(r.maxAge, r.statusMaxAge),
			}}
		})
		got := runCheck(a, "bounded-v1")
		if got.Result != r.result || got.ReasonCode != r.code {
			t.Errorf("row %d: %s %s, want %s %s", i, got.Result, got.ReasonCode, r.result, r.code)
		}
		if got.SourceID != "delegation" {
			t.Errorf("row %d: source %q, want the check's source", i, got.SourceID)
		}
		switch {
		case r.code == "CLOCK_AHEAD" && !got.ObservedAt.IsZero():
			t.Errorf("row %d: a time ahead of the clock is passed on: %v", i, got.ObservedAt)
		case r.code != "CLOCK_AHEAD" && r.observed != nil && got.ObservedAt.Unix() != *r.observed:
			t.Errorf("row %d: ObservedAt %v, want the record's own time", i, got.ObservedAt)
		}
	}
}

// TestBoundedCheckKeepsANativeFailure: a record within its limits reports the
// native verdict, a failure included; the limits only ever take a PASS away.
func TestBoundedCheckKeepsANativeFailure(t *testing.T) {
	a, _ := newAdapter(t, func(st *memory.State) {
		st.Checks = []memory.CheckRecord{{
			ID: "bounded-v1", Result: "FAIL", ReasonCode: "REVOKED_EVIDENCE", SourceID: "delegation",
			ObservedAt: at(-5), StatusCheckedAt: at(-1), Freshness: limits(30, 30),
		}}
	})
	if got := runCheck(a, "bounded-v1"); got.Result != adapter.VerdictFail || got.ReasonCode != "REVOKED_EVIDENCE" {
		t.Errorf("%+v, want the native FAIL with its reason", got)
	}
}

// TestUnboundedCheckTimes: without limits a check is not evaluated for age,
// but a time it cannot pass on still defers it, as for a claim. A status time
// ahead of now by up to the skew can be passed on; one later than now plus the
// skew cannot (draft A.2).
func TestUnboundedCheckTimes(t *testing.T) {
	a, _ := newAdapter(t, func(st *memory.State) {
		st.Checks = []memory.CheckRecord{
			{ID: "old-v1", Result: "PASS", ReasonCode: "REQUIREMENT_SATISFIED", SourceID: "s", ObservedAt: at(-86400), StatusCheckedAt: at(-86400)},
			{ID: "status-at-skew-v1", Result: "PASS", ReasonCode: "REQUIREMENT_SATISFIED", SourceID: "s", ObservedAt: at(-5), StatusCheckedAt: at(5)},
			{ID: "status-ahead-v1", Result: "PASS", ReasonCode: "REQUIREMENT_SATISFIED", SourceID: "s", ObservedAt: at(-5), StatusCheckedAt: at(6)},
		}
	})
	if got := runCheck(a, "old-v1"); got.Result != adapter.VerdictPass {
		t.Errorf("old record without limits: %+v, want PASS", got)
	}
	if got := runCheck(a, "status-at-skew-v1"); got.Result != adapter.VerdictPass {
		t.Errorf("status check at now plus the skew: %+v, want PASS", got)
	}
	if got := runCheck(a, "status-ahead-v1"); got.Result != adapter.VerdictUnknown || got.ReasonCode != "DEPENDENCY_UNAVAILABLE" {
		t.Errorf("status check later than now plus the skew: %+v, want UNKNOWN DEPENDENCY_UNAVAILABLE", got)
	}
}

// TestPinnedRevision: a check pinned to a revision of its source fails with
// REQUIREMENTS_CHANGED when the source reports any other, or none.
func TestPinnedRevision(t *testing.T) {
	a, _ := newAdapter(t, func(st *memory.State) {
		pin := func(id, pinned, revision string) memory.CheckRecord {
			return memory.CheckRecord{ID: id, Result: "PASS", ReasonCode: "REQUIREMENT_SATISFIED", SourceID: "pdp",
				SourceRef: "dec-" + id, PinnedRevision: pinned, Revision: revision}
		}
		st.Checks = []memory.CheckRecord{
			pin("same-v1", "policy-7", "policy-7"),
			pin("changed-v1", "policy-7", "policy-8"),
			pin("case-v1", "policy-7", "Policy-7"),
			pin("absent-v1", "policy-7", ""),
			pin("unpinned-v1", "", "policy-8"),
		}
	})
	for id, want := range map[string]string{
		"same-v1": "REQUIREMENT_SATISFIED", "unpinned-v1": "REQUIREMENT_SATISFIED",
		"changed-v1": "REQUIREMENTS_CHANGED", "case-v1": "REQUIREMENTS_CHANGED", "absent-v1": "REQUIREMENTS_CHANGED",
	} {
		got := runCheck(a, id)
		wantResult := adapter.VerdictPass
		if want == "REQUIREMENTS_CHANGED" {
			wantResult = adapter.VerdictFail
		}
		if got.Result != wantResult || got.ReasonCode != want || got.SourceRef != "dec-"+id {
			t.Errorf("%s: %+v, want %s %s", id, got, wantResult, want)
		}
	}
}

// TestSightings: the guard against re-stamping starts with the sightings of
// the state and records every record a bounded check consults, keyed by
// source and reference together.
func TestSightings(t *testing.T) {
	a, _ := newAdapter(t, func(st *memory.State) {
		bounded := func(id, source, ref string, observed int64) memory.CheckRecord {
			return memory.CheckRecord{ID: id, Result: "PASS", ReasonCode: "REQUIREMENT_SATISFIED", SourceID: source,
				SourceRef: ref, ObservedAt: at(observed), StatusCheckedAt: at(-1), Freshness: limits(300, 30)}
		}
		st.Checks = []memory.CheckRecord{
			bounded("restamped-v1", "delegation", "d-1", -10),
			bounded("same-time-v1", "delegation", "d-2", -100),
			bounded("earlier-v1", "delegation", "d-3", -200),
			bounded("other-source-v1", "directory", "d-1", -10),
			bounded("first-v1", "delegation", "d-4", -100),
			bounded("later-v1", "delegation", "d-4", -10),
			bounded("unguarded-v1", "delegation", "", -10),
		}
		st.Sightings = []memory.Sighting{
			{SourceID: "delegation", SourceRef: "d-1", ObservedAt: at(-3600)},
			{SourceID: "delegation", SourceRef: "d-2", ObservedAt: at(-100)},
			{SourceID: "delegation", SourceRef: "d-3", ObservedAt: at(-150)},
		}
	})
	for _, c := range []struct{ id, code string }{
		{"restamped-v1", "RESTAMPED"},
		{"same-time-v1", "REQUIREMENT_SATISFIED"},
		{"earlier-v1", "REQUIREMENT_SATISFIED"},
		{"other-source-v1", "REQUIREMENT_SATISFIED"},
		{"first-v1", "REQUIREMENT_SATISFIED"},
		{"later-v1", "RESTAMPED"},
		{"unguarded-v1", "REQUIREMENT_SATISFIED"},
		{"restamped-v1", "RESTAMPED"},
	} {
		got := runCheck(a, c.id)
		want := adapter.VerdictPass
		if c.code == "RESTAMPED" {
			want = adapter.VerdictFail
		}
		if got.Result != want || got.ReasonCode != c.code {
			t.Errorf("%s: %s %s, want %s %s", c.id, got.Result, got.ReasonCode, want, c.code)
		}
	}
}

// TestUnavailableSources: a record of a source that cannot answer is not read:
// the binding and the claim fail with DEPENDENCY_UNAVAILABLE and carry
// nothing, and the check is UNKNOWN. Other sources still answer.
func TestUnavailableSources(t *testing.T) {
	realm := memory.Realm{TenantID: "acme", EnvironmentID: env}
	const jkt = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
	// Workload "up" is shared by two agents, so the adapter supports shared
	// workloads; TestResolveAgentBindingDedicatedWorkload has the default.
	a, _ := newSharedAdapter(t, func(st *memory.State) {
		st.Enrollments = []memory.Enrollment{
			{Realm: realm, Workload: "down", AgentID: "https://identity.example/agents/down", HolderJKT: jkt,
				Status: "ACTIVE", ObservedAt: at(-60), StatusCheckedAt: at(-60), SourceID: "registry-down"},
			{Realm: realm, Workload: "revoked-down", AgentID: "https://identity.example/agents/revoked", HolderJKT: jkt,
				Status: "REVOKED", ObservedAt: at(-60), StatusCheckedAt: at(-60), SourceID: "registry-down"},
			{Realm: realm, Workload: "up", AgentID: "https://identity.example/agents/up", HolderJKT: jkt,
				Status: "ACTIVE", ObservedAt: at(-60), StatusCheckedAt: at(-60), SourceID: "registry"},
			// Another agent of the same workload, held by the source that is down.
			{Realm: realm, Workload: "up", AgentID: "https://identity.example/agents/up-other", HolderJKT: jkt,
				Status: "ACTIVE", ObservedAt: at(-60), StatusCheckedAt: at(-60), SourceID: "registry-down"},
		}
		st.ApprovedPaths = []string{"/roles", "/dept"}
		st.Claims = []memory.ClaimRecord{
			{Realm: realm, Principal: "https://idp.example/alice", Path: "/roles", Value: json.RawMessage(`["approver"]`),
				SourceID: "directory-down", ObservedAt: at(-60), StatusCheckedAt: at(-30)},
			{Realm: realm, Principal: "https://idp.example/alice", Path: "/dept", Value: json.RawMessage(`"finance"`),
				SourceID: "directory", ObservedAt: at(-60), StatusCheckedAt: at(-30)},
		}
		st.Checks = []memory.CheckRecord{
			{ID: "down-v1", Result: "PASS", ReasonCode: "REQUIREMENT_SATISFIED", SourceID: "checks-down", SourceRef: "c-1"},
			{ID: "bounded-down-v1", Result: "PASS", ReasonCode: "REQUIREMENT_SATISFIED", SourceID: "checks-down",
				ObservedAt: at(-5), StatusCheckedAt: at(-1), Freshness: limits(300, 30)},
			{ID: "up-v1", Result: "PASS", ReasonCode: "REQUIREMENT_SATISFIED", SourceID: "checks"},
		}
		st.UnavailableSources = []string{"registry-down", "directory-down", "checks-down"}
	})
	ctx := context.Background()
	ar := adapter.Realm{TenantID: "acme", EnvironmentID: env}
	agentOf := map[string]adapter.AgentID{
		"down":         "https://identity.example/agents/down",
		"revoked-down": "https://identity.example/agents/revoked",
		"up":           "https://identity.example/agents/up",
	}
	for _, w := range []string{"down", "revoked-down"} {
		if b, err := a.ResolveAgentBinding(ctx, ar, adapter.Workload(w), agentOf[w]); !errors.Is(err, adapter.ErrDependencyUnavailable) || b != (adapter.AgentBinding{}) {
			t.Errorf("binding %s: %+v, %v; want DEPENDENCY_UNAVAILABLE and no binding", w, b, err)
		}
	}
	// On a shared workload the agent's own records decide: the record of
	// another agent of the workload, held by the source that is down, is not
	// read for it.
	if b, err := a.ResolveAgentBinding(ctx, ar, "up", agentOf["up"]); err != nil || b.Status != adapter.BindingActive {
		t.Errorf("binding of an available source: %+v, %v", b, err)
	}
	if b, err := a.ResolveAgentBinding(ctx, ar, "up", "https://identity.example/agents/up-other"); !errors.Is(err, adapter.ErrDependencyUnavailable) || b != (adapter.AgentBinding{}) {
		t.Errorf("binding of the other agent, from the source that is down: %+v, %v; want DEPENDENCY_UNAVAILABLE", b, err)
	}
	if c, err := a.ReadNativeClaim(ctx, "/roles", adapter.ClaimContext{Principal: alice()}); !errors.Is(err, adapter.ErrDependencyUnavailable) || c.SourceID != "" || c.Value != nil {
		t.Errorf("claim: %+v, %v; want DEPENDENCY_UNAVAILABLE and no claim", c, err)
	} else if !strings.Contains(err.Error(), "directory-down") {
		t.Errorf("claim error %q does not name the source", err)
	}
	if c, err := a.ReadNativeClaim(ctx, "/dept", adapter.ClaimContext{Principal: alice()}); err != nil || c.Value != "finance" {
		t.Errorf("claim of an available source: %+v, %v", c, err)
	}
	for _, id := range []string{"down-v1", "bounded-down-v1"} {
		if got := runCheck(a, id); got.Result != adapter.VerdictUnknown || got.ReasonCode != "DEPENDENCY_UNAVAILABLE" || got.SourceID != "checks-down" {
			t.Errorf("check %s: %+v, want UNKNOWN DEPENDENCY_UNAVAILABLE naming the source", id, got)
		}
	}
	if got := runCheck(a, "up-v1"); got.Result != adapter.VerdictPass {
		t.Errorf("check of an available source: %+v", got)
	}
}

// TestFreshnessStateRules: the members the freshness rules read are complete.
func TestFreshnessStateRules(t *testing.T) {
	limit := int64(30)
	for name, mutate := range map[string]func(*memory.State){
		"freshness without a status limit": func(st *memory.State) {
			st.Checks[0].Freshness = &memory.CheckFreshness{MaxAgeSeconds: &limit}
		},
		"freshness without an age limit": func(st *memory.State) {
			st.Checks[0].Freshness = &memory.CheckFreshness{StatusMaxAgeSeconds: &limit}
		},
		"sighting without a reference": func(st *memory.State) {
			st.Sightings = []memory.Sighting{{SourceID: "s", ObservedAt: at(0)}}
		},
		"sighting without a source": func(st *memory.State) {
			st.Sightings = []memory.Sighting{{SourceRef: "r", ObservedAt: at(0)}}
		},
		"sighting without a time": func(st *memory.State) {
			st.Sightings = []memory.Sighting{{SourceID: "s", SourceRef: "r"}}
		},
		"empty unavailable source": func(st *memory.State) {
			st.UnavailableSources = []string{""}
		},
	} {
		a, _ := newAdapter(t)
		st := a.State()
		st.Checks = append([]memory.CheckRecord(nil), st.Checks...)
		mutate(&st)
		if err := st.Validate(); err == nil {
			t.Errorf("%s: state accepted", name)
		}
	}

	doc := `{"model": "common/1",
	  "gateway": {"tenant_id": "acme", "environment_id": "https://gateway.example/environments/finance",
	    "origin": "https://gateway.example"},
	  "checks": [{"id": "c", "result": "PASS", "reason_code": "REQUIREMENT_SATISFIED", "source_id": "s",
	    "source_ref": "r", "observed_at": 1, "status_checked_at": 2,
	    "freshness": {"max_age_seconds": 3, "status_max_age_seconds": 4},
	    "pinned_revision": "p", "revision": "q"}],
	  "sightings": [{"source_id": "s", "source_ref": "r", "observed_at": 1}],
	  "unavailable_sources": ["t"]}`
	st, err := memory.ParseState([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	c := st.Checks[0]
	if *c.StatusCheckedAt != 2 || *c.Freshness.MaxAgeSeconds != 3 || *c.Freshness.StatusMaxAgeSeconds != 4 ||
		c.PinnedRevision != "p" || c.Revision != "q" || len(st.Sightings) != 1 || st.UnavailableSources[0] != "t" {
		t.Errorf("parsed %+v", st)
	}
}
