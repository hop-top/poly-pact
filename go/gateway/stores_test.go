package gateway_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/gateway"
	"hop.top/pact-go/validator"
)

var bg = context.Background()

func TestMemoryRecords(t *testing.T) {
	now := time.Unix(start, 0)
	d1, d2, d3 := digest.BytesDigest([]byte("1")), digest.BytesDigest([]byte("2")), digest.BytesDigest([]byte("3"))
	m := gateway.NewMemoryRecords(2)
	r1 := gateway.ContractRecord{MappingVersion: mappingV1, OperationID: "operation-1"}
	r2 := gateway.ContractRecord{MappingVersion: mappingV1, OperationID: "operation-2"}
	if err := m.Record(bg, d1, r1, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if rec, err := m.Lookup(bg, d1, now); err != nil || rec != r1 {
		t.Fatalf("Lookup = %+v, %v", rec, err)
	}
	if _, err := m.Lookup(bg, d2, now); !errors.Is(err, gateway.ErrNotRecorded) {
		t.Fatalf("unrecorded contract: %v, want ErrNotRecorded", err)
	}
	if _, err := m.Lookup(bg, d1, now.Add(time.Minute)); !errors.Is(err, gateway.ErrNotRecorded) {
		t.Fatalf("record past its retention: %v, want ErrNotRecorded", err)
	}
	if err := m.Record(bg, d1, gateway.ContractRecord{MappingVersion: mappingV2, OperationID: "operation-1"}, now, now.Add(time.Minute)); err == nil {
		t.Fatal("a contract was recorded twice")
	}
	if err := m.Record(bg, d2, r2, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if rec, err := m.Lookup(bg, d2, now); err != nil || rec != r2 {
		t.Fatalf("second contract: Lookup = %+v, %v, want its own record", rec, err)
	}
	if err := m.Record(bg, d3, r1, now, now.Add(time.Minute)); !errors.Is(err, adapter.ErrDependencyUnavailable) {
		t.Fatalf("full store: %v, want ErrDependencyUnavailable", err)
	}
	if err := m.Record(bg, "", r1, now, now.Add(time.Minute)); err == nil {
		t.Fatal("an empty digest was recorded")
	}
	if err := m.Record(bg, d3, gateway.ContractRecord{OperationID: "operation-3"}, now, now.Add(time.Minute)); err == nil {
		t.Fatal("an empty mapping version was recorded")
	}
	if err := m.Record(bg, d3, gateway.ContractRecord{MappingVersion: mappingV1}, now, now.Add(time.Minute)); err == nil {
		t.Fatal("an empty operation_id was recorded")
	}
}

func TestMemoryRecordsSweep(t *testing.T) {
	now := time.Unix(start, 0)
	m := gateway.NewMemoryRecords(1)
	rec := gateway.ContractRecord{MappingVersion: mappingV1, OperationID: "operation-1"}
	if err := m.Record(bg, digest.BytesDigest([]byte("1")), rec, now, now); err != nil {
		t.Fatal(err)
	}
	// The first record's retention ended at now, so it makes room.
	if err := m.Record(bg, digest.BytesDigest([]byte("2")), rec, now, now.Add(time.Minute)); err != nil {
		t.Fatalf("an expired record still takes room: %v", err)
	}
}

func TestMemoryHolds(t *testing.T) {
	h := gateway.NewMemoryHolds()
	if hs, err := h.Holds(bg, realm, agentID); err != nil || len(hs) != 0 {
		t.Fatalf("Holds = %v, %v", hs, err)
	}
	h.Set(realm, agentID, "hold-1", "hold-2")
	if hs, err := h.Holds(bg, realm, agentID); err != nil || len(hs) != 2 || hs[0] != "hold-1" {
		t.Fatalf("Holds = %v, %v", hs, err)
	}
	other := adapter.Realm{TenantID: tenant, EnvironmentID: "https://gateway.example/environments/test"}
	if hs, _ := h.Holds(bg, other, agentID); len(hs) != 0 {
		t.Fatal("a hold of one realm applies in another")
	}
	h.SetUnavailable(true)
	if _, err := h.Holds(bg, realm, agentID); !errors.Is(err, adapter.ErrDependencyUnavailable) {
		t.Fatalf("unavailable store: %v", err)
	}
	h.SetUnavailable(false)
	h.Set(realm, agentID)
	if hs, _ := h.Holds(bg, realm, agentID); len(hs) != 0 {
		t.Fatal("Set with no holds did not clear them")
	}
}

func TestStaticPolicy(t *testing.T) {
	p := gateway.StaticPolicy{
		ActivePolicy: validator.ActivePolicy{Policy: contract.Policy{BaseRevision: baseRev}, ConservativeSet: baseSet},
		Selected:     validator.Selection{RecordRef: "selection-1"},
	}
	a, err := p.Active(bg)
	if err != nil || a.Policy.BaseRevision != baseRev || a.ConservativeSet != baseSet {
		t.Fatalf("Active = %+v, %v", a, err)
	}
	s, err := p.Selection(bg, contract.Contract{})
	if err != nil || s.RecordRef != "selection-1" {
		t.Fatalf("Selection = %+v, %v", s, err)
	}
}

func TestMemoryStatus(t *testing.T) {
	s := gateway.NewMemoryStatus()
	if _, err := s.EvidenceStatus(bg, "https://issuer.example", "status-1"); !errors.Is(err, adapter.ErrDependencyUnavailable) {
		t.Fatalf("unknown status: %v, want ErrDependencyUnavailable", err)
	}
	want := validator.EvidenceStatus{Revoked: true, CheckedAt: time.Unix(start, 0), SourceID: "status"}
	s.Set("https://issuer.example", "status-1", want)
	if got, err := s.EvidenceStatus(bg, "https://issuer.example", "status-1"); err != nil || got != want {
		t.Fatalf("EvidenceStatus = %+v, %v", got, err)
	}
	if _, err := s.EvidenceStatus(bg, "https://other.example", "status-1"); err == nil {
		t.Fatal("a status of one issuer answers for another")
	}
}

// TestNewChecksConfig: a configuration the gateway cannot enforce with is an
// error, never a middleware that lets requests through.
func TestNewChecksConfig(t *testing.T) {
	w := newWorld(t)
	for name, mutate := range map[string]func(*gateway.Config){
		"no adapter":         func(c *gateway.Config) { c.Adapter = nil },
		"no validator":       func(c *gateway.Config) { c.Validator = nil },
		"no publisher":       func(c *gateway.Config) { c.Publisher = nil },
		"no requirements":    func(c *gateway.Config) { c.Requirements = nil },
		"no records":         func(c *gateway.Config) { c.Records = nil },
		"no mapping version": func(c *gateway.Config) { c.MappingVersion = "" },
		"unknown class":      func(c *gateway.Config) { c.Routes = map[string]gateway.Class{"GET /x": "audit"} },
		"unknown default":    func(c *gateway.Config) { c.Default = "audit" },
		"bad pattern":        func(c *gateway.Config) { c.Routes = map[string]gateway.Class{"GET": gateway.ClassOff} },
		"conflicting patterns": func(c *gateway.Config) {
			c.Routes = map[string]gateway.Class{"GET /x/{a}": gateway.ClassOff, "GET /x/{b}": gateway.ClassEnforce}
		},
		"publisher of another gateway": func(c *gateway.Config) {
			p := *c.Publisher
			p.Audience = "https://other.example/api"
			c.Publisher = &p
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := w.cfg
			mutate(&cfg)
			if mw, err := gateway.New(cfg); err == nil || mw != nil {
				t.Fatal("New accepted the configuration")
			}
		})
	}
	if _, err := gateway.New(w.cfg); err != nil {
		t.Fatalf("New: %v", err)
	}
}
