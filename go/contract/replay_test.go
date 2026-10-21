package contract_test

import (
	"context"
	"sync"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/contract"
)

func record(nonce string) contract.NonceRecord {
	return contract.NonceRecord{
		Nonce: nonce, AgentID: b4Agent, HolderJKT: b4HolderJKT, Realm: b4Realm,
		OperationDigest: b4OpDigest, RequirementsDigest: b4IntDigest,
	}
}

// TestReusedNonceRejected: the second consumption of a nonce is REPLAY, and
// so is a nonce that was never registered (draft 7.5).
func TestReusedNonceRejected(t *testing.T) {
	m := contract.NewMemoryReplay(0)
	r := record("N8WrKpg8XNb9Wh_QuWlHbw")
	wantErr(t, m.Consume(bg, r, at(b4Time), at(b4Time+65)), contract.ErrReplay)
	if err := m.Register(bg, r, at(b4Time), at(b4Time+65)); err != nil {
		t.Fatal(err)
	}
	wantErr(t, m.Register(bg, r, at(b4Time), at(b4Time+65)), contract.ErrReplay)
	if err := m.Consume(bg, r, at(b4Time+1), at(b4Time+66)); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	wantErr(t, m.Consume(bg, r, at(b4Time+2), at(b4Time+67)), contract.ErrReplay)
	wantErr(t, m.Register(bg, r, at(b4Time+2), at(b4Time+67)), contract.ErrReplay)
}

// TestConsumeBinding: a nonce consumed with another agent, key, realm,
// operation or contract is CONTEXT_MISMATCH and stays unconsumed.
func TestConsumeBinding(t *testing.T) {
	for name, edit := range map[string]func(r *contract.NonceRecord){
		"agent":     func(r *contract.NonceRecord) { r.AgentID = "https://identity.example/agents/other" },
		"holder":    func(r *contract.NonceRecord) { r.HolderJKT = "ahxE1XEYqxvLIZy3r4nx9RE4E0683KndykyuZTK9xQg" },
		"tenant":    func(r *contract.NonceRecord) { r.Realm.TenantID = "globex" },
		"env":       func(r *contract.NonceRecord) { r.Realm = adapter.Realm{TenantID: b4Tenant, EnvironmentID: "x"} },
		"operation": func(r *contract.NonceRecord) { r.OperationDigest = b4IntDigest },
		"contract":  func(r *contract.NonceRecord) { r.RequirementsDigest = b4OpDigest },
	} {
		t.Run(name, func(t *testing.T) {
			m := contract.NewMemoryReplay(0)
			r := record("N8WrKpg8XNb9Wh_QuWlHbw")
			if err := m.Register(bg, r, at(b4Time), at(b4Time+65)); err != nil {
				t.Fatal(err)
			}
			other := r
			edit(&other)
			wantErr(t, m.Consume(bg, other, at(b4Time), at(b4Time+65)), contract.ErrContextMismatch)
			if err := m.Consume(bg, r, at(b4Time), at(b4Time+65)); err != nil {
				t.Fatalf("the registered record after a mismatch: %v", err)
			}
		})
	}
}

// TestConsumeConcurrent: of many concurrent consumptions of one nonce,
// exactly one succeeds; every other is REPLAY (draft 7.5, fixture
// admission/replay-same-nonce-two-replicas).
func TestConsumeConcurrent(t *testing.T) {
	m := contract.NewMemoryReplay(0)
	r := record("N8WrKpg8XNb9Wh_QuWlHbw")
	if err := m.Register(bg, r, at(b4Time), at(b4Time+65)); err != nil {
		t.Fatal(err)
	}
	const n = 64
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = m.Consume(bg, r, at(b4Time), at(b4Time+65))
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
		} else {
			wantErr(t, err, contract.ErrReplay)
		}
	}
	if ok != 1 {
		t.Fatalf("%d consumptions succeeded, want 1", ok)
	}
}

// TestRetention: a record is kept until its retention bound, under load
// too: a full store defers (DEPENDENCY_UNAVAILABLE) rather than evict a
// record early. A consumption extends the bound; once it has passed, the
// record may go (fixture admission/old-presentation-after-eviction).
func TestRetention(t *testing.T) {
	m := contract.NewMemoryReplay(2)
	a, b, c := record("aaaaaaaaaaaaaaaaaaaaaa"), record("bbbbbbbbbbbbbbbbbbbbbb"), record("cccccccccccccccccccccc")
	if err := m.Register(bg, a, at(b4Time), at(b4Time+65)); err != nil {
		t.Fatal(err)
	}
	if err := m.Register(bg, b, at(b4Time), at(b4Time+65)); err != nil {
		t.Fatal(err)
	}
	wantErr(t, m.Register(bg, c, at(b4Time+65), at(b4Time+130)), contract.ErrDependencyUnavailable)
	// a is consumed and kept to 1792080075.
	if err := m.Consume(bg, a, at(b4Time+10), at(b4Time+75)); err != nil {
		t.Fatal(err)
	}
	// At 1792080066 b may go, a may not.
	if err := m.Register(bg, c, at(b4Time+66), at(b4Time+130)); err != nil {
		t.Fatalf("Register after b's bound: %v", err)
	}
	wantErr(t, m.Consume(bg, a, at(b4Time+66), at(b4Time+130)), contract.ErrReplay)
	d := record("dddddddddddddddddddddd")
	wantErr(t, m.Register(bg, d, at(b4Time+75), at(b4Time+140)), contract.ErrDependencyUnavailable)
	wantErr(t, m.Consume(bg, a, at(b4Time+75), at(b4Time+140)), contract.ErrReplay)
	if err := m.Register(bg, d, at(b4Time+76), at(b4Time+140)); err != nil {
		t.Fatalf("Register after a's bound: %v", err)
	}
	// An earlier until never shortens a bound.
	e := record("eeeeeeeeeeeeeeeeeeeeee")
	m = contract.NewMemoryReplay(1)
	if err := m.Register(bg, e, at(b4Time), at(b4Time+65)); err != nil {
		t.Fatal(err)
	}
	if err := m.Consume(bg, e, at(b4Time), at(b4Time+1)); err != nil {
		t.Fatal(err)
	}
	wantErr(t, m.Register(bg, d, at(b4Time+64), at(b4Time+100)), contract.ErrDependencyUnavailable)
	wantErr(t, m.Consume(bg, e, at(b4Time+64), at(b4Time+100)), contract.ErrReplay)
}

// TestRetentionBound: a record is kept through its bound and goes after it.
func TestRetentionBound(t *testing.T) {
	m := contract.NewMemoryReplay(0)
	r := record("N8WrKpg8XNb9Wh_QuWlHbw")
	if err := m.Register(bg, r, at(b4Time), at(b4Time+65)); err != nil {
		t.Fatal(err)
	}
	wantErr(t, m.Register(bg, r, at(b4Time+65), at(b4Time+130)), contract.ErrReplay)
	wantErr(t, m.Consume(bg, r, at(b4Time+66), at(b4Time+130)), contract.ErrReplay)
}

// TestReplayContext: a cancelled context defers.
func TestReplayContext(t *testing.T) {
	m := contract.NewMemoryReplay(0)
	ctx, cancel := context.WithCancel(bg)
	cancel()
	r := record("N8WrKpg8XNb9Wh_QuWlHbw")
	wantErr(t, m.Register(ctx, r, at(b4Time), at(b4Time+65)), contract.ErrDependencyUnavailable)
	if err := m.Register(bg, r, at(b4Time), at(b4Time+65)); err != nil {
		t.Fatal(err)
	}
	wantErr(t, m.Consume(ctx, r, at(b4Time), at(b4Time+65)), contract.ErrDependencyUnavailable)
	if err := m.Consume(bg, r, at(b4Time), at(b4Time+65)); err != nil {
		t.Fatalf("Consume after a cancelled attempt: %v", err)
	}
}

// TestCodes: every sentinel carries its draft 13.4 code.
func TestCodes(t *testing.T) {
	for err, want := range map[error]adapter.Code{
		contract.ErrInvalidMessage:         "INVALID_MESSAGE",
		contract.ErrInvalidProof:           "INVALID_PROOF",
		contract.ErrContextMismatch:        "CONTEXT_MISMATCH",
		contract.ErrUnsupportedRequirement: "UNSUPPORTED_REQUIREMENT",
		contract.ErrRequirementsChanged:    "REQUIREMENTS_CHANGED",
		contract.ErrExpired:                "EXPIRED",
		contract.ErrReplay:                 "REPLAY",
		contract.ErrDependencyUnavailable:  "DEPENDENCY_UNAVAILABLE",
	} {
		if got, ok := adapter.CodeOf(err); !ok || got != want {
			t.Errorf("%v: code %q, want %q", err, got, want)
		}
	}
	_, err := b4Verifier(t).Verify(compactOf(t, validContract), at(1792080060))
	if got, _ := adapter.CodeOf(err); got != "EXPIRED" {
		t.Errorf("wrapped error code %q", got)
	}
}
