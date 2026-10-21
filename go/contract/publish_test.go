package contract_test

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
)

var randomID = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

// TestIssueAppendixB4: the B.2 intent, the B.3 operation and the B.4
// requirements, issued at the B.4 time, give the B.4 contract: every claim
// but the random jti, contract_id and nonce is the B.4 value.
func TestIssueAppendixB4(t *testing.T) {
	store := contract.NewMemoryReplay(0)
	c, err := newPublisher(t, store).Issue(bg, b4Request(t), b4Auth(), b4Requirements(t), at(b4Time))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	var want core.RequirementContract
	decodeStrict(t, draftBlock(t, "B.4"), &want)
	got := c.Claims
	for name, id := range map[string]string{"jti": got.JTI, "nonce": got.Nonce, "contract_id": got.ContractID} {
		if !randomID.MatchString(id) {
			t.Errorf("%s %q is not 128 bits of base64url", name, id)
		}
	}
	if got.JTI == got.Nonce || got.JTI == got.ContractID || got.Nonce == got.ContractID {
		t.Errorf("jti, nonce and contract_id are not distinct: %q %q %q", got.JTI, got.Nonce, got.ContractID)
	}
	got.JTI, got.Nonce, got.ContractID = want.JTI, want.Nonce, want.ContractID
	gb, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if g, w := canonical(t, gb), canonical(t, draftBlock(t, "B.4")); g != w {
		t.Fatalf("issued contract differs from B.4:\n got %s\nwant %s", g, w)
	}
	// The payload of the JWS is the claims.
	var signed core.RequirementContract
	decodeStrict(t, segment(t, c.Compact, 1), &signed)
	sb, _ := json.Marshal(signed)
	cb, _ := json.Marshal(c.Claims)
	if string(sb) != string(cb) {
		t.Fatalf("signed payload %s, Claims %s", sb, cb)
	}
}

// TestRoundTrip: an issued contract verifies, passes the contract-validity
// and active-policy checks, and its nonce is registered: consumed once, then
// REPLAY.
func TestRoundTrip(t *testing.T) {
	store := contract.NewMemoryReplay(0)
	issued, err := newPublisher(t, store).Issue(bg, b4Request(t), b4Auth(), b4Requirements(t), at(b4Time))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	now := at(b4Time + 10)
	got, err := b4Verifier(t).Verify(issued.Compact, now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	ib, _ := json.Marshal(issued.Claims)
	gb, _ := json.Marshal(got.Claims)
	if string(ib) != string(gb) || got.Digest != issued.Digest || got.Compact != issued.Compact {
		t.Fatalf("verified contract differs from the issued one")
	}
	if err := got.Check(b4Expect()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if err := got.CheckActive(b4Policy()); err != nil {
		t.Fatalf("CheckActive: %v", err)
	}
	r := got.NonceRecord()
	if r.Nonce != issued.Claims.Nonce || r.RequirementsDigest != issued.Digest || r.OperationDigest != b4OpDigest ||
		r.AgentID != b4Agent || r.HolderJKT != b4HolderJKT || r.Realm != b4Realm {
		t.Fatalf("NonceRecord %+v", r)
	}
	until := at(b4Time + 75)
	if err := store.Consume(bg, r, now, until); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	wantErr(t, store.Consume(bg, r, now, until), contract.ErrReplay)
	wantErr(t, store.Consume(bg, r, at(b4Time+20), until), contract.ErrReplay)

	// Two contracts never share a nonce.
	again, err := newPublisher(t, store).Issue(bg, b4Request(t), b4Auth(), b4Requirements(t), at(b4Time))
	if err != nil {
		t.Fatal(err)
	}
	if again.Claims.Nonce == issued.Claims.Nonce || again.Claims.JTI == issued.Claims.JTI {
		t.Fatal("two issuances share a nonce or jti")
	}
}

// TestIssueLifetime: exp is iat plus the lifetime, 60 s by default, never
// more (draft 9.1, 20.1).
func TestIssueLifetime(t *testing.T) {
	for _, tc := range []struct {
		lifetime time.Duration
		exp      int64
	}{{0, b4Time + 60}, {30 * time.Second, b4Time + 30}, {60 * time.Second, b4Time + 60}, {time.Second, b4Time + 1}} {
		p := newPublisher(t, contract.NewMemoryReplay(0))
		p.Lifetime = tc.lifetime
		c, err := p.Issue(bg, b4Request(t), b4Auth(), b4Requirements(t), time.Unix(b4Time, 900000000))
		if err != nil {
			t.Fatalf("lifetime %v: %v", tc.lifetime, err)
		}
		if c.Claims.IssuedAt != b4Time || c.Claims.NotBefore != b4Time || c.Claims.Expiry != tc.exp {
			t.Errorf("lifetime %v: iat %d nbf %d exp %d, want %d %d %d", tc.lifetime, c.Claims.IssuedAt, c.Claims.NotBefore, c.Claims.Expiry, b4Time, b4Time, tc.exp)
		}
	}
	for _, d := range []time.Duration{61 * time.Second, time.Hour, -time.Second, 1500 * time.Millisecond, time.Millisecond} {
		p := newPublisher(t, contract.NewMemoryReplay(0))
		p.Lifetime = d
		if _, err := p.Issue(bg, b4Request(t), b4Auth(), b4Requirements(t), at(b4Time)); err == nil {
			t.Errorf("lifetime %v accepted", d)
		}
	}
}

// TestIssueRequiresNativeContext: no contract without native authentication
// and a trustworthy agent/key binding for the agent and key the request
// names, in the publisher's realm (draft 9.1, 11.1 step 1).
func TestIssueRequiresNativeContext(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(req *core.ContractRequest, a *contract.Authenticated)
		want error
	}{
		{"no principal", func(_ *core.ContractRequest, a *contract.Authenticated) { a.Principal = adapter.Principal{} }, contract.ErrInvalidProof},
		{"principal in other tenant", func(_ *core.ContractRequest, a *contract.Authenticated) { a.Principal.Realm.TenantID = "globex" }, contract.ErrContextMismatch},
		{"principal in other environment", func(_ *core.ContractRequest, a *contract.Authenticated) {
			a.Principal.Realm.EnvironmentID = "https://gateway.example/environments/payroll"
		}, contract.ErrContextMismatch},
		{"binding unknown", func(_ *core.ContractRequest, a *contract.Authenticated) { a.Binding.Status = adapter.BindingUnknown }, contract.ErrInvalidProof},
		{"binding absent", func(_ *core.ContractRequest, a *contract.Authenticated) { a.Binding = adapter.AgentBinding{} }, contract.ErrInvalidProof},
		{"binding revoked", func(_ *core.ContractRequest, a *contract.Authenticated) { a.Binding.Status = adapter.BindingRevoked }, contract.ErrInvalidProof},
		{"binding compromised", func(_ *core.ContractRequest, a *contract.Authenticated) {
			a.Binding.Status = adapter.BindingCompromised
		}, contract.ErrSecurityHold},
		{"agent enrolled for another workload", func(_ *core.ContractRequest, a *contract.Authenticated) {
			a.Binding = adapter.AgentBinding{Status: adapter.BindingUnknown, EnrolledElsewhere: true}
		}, contract.ErrContextMismatch},
		{"request names another agent", func(req *core.ContractRequest, _ *contract.Authenticated) {
			req.AgentID = "https://identity.example/agents/other"
		}, contract.ErrInvalidProof},
		{"request names another key", func(req *core.ContractRequest, _ *contract.Authenticated) {
			req.HolderJKT = "ahxE1XEYqxvLIZy3r4nx9RE4E0683KndykyuZTK9xQg"
		}, contract.ErrInvalidProof},
		{"operation of another principal", func(req *core.ContractRequest, _ *contract.Authenticated) {
			req.Operation.PrincipalID = "https://identity.example/principals/bob"
		}, contract.ErrContextMismatch},
		{"operation in another environment", func(req *core.ContractRequest, _ *contract.Authenticated) {
			req.Operation.EnvironmentID = "https://gateway.example/environments/payroll"
		}, contract.ErrContextMismatch},
		{"request extension", func(req *core.ContractRequest, _ *contract.Authenticated) {
			req.Extensions = core.Object{"https://extensions.example/x": json.RawMessage(`true`)}
		}, contract.ErrUnsupportedRequirement},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := contract.NewMemoryReplay(0)
			req, auth := b4Request(t), b4Auth()
			tc.edit(&req, &auth)
			c, err := newPublisher(t, store).Issue(bg, req, auth, b4Requirements(t), at(b4Time))
			wantErr(t, err, tc.want)
			if c.Compact != "" {
				t.Fatal("a contract was returned with the error")
			}
		})
	}
}

// TestIssueRequirements: the publisher signs only a complete, valid
// effective set (draft 9.2, 9.4, Appendix A.2).
func TestIssueRequirements(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(r *contract.Requirements)
	}{
		{"weaker set without selection check", func(r *contract.Requirements) { r.SelectedSet = "established" }},
		{"no conservative set", func(r *contract.Requirements) { r.ConservativeSet = "" }},
		{"no selected set", func(r *contract.Requirements) { r.SelectedSet, r.ConservativeSet = "", "" }},
		{"no base revision", func(r *contract.Requirements) { r.Policy.BaseRevision = "" }},
		{"bad learning digest", func(r *contract.Requirements) { r.Policy.LearningPolicyDigest = "x" }},
		{"no context checks", func(r *contract.Requirements) { r.ContextChecks = nil }},
		{"no mode", func(r *contract.Requirements) { r.Mode = "" }},
		{"duplicate rule", func(r *contract.Requirements) { r.FieldRules = append(r.FieldRules, r.FieldRules[0]) }},
		{"evidence rule without issuer", func(r *contract.Requirements) { r.FieldRules[3].AllowedIssuers = []string{} }},
		{"nil issuers", func(r *contract.Requirements) { r.FieldRules[0].AllowedIssuers = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := b4Requirements(t)
			tc.edit(&r)
			_, err := newPublisher(t, contract.NewMemoryReplay(0)).Issue(bg, b4Request(t), b4Auth(), r, at(b4Time))
			wantErr(t, err, contract.ErrInvalidMessage)
		})
	}
	// A weaker set that lists the selection check is issued.
	r := b4Requirements(t)
	r.SelectedSet = "established"
	r.ContextChecks = append(r.ContextChecks, contract.SelectionConsistencyCheck)
	if _, err := newPublisher(t, contract.NewMemoryReplay(0)).Issue(bg, b4Request(t), b4Auth(), r, at(b4Time)); err != nil {
		t.Fatalf("weaker set with the selection check: %v", err)
	}
	// No field rules is a valid set (minItems 0); the payload has an array.
	r = b4Requirements(t)
	r.FieldRules = nil
	c, err := newPublisher(t, contract.NewMemoryReplay(0)).Issue(bg, b4Request(t), b4Auth(), r, at(b4Time))
	if err != nil {
		t.Fatalf("no field rules: %v", err)
	}
	if _, err := b4Verifier(t).Verify(c.Compact, at(b4Time)); err != nil {
		t.Fatalf("contract without field rules: %v", err)
	}
	// Bound extensions are signed into the contract.
	r = b4Requirements(t)
	r.Extensions = core.Object{"pact-transport-profile-v1": json.RawMessage(`{"transport_profile":"https","version":"0.1"}`)}
	c, err = newPublisher(t, contract.NewMemoryReplay(0)).Issue(bg, b4Request(t), b4Auth(), r, at(b4Time))
	if err != nil {
		t.Fatalf("extension: %v", err)
	}
	v, err := b4Verifier(t).Verify(c.Compact, at(b4Time))
	if err != nil {
		t.Fatal(err)
	}
	e := b4Expect()
	wantErr(t, v.Check(e), contract.ErrUnsupportedRequirement)
	e.SupportedExtensions = []string{"pact-transport-profile-v1"}
	if err := v.Check(e); err != nil {
		t.Fatalf("supported extension: %v", err)
	}
}

// TestIssuePublisherConfig: a publisher without identity, signer or store
// issues nothing.
func TestIssuePublisherConfig(t *testing.T) {
	for name, edit := range map[string]func(p *contract.Publisher){
		"no issuer":   func(p *contract.Publisher) { p.Issuer = "" },
		"no audience": func(p *contract.Publisher) { p.Audience = "" },
		"no tenant":   func(p *contract.Publisher) { p.Realm.TenantID = "" },
		"no signer":   func(p *contract.Publisher) { p.Signer = nil },
		"no store":    func(p *contract.Publisher) { p.Replay = nil },
	} {
		t.Run(name, func(t *testing.T) {
			p := newPublisher(t, contract.NewMemoryReplay(0))
			edit(p)
			if _, err := p.Issue(bg, b4Request(t), b4Auth(), b4Requirements(t), at(b4Time)); err == nil {
				t.Fatal("issued")
			}
		})
	}
}

type failingStore struct{ err error }

func (s failingStore) Register(context.Context, contract.NonceRecord, time.Time, time.Time) error {
	return s.err
}

func (s failingStore) Consume(context.Context, contract.NonceRecord, time.Time, time.Time) error {
	return s.err
}

type signerFunc func([]byte) (string, error)

func (f signerFunc) SignContract(p []byte) (string, error) { return f(p) }

// TestIssueFailsClosed: an unavailable store or a failing signer issues no
// contract (DEPENDENCY_UNAVAILABLE), and a signer that signs other bytes is
// refused.
func TestIssueFailsClosed(t *testing.T) {
	p := newPublisher(t, failingStore{errors.New("store down")})
	c, err := p.Issue(bg, b4Request(t), b4Auth(), b4Requirements(t), at(b4Time))
	wantErr(t, err, contract.ErrDependencyUnavailable)
	if c.Compact != "" {
		t.Fatal("contract returned")
	}
	// A store that reports the nonce as known.
	p = newPublisher(t, failingStore{contract.ErrReplay})
	if _, err := p.Issue(bg, b4Request(t), b4Auth(), b4Requirements(t), at(b4Time)); err == nil {
		t.Fatal("issued with a nonce the store already holds")
	}
	full := contract.NewMemoryReplay(1)
	p = newPublisher(t, full)
	if _, err := p.Issue(bg, b4Request(t), b4Auth(), b4Requirements(t), at(b4Time)); err != nil {
		t.Fatal(err)
	}
	_, err = p.Issue(bg, b4Request(t), b4Auth(), b4Requirements(t), at(b4Time))
	wantErr(t, err, contract.ErrDependencyUnavailable)

	p = newPublisher(t, contract.NewMemoryReplay(0))
	p.Signer = signerFunc(func([]byte) (string, error) { return "", errors.New("hsm down") })
	_, err = p.Issue(bg, b4Request(t), b4Auth(), b4Requirements(t), at(b4Time))
	wantErr(t, err, contract.ErrDependencyUnavailable)

	other := compactOf(t, validContract)
	p.Signer = signerFunc(func([]byte) (string, error) { return other, nil })
	if _, err := p.Issue(bg, b4Request(t), b4Auth(), b4Requirements(t), at(b4Time)); err == nil {
		t.Fatal("accepted a signature over other bytes")
	}
	ctx, cancel := context.WithCancel(bg)
	cancel()
	p = newPublisher(t, contract.NewMemoryReplay(0))
	_, err = p.Issue(ctx, b4Request(t), b4Auth(), b4Requirements(t), at(b4Time))
	wantErr(t, err, contract.ErrDependencyUnavailable)
}
