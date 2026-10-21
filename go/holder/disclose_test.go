package holder_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/holder"
)

func TestDisclosureIsRequirementDriven(t *testing.T) {
	in := bInput(t)
	unused := withClaims(bEvidence(t), core.Claim{Path: "/attributes/capabilities/languages", Value: json.RawMessage(`["en","fr"]`)})
	unused.JTI = "unusedEvidence000000000"
	in.Evidence = append([]string{signEvidence(t, 2, "test-issuer-key-1", unused)}, in.Evidence...)
	p, err := bHolder(t, memoryKey(t, 1)).Present(bg, in, at(bTime))
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	attrs := canonicalOf(t, p.Claims.Profile.Attributes)
	for _, withheld := range []string{"display_name", "capabilities", "build-17"} {
		if strings.Contains(attrs, withheld) {
			t.Fatalf("disclosed %s: %s", withheld, attrs)
		}
	}
	if len(p.Claims.Evidence) != 1 || p.Claims.Evidence[0] != bInput(t).Evidence[0] {
		t.Fatalf("evidence %v, want only the runtime evidence", p.Claims.Evidence)
	}
	if p.Claims.Reputation == nil || *p.Claims.Reputation != bInput(t).Reputation {
		t.Fatal("snapshot not attached")
	}
	// A contract without reputation rules attaches no snapshot.
	r := bRequirements(t)
	r.FieldRules = slices.DeleteFunc(slices.Clone(r.FieldRules), func(fr core.FieldRule) bool { return fr.RuleID == "reputation-status" })
	c := issue(t, contract.NewMemoryReplay(4), bHolderJKT, r, bOperation(t), at(bTime))
	in = bInput(t)
	in.Contract = c.Compact
	p, err = bHolder(t, memoryKey(t, 1)).Present(bg, in, at(bTime))
	if err != nil {
		t.Fatalf("Present without reputation rules: %v", err)
	}
	if p.Claims.Reputation != nil {
		t.Fatal("snapshot attached although no rule requires it")
	}
	if _, ok := p.Claims.Profile.Attributes["reputation"]; ok {
		t.Fatal("reputation disclosed although no rule requires it")
	}
}

func withClaims(e core.Evidence, claims ...core.Claim) core.Evidence {
	e.Claims = claims
	return e
}

func TestMissingValuesFail(t *testing.T) {
	cases := map[string]func(in *holder.Input){
		"native value": func(in *holder.Input) { delete(in.Profile.Attributes, "delegation") },
		"no evidence":  func(in *holder.Input) { in.Evidence = nil },
		"no snapshot":  func(in *holder.Input) { in.Reputation = "" },
		"self-asserted reputation": func(in *holder.Input) {
			in.Reputation = ""
			in.Profile.Attributes["reputation"] = json.RawMessage(`{"security_status":"CLEAR"}`)
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			in := bInput(t)
			edit(&in)
			_, err := bHolder(t, memoryKey(t, 1)).Present(bg, in, at(bTime))
			wantErr(t, err, holder.ErrMissingField)
		})
	}
	// Evidence supplies a value the source profile lacks: it is authoritative.
	in := bInput(t)
	in.Profile.Attributes["runtime"] = json.RawMessage(`{}`)
	p, err := bHolder(t, memoryKey(t, 1)).Present(bg, in, at(bTime))
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if got := string(p.Claims.Profile.Attributes["runtime"]); got != `{"isolation":"managed"}` {
		t.Fatalf("runtime %s", got)
	}
}

func TestEvidenceSelection(t *testing.T) {
	inapplicable := map[string]func(e *core.Evidence){
		"audience": func(e *core.Evidence) { e.Audience = "https://gateway.example/other" },
		"subject":  func(e *core.Evidence) { e.Subject = "https://identity.example/agents/other" },
		"holder":   func(e *core.Evidence) { e.HolderJKT = core.Digest(strings.Repeat("A", 43)) },
		"tenant":   func(e *core.Evidence) { e.TenantID = "globex" },
		"env":      func(e *core.Evidence) { e.EnvironmentID = "https://gateway.example/environments/other" },
		"issuer":   func(e *core.Evidence) { e.Issuer = "https://trust.example/issuers/other" },
		"expired":  func(e *core.Evidence) { e.IssuedAt, e.NotBefore, e.Expiry = bTime-600, bTime-600, bTime },
		"future":   func(e *core.Evidence) { e.IssuedAt, e.NotBefore, e.Expiry = bTime+60, bTime+60, bTime+300 },
		"path":     func(e *core.Evidence) { e.Claims[0].Path = "/attributes/runtime" },
	}
	for name, edit := range inapplicable {
		t.Run(name, func(t *testing.T) {
			e := bEvidence(t)
			edit(&e)
			in := bInput(t)
			in.Evidence = []string{signEvidence(t, 2, "test-issuer-key-1", e)}
			_, err := bHolder(t, memoryKey(t, 1)).Present(bg, in, at(bTime))
			wantErr(t, err, holder.ErrMissingField)
		})
	}
	t.Run("conflict", func(t *testing.T) {
		in := bInput(t)
		in.Profile.Attributes["runtime"] = json.RawMessage(`{"isolation":"shared"}`)
		_, err := bHolder(t, memoryKey(t, 1)).Present(bg, in, at(bTime))
		wantErr(t, err, holder.ErrConflictingEvidence)
	})
	t.Run("evidence disagrees", func(t *testing.T) {
		in := bInput(t)
		in.Profile.Attributes["runtime"] = json.RawMessage(`{}`)
		e := withClaims(bEvidence(t), core.Claim{Path: "/attributes/runtime/isolation", Value: json.RawMessage(`"shared"`)})
		in.Evidence = append(in.Evidence, signEvidence(t, 2, "test-issuer-key-1", e))
		_, err := bHolder(t, memoryKey(t, 1)).Present(bg, in, at(bTime))
		wantErr(t, err, holder.ErrConflictingEvidence)
	})
	t.Run("held value, evidence disagrees", func(t *testing.T) {
		in := bInput(t)
		e := withClaims(bEvidence(t), core.Claim{Path: "/attributes/runtime/isolation", Value: json.RawMessage(`"shared"`)})
		in.Evidence = append(in.Evidence, signEvidence(t, 2, "test-issuer-key-1", e))
		_, err := bHolder(t, memoryKey(t, 1)).Present(bg, in, at(bTime))
		wantErr(t, err, holder.ErrConflictingEvidence)
	})
	t.Run("snapshot binding", func(t *testing.T) {
		in := bInput(t)
		in.Reputation = in.Evidence[0] // evidence in the snapshot slot
		_, err := bHolder(t, memoryKey(t, 1)).Present(bg, in, at(bTime))
		wantErr(t, err, holder.ErrInvalidMessage)
	})
	t.Run("malformed evidence", func(t *testing.T) {
		in := bInput(t)
		in.Evidence = []string{"not.a.jws"}
		_, err := bHolder(t, memoryKey(t, 1)).Present(bg, in, at(bTime))
		wantErr(t, err, holder.ErrInvalidMessage)
	})
	t.Run("evidence version", func(t *testing.T) {
		e := bEvidence(t)
		e.PactVersion = "0.2"
		in := bInput(t)
		in.Evidence = []string{signEvidence(t, 2, "test-issuer-key-1", e)}
		_, err := bHolder(t, memoryKey(t, 1)).Present(bg, in, at(bTime))
		wantErr(t, err, holder.ErrUnsupportedVersion)
	})
}

func TestProfileChecks(t *testing.T) {
	cases := map[string]struct {
		edit func(p *core.AgentProfile)
		want error
	}{
		"holder_jkt": {func(p *core.AgentProfile) { p.HolderJKT = core.Digest(strings.Repeat("A", 43)) }, holder.ErrInvalidProof},
		"agent":      {func(p *core.AgentProfile) { p.AgentID = "https://identity.example/agents/other" }, holder.ErrContextMismatch},
		"tenant":     {func(p *core.AgentProfile) { p.TenantID = "globex" }, holder.ErrContextMismatch},
		"expired":    {func(p *core.AgentProfile) { p.CreatedAt, p.ExpiresAt = bTime-7200, bTime }, holder.ErrExpired},
		"future":     {func(p *core.AgentProfile) { p.CreatedAt, p.ExpiresAt = bTime+60, bTime+3600 }, holder.ErrInvalidMessage},
		"lifetime":   {func(p *core.AgentProfile) { p.CreatedAt, p.ExpiresAt = bTime-60, bTime-60+86401 }, holder.ErrInvalidMessage},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			in := bInput(t)
			c.edit(&in.Profile)
			_, err := bHolder(t, memoryKey(t, 1)).Present(bg, in, at(bTime))
			wantErr(t, err, c.want)
		})
	}
	in := bInput(t)
	in.Profile.CreatedAt, in.Profile.ExpiresAt = bTime-60, bTime-60+86400
	if _, err := bHolder(t, memoryKey(t, 1)).Present(bg, in, at(bTime)); err != nil {
		t.Fatalf("24-hour profile: %v", err)
	}
}

func TestSnapshotSelection(t *testing.T) {
	cases := map[string]func(s *core.ReputationSnapshot){
		"issuer":   func(s *core.ReputationSnapshot) { s.Issuer = "https://reputation.example/other" },
		"holder":   func(s *core.ReputationSnapshot) { s.HolderJKT = core.Digest(strings.Repeat("A", 43)) },
		"audience": func(s *core.ReputationSnapshot) { s.Audience = "https://gateway.example/other" },
		"subject":  func(s *core.ReputationSnapshot) { s.Subject = "https://identity.example/agents/other" },
		"env":      func(s *core.ReputationSnapshot) { s.EnvironmentID = "https://gateway.example/environments/other" },
		"expired":  func(s *core.ReputationSnapshot) { s.IssuedAt, s.NotBefore, s.Expiry = bTime-300, bTime-300, bTime },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			in := bInput(t)
			in.Reputation = signSnapshotWith(t, jws.TypReputation, edit)
			_, err := bHolder(t, memoryKey(t, 1)).Present(bg, in, at(bTime))
			wantErr(t, err, holder.ErrMissingField)
		})
	}
	in := bInput(t)
	in.Reputation = signSnapshotWith(t, jws.TypReputation, func(*core.ReputationSnapshot) {})
	if _, err := bHolder(t, memoryKey(t, 1)).Present(bg, in, at(bTime)); err != nil {
		t.Fatalf("unedited snapshot: %v", err)
	}
	in.Reputation = signSnapshotWith(t, jws.TypEvidence, func(*core.ReputationSnapshot) {})
	_, err := bHolder(t, memoryKey(t, 1)).Present(bg, in, at(bTime))
	wantErr(t, err, holder.ErrInvalidMessage)
}

func signSnapshotWith(t testing.TB, typ string, edit func(s *core.ReputationSnapshot)) string {
	t.Helper()
	var s core.ReputationSnapshot
	decodeStrict(t, draftBlock(t, "B.6"), &s)
	edit(&s)
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jws.Sign(jws.Header{Typ: typ, Kid: "test-reputation-service-key-1"}, b, scalarKey(t, 4))
	if err != nil {
		t.Fatal(err)
	}
	return out
}
