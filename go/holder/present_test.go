package holder_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/holder"
)

// TestAppendixBPresentationReproduces: from the Appendix B inputs (the
// signed B.4 contract, B.5 evidence and B.6 snapshot of the admission/valid
// fixture, the B.2 intent, the B.3 operation and a source profile holding
// more than B.4 asks for), with the jti of the B.7 receipt, the holder
// builds the fixture presentation: the same protected header and payload,
// byte for byte. ES256 signatures are randomized, so the signature is
// compared by verification only (draft Appendix C). The disclosed profile
// is B.1 and its object_digest is the B.7 profile_digest.
func TestAppendixBPresentationReproduces(t *testing.T) {
	h := bHolder(t, memoryKey(t, 1))
	h.Random = jtiRandom(t, bPresentationID)
	got, err := h.Present(bg, bInput(t), at(bTime))
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	want := compactOf(t, validCase+"signed/presentation.jws")
	if signingInput(got.Compact) != signingInput(want) {
		t.Fatalf("signing input differs from the fixture presentation:\n got header %s\nwant header %s\n got payload %s\nwant payload %s",
			segment(t, got.Compact, 0), segment(t, want, 0), segment(t, got.Compact, 1), segment(t, want, 1))
	}
	if got, want := canonicalOf(t, got.Claims.Profile), canonical(t, draftBlock(t, "B.1")); got != want {
		t.Fatalf("disclosed profile is not B.1:\n got %s\nwant %s", got, want)
	}
	if got.ProfileDigest != bProfileDigest {
		t.Fatalf("ProfileDigest %s, want the B.7 profile_digest %s", got.ProfileDigest, bProfileDigest)
	}
	if got.Claims.JTI != bPresentationID {
		t.Fatalf("jti %s, want the B.7 presentation_id %s", got.Claims.JTI, bPresentationID)
	}
	for name, d := range map[string]struct{ got, want core.Digest }{
		"operation": {mustDigest(t, got.Claims.Operation), bOpDigest},
		"intent":    {mustDigest(t, got.Claims.Intent), bIntentDigest},
	} {
		if d.got != d.want {
			t.Fatalf("%s digest %s, want %s", name, d.got, d.want)
		}
	}
	ad, err := digest.ArtifactDigest(got.Compact)
	if err != nil || got.Digest != ad {
		t.Fatalf("Digest %s, want artifact_digest %s (%v)", got.Digest, ad, err)
	}
	if got.Contract.Compact != bInput(t).Contract {
		t.Fatal("Contract is not the embedded contract")
	}
	// The gateway checks on main accept both the fixture and the rebuilt
	// presentation.
	for name, compact := range map[string]string{"fixture": want, "rebuilt": got.Compact} {
		if _, _, err := bChecks(t, bOperation(t), at(bTime)).run(t, compact); err != nil {
			t.Fatalf("%s presentation fails the gateway checks: %v", name, err)
		}
	}
}

func mustDigest(t testing.TB, v any) core.Digest {
	t.Helper()
	d, err := digest.ObjectDigest(v)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestFreshContractPresentationPasses: a contract issued now by the
// publisher on main, presented by the holder, passes the gateway checks, and
// the nonce record the presentation binds is the one the publisher
// registered: it is consumed once, then replayed.
func TestFreshContractPresentationPasses(t *testing.T) {
	now := at(bTime + 3600)
	store := contract.NewMemoryReplay(16)
	c := issue(t, store, bHolderJKT, bRequirements(t), bOperation(t), now)
	in := bInput(t)
	in.Contract = c.Compact
	in.Evidence = []string{signEvidence(t, 2, "test-issuer-key-1", withTimes(bEvidence(t), now.Unix(), now.Unix()+300))}
	in.Reputation = signSnapshot(t, now.Unix())
	in.Profile.CreatedAt, in.Profile.ExpiresAt = now.Unix(), now.Unix()+3600
	p, err := bHolder(t, memoryKey(t, 1)).Present(bg, in, now)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if p.Claims.Nonce != c.Claims.Nonce || p.Claims.IssuedAt != now.Unix() || p.Claims.Expiry != now.Unix()+60 {
		t.Fatalf("nonce %s iat %d exp %d", p.Claims.Nonce, p.Claims.IssuedAt, p.Claims.Expiry)
	}
	_, rec, err := bChecks(t, bOperation(t), now.Add(2*time.Second)).run(t, p.Compact)
	if err != nil {
		t.Fatalf("gateway checks: %v", err)
	}
	until := now.Add(65 * time.Second)
	if err := store.Consume(bg, rec, now.Add(2*time.Second), until); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if err := store.Consume(bg, rec, now.Add(3*time.Second), until); !errors.Is(err, contract.ErrReplay) {
		t.Fatalf("second Consume: %v, want ErrReplay", err)
	}
	// Two presentations of one input differ in jti.
	q, err := bHolder(t, memoryKey(t, 1)).Present(bg, in, now)
	if err != nil {
		t.Fatal(err)
	}
	if q.Claims.JTI == p.Claims.JTI || len(q.Claims.JTI) != 22 {
		t.Fatalf("jti %q and %q: want two distinct 128-bit values", p.Claims.JTI, q.Claims.JTI)
	}
}

func withTimes(e core.Evidence, iat, exp int64) core.Evidence {
	e.IssuedAt, e.NotBefore, e.Expiry = iat, iat, exp
	return e
}

// signSnapshot signs the B.6 snapshot, issued at iat, under the reputation
// service key (scalar 4).
func signSnapshot(t testing.TB, iat int64) string {
	t.Helper()
	return signSnapshotFor(t, iat, bHolderJKT)
}

// signSnapshotFor is signSnapshot for the holder key jkt.
func signSnapshotFor(t testing.TB, iat int64, jkt core.Digest) string {
	t.Helper()
	var s core.ReputationSnapshot
	decodeStrict(t, draftBlock(t, "B.6"), &s)
	s.HolderJKT = jkt
	s.IssuedAt, s.NotBefore, s.Expiry = iat, iat, iat+300
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jws.Sign(jws.Header{Typ: jws.TypReputation, Kid: "test-reputation-service-key-1"}, b, scalarKey(t, 4))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestWrongKeyFails: a key source whose key is not the contract's
// holder_jkt (the second holder key, scalar 10) signs nothing, and one
// that advertises the enrolled key but signs with another (scalar 3) does
// not produce a presentation (draft 6.2, 11.2).
func TestWrongKeyFails(t *testing.T) {
	other := &countingKey{public: memoryKey(t, 10), signer: memoryKey(t, 10)}
	_, err := bHolder(t, other).Present(bg, bInput(t), at(bTime))
	wantErr(t, err, holder.ErrInvalidProof)
	if other.signs != 0 {
		t.Fatalf("the wrong key signed %d times", other.signs)
	}
	_, err = bHolder(t, other).VerifyContract(bg, bInput(t).Contract, bIntent(t), bOperation(t), at(bTime))
	wantErr(t, err, holder.ErrInvalidProof)

	impostor := &countingKey{public: memoryKey(t, 1), signer: memoryKey(t, 3)}
	_, err = bHolder(t, impostor).Present(bg, bInput(t), at(bTime))
	wantErr(t, err, holder.ErrInvalidProof)
	if impostor.signs != 1 {
		t.Fatalf("signs %d, want 1", impostor.signs)
	}

	// A presentation the wrong key signed, for a contract that names that
	// key, fails the gateway's binding to the enrolled key.
	jkt, err := jws.Thumbprint(mustJWK(t, memoryKey(t, 10)))
	if err != nil {
		t.Fatal(err)
	}
	r := bRequirements(t)
	r.FieldRules = slices.DeleteFunc(slices.Clone(r.FieldRules), func(fr core.FieldRule) bool { return fr.RuleID == "reputation-status" })
	c := issue(t, contract.NewMemoryReplay(4), jkt, r, bOperation(t), at(bTime))
	in := bInput(t)
	in.Contract = c.Compact
	in.Profile.HolderJKT = jkt
	in.Evidence = []string{signEvidence(t, 2, "test-issuer-key-1", withHolder(bEvidence(t), jkt))}
	p, err := bHolder(t, memoryKey(t, 10)).Present(bg, in, at(bTime))
	if err != nil {
		t.Fatalf("Present with the key the contract names: %v", err)
	}
	if _, _, err := bChecks(t, bOperation(t), at(bTime)).run(t, p.Compact); err == nil || !strings.Contains(err.Error(), "step 2") {
		t.Fatalf("gateway checks: %v, want a step 2 failure", err)
	}
}

func withHolder(e core.Evidence, jkt core.Digest) core.Evidence {
	e.HolderJKT = jkt
	return e
}

func mustJWK(t testing.TB, k holder.KeySource) jws.JWK {
	t.Helper()
	j, err := k.PublicJWK(bg)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

// TestStaleContractFails: a contract at or after its exp is EXPIRED, with
// no grace period (draft 7.5); one signed by an untrusted publisher, or
// whose rules were edited after signing, fails the publisher proof.
func TestStaleContractFails(t *testing.T) {
	for _, now := range []int64{bContractExp, bContractExp + 1, bTime + 3600} {
		_, err := bHolder(t, memoryKey(t, 1)).Present(bg, bInput(t), at(now))
		wantErr(t, err, holder.ErrExpired)
	}
	h := bHolder(t, memoryKey(t, 1))
	h.Publishers = map[string]*jws.KeySet{bPublisher: fixtureKeySet(t, nil, "adversarial")}
	_, err := h.Present(bg, bInput(t), at(bTime))
	wantErr(t, err, holder.ErrInvalidProof)

	in := bInput(t)
	parts := strings.Split(in.Contract, ".")
	edited := strings.Replace(string(segment(t, in.Contract, 1)), `"const":"managed"`, `"const":"shared"`, 1)
	in.Contract = parts[0] + "." + b64(edited) + "." + parts[2]
	_, err = bHolder(t, memoryKey(t, 1)).Present(bg, in, at(bTime))
	wantErr(t, err, holder.ErrInvalidProof)
}

// TestModifiedOperationFails: an operation or intent that differs in any
// member from the one the contract binds fails before signing (draft 10.3),
// and a presentation of the contracted operation fails the gateway's
// binding check when the actual operation differs (draft 11.3 step 5).
func TestModifiedOperationFails(t *testing.T) {
	edits := map[string]func(op *core.OperationContext){
		"resource":  func(op *core.OperationContext) { op.Resources = []string{"https://invoices.example/invoices/INV-1043"} },
		"method":    func(op *core.OperationContext) { op.Method = "DELETE" },
		"target":    func(op *core.OperationContext) { op.TargetURI += "?all=1" },
		"body":      func(op *core.OperationContext) { op.BodyDigest = digest.BytesDigest([]byte("{}")) },
		"header":    func(op *core.OperationContext) { op.Headers = map[string]string{"x-dry-run": "false"} },
		"principal": func(op *core.OperationContext) { op.PrincipalID = "https://identity.example/principals/mallory" },
		"action":    func(op *core.OperationContext) { op.Action = "invoice.pay" },
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			key := &countingKey{public: memoryKey(t, 1), signer: memoryKey(t, 1)}
			in := bInput(t)
			edit(&in.Operation)
			_, err := bHolder(t, key).Present(bg, in, at(bTime))
			wantErr(t, err, holder.ErrContextMismatch)
			if key.signs != 0 {
				t.Fatal("signed a presentation for a modified operation")
			}
			p, err := bHolder(t, memoryKey(t, 1)).Present(bg, bInput(t), at(bTime))
			if err != nil {
				t.Fatal(err)
			}
			actual := bOperation(t)
			edit(&actual)
			if _, _, err := bChecks(t, actual, at(bTime)).run(t, p.Compact); err == nil || !strings.Contains(err.Error(), "step 5") {
				t.Fatalf("gateway checks with a modified actual operation: %v, want a step 5 failure", err)
			}
		})
	}
	in := bInput(t)
	in.Intent.PurposeID = "https://policies.example/purposes/invoice-payment/v1"
	_, err := bHolder(t, memoryKey(t, 1)).Present(bg, in, at(bTime))
	wantErr(t, err, holder.ErrContextMismatch)
}

// TestContractContext: a contract for another agent, gateway or realm is a
// context mismatch (draft 11.2, 11.3 step 3).
func TestContractContext(t *testing.T) {
	for name, edit := range map[string]func(h *holder.Holder){
		"agent":   func(h *holder.Holder) { h.AgentID = "https://identity.example/agents/other" },
		"gateway": func(h *holder.Holder) { h.Gateway = "https://gateway.example/other" },
		"tenant":  func(h *holder.Holder) { h.Realm.TenantID = "globex" },
		"env":     func(h *holder.Holder) { h.Realm.EnvironmentID = "https://gateway.example/environments/other" },
	} {
		t.Run(name, func(t *testing.T) {
			h := bHolder(t, memoryKey(t, 1))
			edit(h)
			_, err := h.VerifyContract(bg, bInput(t).Contract, bIntent(t), bOperation(t), at(bTime))
			wantErr(t, err, holder.ErrContextMismatch)
		})
	}
	c, err := bHolder(t, memoryKey(t, 1)).VerifyContract(bg, bInput(t).Contract, bIntent(t), bOperation(t), at(bTime))
	if err != nil {
		t.Fatalf("VerifyContract: %v", err)
	}
	if c.Claims.Nonce != "N8WrKpg8XNb9Wh_QuWlHbw" || c.Claims.SelectedSet != "supervised" {
		t.Fatalf("claims %+v", c.Claims)
	}
}

// TestUnsupportedContractExtension: a contract extension the holder does not
// support defers (draft 7.1, 21); a supported one is accepted.
func TestUnsupportedContractExtension(t *testing.T) {
	r := bRequirements(t)
	r.Extensions = core.Object{"https://ext.example/pact/transport-hint": json.RawMessage(`{"v":1}`)}
	c := issue(t, contract.NewMemoryReplay(4), bHolderJKT, r, bOperation(t), at(bTime))
	h := bHolder(t, memoryKey(t, 1))
	_, err := h.VerifyContract(bg, c.Compact, bIntent(t), bOperation(t), at(bTime))
	wantErr(t, err, holder.ErrUnsupportedRequirement)
	h.Extensions = []string{"https://ext.example/pact/transport-hint"}
	if _, err := h.VerifyContract(bg, c.Compact, bIntent(t), bOperation(t), at(bTime)); err != nil {
		t.Fatalf("supported extension: %v", err)
	}
}

// TestDisclosureIsRequirementDriven: the view holds exactly the attribute
// paths the contract's rules name, the reputation value is the snapshot's
// (draft 15.2), attributes no rule names are withheld (draft 8.1, 19), and
// only the evidence a rule uses is attached.
// TestMissingValuesFail: a rule's value the agent does not hold, an evidence
// rule without applicable evidence, and a reputation rule without a snapshot
// fail; the holder does not fill them in (draft 8.6, 9.2).
// TestEvidenceSelection: evidence for another audience, subject, holder key
// or realm, from an issuer the rule does not allow, expired, or of another
// typ is not used; a profile value that differs from the authoritative value
// conflicts (draft 8.3, 8.4).
// TestProfileChecks: the profile view must name the holder's agent, key and
// tenant and be current, with a lifetime of at most 24 hours (draft 8.1,
// 11.2, Appendix A.2).
// TestPresentationLifetime: exp - iat is the configured lifetime, 60 s by
// default and never more (draft 7.5, 20.1).
func TestPresentationLifetime(t *testing.T) {
	h := bHolder(t, memoryKey(t, 1))
	h.Lifetime = 30 * time.Second
	p, err := h.Present(bg, bInput(t), at(bTime+5))
	if err != nil {
		t.Fatal(err)
	}
	if p.Claims.IssuedAt != bTime+5 || p.Claims.NotBefore != bTime+5 || p.Claims.Expiry != bTime+35 {
		t.Fatalf("iat %d nbf %d exp %d", p.Claims.IssuedAt, p.Claims.NotBefore, p.Claims.Expiry)
	}
	for _, bad := range []time.Duration{61 * time.Second, 1500 * time.Millisecond, -time.Second} {
		h.Lifetime = bad
		_, err := h.Present(bg, bInput(t), at(bTime))
		wantErr(t, err, holder.ErrInvalidMessage)
	}
	h = bHolder(t, memoryKey(t, 1))
	h.Skew = 6 * time.Second
	_, err = h.Present(bg, bInput(t), at(bTime))
	wantErr(t, err, holder.ErrInvalidMessage)
}

// TestKeySourceUnavailable: a key source that cannot sign defers; a random
// source that fails does too.
func TestKeySourceUnavailable(t *testing.T) {
	_, err := bHolder(t, failingKey{public: memoryKey(t, 1)}).Present(bg, bInput(t), at(bTime))
	wantErr(t, err, holder.ErrDependencyUnavailable)
	h := bHolder(t, memoryKey(t, 1))
	h.Random = strings.NewReader("short")
	_, err = h.Present(bg, bInput(t), at(bTime))
	wantErr(t, err, holder.ErrDependencyUnavailable)
}

// TestLimits: a presentation is never truncated to fit the draft 20.1
// limits; an input over them fails.
func TestLimits(t *testing.T) {
	in := bInput(t)
	in.Intent.Description = strings.Repeat("x", 4097)
	_, err := bHolder(t, memoryKey(t, 1)).Present(bg, in, at(bTime))
	// The contract binds the original intent, so the oversized one also
	// mismatches; the limit is checked first.
	wantErr(t, err, holder.ErrInvalidMessage)
}

// TestErrorCodes: each sentinel carries its draft 13.4 code.
func TestErrorCodes(t *testing.T) {
	for err, want := range map[error]adapter.Code{
		holder.ErrInvalidMessage:         adapter.CodeInvalidMessage,
		holder.ErrUnsupportedVersion:     adapter.CodeInvalidMessage,
		holder.ErrInvalidProof:           adapter.CodeInvalidProof,
		holder.ErrContextMismatch:        adapter.CodeContextMismatch,
		holder.ErrUnsupportedRequirement: adapter.CodeUnsupportedRequirement,
		holder.ErrMissingField:           adapter.CodeMissingField,
		holder.ErrConflictingEvidence:    "CONFLICTING_EVIDENCE",
		holder.ErrExpired:                "EXPIRED",
		holder.ErrDependencyUnavailable:  adapter.CodeDependencyUnavailable,
	} {
		if got, ok := adapter.CodeOf(err); !ok || got != want {
			t.Fatalf("%v: code %s, want %s", err, got, want)
		}
	}
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// TestSnapshotSelection: a snapshot from a service the rule does not allow,
// or bound to another holder key, audience or realm, or expired, does not
// back a reputation rule; one under another typ is refused (draft 7.2,
// 15.2).
// signSnapshotWith signs the B.6 snapshot, edited, under the reputation
// service key with header typ typ.
