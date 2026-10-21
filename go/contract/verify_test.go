package contract_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core/jws"
)

const validContract = "admission/valid/signed/contract.jws"

func wantErr(t testing.TB, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error %v, want %v", err, want)
	}
	for _, other := range []error{
		contract.ErrInvalidMessage, contract.ErrInvalidProof, contract.ErrContextMismatch,
		contract.ErrUnsupportedRequirement, contract.ErrRequirementsChanged, contract.ErrExpired,
		contract.ErrReplay, contract.ErrDependencyUnavailable, contract.ErrSecurityHold, contract.ErrUnsupportedPurpose,
	} {
		if other != want && errors.Is(err, other) {
			t.Fatalf("error %v also wraps %v", err, other)
		}
	}
}

// TestAppendixB4Verifies: the signed contract of the admission/valid case,
// whose payload is the Appendix B.4 contract, verifies under the publisher
// key at the B.4 time and passes the contract-validity and active-policy
// checks against the B.4 context.
func TestAppendixB4Verifies(t *testing.T) {
	compact := compactOf(t, validContract)
	c, err := b4Verifier(t).Verify(compact, at(b4Time))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got, want := canonical(t, segment(t, compact, 1)), canonical(t, draftBlock(t, "B.4")); got != want {
		t.Fatalf("fixture payload is not the B.4 contract:\n got %s\nwant %s", got, want)
	}
	claims, err := json.Marshal(c.Claims)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := canonical(t, claims), canonical(t, draftBlock(t, "B.4")); got != want {
		t.Fatalf("Claims are not the B.4 contract:\n got %s\nwant %s", got, want)
	}
	if c.Compact != compact {
		t.Fatal("Compact is not the received text")
	}
	sum := sha256.Sum256([]byte(compact))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); string(c.Digest) != want {
		t.Fatalf("Digest %s, want artifact_digest %s", c.Digest, want)
	}
	if err := c.Check(b4Expect()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if err := c.CheckActive(b4Policy()); err != nil {
		t.Fatalf("CheckActive: %v", err)
	}
	r := c.NonceRecord()
	want := contract.NonceRecord{
		Nonce: "N8WrKpg8XNb9Wh_QuWlHbw", AgentID: b4Agent, HolderJKT: b4HolderJKT, Realm: b4Realm,
		OperationDigest: b4OpDigest, RequirementsDigest: c.Digest,
	}
	if r != want {
		t.Fatalf("NonceRecord %+v, want %+v", r, want)
	}
}

// TestTamperedRulesRejected: rules edited after signing fail the publisher
// signature (INVALID_PROOF), whether the agent swapped in another set
// (selection/agent-requests-weaker-set) or changed one member of one rule.
func TestTamperedRulesRejected(t *testing.T) {
	v := b4Verifier(t)
	edited := compactOf(t, "selection/agent-requests-weaker-set/signed/contract.jws")
	if _, err := v.Verify(edited, at(b4Time+10)); err == nil {
		t.Fatal("edited contract verified")
	} else {
		wantErr(t, err, contract.ErrInvalidProof)
	}

	compact := compactOf(t, validContract)
	for name, edit := range map[string]func(m map[string]any){
		"max_age_seconds": func(m map[string]any) {
			m["field_rules"].([]any)[3].(map[string]any)["max_age_seconds"] = json.Number("3600")
		},
		"allowed_issuers": func(m map[string]any) {
			m["field_rules"].([]any)[3].(map[string]any)["allowed_issuers"] = []any{"https://attacker.example/issuer"}
		},
		"rule removed": func(m map[string]any) {
			m["field_rules"] = m["field_rules"].([]any)[:4]
		},
		"context check removed": func(m map[string]any) {
			m["context_checks"] = m["context_checks"].([]any)[:3]
		},
		"selected_set": func(m map[string]any) { m["selected_set"] = "established" },
	} {
		t.Run(name, func(t *testing.T) {
			parts := strings.Split(compact, ".")
			parts[1] = base64.RawURLEncoding.EncodeToString(editPayload(t, compact, edit))
			_, err := v.Verify(strings.Join(parts, "."), at(b4Time))
			wantErr(t, err, contract.ErrInvalidProof)
		})
	}
}

// TestPublisherAuthority: only a key of the trust record that iss names
// verifies a contract. Another trusted key, or an iss without a trust
// record, is INVALID_PROOF.
func TestPublisherAuthority(t *testing.T) {
	compact := compactOf(t, validContract)
	for name, v := range map[string]contract.Verifier{
		"no publishers": {Skew: 5 * time.Second},
		"iss not configured": {Publishers: map[string]*jws.KeySet{
			"https://trust.example/issuers/payroll": fixtureKeySet(t, "issuer"),
		}, Skew: 5 * time.Second},
		"other key for iss": {Publishers: map[string]*jws.KeySet{
			b4Publisher: fixtureKeySet(t, "validator"),
		}, Skew: 5 * time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(compact, at(b4Time))
			wantErr(t, err, contract.ErrInvalidProof)
		})
	}
	// A contract signed by the adversarial key under the publisher's kid.
	forged := resign(t, segment(t, compact, 0), segment(t, compact, 1), scalarKey(t, 3))
	_, err := b4Verifier(t).Verify(forged, at(b4Time))
	wantErr(t, err, contract.ErrInvalidProof)
}

// TestWrongAudienceAndRealm: the admission cases whose gateway differs from
// the one the contract names fail the contract-validity check with
// CONTEXT_MISMATCH (spec/v1.0/fixtures/admission/README.md rows R04).
func TestWrongAudienceAndRealm(t *testing.T) {
	for _, tc := range []struct {
		name   string
		expect contract.Expect
	}{
		{"wrong-audience", contract.Expect{AgentID: b4Agent, Audience: "https://gateway.example/payroll", Realm: b4Realm}},
		{"wrong-tenant", contract.Expect{AgentID: b4Agent, Audience: b4Gateway, Realm: adapter.Realm{TenantID: "globex", EnvironmentID: b4Env}}},
		{"wrong-environment", contract.Expect{AgentID: b4Agent, Audience: b4Gateway, Realm: adapter.Realm{TenantID: b4Tenant, EnvironmentID: "https://gateway.example/environments/payroll"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := b4Verifier(t).Verify(compactOf(t, "admission/"+tc.name+"/signed/contract.jws"), at(b4Time))
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			wantErr(t, c.Check(tc.expect), contract.ErrContextMismatch)
			if err := c.Check(b4Expect()); err != nil {
				t.Fatalf("Check against the contract's own context: %v", err)
			}
		})
	}
	c, err := b4Verifier(t).Verify(compactOf(t, validContract), at(b4Time))
	if err != nil {
		t.Fatal(err)
	}
	for name, e := range map[string]contract.Expect{
		"other agent":     {AgentID: "https://identity.example/agents/other", Audience: b4Gateway, Realm: b4Realm},
		"empty agent":     {Audience: b4Gateway, Realm: b4Realm},
		"empty audience":  {AgentID: b4Agent, Realm: b4Realm},
		"empty realm":     {AgentID: b4Agent, Audience: b4Gateway},
		"audience suffix": {AgentID: b4Agent, Audience: b4Gateway + "/", Realm: b4Realm},
	} {
		t.Run(name, func(t *testing.T) { wantErr(t, c.Check(e), contract.ErrContextMismatch) })
	}
}

// TestUnsupportedExtension: admission/unknown-required-extension carries an
// extension the gateway does not support: contract-validity is
// UNSUPPORTED_REQUIREMENT, unless the gateway supports it.
func TestUnsupportedExtension(t *testing.T) {
	c, err := b4Verifier(t).Verify(compactOf(t, "admission/unknown-required-extension/signed/contract.jws"), at(b4Time))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	wantErr(t, c.Check(b4Expect()), contract.ErrUnsupportedRequirement)
	e := b4Expect()
	e.SupportedExtensions = []string{"https://extensions.example/pact/geo-fence-v1"}
	if err := c.Check(e); err != nil {
		t.Fatalf("Check with the extension supported: %v", err)
	}
	// A context mismatch is reported before the unsupported extension.
	e = b4Expect()
	e.Audience = "https://gateway.example/payroll"
	wantErr(t, c.Check(e), contract.ErrContextMismatch)
}

// TestRequirementsChanged: the selection cases whose active policy changed
// after issuance (spec/v1.0/fixtures/selection/README.md) fail the active-policy
// check with REQUIREMENTS_CHANGED.
func TestRequirementsChanged(t *testing.T) {
	for _, tc := range []struct {
		name   string
		active contract.Policy
	}{
		{"policy-revision-changed", contract.Policy{BaseRevision: "finance-base-4", LearningPolicyDigest: b4PolicyDig, LearningArtifactDigest: b4ArtDig}},
		{"selector-rolled-back", contract.Policy{BaseRevision: b4Base, LearningPolicyDigest: b4PolicyDig, LearningArtifactDigest: "rzz4zv_9KiTRHF7_aQVAYUILJEYi0VlrBJDdRRgzCzg"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := b4Verifier(t).Verify(compactOf(t, "selection/"+tc.name+"/signed/contract.jws"), at(b4Time+10))
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			wantErr(t, c.CheckActive(tc.active), contract.ErrRequirementsChanged)
			if err := c.CheckActive(b4Policy()); err != nil {
				t.Fatalf("CheckActive against the pinned policy: %v", err)
			}
		})
	}
	c, err := b4Verifier(t).Verify(compactOf(t, validContract), at(b4Time))
	if err != nil {
		t.Fatal(err)
	}
	p := b4Policy()
	p.LearningPolicyDigest = b4ArtDig
	wantErr(t, c.CheckActive(p), contract.ErrRequirementsChanged)
}

// TestExpiredContract: B.4 has exp 1792080060. There is no grace period:
// at exp, and at exp plus the skew, it is EXPIRED (draft 7.5, 12.2).
func TestExpiredContract(t *testing.T) {
	compact := compactOf(t, validContract)
	v := b4Verifier(t)
	if _, err := v.Verify(compact, at(1792080059)); err != nil {
		t.Fatalf("one second before exp: %v", err)
	}
	if _, err := v.Verify(compact, time.Unix(1792080059, 999999999)); err != nil {
		t.Fatalf("just before exp: %v", err)
	}
	for _, now := range []int64{1792080060, 1792080065, 1792090000} {
		_, err := v.Verify(compact, at(now))
		wantErr(t, err, contract.ErrExpired)
	}
}

// TestTimeRules: nbf and iat later than now plus skew, a lifetime over 60 s
// (draft 9.1, 20.1) and nbf not before exp (Appendix A.2) are invalid.
func TestTimeRules(t *testing.T) {
	compact := compactOf(t, validContract)
	v := b4Verifier(t)
	// iat = nbf = 1792080000; skew 5 s.
	if _, err := v.Verify(compact, at(b4Time-5)); err != nil {
		t.Fatalf("issued at now plus skew: %v", err)
	}
	_, err := v.Verify(compact, at(b4Time-6))
	wantErr(t, err, contract.ErrInvalidMessage)

	key := scalarKey(t, 2)
	header := segment(t, compact, 0)
	for _, tc := range []struct {
		name string
		now  int64
		edit func(m map[string]any)
	}{
		{"lifetime 61 s", b4Time, func(m map[string]any) { m["exp"] = json.Number("1792080061") }},
		// nbf <= now+skew and now < exp hold; only nbf < exp fails.
		{"nbf at exp", b4Time, func(m map[string]any) {
			m["iat"] = json.Number("1792079990")
			m["nbf"] = json.Number("1792080003")
			m["exp"] = json.Number("1792080003")
		}},
		{"exp at iat", b4Time - 3, func(m map[string]any) { m["exp"] = json.Number("1792080000") }},
		{"nbf in the future", b4Time, func(m map[string]any) { m["nbf"] = json.Number("1792080006") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Verify(resign(t, header, editPayload(t, compact, tc.edit), key), at(tc.now))
			wantErr(t, err, contract.ErrInvalidMessage)
		})
	}

	bad := contract.Verifier{Publishers: v.Publishers, Skew: 6 * time.Second}
	if _, err := bad.Verify(compact, at(b4Time)); err == nil {
		t.Fatal("skew above 5 s accepted")
	}
}

// TestInvalidContracts: a contract signed by the publisher that breaks the
// schema or Appendix A.2 is INVALID_MESSAGE, as is a JWS of another typ.
func TestInvalidContracts(t *testing.T) {
	compact := compactOf(t, validContract)
	v := b4Verifier(t)
	key := scalarKey(t, 2)
	header := segment(t, compact, 0)
	rule := func(i int, member string, value any) func(m map[string]any) {
		return func(m map[string]any) { m["field_rules"].([]any)[i].(map[string]any)[member] = value }
	}
	for name, edit := range map[string]func(m map[string]any){
		"unknown member":           func(m map[string]any) { m["max_uses"] = json.Number("2") },
		"pact_version":             func(m map[string]any) { m["pact_version"] = "0.2" },
		"missing nonce":            func(m map[string]any) { delete(m, "nonce") },
		"short nonce":              func(m map[string]any) { m["nonce"] = "N8WrKpg8XNb9Wh_QuWlHb" },
		"nonce not base64url":      func(m map[string]any) { m["nonce"] = "N8WrKpg8XNb9Wh/QuWlHbw" },
		"short jti":                func(m map[string]any) { m["jti"] = "zIMh1jdcSU0EP90CYPIbw" },
		"empty sub":                func(m map[string]any) { m["sub"] = "" },
		"relative aud":             func(m map[string]any) { m["aud"] = "gateway.example/finance" },
		"empty tenant":             func(m map[string]any) { m["tenant_id"] = "" },
		"empty contract_id":        func(m map[string]any) { m["contract_id"] = "" },
		"empty base_revision":      func(m map[string]any) { m["base_revision"] = "" },
		"empty selected_set":       func(m map[string]any) { m["selected_set"] = "" },
		"holder_jkt":               func(m map[string]any) { m["holder_jkt"] = "xx0BcA" },
		"operation_digest":         func(m map[string]any) { m["operation_digest"] = "R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn=" },
		"mode":                     func(m map[string]any) { m["mode"] = "permissive" },
		"no context checks":        func(m map[string]any) { m["context_checks"] = []any{} },
		"duplicate context check":  func(m map[string]any) { m["context_checks"] = []any{"security-hold-v1", "security-hold-v1"} },
		"field_rules null":         func(m map[string]any) { m["field_rules"] = nil },
		"duplicate rule_id":        rule(1, "rule_id", "principal"),
		"empty rule_id":            rule(0, "rule_id", ""),
		"path not a pointer":       rule(0, "path", "attributes/environment/principal_id"),
		"path bad escape":          rule(0, "path", "/attributes/a~2b"),
		"schema string":            rule(0, "schema", "string"),
		"source":                   rule(0, "source", "agent"),
		"comparison":               rule(0, "comparison", "contains"),
		"native with issuers":      rule(0, "allowed_issuers", []any{b4Publisher}),
		"native without path":      rule(0, "native_path", nil),
		"native_path not pointer":  rule(0, "native_path", "principal/id"),
		"evidence without issuers": rule(3, "allowed_issuers", []any{}),
		"evidence with path":       rule(3, "native_path", "/principal/id"),
		"duplicate issuers":        rule(3, "allowed_issuers", []any{b4Publisher, b4Publisher}),
		"relative issuer":          rule(3, "allowed_issuers", []any{"trust.example"}),
		"negative age":             rule(3, "max_age_seconds", json.Number("-1")),
		"self with issuers": func(m map[string]any) {
			r := m["field_rules"].([]any)[3].(map[string]any)
			r["source"], r["max_age_seconds"], r["status_max_age_seconds"] = "self", json.Number("0"), json.Number("0")
		},
		"self with native_path": func(m map[string]any) {
			r := m["field_rules"].([]any)[0].(map[string]any)
			r["source"], r["max_age_seconds"], r["status_max_age_seconds"] = "self", json.Number("0"), json.Number("0")
		},
		"self subset": func(m map[string]any) {
			r := m["field_rules"].([]any)[3].(map[string]any)
			r["source"], r["allowed_issuers"], r["max_age_seconds"], r["status_max_age_seconds"], r["comparison"] = "self", []any{}, json.Number("0"), json.Number("0"), "subset"
		},
		"self with age": func(m map[string]any) {
			r := m["field_rules"].([]any)[3].(map[string]any)
			r["source"], r["allowed_issuers"], r["max_age_seconds"], r["status_max_age_seconds"] = "self", []any{}, json.Number("30"), json.Number("0")
		},
		"self with status age": func(m map[string]any) {
			r := m["field_rules"].([]any)[3].(map[string]any)
			r["source"], r["allowed_issuers"], r["max_age_seconds"], r["status_max_age_seconds"] = "self", []any{}, json.Number("0"), json.Number("1")
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(resign(t, header, editPayload(t, compact, edit), key), at(b4Time))
			wantErr(t, err, contract.ErrInvalidMessage)
		})
	}

	// A valid self rule is accepted.
	selfRule := func(m map[string]any) {
		r := m["field_rules"].([]any)[3].(map[string]any)
		r["source"], r["allowed_issuers"], r["max_age_seconds"], r["status_max_age_seconds"] = "self", []any{}, json.Number("0"), json.Number("0")
	}
	if _, err := v.Verify(resign(t, header, editPayload(t, compact, selfRule), key), at(b4Time)); err != nil {
		t.Fatalf("self rule: %v", err)
	}

	// A boolean schema is a valid rule schema (Appendix A.1).
	if _, err := v.Verify(resign(t, header, editPayload(t, compact, rule(0, "schema", true)), key), at(b4Time)); err != nil {
		t.Fatalf("boolean schema: %v", err)
	}

	// The evidence typ under the publisher key.
	ev, err := jws.Sign(jws.Header{Typ: jws.TypEvidence, Kid: "test-issuer-key-1"}, segment(t, compact, 1), key)
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(ev, at(b4Time))
	wantErr(t, err, contract.ErrInvalidMessage)

	for name, s := range map[string]string{
		"empty":        "",
		"two segments": strings.Join(strings.Split(compact, ".")[:2], "."),
		"not base64":   "!" + compact,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(s, at(b4Time))
			wantErr(t, err, contract.ErrInvalidMessage)
		})
	}
}
