package ssf_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"sync"
	"testing"
	"time"

	"hop.top/pact-go/adapter/source"
	"hop.top/pact-go/adapter/source/ssf"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/jws"
)

const (
	nowSec   int64 = 1792080000 // 2026-10-15T16:00:00Z, the draft's sample time
	txIssuer       = "https://tx.example.com"
	rxAud          = "https://rx.example.com/ssf"
	prefix         = "oauth:https%3A%2F%2Fidp.example.com:t1:"
	kid            = "test-issuer-key-1"
)

// key returns the P-256 test key whose private scalar is n (the public test
// keys of spec/v1.0/fixtures/keys: scalar 2 is the issuer key, 3 the adversarial
// key).
func key(t testing.TB, n int64) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), big.NewInt(n).FillBytes(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func jwkOf(t testing.TB, k *ecdsa.PrivateKey, kid string) jws.JWK {
	t.Helper()
	j, err := jws.PublicJWK(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	j.Kid = kid
	return j
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// compact signs header and claims with k as ES256 and returns the compact
// serialization. A nil k writes an empty signature (an unsecured JWT).
func compact(t testing.TB, k *ecdsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	in := b64(h) + "." + b64(c)
	if k == nil {
		return in + "."
	}
	sum := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(randReader{}, k, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return in + "." + b64(sig)
}

// setHeader is the header of a well-formed SET signed by the issuer key.
func setHeader() map[string]any {
	return map[string]any{"alg": "ES256", "typ": "secevent+jwt", "kid": kid}
}

// claims builds the claims of a SET with one event.
func claims(jti string, iat int64, subID any, eventType string, payload map[string]any) map[string]any {
	if payload == nil {
		payload = map[string]any{}
	}
	m := map[string]any{
		"iss": txIssuer, "aud": rxAud, "jti": jti, "iat": iat,
		"events": map[string]any{eventType: payload},
	}
	if subID != nil {
		m["sub_id"] = subID
	}
	return m
}

func issSub(sub string) map[string]any {
	return map[string]any{"format": "iss_sub", "iss": txIssuer, "sub": sub}
}

// signed returns a SET signed by the issuer key.
func signed(t testing.TB, c map[string]any) string {
	t.Helper()
	return compact(t, key(t, 2), setHeader(), c)
}

// telemetry records what the receiver reports.
type telemetry struct {
	mu   sync.Mutex
	recs []ssf.Record
}

func (m *telemetry) Observe(r ssf.Record) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recs = append(m.recs, r)
}

func (m *telemetry) kinds() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, r := range m.recs {
		out = append(out, r.Kind)
	}
	return out
}

func (m *telemetry) reset() {
	m.mu.Lock()
	m.recs = nil
	m.mu.Unlock()
}

func (m *telemetry) last() ssf.Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.recs[len(m.recs)-1]
}

// holds records the hold candidates.
type holds struct {
	mu  sync.Mutex
	got []ssf.HoldCandidate
	err error
}

func (h *holds) Candidate(_ ctxT, c ssf.HoldCandidate) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.err != nil {
		return h.err
	}
	h.got = append(h.got, c)
	return nil
}

// rig is a receiver with its fakes.
type rig struct {
	rx    *ssf.Receiver
	clock *clock.Fake
	store *source.Memory
	tel   *telemetry
	holds *holds
}

// defaultMappings: principal local parts are the immutable ids.
func defaultMappings() []ssf.Mapping {
	return []ssf.Mapping{
		{Issuer: txIssuer, Format: "iss_sub", SubjectIss: txIssuer, Value: "u-1", Local: "7a1f"},
		{Issuer: txIssuer, Format: "iss_sub", SubjectIss: txIssuer, Value: "u-2", Local: "9c2e"},
		{Issuer: txIssuer, Format: "opaque", Value: "o-1", Local: "5b3d"},
		{Issuer: txIssuer, Format: "email", Value: "ada@example.com", Local: "4d4d"},
	}
}

func principal(local string) string { return prefix + local }

func newRig(t testing.TB, mod ...func(*ssf.Config)) *rig {
	t.Helper()
	r := &rig{
		clock: clock.NewFake(time.Unix(nowSec, 0)),
		store: source.NewMemory(),
		tel:   &telemetry{},
		holds: &holds{},
	}
	cfg := ssf.Config{
		SourceID:        "ssf-test",
		Store:           r.store,
		Clock:           r.clock,
		PrincipalPrefix: prefix,
		Issuers: []ssf.Issuer{{
			Issuer: txIssuer, Audience: rxAud,
			Keys: ssf.StaticKeys{jwkOf(t, key(t, 2), kid)},
		}},
		Mappings:  defaultMappings(),
		Telemetry: r.tel,
		Holds:     r.holds,
	}
	for _, m := range mod {
		m(&cfg)
	}
	rx, err := ssf.NewReceiver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.rx = rx
	return r
}
