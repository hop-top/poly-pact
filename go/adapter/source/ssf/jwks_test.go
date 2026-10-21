package ssf_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"hop.top/pact-go/adapter/source/ssf"
	"hop.top/pact-go/core/clock"
)

type jwksServer struct {
	*httptest.Server
	hits atomic.Int32
	body atomic.Value // string
	code atomic.Int32
}

func newJWKS(t testing.TB, body string) *jwksServer {
	s := &jwksServer{}
	s.body.Store(body)
	s.code.Store(200)
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.WriteHeader(int(s.code.Load()))
		_, _ = w.Write([]byte(s.body.Load().(string)))
	}))
	t.Cleanup(s.Close)
	return s
}

func jwksOf(t testing.TB, ks ...any) string {
	b, err := json.Marshal(map[string]any{"keys": ks})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// RFC 7517 section 5: the issuer's JWKS, fetched over TLS, cached, refreshed
// on an unknown kid but not more often than the minimum interval.
func TestJWKS(t *testing.T) {
	k2, k3 := jwkOf(t, key(t, 2), "k-2"), jwkOf(t, key(t, 3), "k-3")
	rsa := map[string]any{"kty": "RSA", "kid": "rsa-1", "n": "AQAB", "e": "AQAB", "alg": "RS256"}
	srv := newJWKS(t, jwksOf(t, k2, rsa))
	clk := clock.NewFake(time.Unix(nowSec, 0))
	j, err := ssf.NewJWKS(srv.URL, srv.Client(), clk, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	got, err := j.Key(bg, "k-2")
	if err != nil || got.Kid != "k-2" {
		t.Fatalf("%v %v", got, err)
	}
	// Served from the cache.
	if _, err := j.Key(bg, "k-2"); err != nil || srv.hits.Load() != 1 {
		t.Fatalf("hits %d err %v", srv.hits.Load(), err)
	}
	// A key the profile cannot use is skipped, not fatal, and is unknown.
	if _, err := j.Key(bg, "rsa-1"); !isUnknownKey(err) {
		t.Fatalf("rsa key: %v", err)
	}
	// An unknown kid inside the interval does not refetch.
	hits := srv.hits.Load()
	if _, err := j.Key(bg, "k-3"); !isUnknownKey(err) || srv.hits.Load() != hits {
		t.Fatalf("hits %d err %v", srv.hits.Load(), err)
	}
	// After the interval, a rotated-in key is found.
	srv.body.Store(jwksOf(t, k2, k3))
	clk.Advance(2 * time.Minute)
	if got, err := j.Key(bg, "k-3"); err != nil || got.Kid != "k-3" {
		t.Fatalf("%v %v", got, err)
	}
	// A key removed from the set is no longer served after the next refresh.
	srv.body.Store(jwksOf(t, k3))
	clk.Advance(2 * time.Minute)
	if _, err := j.Key(bg, "k-2"); !isUnknownKey(err) {
		t.Fatalf("revoked key still served: %v", err)
	}
	// A failing endpoint is an outage, not an unknown key.
	srv.code.Store(500)
	clk.Advance(2 * time.Minute)
	if _, err := j.Key(bg, "k-9"); err == nil || isUnknownKey(err) {
		t.Fatalf("outage: %v", err)
	}
}

func TestJWKSMalformedAndInsecure(t *testing.T) {
	if _, err := ssf.NewJWKS("http://keys.example.com/jwks", nil, clock.NewFake(time.Unix(nowSec, 0)), time.Minute); err == nil {
		t.Fatal("http URL accepted")
	}
	for name, body := range map[string]string{
		"not json":      "<html>",
		"no keys":       `{}`,
		"duplicate key": `{"keys":[],"keys":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := newJWKS(t, body)
			j, err := ssf.NewJWKS(srv.URL, srv.Client(), clock.NewFake(time.Unix(nowSec, 0)), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := j.Key(bg, "k"); err == nil || isUnknownKey(err) {
				t.Fatalf("%v", err)
			}
		})
	}
}

// The receiver verifies against a fetched JWKS and answers an unknown kid as
// invalid_key.
func TestReceiverWithJWKS(t *testing.T) {
	srv := newJWKS(t, jwksOf(t, jwkOf(t, key(t, 2), kid)))
	clk := clock.NewFake(time.Unix(nowSec, 0))
	j, err := ssf.NewJWKS(srv.URL, srv.Client(), clk, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	r := newRig(t, func(c *ssf.Config) { c.Issuers[0].Keys = j })
	r.accept(t, signed(t, claims("j-1", nowSec-10, issSub("u-1"), ssf.EventAccountDisabled, nil)))
	r.wantState(t, principal("7a1f"), ssf.StateDisabled, nowSec-10)
	_, err = r.rx.Accept(bg, compact(t, key(t, 3), map[string]any{"alg": "ES256", "typ": "secevent+jwt", "kid": "unlisted"}, claims("j-2", nowSec-10, issSub("u-1"), ssf.EventAccountEnabled, nil)))
	wantCode(t, err, ssf.CodeInvalidKey)
	srv.code.Store(500)
	clk.Advance(2 * time.Minute)
	_, err = r.rx.Accept(bg, compact(t, key(t, 3), map[string]any{"alg": "ES256", "typ": "secevent+jwt", "kid": "unlisted-2"}, claims("j-3", nowSec-10, issSub("u-1"), ssf.EventAccountEnabled, nil)))
	if err == nil {
		t.Fatal("accepted during a key outage")
	}
	var e *ssf.Error
	if asErr(err, &e) {
		t.Fatalf("a key outage is reported as a rejection: %v", err)
	}
}
