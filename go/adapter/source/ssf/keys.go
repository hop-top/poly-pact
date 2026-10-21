package ssf

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
)

// KeySource supplies the ES256 keys a transmitter signs SETs with, by kid:
// the EC P-256 keys of the JWS profile (package jws). A source that also
// serves RSA keys implements [RSAKeySource].
type KeySource interface {
	// Key returns the key with the given kid. A kid with no usable key is
	// [ErrUnknownKey]; any other error means the source cannot answer now.
	Key(ctx context.Context, kid string) (jws.JWK, error)
}

// StaticKeys is a [KeySource] over fixed configuration: EC P-256 keys served
// to ES256. [NewReceiver] checks each key as a verification would use it and
// refuses a list that holds a key that is not usable or a kid that two keys
// share. Used without a receiver, the list trusts such a kid for neither key.
type StaticKeys []jws.JWK

// Key implements [KeySource].
func (s StaticKeys) Key(_ context.Context, kid string) (jws.JWK, error) {
	if k, ok := unique(s, kid, func(k jws.JWK) string { return k.Kid }); ok {
		return k, nil
	}
	return jws.JWK{}, ErrUnknownKey
}

// maxJWKS bounds a JWKS response.
const maxJWKS = 1 << 20

// JWKS is a [KeySource] over the jwks_uri of a transmitter (SSF 1.0 section
// 7.1; RFC 7517 section 5). The set is fetched over HTTPS and held for at
// most the refresh interval, after which the next use fetches it again, so a
// key the transmitter removes stops verifying within one interval. When a
// refresh fails (a network or HTTP error, or a response that is not a key
// set), the source fails until the interval ends: it never serves keys it
// cannot confirm. One fetch runs at a time: the callers that need the set
// meanwhile wait for it, each no longer than its own context allows. The
// context of the caller that runs the fetch bounds it; a fetch cut short
// because that context ended is not a failed refresh, and the next caller, a
// waiting one included, fetches. A key that is neither an EC P-256 key of the profile ([KeySource]) nor an RSA
// key ([RSAKeySource], see [ParseRSAKey]) is skipped. A kid that two keys of
// one type share is trusted for neither of them; keys of different types may
// share a kid (RFC 7517 section 4.5), each lookup serving the key of its type.
type JWKS struct {
	url     string
	client  *http.Client
	clock   clock.Clock
	refresh time.Duration

	// mu guards the fields below; it is never held during a fetch.
	mu      sync.Mutex
	keys    map[string]jws.JWK
	rsa     map[string]RSAKey
	attempt time.Time
	err     error
	// fetching is closed when the fetch in flight ends; nil when none is.
	fetching chan struct{}
}

// NewJWKS returns a JWKS source for an https URL. A nil client is
// http.DefaultClient; refresh is the longest time a fetched set is used and
// the shortest time between two fetches that complete or fail (one cut short
// by its caller's context does not count), and must be positive.
func NewJWKS(rawURL string, client *http.Client, clk clock.Clock, refresh time.Duration) (*JWKS, error) {
	if err := httpsURL(rawURL); err != nil {
		return nil, fmt.Errorf("ssf: jwks_uri: %w", err)
	}
	if clk == nil {
		return nil, errors.New("ssf: no clock")
	}
	if refresh <= 0 {
		return nil, errors.New("ssf: the refresh interval must be positive")
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &JWKS{url: rawURL, client: client, clock: clk, refresh: refresh}, nil
}

// Key implements [KeySource]. It serves EC keys only.
func (j *JWKS) Key(ctx context.Context, kid string) (jws.JWK, error) {
	keys, _, err := j.load(ctx)
	if err != nil {
		return jws.JWK{}, err
	}
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return jws.JWK{}, ErrUnknownKey
}

// RSAKey implements [RSAKeySource]. It serves RSA keys only.
func (j *JWKS) RSAKey(ctx context.Context, kid string) (RSAKey, error) {
	_, rsaKeys, err := j.load(ctx)
	if err != nil {
		return RSAKey{}, err
	}
	if k, ok := rsaKeys[kid]; ok {
		return k, nil
	}
	return RSAKey{}, ErrUnknownKey
}

// load returns the current set, fetching it when it is due. One caller
// fetches at a time, without j.mu; the others wait for that fetch or for
// their own context, and none is served a set that is due. A fetched set is
// never changed, so the maps are shared with the callers.
func (j *JWKS) load(ctx context.Context) (map[string]jws.JWK, map[string]RSAKey, error) {
	j.mu.Lock()
	for {
		now := j.clock.Now()
		if !j.attempt.IsZero() && now.Sub(j.attempt) < j.refresh {
			keys, rsaKeys, err := j.keys, j.rsa, j.err
			j.mu.Unlock()
			return keys, rsaKeys, err
		}
		if j.fetching == nil {
			break
		}
		done := j.fetching
		j.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
		j.mu.Lock()
	}
	done := make(chan struct{})
	j.fetching = done
	start := j.clock.Now()
	j.mu.Unlock()
	return j.refetch(ctx, start, done)
}

// refetch runs the one fetch in flight and records its outcome, a failure
// included, as the set of the interval that began at start. A fetch cut short
// because the context of its caller ended is not an outcome: nothing is
// recorded, the caller gets its context's error, and the next caller, a
// waiting one included, fetches. It releases the waiting callers even if the
// fetch panics.
func (j *JWKS) refetch(ctx context.Context, start time.Time, done chan struct{}) (keys map[string]jws.JWK, rsaKeys map[string]RSAKey, err error) {
	err = errors.New("ssf: the JWKS fetch did not complete")
	canceled := false
	defer func() {
		j.mu.Lock()
		if !canceled {
			j.attempt, j.keys, j.rsa, j.err = start, keys, rsaKeys, err
		}
		j.fetching = nil
		close(done)
		j.mu.Unlock()
	}()
	keys, rsaKeys, err = j.fetch(ctx)
	if err != nil && ctx.Err() != nil {
		canceled = true
		return nil, nil, ctx.Err()
	}
	return keys, rsaKeys, err
}

func (j *JWKS) fetch(ctx context.Context) (map[string]jws.JWK, map[string]RSAKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := j.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("ssf: fetching the JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("ssf: the JWKS endpoint answered %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKS+1))
	if err != nil || len(body) > maxJWKS {
		return nil, nil, errors.New("ssf: the JWKS response is unreadable or too large")
	}
	var set map[string]json.RawMessage
	if err := strictjson.Unmarshal(body, strictjson.Limits{}, &set); err != nil {
		return nil, nil, fmt.Errorf("ssf: the JWKS is not a strict JSON object: %w", err)
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(set["keys"], &raws); err != nil || set["keys"] == nil {
		return nil, nil, errors.New("ssf: the JWKS has no keys array")
	}
	keys := map[string]jws.JWK{}
	rsaKeys := map[string]RSAKey{}
	// A kid is ambiguous per key type: two keys of one type under a kid are
	// trusted for neither, and a key of the other type under it is unaffected.
	ambiguousEC, ambiguousRSA := map[string]bool{}, map[string]bool{}
	for _, r := range raws {
		// A JWK is an RSA key or an EC key; one that is neither is skipped.
		if k, err := ParseRSAKey(r); err == nil {
			addUnique(rsaKeys, ambiguousRSA, k.Kid, k)
		} else if k, err := jws.ParseJWK(r); err == nil {
			addUnique(keys, ambiguousEC, k.Kid, k)
		}
	}
	return keys, rsaKeys, nil
}

// addUnique adds k under kid to the keys of one type, unless kid is empty;
// a second key under the same kid removes both and marks the kid ambiguous.
func addUnique[K any](keys map[string]K, ambiguous map[string]bool, kid string, k K) {
	if kid == "" || ambiguous[kid] {
		return
	}
	if _, ok := keys[kid]; ok {
		delete(keys, kid)
		ambiguous[kid] = true
		return
	}
	keys[kid] = k
}

// publicKey returns the ES256 public key of k, after the checks
// [jws.ParseJWK] makes of a published key: a key built in Go is held to the
// same alg and use as one fetched (RFC 7517 sections 4.2, 4.4).
func publicKey(k jws.JWK) (*ecdsa.PublicKey, error) {
	if alg, err := k.Algorithm(); err != nil || alg != jws.AlgES256 {
		return nil, errors.New("not an ES256 key")
	}
	if k.Alg != "" && k.Alg != jws.AlgES256 {
		return nil, fmt.Errorf("alg %q, want %s", k.Alg, jws.AlgES256)
	}
	if k.Use != "" && k.Use != "sig" {
		return nil, fmt.Errorf("use %q, want sig", k.Use)
	}
	return k.PublicKey()
}

// httpsURL checks that raw is an absolute https URL without userinfo or
// fragment.
func httpsURL(raw string) error {
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return err
	case u.Scheme != "https" || u.Host == "":
		return fmt.Errorf("%q is not an https URL", raw)
	case u.User != nil || u.Fragment != "":
		return fmt.Errorf("%q carries userinfo or a fragment", raw)
	}
	return nil
}
