package oauth_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapters/memory"
)

// oauthModel names the native state of the OAuth cases
// (spec/v1.0/fixtures/adapters/oauth/README.md).
const oauthModel = "oauth/1"

// oauthState is the native state of an OAuth case.
type oauthState struct {
	Model              string               `json:"model"`
	Gateway            memory.Gateway       `json:"gateway"`
	Entries            []entryState         `json:"entries"`
	Routes             []routeState         `json:"routes"`
	Keys               []keyState           `json:"keys"`
	Tokens             []tokenState         `json:"tokens"`
	Authorization      []string             `json:"authorization"`
	SenderProof        *senderProofState    `json:"sender_proof"`
	Introspection      []introspectionState `json:"introspection"`
	Discovery          []discoveryState     `json:"discovery"`
	KeySets            []keySetState        `json:"key_sets"`
	Prefetch           *prefetchState       `json:"prefetch"`
	Outages            []string             `json:"outages"`
	Enrollments        []memory.Enrollment  `json:"enrollments"`
	Policy             []memory.PolicyRule  `json:"policy"`
	UnavailableSources []string             `json:"unavailable_sources"`
}

// entryState is an issuer entry (profile OAUTH-5).
type entryState struct {
	ID                    string   `json:"id"`
	Form                  string   `json:"form"`
	Issuer                string   `json:"issuer"`
	Tenant                string   `json:"tenant"`
	Audiences             []string `json:"audiences"`
	Clients               []string `json:"clients"`
	SenderConstraint      string   `json:"sender_constraint"`
	LifetimeSeconds       int64    `json:"lifetime_seconds"`
	IntrospectionEndpoint string   `json:"introspection_endpoint"`
	GatewayClientID       string   `json:"gateway_client_id"`
	GatewayClientSecret   string   `json:"gateway_client_secret"`
	ResourceBinding       string   `json:"resource_binding"`
	CacheSeconds          int64    `json:"cache_seconds"`
	Algorithms            []string `json:"algorithms"`
	KeyRefreshSeconds     int64    `json:"key_refresh_seconds"`
	KeyMaxAgeSeconds      int64    `json:"key_max_age_seconds"`
	TrustedOrigins        []string `json:"trusted_origins"`
}

// routeState names the issuer entry and the required scope of a route.
type routeState struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Entry  string `json:"entry"`
	Scope  string `json:"scope"`
}

type keyState struct {
	Ref  string `json:"ref"`
	Bits int    `json:"bits"`
}

type tokenState struct {
	Ref    string    `json:"ref"`
	Opaque string    `json:"opaque"`
	JWS    *jwsState `json:"jws"`
	JWE    bool      `json:"jwe"`
}

type jwsState struct {
	Header    map[string]any `json:"header"`
	Claims    map[string]any `json:"claims"`
	Key       string         `json:"key"`
	Signature string         `json:"signature"`
}

type senderProofState struct {
	Kind string `json:"kind"`
}

type introspectionState struct {
	Endpoint string          `json:"endpoint"`
	Token    string          `json:"token"`
	Status   int             `json:"status"`
	Response json.RawMessage `json:"response"`
	Body     *string         `json:"body"`
	Behavior string          `json:"behavior"`
}

type discoveryState struct {
	Entry    string          `json:"entry"`
	URL      string          `json:"url"`
	Status   int             `json:"status"`
	Document json.RawMessage `json:"document"`
}

type keySetState struct {
	Entry   string            `json:"entry"`
	URL     string            `json:"url"`
	Status  int               `json:"status"`
	Keys    []memberState     `json:"keys"`
	Headers map[string]string `json:"headers"`
}

type memberState struct {
	Key    string `json:"key"`
	KID    string `json:"kid"`
	KTY    string `json:"kty"`
	Use    string `json:"use"`
	Alg    string `json:"alg"`
	Issuer string `json:"issuer"`
}

type prefetchState struct {
	Entry   string        `json:"entry"`
	At      int64         `json:"at"`
	KeySets []keySetState `json:"key_sets"`
}

// modelOf returns the model member of a native state.
func modelOf(raw json.RawMessage) (string, error) {
	var m struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", fmt.Errorf("native_state: %w", err)
	}
	return m.Model, nil
}

// world realizes an oauth/1 state: the RSA keys, the minted tokens, and the
// authorization server, discovery documents and key sets behind an in-memory
// HTTP transport.
type world struct {
	st     oauthState
	hooks  *adaptertest.Hooks
	tokens map[string]string

	mu          sync.Mutex
	prefetching bool

	// attachProof, when set, attaches the native verifier's report to a
	// request through the adapter's authenticated context.
	attachProof func(r *http.Request, kind string) *http.Request
}

// loadWorld parses an oauth/1 state strictly and mints its tokens.
func loadWorld(raw json.RawMessage, hooks *adaptertest.Hooks) (*world, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var st oauthState
	if err := dec.Decode(&st); err != nil {
		return nil, fmt.Errorf("oauth/1 state: %w", err)
	}
	if st.Model != oauthModel {
		return nil, fmt.Errorf("model %q is not %s", st.Model, oauthModel)
	}
	if hooks == nil {
		hooks = &adaptertest.Hooks{}
	}
	w := &world{st: st, hooks: hooks, tokens: map[string]string{}}
	for _, t := range st.Tokens {
		text, err := w.mint(t)
		if err != nil {
			return nil, fmt.Errorf("token %s: %w", t.Ref, err)
		}
		w.tokens[t.Ref] = text
	}
	return w, nil
}

// rsaKeys caches the keys of every ref and size for the test binary: RSA key
// generation is slow, and a case only needs a key that is the same within it.
var rsaKeys = struct {
	sync.Mutex
	m map[string]*rsa.PrivateKey
}{m: map[string]*rsa.PrivateKey{}}

// key returns the RSA key of ref, generated on first use.
func (w *world) key(ref string) (*rsa.PrivateKey, error) {
	bits := 0
	for _, k := range w.st.Keys {
		if k.Ref == ref {
			bits = k.Bits
		}
	}
	if bits == 0 {
		return nil, fmt.Errorf("no key %q", ref)
	}
	id := fmt.Sprintf("%s/%d", ref, bits)
	rsaKeys.Lock()
	defer rsaKeys.Unlock()
	if k, ok := rsaKeys.m[id]; ok {
		return k, nil
	}
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	rsaKeys.m[id] = k
	return k, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// publicJWK is the RSA public JWK of a key: kty, n and e.
func publicJWK(k *rsa.PublicKey) map[string]any {
	return map[string]any{"kty": "RSA", "n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes())}
}

// mint returns the text of a token.
func (w *world) mint(t tokenState) (string, error) {
	switch {
	case t.Opaque != "":
		return t.Opaque, nil
	case t.JWE:
		segs := make([]string, 5)
		segs[0] = b64([]byte(`{"alg":"RSA-OAEP-256","enc":"A256GCM","typ":"JWT"}`))
		for i := 1; i < 5; i++ {
			b := make([]byte, 24)
			if _, err := rand.Read(b); err != nil {
				return "", err
			}
			segs[i] = b64(b)
		}
		return strings.Join(segs, "."), nil
	case t.JWS != nil:
		return w.mintJWS(*t.JWS)
	}
	return "", errors.New("a token is opaque, a jws or a jwe")
}

func (w *world) mintJWS(j jwsState) (string, error) {
	key, err := w.key(j.Key)
	if err != nil {
		return "", err
	}
	header := map[string]any{}
	for k, v := range j.Header {
		if s, ok := v.(string); ok && strings.HasPrefix(s, "@public:") {
			pk, err := w.key(strings.TrimPrefix(s, "@public:"))
			if err != nil {
				return "", err
			}
			v = publicJWK(&pk.PublicKey)
		}
		header[k] = v
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(j.Claims)
	if err != nil {
		return "", err
	}
	input := b64(hb) + "." + b64(cb)
	digest := sha256.Sum256([]byte(input))
	var sig []byte
	switch j.Signature {
	case "", "valid", "altered":
		alg, _ := header["alg"].(string)
		switch alg {
		case "RS256":
			sig, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		case "PS256":
			sig, err = rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		default:
			return "", fmt.Errorf("the harness signs RS256 and PS256, not %q", alg)
		}
		if err != nil {
			return "", err
		}
		if j.Signature == "altered" {
			sig[len(sig)/2] ^= 0x01
		}
	case "empty":
	case "hs256-public-key":
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return "", err
		}
		m := hmac.New(sha256.New, der)
		m.Write([]byte(input))
		sig = m.Sum(nil)
	default:
		return "", fmt.Errorf("signature %q", j.Signature)
	}
	return input + "." + b64(sig), nil
}

// Credential attaches the token of ref as the Authorization field lines of
// the state, and the native verifier's report when the state has one.
func (w *world) Credential(r *http.Request, ref string) error {
	text, ok := w.tokens[ref]
	if !ok {
		return fmt.Errorf("no token %q", ref)
	}
	lines := w.st.Authorization
	if len(lines) == 0 {
		lines = []string{"Bearer {token}"}
	}
	for _, l := range lines {
		r.Header.Add("Authorization", strings.ReplaceAll(l, "{token}", text))
	}
	if w.st.SenderProof != nil {
		if w.attachProof == nil {
			return errors.New("the state has a sender proof and the factory attaches none")
		}
		*r = *w.attachProof(r, w.st.SenderProof.Kind)
	}
	return nil
}

// commonState returns the common/1 state of the enrollments and the policy of
// the world, for the reference enrollment source and the permission lookup.
func (w *world) commonState() memory.State {
	g := w.st.Gateway
	if g.HeaderAllowlist == nil {
		g.HeaderAllowlist = []string{}
	}
	return memory.State{
		Model:              memory.Model,
		Gateway:            g,
		Enrollments:        w.st.Enrollments,
		Policy:             w.st.Policy,
		UnavailableSources: w.st.UnavailableSources,
	}
}

// client is the HTTP client the adapter uses: every request goes to the
// world's transport, never to the network.
func (w *world) client() *http.Client {
	return &http.Client{Transport: w}
}

// fire records a hook unless the harness is prefetching the key set.
func (w *world) fire(name string) {
	w.mu.Lock()
	pre := w.prefetching
	w.mu.Unlock()
	if !pre {
		w.hooks.Fire(name)
	}
}

// setPrefetching switches the transport to the state of the prefetch: its
// key sets, no outages and no hooks.
func (w *world) setPrefetching(on bool) {
	w.mu.Lock()
	w.prefetching = on
	w.mu.Unlock()
}

func (w *world) isPrefetching() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.prefetching
}

// errOutage is the transport error of an unreachable source.
var errOutage = errors.New("harness: connection refused")

func respond(r *http.Request, status int, contentType string, body []byte) *http.Response {
	return &http.Response{
		StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:        http.Header{"Content-Type": {contentType}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)), Request: r,
	}
}

// RoundTrip serves the configured endpoints of the state. A URL that is not
// one of them fires the hook fetch-untrusted.
func (w *world) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		defer func() { _ = r.Body.Close() }()
	}
	target := r.URL.String()
	if !w.isPrefetching() {
		for _, o := range w.st.Outages {
			if o == target {
				return nil, errOutage
			}
		}
	}
	for _, e := range w.st.Entries {
		if e.IntrospectionEndpoint != "" && e.IntrospectionEndpoint == target {
			w.fire("introspect:" + e.ID)
			return w.introspect(r, e)
		}
	}
	for _, d := range w.st.Discovery {
		if d.URL == target {
			w.fire("discover:" + d.Entry)
			return respond(r, d.Status, "application/json", d.Document), nil
		}
	}
	sets := w.st.KeySets
	if w.isPrefetching() && w.st.Prefetch != nil && w.st.Prefetch.KeySets != nil {
		sets = w.st.Prefetch.KeySets
	}
	for _, s := range sets {
		if s.URL == target {
			w.fire("fetch-keys:" + s.Entry)
			body, err := w.jwks(s)
			if err != nil {
				return nil, err
			}
			resp := respond(r, s.Status, "application/json", body)
			for name, v := range s.Headers {
				resp.Header.Set(name, v)
			}
			return resp, nil
		}
	}
	w.fire("fetch-untrusted")
	return respond(r, http.StatusNotFound, "text/plain", []byte("not found")), nil
}

// jwks writes the JWK Set of a key set.
func (w *world) jwks(s keySetState) ([]byte, error) {
	keys := []map[string]any{}
	for _, m := range s.Keys {
		k, err := w.key(m.Key)
		if err != nil {
			return nil, err
		}
		j := publicJWK(&k.PublicKey)
		j["kty"] = m.KTY
		j["kid"] = m.KID
		if m.Use != "" {
			j["use"] = m.Use
		}
		if m.Alg != "" {
			j["alg"] = m.Alg
		}
		if m.Issuer != "" {
			j["issuer"] = m.Issuer
		}
		keys = append(keys, j)
	}
	return json.Marshal(map[string]any{"keys": keys})
}

// introspect is the authorization server's introspection endpoint (RFC 7662
// section 2): it requires POST, a form body with the token and the hint
// access_token, and the gateway's client_secret_basic credentials; anything
// else is HTTP 400 or 401. An unknown token is active false.
func (w *world) introspect(r *http.Request, e entryState) (*http.Response, error) {
	bad := func(status int) (*http.Response, error) {
		return respond(r, status, "application/json", []byte(`{"error":"invalid_request"}`)), nil
	}
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return bad(http.StatusBadRequest)
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		return bad(http.StatusUnauthorized)
	}
	u, err1 := url.QueryUnescape(user)
	p, err2 := url.QueryUnescape(pass)
	if err1 != nil || err2 != nil || u != e.GatewayClientID || p != e.GatewayClientSecret {
		return bad(http.StatusUnauthorized)
	}
	if r.Body == nil {
		return bad(http.StatusBadRequest)
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	form, err := url.ParseQuery(string(raw))
	if err != nil || len(form["token"]) != 1 || form.Get("token_type_hint") != "access_token" {
		return bad(http.StatusBadRequest)
	}
	token := form.Get("token")
	for _, rec := range w.st.Introspection {
		if rec.Endpoint != e.IntrospectionEndpoint || rec.Token != token {
			continue
		}
		if rec.Behavior == "timeout" {
			select {
			case <-r.Context().Done():
				return nil, r.Context().Err()
			case <-time.After(10 * time.Second):
				return nil, errors.New("harness: the adapter set no timeout")
			}
		}
		body := []byte(rec.Response)
		if rec.Body != nil {
			body = []byte(*rec.Body)
		}
		return respond(r, rec.Status, "application/json", body), nil
	}
	return respond(r, http.StatusOK, "application/json", []byte(`{"active":false}`)), nil
}

// prefetchAt is the instant of the state's prefetch, if any.
func (w *world) prefetchAt() (string, time.Time, bool) {
	if w.st.Prefetch == nil {
		return "", time.Time{}, false
	}
	return w.st.Prefetch.Entry, time.Unix(w.st.Prefetch.At, 0), true
}

// withPrefetch runs fn with the transport in its prefetch state.
func (w *world) withPrefetch(ctx context.Context, fn func(context.Context) error) error {
	w.setPrefetching(true)
	defer w.setPrefetching(false)
	return fn(ctx)
}
