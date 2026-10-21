package graph

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/internal/ascii"
)

// Grant is the token request an acquirer makes.
type Grant string

const (
	// GrantOnBehalfOf is the OBO request of GR-6 [M1].
	GrantOnBehalfOf Grant = "on_behalf_of"
	// GrantClientCredentials is the client credentials request of GR-15
	// [M2].
	GrantClientCredentials Grant = "client_credentials"
)

// TokenAcquirer obtains token B. An adapter is built with exactly one, so
// the type of its configuration leaves no credential to fall back to
// (GR-11). The two implementations of this package use the standard library
// only; the boundary keeps another implementation, such as a Microsoft
// Authentication Library binding, swappable.
type TokenAcquirer interface {
	// Grant is the token request the acquirer makes.
	Grant() Grant
	// ClientID is the application (client) ID that makes it.
	ClientID() string
	// Acquire requests a token. assertion is token A for [GrantOnBehalfOf]
	// and empty for [GrantClientCredentials]. A token endpoint's refusal
	// is an error that matches [ErrNativeDenial], an interaction
	// requirement an [*InteractionRequired], and an endpoint that cannot be
	// reached or answers 5xx wraps [adapter.ErrDependencyUnavailable].
	Acquire(ctx context.Context, assertion string) (Token, error)
}

// Token is token B. Its value is never formatted, logged or encoded; the
// gateway never reads its claims (GR-8, GR-31).
type Token struct {
	value string
	// ExpiresAt is the time of the read plus expires_in.
	ExpiresAt time.Time
	// Scopes is the scope member of the response, split at spaces.
	Scopes []string
}

const redacted = "[redacted]"

// String hides the value.
func (Token) String() string { return redacted }

// GoString hides the value.
func (Token) GoString() string { return redacted }

// MarshalJSON hides the value.
func (Token) MarshalJSON() ([]byte, error) { return json.Marshal(redacted) }

// Authorize sets the Authorization field of r to the token as a bearer
// token, the one way the value leaves the token.
func (t Token) Authorize(r *http.Request) { r.Header.Set("Authorization", "Bearer "+t.value) }

// usable reports whether the token has a value and has not expired at now.
func (t Token) usable(now time.Time) bool { return t.value != "" && now.Before(t.ExpiresAt) }

// ErrNativeDenial is a native denial after admission: a refused token
// request, a token response that fails GR-8, or Graph refusing the
// downstream request. It is final and never followed by another credential
// (GR-3, GR-11, GR-30).
var ErrNativeDenial = errors.New("graph: native denial")

// InteractionRequired is the token endpoint's answer to an OBO request that
// needs the user's interaction, such as multifactor authentication under a
// Conditional Access policy [M1]. The gateway answers 401 with Challenge in
// WWW-Authenticate (GR-10). It matches [ErrNativeDenial].
type InteractionRequired struct {
	// Challenge is the WWW-Authenticate value.
	Challenge string
}

func (e *InteractionRequired) Error() string {
	return "graph: the token endpoint requires user interaction"
}

// Is matches [ErrNativeDenial].
func (e *InteractionRequired) Is(target error) bool { return target == ErrNativeDenial }

// tokenRefused is a token endpoint error answer.
type tokenRefused struct {
	code   string
	codes  []int
	status int
}

func (e *tokenRefused) Error() string {
	return fmt.Sprintf("graph: the token endpoint refused the request: HTTP %d, error %q, codes %v", e.status, e.code, e.codes)
}

func (e *tokenRefused) Is(target error) bool { return target == ErrNativeDenial }

// Certificate is a certificate credential: the private key of the
// certificate registered for the application and the SHA-256 thumbprint of
// its DER encoding, the x5t#S256 of the assertion header [M12].
type Certificate struct {
	Key        *rsa.PrivateKey
	Thumbprint [32]byte
}

// NewCertificate returns the credential of a DER certificate and its key.
func NewCertificate(der []byte, key *rsa.PrivateKey) (*Certificate, error) {
	if len(der) == 0 || key == nil || key.N.BitLen() < 2048 {
		return nil, errors.New("graph: a certificate credential needs the DER certificate and an RSA key of at least 2048 bits")
	}
	return &Certificate{Key: key, Thumbprint: sha256.Sum256(der)}, nil
}

// ClientAuth is the client authentication of a token request: a client
// secret or a certificate assertion, exactly one (GR-6, GR-15).
type ClientAuth struct {
	Secret      string
	Certificate *Certificate
}

// AcquirerConfig configures a token acquirer.
type AcquirerConfig struct {
	// Tenant is the pinned tenant ID, a GUID.
	Tenant string
	// ClientID is the application (client) ID, a GUID.
	ClientID string
	// Auth is the client authentication.
	Auth ClientAuth
	// Scope is the scope of the OBO request. Empty is [ScopeMailRead]. An
	// executor of another resource, such as Azure Resource Manager, names
	// its own scope and then gives AcceptedScopes: the spellings its
	// response may use are the deployment's to state. Ignored for client
	// credentials.
	Scope string
	// AcceptedScopes are the spellings of the requested permission that an
	// OBO response's scope may use (GR-8, probe P3). Nil is ScopeMailRead
	// and "Mail.Read" for the default scope, and required for another.
	// Ignored for client credentials.
	AcceptedScopes []string
	// HTTPClient sends the token requests. Nil is a client with TLS
	// verification and no proxy. Redirects are never followed.
	HTTPClient *http.Client
	// Timeout bounds each request. Zero is [DefaultTimeout].
	Timeout time.Duration
	// Clock is the source of the current time. Required.
	Clock clock.Clock
}

// acquirer is the token request machinery shared by both grants.
type acquirer struct {
	cfg      AcquirerConfig
	client   *http.Client
	endpoint string
}

func newAcquirer(cfg AcquirerConfig) (*acquirer, error) {
	switch {
	case cfg.Clock == nil:
		return nil, errors.New("graph: acquirer: no clock")
	case !guidPattern.MatchString(cfg.Tenant) || !guidPattern.MatchString(cfg.ClientID):
		return nil, errors.New("graph: acquirer: the tenant and the client ID are lower-case GUIDs")
	case (cfg.Auth.Secret == "") == (cfg.Auth.Certificate == nil):
		return nil, errors.New("graph: acquirer: exactly one of a client secret and a certificate")
	case cfg.Auth.Certificate != nil && (cfg.Auth.Certificate.Key == nil || cfg.Auth.Certificate.Key.N.BitLen() < 2048):
		return nil, errors.New("graph: acquirer: the certificate key is not an RSA key of at least 2048 bits")
	case cfg.Timeout < 0:
		return nil, errors.New("graph: acquirer: negative timeout")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	switch {
	case cfg.Scope != "" && cfg.Scope != ScopeMailRead && len(cfg.AcceptedScopes) == 0:
		return nil, errors.New("graph: acquirer: a scope other than Mail.Read needs its accepted response scopes")
	case cfg.Scope == "":
		cfg.Scope = ScopeMailRead
	}
	if cfg.AcceptedScopes == nil {
		cfg.AcceptedScopes = []string{ScopeMailRead, "Mail.Read"}
	}
	return &acquirer{cfg: cfg, client: noRedirect(cfg.HTTPClient), endpoint: LoginOrigin + "/" + cfg.Tenant + "/oauth2/v2.0/token"}, nil
}

// OnBehalfOf is the OBO acquirer of the gateway application (GR-5, GR-6).
type OnBehalfOf struct{ a *acquirer }

// NewOnBehalfOf returns the OBO acquirer of cfg.
func NewOnBehalfOf(cfg AcquirerConfig) (*OnBehalfOf, error) {
	a, err := newAcquirer(cfg)
	if err != nil {
		return nil, err
	}
	return &OnBehalfOf{a}, nil
}

// Grant is [GrantOnBehalfOf].
func (o *OnBehalfOf) Grant() Grant { return GrantOnBehalfOf }

// ClientID is the gateway application.
func (o *OnBehalfOf) ClientID() string { return o.a.cfg.ClientID }

// Acquire exchanges token A for token B: grant_type
// urn:ietf:params:oauth:grant-type:jwt-bearer, requested_token_use
// on_behalf_of, the one configured scope (Mail.Read of Graph unless
// configured otherwise), with no offline_access [M1]. The response's scope
// must name only accepted spellings of it (GR-8).
func (o *OnBehalfOf) Acquire(ctx context.Context, assertion string) (Token, error) {
	if assertion == "" {
		return Token{}, fmt.Errorf("graph: OBO without token A: %w", adapter.ErrContextMismatch)
	}
	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":           {assertion},
		"scope":               {o.a.cfg.Scope},
		"requested_token_use": {"on_behalf_of"},
	}
	t, err := o.a.request(ctx, form)
	if err != nil {
		return Token{}, err
	}
	if len(t.Scopes) == 0 {
		return Token{}, fmt.Errorf("graph: the OBO response has no scope (GR-8): %w", ErrNativeDenial)
	}
	for _, s := range t.Scopes {
		if !slices.Contains(o.a.cfg.AcceptedScopes, s) {
			return Token{}, fmt.Errorf("graph: the OBO response's scope names a permission other than the requested one (GR-8): %w", ErrNativeDenial)
		}
	}
	return t, nil
}

// ClientCredentials is the client credentials acquirer of an executor
// application or of the auditor identity (GR-15, GR-17).
type ClientCredentials struct{ a *acquirer }

// NewClientCredentials returns the client credentials acquirer of cfg.
func NewClientCredentials(cfg AcquirerConfig) (*ClientCredentials, error) {
	a, err := newAcquirer(cfg)
	if err != nil {
		return nil, err
	}
	return &ClientCredentials{a}, nil
}

// Grant is [GrantClientCredentials].
func (c *ClientCredentials) Grant() Grant { return GrantClientCredentials }

// ClientID is the application.
func (c *ClientCredentials) ClientID() string { return c.a.cfg.ClientID }

// Acquire requests an app-only token with scope
// https://graph.microsoft.com/.default [M2, M3]. The documented response has
// no scope member, so the grants are not observed here but by the preflight
// (GR-15, GR-16).
func (c *ClientCredentials) Acquire(ctx context.Context, assertion string) (Token, error) {
	if assertion != "" {
		return Token{}, fmt.Errorf("graph: a client credentials request carries no user assertion: %w", adapter.ErrContextMismatch)
	}
	return c.a.request(ctx, url.Values{"grant_type": {"client_credentials"}, "scope": {ScopeGraphDefault}})
}

// request posts the form with the client authentication and reads the
// answer.
func (a *acquirer) request(ctx context.Context, form url.Values) (Token, error) {
	if err := ctx.Err(); err != nil {
		return Token{}, fmt.Errorf("graph: token request: %w: %w", adapter.ErrDependencyUnavailable, err)
	}
	form.Set("client_id", a.cfg.ClientID)
	if a.cfg.Auth.Secret != "" {
		form.Set("client_secret", a.cfg.Auth.Secret)
	} else {
		jwt, err := a.clientAssertion()
		if err != nil {
			return Token{}, err
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", jwt)
	}
	ctx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, fmt.Errorf("graph: token request: %w", adapter.ErrDependencyUnavailable)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "")
	resp, err := a.client.Do(req)
	if err != nil {
		return Token{}, fmt.Errorf("graph: the token endpoint cannot be reached: %w", adapter.ErrDependencyUnavailable)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10+1))
	if err != nil || len(raw) > 64<<10 {
		return Token{}, fmt.Errorf("graph: the token endpoint's answer cannot be read: %w", adapter.ErrDependencyUnavailable)
	}
	if resp.StatusCode == http.StatusOK {
		return a.tokenOf(raw)
	}
	if resp.StatusCode >= 500 || resp.StatusCode < 400 {
		return Token{}, fmt.Errorf("graph: the token endpoint answered %d: %w", resp.StatusCode, adapter.ErrDependencyUnavailable)
	}
	var e struct {
		Error  string `json:"error"`
		Codes  []int  `json:"error_codes"`
		Claims string `json:"claims"`
	}
	_ = json.Unmarshal(raw, &e)
	if e.Error == "interaction_required" || e.Claims != "" {
		return Token{}, &InteractionRequired{Challenge: a.challenge(e.Error, e.Claims)}
	}
	return Token{}, &tokenRefused{code: e.Error, codes: e.Codes, status: resp.StatusCode}
}

// challenge is the WWW-Authenticate value of GR-10: with a claims value,
// the claims challenge of [M11] (realm the tenant, authorization_uri the
// tenant's authorize endpoint, error insufficient_claims, claims in base64);
// without one, the error of the token endpoint.
func (a *acquirer) challenge(code, claims string) string {
	if claims == "" {
		if code == "" {
			code = "interaction_required"
		}
		return `Bearer error="` + quotable(code) + `"`
	}
	return `Bearer realm="` + a.cfg.Tenant + `", authorization_uri="` + LoginOrigin + "/" + a.cfg.Tenant + `/oauth2/v2.0/authorize", error="insufficient_claims", claims="` +
		base64.StdEncoding.EncodeToString([]byte(claims)) + `"`
}

// quotable keeps the printable ASCII characters of s other than the quote
// and the backslash, so that the value is one quoted string.
func quotable(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= 0x20 && c <= 0x7e && c != '"' && c != '\\' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// tokenOf reads a success answer: token_type Bearer, an access_token, a
// positive expires_in, and the scope member when present (GR-8). The
// documents show both "Bearer" and "bearer" for the type [M1, M2], so it is
// compared without regard to case.
func (a *acquirer) tokenOf(raw []byte) (Token, error) {
	var r struct {
		TokenType   string          `json:"token_type"`
		AccessToken string          `json:"access_token"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
		Scope       *string         `json:"scope"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return Token{}, fmt.Errorf("graph: the token response is not JSON (GR-8): %w", ErrNativeDenial)
	}
	life, err := strconv.ParseInt(strings.Trim(string(r.ExpiresIn), `"`), 10, 64)
	switch {
	case !ascii.EqualFold(r.TokenType, "Bearer"):
		return Token{}, fmt.Errorf("graph: the token type is not Bearer (GR-8): %w", ErrNativeDenial)
	case r.AccessToken == "" || strings.ContainsAny(r.AccessToken, " \t\r\n"):
		return Token{}, fmt.Errorf("graph: the token response has no usable access_token (GR-8): %w", ErrNativeDenial)
	case err != nil || life <= 0:
		return Token{}, fmt.Errorf("graph: the token response has no positive expires_in (GR-8): %w", ErrNativeDenial)
	}
	t := Token{value: r.AccessToken, ExpiresAt: a.cfg.Clock.Now().Add(time.Duration(life) * time.Second)}
	if r.Scope != nil {
		t.Scopes = strings.Fields(*r.Scope)
	}
	return t, nil
}

// clientAssertion is the certificate assertion of [M12]: header alg PS256,
// typ JWT and x5t#S256; claims aud the token endpoint, iss and sub the
// client ID, a random jti, nbf and iat now, exp five minutes later; signed
// with RSASSA-PSS and SHA-256.
func (a *acquirer) clientAssertion() (string, error) {
	cert := a.cfg.Auth.Certificate
	now := a.cfg.Clock.Now().Unix()
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("graph: client assertion: %w", adapter.ErrDependencyUnavailable)
	}
	header, _ := json.Marshal(map[string]string{"alg": "PS256", "typ": "JWT", "x5t#S256": base64.RawURLEncoding.EncodeToString(cert.Thumbprint[:])})
	claims, _ := json.Marshal(map[string]any{
		"aud": a.endpoint, "iss": a.cfg.ClientID, "sub": a.cfg.ClientID, "jti": hex.EncodeToString(jti),
		"nbf": now, "iat": now, "exp": now + 300,
	})
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPSS(rand.Reader, cert.Key, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return "", fmt.Errorf("graph: client assertion: %w", adapter.ErrDependencyUnavailable)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
