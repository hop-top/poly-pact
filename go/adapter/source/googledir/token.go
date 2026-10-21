package googledir

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/internal/ascii"
)

// TokenSource supplies the OAuth 2.0 access token a [Client] presents to one
// Google API. An implementation is safe for concurrent use.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

const (
	// DefaultTokenURL is the token endpoint of the service account flow.
	DefaultTokenURL = "https://oauth2.googleapis.com/token"
	// assertionLife is the lifetime of the signed assertion: the page caps
	// it at one hour after iat.
	assertionLife = time.Hour
	// tokenMargin is how long before its expiry a token is replaced.
	tokenMargin  = 60 * time.Second
	maxTokenBody = 64 << 10
)

// ServiceAccountConfig configures a [ServiceAccount].
type ServiceAccountConfig struct {
	// Key is the service account key file (JSON) with its RSA private key.
	Key []byte
	// Subject is the user the service account acts as under domain-wide
	// delegation (the sub claim). Directory calls need a user with the
	// administrator privilege for the data read.
	Subject string
	// Scopes are the scopes of the token. A token carries the scopes of one
	// API only, so that a leaked Directory token cannot read Cloud Identity
	// and the reverse. Each scope must also be authorized for the service
	// account's client ID in the Admin console.
	Scopes []string
	// TokenURL is the token endpoint; DefaultTokenURL when empty. It must be
	// https, and it is never taken from the key file.
	TokenURL string
	// HTTP is the client used for the token request; a client with a 30 s
	// timeout when nil.
	HTTP *http.Client
	// Clock is the only source of the current time.
	Clock clock.Clock
}

// ServiceAccount is a [TokenSource] for a Google service account with
// domain-wide delegation: it signs a JWT assertion with the account's key,
// exchanges it at the token endpoint with the jwt-bearer grant type (RFC
// 7523 section 2.1), and reuses the access token until shortly before it
// expires.
type ServiceAccount struct {
	cfg   ServiceAccountConfig
	email string
	keyID string
	key   *rsa.PrivateKey
	http  *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

// NewServiceAccount returns a ServiceAccount for cfg.
func NewServiceAccount(cfg ServiceAccountConfig) (*ServiceAccount, error) {
	var kf struct {
		Type       string `json:"type"`
		ClientMail string `json:"client_email"`
		PrivateKey string `json:"private_key"`
		KeyID      string `json:"private_key_id"`
	}
	if len(cfg.Key) == 0 {
		return nil, errors.New("googledir: no service account key")
	}
	if err := json.Unmarshal(cfg.Key, &kf); err != nil {
		return nil, fmt.Errorf("googledir: the service account key is not JSON: %w", err)
	}
	switch {
	case kf.Type != "service_account":
		return nil, errors.New("googledir: the key file is not a service account key")
	case kf.ClientMail == "":
		return nil, errors.New("googledir: the key file has no client_email")
	case cfg.Subject == "":
		return nil, errors.New("googledir: no delegated subject")
	case len(cfg.Scopes) == 0:
		return nil, errors.New("googledir: no scope")
	case cfg.Clock == nil:
		return nil, errors.New("googledir: no clock")
	}
	for _, s := range cfg.Scopes {
		if s == "" || strings.ContainsAny(s, " \t\r\n") {
			return nil, fmt.Errorf("googledir: %q is not a scope", s)
		}
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = DefaultTokenURL
	}
	if err := requireHTTPS(cfg.TokenURL); err != nil {
		return nil, fmt.Errorf("googledir: token URL: %w", err)
	}
	block, _ := pem.Decode([]byte(kf.PrivateKey))
	if block == nil {
		return nil, errors.New("googledir: the private key is not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("googledir: the private key: %w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("googledir: the private key is not an RSA key")
	}
	hc := cfg.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &ServiceAccount{cfg: cfg, email: kf.ClientMail, keyID: kf.KeyID, key: rk, http: noRedirect(hc)}, nil
}

// requireHTTPS refuses a URL that is not an absolute https URL with a host.
func requireHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return fmt.Errorf("%q is not an https URL", raw)
	}
	return nil
}

// noRedirect returns a copy of c that does not follow redirects: a bearer
// token or an assertion is sent to the configured endpoint only.
func noRedirect(c *http.Client) *http.Client {
	cp := *c
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cp
}

// Token returns an access token for the configured scopes and subject.
func (s *ServiceAccount) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Clock.Now()
	if s.token != "" && now.Before(s.expires.Add(-tokenMargin)) {
		return s.token, nil
	}
	assertion, err := s.assertion(now)
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("googledir: token endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenBody+1))
	if err != nil || len(body) > maxTokenBody {
		return "", errors.New("googledir: token endpoint: the reply cannot be read")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("googledir: token endpoint: status %d", resp.StatusCode)
	}
	var m map[string]json.RawMessage
	if err := strictjson.Unmarshal(body, strictjson.Limits{}, &m); err != nil {
		return "", fmt.Errorf("googledir: token endpoint: %w", err)
	}
	var tok, typ string
	var life int64
	if err := member(m, "access_token", &tok); err != nil {
		return "", fmt.Errorf("googledir: token endpoint: %w", err)
	}
	if err := member(m, "token_type", &typ); err != nil {
		return "", fmt.Errorf("googledir: token endpoint: %w", err)
	}
	if err := member(m, "expires_in", &life); err != nil {
		return "", fmt.Errorf("googledir: token endpoint: %w", err)
	}
	if tok == "" || !ascii.EqualFold(typ, "Bearer") || life <= 0 {
		return "", errors.New("googledir: token endpoint: the reply is not a bearer token with a lifetime")
	}
	// The lifetime counts from the request, not from the reply.
	s.token, s.expires = tok, now.Add(time.Duration(life)*time.Second)
	return tok, nil
}

// assertion is the signed JWT of the service account page: header RS256 and
// JWT, claims iss, sub, scope, aud, iat and exp.
func (s *ServiceAccount) assertion(now time.Time) (string, error) {
	hdr := map[string]string{"alg": "RS256", "typ": "JWT"}
	if s.keyID != "" {
		hdr["kid"] = s.keyID
	}
	claims := map[string]any{
		"iss": s.email, "sub": s.cfg.Subject, "scope": strings.Join(s.cfg.Scopes, " "),
		"aud": s.cfg.TokenURL, "iat": now.Unix(), "exp": now.Add(assertionLife).Unix(),
	}
	h, _ := json.Marshal(hdr)
	c, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("googledir: signing the assertion: %w", err)
	}
	return signing + "." + enc.EncodeToString(sig), nil
}
