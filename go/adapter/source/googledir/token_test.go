package googledir_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapter/source/googledir"
	"hop.top/pact-go/core/clock"
)

func saFor(t *testing.T, f *fakeGoogle, clk clock.Clock, scopes ...string) *googledir.ServiceAccount {
	t.Helper()
	sa, err := googledir.NewServiceAccount(googledir.ServiceAccountConfig{
		Key: testKey(t), Subject: fakeSubject, Scopes: scopes,
		TokenURL: f.srv.URL + "/token", HTTP: f.srv.Client(), Clock: clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	return sa
}

var dirScopes = strings.Fields(dirScope)

// The assertion follows the service account page: header RS256/JWT, claims
// iss (the service account), sub (the delegated user), scope (space
// delimited), aud (the token endpoint), iat and an exp no later than an hour
// after iat, signed with the account's key; it is posted with the
// jwt-bearer grant type.
func TestServiceAccountAssertion(t *testing.T) {
	now := time.Unix(1792080000, 0)
	clk := clock.NewFake(now)
	f := newFakeGoogle(t, clk, &adaptertest.Hooks{})
	sa := saFor(t, f, clk, dirScopes...)
	tok, err := sa.Token(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "directory-token-1" {
		t.Fatalf("token %q", tok)
	}
	if len(f.assertions) != 1 {
		t.Fatalf("%d assertions", len(f.assertions))
	}
	parts := strings.Split(f.assertions[0], ".")
	var hdr map[string]string
	var cl struct {
		Iss, Sub, Scope, Aud string
		Iat, Exp             int64
	}
	for i, dst := range []any{&hdr, &cl} {
		raw, err := b64(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			t.Fatal(err)
		}
	}
	if hdr["alg"] != "RS256" || hdr["typ"] != "JWT" {
		t.Errorf("header %v", hdr)
	}
	if cl.Iss != fakeClientEmail || cl.Sub != fakeSubject || cl.Scope != dirScope || cl.Aud != f.srv.URL+"/token" {
		t.Errorf("claims %+v", cl)
	}
	if cl.Iat != now.Unix() || cl.Exp != now.Unix()+3600 {
		t.Errorf("iat %d exp %d, want %d and %d", cl.Iat, cl.Exp, now.Unix(), now.Unix()+3600)
	}
	sig, _ := b64(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&keyRSA.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Errorf("signature: %v", err)
	}
}

// A token is reused for its lifetime less a margin and fetched again after.
func TestTokenReuseAndExpiry(t *testing.T) {
	clk := clock.NewFake(time.Unix(1792080000, 0))
	f := newFakeGoogle(t, clk, &adaptertest.Hooks{})
	sa := saFor(t, f, clk, dirScopes...)
	get := func() string {
		tok, err := sa.Token(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	first := get()
	clk.Set(time.Unix(1792080000+3500, 0))
	if got := get(); got != first || len(f.assertions) != 1 {
		t.Fatalf("token fetched again at 3500 s: %q, %d assertions", got, len(f.assertions))
	}
	clk.Set(time.Unix(1792080000+3541, 0)) // inside the 60 s margin of expires_in 3600
	if got := get(); got == first || len(f.assertions) != 2 {
		t.Fatalf("token not renewed inside the margin: %q, %d assertions", got, len(f.assertions))
	}
}

func TestTokenEndpointFailures(t *testing.T) {
	clk := clock.NewFake(time.Unix(1792080000, 0))
	f := newFakeGoogle(t, clk, &adaptertest.Hooks{})
	sa := saFor(t, f, clk, dirScopes...)
	f.fail["token"] = 500
	if _, err := sa.Token(t.Context()); err == nil {
		t.Fatal("a failing token endpoint gave a token")
	}
	delete(f.fail, "token")
	if _, err := sa.Token(t.Context()); err != nil {
		t.Fatalf("no recovery after the endpoint recovered: %v", err)
	}
	// A scope the admin console did not authorize is refused by the endpoint.
	bad := saFor(t, f, clk, "https://www.googleapis.com/auth/admin.directory.user")
	if _, err := bad.Token(t.Context()); err == nil {
		t.Fatal("an unauthorized scope gave a token")
	}
}

func TestNewServiceAccountRejects(t *testing.T) {
	good := googledir.ServiceAccountConfig{
		Key: testKey(t), Subject: fakeSubject, Scopes: dirScopes,
		TokenURL: "https://127.0.0.1:1/token", Clock: clock.NewFake(time.Unix(1, 0)),
	}
	if _, err := googledir.NewServiceAccount(good); err != nil {
		t.Fatalf("good config: %v", err)
	}
	mut := func(name string, f func(c *googledir.ServiceAccountConfig)) {
		t.Run(name, func(t *testing.T) {
			c := good
			f(&c)
			if _, err := googledir.NewServiceAccount(c); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	mut("no key", func(c *googledir.ServiceAccountConfig) { c.Key = nil })
	mut("not json", func(c *googledir.ServiceAccountConfig) { c.Key = []byte("x") })
	mut("not a service account", func(c *googledir.ServiceAccountConfig) {
		c.Key = []byte(`{"type":"authorized_user","client_email":"a@b","private_key":"x"}`)
	})
	mut("no client email", func(c *googledir.ServiceAccountConfig) {
		c.Key = []byte(`{"type":"service_account","private_key":"x"}`)
	})
	mut("bad pem", func(c *googledir.ServiceAccountConfig) {
		c.Key = []byte(`{"type":"service_account","client_email":"a@b","private_key":"not pem"}`)
	})
	mut("no subject", func(c *googledir.ServiceAccountConfig) { c.Subject = "" })
	mut("no scope", func(c *googledir.ServiceAccountConfig) { c.Scopes = nil })
	mut("scope with a space", func(c *googledir.ServiceAccountConfig) { c.Scopes = []string{"a b"} })
	mut("plain http token url", func(c *googledir.ServiceAccountConfig) { c.TokenURL = "http://oauth2.googleapis.com/token" })
	mut("no clock", func(c *googledir.ServiceAccountConfig) { c.Clock = nil })
}
