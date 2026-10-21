package ssf_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapter/source"
	"hop.top/pact-go/adapter/source/ssf"
	"hop.top/pact-go/adapter/sourcetest"
	"hop.top/pact-go/core/jcs"
	"hop.top/pact-go/core/jws"
)

// The source model ssf/1 is defined in spec/v1.0/profiles/sources/ssf.md.

type ssfSource struct {
	Model                  string   `json:"model"`
	SourceID               string   `json:"source_id"`
	PrincipalPrefix        string   `json:"principal_prefix"`
	MaxAgeSeconds          int64    `json:"max_age_seconds"`
	Authorization          string   `json:"authorization"`
	HoldOn                 []string `json:"hold_on"`
	CriticalSubjectMembers []string `json:"critical_subject_members"`
	Issuers                []struct {
		Issuer     string   `json:"issuer"`
		Audience   string   `json:"audience"`
		Algorithms []string `json:"algorithms"`
		JWKS       struct {
			Keys []json.RawMessage `json:"keys"`
		} `json:"jwks"`
	} `json:"issuers"`
	Mappings []struct {
		Issuer     string `json:"issuer"`
		Format     string `json:"format"`
		SubjectIss string `json:"subject_iss"`
		Value      string `json:"value"`
		Local      string `json:"local"`
	} `json:"mappings"`
}

type inbound struct {
	Push *struct {
		Set           string          `json:"set"`
		ContentType   string          `json:"content_type"`
		Authorization string          `json:"authorization"`
		Decoded       json.RawMessage `json:"decoded"`
	} `json:"push"`
	Poll *struct {
		Sets          map[string]string `json:"sets"`
		MoreAvailable bool              `json:"more_available"`
	} `json:"poll"`
}

type stepExpect struct {
	Status    int               `json:"status"`
	Err       string            `json:"err"`
	Ack       []string          `json:"ack"`
	SetErrs   map[string]string `json:"set_errs"`
	Telemetry []string          `json:"telemetry"`
	Holds     *[]struct {
		Principal string `json:"principal"`
		EventType string `json:"event_type"`
		JTI       string `json:"jti"`
		EventTime int64  `json:"event_time"`
	} `json:"holds"`
}

// pollSide is the fake transmitter a poll step talks to.
type pollSide struct {
	srv    *httptest.Server
	mu     sync.Mutex
	next   []string
	bodies []map[string]any
}

func driver() sourcetest.Driver {
	return sourcetest.Driver{Model: "ssf/1", Open: func(t testing.TB, env sourcetest.Env) (sourcetest.Subject, error) {
		dec := json.NewDecoder(bytes.NewReader(env.Source))
		dec.DisallowUnknownFields()
		var s ssfSource
		if err := dec.Decode(&s); err != nil {
			return sourcetest.Subject{}, err
		}
		tel, hs := &telemetry{}, &holds{}
		cfg := ssf.Config{
			SourceID: s.SourceID, Store: source.NewMemory(), Clock: env.Clock, PrincipalPrefix: s.PrincipalPrefix,
			MaxAge: time.Duration(s.MaxAgeSeconds) * time.Second, Authorization: s.Authorization,
			HoldOn: s.HoldOn, CriticalSubjectMembers: s.CriticalSubjectMembers, Telemetry: tel,
		}
		if len(s.HoldOn) > 0 {
			cfg.Holds = hs
		}
		for _, is := range s.Issuers {
			// The jwks of an issuer is its jwks_uri document (ssf.md, section
			// 13): the receiver fetches it and checks each key when it is used.
			keys, err := serveJWKS(t, env, is.JWKS.Keys)
			if err != nil {
				return sourcetest.Subject{}, err
			}
			cfg.Issuers = append(cfg.Issuers, ssf.Issuer{Issuer: is.Issuer, Audience: is.Audience, Algorithms: is.Algorithms, Keys: keys})
		}
		for _, m := range s.Mappings {
			cfg.Mappings = append(cfg.Mappings, ssf.Mapping{Issuer: m.Issuer, Format: m.Format, SubjectIss: m.SubjectIss, Value: m.Value, Local: m.Local})
		}
		rx, err := ssf.NewReceiver(cfg)
		if err != nil {
			return sourcetest.Subject{}, err
		}
		var side *pollSide
		var poller *ssf.Poller
		apply := func(ctx context.Context, in, ex json.RawMessage) error {
			var i inbound
			var e stepExpect
			if err := json.Unmarshal(in, &i); err != nil {
				return err
			}
			if err := json.Unmarshal(ex, &e); err != nil {
				return err
			}
			tel.reset()
			hs.got = nil
			var fail []string
			switch {
			case i.Push != nil:
				ct := i.Push.ContentType
				if ct == "" {
					ct = "application/secevent+jwt"
				}
				rec := post(rx.PushHandler(), ct, i.Push.Authorization, i.Push.Set)
				if rec.Code != e.Status {
					fail = append(fail, fmt.Sprintf("status %d, want %d", rec.Code, e.Status))
				}
				if e.Err != "" {
					var b struct {
						Err string `json:"err"`
					}
					_ = json.Unmarshal(rec.Body.Bytes(), &b)
					if b.Err != e.Err {
						fail = append(fail, fmt.Sprintf("err %q, want %q", b.Err, e.Err))
					}
				}
			case i.Poll != nil:
				if side == nil {
					side = &pollSide{}
					side.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						side.mu.Lock()
						defer side.mu.Unlock()
						b, _ := io.ReadAll(r.Body)
						var m map[string]any
						_ = json.Unmarshal(b, &m)
						side.bodies = append(side.bodies, m)
						resp := `{"sets":{}}`
						if len(side.next) > 0 {
							resp, side.next = side.next[0], side.next[1:]
						}
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write([]byte(resp))
					}))
					t.Cleanup(side.srv.Close)
					var err error
					poller, err = ssf.NewPoller(ssf.PollConfig{URL: side.srv.URL, Client: side.srv.Client(), Receiver: rx, ReturnImmediately: true})
					if err != nil {
						return err
					}
				}
				body, _ := json.Marshal(map[string]any{"sets": i.Poll.Sets, "moreAvailable": i.Poll.MoreAvailable})
				side.mu.Lock()
				side.next = []string{string(body)}
				side.mu.Unlock()
				if _, err := poller.Poll(ctx); err != nil {
					return err
				}
				kinds := tel.kinds()
				// The next request carries the acknowledgments.
				if _, err := poller.Poll(ctx); err != nil {
					return err
				}
				side.mu.Lock()
				last := side.bodies[len(side.bodies)-1]
				side.mu.Unlock()
				var ack []string
				if v, ok := last["ack"]; ok {
					ack = strs(v)
				}
				want := append([]string{}, e.Ack...)
				slices.Sort(want)
				if !slices.Equal(ack, want) {
					fail = append(fail, fmt.Sprintf("ack %v, want %v", ack, want))
				}
				gotErrs := map[string]string{}
				if m, ok := last["setErrs"].(map[string]any); ok {
					for k, v := range m {
						gotErrs[k], _ = v.(map[string]any)["err"].(string)
					}
				}
				if len(gotErrs) != len(e.SetErrs) {
					fail = append(fail, fmt.Sprintf("setErrs %v, want %v", gotErrs, e.SetErrs))
				}
				for k, v := range e.SetErrs {
					if gotErrs[k] != v {
						fail = append(fail, fmt.Sprintf("setErrs[%s] %q, want %q", k, gotErrs[k], v))
					}
				}
				if e.Telemetry != nil && !slices.Equal(kinds, e.Telemetry) {
					fail = append(fail, fmt.Sprintf("telemetry %v, want %v", kinds, e.Telemetry))
				}
				return joinFail(fail)
			default:
				return fmt.Errorf("inbound is neither push nor poll")
			}
			if e.Telemetry != nil && !slices.Equal(tel.kinds(), e.Telemetry) {
				fail = append(fail, fmt.Sprintf("telemetry %v, want %v", tel.kinds(), e.Telemetry))
			}
			if e.Holds != nil {
				if len(hs.got) != len(*e.Holds) {
					fail = append(fail, fmt.Sprintf("hold candidates %d, want %d", len(hs.got), len(*e.Holds)))
				} else {
					for j, w := range *e.Holds {
						g := hs.got[j]
						if g.Principal != w.Principal || g.EventType != w.EventType || g.JTI != w.JTI || g.EventTime.Unix() != w.EventTime {
							fail = append(fail, fmt.Sprintf("hold candidate %d: %+v, want %+v", j, g, w))
						}
					}
				}
			}
			return joinFail(fail)
		}
		return sourcetest.Subject{Reader: rx.Reader(), Apply: apply}, nil
	}}
}

// serveJWKS serves keys as a JWK Set over TLS and returns the receiver's
// source for it, refreshed less often than any case lasts.
func serveJWKS(t testing.TB, env sourcetest.Env, keys []json.RawMessage) (*ssf.JWKS, error) {
	body, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		return nil, err
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return ssf.NewJWKS(srv.URL, srv.Client(), env.Clock, 24*time.Hour)
}

func joinFail(f []string) error {
	if len(f) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(f, "; "))
}

func TestConformance(t *testing.T) {
	sourcetest.Run(t, driver(), sourcetest.Options{Source: "ssf"})
}

// The decoded form each push step carries beside its compact SET is what the
// compact SET holds, and it is signed by the key it names.
func TestFixtureDecodedForms(t *testing.T) {
	fsys, err := adaptertest.DefaultFixtures()
	if err != nil {
		t.Fatal(err)
	}
	keyOf := map[string]*ecdsa.PublicKey{}
	for role, file := range map[string]string{"issuer": "keys/issuer.jwk.json", "adversarial": "keys/adversarial.jwk.json"} {
		b, err := fs.ReadFile(fsys, file)
		if err != nil {
			t.Fatal(err)
		}
		j, err := jws.ParseJWK(b)
		if err != nil {
			t.Fatal(err)
		}
		if keyOf[role], err = j.PublicKey(); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := fs.ReadDir(fsys, "sources/ssf")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		if path.Ext(e.Name()) != ".json" {
			continue
		}
		b, _ := fs.ReadFile(fsys, path.Join("sources/ssf", e.Name()))
		var c struct {
			Steps []struct {
				Inbound inbound `json:"inbound"`
			} `json:"steps"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		for i, s := range c.Steps {
			if s.Inbound.Push == nil || s.Inbound.Push.Decoded == nil {
				continue
			}
			var d struct {
				SignedBy string          `json:"signed_by"`
				Header   json.RawMessage `json:"header"`
				Claims   json.RawMessage `json:"claims"`
			}
			if err := json.Unmarshal(s.Inbound.Push.Decoded, &d); err != nil {
				t.Fatalf("%s step %d: %v", e.Name(), i, err)
			}
			parts := strings.Split(s.Inbound.Push.Set, ".")
			if len(parts) != 3 {
				t.Fatalf("%s step %d: not compact", e.Name(), i)
			}
			for n, want := range []json.RawMessage{d.Header, d.Claims} {
				got, err := base64.RawURLEncoding.DecodeString(parts[n])
				if err != nil {
					t.Fatalf("%s step %d: %v", e.Name(), i, err)
				}
				gc, _ := jcs.Canonicalize(got)
				wc, _ := jcs.Canonicalize(want)
				if !bytes.Equal(gc, wc) {
					t.Errorf("%s step %d: segment %d is %s, decoded form says %s", e.Name(), i, n, got, want)
				}
			}
			sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
			switch d.SignedBy {
			case "none":
				if parts[2] != "" {
					t.Errorf("%s step %d: signed_by none, but has a signature", e.Name(), i)
				}
			case "issuer", "adversarial":
				sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
				if len(sig) != 64 || !ecdsa.Verify(keyOf[d.SignedBy], sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
					t.Errorf("%s step %d: not signed by the %s key", e.Name(), i, d.SignedBy)
				}
				other := map[string]string{"issuer": "adversarial", "adversarial": "issuer"}[d.SignedBy]
				if len(sig) == 64 && ecdsa.Verify(keyOf[other], sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
					t.Errorf("%s step %d: also verifies under the %s key", e.Name(), i, other)
				}
			default:
				if !checkRSASigner(t, fmt.Sprintf("%s step %d", e.Name(), i), d.SignedBy, parts, sig) {
					t.Errorf("%s step %d: signed_by %q", e.Name(), i, d.SignedBy)
				}
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no decoded push step found")
	}
}

// checkRSASigner checks a signed_by of the RSA cases and reports whether it
// knows the name: "rsa:<kid>" is an RS256 signature by the test key of that
// kid (and by no other); "hmac:<kid>:pkix-pem" and "hmac:<kid>:pkix-der" are
// an HS256 MAC keyed by that key's public half in the named encoding.
func checkRSASigner(t *testing.T, where, signedBy string, parts []string, sig []byte) bool {
	t.Helper()
	input := []byte(parts[0] + "." + parts[1])
	switch fields := strings.Split(signedBy, ":"); {
	case len(fields) == 2 && fields[0] == "rsa":
		sum := sha256.Sum256(input)
		for name := range rsaSpecs {
			err := rsa.VerifyPKCS1v15(&rsaKeyOf(t, name).PublicKey, crypto.SHA256, sum[:], sig)
			if (name == fields[1]) != (err == nil) {
				t.Errorf("%s: RS256 signature under %s: %v, signed_by says %s", where, name, err, fields[1])
			}
		}
		return true
	case len(fields) == 3 && fields[0] == "hmac":
		der, err := x509.MarshalPKIXPublicKey(&rsaKeyOf(t, fields[1]).PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		secret := der
		switch fields[2] {
		case "pkix-der":
		case "pkix-pem":
			secret = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		default:
			return false
		}
		mac := hmac.New(sha256.New, secret)
		mac.Write(input)
		if !hmac.Equal(mac.Sum(nil), sig) {
			t.Errorf("%s: not the HS256 MAC under the %s key", where, fields[2])
		}
		return true
	}
	return false
}

// The RSA keys of the cases are the keys derived from their labels (ssf.md,
// section 13): each RSA JWK of a case is the public key of the derivation.
func TestFixtureRSAKeys(t *testing.T) {
	fsys, err := adaptertest.DefaultFixtures()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(fsys, "sources/ssf")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		b, _ := fs.ReadFile(fsys, path.Join("sources/ssf", e.Name()))
		var c struct {
			Source ssfSource `json:"source"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		for _, is := range c.Source.Issuers {
			for _, raw := range is.JWKS.Keys {
				var k struct {
					Kty, Kid, N, E string
				}
				_ = json.Unmarshal(raw, &k)
				if k.Kty != "RSA" {
					continue
				}
				want := rsaKeyOf(t, k.Kid)
				if k.N != b64(want.N.Bytes()) || k.E != b64(big.NewInt(int64(want.E)).Bytes()) {
					t.Errorf("%s: the key %s is not the derived key", e.Name(), k.Kid)
				}
				checked++
			}
		}
	}
	if checked == 0 {
		t.Fatal("no RSA key found")
	}
}
