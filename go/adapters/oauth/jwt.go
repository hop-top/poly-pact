package oauth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/strictjson"
)

// algRS256 is RSASSA-PKCS1-v1_5 with SHA-256 (RFC 7518 section 3.3).
const algRS256 = "RS256"

// minRSABits is the smallest RSA key RFC 7518 section 3.3 allows.
const minRSABits = 2048

// maxToken bounds the length of a JWT access token.
const maxToken = 16 << 10

// jose is the protected header of a form E token.
type jose struct {
	alg, typ, kid string
	hasTyp, crit  bool
}

// verifyJWT validates a Microsoft Entra ID v2.0 access token of a form E entry
// (profile section D).
//
// The token is a compact JWS of three segments (OAUTH-20). Its header has typ
// JWT, an alg of the entry's allowlist, a kid, and no crit; jku, x5u, jwk and
// x5c are ignored and never fetched (OAUTH-21, OAUTH-22; RFC 8725 sections
// 3.1, 3.10). The key is the member of the entry's key set with that kid
// ([Adapter.keyFor]), an RSA signing key of at least 2048 bits, and the
// signature is verified before any claim is read (OAUTH-25). The claims then
// need ver 2.0, the entry's iss and tid with the issuer path /{tid}/v2.0, an
// accepted aud, exp, nbf and iat inside draft 7.5 and a lifetime of at most
// L, an allowlisted azp, a non-empty scp of OAUTH-14 syntax, and oid
// (OAUTH-19, OAUTH-26 to OAUTH-31, OAUTH-37). Every failure is a native
// denial; a key set that cannot be had is [adapter.ErrDependencyUnavailable]
// (OAUTH-24).
func (a *Adapter) verifyJWT(ctx context.Context, e *entry, token string) (facts, error) {
	if len(token) > maxToken {
		return facts{}, rejected
	}
	segs := strings.Split(token, ".")
	if len(segs) != 3 {
		return facts{}, rejected
	}
	h, ok := parseHeader(segs[0])
	if !ok || h.typ != "JWT" || h.crit || h.kid == "" || !slices.Contains(e.Algorithms, h.alg) {
		return facts{}, rejected
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(segs[2])
	if err != nil || len(sig) == 0 {
		return facts{}, rejected
	}
	pub, err := a.keyFor(ctx, e, h.kid)
	if err != nil {
		return facts{}, err
	}
	if err := verifyRS256(pub, segs[0]+"."+segs[1], sig); err != nil {
		return facts{}, rejected
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(segs[1])
	if err != nil {
		return facts{}, rejected
	}
	return e.entraClaims(payload, a.cfg.Clock.Now())
}

// parseHeader decodes the protected header strictly.
func parseHeader(seg string) (jose, bool) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(seg)
	if err != nil {
		return jose{}, false
	}
	var m map[string]json.RawMessage
	if strictjson.Unmarshal(raw, strictjson.Limits{}, &m) != nil {
		return jose{}, false
	}
	var h jose
	for name, v := range m {
		var s string
		switch name {
		case "alg":
			if strictString(v, &s) != nil {
				return jose{}, false
			}
			h.alg = s
		case "typ":
			if strictString(v, &s) != nil {
				return jose{}, false
			}
			h.typ, h.hasTyp = s, true
		case "kid":
			if strictString(v, &s) != nil {
				return jose{}, false
			}
			h.kid = s
		case "crit":
			// RFC 7515 section 4.1.11: this profile understands no
			// extension, so any crit makes the JWS invalid.
			h.crit = true
		}
	}
	return h, true
}

// verifyRS256 verifies an RSASSA-PKCS1-v1_5 SHA-256 signature over the
// received signing input (RFC 7518 section 3.3).
func verifyRS256(pub *rsa.PublicKey, input string, sig []byte) error {
	if pub.N.BitLen() < minRSABits {
		return errors.New("oauth: RSA key shorter than 2048 bits")
	}
	if len(sig) != pub.Size() {
		return errors.New("oauth: signature length differs from the key size")
	}
	digest := sha256.Sum256([]byte(input))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
}

// entraClaims applies the claim rules of section D to a verified payload.
func (e *entry) entraClaims(payload []byte, now time.Time) (facts, error) {
	var m map[string]json.RawMessage
	if strictjson.Unmarshal(payload, strictjson.Limits{}, &m) != nil {
		return facts{}, rejected
	}
	str := func(name string) (string, bool) {
		v, ok := m[name]
		if !ok {
			return "", false
		}
		var s string
		if strictString(v, &s) != nil {
			return "", false
		}
		return s, true
	}
	num := func(name string) (int64, bool) {
		v, ok := m[name]
		if !ok {
			return 0, false
		}
		n, err := number(v)
		if err != nil {
			return 0, false
		}
		t, ok := unixOf(n)
		return t.Unix(), ok
	}
	if ver, _ := str("ver"); ver != "2.0" {
		return facts{}, rejected
	}
	iss, _ := str("iss")
	tid, _ := str("tid")
	if iss != e.Issuer || tid == "" || tid != e.Tenant {
		return facts{}, rejected
	}
	if u, err := url.Parse(iss); err != nil || u.Path != "/"+tid+"/v2.0" {
		return facts{}, rejected
	}
	if aud, ok := str("aud"); !ok || !slices.Contains(e.Audiences, aud) {
		return facts{}, rejected
	}
	exp, okE := num("exp")
	nbf, okN := num("nbf")
	iat, okI := num("iat")
	if !okE || !okN || !okI || clock.CheckWindow(iat, nbf, exp, now, clock.BaselineSkew) != nil {
		return facts{}, rejected
	}
	if time.Duration(exp-iat)*time.Second > e.Lifetime {
		return facts{}, rejected
	}
	azp, ok := str("azp")
	if !ok || !slices.Contains(e.Clients, azp) {
		return facts{}, rejected
	}
	scp, _ := str("scp")
	scopes, ok := scopeList(scp)
	if !ok {
		return facts{}, rejected
	}
	oid, ok := str("oid")
	if !ok || oid == "" {
		return facts{}, rejected
	}
	f := facts{subject: oid, client: azp, scopes: scopes, issuedAt: time.Unix(iat, 0)}
	if uti, ok := str("uti"); ok {
		f.tokenID = uti
	}
	if raw, ok := m["cnf"]; ok {
		c, err := confirmation(raw)
		if err != nil || c == nil {
			return facts{}, rejected
		}
		f.cnf = c
	}
	return f, nil
}
