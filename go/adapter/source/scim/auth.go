package scim

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"

	"hop.top/pact-go/internal/ascii"
)

// authResult is the outcome of authenticating one request.
type authResult int

const (
	authOK authResult = iota
	authMissing
	authInvalid
	authForbidden
)

// credential is a configured token, held as its digest so the comparison does
// not depend on the length of the token presented.
type credential struct {
	digest       [sha256.Size]byte
	provisioning bool
}

// authenticate checks the Authorization header of r. The bearer scheme name
// is case-insensitive (RFC 9110 section 11.1). A request with no header, or
// with another scheme, presents no bearer credentials. The comparison visits
// every configured token whatever the outcome.
func (s *Server) authenticate(r *http.Request) authResult {
	scheme, rest, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !ascii.EqualFold(scheme, "Bearer") {
		return authMissing
	}
	presented := sha256.Sum256([]byte(strings.TrimSpace(rest)))
	matched, provisioning := 0, 0
	for _, c := range s.creds {
		eq := subtle.ConstantTimeCompare(presented[:], c.digest[:])
		matched |= eq
		if c.provisioning {
			provisioning |= eq
		}
	}
	switch {
	case matched == 0:
		return authInvalid
	case provisioning == 0:
		return authForbidden
	}
	return authOK
}

// challenge writes the WWW-Authenticate field of a failed authentication
// (RFC 6750 section 3): no error code when the request presented no bearer
// credentials, invalid_token for a token the service does not know, and
// insufficient_scope for a known token without the provisioning right.
func challenge(w http.ResponseWriter, res authResult) {
	v := `Bearer realm="scim"`
	switch res {
	case authInvalid:
		v += `, error="invalid_token"`
	case authForbidden:
		v += `, error="insufficient_scope"`
	}
	w.Header().Set("WWW-Authenticate", v)
}
