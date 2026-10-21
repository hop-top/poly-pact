package mtls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
	"hop.top/pact-go/internal/ascii"
)

// ForwardedHeader is the forwarded-certificate header of MTLS-24.
const ForwardedHeader = "X-Forwarded-Client-Cert"

// forwardedIdentityHeaders are the headers besides ForwardedHeader that carry
// data from a client certificate and never contribute to identity (MTLS-26):
// the ssl-client-* family by prefix, and these names.
var forwardedIdentityHeaders = []string{"X-Client-Cert", "X-Client-Verify", "X-Client-Dn", "X-Ssl-Client-Cert", "X-Ssl-Client-Verify", "X-Ssl-Client-S-Dn"}

func denied(reason adapter.DenialReason) error { return &adapter.NativeDenial{Reason: reason} }

// AuthenticateNative authenticates the request by the client certificate of
// the TLS connection that carried it (MTLS-18), or, on a terminated listener,
// by the certificate the allowlisted terminator forwarded (MTLS-24).
//
// The request must carry the status record of a connection that this
// listener accepted ([Adapter.ConnContext]); one that does not is refused
// with CREDENTIAL_REJECTED before anything else is read. The headers of
// MTLS-26 are then removed from the request, so that none reaches
// authorization or execution. The TLS state must be a completed TLS 1.3
// handshake that the stack does not report as resumed (MTLS-1, MTLS-17); a
// request without TLS state or without a client certificate is a denial with
// NO_CREDENTIAL, every other refusal is CREDENTIAL_REJECTED. The peer leaf
// passes MTLS-3 to MTLS-7 against the current pinned set and its status is
// established as MTLS-19 says for the connection's peer and MTLS-25 for a
// forwarded leaf: a revoked leaf is CREDENTIAL_REJECTED, a status that cannot
// be established is an error that wraps [adapter.ErrDependencyUnavailable],
// and a connection record older than the status bound is
// [ErrConnectionExpired].
//
// The principal and the workload are both the identifier of MTLS-6, in the
// listener's realm, with mechanism mtls. The principal's attribute cnf holds
// the RFC 7638 thumbprint of the leaf's public key (MTLS-9), and the attribute
// mtls the status time and, on a direct listener, the observation time of the
// identity (MTLS-30).
func (a *Adapter) AuthenticateNative(ctx context.Context, r *http.Request) (adapter.Principal, error) {
	if err := live(ctx, "authenticate"); err != nil {
		return adapter.Principal{}, err
	}
	if r == nil {
		return adapter.Principal{}, denied(adapter.DenialNoCredential)
	}
	rec := a.record(r)
	if rec == nil {
		return adapter.Principal{}, denied(adapter.DenialCredentialRejected)
	}
	forwarded, hasForwarded := r.Header[http.CanonicalHeaderKey(ForwardedHeader)]
	a.stripIdentityHeaders(r.Header)
	cs := r.TLS
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return adapter.Principal{}, denied(adapter.DenialNoCredential)
	}
	if cs.Version != tls.VersionTLS13 || !cs.HandshakeComplete || cs.DidResume {
		return adapter.Principal{}, denied(adapter.DenialCredentialRejected)
	}
	now := a.cfg.Clock.Now()
	peer, err := a.verifyLeaf(cs.PeerCertificates[0], cs.PeerCertificates[1:], now)
	if err != nil {
		return adapter.Principal{}, denied(adapter.DenialCredentialRejected)
	}
	if a.cfg.Role == RoleTerminated && !a.terminator(peer.workload) {
		return adapter.Principal{}, denied(adapter.DenialCredentialRejected)
	}
	observedAt, statusTime, err := a.connectionStatus(rec, peer, cs.PeerCertificates[0], now)
	if err != nil {
		return adapter.Principal{}, err
	}
	leaf, ident := cs.PeerCertificates[0], peer
	if a.cfg.Role == RoleTerminated {
		if !hasForwarded {
			return adapter.Principal{}, denied(adapter.DenialNoCredential)
		}
		leaf, err = forwardedLeaf(forwarded)
		if err != nil {
			return adapter.Principal{}, denied(adapter.DenialCredentialRejected)
		}
		if ident, err = a.verifyLeaf(leaf, nil, now); err != nil {
			return adapter.Principal{}, denied(adapter.DenialCredentialRejected)
		}
		s := a.statusOf(ident.entry.CAID, now)
		if s == nil {
			return adapter.Principal{}, fmt.Errorf("mtls: authenticate: no usable status for the forwarded leaf: %w", adapter.ErrDependencyUnavailable)
		}
		if s.isRevoked(leaf) {
			return adapter.Principal{}, denied(adapter.DenialCredentialRejected)
		}
		observedAt, statusTime = time.Time{}, s.thisUpdate
	}
	jkt, err := thumbprint(leaf.PublicKey)
	if err != nil {
		return adapter.Principal{}, denied(adapter.DenialCredentialRejected)
	}
	status := map[string]any{"status_time": statusTime.Unix()}
	if !observedAt.IsZero() {
		status["observed_at"] = observedAt.Unix()
	}
	return adapter.Principal{
		ID:              string(ident.workload),
		Realm:           a.cfg.Realm,
		Workload:        ident.workload,
		Mechanism:       Mechanism,
		AuthenticatedAt: now,
		Attributes: map[string]any{
			AttrConfirmation: map[string]any{"jkt": string(jkt)},
			AttrStatus:       status,
		},
	}, nil
}

// connectionStatus applies MTLS-19 to the connection's own peer leaf. The
// first successful evaluation of a connection tests the leaf against the
// snapshot of its pinned CA and creates the record; it is never refreshed. A
// later request compares the age of the record with the status bound. A
// failed evaluation creates no record.
func (a *Adapter) connectionStatus(rec *connRecord, peer verified, leaf *x509.Certificate, now time.Time) (observedAt, statusTime time.Time, err error) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.set {
		if now.Sub(rec.statusTime) > a.cfg.StatusBound {
			return time.Time{}, time.Time{}, ErrConnectionExpired
		}
		return rec.observedAt, rec.statusTime, nil
	}
	s := a.statusOf(peer.entry.CAID, now)
	if s == nil {
		return time.Time{}, time.Time{}, fmt.Errorf("mtls: authenticate: no usable status for the peer certificate: %w", adapter.ErrDependencyUnavailable)
	}
	if s.isRevoked(leaf) {
		return time.Time{}, time.Time{}, denied(adapter.DenialCredentialRejected)
	}
	rec.set, rec.observedAt, rec.statusTime = true, now, s.thisUpdate
	return now, s.thisUpdate, nil
}

// stripIdentityHeaders removes every header of MTLS-26 from h.
func (a *Adapter) stripIdentityHeaders(h http.Header) {
	h.Del(ForwardedHeader)
	for _, name := range forwardedIdentityHeaders {
		h.Del(name)
	}
	for _, name := range a.cfg.ForwardedIdentityHeaders {
		h.Del(name)
	}
	for name := range h {
		if strings.HasPrefix(ascii.ToLower(name), "ssl-client-") {
			delete(h, name)
		}
	}
}

// forwardedLeaf parses the forwarded-certificate header of MTLS-24: exactly
// one header line with exactly one element, exactly one Cert pair, and a Cert
// value that, percent-decoded, is exactly one PEM certificate and nothing
// else. Every other key is ignored.
func forwardedLeaf(lines []string) (*x509.Certificate, error) {
	if len(lines) != 1 {
		return nil, errors.New("more than one header line")
	}
	elems, err := splitQuoted(lines[0], ',')
	if err != nil || len(elems) != 1 {
		return nil, errors.New("not exactly one element")
	}
	pairs, err := splitQuoted(elems[0], ';')
	if err != nil {
		return nil, err
	}
	var cert string
	n := 0
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			return nil, errors.New("a pair has no value")
		}
		if ascii.EqualFold(strings.TrimSpace(k), "Cert") {
			n++
			cert = v
		}
	}
	if n != 1 {
		return nil, errors.New("not exactly one Cert")
	}
	cert, err = unquote(cert)
	if err != nil {
		return nil, err
	}
	raw, err := url.PathUnescape(cert)
	if err != nil {
		return nil, err
	}
	data := []byte(raw)
	if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
		return nil, errors.New("the Cert value is not a PEM certificate")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) > 0 || len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("the Cert value is not exactly one PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// splitQuoted splits s at sep outside double quotes; a backslash escapes a
// double quote inside them.
func splitQuoted(s string, sep byte) ([]string, error) {
	var out []string
	start, quoted := 0, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && quoted:
			i++
		case c == '"':
			quoted = !quoted
		case c == sep && !quoted:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if quoted {
		return nil, errors.New("unterminated quote")
	}
	return append(out, s[start:]), nil
}

// unquote removes the double quotes of a quoted value and its \" escapes.
func unquote(v string) (string, error) {
	if !strings.HasPrefix(v, `"`) {
		return v, nil
	}
	if len(v) < 2 || !strings.HasSuffix(v, `"`) {
		return "", errors.New("malformed quoted value")
	}
	return strings.ReplaceAll(v[1:len(v)-1], `\"`, `"`), nil
}

// thumbprint is the RFC 7638 SHA-256 thumbprint of a public key: the required
// members of its JWK in lexicographic order, without white space.
func thumbprint(pub any) (core.Digest, error) {
	b64 := base64.RawURLEncoding
	var input string
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		point, err := k.Bytes()
		if err != nil {
			return "", fmt.Errorf("mtls: %w", err)
		}
		size := (len(point) - 1) / 2
		x, y := point[1:1+size], point[1+size:]
		input = `{"crv":"` + k.Curve.Params().Name + `","kty":"EC","x":"` + b64.EncodeToString(x) + `","y":"` + b64.EncodeToString(y) + `"}`
	case *rsa.PublicKey:
		e := big.NewInt(int64(k.E)).Bytes()
		input = `{"e":"` + b64.EncodeToString(e) + `","kty":"RSA","n":"` + b64.EncodeToString(k.N.Bytes()) + `"}`
	case ed25519.PublicKey:
		input = `{"crv":"Ed25519","kty":"OKP","x":"` + b64.EncodeToString(k) + `"}`
	default:
		return "", fmt.Errorf("mtls: no thumbprint for a %T key", pub)
	}
	sum := sha256.Sum256([]byte(input))
	return core.Digest(b64.EncodeToString(sum[:])), nil
}
