package adaptertest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	"hop.top/pact-go/internal/ascii"
)

// decodeBody decodes a body_b64 member: standard base64 with padding, empty
// for no body.
func decodeBody(b64 string) ([]byte, error) {
	if b64 == "" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("request.body_b64 is not standard padded base64: %w", err)
	}
	return b, nil
}

// buildRequest builds the *http.Request of a case, before any credential is
// attached or the enforcement point marks it. The URL is kept as the case
// states it, so a fragment or userinfo reaches the adapter intact, and it is
// also the request-target the gateway received, in absolute-form (RFC 9112
// 3.2.2): RequestURI holds it octet for octet, as a server sets it. The body is
// returned as well, for the check that an adapter restores what it reads.
func buildRequest(ctx context.Context, r *Request) (*http.Request, []byte, error) {
	body, err := decodeBody(r.BodyB64)
	if err != nil {
		return nil, nil, err
	}
	var rd *bytes.Reader
	if len(body) > 0 {
		rd = bytes.NewReader(body)
	}
	var req *http.Request
	if rd != nil {
		req, err = http.NewRequestWithContext(ctx, r.Method, r.URL, rd)
	} else {
		req, err = http.NewRequestWithContext(ctx, r.Method, r.URL, nil)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("request: %w", err)
	}
	req.RequestURI = r.URL
	for name, value := range r.Headers {
		if ascii.EqualFold(name, "host") {
			req.Host = value
			continue
		}
		req.Header.Add(name, value)
	}
	if r.TLSPeer != nil {
		cs, err := r.TLSPeer.state()
		if err != nil {
			return nil, nil, err
		}
		req.TLS = cs
	}
	return req, body, nil
}

// state returns the TLS connection state of a handshake with a client that
// presented a certificate with these attributes. The certificate has no raw
// bytes and no signature: it carries the attributes an adapter reads and
// nothing a verifier could check.
func (p *TLSPeer) state() (*tls.ConnectionState, error) {
	cert := &x509.Certificate{
		Subject:  pkix.Name{CommonName: p.SubjectCN},
		Issuer:   pkix.Name{CommonName: p.IssuerCN},
		DNSNames: p.DNSNames,
	}
	for _, u := range p.URIs {
		parsed, err := url.Parse(u)
		if err != nil {
			return nil, fmt.Errorf("request.tls_peer.uris: %w", err)
		}
		cert.URIs = append(cert.URIs, parsed)
	}
	return &tls.ConnectionState{
		Version:           tls.VersionTLS13,
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{cert},
	}, nil
}
