package mtls_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core/strictjson"
)

// mtlsModel is the model of the native state of the mTLS cases, defined in
// spec/v1.0/fixtures/adapters/mtls/README.md.
const mtlsModel = "mtls/1"

// xfccHeader is the forwarded-certificate header of MTLS-24.
const xfccHeader = "X-Forwarded-Client-Cert"

// mtlsState is the mtls/1 native state of a case.
type mtlsState struct {
	Model              string              `json:"model"`
	Listener           listenerState       `json:"listener"`
	StatusBound        int64               `json:"status_bound_seconds"`
	Authorities        []authorityState    `json:"authorities"`
	PinnedCAs          []pinnedState       `json:"pinned_cas"`
	Terminators        []string            `json:"terminators"`
	Peers              []peerState         `json:"peers"`
	Snapshots          []snapshotState     `json:"snapshots"`
	Connection         *connectionState    `json:"connection"`
	Forwarded          [][][]string        `json:"forwarded"`
	Enrollments        []memory.Enrollment `json:"enrollments"`
	UnavailableSources []string            `json:"unavailable_sources"`
}

type listenerState struct {
	Role          string `json:"role"`
	TenantID      string `json:"tenant_id"`
	EnvironmentID string `json:"environment_id"`
}

type authorityState struct {
	Ref       string `json:"ref"`
	SubjectCN string `json:"subject_cn"`
	KeySeed   string `json:"key_seed"`
	Issuer    string `json:"issuer"`
	NotBefore int64  `json:"not_before"`
	NotAfter  int64  `json:"not_after"`
}

type pinnedState struct {
	CAID      string `json:"ca_id"`
	Authority string `json:"authority"`
	SANKind   string `json:"san_kind"`
}

type peerState struct {
	Ref         string    `json:"ref"`
	Issuer      string    `json:"issuer"`
	Serial      int64     `json:"serial"`
	SubjectCN   string    `json:"subject_cn"`
	URIs        []string  `json:"uris"`
	DNSNames    []string  `json:"dns_names"`
	NotBefore   int64     `json:"not_before"`
	NotAfter    int64     `json:"not_after"`
	ExtKeyUsage *[]string `json:"ext_key_usage"`
	KeyUsage    *[]string `json:"key_usage"`
	IsCA        bool      `json:"is_ca"`
	KeySeed     string    `json:"key_seed"`
	Chain       []string  `json:"chain"`
	OCSPServers []string  `json:"ocsp_servers"`
}

type snapshotState struct {
	CAID       string         `json:"ca_id"`
	Number     int64          `json:"number"`
	ThisUpdate int64          `json:"this_update"`
	NextUpdate int64          `json:"next_update"`
	Revoked    []revokedState `json:"revoked"`
}

type revokedState struct {
	Serial    int64  `json:"serial"`
	Reason    string `json:"reason"`
	RevokedAt int64  `json:"revoked_at"`
}

type connectionState struct {
	TLSVersion string `json:"tls_version"`
	Resumed    bool   `json:"resumed"`
	Cleartext  bool   `json:"cleartext"`
}

// minted is a certificate the harness made, with its key.
type minted struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// world is a parsed mtls/1 state with every certificate and list minted.
type world struct {
	st          mtlsState
	authorities map[string]minted
	peers       map[string]minted
	// crls holds the DER snapshot of each pinned CA that has one, by ca-id.
	crls map[string][]byte
}

// modelOf returns the model member of a native state.
func modelOf(raw []byte) (string, error) {
	var probe struct {
		Model string `json:"model"`
	}
	// Only the model member is read here; the full parse is strict.
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", err
	}
	return probe.Model, nil
}

// keyOf is the P-256 key whose scalar is SHA-256 of the seed.
func keyOf(seed string) (*ecdsa.PrivateKey, error) {
	d := sha256.Sum256([]byte(seed))
	return ecdsa.ParseRawPrivateKey(elliptic.P256(), d[:])
}

// loadWorld parses an mtls/1 state strictly and mints its certificates and
// revocation lists.
func loadWorld(raw []byte) (*world, error) {
	var st mtlsState
	if err := strictjson.Unmarshal(raw, strictjson.Limits{}, &st); err != nil {
		return nil, fmt.Errorf("mtls/1 state: %w", err)
	}
	switch {
	case st.Model != mtlsModel:
		return nil, fmt.Errorf("model is %q, want %q", st.Model, mtlsModel)
	case st.Listener.Role != "direct" && st.Listener.Role != "terminated":
		return nil, fmt.Errorf("mtls/1 state: listener role %q", st.Listener.Role)
	case st.Listener.TenantID == "" || st.Listener.EnvironmentID == "":
		return nil, errors.New("mtls/1 state: the listener needs a tenant_id and an environment_id")
	case st.StatusBound <= 0:
		return nil, errors.New("mtls/1 state: status_bound_seconds must be positive")
	}
	return buildWorld(st)
}

// buildWorld mints the certificates and revocation lists of a parsed state.
func buildWorld(st mtlsState) (*world, error) {
	w := &world{st: st, authorities: map[string]minted{}, peers: map[string]minted{}, crls: map[string][]byte{}}
	for _, a := range st.Authorities {
		if _, err := w.authority(a.Ref, 0); err != nil {
			return nil, err
		}
	}
	for _, p := range st.Peers {
		if _, dup := w.peers[p.Ref]; dup {
			return nil, fmt.Errorf("mtls/1 state: peer %q is listed twice", p.Ref)
		}
		m, err := w.mintPeer(p)
		if err != nil {
			return nil, fmt.Errorf("peer %s: %w", p.Ref, err)
		}
		w.peers[p.Ref] = m
	}
	for _, s := range st.Snapshots {
		der, err := w.mintCRL(s)
		if err != nil {
			return nil, fmt.Errorf("snapshot of %s: %w", s.CAID, err)
		}
		w.crls[s.CAID] = der
	}
	return w, nil
}

func (w *world) authorityState(ref string) (authorityState, bool) {
	for _, a := range w.st.Authorities {
		if a.Ref == ref {
			return a, true
		}
	}
	return authorityState{}, false
}

// authority mints the authority ref and, first, its issuer.
func (w *world) authority(ref string, depth int) (minted, error) {
	if m, ok := w.authorities[ref]; ok {
		return m, nil
	}
	a, ok := w.authorityState(ref)
	if !ok || depth > 8 {
		return minted{}, fmt.Errorf("mtls/1 state: no authority %q", ref)
	}
	key, err := keyOf(a.KeySeed)
	if err != nil {
		return minted{}, fmt.Errorf("authority %s: %w", ref, err)
	}
	sum := sha256.Sum256([]byte("serial:" + ref))
	tmpl := &x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(sum[:16]),
		Subject:               pkix.Name{CommonName: a.SubjectCN},
		NotBefore:             time.Unix(a.NotBefore, 0),
		NotAfter:              time.Unix(a.NotAfter, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	parent, signer := tmpl, key
	if a.Issuer != "" {
		p, err := w.authority(a.Issuer, depth+1)
		if err != nil {
			return minted{}, err
		}
		parent, signer = p.cert, p.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		return minted{}, fmt.Errorf("authority %s: %w", ref, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return minted{}, fmt.Errorf("authority %s: %w", ref, err)
	}
	m := minted{cert: cert, key: key}
	w.authorities[ref] = m
	return m, nil
}

// sanExtension is a subject alternative name extension with the URI and DNS
// entries as their octets, written by hand so that no library rewrites them.
func sanExtension(uris, dns []string) (pkix.Extension, error) {
	var names []asn1.RawValue
	for _, u := range uris {
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(u)})
	}
	for _, d := range dns {
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(d)})
	}
	val, err := asn1.Marshal(names)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: val}, nil
}

var extKeyUsages = map[string]x509.ExtKeyUsage{
	"client_auth": x509.ExtKeyUsageClientAuth,
	"server_auth": x509.ExtKeyUsageServerAuth,
	"any":         x509.ExtKeyUsageAny,
}

var keyUsages = map[string]x509.KeyUsage{
	"digital_signature": x509.KeyUsageDigitalSignature,
	"key_encipherment":  x509.KeyUsageKeyEncipherment,
	"key_agreement":     x509.KeyUsageKeyAgreement,
	"cert_sign":         x509.KeyUsageCertSign,
	"crl_sign":          x509.KeyUsageCRLSign,
}

func (w *world) mintPeer(p peerState) (minted, error) {
	issuer, ok := w.authorities[p.Issuer]
	if !ok {
		return minted{}, fmt.Errorf("no authority %q", p.Issuer)
	}
	key, err := keyOf(p.KeySeed)
	if err != nil {
		return minted{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(p.Serial),
		Subject:      pkix.Name{CommonName: p.SubjectCN},
		NotBefore:    time.Unix(p.NotBefore, 0),
		NotAfter:     time.Unix(p.NotAfter, 0),
		OCSPServer:   p.OCSPServers,
	}
	if len(p.URIs)+len(p.DNSNames) > 0 {
		ext, err := sanExtension(p.URIs, p.DNSNames)
		if err != nil {
			return minted{}, err
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
	}
	if p.ExtKeyUsage != nil {
		for _, n := range *p.ExtKeyUsage {
			u, ok := extKeyUsages[n]
			if !ok {
				return minted{}, fmt.Errorf("ext_key_usage %q", n)
			}
			tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, u)
		}
	}
	if p.KeyUsage != nil {
		for _, n := range *p.KeyUsage {
			u, ok := keyUsages[n]
			if !ok {
				return minted{}, fmt.Errorf("key_usage %q", n)
			}
			tmpl.KeyUsage |= u
		}
	}
	if p.IsCA {
		tmpl.BasicConstraintsValid, tmpl.IsCA = true, true
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer.cert, &key.PublicKey, issuer.key)
	if err != nil {
		return minted{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return minted{}, err
	}
	return minted{cert: cert, key: key}, nil
}

// reasonCodes are the CRL reason codes of RFC 5280, section 5.3.1.
var reasonCodes = map[string]int{
	"unspecified": 0, "keyCompromise": 1, "cACompromise": 2, "affiliationChanged": 3,
	"superseded": 4, "cessationOfOperation": 5, "certificateHold": 6, "removeFromCRL": 8,
	"privilegeWithdrawn": 9, "aACompromise": 10,
}

func (w *world) pinned(caID string) (pinnedState, bool) {
	for _, p := range w.st.PinnedCAs {
		if p.CAID == caID {
			return p, true
		}
	}
	return pinnedState{}, false
}

func (w *world) mintCRL(s snapshotState) ([]byte, error) {
	p, ok := w.pinned(s.CAID)
	if !ok {
		return nil, errors.New("not a pinned ca-id")
	}
	ca := w.authorities[p.Authority]
	rl := &x509.RevocationList{
		Number:     big.NewInt(s.Number),
		ThisUpdate: time.Unix(s.ThisUpdate, 0),
		NextUpdate: time.Unix(s.NextUpdate, 0),
	}
	for _, r := range s.Revoked {
		code, ok := reasonCodes[r.Reason]
		if !ok {
			return nil, fmt.Errorf("reason %q", r.Reason)
		}
		rl.RevokedCertificateEntries = append(rl.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber: big.NewInt(r.Serial), RevocationTime: time.Unix(r.RevokedAt, 0), ReasonCode: code,
		})
	}
	return x509.CreateRevocationList(rand.Reader, rl, ca.cert, ca.key)
}

// presented returns the certificate the TLS peer ref presents, a peer's or an
// authority's own, and the certificates it sends after it.
func (w *world) presented(ref string) ([]*x509.Certificate, error) {
	if m, ok := w.peers[ref]; ok {
		certs := []*x509.Certificate{m.cert}
		for _, p := range w.st.Peers {
			if p.Ref != ref {
				continue
			}
			for _, c := range p.Chain {
				a, ok := w.authorities[c]
				if !ok {
					return nil, fmt.Errorf("peer %s: chain names no authority %q", ref, c)
				}
				certs = append(certs, a.cert)
			}
		}
		return certs, nil
	}
	if a, ok := w.authorities[ref]; ok {
		return []*x509.Certificate{a.cert}, nil
	}
	return nil, fmt.Errorf("no peer or authority %q", ref)
}

// tlsState is the TLS state of a completed handshake with the peers
// certificates, at the version and with the resumption flag of the case.
func (w *world) tlsState(certs []*x509.Certificate) *tls.ConnectionState {
	cs := &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, PeerCertificates: certs}
	if c := w.st.Connection; c != nil {
		if c.TLSVersion == "1.2" {
			cs.Version = tls.VersionTLS12
		}
		cs.DidResume = c.Resumed
	}
	return cs
}

// Credential attaches the TLS state of the peer ref and, when the state has
// one, the forwarded-certificate header.
func (w *world) Credential(r *http.Request, ref string) error {
	certs, err := w.presented(ref)
	if err != nil {
		return err
	}
	if w.st.Connection == nil || !w.st.Connection.Cleartext {
		r.TLS = w.tlsState(certs)
	}
	if w.st.Forwarded != nil {
		h, err := w.forwardedHeader()
		if err != nil {
			return err
		}
		r.Header.Set(xfccHeader, h)
	}
	return nil
}

// pemOf returns the PEM form of the certificates of the peers refs.
func (w *world) pemOf(refs ...string) (string, error) {
	var b strings.Builder
	for _, ref := range refs {
		m, ok := w.peers[ref]
		if !ok {
			return "", fmt.Errorf("forwarded: no peer %q", ref)
		}
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.cert.Raw}))
	}
	return b.String(), nil
}

// percentEncode writes every octet that is not unreserved (RFC 3986, section
// 2.3) as %XX in upper-case hexadecimal.
func percentEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// forwardedHeader writes the forwarded elements of the state in the text form
// of MTLS-24.
func (w *world) forwardedHeader() (string, error) {
	elems := make([]string, 0, len(w.st.Forwarded))
	for _, el := range w.st.Forwarded {
		pairs := make([]string, 0, len(el))
		for _, kv := range el {
			if len(kv) != 2 {
				return "", fmt.Errorf("forwarded: a pair has %d members", len(kv))
			}
			v := kv[1]
			switch {
			case strings.HasPrefix(v, "@cert:"):
				p, err := w.pemOf(strings.TrimPrefix(v, "@cert:"))
				if err != nil {
					return "", err
				}
				v = percentEncode(p)
			case strings.HasPrefix(v, "@certs:"):
				p, err := w.pemOf(strings.Split(strings.TrimPrefix(v, "@certs:"), ",")...)
				if err != nil {
					return "", err
				}
				v = percentEncode(p)
			}
			if strings.ContainsAny(v, `,;="`) {
				v = `"` + strings.ReplaceAll(v, `"`, `\"`) + `"`
			}
			pairs = append(pairs, kv[0]+"="+v)
		}
		elems = append(elems, strings.Join(pairs, ";"))
	}
	return strings.Join(elems, ","), nil
}

// commonState returns the common/1 state of the enrollments of the world,
// for the reference enrollment source.
func (w *world) commonState() memory.State {
	return memory.State{
		Model: memory.Model,
		Gateway: memory.Gateway{
			TenantID: w.st.Listener.TenantID, EnvironmentID: w.st.Listener.EnvironmentID,
			Origin: "https://gateway.example", HeaderAllowlist: []string{},
		},
		Enrollments:        w.st.Enrollments,
		UnavailableSources: w.st.UnavailableSources,
	}
}

// mintCRLAt mints a list of the world's first pinned CA with the CRL number
// number, published at thisUpdate, valid for an hour, listing serials.
func (w *world) mintCRLAt(t testing.TB, number int64, thisUpdate time.Time, serials []int64) []byte {
	t.Helper()
	s := snapshotState{CAID: w.st.PinnedCAs[0].CAID, Number: number, ThisUpdate: thisUpdate.Unix(), NextUpdate: thisUpdate.Add(time.Hour).Unix()}
	for _, n := range serials {
		s.Revoked = append(s.Revoked, revokedState{Serial: n, Reason: "keyCompromise", RevokedAt: thisUpdate.Unix()})
	}
	der, err := w.mintCRL(s)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
