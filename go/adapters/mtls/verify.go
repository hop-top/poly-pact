package mtls

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/internal/ascii"
)

// pinnedSet is one version of the pinned CA set.
type pinnedSet struct {
	entries []CAEntry
	roots   *x509.CertPool
}

// ReplacePinnedCAs replaces the pinned CA set, as the gateway's administrative
// controls do (MTLS-2). The next request is evaluated against the new set:
// removing an authority ends service to the connections it issued (MTLS-21).
// Snapshots of the authorities that stay are kept.
func (a *Adapter) ReplacePinnedCAs(entries []CAEntry) error {
	set := &pinnedSet{roots: x509.NewCertPool()}
	seen := map[string]bool{}
	for _, e := range entries {
		switch {
		case e.CAID == "":
			return errors.New("mtls: a pinned CA has no ca-id")
		case seen[e.CAID]:
			return fmt.Errorf("mtls: ca-id %q is pinned twice", e.CAID)
		case e.Certificate == nil:
			return fmt.Errorf("mtls: pinned CA %q has no certificate", e.CAID)
		case e.SANKind != SANKindURI && e.SANKind != SANKindDNS:
			return fmt.Errorf("mtls: pinned CA %q has san-kind %q", e.CAID, e.SANKind)
		}
		seen[e.CAID] = true
		set.roots.AddCert(e.Certificate)
		set.entries = append(set.entries, e)
	}
	if len(set.entries) == 0 {
		return errors.New("mtls: the pinned CA set is empty")
	}
	a.pinned.Store(set)
	return nil
}

// entry returns the pinned entry whose certificate is c, byte for byte.
func (s *pinnedSet) entry(c *x509.Certificate) (CAEntry, bool) {
	for _, e := range s.entries {
		if bytes.Equal(e.Certificate.Raw, c.Raw) {
			return e, true
		}
	}
	return CAEntry{}, false
}

// byID returns the pinned entry with the ca-id id.
func (s *pinnedSet) byID(id string) (CAEntry, bool) {
	for _, e := range s.entries {
		if e.CAID == id {
			return e, true
		}
	}
	return CAEntry{}, false
}

// errRefused is the internal cause of a refused certificate. It never leaves
// the adapter: the caller answers with a native denial whose public reason is
// CREDENTIAL_REJECTED (draft 13.4).
type errRefused struct{ why string }

func (e errRefused) Error() string { return "certificate refused: " + e.why }

func refused(format string, args ...any) error { return errRefused{fmt.Sprintf(format, args...)} }

// verified is a peer leaf that passed MTLS-3 to MTLS-7.
type verified struct {
	entry    CAEntry
	workload adapter.Workload
}

// verifyLeaf applies MTLS-3 to MTLS-7 to the peer leaf at the instant now,
// with intermediates as path-building input only.
func (a *Adapter) verifyLeaf(leaf *x509.Certificate, intermediates []*x509.Certificate, now time.Time) (verified, error) {
	set := a.pinned.Load()
	if leaf == nil {
		return verified{}, refused("no certificate")
	}
	if err := withinValidity(leaf, now); err != nil {
		return verified{}, err
	}
	pool := x509.NewCertPool()
	for _, c := range intermediates {
		pool.AddCert(c)
	}
	// The baseline skew applies to notBefore only (MTLS-5): a leaf whose
	// notBefore is ahead of now by at most the skew is verified at its
	// notBefore; notAfter was checked at now above.
	at := now
	if leaf.NotBefore.After(now) {
		at = leaf.NotBefore
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots: set.roots, Intermediates: pool, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return verified{}, refused("chain: %v", err)
	}
	var entry CAEntry
	for i, chain := range chains {
		// The issuer of the leaf, the second certificate of every chain, is
		// itself pinned; a pinned certificate presented as the leaf is a
		// chain of one (MTLS-3).
		if len(chain) < 2 {
			return verified{}, refused("a pinned certificate is presented as the leaf")
		}
		e, ok := set.entry(chain[1])
		if !ok {
			return verified{}, refused("the issuer of the leaf is not pinned")
		}
		if i > 0 && e.CAID != entry.CAID {
			return verified{}, refused("the chains name different pinned entries")
		}
		entry = e
	}
	if err := withinValidity(entry.Certificate, now); err != nil {
		return verified{}, refused("issuer: %v", err)
	}
	if err := endEntity(leaf); err != nil {
		return verified{}, err
	}
	name, err := workloadName(leaf, entry.SANKind)
	if err != nil {
		return verified{}, err
	}
	return verified{entry: entry, workload: Identifier(entry.CAID, entry.SANKind, name)}, nil
}

// withinValidity applies MTLS-5: the baseline skew to notBefore, none to
// notAfter.
func withinValidity(c *x509.Certificate, now time.Time) error {
	if c.NotBefore.After(now.Add(clock.BaselineSkew)) {
		return refused("not yet valid")
	}
	if now.After(c.NotAfter) {
		return refused("expired")
	}
	return nil
}

var (
	oidKeyUsage       = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

func extension(c *x509.Certificate, oid asn1.ObjectIdentifier) ([]byte, bool) {
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			return e.Value, true
		}
	}
	return nil, false
}

// endEntity applies MTLS-4: the client-auth purpose listed, no cA, no
// certificate or list signing, and digitalSignature in a key usage extension.
func endEntity(c *x509.Certificate) error {
	clientAuth := false
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if !clientAuth {
		return refused("the extended key usage does not list clientAuth")
	}
	if c.BasicConstraintsValid && c.IsCA {
		return refused("the leaf asserts cA")
	}
	if _, ok := extension(c, oidKeyUsage); ok {
		if c.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
			return refused("the leaf's key usage asserts certificate or list signing")
		}
		if c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return refused("the leaf's key usage lacks digitalSignature")
		}
	}
	return nil
}

// workloadName returns the canonical value of the one subject alternative
// name of the kind kind (MTLS-6, MTLS-7), read from the octets of the
// extension.
func workloadName(c *x509.Certificate, kind SANKind) (string, error) {
	raw, ok := extension(c, oidSubjectAltName)
	if !ok {
		return "", refused("no subject alternative name")
	}
	var names []asn1.RawValue
	rest, err := asn1.Unmarshal(raw, &names)
	if err != nil || len(rest) > 0 {
		return "", refused("malformed subject alternative name")
	}
	tag := 6
	if kind == SANKindDNS {
		tag = 2
	}
	var values []string
	for _, n := range names {
		if n.Class == asn1.ClassContextSpecific && n.Tag == tag {
			values = append(values, string(n.Bytes))
		}
	}
	if len(values) != 1 {
		return "", refused("%d names of kind %s, want exactly one", len(values), kind)
	}
	if kind == SANKindURI {
		return canonicalURI(values[0])
	}
	return canonicalDNS(values[0])
}

// canonicalURI applies MTLS-7 to a URI name: absolute, octets 0x21 to 0x7E
// only, and no normalization.
func canonicalURI(v string) (string, error) {
	for i := 0; i < len(v); i++ {
		if v[i] < 0x21 || v[i] > 0x7E {
			return "", refused("URI name has an octet outside 0x21 to 0x7E")
		}
	}
	scheme, rest, ok := strings.Cut(v, ":")
	if !ok || !isScheme(scheme) || rest == "" {
		return "", refused("URI name is not absolute")
	}
	return v, nil
}

// isScheme reports whether s is a URI scheme (RFC 3986, section 3.1).
func isScheme(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return true
}

// canonicalDNS applies MTLS-7 to a DNS name: lower case, letters, digits,
// hyphen and dot only, no trailing dot, no wildcard.
func canonicalDNS(v string) (string, error) {
	v = ascii.ToLower(v)
	if v == "" || strings.HasSuffix(v, ".") {
		return "", refused("DNS name is empty or ends with a dot")
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' {
			return "", refused("DNS name has a character outside letters, digits, hyphen and dot")
		}
	}
	return v, nil
}

// Identifier returns the workload identifier of MTLS-6:
// mtls:{ca-id}:{san-kind}:{workload-id}, each component written under IM-2.
func Identifier(caID string, kind SANKind, name string) adapter.Workload {
	return adapter.Workload("mtls:" + component(caID) + ":" + string(kind) + ":" + component(name))
}

// component writes every octet that is not unreserved as %XX in upper-case
// hexadecimal (identity-mapping IM-2).
func component(s string) string {
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
