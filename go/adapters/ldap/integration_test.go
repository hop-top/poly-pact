package ldap_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/fs"
	neturl "net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapters/ldap"
)

// The environment of the integration tier. Without envURL the tier is
// skipped; with it, the other three are required.
const (
	// envURL is the server: ldaps://host:port, or ldap://host:port with
	// StartTLS.
	envURL = "PACT_TEST_LDAP_URL"
	// envCA is a PEM file of the certificate that anchors the server's.
	envCA = "PACT_TEST_LDAP_CA"
	// envAdminDN and envAdminPassword are an account that may write the
	// suffix and set entryUUID with the Relax Rules control, such as the
	// root DN of the database.
	envAdminDN       = "PACT_TEST_LDAP_ADMIN_DN"
	envAdminPassword = "PACT_TEST_LDAP_ADMIN_PASSWORD"
)

// seedSuffix is the suffix of seed.ldif.
const seedSuffix = "dc=northstar,dc=example"

// relaxOID is the control the OpenLDAP 2.6 client tools send for "-e relax"
// (the Relax Rules control of draft-zeilenga-ldap-relax, whose OID the draft
// leaves to IANA). With it the root DN may set entryUUID on add, which keeps
// the identifiers the cases expect.
const relaxOID = "1.3.6.1.4.1.4203.666.5.12"

// TestIntegration runs the LDAP cases that a single OpenLDAP 2.6 server can
// realize against the server at $PACT_TEST_LDAP_URL. Before each case it
// restores the seed and applies the case's changes. The server loads the
// memberof and ppolicy overlays, and its access control lets the lookup
// accounts of the seed read every entry and attribute of the suffix except
// userPassword. Cases that need an Active Directory realm, or a server
// behavior stated by tls_fails, in_chain or hidden, run in the unit tier
// only, and the common cases run against the unit tier's fake.
func TestIntegration(t *testing.T) {
	url := os.Getenv(envURL)
	if url == "" {
		t.Skip(envURL + " is not set; the integration tier needs an OpenLDAP 2.6 server")
	}
	it, err := newIntegration(url)
	if err != nil {
		t.Fatal(err)
	}
	adaptertest.Run(t, it.factory, adaptertest.Options{Adapter: "ldap", Replaced: replaced})
}

type integration struct {
	url, adminDN, adminPassword string
	tls                         *tls.Config
}

func newIntegration(url string) (*integration, error) {
	it := &integration{url: url, adminDN: os.Getenv(envAdminDN), adminPassword: os.Getenv(envAdminPassword)}
	if it.adminDN == "" || it.adminPassword == "" || os.Getenv(envCA) == "" {
		return nil, fmt.Errorf("%s needs %s, %s and %s", envURL, envCA, envAdminDN, envAdminPassword)
	}
	pem, err := os.ReadFile(os.Getenv(envCA))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no certificate", envCA)
	}
	u, err := neturl.Parse(url)
	if err != nil {
		return nil, err
	}
	it.tls = &tls.Config{RootCAs: pool, ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}
	return it, nil
}

// hookedServer fires the directory hook and opens the real server.
type hookedServer struct {
	srv   ldap.Server
	hooks *adaptertest.Hooks
}

func (h hookedServer) Open(ctx context.Context) (ldap.Session, error) {
	h.hooks.Fire(hookDirectory)
	return h.srv.Open(ctx)
}

func (it *integration) factory(tb testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	if model != ldapModel {
		return ldapFactory(tb, env)
	}
	fsys, err := fixtures()
	if err != nil {
		return adaptertest.Subject{}, err
	}
	w, err := loadWorld(env.State, fsys)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	if reason := unitOnly(w); reason != "" {
		tb.Skip("unit tier only: " + reason)
	}
	for _, d := range w.st.Directories {
		if !d.Unreachable {
			if err := it.reset(fsys, d); err != nil {
				return adaptertest.Subject{}, fmt.Errorf("restoring %s: %w", d.Name, err)
			}
		}
	}
	return ldapSubject(env, func(srv *server) ldap.Directory {
		s := ldap.Server{URL: it.url, TLS: it.tls, Timeout: 5 * time.Second}
		if srv.state.Unreachable {
			s.URL = "ldaps://127.0.0.1:1"
		}
		return hookedServer{srv: s, hooks: env.Hooks}
	})
}

// unitOnly says why a world needs the unit tier, or "".
func unitOnly(w *world) string {
	for _, r := range w.st.Realms {
		if r.Kind != kindOpenLDAP {
			return "an " + r.Kind + " realm"
		}
	}
	for _, d := range w.st.Directories {
		switch {
		case d.TLSFails:
			return "tls_fails"
		case d.InChain != nil:
			return "in_chain"
		case len(d.Hidden) > 0:
			return "hidden"
		}
	}
	return ""
}

// admin opens an admin connection over the protected transport.
func (it *integration) admin() (*goldap.Conn, error) {
	conn, err := goldap.DialURL(it.url, goldap.DialWithTLSConfig(it.tls))
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(it.url, "ldap://") {
		if err := conn.StartTLS(it.tls); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	if err := conn.Bind(it.adminDN, it.adminPassword); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// reset deletes every entry of the suffix, adds the seed with the Relax Rules
// control, and applies the changes of d.
func (it *integration) reset(fsys fs.FS, d directoryState) error {
	conn, err := it.admin()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	res, err := conn.Search(goldap.NewSearchRequest(seedSuffix, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"1.1"}, nil))
	if err != nil && !goldap.IsErrorWithCode(err, goldap.LDAPResultNoSuchObject) {
		return err
	}
	if res != nil {
		dns := make([]string, 0, len(res.Entries))
		for _, e := range res.Entries {
			dns = append(dns, e.DN)
		}
		// Children before parents: more RDNs first.
		slices.SortFunc(dns, func(a, b string) int { return strings.Count(b, ",") - strings.Count(a, ",") })
		for _, dn := range dns {
			if err := conn.Del(goldap.NewDelRequest(dn, nil)); err != nil {
				return fmt.Errorf("delete %s: %w", dn, err)
			}
		}
	}
	seed, err := readLDIF(fsys, d.Seed)
	if err != nil {
		return err
	}
	relax := []goldap.Control{goldap.NewControlString(relaxOID, true, "")}
	for _, rec := range seed {
		req := goldap.NewAddRequest(rec.dn, relax)
		for _, a := range rec.attrs {
			req.Attribute(a.name, strs(a.values))
		}
		if err := conn.Add(req); err != nil {
			return fmt.Errorf("add %s: %w", rec.dn, err)
		}
	}
	for _, p := range d.Changes {
		changes, err := readLDIF(fsys, p)
		if err != nil {
			return err
		}
		for _, rec := range changes {
			if err := applyChange(conn, rec); err != nil {
				return fmt.Errorf("%s: %s: %w", p, rec.dn, err)
			}
		}
	}
	return nil
}

func applyChange(conn *goldap.Conn, rec ldifRecord) error {
	switch rec.changeType {
	case "delete":
		return conn.Del(goldap.NewDelRequest(rec.dn, nil))
	case "modify":
		req := goldap.NewModifyRequest(rec.dn, nil)
		for _, m := range rec.mods {
			switch m.op {
			case "add":
				req.Add(m.attr, strs(m.values))
			case "delete":
				req.Delete(m.attr, strs(m.values))
			case "replace":
				req.Replace(m.attr, strs(m.values))
			}
		}
		return conn.Modify(req)
	}
	return fmt.Errorf("changetype %q is not supported", rec.changeType)
}

func strs(v [][]byte) []string {
	out := make([]string, len(v))
	for i, b := range v {
		out[i] = string(b)
	}
	return out
}
