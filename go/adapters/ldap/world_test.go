package ldap_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"slices"
	"strings"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core/strictjson"
)

// ldapModel is the model of the native state of the LDAP cases, defined in
// spec/v1.0/fixtures/adapters/ldap/README.md.
const ldapModel = "ldap/1"

// casesDir is the directory of the LDAP cases in the fixture tree; the seed
// and change paths of a state are relative to it.
const casesDir = "adapters/ldap"

// hookDirectory is the native hook an LDAP harness fires each time the adapter
// opens a connection to a directory server.
const hookDirectory = "directory"

// permissionSource is the source id of the native permissions of ldap/1.
const permissionSource = "inventory-permissions"

// The kinds of a realm (profile Appendix A).
const (
	kindOpenLDAP = "openldap"
	kindAD       = "activedirectory"
)

// ldapState is the ldap/1 native state of a case.
type ldapState struct {
	Model       string              `json:"model"`
	Gateway     memory.Gateway      `json:"gateway"`
	LoginRealm  string              `json:"login_realm"`
	Directories []directoryState    `json:"directories"`
	Realms      []realmState        `json:"realms"`
	Credentials []credential        `json:"credentials"`
	Enrollments []memory.Enrollment `json:"enrollments"`
	Permissions []permission        `json:"permissions"`
	Execution   *execution          `json:"execution"`
	Reporting   *memory.Reporting   `json:"reporting"`
}

// directoryState is one directory server of a case.
type directoryState struct {
	Name        string       `json:"name"`
	Seed        string       `json:"seed"`
	Changes     []string     `json:"changes"`
	Unreachable bool         `json:"unreachable"`
	TLSFails    bool         `json:"tls_fails"`
	InChain     *bool        `json:"in_chain"`
	Hidden      []hiddenRule `json:"hidden"`
}

// hiddenRule is what the access control of a server withholds from the
// lookup account under Base, silently.
type hiddenRule struct {
	Base       string   `json:"base"`
	Attributes []string `json:"attributes"`
	Entries    bool     `json:"entries"`
}

// realmState is a realm record of profile Appendix A.
type realmState struct {
	RealmID          string   `json:"realm_id"`
	Kind             string   `json:"kind"`
	Directory        string   `json:"directory"`
	UniqueIDText     string   `json:"unique_id_text"`
	UserBases        []string `json:"user_bases"`
	GroupBases       []string `json:"group_bases"`
	AccountClass     string   `json:"account_class"`
	GroupClass       string   `json:"group_class"`
	LoginAttribute   string   `json:"login_attribute"`
	Lookup           lookup   `json:"lookup"`
	DeniedPrincipals []string `json:"denied_principals"`
	Sentinel         sentinel `json:"sentinel"`
	DirectGroups     bool     `json:"direct_groups"`
	Nested           string   `json:"nested"`
}

type lookup struct {
	DN       string `json:"dn"`
	Password string `json:"password"`
}

type sentinel struct {
	Account     string `json:"account"`
	Group       string `json:"group"`
	ParentGroup string `json:"parent_group"`
}

// credential is what a client holds: a login name and a password.
type credential struct {
	Ref      string `json:"ref"`
	UserID   string `json:"user_id"`
	Password string `json:"password"`
}

// permission allows one principal one action on one resource.
type permission struct {
	Principal string `json:"principal"`
	Action    string `json:"action"`
	Resource  string `json:"resource"`
}

// execution is what the deployment's executor source reports.
type execution struct {
	RunningIdentity string `json:"running_identity"`
}

// world is a parsed ldap/1 state with its directory servers built.
type world struct {
	st      ldapState
	servers map[string]*server
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

// loadWorld parses an ldap/1 state strictly and builds each directory server
// from its seed and its changes in the fixture tree.
func loadWorld(raw []byte, fsys fs.FS) (*world, error) {
	var st ldapState
	if err := strictjson.Unmarshal(raw, strictjson.Limits{}, &st); err != nil {
		return nil, fmt.Errorf("ldap/1 state: %w", err)
	}
	if st.Model != ldapModel {
		return nil, fmt.Errorf("model is %q, want %q", st.Model, ldapModel)
	}
	if st.Gateway.TenantID == "" || st.Gateway.EnvironmentID == "" || st.Gateway.Origin == "" {
		return nil, errors.New("ldap/1 state: gateway needs a tenant_id, an environment_id and an origin")
	}
	w := &world{st: st, servers: map[string]*server{}}
	for _, d := range st.Directories {
		if d.Name == "" || w.servers[d.Name] != nil {
			return nil, fmt.Errorf("ldap/1 state: directory name %q is empty or used twice", d.Name)
		}
		srv, err := buildServer(fsys, d)
		if err != nil {
			return nil, fmt.Errorf("directory %s: %w", d.Name, err)
		}
		w.servers[d.Name] = srv
	}
	ids := map[string]bool{}
	for _, r := range st.Realms {
		switch {
		case r.RealmID == "" || ids[r.RealmID]:
			return nil, fmt.Errorf("ldap/1 state: realm_id %q is empty or used twice", r.RealmID)
		case w.servers[r.Directory] == nil:
			return nil, fmt.Errorf("realm %s: no directory %q", r.RealmID, r.Directory)
		case r.Kind != kindOpenLDAP && r.Kind != kindAD:
			return nil, fmt.Errorf("realm %s: kind %q", r.RealmID, r.Kind)
		case r.Nested != "none" && r.Nested != "ad-chain":
			return nil, fmt.Errorf("realm %s: nested %q", r.RealmID, r.Nested)
		case len(r.UserBases) == 0 || len(r.GroupBases) == 0 || r.LoginAttribute == "" || r.Lookup.DN == "" || r.Sentinel.Account == "":
			return nil, fmt.Errorf("realm %s is incomplete", r.RealmID)
		}
		ids[r.RealmID] = true
		w.servers[r.Directory].kind = r.Kind
	}
	if !ids[st.LoginRealm] {
		return nil, fmt.Errorf("ldap/1 state: login_realm %q is not a realm", st.LoginRealm)
	}
	refs := map[string]bool{}
	for _, c := range st.Credentials {
		if c.Ref == "" || refs[c.Ref] {
			return nil, fmt.Errorf("ldap/1 state: credential ref %q is empty or used twice", c.Ref)
		}
		refs[c.Ref] = true
	}
	return w, nil
}

// realm returns the realm record of id.
func (w *world) realm(id string) (realmState, bool) {
	for _, r := range w.st.Realms {
		if r.RealmID == id {
			return r, true
		}
	}
	return realmState{}, false
}

// pactRealm is the PACT realm of the gateway, which every directory realm of
// the world belongs to.
func (w *world) pactRealm() adapter.Realm {
	return adapter.Realm{TenantID: w.st.Gateway.TenantID, EnvironmentID: w.st.Gateway.EnvironmentID}
}

// commonState returns the common/1 state of the enrollments of the world, for
// the reference enrollment source.
func (w *world) commonState() memory.State {
	return memory.State{Model: memory.Model, Gateway: w.st.Gateway, Enrollments: w.st.Enrollments}
}

// basicCredential is the Authorization value of user-id and password
// (RFC 7617, section 2).
func basicCredential(userID, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(userID+":"+password))
}

// attachCredential sets the credential of ref from creds on r, unless r
// already carries an Authorization header.
func attachCredential(creds []credential, r *http.Request, ref string) error {
	for _, c := range creds {
		if c.Ref != ref {
			continue
		}
		if r.Header.Get("Authorization") == "" {
			r.Header.Set("Authorization", basicCredential(c.UserID, c.Password))
		}
		return nil
	}
	return fmt.Errorf("no credential %q", ref)
}

// fixtures is the fixture tree of the source repository.
func fixtures() (fs.FS, error) { return adaptertest.DefaultFixtures() }

// server is a directory server of a case: the entries of its seed after its
// changes, with memberOf derived from the member values of the groups.
type server struct {
	kind    string
	state   directoryState
	entries []*entry
}

// entry is one directory entry.
type entry struct {
	dn    string
	attrs []attribute
}

// attribute is one attribute of an entry, with its values in order.
type attribute struct {
	name   string
	values [][]byte
}

// normDN is the key under which the fixture server finds an entry: the DN in
// lower case. The seeds write every DN in one spelling, so this is enough to
// tell entries apart; it is not distinguishedNameMatch.
func normDN(dn string) string { return strings.ToLower(strings.TrimSpace(dn)) }

// get returns the values of the attribute name, compared case-insensitively.
func (e *entry) get(name string) [][]byte {
	for _, a := range e.attrs {
		if strings.EqualFold(a.name, name) {
			return a.values
		}
	}
	return nil
}

// first returns the first value of the attribute name as text.
func (e *entry) first(name string) string {
	if v := e.get(name); len(v) > 0 {
		return string(v[0])
	}
	return ""
}

// has reports whether the attribute name has value v, compared
// case-insensitively.
func (e *entry) has(name, v string) bool {
	for _, x := range e.get(name) {
		if strings.EqualFold(string(x), v) {
			return true
		}
	}
	return false
}

func (e *entry) set(name string, values [][]byte) {
	for i := range e.attrs {
		if strings.EqualFold(e.attrs[i].name, name) {
			if len(values) == 0 {
				e.attrs = slices.Delete(e.attrs, i, i+1)
			} else {
				e.attrs[i].values = values
			}
			return
		}
	}
	if len(values) > 0 {
		e.attrs = append(e.attrs, attribute{name: name, values: values})
	}
}

// buildServer reads the seed and the changes of d from the fixture tree.
func buildServer(fsys fs.FS, d directoryState) (*server, error) {
	srv := &server{state: d}
	records, err := readLDIF(fsys, d.Seed)
	if err != nil {
		return nil, err
	}
	for _, rec := range records {
		if rec.changeType != "" {
			return nil, fmt.Errorf("seed %s: %s is a change record", d.Seed, rec.dn)
		}
		if srv.find(rec.dn) != nil {
			return nil, fmt.Errorf("seed %s: %s twice", d.Seed, rec.dn)
		}
		srv.entries = append(srv.entries, &entry{dn: rec.dn, attrs: rec.attrs})
	}
	for _, p := range d.Changes {
		changes, err := readLDIF(fsys, p)
		if err != nil {
			return nil, err
		}
		for _, rec := range changes {
			if err := srv.apply(rec); err != nil {
				return nil, fmt.Errorf("changes %s: %w", p, err)
			}
		}
	}
	srv.deriveMemberOf()
	return srv, nil
}

// readLDIF parses an LDIF file of the fixture tree, relative to the cases
// directory.
func readLDIF(fsys fs.FS, p string) ([]ldifRecord, error) {
	if p == "" || path.IsAbs(p) || strings.Contains(p, "..") {
		return nil, fmt.Errorf("%q is not a path inside %s", p, casesDir)
	}
	data, err := fs.ReadFile(fsys, path.Join(casesDir, p))
	if err != nil {
		return nil, err
	}
	recs, err := parseLDIF(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return recs, nil
}

// find returns the entry of dn, or nil.
func (s *server) find(dn string) *entry {
	k := normDN(dn)
	for _, e := range s.entries {
		if normDN(e.dn) == k {
			return e
		}
	}
	return nil
}

// apply applies one change record (RFC 2849).
func (s *server) apply(rec ldifRecord) error {
	switch rec.changeType {
	case "add", "":
		if s.find(rec.dn) != nil {
			return fmt.Errorf("add %s: entry exists", rec.dn)
		}
		s.entries = append(s.entries, &entry{dn: rec.dn, attrs: rec.attrs})
	case "delete":
		k := normDN(rec.dn)
		i := slices.IndexFunc(s.entries, func(e *entry) bool { return normDN(e.dn) == k })
		if i < 0 {
			return fmt.Errorf("delete %s: no such entry", rec.dn)
		}
		s.entries = slices.Delete(s.entries, i, i+1)
	case "modify":
		e := s.find(rec.dn)
		if e == nil {
			return fmt.Errorf("modify %s: no such entry", rec.dn)
		}
		for _, m := range rec.mods {
			cur := e.get(m.attr)
			switch m.op {
			case "add":
				e.set(m.attr, append(slices.Clone(cur), m.values...))
			case "replace":
				e.set(m.attr, m.values)
			case "delete":
				if len(m.values) == 0 {
					e.set(m.attr, nil)
					continue
				}
				kept := slices.DeleteFunc(slices.Clone(cur), func(v []byte) bool {
					return slices.ContainsFunc(m.values, func(d []byte) bool { return strings.EqualFold(string(d), string(v)) })
				})
				e.set(m.attr, kept)
			}
		}
	default:
		return fmt.Errorf("%s: changetype %q is not supported", rec.dn, rec.changeType)
	}
	return nil
}

// deriveMemberOf sets memberOf of every entry to the DNs of the groups whose
// member values name it, as the memberof overlay and Active Directory do.
func (s *server) deriveMemberOf() {
	for _, e := range s.entries {
		e.set("memberOf", nil)
	}
	for _, g := range s.entries {
		for _, m := range g.get("member") {
			if e := s.find(string(m)); e != nil {
				e.set("memberOf", append(e.get("memberOf"), []byte(g.dn)))
			}
		}
	}
}

// uniqueID returns the unique id of e as identifier text: entryUUID for an
// OpenLDAP server, objectGUID in RFC 4122 octet order for Active Directory.
func (s *server) uniqueID(e *entry) string {
	if s.kind == kindAD {
		v := e.get("objectGUID")
		if len(v) == 0 || len(v[0]) != 16 {
			return ""
		}
		b := v[0]
		return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	}
	return strings.ToLower(e.first("entryUUID"))
}

// byUniqueID returns the entry whose unique id is id.
func (s *server) byUniqueID(id string) *entry {
	for _, e := range s.entries {
		if s.uniqueID(e) == strings.ToLower(id) {
			return e
		}
	}
	return nil
}

// ldifRecord is one record of an LDIF file: a content record, or a change
// record with its changetype.
type ldifRecord struct {
	dn         string
	changeType string
	attrs      []attribute
	mods       []ldifMod
}

// ldifMod is one mod-spec of a modify record.
type ldifMod struct {
	op     string
	attr   string
	values [][]byte
}

// parseLDIF parses the subset of RFC 2849 that the fixture assets use:
// version 1, comments, folded lines, SAFE-STRING and base64 values, content
// records, and add, delete and modify change records. A URL value, a control
// and a moddn record are errors.
func parseLDIF(data []byte) ([]ldifRecord, error) {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	var lines []string
	for _, l := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(l, "#"):
			continue
		case strings.HasPrefix(l, " ") && len(lines) > 0 && lines[len(lines)-1] != "":
			lines[len(lines)-1] += l[1:]
		default:
			lines = append(lines, l)
		}
	}
	var out []ldifRecord
	var block [][2]string
	flush := func() error {
		if len(block) == 0 {
			return nil
		}
		rec, err := ldifBlock(block)
		block = nil
		if err != nil {
			return err
		}
		out = append(out, rec)
		return nil
	}
	versionSeen := false
	for _, l := range lines {
		if l == "" {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		if l == "-" {
			block = append(block, [2]string{"-", ""})
			continue
		}
		name, value, err := ldifLine(l)
		if err != nil {
			return nil, err
		}
		if !versionSeen && len(out) == 0 && len(block) == 0 && name == "version" {
			if value != "1" {
				return nil, fmt.Errorf("version %q", value)
			}
			versionSeen = true
			continue
		}
		block = append(block, [2]string{name, value})
	}
	if err := flush(); err != nil {
		return nil, err
	}
	if !versionSeen {
		return nil, errors.New("no version line")
	}
	return out, nil
}

// ldifLine splits one attrval-spec into its description and its decoded
// value.
func ldifLine(l string) (string, string, error) {
	name, rest, ok := strings.Cut(l, ":")
	if !ok || name == "" {
		return "", "", fmt.Errorf("line %q has no attribute description", l)
	}
	switch {
	case strings.HasPrefix(rest, ":"):
		v, err := base64.StdEncoding.DecodeString(strings.TrimLeft(rest[1:], " "))
		if err != nil {
			return "", "", fmt.Errorf("%s: %w", name, err)
		}
		return name, string(v), nil
	case strings.HasPrefix(rest, "<"):
		return "", "", fmt.Errorf("%s: URL values are not supported", name)
	}
	return name, strings.TrimLeft(rest, " "), nil
}

// ldifBlock builds a record from the lines of one block.
func ldifBlock(block [][2]string) (ldifRecord, error) {
	if block[0][0] != "dn" || block[0][1] == "" {
		return ldifRecord{}, fmt.Errorf("record does not start with a dn: %q", block[0][0])
	}
	rec := ldifRecord{dn: block[0][1]}
	rest := block[1:]
	if len(rest) > 0 && strings.EqualFold(rest[0][0], "changetype") {
		rec.changeType = rest[0][1]
		rest = rest[1:]
	}
	switch rec.changeType {
	case "", "add":
		for _, kv := range rest {
			if kv[0] == "-" || strings.EqualFold(kv[0], "control") {
				return ldifRecord{}, fmt.Errorf("%s: unexpected %q", rec.dn, kv[0])
			}
			rec.attrs = appendValue(rec.attrs, kv[0], kv[1])
		}
	case "delete":
		if len(rest) > 0 {
			return ldifRecord{}, fmt.Errorf("%s: delete record with attributes", rec.dn)
		}
	case "modify":
		var cur *ldifMod
		for _, kv := range rest {
			switch {
			case kv[0] == "-":
				if cur == nil {
					return ldifRecord{}, fmt.Errorf("%s: stray -", rec.dn)
				}
				rec.mods = append(rec.mods, *cur)
				cur = nil
			case cur == nil:
				if kv[0] != "add" && kv[0] != "delete" && kv[0] != "replace" {
					return ldifRecord{}, fmt.Errorf("%s: mod-spec %q", rec.dn, kv[0])
				}
				cur = &ldifMod{op: kv[0], attr: kv[1]}
			case strings.EqualFold(kv[0], cur.attr):
				cur.values = append(cur.values, []byte(kv[1]))
			default:
				return ldifRecord{}, fmt.Errorf("%s: value of %s inside a mod-spec of %s", rec.dn, kv[0], cur.attr)
			}
		}
		if cur != nil {
			return ldifRecord{}, fmt.Errorf("%s: mod-spec without -", rec.dn)
		}
	default:
		return ldifRecord{}, fmt.Errorf("%s: changetype %q is not supported", rec.dn, rec.changeType)
	}
	return rec, nil
}

func appendValue(attrs []attribute, name, value string) []attribute {
	for i := range attrs {
		if strings.EqualFold(attrs[i].name, name) {
			attrs[i].values = append(attrs[i].values, []byte(value))
			return attrs
		}
	}
	return append(attrs, attribute{name: name, values: [][]byte{[]byte(value)}})
}
