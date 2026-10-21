package scim

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"hop.top/pact-go/internal/ascii"
)

// newID returns a version 4 UUID (RFC 4122) from the system's random source.
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("scim: no random source: " + err.Error())
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// baseURL is the absolute URL of the endpoint root as the client reached it.
func (s *Server) baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + s.cfg.BasePath
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func (s *Server) renderUser(u *user, base string) map[string]any {
	m := map[string]any{
		"schemas":  []string{userURN},
		"id":       u.id,
		"userName": u.userName,
		"meta": map[string]any{
			"resourceType": "User", "created": stamp(u.created), "lastModified": stamp(u.modified),
			"location": base + "/Users/" + u.id,
		},
	}
	if u.externalID != "" {
		m["externalId"] = u.externalID
	}
	if u.displayName != "" {
		m["displayName"] = u.displayName
	}
	if u.active != nil {
		m["active"] = *u.active
	}
	return m
}

// renderGroup lists the members in the order of their ids.
func (s *Server) renderGroup(g *group, base string) map[string]any {
	ids := make([]string, 0, len(g.members))
	for id := range g.members {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	members := make([]any, 0, len(ids))
	for _, id := range ids {
		members = append(members, map[string]any{"value": id, "type": "User", "$ref": base + "/Users/" + id})
	}
	m := map[string]any{
		"schemas":     []string{groupURN},
		"id":          g.id,
		"displayName": g.displayName,
		"members":     members,
		"meta": map[string]any{
			"resourceType": "Group", "created": stamp(g.created), "lastModified": stamp(g.modified),
			"location": base + "/Groups/" + g.id,
		},
	}
	if g.externalID != "" {
		m["externalId"] = g.externalID
	}
	return m
}

func (s *Server) get(w http.ResponseWriter, r *http.Request, kind, id string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	base := s.baseURL(r)
	if kind == "Users" {
		if u, ok := s.users[id]; ok {
			writeJSON(w, http.StatusOK, s.renderUser(u, base))
			return
		}
	} else if g, ok := s.groups[id]; ok {
		writeJSON(w, http.StatusOK, s.renderGroup(g, base))
		return
	}
	writeError(w, errNotFound("resource "+id+" not found"))
}

var filterRE = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9]*)\s+(?i:eq)\s+("(?:[^"\\]|\\.)*")\s*$`)

// listFilter is a filter attribute eq "value" on one attribute.
type listFilter struct {
	attr, value string
}

// parseFilter parses the filter parameter: one equality comparison on one of
// the attributes the service can match.
func parseFilter(raw string, kind string) (*listFilter, error) {
	m := filterRE.FindStringSubmatch(raw)
	if m == nil {
		return nil, newErr(http.StatusBadRequest, "invalidFilter", "the filter is not attribute eq \"value\"")
	}
	var v string
	if err := json.Unmarshal([]byte(m[2]), &v); err != nil {
		return nil, newErr(http.StatusBadRequest, "invalidFilter", "the filter value is not a string")
	}
	attr := ascii.ToLower(m[1])
	ok := attr == "externalid" || kind == "Users" && attr == "username" || kind == "Groups" && attr == "displayname"
	if !ok {
		return nil, newErr(http.StatusBadRequest, "invalidFilter", "the filter attribute "+m[1]+" is not supported")
	}
	return &listFilter{attr: attr, value: v}, nil
}

// intParam reads a non-negative-or-clamped integer query parameter.
func intParam(q map[string][]string, name string, def int64) (int64, error) {
	vs, ok := q[name]
	if !ok {
		return def, nil
	}
	n, err := strconv.ParseInt(vs[0], 10, 32)
	if err != nil {
		return 0, invalidValue("%s is not an integer", name)
	}
	return n, nil
}

func (s *Server) list(w http.ResponseWriter, r *http.Request, kind string) {
	q := r.URL.Query()
	var f *listFilter
	if vs, ok := q["filter"]; ok {
		var err error
		if f, err = parseFilter(vs[0], kind); err != nil {
			writeError(w, err)
			return
		}
	}
	start, err := intParam(q, "startIndex", 1)
	if err != nil {
		writeError(w, err)
		return
	}
	count, err := intParam(q, "count", maxResults)
	if err != nil {
		writeError(w, err)
		return
	}
	start = max(start, 1)
	count = min(max(count, 0), maxResults)

	s.mu.RLock()
	defer s.mu.RUnlock()
	type item struct {
		seq uint64
		res func() map[string]any
	}
	base := s.baseURL(r)
	var items []item
	if kind == "Users" {
		for _, u := range s.users {
			if f == nil || matchUser(f, u) {
				items = append(items, item{u.seq, func() map[string]any { return s.renderUser(u, base) }})
			}
		}
	} else {
		for _, g := range s.groups {
			if f == nil || matchGroup(f, g) {
				items = append(items, item{g.seq, func() map[string]any { return s.renderGroup(g, base) }})
			}
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].seq < items[j].seq })
	page := []any{}
	for i := start - 1; i < int64(len(items)) && int64(len(page)) < count; i++ {
		page = append(page, items[i].res())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schemas": []string{listURN}, "totalResults": len(items), "itemsPerPage": len(page),
		"startIndex": start, "Resources": page,
	})
}

// matchUser compares as RFC 7643 section 4.1.1 gives each attribute:
// userName is case-insensitive, externalId is case-exact.
func matchUser(f *listFilter, u *user) bool {
	if f.attr == "username" {
		return strings.EqualFold(u.userName, f.value)
	}
	return u.externalID != "" && u.externalID == f.value
}

func matchGroup(f *listFilter, g *group) bool {
	if f.attr == "displayname" {
		return strings.EqualFold(g.displayName, f.value)
	}
	return g.externalID != "" && g.externalID == f.value
}

func (s *Server) create(w http.ResponseWriter, r *http.Request, kind string) {
	body, err := readBody(w, r)
	if err != nil {
		writeError(w, err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	base := s.baseURL(r)
	var res map[string]any
	if kind == "Users" {
		var u *user
		if u, err = s.createUser(body); err == nil {
			res = s.renderUser(u, base)
		}
	} else {
		var g *group
		if g, err = s.createGroup(body); err == nil {
			res = s.renderGroup(g, base)
		}
	}
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Location", res["meta"].(map[string]any)["location"].(string))
	writeJSON(w, http.StatusCreated, res)
}

// objectOf checks that v is a JSON object that names schema.
func objectOf(v any, schema string) (map[string]any, error) {
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, newErr(http.StatusBadRequest, "invalidSyntax", "the request body is not a JSON object")
	}
	list, ok := obj["schemas"].([]any)
	if !ok {
		return nil, invalidValue("schemas is not a list")
	}
	for _, e := range list {
		if e == schema {
			return obj, nil
		}
	}
	return nil, invalidValue("schemas does not list %s", schema)
}

// optString reads an optional string attribute; null is not asserted.
func optString(obj map[string]any, name string) (string, error) {
	v, ok := obj[name]
	if !ok || v == nil {
		return "", nil
	}
	str, ok := v.(string)
	if !ok {
		return "", invalidValue("%s is not a string", name)
	}
	return str, nil
}

// createUser runs with s.mu held for writing.
func (s *Server) createUser(body any) (*user, error) {
	obj, err := objectOf(body, userURN)
	if err != nil {
		return nil, err
	}
	u := &user{id: newID(), seq: s.nextSeq(), created: s.now()}
	u.modified = u.created
	if u.userName, err = optString(obj, "userName"); err != nil {
		return nil, err
	}
	if u.userName == "" {
		return nil, invalidValue("userName is required")
	}
	if u.externalID, err = optString(obj, "externalId"); err != nil {
		return nil, err
	}
	if u.displayName, err = optString(obj, "displayName"); err != nil {
		return nil, err
	}
	if v, ok := obj["active"]; ok && v != nil {
		b, ok := v.(bool)
		if !ok {
			return nil, invalidValue("active is not a boolean")
		}
		u.active = &b
	}
	if err := s.checkUserUnique(u); err != nil {
		return nil, err
	}
	s.addUser(u)
	if err := s.publish(u); err != nil {
		if u.principal != "" {
			_ = s.cfg.Store.Delete(contextBackground, u.principal)
		}
		s.dropUser(u)
		return nil, errInternal(err)
	}
	return u, nil
}

// createGroup runs with s.mu held for writing.
func (s *Server) createGroup(body any) (*group, error) {
	obj, err := objectOf(body, groupURN)
	if err != nil {
		return nil, err
	}
	g := &group{id: newID(), seq: s.nextSeq(), created: s.now(), members: map[string]struct{}{}}
	g.modified = g.created
	if g.displayName, err = optString(obj, "displayName"); err != nil {
		return nil, err
	}
	if g.displayName == "" {
		return nil, invalidValue("displayName is required")
	}
	if g.externalID, err = optString(obj, "externalId"); err != nil {
		return nil, err
	}
	if err := s.checkGroupUnique(g); err != nil {
		return nil, err
	}
	var members []string
	if v, ok := obj["members"]; ok && v != nil {
		if members, err = parseMembers(v); err != nil {
			return nil, err
		}
		if err := s.checkMembers(members); err != nil {
			return nil, err
		}
	}
	s.groups[g.id] = g
	if g.externalID != "" {
		s.groupExt[g.externalID] = g.id
	}
	changed := map[string]struct{}{}
	for _, m := range members {
		s.link(m, g.id)
		changed[m] = struct{}{}
	}
	s.noteGroup(g)
	if err := s.publishAll(changed); err != nil {
		for m := range changed {
			s.unlink(m, g.id)
		}
		_ = s.publishAll(changed)
		delete(s.groups, g.id)
		delete(s.groupExt, g.externalID)
		return nil, errInternal(err)
	}
	return g, nil
}

// noteGroup logs a group that has members but no externalId: its members get
// no group id from it.
func (s *Server) noteGroup(g *group) {
	if g.externalID == "" && len(g.members) > 0 {
		s.logf("scim: group %s has no externalId and contributes no group id to its members", g.id)
	}
}

// parseMembers reads a members value: a list of objects, or one object, each
// with a string value.
func parseMembers(v any) ([]string, error) {
	var list []any
	switch t := v.(type) {
	case []any:
		list = t
	case map[string]any:
		list = []any{t}
	default:
		return nil, invalidValue("members is not a list of members")
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, invalidValue("a member is not an object")
		}
		id, ok := m["value"].(string)
		if !ok || id == "" {
			return nil, invalidValue("a member has no value")
		}
		out = append(out, id)
	}
	return out, nil
}

// checkMembers requires every id to be a user of this service. A group is not
// a member: nested groups are not provisioned.
func (s *Server) checkMembers(ids []string) error {
	for _, id := range ids {
		if _, ok := s.users[id]; !ok {
			if _, isGroup := s.groups[id]; isGroup {
				return invalidValue("member %q is a group: nested groups are not supported", id)
			}
			return invalidValue("member %q is not a User of this service", id)
		}
	}
	return nil
}

func (s *Server) remove(w http.ResponseWriter, kind, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if kind == "Users" {
		err = s.deleteUser(id)
	} else {
		err = s.deleteGroup(id)
	}
	if err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// deleteUser removes the user's facts first: if the store cannot, the record
// stays and a retry can finish the delete.
func (s *Server) deleteUser(id string) error {
	u, ok := s.users[id]
	if !ok {
		return errNotFound("resource " + id + " not found")
	}
	if u.principal != "" {
		if err := s.cfg.Store.Delete(contextBackground, u.principal); err != nil {
			return errInternal(err)
		}
	}
	s.dropUser(u)
	return nil
}

func (s *Server) deleteGroup(id string) error {
	g, ok := s.groups[id]
	if !ok {
		return errNotFound("resource " + id + " not found")
	}
	changed := map[string]struct{}{}
	for m := range g.members {
		changed[m] = struct{}{}
	}
	for m := range changed {
		s.unlink(m, id)
	}
	delete(s.groups, id)
	if g.externalID != "" {
		delete(s.groupExt, g.externalID)
	}
	if err := s.publishAll(changed); err != nil {
		// The members' facts may still list the group: put the group back so
		// that a retry of the delete finishes the job.
		s.groups[id] = g
		if g.externalID != "" {
			s.groupExt[g.externalID] = id
		}
		for m := range changed {
			s.link(m, id)
		}
		_ = s.publishAll(changed)
		return errInternal(err)
	}
	return nil
}
