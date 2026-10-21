package scim

import (
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"hop.top/pact-go/internal/ascii"
)

// patchOp is one operation of a PatchOp message (RFC 7644 section 3.5.2).
type patchOp struct {
	op       string // add, remove or replace
	path     string
	value    any
	hasValue bool
}

// memberFilterRE is a members path with a value filter,
// members[value eq "id"] (RFC 7644 section 3.5.2.2), in any letter case
// outside the quoted value.
var memberFilterRE = regexp.MustCompile(`(?i)^members\[\s*value\s+eq\s+("(?:[^"\\]|\\.)*")\s*\]$`)

// parsePatch checks the envelope of a PatchOp message and returns its
// operations. The op values are case-insensitive: the provisioning client
// sends Add, Replace and Remove.
func parsePatch(body any) ([]patchOp, error) {
	obj, ok := body.(map[string]any)
	if !ok {
		return nil, newErr(http.StatusBadRequest, "invalidSyntax", "the request body is not a JSON object")
	}
	has := false
	if list, ok := obj["schemas"].([]any); ok {
		for _, e := range list {
			has = has || e == patchURN
		}
	}
	if !has {
		return nil, newErr(http.StatusBadRequest, "invalidSyntax", "schemas does not list "+patchURN)
	}
	list, ok := obj["Operations"].([]any)
	if !ok || len(list) == 0 {
		return nil, newErr(http.StatusBadRequest, "invalidSyntax", "Operations is not a list of one or more operations")
	}
	ops := make([]patchOp, 0, len(list))
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, newErr(http.StatusBadRequest, "invalidSyntax", "an operation is not an object")
		}
		name, _ := m["op"].(string)
		name = ascii.ToLower(name)
		if name != "add" && name != "remove" && name != "replace" {
			return nil, newErr(http.StatusBadRequest, "invalidSyntax", "op is not add, remove or replace")
		}
		op := patchOp{op: name}
		if p, present := m["path"]; present && p != nil {
			if op.path, ok = p.(string); !ok {
				return nil, newErr(http.StatusBadRequest, "invalidPath", "path is not a string")
			}
		}
		op.value, op.hasValue = m["value"]
		ops = append(ops, op)
	}
	return ops, nil
}

// stripSchema removes a leading core schema URN from an attribute name
// (RFC 7644 section 3.10).
func stripSchema(attr, schema string) string {
	if len(attr) > len(schema) && ascii.EqualFold(attr[:len(schema)+1], schema+":") {
		return attr[len(schema)+1:]
	}
	return attr
}

func (s *Server) patch(w http.ResponseWriter, r *http.Request, kind, id string) {
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
		u, ok := s.users[id]
		if !ok {
			writeError(w, errNotFound("resource "+id+" not found"))
			return
		}
		if err = s.patchUser(u, body); err == nil {
			res = s.renderUser(u, base)
		}
	} else {
		g, ok := s.groups[id]
		if !ok {
			writeError(w, errNotFound("resource "+id+" not found"))
			return
		}
		if err = s.patchGroup(g, body); err == nil {
			res = s.renderGroup(g, base)
		}
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// patchUser applies a PatchOp to u as a whole or not at all (RFC 7644
// section 3.5.2) and publishes the user's facts.
func (s *Server) patchUser(u *user, body any) error {
	ops, err := parsePatch(body)
	if err != nil {
		return err
	}
	nu := *u
	for _, op := range ops {
		if err := applyUserOp(&nu, op); err != nil {
			return err
		}
	}
	if err := s.checkUserUnique(&nu); err != nil {
		return err
	}
	if !sameUser(u, &nu) {
		delete(s.userNames, strings.ToLower(u.userName))
		if u.externalID != "" {
			delete(s.userExt, u.externalID)
		}
		nu.modified = s.now()
		*u = nu
		s.userNames[strings.ToLower(u.userName)] = u.id
		if u.externalID != "" {
			s.userExt[u.externalID] = u.id
		}
	}
	if err := s.publish(u); err != nil {
		return errInternal(err)
	}
	return nil
}

func sameUser(a, b *user) bool {
	same := a.active == nil && b.active == nil || a.active != nil && b.active != nil && *a.active == *b.active
	return same && a.userName == b.userName && a.externalID == b.externalID && a.displayName == b.displayName
}

func applyUserOp(u *user, op patchOp) error {
	if op.path == "" {
		obj, err := pathlessObject(op)
		if err != nil {
			return err
		}
		for _, k := range sortedKeys(obj) {
			if err := setUserAttr(u, ascii.ToLower(stripSchema(k, userURN)), obj[k], false); err != nil {
				return err
			}
		}
		return nil
	}
	attr := ascii.ToLower(stripSchema(op.path, userURN))
	if op.op == "remove" {
		return setUserAttr(u, attr, nil, true)
	}
	if !op.hasValue {
		return invalidValue("%s of %s needs a value", op.op, op.path)
	}
	return setUserAttr(u, attr, op.value, false)
}

// pathlessObject returns the attribute object of an add or replace with no
// path (RFC 7644 sections 3.5.2.1 and 3.5.2.3). A remove needs a path.
func pathlessObject(op patchOp) (map[string]any, error) {
	if op.op == "remove" {
		return nil, newErr(http.StatusBadRequest, "noTarget", "remove needs a path")
	}
	obj, ok := op.value.(map[string]any)
	if !ok {
		return nil, invalidValue("the value of an operation with no path is an object of attributes")
	}
	return obj, nil
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// setUserAttr sets or, for remove, clears one attribute named in lower case.
// An attribute the service does not hold is ignored.
func setUserAttr(u *user, attr string, v any, remove bool) error {
	switch attr {
	case "active":
		if remove {
			u.active = nil
			return nil
		}
		b, ok := v.(bool)
		if !ok {
			return invalidValue("active is not a boolean")
		}
		u.active = &b
	case "externalid":
		return setString(&u.externalID, "externalId", v, remove)
	case "username":
		if remove {
			return newErr(http.StatusBadRequest, "mutability", "userName is required")
		}
		return setRequired(&u.userName, "userName", v)
	case "displayname":
		return setString(&u.displayName, "displayName", v, remove)
	}
	return nil
}

func setString(dst *string, name string, v any, remove bool) error {
	if remove {
		*dst = ""
		return nil
	}
	str, ok := v.(string)
	if !ok {
		return invalidValue("%s is not a string", name)
	}
	*dst = str
	return nil
}

func setRequired(dst *string, name string, v any) error {
	str, ok := v.(string)
	if !ok || str == "" {
		return invalidValue("%s is not a non-empty string", name)
	}
	*dst = str
	return nil
}

// memberView is the members of a group as a PatchOp's operations leave them:
// the group's own members, less all of them when cleared, and then the
// overlay of members added (true) and removed (false). The group changes only
// when the whole PatchOp is applied.
type memberView struct {
	overlay map[string]bool
	cleared bool
}

func (v *memberView) clear() { v.cleared, v.overlay = true, map[string]bool{} }

// patchGroup applies a PatchOp to g as a whole or not at all and publishes
// the facts of every user whose group list changed.
func (s *Server) patchGroup(g *group, body any) error {
	ops, err := parsePatch(body)
	if err != nil {
		return err
	}
	ng := *g
	view := &memberView{overlay: map[string]bool{}}
	for _, op := range ops {
		if err := s.applyGroupOp(&ng, view, op); err != nil {
			return err
		}
	}
	if err := s.checkGroupUnique(&ng); err != nil {
		return err
	}

	changed := map[string]struct{}{}
	if view.cleared {
		for m := range g.members {
			if in, ok := view.overlay[m]; !ok || !in {
				s.unlink(m, g.id)
				changed[m] = struct{}{}
			}
		}
	}
	for m, in := range view.overlay {
		_, has := g.members[m]
		switch {
		case in && !has:
			s.link(m, g.id)
			changed[m] = struct{}{}
		case !in && has:
			s.unlink(m, g.id)
			changed[m] = struct{}{}
		}
	}
	if ng.externalID != g.externalID {
		if g.externalID != "" {
			delete(s.groupExt, g.externalID)
		}
		if ng.externalID != "" {
			s.groupExt[ng.externalID] = g.id
		}
		for m := range g.members {
			changed[m] = struct{}{}
		}
	}
	if ng.displayName != g.displayName || ng.externalID != g.externalID || len(changed) > 0 {
		g.modified = s.now()
	}
	g.displayName, g.externalID = ng.displayName, ng.externalID
	s.noteGroup(g)
	if err := s.publishAll(changed); err != nil {
		return errInternal(err)
	}
	return nil
}

func (s *Server) applyGroupOp(g *group, view *memberView, op patchOp) error {
	if op.path == "" {
		obj, err := pathlessObject(op)
		if err != nil {
			return err
		}
		for _, k := range sortedKeys(obj) {
			attr := ascii.ToLower(stripSchema(k, groupURN))
			if attr == "members" {
				if err := s.memberOp(view, op.op, obj[k], true); err != nil {
					return err
				}
				continue
			}
			if err := setGroupAttr(g, attr, obj[k], false); err != nil {
				return err
			}
		}
		return nil
	}
	path := stripSchema(op.path, groupURN)
	lower := ascii.ToLower(path)
	switch {
	case lower == "members":
		return s.memberOp(view, op.op, op.value, op.hasValue)
	case strings.HasPrefix(lower, "members["):
		m := memberFilterRE.FindStringSubmatch(path)
		if m == nil {
			return newErr(http.StatusBadRequest, "invalidPath", "the path is not members or members[value eq \"id\"]")
		}
		if op.op != "remove" {
			return newErr(http.StatusBadRequest, "invalidPath", "a value filter on members is supported for remove only")
		}
		var id string
		if err := json.Unmarshal([]byte(m[1]), &id); err != nil {
			return newErr(http.StatusBadRequest, "invalidPath", "the filter value is not a string")
		}
		view.overlay[id] = false
		return nil
	}
	if op.op == "remove" {
		return setGroupAttr(g, lower, nil, true)
	}
	if !op.hasValue {
		return invalidValue("%s of %s needs a value", op.op, op.path)
	}
	return setGroupAttr(g, lower, op.value, false)
}

func setGroupAttr(g *group, attr string, v any, remove bool) error {
	switch attr {
	case "externalid":
		return setString(&g.externalID, "externalId", v, remove)
	case "displayname":
		if remove {
			return newErr(http.StatusBadRequest, "mutability", "displayName is required")
		}
		return setRequired(&g.displayName, "displayName", v)
	}
	return nil
}

// memberOp applies add, replace or remove of the members attribute with no
// value filter. Remove with no value removes every member (RFC 7644 section
// 3.5.2.2); with a value it removes the members that value lists, as the
// provisioning client sends it.
func (s *Server) memberOp(view *memberView, op string, v any, hasValue bool) error {
	if op == "remove" && !hasValue {
		view.clear()
		return nil
	}
	if !hasValue {
		return invalidValue("%s of members needs a value", op)
	}
	ids, err := parseMembers(v)
	if err != nil {
		return err
	}
	switch op {
	case "remove":
		for _, id := range ids {
			view.overlay[id] = false
		}
	case "add", "replace":
		if err := s.checkMembers(ids); err != nil {
			return err
		}
		if op == "replace" {
			view.clear()
		}
		for _, id := range ids {
			view.overlay[id] = true
		}
	}
	return nil
}
