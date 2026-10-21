package scim

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"hop.top/pact-go/adapter/source"
)

// user is a User resource: the attributes the facts depend on.
type user struct {
	id, userName, externalID, displayName string
	active                                *bool // nil: never asserted
	seq                                   uint64
	created, modified                     time.Time
	// principal is the principal the user's facts are published for; empty
	// when the record joins none.
	principal string
}

// group is a Group resource.
type group struct {
	id, displayName, externalID string
	members                     map[string]struct{} // user ids
	seq                         uint64
	created, modified           time.Time
}

func (s *Server) now() time.Time { return s.cfg.Clock.Now().UTC().Truncate(time.Second) }

// The next two methods run with s.mu held for writing.

func (s *Server) nextSeq() uint64 { s.seq++; return s.seq }

// publish writes the facts of u: it removes those of a principal the record
// no longer joins, then writes account_state (when active is known) and
// group_ids for the principal it joins now. A request that changes a user
// calls it whether or not anything changed, so a retry after a store failure
// repairs the facts.
func (s *Server) publish(u *user) error {
	ctx := context.Background()
	p, err := s.cfg.Join.Principal(joinAttrs(u))
	if err != nil {
		if !errors.Is(err, source.ErrNoJoin) {
			return err
		}
		s.logf("scim: user %s joins no principal and answers no fact: %v", u.id, err)
		p = ""
	}
	if u.principal != "" && u.principal != p {
		if err := s.cfg.Store.Delete(ctx, u.principal); err != nil {
			return err
		}
		u.principal = ""
	}
	if p == "" {
		return nil
	}
	if u.active == nil {
		// The store cannot drop one path; drop the principal's facts and
		// write the groups again.
		if err := s.cfg.Store.Delete(ctx, p); err != nil {
			return err
		}
	} else {
		state := "disabled"
		if *u.active {
			state = "active"
		}
		if err := s.cfg.Store.Put(ctx, p, PathAccountState, source.Fact{Value: state, SourceRef: u.id}); err != nil {
			return err
		}
	}
	u.principal = p
	return s.cfg.Store.Put(ctx, p, PathGroupIDs, source.Fact{Value: s.groupIDs(u.id), SourceRef: u.id})
}

func joinAttrs(u *user) map[string]string {
	if u.externalID == "" {
		return map[string]string{}
	}
	return map[string]string{joinAttribute: u.externalID}
}

// groupIDs returns the sorted externalIds of the groups of user id; a group
// with none contributes none.
func (s *Server) groupIDs(id string) []string {
	out := []string{}
	for gid := range s.memberOf[id] {
		if x := s.groups[gid].externalID; x != "" {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// publishAll publishes every user of ids that still exists and returns the
// first error after trying them all.
func (s *Server) publishAll(ids map[string]struct{}) error {
	var first error
	for id := range ids {
		if u, ok := s.users[id]; ok {
			if err := s.publish(u); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

// addUser puts u into the indexes.
func (s *Server) addUser(u *user) {
	s.users[u.id] = u
	s.userNames[strings.ToLower(u.userName)] = u.id
	if u.externalID != "" {
		s.userExt[u.externalID] = u.id
	}
}

// dropUser takes u out of the indexes and out of every group.
func (s *Server) dropUser(u *user) {
	delete(s.users, u.id)
	delete(s.userNames, strings.ToLower(u.userName))
	if u.externalID != "" {
		delete(s.userExt, u.externalID)
	}
	for gid := range s.memberOf[u.id] {
		delete(s.groups[gid].members, u.id)
		s.groups[gid].modified = s.now()
	}
	delete(s.memberOf, u.id)
}

func (s *Server) link(uid, gid string) {
	if s.memberOf[uid] == nil {
		s.memberOf[uid] = map[string]struct{}{}
	}
	s.memberOf[uid][gid] = struct{}{}
	s.groups[gid].members[uid] = struct{}{}
}

func (s *Server) unlink(uid, gid string) {
	delete(s.memberOf[uid], gid)
	if len(s.memberOf[uid]) == 0 {
		delete(s.memberOf, uid)
	}
	delete(s.groups[gid].members, uid)
}

// checkUserUnique reports a conflict of the userName or externalId of u with
// another user.
func (s *Server) checkUserUnique(u *user) error {
	if id, ok := s.userNames[strings.ToLower(u.userName)]; ok && id != u.id {
		return uniqueness("userName %q is already in use", u.userName)
	}
	if u.externalID != "" {
		if id, ok := s.userExt[u.externalID]; ok && id != u.id {
			return uniqueness("externalId %q is already in use", u.externalID)
		}
	}
	return nil
}

func (s *Server) checkGroupUnique(g *group) error {
	if g.externalID != "" {
		if id, ok := s.groupExt[g.externalID]; ok && id != g.id {
			return uniqueness("externalId %q is already in use", g.externalID)
		}
	}
	return nil
}
