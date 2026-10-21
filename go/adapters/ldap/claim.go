package ldap

import (
	"context"
	"fmt"
	"slices"
	"strconv"

	goldap "github.com/go-ldap/ldap/v3"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/installed"
)

// ClaimSource is the source of an approved native path other than the four of
// mapping pact-ldap-1.
type ClaimSource = installed.ClaimSource

// ClaimRecord is one value of a [ClaimSource].
type ClaimRecord = installed.ClaimRecord

// ReadNativeClaim reads the value at nativePath for the claim context.
//
// The four paths of mapping pact-ldap-1 are facts of the principal, which
// must be an identifier ldap:{realm_id}:{unique_id} of a configured realm in
// that realm's PACT realm, and not a denied principal; anything else is
// [adapter.ErrContextMismatch] (LR-12, LR-13).
//
//   - /principal/id is the principal identifier, with the authentication
//     time as observation and status time (LR-25).
//   - /principal/group_ids is the direct resolver's sorted list of group
//     identifiers (LR-16); /principal/group_ids_nested the in-chain
//     resolver's (LR-17). A realm without the resolver answers
//     [adapter.ErrUnsupportedRequirement] without a directory request.
//   - /principal/account_state is a value of LR-20 by the realm's state map.
//
// A directory read binds the lookup account, reads the sentinel and the
// account by unique id on the same connection, and stands only if the
// sentinel shows what the read depends on (LR-14); otherwise it is
// [adapter.ErrDependencyUnavailable], or [adapter.ErrUnsupportedRequirement]
// when only the nested sentinel fails. An account with no entry is absent,
// with no groups (LR-24). The observation and status time of a directory read
// are its as-of instant, the clock reading before the reads minus the
// replication bound, and the source reference is {unique_id}@{as-of seconds}
// (LR-25). Any other path is read from its source in [Config.Claims], or is
// unsupported.
func (a *Adapter) ReadNativeClaim(ctx context.Context, nativePath string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	if err := live(ctx, "read claim"); err != nil {
		return adapter.NativeClaim{}, err
	}
	if !isDirectoryPath(nativePath) {
		src, ok := a.cfg.Claims[nativePath]
		if !ok {
			return adapter.NativeClaim{}, fmt.Errorf("ldap: %q is not an approved native path: %w", nativePath, adapter.ErrUnsupportedRequirement)
		}
		c, err := installed.ReadClaim(ctx, src, nativePath, cc, a.cfg.Clock.Now())
		if err != nil {
			return adapter.NativeClaim{}, fmt.Errorf("ldap: read claim: %w", err)
		}
		return c, nil
	}
	p := cc.Principal
	realmID, uid, ok := parseID(p.ID)
	rlm := a.realms[realmID]
	if !ok || rlm == nil || p.Realm != rlm.pact || rlm.isDenied(p.ID) {
		return adapter.NativeClaim{}, fmt.Errorf("ldap: the principal is not an account of a configured realm: %w", adapter.ErrContextMismatch)
	}
	switch nativePath {
	case PathPrincipalID:
		return a.principalClaim(rlm, p, uid)
	case PathGroupIDs:
		if !rlm.DirectGroups {
			return adapter.NativeClaim{}, fmt.Errorf("ldap: realm %s has no direct group resolver: %w", rlm.ID, adapter.ErrUnsupportedRequirement)
		}
	case PathGroupIDsNested:
		if rlm.Nested != NestingADChain || !rlm.DirectGroups {
			return adapter.NativeClaim{}, fmt.Errorf("ldap: realm %s has no nested group resolver: %w", rlm.ID, adapter.ErrUnsupportedRequirement)
		}
	}
	return a.directoryClaim(ctx, rlm, nativePath, uid)
}

// principalClaim answers /principal/id from the authenticated principal.
func (a *Adapter) principalClaim(rlm *realm, p adapter.Principal, uid string) (adapter.NativeClaim, error) {
	if err := installed.SourceTimes(a.cfg.Clock.Now(), p.AuthenticatedAt); err != nil {
		return adapter.NativeClaim{}, fmt.Errorf("ldap: read claim: %w", err)
	}
	c := adapter.NativeClaim{
		Value:           p.ID,
		ObservedAt:      p.AuthenticatedAt,
		StatusCheckedAt: p.AuthenticatedAt,
		SourceID:        "ldap:" + rlm.ID + ":identity",
		SourceRef:       uid,
	}
	if !p.AuthenticatedAt.IsZero() {
		c.SourceRef = uid + "@" + strconv.FormatInt(p.AuthenticatedAt.Unix(), 10)
	}
	return c, nil
}

// directoryClaim reads a group or state path from the directory.
func (a *Adapter) directoryClaim(ctx context.Context, rlm *realm, path, uid string) (adapter.NativeClaim, error) {
	asOf := a.cfg.Clock.Now().Add(-rlm.ReplicationBound)
	s, err := a.lookupSession(ctx, rlm, "read claim")
	if err != nil {
		return adapter.NativeClaim{}, err
	}
	defer func() { _ = s.Close() }()
	rd := reader{a: a, s: s, r: rlm}

	attrs := []string{rlm.uniqueAttr}
	switch path {
	case PathAccountState:
		attrs = append(attrs, rlm.stateAttrs()...)
	default:
		attrs = append(attrs, "memberOf")
	}
	sentinel, found, err := rd.byUniqueID(ctx, rlm.Sentinel.Account, attrs)
	if err != nil {
		return adapter.NativeClaim{}, err
	}
	if !found {
		return adapter.NativeClaim{}, outage("read claim", "the sentinel account is not visible")
	}
	if err := rd.checkSentinel(ctx, path, sentinel); err != nil {
		return adapter.NativeClaim{}, err
	}
	subject, found, err := rd.byUniqueID(ctx, uid, attrs)
	if err != nil {
		return adapter.NativeClaim{}, err
	}
	claim := adapter.NativeClaim{
		ObservedAt:      asOf,
		StatusCheckedAt: asOf,
		SourceRef:       uid + "@" + strconv.FormatInt(asOf.Unix(), 10),
	}
	switch path {
	case PathAccountState:
		claim.SourceID = "ldap:" + rlm.ID + ":state:" + rlm.StateRevision
		claim.Value = "absent"
		if found {
			st, err := rlm.accountState(subject, asOf)
			if err != nil {
				return adapter.NativeClaim{}, err
			}
			claim.Value = st
		}
	case PathGroupIDs, PathGroupIDsNested:
		rev := rlm.GroupsRevision
		if path == PathGroupIDsNested {
			rev = rlm.NestedRevision
		}
		claim.SourceID = "ldap:" + rlm.ID + ":groups:" + rev
		groups := []string{}
		if found {
			if path == PathGroupIDs {
				groups, err = rd.directGroups(ctx, subject)
			} else {
				groups, err = rd.chainGroups(ctx, subject.DN)
			}
			if err != nil {
				return adapter.NativeClaim{}, err
			}
		}
		v := make([]any, len(groups))
		for i, g := range groups {
			v[i] = PrincipalID(rlm.ID, g)
		}
		claim.Value = v
	}
	if err := installed.SourceTimes(a.cfg.Clock.Now(), claim.ObservedAt); err != nil {
		return adapter.NativeClaim{}, fmt.Errorf("ldap: read claim: %w", err)
	}
	return claim, nil
}

// reader reads one realm on one lookup session.
type reader struct {
	a *Adapter
	s Session
	r *realm
}

// complete returns the entries of a search that ended in success with no
// reference; any other answer is incomplete and an outage (profile LR-15).
func complete(res Result, err error) ([]Entry, error) {
	switch {
	case err != nil:
		return nil, outage("read claim", "a directory search could not be completed")
	case len(res.References) > 0 || res.Code != ResultSuccess:
		return nil, outage("read claim", "a directory search returned an incomplete answer")
	}
	return res.Entries, nil
}

// byUniqueID searches the user bases for the account whose unique id is uid
// (LR-12). Two entries for one unique id are an outage.
func (rd reader) byUniqueID(ctx context.Context, uid string, attrs []string) (Entry, bool, error) {
	v, err := rd.r.uniqueValue(uid)
	if err != nil {
		return Entry{}, false, outage("read claim", "the unique id does not convert")
	}
	f := And{Equal{Attr: "objectClass", Value: []byte(rd.r.AccountClass)}, Equal{Attr: rd.r.uniqueAttr, Value: v, Binary: rd.r.Kind == KindActiveDirectory}}
	var found []Entry
	for _, base := range rd.r.UserBases {
		es, err := complete(rd.s.Search(ctx, Query{
			Base: base, Scope: ScopeSubtree, Filter: f, Attributes: attrs, SizeLimit: 2, TimeLimit: rd.r.TimeLimit,
		}))
		if err != nil {
			return Entry{}, false, err
		}
		found = append(found, es...)
	}
	switch len(found) {
	case 0:
		return Entry{}, false, nil
	case 1:
		if got, ok := rd.r.uniqueText(found[0]); !ok || got != uid {
			return Entry{}, false, outage("read claim", "the entry found has another unique id")
		}
		return found[0], true, nil
	}
	return Entry{}, false, outage("read claim", "a unique id matched more than one entry")
}

// checkSentinel requires of the sentinel what the read of path depends on: a
// value for each attribute of the state map, its group among its direct
// groups, and its parent group among its nested groups (LR-14).
func (rd reader) checkSentinel(ctx context.Context, path string, s Entry) error {
	switch path {
	case PathAccountState:
		for _, attr := range rd.r.stateAttrs() {
			if len(s.Values(attr)) == 0 {
				return outage("read claim", "the sentinel does not show the state attributes")
			}
		}
		return nil
	}
	direct, err := rd.directGroups(ctx, s)
	if err != nil {
		return err
	}
	if !slices.Contains(direct, rd.r.Sentinel.Group) {
		return outage("read claim", "the sentinel does not show its group")
	}
	if path != PathGroupIDsNested {
		return nil
	}
	nested, err := rd.chainGroups(ctx, s.DN)
	if err != nil {
		return err
	}
	if !slices.Contains(nested, rd.r.Sentinel.ParentGroup) {
		return fmt.Errorf("ldap: realm %s: the nested sentinel fails, so the in-chain resolver is unsupported: %w", rd.r.ID, adapter.ErrUnsupportedRequirement)
	}
	return nil
}

// directGroups resolves the memberOf values of e (LR-16): each is read by a
// base-scope search, must be of the group class and lie under a group base,
// compared as DNs, and is dropped when it names no readable group entry.
func (rd reader) directGroups(ctx context.Context, e Entry) ([]string, error) {
	var out []string
	for _, v := range e.Values("memberOf") {
		dn, err := parseDN(string(v))
		if err != nil || !rd.r.underGroupBase(dn) {
			continue
		}
		res, err := rd.s.Search(ctx, Query{
			Base: string(v), Scope: ScopeBase, Filter: Equal{Attr: "objectClass", Value: []byte(rd.r.GroupClass)},
			Attributes: []string{rd.r.uniqueAttr}, SizeLimit: 1, TimeLimit: rd.r.TimeLimit,
		})
		if err == nil && res.Code == ResultNoSuchObject && len(res.References) == 0 {
			continue
		}
		es, err := complete(res, err)
		if err != nil {
			return nil, err
		}
		for _, g := range es {
			if id, ok := rd.r.uniqueText(g); ok {
				out = append(out, id)
			}
		}
	}
	return sortedUnique(out), nil
}

// chainGroups searches each group base for the groups that hold dn through
// the in-chain matching rule (LR-17).
func (rd reader) chainGroups(ctx context.Context, dn string) ([]string, error) {
	f := And{Equal{Attr: "objectClass", Value: []byte(rd.r.GroupClass)}, InChain{Attr: "member", DN: dn}}
	var out []string
	for _, base := range rd.r.GroupBases {
		es, err := complete(rd.s.Search(ctx, Query{
			Base: base, Scope: ScopeSubtree, Filter: f, Attributes: []string{rd.r.uniqueAttr}, TimeLimit: rd.r.TimeLimit,
		}))
		if err != nil {
			return nil, err
		}
		for _, g := range es {
			if id, ok := rd.r.uniqueText(g); ok {
				out = append(out, id)
			}
		}
	}
	return sortedUnique(out), nil
}

func sortedUnique(s []string) []string {
	if s == nil {
		return []string{}
	}
	slices.Sort(s)
	return slices.Compact(s)
}

// underGroupBase reports whether dn lies under a group base of the realm.
func (r *realm) underGroupBase(dn *goldap.DN) bool {
	for _, b := range r.groupBases {
		if b.AncestorOfFold(dn) {
			return true
		}
	}
	return false
}

func parseDN(s string) (*goldap.DN, error) { return goldap.ParseDN(s) }
