package ldap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core/binding"
	"hop.top/pact-go/core/clock"
)

// The descriptor of the adapter (profile section 1).
const (
	Protocol        = "ldap"
	Version         = "3"
	MappingRevision = "pact-ldap-1"
)

// Mechanism is the Mechanism of a principal the adapter authenticates.
const Mechanism adapter.Mechanism = "ldap-simple-bind"

// The approved native paths of mapping pact-ldap-1 (profile section 2).
const (
	PathPrincipalID    = "/principal/id"
	PathGroupIDs       = "/principal/group_ids"
	PathGroupIDsNested = "/principal/group_ids_nested"
	PathAccountState   = "/principal/account_state"
)

// The baseline revisions of the group resolvers and the state maps (profile
// LR-16 to LR-18, LR-21, LR-22).
const (
	RevisionGroupsDirect  = "pact-ldap-groups-direct-1"
	RevisionGroupsADChain = "pact-ldap-groups-ad-chain-1"
	RevisionStateOpenLDAP = "pact-ldap-state-openldap-1"
	RevisionStateAD       = "pact-ldap-state-ad-1"
)

// Kind is the kind of directory of a realm (profile Appendix A).
type Kind string

// The kinds the profile claims.
const (
	KindOpenLDAP        Kind = "openldap"
	KindActiveDirectory Kind = "activedirectory"
)

// Nesting is the nested group setting of a realm (profile LR-17).
type Nesting string

// The nested settings of the profile.
const (
	NestingNone    Nesting = "none"
	NestingADChain Nesting = "ad-chain"
)

// maxBody is the largest request body the adapter reads to digest it.
const maxBody = 8 << 20

// headerNormalizationID names the header normalization of the baseline HTTP
// mapping, which package binding applies.
const headerNormalizationID = "pact-ldap-header-normalization-1"

// guardCapacity bounds the guard against re-stamping that New creates when
// the configuration supplies none.
const guardCapacity = 4096

// defaultTimeLimit is the time limit of a directory request when the realm
// sets none (profile LR-30).
const defaultTimeLimit = 10 * time.Second

// Config names the gateway's native systems and its trusted configuration.
// Every value comes from gateway configuration, never from a request.
type Config struct {
	// Realm is the tenant and environment of the gateway; every directory
	// realm belongs to it (profile LR-1).
	Realm adapter.Realm
	// Origin is the public HTTPS origin of the gateway (draft 10.2).
	Origin string
	// HeaderAllowlist names the application headers an operation context
	// covers besides content-type.
	HeaderAllowlist []string
	// Mappings are the installed route tables by mapping revision. Nil
	// installs [StockRoutes] under [MappingRevision].
	Mappings map[string][]Route

	// Realms are the directory realms. Required.
	Realms []RealmConfig
	// LoginRealm is the realm_id of the realm whose directory
	// AuthenticateNative searches. Required.
	LoginRealm string

	// Claims are the sources of approved native paths other than the four of
	// mapping pact-ldap-1, by path. They are not directory facts.
	Claims map[string]ClaimSource
	// Checks are the installed context checks by exact check id.
	Checks map[string]InstalledCheck
	// Guard is the guard against re-stamping that installed checks with
	// freshness limits share. Nil creates an empty one.
	Guard *freshness.Monotonic

	// Registry is the enrollment registry. Required.
	Registry enroll.Registry
	// Permissions is the application's native authorization. Required.
	Permissions PermissionLookup

	// Reporting signs outcome reports. Nil leaves RecordOutcome unsupported.
	Reporting *Reporting
	// ExecutionVisible says that the gateway observes the execution of the
	// operations it forwards.
	ExecutionVisible bool

	// Clock is the adapter's only source of the current time. Required.
	Clock clock.Clock
}

// RealmConfig is the realm record of profile Appendix A.
type RealmConfig struct {
	// ID is the realm_id: unreserved characters only (profile LR-1).
	ID string
	// Kind is openldap or activedirectory.
	Kind Kind
	// Directory opens sessions to the realm's server. Required.
	Directory Directory
	// GUIDText converts the 16 octets of objectGUID to the identifier text
	// and back. Required for an activedirectory realm, which the profile
	// accepts only once the octet order is established (Appendix H, P3);
	// [OctetOrderGUID] is the order of RFC 4122 as received. Unused for
	// openldap.
	GUIDText GUIDCodec
	// UserBases and GroupBases are the bases of accounts and of groups.
	UserBases  []string
	GroupBases []string
	// AccountClass and GroupClass are the object classes of accounts and of
	// groups.
	AccountClass string
	GroupClass   string
	// LoginAttribute is the attribute the login search matches against the
	// typed name; it selects an entry and is never an identity (LR-11).
	LoginAttribute string
	// LookupDN and LookupPassword are the read-only lookup account (LR-13).
	LookupDN       string
	LookupPassword string
	// DeniedPrincipals are identifiers that never authenticate: the lookup
	// account and any other service account (LR-13).
	DeniedPrincipals []string
	// Sentinel names the visibility sentinel by unique id (LR-14).
	Sentinel Sentinel
	// DirectGroups says the direct resolver exists: memberOf is maintained,
	// as by the OpenLDAP memberof overlay or by Active Directory (LR-16).
	DirectGroups bool
	// Nested is the nested setting; ad-chain only for activedirectory.
	Nested Nesting
	// ReplicationBound is the declared replication bound of a replicated
	// topology; zero for single-server (LR-26). The as-of instant of a read
	// is the send time minus the bound (LR-25).
	ReplicationBound time.Duration
	// TimeLimit is the time limit of each directory request; zero is 10
	// seconds (LR-30).
	TimeLimit time.Duration
	// GroupsRevision, NestedRevision and StateRevision override the baseline
	// revisions when the deployment changed the resolver or the state map
	// (LR-18, LR-22).
	GroupsRevision string
	NestedRevision string
	StateRevision  string
}

// Sentinel holds the unique ids of the sentinel account, its group, and, for
// the nested resolver, the parent group (profile LR-14).
type Sentinel struct {
	Account     string
	Group       string
	ParentGroup string
}

// Reporting is the signer of outcome reports.
type Reporting = installed.Reporting

// realm is a validated realm record.
type realm struct {
	RealmConfig
	pact       adapter.Realm
	uniqueAttr string
	userBases  []*goldap.DN
	groupBases []*goldap.DN
	lookupDN   *goldap.DN
}

// Adapter is the LDAP adapter. It is safe for concurrent use when its native
// systems are.
type Adapter struct {
	cfg      Config
	mappings map[string][]Route
	realms   map[string]*realm
}

var _ adapter.Adapter = (*Adapter)(nil)

// New returns the adapter over cfg. It validates the configuration.
func New(cfg Config) (*Adapter, error) {
	switch {
	case cfg.Clock == nil:
		return nil, errors.New("ldap: no clock")
	case cfg.Realm.TenantID == "" || cfg.Realm.EnvironmentID == "":
		return nil, errors.New("ldap: the gateway realm needs a tenant and an environment")
	case cfg.Registry == nil:
		return nil, errors.New("ldap: no enrollment registry")
	case cfg.Permissions == nil:
		return nil, errors.New("ldap: no native authorization")
	case len(cfg.Realms) == 0:
		return nil, errors.New("ldap: no directory realm")
	}
	a := &Adapter{cfg: cfg, mappings: cfg.Mappings, realms: map[string]*realm{}}
	for _, rc := range cfg.Realms {
		r, err := newRealm(rc, cfg.Realm)
		if err != nil {
			return nil, fmt.Errorf("ldap: realm %q: %w", rc.ID, err)
		}
		if a.realms[rc.ID] != nil {
			return nil, fmt.Errorf("ldap: realm %q twice", rc.ID)
		}
		a.realms[rc.ID] = r
	}
	if a.realms[cfg.LoginRealm] == nil {
		return nil, fmt.Errorf("ldap: login realm %q is not configured", cfg.LoginRealm)
	}
	for path, src := range cfg.Claims {
		if isDirectoryPath(path) {
			return nil, fmt.Errorf("ldap: %s is answered by the directory", path)
		}
		if src == nil {
			return nil, fmt.Errorf("ldap: no source for %s", path)
		}
	}
	if err := installed.ValidateChecks(cfg.Checks); err != nil {
		return nil, fmt.Errorf("ldap: %w", err)
	}
	if err := cfg.Reporting.Validate(); err != nil {
		return nil, fmt.Errorf("ldap: %w", err)
	}
	if a.cfg.Guard == nil {
		a.cfg.Guard = freshness.NewMonotonic(guardCapacity)
	}
	if a.mappings == nil {
		a.mappings = map[string][]Route{MappingRevision: StockRoutes()}
	}
	for version, routes := range a.mappings {
		if err := a.bindingConfig(version).Validate(); err != nil {
			return nil, fmt.Errorf("ldap: mapping %q: %w", version, err)
		}
		for _, rt := range routes {
			if err := rt.Validate(); err != nil {
				return nil, fmt.Errorf("ldap: mapping %q: %w", version, err)
			}
		}
	}
	return a, nil
}

// newRealm validates one realm record.
func newRealm(rc RealmConfig, pact adapter.Realm) (*realm, error) {
	if rc.ID == "" || !unreserved(rc.ID) {
		return nil, errors.New("realm_id must be non-empty unreserved characters")
	}
	if rc.Directory == nil {
		return nil, errors.New("no directory")
	}
	r := &realm{RealmConfig: rc, pact: pact}
	switch rc.Kind {
	case KindOpenLDAP:
		r.uniqueAttr = "entryUUID"
		if rc.Nested != NestingNone {
			return nil, errors.New("an openldap realm has the nested setting none")
		}
	case KindActiveDirectory:
		r.uniqueAttr = "objectGUID"
		if rc.GUIDText == nil {
			return nil, errors.New("an activedirectory realm needs the established objectGUID octet order")
		}
		if rc.Nested != NestingNone && rc.Nested != NestingADChain {
			return nil, fmt.Errorf("nested setting %q", rc.Nested)
		}
	default:
		return nil, fmt.Errorf("kind %q", rc.Kind)
	}
	switch {
	case len(rc.UserBases) == 0 || len(rc.GroupBases) == 0:
		return nil, errors.New("no user or group base")
	case rc.AccountClass == "" || rc.GroupClass == "" || rc.LoginAttribute == "":
		return nil, errors.New("no account class, group class or login attribute")
	case rc.LookupDN == "" || rc.LookupPassword == "":
		return nil, errors.New("no lookup account")
	case rc.Sentinel.Account == "" || rc.Sentinel.Group == "":
		return nil, errors.New("no sentinel")
	case rc.Nested == NestingADChain && rc.Sentinel.ParentGroup == "":
		return nil, errors.New("the nested resolver needs a sentinel parent group")
	}
	for _, id := range []string{rc.Sentinel.Account, rc.Sentinel.Group, rc.Sentinel.ParentGroup} {
		if id != "" && !isUUID(id) {
			return nil, fmt.Errorf("sentinel id %q is not a lower-case UUID", id)
		}
	}
	var err error
	if r.userBases, err = parseDNs(rc.UserBases); err != nil {
		return nil, err
	}
	if r.groupBases, err = parseDNs(rc.GroupBases); err != nil {
		return nil, err
	}
	if r.lookupDN, err = goldap.ParseDN(rc.LookupDN); err != nil {
		return nil, fmt.Errorf("lookup DN: %w", err)
	}
	if r.TimeLimit <= 0 {
		r.TimeLimit = defaultTimeLimit
	}
	if r.GroupsRevision == "" {
		r.GroupsRevision = RevisionGroupsDirect
	}
	if r.NestedRevision == "" {
		r.NestedRevision = RevisionGroupsADChain
	}
	if r.StateRevision == "" {
		r.StateRevision = RevisionStateOpenLDAP
		if rc.Kind == KindActiveDirectory {
			r.StateRevision = RevisionStateAD
		}
	}
	return r, nil
}

func parseDNs(dns []string) ([]*goldap.DN, error) {
	out := make([]*goldap.DN, 0, len(dns))
	for _, s := range dns {
		dn, err := goldap.ParseDN(s)
		if err != nil {
			return nil, fmt.Errorf("base %q: %w", s, err)
		}
		out = append(out, dn)
	}
	return out, nil
}

// unreserved reports whether s has only the unreserved characters of RFC 3986,
// section 2.3, as identity mapping section 3.1 requires of a realm_id.
func unreserved(s string) bool {
	return !strings.ContainsFunc(s, func(c rune) bool { return !unreservedRune(c) })
}

// unreservedRune reports whether c is an unreserved character of RFC 3986,
// section 2.3.
func unreservedRune(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}

func isDirectoryPath(p string) bool {
	return slices.Contains([]string{PathPrincipalID, PathGroupIDs, PathGroupIDsNested, PathAccountState}, p)
}

// Describe returns the descriptor of the profile: ldap, 3, pact-ldap-1.
func (a *Adapter) Describe() adapter.Descriptor {
	return adapter.Descriptor{Protocol: Protocol, Version: Version, MappingRevision: MappingRevision}
}

// bindingConfig is the baseline HTTP mapping under one installed revision.
func (a *Adapter) bindingConfig(version string) binding.Config {
	return binding.Config{
		Origin:                a.cfg.Origin,
		HeaderAllowlist:       a.cfg.HeaderAllowlist,
		HeaderNormalizationID: headerNormalizationID,
		MappingVersion:        version,
		MaxBody:               maxBody,
	}
}

// live fails with a dependency error when ctx is already done.
func live(ctx context.Context, fn string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("ldap: %s: %w: %w", fn, adapter.ErrDependencyUnavailable, err)
	}
	return nil
}

// outage returns the dependency-unavailable error of fn with a reason that
// names no credential.
func outage(fn, reason string) error {
	return fmt.Errorf("ldap: %s: %s: %w", fn, reason, adapter.ErrDependencyUnavailable)
}

// denied is the native denial with reason.
func denied(reason adapter.DenialReason) error { return &adapter.NativeDenial{Reason: reason} }

// markKey is the context key of the enforcement marker. The type is
// unexported, so nothing outside this package, and no request header, can set
// it.
type markKey struct{}

// Mark returns r marked as accepted by the gateway's filter chain for the
// enforced path. A request that did not pass through it carries no marker.
func Mark(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), markKey{}, true))
}

// Marked reports whether r carries the enforcement marker.
func Marked(r *http.Request) bool {
	v, _ := r.Context().Value(markKey{}).(bool)
	return v
}

// Enforce is the filter that marks every request it passes to next.
func Enforce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, Mark(r))
	})
}
