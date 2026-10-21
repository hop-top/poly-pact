package rebac

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core/binding"
	"hop.top/pact-go/core/clock"
)

// The descriptor of the adapter (profile section 1).
const (
	Protocol        = "openfga-http"
	Version         = "1.x"
	MappingRevision = "pact-rebac-1"
)

// The actions and relations of the relation table of revision pact-rebac-1
// (profile section 2.1).
const (
	ActionRead      = "document.read"
	ActionWrite     = "document.write"
	RelationViewer  = "viewer"
	RelationEditor  = "editor"
	ObjectDocument  = "document"
	subjectType     = "user"
	defaultTimeout  = 5 * time.Second
	maxBody         = 8 << 20
	maxAnswer       = 64 << 10
	guardCapacity   = 4096
	headerNormalize = "pact-rebac-header-normalization-1"
)

// The identifier limits of the Check request (profile RB-6, [OF-2]).
const (
	maxUser     = 512
	maxObject   = 256
	maxRelation = 50
)

// ulid is the form of a store id the server accepts, as a probe of OpenFGA
// v1.10.0 reported it (profile section 14.3); model ids take the same form.
var ulid = regexp.MustCompile(`^[0-9ABCDEFGHJKMNPQRSTVWXYZ]{26}$`)

// Pin is the pin record of the gateway's realm (profile RB-1): the store and
// the authorization model every Check names, and the mapping revision whose
// routes and relation table the adapter uses.
type Pin struct {
	StoreID              string
	AuthorizationModelID string
	MappingRevision      string
}

// Relation is one row of a relation table: the relation and the object type
// a Check uses for an action (profile RB-5).
type Relation struct {
	Action     string
	Relation   string
	ObjectType string
}

// DocumentRelations is the relation table of revision pact-rebac-1:
// document.read checks viewer and document.write checks editor, on objects of
// type document (profile section 2.1).
func DocumentRelations() []Relation {
	return []Relation{
		{Action: ActionRead, Relation: RelationViewer, ObjectType: ObjectDocument},
		{Action: ActionWrite, Relation: RelationEditor, ObjectType: ObjectDocument},
	}
}

// Route maps a method and a path template to an action and a resource
// template.
type Route = installed.Route

// DocumentRoutes is the route table of revision pact-rebac-1, routes R1 and
// R2 of the profile: GET and PATCH /documents/{document_id}, the actions
// document.read and document.write on resource, the deployment's native
// document identifier with the placeholder {document_id}, such as
// https://docs.example/documents/{document_id}.
func DocumentRoutes(resource string) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/documents/{document_id}", Action: ActionRead, Resource: resource},
		{Method: http.MethodPatch, Path: "/documents/{document_id}", Action: ActionWrite, Resource: resource},
	}
}

// Store is the OpenFGA server and the gateway's client of it.
type Store struct {
	// URL is the base URL of the HTTP API. It is https, or http to a
	// loopback address only. Required.
	URL string
	// Credential is the pre-shared key the server accepts, sent as
	// Authorization: Bearer (profile [OF-6]). Empty sends none.
	Credential string
	// Client is the HTTP client, such as one with the server's trust
	// anchors. Nil uses a client of its own. The adapter never follows a
	// redirect, whatever the client says.
	Client *http.Client
	// Timeout bounds each Check. Zero is five seconds.
	Timeout time.Duration
}

// Config names the gateway's native systems and its trusted configuration.
// Every value comes from gateway configuration, never from a request.
type Config struct {
	// Realm is the tenant and environment of the gateway, the realm of the
	// pin record.
	Realm adapter.Realm
	// Origin is the public HTTPS origin of the gateway (draft 10.2).
	Origin string
	// HeaderAllowlist names the application headers an operation context
	// covers besides content-type.
	HeaderAllowlist []string
	// Mappings are the installed route tables by mapping revision. The
	// revision of the pin is required.
	Mappings map[string][]Route
	// Relations are the relation tables by mapping revision. Nil installs
	// [DocumentRelations] under [MappingRevision]. The revision of the pin is
	// required.
	Relations map[string][]Relation
	// Pin is the pin record. Required.
	Pin Pin
	// Registry maps principals and resources to Check subjects and objects.
	// Required.
	Registry Registry
	// Store is the OpenFGA server. Required.
	Store Store

	// Authenticator is the deployment's identity mechanism; the relationship
	// store authenticates nobody (profile section 3). Required.
	Authenticator adapter.NativeAuthenticator
	// Enrollments is the enrollment registry. Required.
	Enrollments enroll.Registry
	// Claims are the sources of the approved native paths, by path.
	Claims map[string]ClaimSource
	// Checks are the installed context checks by exact check id.
	Checks map[string]InstalledCheck
	// Guard is the guard against re-stamping that installed checks with
	// freshness limits share. Nil creates an empty one.
	Guard *freshness.Monotonic
	// Reporting signs outcome reports. Nil leaves RecordOutcome unsupported.
	Reporting *Reporting
	// ExecutionVisible says that the gateway observes the execution of the
	// operations it forwards.
	ExecutionVisible bool

	// Clock is the adapter's only source of the current time. Required.
	Clock clock.Clock
}

// ClaimSource is the source of an approved native path.
type ClaimSource = installed.ClaimSource

// ClaimRecord is one value of a [ClaimSource].
type ClaimRecord = installed.ClaimRecord

// Check is the native implementation of an installed context check.
type Check = installed.Check

// CheckRecord is what a [Check] found.
type CheckRecord = installed.CheckRecord

// InstalledCheck is a check as the gateway installed it.
type InstalledCheck = installed.InstalledCheck

// Freshness is a pair of age limits in seconds.
type Freshness = installed.Freshness

// Reporting is the signer of outcome reports.
type Reporting = installed.Reporting

// Adapter is the ReBAC adapter. It is safe for concurrent use when its native
// systems are.
type Adapter struct {
	cfg       Config
	mappings  map[string][]Route
	relations map[string]Relation
	routes    []Route
	origin    string
	checkURL  string
	client    *http.Client
}

var _ adapter.Adapter = (*Adapter)(nil)

// New returns the adapter over cfg. It validates the configuration.
func New(cfg Config) (*Adapter, error) {
	switch {
	case cfg.Clock == nil:
		return nil, errors.New("rebac: no clock")
	case cfg.Realm.TenantID == "" || cfg.Realm.EnvironmentID == "":
		return nil, errors.New("rebac: the gateway realm needs a tenant and an environment")
	case cfg.Authenticator == nil:
		return nil, errors.New("rebac: no identity mechanism")
	case cfg.Enrollments == nil:
		return nil, errors.New("rebac: no enrollment registry")
	case cfg.Registry == nil:
		return nil, errors.New("rebac: no mapping registry")
	case !ulid.MatchString(cfg.Pin.StoreID):
		return nil, errors.New("rebac: the pin needs a store id")
	case !ulid.MatchString(cfg.Pin.AuthorizationModelID):
		return nil, errors.New("rebac: the pin needs an authorization model id; the latest model is never used (profile RB-2)")
	}
	a := &Adapter{cfg: cfg, mappings: cfg.Mappings, relations: map[string]Relation{}}
	for version, routes := range a.mappings {
		if err := a.bindingConfig(version).Validate(); err != nil {
			return nil, fmt.Errorf("rebac: mapping %q: %w", version, err)
		}
		for _, rt := range routes {
			if err := rt.Validate(); err != nil {
				return nil, fmt.Errorf("rebac: mapping %q: %w", version, err)
			}
		}
	}
	routes, ok := a.mappings[cfg.Pin.MappingRevision]
	if !ok {
		return nil, fmt.Errorf("rebac: the mapping revision %q of the pin is not installed", cfg.Pin.MappingRevision)
	}
	a.routes = routes
	tables := cfg.Relations
	if tables == nil {
		tables = map[string][]Relation{MappingRevision: DocumentRelations()}
	}
	table, ok := tables[cfg.Pin.MappingRevision]
	if !ok {
		return nil, fmt.Errorf("rebac: no relation table for the mapping revision %q of the pin", cfg.Pin.MappingRevision)
	}
	for _, r := range table {
		switch {
		case r.Action == "" || !validID(r.Relation) || len(r.Relation) > maxRelation || !validID(r.ObjectType):
			return nil, fmt.Errorf("rebac: relation table row %+v", r)
		case a.relations[r.Action] != (Relation{}):
			return nil, fmt.Errorf("rebac: action %q has two rows", r.Action)
		}
		a.relations[r.Action] = r
	}
	if err := installed.ValidateChecks(cfg.Checks); err != nil {
		return nil, fmt.Errorf("rebac: %w", err)
	}
	for path, src := range cfg.Claims {
		if src == nil {
			return nil, fmt.Errorf("rebac: no source for %s", path)
		}
	}
	if err := cfg.Reporting.Validate(); err != nil {
		return nil, fmt.Errorf("rebac: %w", err)
	}
	if a.cfg.Guard == nil {
		a.cfg.Guard = freshness.NewMonotonic(guardCapacity)
	}
	origin, err := a.normalizedOrigin()
	if err != nil {
		return nil, err
	}
	a.origin = origin
	if a.checkURL, err = checkURL(cfg.Store.URL, cfg.Pin.StoreID); err != nil {
		return nil, err
	}
	a.client = storeClient(cfg.Store)
	return a, nil
}

// normalizedOrigin is the origin as the baseline HTTP mapping writes it in a
// target URI.
func (a *Adapter) normalizedOrigin() (string, error) {
	r, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		return "", err
	}
	r.RequestURI = "/"
	// An origin-form request needs a Host (request-binding.md RB-66); the
	// binding never reads its value (RB-3).
	r.Host = "localhost"
	op, err := binding.FromRequest(a.bindingConfig(a.cfg.Pin.MappingRevision), r, "origin", "", nil)
	if err != nil {
		return "", fmt.Errorf("rebac: origin: %w", err)
	}
	return strings.TrimSuffix(op.TargetURI, "/"), nil
}

// checkURL is the Check endpoint of the pinned store (profile RB-2, [OF-2]).
func checkURL(base, storeID string) (string, error) {
	u, err := url.Parse(base)
	switch {
	case err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "":
		return "", errors.New("rebac: the store URL must be an absolute URL with no userinfo, query or fragment")
	case u.Scheme == "https":
	case u.Scheme == "http" && loopback(u.Hostname()):
	default:
		return "", errors.New("rebac: the store URL must be https, or http to a loopback address")
	}
	return strings.TrimSuffix(u.String(), "/") + "/stores/" + storeID + "/check", nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// storeClient is the configured client with the adapter's own redirect rule
// and time limit.
func storeClient(s Store) *http.Client {
	c := &http.Client{}
	if s.Client != nil {
		*c = *s.Client
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c.Timeout = s.Timeout
	if c.Timeout <= 0 {
		c.Timeout = defaultTimeout
	}
	return c
}

// validID reports whether s is a non-empty identifier of the form profile
// RB-6 allows: ASCII letters, digits, "-", "_" and ".".
func validID(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

// Describe returns the descriptor of the profile: openfga-http, 1.x,
// pact-rebac-1.
func (a *Adapter) Describe() adapter.Descriptor {
	return adapter.Descriptor{Protocol: Protocol, Version: Version, MappingRevision: MappingRevision}
}

// bindingConfig is the baseline HTTP mapping under one installed revision.
func (a *Adapter) bindingConfig(version string) binding.Config {
	return binding.Config{
		Origin:                a.cfg.Origin,
		HeaderAllowlist:       a.cfg.HeaderAllowlist,
		HeaderNormalizationID: headerNormalize,
		MappingVersion:        version,
		MaxBody:               maxBody,
	}
}

// live fails with a dependency error when ctx is already done.
func live(ctx context.Context, fn string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("rebac: %s: %w: %w", fn, adapter.ErrDependencyUnavailable, err)
	}
	return nil
}
