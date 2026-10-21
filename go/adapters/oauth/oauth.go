package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core/binding"
	"hop.top/pact-go/core/clock"
)

// The descriptors of the three token forms (profile section 1).
const (
	ProtocolIntrospection = "oauth-introspection"
	VersionIntrospection  = "rfc7662"
	ProtocolEntra         = "entra-access-token"
	VersionEntra          = "2.0"
	ProtocolGoogleID      = "google-id-token"
	VersionGoogleID       = "oidc-core-1.0"
	MappingRevision       = "pact-oauth-1"
)

// Mechanism is the Mechanism of a principal the adapter authenticates.
const Mechanism adapter.Mechanism = "oauth"

// The approved native paths of section F of the profile.
const (
	PathPrincipalID = "/oauth/principal_id"
	PathTenantID    = "/oauth/tenant_id"
	PathClientID    = "/oauth/client_id"
	PathScopes      = "/oauth/scopes"
)

// The attributes of an authenticated principal.
const (
	// AttrToken holds the facts of the token: {"entry", "form", "tenant",
	// "scopes", "issued_at", "status_checked_at", "token_id"}, the last three
	// only when the token gives them.
	AttrToken = "oauth"
	// AttrConfirmation holds the token's cnf as {"jkt": ...} or
	// {"x5t#S256": ...} (OAUTH-34). It never enrolls a key.
	AttrConfirmation = "cnf"
)

// Form is the token form of an issuer entry (OAUTH-5).
type Form string

const (
	// FormIntrospection is form I: an opaque token validated by RFC 7662
	// introspection.
	FormIntrospection Form = "introspection"
	// FormEntraV2 is form E: a Microsoft Entra ID v2.0 access token validated
	// locally.
	FormEntraV2 Form = "entra-v2"
	// FormGoogleID is form G: a Google ID token validated locally against the
	// key set of Google's discovery document, for one pinned hosted domain.
	FormGoogleID Form = "google-id-token"
)

// SenderConstraint is the sender constraint of an issuer entry (OAUTH-34).
type SenderConstraint string

const (
	SenderNone SenderConstraint = "none"
	SenderDPoP SenderConstraint = "dpop"
	SenderMTLS SenderConstraint = "mtls"
)

// ResourceBinding is how a form I entry binds a token to the gateway's
// resource (OAUTH-12, OAUTH-13).
type ResourceBinding string

const (
	// BindingAudience requires aud to name an accepted audience.
	BindingAudience ResourceBinding = "aud"
	// BindingIntrospectionScoped is the deployment statement that the
	// authorization server answers active true only for tokens usable at the
	// gateway's resource; aud is then optional.
	BindingIntrospectionScoped ResourceBinding = "introspection-scoped"
)

// The reference configuration of the profile, illustrative policy choices.
const (
	DefaultLifetimeIntrospection = 3600 * time.Second
	DefaultLifetimeEntra         = 5400 * time.Second
	DefaultKeyRefresh            = 3600 * time.Second
	DefaultKeyMaxAge             = 86400 * time.Second
	// UnknownKeyRefetch is the shortest interval between two fetches of a key
	// set for a kid the adapter does not hold (OAUTH-24).
	UnknownKeyRefetch = 300 * time.Second
	// DefaultTimeout bounds every request to an introspection endpoint, a
	// discovery document or a key set.
	DefaultTimeout = 5 * time.Second
)

// EntraOrigin is the only trusted origin of form E key sets in the reference
// configuration (OAUTH-23).
const EntraOrigin = "https://login.microsoftonline.com"

// The form G constants (OAUTH-41, OAUTH-43).
const (
	// GoogleIssuer is the issuer identifier of every form G entry: the
	// issuer of Google's discovery document. A token's iss may also be
	// accounts.google.com; the identifier is the entry's, in either case.
	GoogleIssuer = "https://accounts.google.com"
	// GoogleKeyOrigin is the only trusted origin of form G key sets in the
	// reference configuration: the jwks_uri of Google's discovery document is
	// https://www.googleapis.com/oauth2/v3/certs.
	GoogleKeyOrigin = "https://www.googleapis.com"
	// DefaultLifetimeGoogle is the reference value of L for form G, an
	// illustrative policy choice: the lifetime of the example ID token on
	// Google's OpenID Connect page, iat 1353601026 and exp 1353604926. No page
	// states the lifetime of the tokens Google issues.
	DefaultLifetimeGoogle = 3900 * time.Second
)

// Entry is an issuer entry: trusted configuration installed through the
// gateway's administrative controls (OAUTH-5). No token, request or fetched
// document changes it.
type Entry struct {
	// ID names the entry; it is the SourceID of every claim the entry's
	// tokens give.
	ID string
	// Form is the token form.
	Form Form
	// Issuer is the issuer identifier, compared exactly.
	Issuer string
	// Tenant is the tenant component of the identifiers: the tenant ID in
	// form E, the pinned hosted domain (the hd claim) in form G, the
	// configured tenant or "none" in form I.
	Tenant string
	// Audiences are the accepted audience values; in form G the OAuth client
	// IDs of the application.
	Audiences []string
	// Clients is the client allowlist, compared exactly; in form G the
	// azp, or the aud when there is none.
	Clients []string
	// SenderConstraint is none, dpop or mtls. Empty is none.
	SenderConstraint SenderConstraint
	// Lifetime is the bound L on exp - iat. Zero is the reference value of
	// the form.
	Lifetime time.Duration

	// IntrospectionEndpoint is the form I endpoint, an https URL.
	IntrospectionEndpoint string
	// ClientID and ClientSecret are the gateway's own client credentials at
	// the endpoint, sent with client_secret_basic (RFC 6749 section 2.3.1).
	ClientID, ClientSecret string
	// Binding is the resource binding mode. Empty is aud.
	Binding ResourceBinding
	// CacheBound is C, the longest reuse of an introspection response. Zero
	// introspects every evaluation.
	CacheBound time.Duration

	// Algorithms is the form E and form G algorithm allowlist. Empty is RS256
	// alone.
	Algorithms []string
	// KeyRefresh is K and KeyMaxAge is T (OAUTH-24, OAUTH-43). Zero is the
	// reference value. In form G, K is the freshness of a key set whose
	// response gives none, and T bounds the freshness that it gives.
	KeyRefresh, KeyMaxAge time.Duration
	// TrustedOrigins are the origins a jwks_uri may name. Empty is
	// [EntraOrigin] in form E and [GoogleKeyOrigin] in form G.
	TrustedOrigins []string
}

// Route names the one issuer entry that authenticates a route and the
// delegated scope it requires (OAUTH-6, OAUTH-31).
type Route struct {
	// Method and Path match a request; a {name} segment of Path matches one
	// path segment.
	Method, Path string
	// Entry is the ID of the issuer entry.
	Entry string
	// Scope is the required delegated scope; empty requires none.
	Scope string
}

// Config names the gateway's trusted configuration and native systems. Every
// value comes from configuration, never from a request.
type Config struct {
	// Realm is the gateway's tenant and environment, the realm of every
	// principal.
	Realm adapter.Realm
	// Entries are the issuer entries. Required.
	Entries []Entry
	// Routes are the protected routes and the PACT endpoints that need native
	// authentication. A request no route matches is served by DefaultEntry.
	Routes []Route
	// DefaultEntry, when set, authenticates the requests that no route
	// names, with no required scope.
	DefaultEntry string
	// HTTPClient sends introspection, discovery and key-set requests. Nil is
	// a client with TLS verification and no proxy from the environment.
	HTTPClient *http.Client
	// Timeout bounds each such request. Zero is [DefaultTimeout].
	Timeout time.Duration

	// Origin is the public HTTPS origin of the gateway (draft 10.2).
	Origin string
	// HeaderAllowlist names the application headers an operation context
	// covers besides content-type.
	HeaderAllowlist []string
	// Mappings are the installed route tables by mapping revision. Nil
	// installs [ReferenceRoutes] under [MappingRevision].
	Mappings map[string][]installed.Route

	// Registry is the enrollment registry. Required.
	Registry enroll.Registry
	// Claims are the sources of approved native paths other than the four of
	// section F, by path.
	Claims map[string]installed.ClaimSource
	// Checks are the context checks the deployment installs, by exact id.
	Checks map[string]installed.InstalledCheck
	// Guard is the guard against re-stamping shared by installed checks.
	// Nil creates an empty one.
	Guard *freshness.Monotonic
	// Permissions is the API's native permission lookup. Required.
	Permissions installed.PermissionLookup
	// Reporting signs outcome reports. Nil leaves RecordOutcome unsupported.
	Reporting *installed.Reporting
	// ExecutionVisible says that the gateway observes execution.
	ExecutionVisible bool

	// Clock is the adapter's only source of the current time. Required.
	Clock clock.Clock
}

// ReferenceRoutes is the route table of mapping revision pact-oauth-1, rows R1
// and R2 of profile section 2. The resource of R2 is filled from the
// principal.
func ReferenceRoutes() []installed.Route {
	return []installed.Route{
		{Method: http.MethodGet, Path: "/customers/{customer_id}", Action: "crm.customer.read", Resource: "crm-customer:{customer_id}"},
		{Method: http.MethodGet, Path: "/mail/messages", Action: "mail.message.list", Resource: "mailbox:{principal_id}"},
	}
}

// Adapter is the OAuth adapter of one gateway. It is safe for concurrent use
// when its native systems are.
type Adapter struct {
	cfg      Config
	entries  map[string]*entry
	mappings map[string][]installed.Route
	client   *http.Client
}

var _ adapter.Adapter = (*Adapter)(nil)

// entry is an issuer entry with its runtime state.
type entry struct {
	Entry
	mu sync.Mutex
	// keys is the held key set of a form E entry.
	keys *keySet
	// lastFetch is the last fetch attempt for an unknown kid.
	lastFetch time.Time
	// cache holds introspected facts by a digest of the token (OAUTH-15).
	cache map[[32]byte]cached
}

// New returns the adapter over cfg. It validates the configuration.
func New(cfg Config) (*Adapter, error) {
	switch {
	case cfg.Clock == nil:
		return nil, errors.New("oauth: no clock")
	case cfg.Realm.TenantID == "" || cfg.Realm.EnvironmentID == "":
		return nil, errors.New("oauth: the gateway realm needs a tenant and an environment")
	case cfg.Registry == nil:
		return nil, errors.New("oauth: no enrollment registry")
	case cfg.Permissions == nil:
		return nil, errors.New("oauth: no permission lookup")
	case len(cfg.Entries) == 0:
		return nil, errors.New("oauth: no issuer entry")
	case cfg.Timeout < 0:
		return nil, errors.New("oauth: negative timeout")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	a := &Adapter{cfg: cfg, entries: map[string]*entry{}}
	client := http.Client{Transport: &http.Transport{}}
	if cfg.HTTPClient != nil {
		client = *cfg.HTTPClient
	}
	// A redirect could leave the configured endpoint or the trusted origins
	// (OAUTH-7, OAUTH-23): it is an answer that is not HTTP 200.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	a.client = &client
	for _, e := range cfg.Entries {
		e, err := validEntry(e)
		if err != nil {
			return nil, err
		}
		if _, dup := a.entries[e.ID]; dup {
			return nil, fmt.Errorf("oauth: two issuer entries %q", e.ID)
		}
		a.entries[e.ID] = &entry{Entry: e, cache: map[[32]byte]cached{}}
	}
	for _, rt := range cfg.Routes {
		e, ok := a.entries[rt.Entry]
		if !ok || rt.Method == "" || !strings.HasPrefix(rt.Path, "/") {
			return nil, fmt.Errorf("oauth: route %s %s names no issuer entry", rt.Method, rt.Path)
		}
		if e.Form == FormGoogleID && rt.Scope != "" {
			return nil, fmt.Errorf("oauth: route %s %s requires a scope, which an ID token of entry %q never carries (OAUTH-49)", rt.Method, rt.Path, e.ID)
		}
	}
	if _, ok := a.entries[cfg.DefaultEntry]; cfg.DefaultEntry != "" && !ok {
		return nil, fmt.Errorf("oauth: the default entry %q is not configured", cfg.DefaultEntry)
	}
	for path, src := range cfg.Claims {
		if slices.Contains([]string{PathPrincipalID, PathTenantID, PathClientID, PathScopes}, path) {
			return nil, fmt.Errorf("oauth: %s is answered from the token", path)
		}
		if src == nil {
			return nil, fmt.Errorf("oauth: no source for %s", path)
		}
	}
	if err := installed.ValidateChecks(cfg.Checks); err != nil {
		return nil, fmt.Errorf("oauth: %w", err)
	}
	if err := cfg.Reporting.Validate(); err != nil {
		return nil, fmt.Errorf("oauth: %w", err)
	}
	if cfg.Guard == nil {
		a.cfg.Guard = freshness.NewMonotonic(4096)
	}
	a.mappings = cfg.Mappings
	if a.mappings == nil {
		a.mappings = map[string][]installed.Route{MappingRevision: ReferenceRoutes()}
	}
	for version, routes := range a.mappings {
		if err := a.bindingConfig(version).Validate(); err != nil {
			return nil, fmt.Errorf("oauth: mapping %q: %w", version, err)
		}
		for _, rt := range routes {
			if err := rt.Validate(); err != nil {
				return nil, fmt.Errorf("oauth: mapping %q: %w", version, err)
			}
		}
	}
	return a, nil
}

// validEntry checks an entry and fills in the reference values.
func validEntry(e Entry) (Entry, error) {
	bad := func(format string, args ...any) (Entry, error) {
		return Entry{}, fmt.Errorf("oauth: entry %q: "+format, append([]any{e.ID}, args...)...)
	}
	switch {
	case e.ID == "":
		return bad("no id")
	case e.Issuer == "" || e.Tenant == "":
		return bad("an entry needs an issuer and a tenant")
	case len(e.Audiences) == 0 || len(e.Clients) == 0:
		return bad("an entry needs accepted audiences and a client allowlist")
	case e.Lifetime < 0 || e.CacheBound < 0 || e.KeyRefresh < 0 || e.KeyMaxAge < 0:
		return bad("negative bound")
	}
	if e.SenderConstraint == "" {
		e.SenderConstraint = SenderNone
	}
	if !slices.Contains([]SenderConstraint{SenderNone, SenderDPoP, SenderMTLS}, e.SenderConstraint) {
		return bad("sender constraint %q", e.SenderConstraint)
	}
	e.Audiences, e.Clients = slices.Clone(e.Audiences), slices.Clone(e.Clients)
	switch e.Form {
	case FormIntrospection:
		u, err := url.Parse(e.IntrospectionEndpoint)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return bad("the introspection endpoint must be an https URL")
		}
		if e.ClientID == "" || e.ClientSecret == "" {
			return bad("the gateway's client credentials are required (OAUTH-8)")
		}
		if e.Binding == "" {
			e.Binding = BindingAudience
		}
		if e.Binding != BindingAudience && e.Binding != BindingIntrospectionScoped {
			return bad("resource binding %q", e.Binding)
		}
		if e.Lifetime == 0 {
			e.Lifetime = DefaultLifetimeIntrospection
		}
	case FormEntraV2:
		u, err := url.Parse(e.Issuer)
		if err != nil || u.Scheme != "https" || u.Path != "/"+e.Tenant+"/v2.0" {
			return bad("a form E issuer is https://{host}/{tenant}/v2.0 for the entry's tenant")
		}
		if len(e.Algorithms) == 0 {
			e.Algorithms = []string{algRS256}
		}
		for _, alg := range e.Algorithms {
			if alg != algRS256 {
				return bad("algorithm %q is not implemented; the profile's allowlist is RS256", alg)
			}
		}
		if e.Lifetime == 0 {
			e.Lifetime = DefaultLifetimeEntra
		}
		if e.KeyRefresh == 0 {
			e.KeyRefresh = DefaultKeyRefresh
		}
		if e.KeyMaxAge == 0 {
			e.KeyMaxAge = DefaultKeyMaxAge
		}
		if e.KeyRefresh > e.KeyMaxAge {
			return bad("K exceeds T")
		}
		if len(e.TrustedOrigins) == 0 {
			e.TrustedOrigins = []string{EntraOrigin}
		}
		e.TrustedOrigins = slices.Clone(e.TrustedOrigins)
	case FormGoogleID:
		if e.Issuer != GoogleIssuer {
			return bad("a form G issuer is %s", GoogleIssuer)
		}
		if !domainName(e.Tenant) {
			return bad("a form G tenant is the pinned hosted domain, a domain name")
		}
		if e.SenderConstraint != SenderNone {
			return bad("a Google ID token carries no sender constraint")
		}
		if len(e.Algorithms) == 0 {
			e.Algorithms = []string{algRS256}
		}
		for _, alg := range e.Algorithms {
			if alg != algRS256 {
				return bad("algorithm %q is not implemented; the profile's allowlist is RS256", alg)
			}
		}
		if e.Lifetime == 0 {
			e.Lifetime = DefaultLifetimeGoogle
		}
		if e.KeyRefresh == 0 {
			e.KeyRefresh = DefaultKeyRefresh
		}
		if e.KeyMaxAge == 0 {
			e.KeyMaxAge = DefaultKeyMaxAge
		}
		if e.KeyRefresh > e.KeyMaxAge {
			return bad("K exceeds T")
		}
		if len(e.TrustedOrigins) == 0 {
			e.TrustedOrigins = []string{GoogleKeyOrigin}
		}
		e.TrustedOrigins = slices.Clone(e.TrustedOrigins)
	default:
		return bad("form %q is not introspection, entra-v2 or google-id-token", e.Form)
	}
	return e, nil
}

// Describe returns the primary form, the first entry's: the descriptor of the
// form of the first issuer entry, oauth-introspection, rfc7662,
// entra-access-token, 2.0 or google-id-token, oidc-core-1.0, with mapping
// revision pact-oauth-1.
// [Adapter.Descriptors] returns one per form, as [adapter.DescriptorsOf] does.
func (a *Adapter) Describe() adapter.Descriptor {
	return descriptor(a.cfg.Entries[0].Form)
}

// Descriptors returns the descriptor of each form the adapter's entries use,
// in entry order, for the gateway's metadata (profile section 1).
func (a *Adapter) Descriptors() []adapter.Descriptor {
	var out []adapter.Descriptor
	for _, e := range a.cfg.Entries {
		if d := descriptor(e.Form); !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out
}

func descriptor(f Form) adapter.Descriptor {
	switch f {
	case FormEntraV2:
		return adapter.Descriptor{Protocol: ProtocolEntra, Version: VersionEntra, MappingRevision: MappingRevision}
	case FormGoogleID:
		return adapter.Descriptor{Protocol: ProtocolGoogleID, Version: VersionGoogleID, MappingRevision: MappingRevision}
	}
	return adapter.Descriptor{Protocol: ProtocolIntrospection, Version: VersionIntrospection, MappingRevision: MappingRevision}
}

// bindingConfig is the baseline HTTP mapping under one installed revision.
func (a *Adapter) bindingConfig(version string) binding.Config {
	return binding.Config{
		Origin:                a.cfg.Origin,
		HeaderAllowlist:       a.cfg.HeaderAllowlist,
		HeaderNormalizationID: "pact-oauth-header-normalization-1",
		MappingVersion:        version,
		MaxBody:               maxBody,
	}
}

// maxBody is the largest request body the adapter reads.
const maxBody = 8 << 20

// markKey marks a request that came through the enforcement point.
type markKey struct{}

// Mark returns r marked as having come through the gateway's enforcement
// point. Only the gateway's own filter calls it.
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

// proofKey carries the native sender-constraint verifier's report.
type proofKey struct{}

// WithSenderProof returns r with the report of the deployment's native
// sender-constraint verifier that it verified this request's proof of the
// given constraint, dpop or mtls (profile DR4). The verifier calls it in the
// request path before AuthenticateNative; a header never stands in for it.
func WithSenderProof(r *http.Request, kind SenderConstraint) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), proofKey{}, kind))
}

// senderProof returns the reported constraint, if any.
func senderProof(r *http.Request) SenderConstraint {
	v, _ := r.Context().Value(proofKey{}).(SenderConstraint)
	return v
}

// live fails with a dependency error when ctx is already done.
func live(ctx context.Context, fn string) error {
	if err := installed.Live(ctx); err != nil {
		return fmt.Errorf("oauth: %s: %w", fn, err)
	}
	return nil
}

// routeOf returns the route that matches method and path, and whether one
// does.
func (a *Adapter) routeOf(method, path string) (Route, bool) {
	segs := strings.Split(path, "/")
	for _, rt := range a.cfg.Routes {
		if rt.Method != method {
			continue
		}
		tmpl := strings.Split(rt.Path, "/")
		if len(tmpl) != len(segs) {
			continue
		}
		ok := true
		for i, t := range tmpl {
			if strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}") {
				if segs[i] == "" {
					ok = false
				}
				continue
			}
			if t != segs[i] {
				ok = false
			}
		}
		if ok {
			return rt, true
		}
	}
	if a.cfg.DefaultEntry != "" {
		return Route{Method: method, Path: path, Entry: a.cfg.DefaultEntry}, true
	}
	return Route{}, false
}
