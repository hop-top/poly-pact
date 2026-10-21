package graph

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sync"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/adapter/task"
	"hop.top/pact-go/adapters/oauth"
	"hop.top/pact-go/core/binding"
	"hop.top/pact-go/core/clock"
)

// The descriptors of the two adapter entries (profile section 1).
const (
	ProtocolDelegated   = "graph-delegated-obo"
	ProtocolApplication = "graph-app-only"
	Version             = "v1.0"
	MappingRevision     = "pact-graph-1"
)

// Form is one of the two execution forms of the profile.
type Form string

const (
	// FormDelegated is form D: on-behalf-of execution for a signed-in user,
	// rows GD1 and GD2.
	FormDelegated Form = "delegated"
	// FormApplication is form A: app-only execution for an enrolled
	// workload, rows GA1 and GA2.
	FormApplication Form = "application"
)

// Row is a mapping row of profile section 2.
type Row string

// The rows of revision pact-graph-1.
const (
	RowGD1 Row = "GD1"
	RowGD2 Row = "GD2"
	RowGA1 Row = "GA1"
	RowGA2 Row = "GA2"
)

// Profile constants.
const (
	// ActionMailList is the action of every row.
	ActionMailList = "mail.message.list"
	// FixedQuery is the gateway and downstream query of GD1 and GA1 (GR-23).
	FixedQuery = "$select=id,subject,body&$top=10"
	// GraphOrigin is the downstream origin of every row (GR-4).
	GraphOrigin = "https://graph.microsoft.com"
	// LoginOrigin is the origin of the tenant's token endpoint (GR-4).
	LoginOrigin = "https://login.microsoftonline.com"
	// ScopeMailRead is the scope of the OBO request (GR-6).
	ScopeMailRead = GraphOrigin + "/Mail.Read"
	// ScopeGraphDefault is the scope of a client credentials request for
	// Graph (GR-15).
	ScopeGraphDefault = GraphOrigin + "/.default"
	// CheckExecutionIdentity is the installed check of GR-26.
	CheckExecutionIdentity = "execution-identity-v1"
	// CodeExecutorMismatch is the check reason code of draft 17.5.
	CodeExecutorMismatch = "EXECUTOR_MISMATCH"
	// The executor identity classes of draft 17.5 that the rows use (GR-1).
	ClassDelegatedUser = "delegated-user"
	ClassRegisteredApp = "registered-app-executor"
	// PathExecutionAppID is the approved native path of GR-32.
	PathExecutionAppID = "/graph/execution_app_id"
	// SourceExecutorRegistry is the source id of the executor registry (G1).
	SourceExecutorRegistry = "executor-registry"
	// SourcePreflight is the source id of the grant preflight result (G3).
	SourcePreflight = "grant-preflight"
)

// The reference configuration of GR-20, illustrative policy choices.
const (
	DefaultPreflightInterval = 300 * time.Second
	DefaultSettleWindow      = 7200 * time.Second
	// DefaultTimeout bounds each request to the token endpoint or Graph.
	DefaultTimeout = 10 * time.Second
)

const (
	headerNormalize = "pact-graph-header-normalization-1"
	maxBody         = 1 << 20
	guardCapacity   = 4096
	maxAnswer       = 4 << 20
	// emptyDigest is the base64url SHA-256 of the empty body.
	emptyDigest = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
)

// PageTokenPattern is the grammar of page_token in GD2 and GA2: 22 to 128
// base64url characters (profile section 2).
var PageTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22,128}$`)

// guidPattern is the lower-case form of a directory object or application
// ID.
var guidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Config names the gateway's native systems and its trusted configuration.
// Every value comes from configuration, never from a request.
type Config struct {
	// Form is the execution form of this adapter. Required.
	Form Form
	// Realm is the gateway's tenant and environment.
	Realm adapter.Realm
	// Origin is the public HTTPS origin of the gateway (draft 10.2).
	Origin string
	// HeaderAllowlist names the covered application headers. Nil is the
	// profile's allowlist, accept.
	HeaderAllowlist []string
	// Tenant is the pinned Entra tenant ID, a GUID (GR-4). The issuer
	// identifier of the executor identifiers is the tenant's form E issuer,
	// https://login.microsoftonline.com/{tenant}/v2.0 (OAUTH-37; profile
	// section 7).
	Tenant string
	// Acquirer is the one token acquirer of the adapter: an [OnBehalfOf] of
	// the gateway application in form D, a [ClientCredentials] of the
	// executor application in form A. The adapter holds no other
	// credential, so it has nothing to fall back to (GR-11). Required.
	Acquirer TokenAcquirer
	// Registry is the executor registry (G1). Required.
	Registry ExecutorRegistry
	// Continuations records the continuations of RB-57. Nil is an
	// in-memory store.
	Continuations ContinuationStore
	// Tasks is the task ledger of the multi-operation profile
	// (spec/v1.0/profiles/multi-operation.md). With one, each page is reserved
	// against the budget of its native task before token B is requested
	// (MO-55), the bytes of an answer are released only within max_bytes
	// (MO-21), and a continuation is bound to the native task through the
	// ledger, whose pager is [NewPager] of the form (MO-56). Nil leaves pages
	// unbudgeted: no page is reserved against a task budget (MO-55).
	Tasks task.TaskLedger
	// Preflight configures the grant preflight of form A (GR-16 to GR-21).
	// Required in form A, refused in form D.
	Preflight *PreflightConfig
	// HTTPClient sends the Graph requests of the executor and the auditor.
	// Nil is a client with TLS verification and no proxy. Redirects are
	// never followed.
	HTTPClient *http.Client
	// Timeout bounds each Graph request. Zero is [DefaultTimeout].
	Timeout time.Duration
	// Mappings are further installed route tables by mapping revision,
	// mapped with the baseline binding and executed by nothing.
	Mappings map[string][]installed.Route

	// Authenticator is the inbound authentication of the authenticating
	// profile: form E of the OAuth profile in form D, the workload profile
	// in form A. Required.
	Authenticator adapter.NativeAuthenticator
	// Enrollments is the enrollment registry. Required.
	Enrollments enroll.Registry
	// Permissions is the gateway's policy for authorize_native. Required.
	Permissions installed.PermissionLookup
	// Claims are the sources of the other approved native paths.
	Claims map[string]installed.ClaimSource
	// Checks are the other installed checks, native-delegation-v1 among
	// them, by exact id.
	Checks map[string]installed.InstalledCheck
	// Guard is the guard against re-stamping of installed checks. Nil
	// creates an empty one.
	Guard *freshness.Monotonic
	// Reporting signs outcome reports. Nil leaves RecordOutcome
	// unsupported.
	Reporting *installed.Reporting
	// ExecutionVisible says that the gateway observes the execution of the
	// operations, which it does when [Adapter.Execute] runs them.
	ExecutionVisible bool

	// Clock is the adapter's only source of the current time. Required.
	Clock clock.Clock
}

// Adapter is the Graph adapter of one form and one executor. It is safe for
// concurrent use when its native systems are.
type Adapter struct {
	cfg    Config
	client *http.Client
	checks map[string]installed.InstalledCheck

	mu sync.Mutex
	// appToken is the cached token B of form A (GR-15).
	appToken *Token
	// runs is the preflight history of form A.
	runs preflightHistory
}

var _ adapter.Adapter = (*Adapter)(nil)

// New returns the adapter over cfg. It validates the configuration.
func New(cfg Config) (*Adapter, error) {
	switch {
	case cfg.Clock == nil:
		return nil, errors.New("graph: no clock")
	case cfg.Form != FormDelegated && cfg.Form != FormApplication:
		return nil, fmt.Errorf("graph: form %q", cfg.Form)
	case cfg.Realm.TenantID == "" || cfg.Realm.EnvironmentID == "":
		return nil, errors.New("graph: the gateway realm needs a tenant and an environment")
	case !guidPattern.MatchString(cfg.Tenant):
		return nil, errors.New("graph: the tenant must be a lower-case GUID")
	case cfg.Acquirer == nil:
		return nil, errors.New("graph: no token acquirer")
	case cfg.Registry == nil:
		return nil, errors.New("graph: no executor registry")
	case cfg.Authenticator == nil:
		return nil, errors.New("graph: no inbound authentication")
	case cfg.Enrollments == nil:
		return nil, errors.New("graph: no enrollment registry")
	case cfg.Permissions == nil:
		return nil, errors.New("graph: no policy")
	case cfg.Timeout < 0:
		return nil, errors.New("graph: negative timeout")
	}
	want := GrantOnBehalfOf
	if cfg.Form == FormApplication {
		want = GrantClientCredentials
	}
	if cfg.Acquirer.Grant() != want || !guidPattern.MatchString(cfg.Acquirer.ClientID()) {
		return nil, fmt.Errorf("graph: a %s adapter takes one %s acquirer of an application ID (GR-1, GR-11)", cfg.Form, want)
	}
	switch {
	case cfg.Form == FormDelegated && cfg.Preflight != nil:
		return nil, errors.New("graph: the grant preflight is for form A")
	case cfg.Form == FormApplication:
		if err := cfg.Preflight.validate(cfg.Acquirer.ClientID()); err != nil {
			return nil, err
		}
	}
	if cfg.HeaderAllowlist == nil {
		cfg.HeaderAllowlist = []string{"accept"}
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Continuations == nil {
		cfg.Continuations = NewMemoryContinuations(nil)
	}
	if cfg.Guard == nil {
		cfg.Guard = freshness.NewMonotonic(guardCapacity)
	}
	a := &Adapter{cfg: cfg, client: noRedirect(cfg.HTTPClient)}
	if err := a.bindingConfig(MappingRevision).Validate(); err != nil {
		return nil, fmt.Errorf("graph: %w", err)
	}
	for version, routes := range cfg.Mappings {
		if version == MappingRevision {
			return nil, fmt.Errorf("graph: %s holds the profile's rows only", MappingRevision)
		}
		if err := a.bindingConfig(version).Validate(); err != nil {
			return nil, fmt.Errorf("graph: mapping %q: %w", version, err)
		}
		for _, rt := range routes {
			if err := rt.Validate(); err != nil {
				return nil, fmt.Errorf("graph: mapping %q: %w", version, err)
			}
		}
	}
	for path, src := range cfg.Claims {
		if src == nil || path == PathExecutionAppID {
			return nil, fmt.Errorf("graph: claim source for %s: none, or the executor registry's path", path)
		}
	}
	if _, ok := cfg.Checks[CheckExecutionIdentity]; ok {
		return nil, fmt.Errorf("graph: %s is the adapter's own check", CheckExecutionIdentity)
	}
	if err := installed.ValidateChecks(cfg.Checks); err != nil {
		return nil, fmt.Errorf("graph: %w", err)
	}
	if err := cfg.Reporting.Validate(); err != nil {
		return nil, fmt.Errorf("graph: %w", err)
	}
	a.checks = map[string]installed.InstalledCheck{CheckExecutionIdentity: {Check: identityCheck{a}}}
	for id, c := range cfg.Checks {
		a.checks[id] = c
	}
	return a, nil
}

// noRedirect is a copy of c, or of a client with TLS verification and no
// proxy, that never follows a redirect (GR-4, RB-48).
func noRedirect(c *http.Client) *http.Client {
	out := http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	if c != nil {
		out = *c
	}
	out.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &out
}

// Describe returns the descriptor of the adapter's form (profile section 1).
func (a *Adapter) Describe() adapter.Descriptor {
	if a.cfg.Form == FormDelegated {
		return adapter.Descriptor{Protocol: ProtocolDelegated, Version: Version, MappingRevision: MappingRevision}
	}
	return adapter.Descriptor{Protocol: ProtocolApplication, Version: Version, MappingRevision: MappingRevision}
}

// bindingConfig is the baseline HTTP mapping under one revision.
func (a *Adapter) bindingConfig(version string) binding.Config {
	return binding.Config{
		Origin:                a.cfg.Origin,
		HeaderAllowlist:       a.cfg.HeaderAllowlist,
		HeaderNormalizationID: headerNormalize,
		MappingVersion:        version,
		MaxBody:               maxBody,
	}
}

// ExecutorID is the namespaced identifier of an application of the tenant,
// oauth:{issuer-id}:{tenant}:{app-id}, the form of an OAuth client workload
// (profile section 7).
func (a *Adapter) ExecutorID(appID string) string {
	return oauth.Identifier(LoginOrigin+"/"+a.cfg.Tenant+"/v2.0", a.cfg.Tenant, appID)
}

// class is the executor class of the adapter's rows (GR-1).
func (a *Adapter) class() string {
	if a.cfg.Form == FormDelegated {
		return ClassDelegatedUser
	}
	return ClassRegisteredApp
}

// grant is the token request of the adapter's rows.
func (a *Adapter) grant() Grant {
	if a.cfg.Form == FormDelegated {
		return GrantOnBehalfOf
	}
	return GrantClientCredentials
}
