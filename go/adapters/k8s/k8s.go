package k8s

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"hop.top/pact-go/internal/ascii"
)

// The descriptor of the adapter (profile section 1).
const (
	Protocol        = "kubernetes-serviceaccount"
	Version         = "authentication.k8s.io/v1+authorization.k8s.io/v1"
	MappingRevision = "pact-k8s-1"
)

// Mechanism is the Mechanism of a principal the adapter authenticates.
const Mechanism adapter.Mechanism = "kubernetes-serviceaccount"

// The approved native paths of KR-20.
const (
	PathPrincipalID = "/attributes/environment/principal_id"
	PathNamespace   = "/attributes/environment/namespace"
	PathClusterID   = "/attributes/environment/cluster_id"
)

// AttrK8s is the attribute of an authenticated principal that holds
// {"cluster_id", "namespace", "name", "uid", "groups", "issued_at",
// "reviewed_at"}: the reviewed account, its groups as the review reported
// them, the token's iat and the time of the review, in Unix seconds.
const AttrK8s = "k8s"

// CheckExecutionIdentity is the installed check of KR-11 (draft 17.5).
const CheckExecutionIdentity = "execution-identity-v1"

// CodeExecutorMismatch is the check reason code of draft 17.5 for an executor
// other than the registered account.
const CodeExecutorMismatch = "EXECUTOR_MISMATCH"

// The source ids the adapter names in what it returns.
const (
	SourceTokenReview  = "kubernetes-tokenreview"
	SourceClusterEntry = "cluster-entry"
	SourceAPIServer    = "kubernetes-api-server"
	SourceExecutor     = "kubernetes-executor"
	// sourceMapping names the adapter itself as the source of a denial for a
	// principal the API server cannot be asked about.
	sourceMapping = "kubernetes-principal-mapping"
)

// The reference configuration of the profile (section 8, KR-17), an
// illustrative policy choice and not a recommended threshold.
const (
	DefaultReviewBound       = 60 * time.Second
	DefaultPreflightInterval = 300 * time.Second
	// DefaultTimeout bounds every request to the API server (KR-22).
	DefaultTimeout = 5 * time.Second
)

// RowNamespace is the namespace constant of rows R1 and R2 (profile section
// 2).
const RowNamespace = "operations"

// Account is a registered service account (KR-7): its namespace, name and
// the uid recorded at enrollment.
type Account struct {
	Namespace, Name, UID string
}

// Username is the user name the cluster reports for the account [K3].
func (a Account) Username() string {
	return "system:serviceaccount:" + a.Namespace + ":" + a.Name
}

// TokenSource returns a bearer token, read fresh for each request so that a
// refreshed projected token is used.
type TokenSource func(ctx context.Context) (string, error)

// Config names the gateway's trusted configuration and native systems. Every
// value comes from configuration, never from a request or a token.
type Config struct {
	// Realm is the gateway's tenant and environment.
	Realm adapter.Realm

	// ClusterID is the configured identifier of the cluster (KR-1), made of
	// unreserved characters.
	ClusterID string
	// APIServer is the https URL of the pinned API server.
	APIServer string
	// RootCAs are the trust anchors of the API server's certificate.
	// Required: the system pool is never used.
	RootCAs *x509.CertPool
	// GatewayAudience is the audience every review asks for (KR-2).
	GatewayAudience string
	// Namespaces are the claimed namespaces.
	Namespaces []string
	// Accounts are the registered accounts.
	Accounts []Account
	// GatewayToken is the gateway account's token, sent with every review
	// and pod read and never elsewhere (KR-3).
	GatewayToken TokenSource
	// Timeout bounds each request to the API server. Zero is
	// [DefaultTimeout].
	Timeout time.Duration
	// ReviewBound is B (section 8). Zero is [DefaultReviewBound].
	ReviewBound time.Duration
	// PreflightInterval is P (KR-17). Zero is [DefaultPreflightInterval].
	PreflightInterval time.Duration

	// Executors report the executor of each registered account, by
	// "namespace/name", for [CheckExecutionIdentity].
	Executors map[string]ExecutorSource

	// Origin is the public HTTPS origin of the gateway (draft 10.2).
	Origin string
	// HeaderAllowlist names the application headers an operation context
	// covers besides content-type. It never names authorization or a header
	// that names a user (KR-9).
	HeaderAllowlist []string
	// Mappings are the installed route tables by mapping revision. Nil
	// installs [ReferenceRoutes] under [MappingRevision].
	Mappings map[string][]installed.Route

	// Registry is the enrollment registry. Required.
	Registry enroll.Registry
	// Claims are the sources of approved native paths other than those of
	// KR-20, by path.
	Claims map[string]installed.ClaimSource
	// Checks are the further context checks the deployment installs. It
	// cannot name [CheckExecutionIdentity].
	Checks map[string]installed.InstalledCheck
	// Guard is the guard against re-stamping shared by installed checks.
	// Nil creates an empty one.
	Guard *freshness.Monotonic
	// Reporting signs outcome reports. Nil leaves RecordOutcome unsupported.
	Reporting *installed.Reporting
	// ExecutionVisible says that the gateway observes execution.
	ExecutionVisible bool

	// Clock is the adapter's only source of the current time. Required.
	Clock clock.Clock
}

// ReferenceRoutes is the route table of mapping revision pact-k8s-1 for a
// cluster: rows R1 and R2 of profile section 2.
func ReferenceRoutes(clusterID string) []installed.Route {
	base := ResourceBase(clusterID)
	return []installed.Route{
		{Method: http.MethodGet, Path: "/api/v1/deployments", Action: ActionList, Resource: base},
		{Method: http.MethodGet, Path: "/api/v1/deployments/{name}", Action: ActionGet, Resource: base + "/{name}"},
	}
}

// The actions of rows R1 and R2.
const (
	ActionList = "deployments.list"
	ActionGet  = "deployments.get"
)

// ResourceBase is the resource of row R1 for a cluster.
func ResourceBase(clusterID string) string {
	return "https://k8s.example/clusters/" + clusterID + "/apis/apps/v1/namespaces/" + RowNamespace + "/deployments"
}

// Adapter is the Kubernetes adapter of one gateway and one cluster. It is
// safe for concurrent use when its native systems are.
type Adapter struct {
	cfg      Config
	api      *apiClient
	mappings map[string][]installed.Route
	checks   map[string]installed.InstalledCheck
	accounts map[string]Account

	mu        sync.Mutex
	preflight map[string]preflightResult
}

var _ adapter.Adapter = (*Adapter)(nil)

// guardCapacity bounds the guard against re-stamping that New creates.
const guardCapacity = 4096

// New returns the adapter over cfg. It validates the configuration.
func New(cfg Config) (*Adapter, error) {
	switch {
	case cfg.Clock == nil:
		return nil, errors.New("k8s: no clock")
	case cfg.Realm.TenantID == "" || cfg.Realm.EnvironmentID == "":
		return nil, errors.New("k8s: the gateway realm needs a tenant and an environment")
	case cfg.ClusterID == "" || component(cfg.ClusterID) != cfg.ClusterID:
		return nil, fmt.Errorf("k8s: cluster id %q is empty or not unreserved", cfg.ClusterID)
	case cfg.RootCAs == nil:
		return nil, errors.New("k8s: no trust anchors for the API server (KR-1)")
	case cfg.GatewayToken == nil:
		return nil, errors.New("k8s: no gateway account token (KR-3)")
	case cfg.Registry == nil:
		return nil, errors.New("k8s: no enrollment registry")
	case len(cfg.Namespaces) == 0:
		return nil, errors.New("k8s: no claimed namespace")
	case cfg.Timeout < 0 || cfg.ReviewBound < 0 || cfg.PreflightInterval < 0:
		return nil, errors.New("k8s: negative timeout, bound or interval")
	}
	u, err := url.Parse(cfg.APIServer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.TrimSuffix(u.Path, "/") != "" {
		return nil, fmt.Errorf("k8s: the API server %q must be an https origin", cfg.APIServer)
	}
	if a, err := url.Parse(cfg.GatewayAudience); err != nil || a.Scheme != "https" || a.Host == "" {
		return nil, fmt.Errorf("k8s: the gateway audience %q must be an https URI (KR-2)", cfg.GatewayAudience)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.ReviewBound == 0 {
		cfg.ReviewBound = DefaultReviewBound
	}
	if cfg.PreflightInterval == 0 {
		cfg.PreflightInterval = DefaultPreflightInterval
	}
	cfg.Namespaces = slices.Clone(cfg.Namespaces)
	for _, name := range cfg.HeaderAllowlist {
		if n := ascii.ToLower(name); n == "authorization" || userHeader(n) {
			return nil, fmt.Errorf("k8s: header %q is never covered (KR-9)", name)
		}
	}
	a := &Adapter{
		cfg: cfg, accounts: map[string]Account{}, checks: map[string]installed.InstalledCheck{},
		preflight: map[string]preflightResult{},
	}
	for _, acct := range cfg.Accounts {
		switch {
		case acct.Namespace == "" || acct.Name == "" || acct.UID == "":
			return nil, errors.New("k8s: a registered account needs a namespace, a name and a uid")
		case !slices.Contains(cfg.Namespaces, acct.Namespace):
			return nil, fmt.Errorf("k8s: account %s/%s is outside the claimed namespaces", acct.Namespace, acct.Name)
		}
		a.accounts[acct.Namespace+"/"+acct.Name] = acct
	}
	for path, src := range cfg.Claims {
		if path == PathPrincipalID || path == PathNamespace || path == PathClusterID {
			return nil, fmt.Errorf("k8s: %s is answered from the review", path)
		}
		if src == nil {
			return nil, fmt.Errorf("k8s: no source for %s", path)
		}
	}
	if _, ok := cfg.Checks[CheckExecutionIdentity]; ok {
		return nil, fmt.Errorf("k8s: %s is the adapter's own check", CheckExecutionIdentity)
	}
	if err := installed.ValidateChecks(cfg.Checks); err != nil {
		return nil, fmt.Errorf("k8s: %w", err)
	}
	if err := cfg.Reporting.Validate(); err != nil {
		return nil, fmt.Errorf("k8s: %w", err)
	}
	if cfg.Guard == nil {
		a.cfg.Guard = freshness.NewMonotonic(guardCapacity)
	}
	a.mappings = cfg.Mappings
	if a.mappings == nil {
		a.mappings = map[string][]installed.Route{MappingRevision: ReferenceRoutes(cfg.ClusterID)}
	}
	for version, routes := range a.mappings {
		if err := a.bindingConfig(version).Validate(); err != nil {
			return nil, fmt.Errorf("k8s: mapping %q: %w", version, err)
		}
		for _, rt := range routes {
			if err := rt.Validate(); err != nil {
				return nil, fmt.Errorf("k8s: mapping %q: %w", version, err)
			}
		}
	}
	for id, c := range cfg.Checks {
		a.checks[id] = c
	}
	a.checks[CheckExecutionIdentity] = installed.InstalledCheck{Check: executionCheck{a: a}}
	a.api = newAPIClient(strings.TrimSuffix(cfg.APIServer, "/"), cfg.RootCAs, cfg.Timeout)
	return a, nil
}

// newHTTPClient is a client that trusts only roots, takes no proxy from the
// environment and follows no redirect, which could leave the pinned API
// server (KR-1).
func newHTTPClient(roots *x509.CertPool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Describe returns the descriptor of the profile.
func (a *Adapter) Describe() adapter.Descriptor {
	return adapter.Descriptor{Protocol: Protocol, Version: Version, MappingRevision: MappingRevision}
}

// bindingConfig is the baseline HTTP mapping under one installed revision.
func (a *Adapter) bindingConfig(version string) binding.Config {
	return binding.Config{
		Origin:                a.cfg.Origin,
		HeaderAllowlist:       a.cfg.HeaderAllowlist,
		HeaderNormalizationID: "pact-k8s-header-normalization-1",
		MappingVersion:        version,
		MaxBody:               maxBody,
	}
}

// maxBody is the largest request body the adapter reads.
const maxBody = 1 << 20

// userHeader reports whether a lowercase header name names a user: the
// impersonation headers [K12] and the authenticating-proxy headers [K3].
func userHeader(n string) bool {
	return strings.HasPrefix(n, "impersonate-") || strings.HasPrefix(n, "x-remote-")
}

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

// Enforce is the filter that marks every request it passes to next, after
// removing every header that names a user (KR-9), so that nothing after it
// can read or forward one.
func Enforce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, Mark(StripUserHeaders(r)))
	})
}

// StripUserHeaders returns r without the impersonation and
// authenticating-proxy headers (KR-9).
func StripUserHeaders(r *http.Request) *http.Request {
	var drop []string
	for name := range r.Header {
		if userHeader(ascii.ToLower(name)) {
			drop = append(drop, name)
		}
	}
	if len(drop) == 0 {
		return r
	}
	r = r.Clone(r.Context())
	for _, name := range drop {
		r.Header.Del(name)
	}
	return r
}

// live fails with a dependency error when ctx is already done.
func live(ctx context.Context, fn string) error {
	if err := installed.Live(ctx); err != nil {
		return fmt.Errorf("k8s: %s: %w", fn, err)
	}
	return nil
}

// Identifier is k8s:{cluster-id}:system:serviceaccount:{namespace}:{name},
// each component written under IM-2.
func Identifier(clusterID, namespace, name string) string {
	return "k8s:" + component(clusterID) + ":system:serviceaccount:" + component(namespace) + ":" + component(name)
}

// component writes s under IM-2: every octet that is not unreserved as %XX
// in upper case.
func component(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		}
	}
	return b.String()
}

// accountOf returns the registered account whose identifier is id.
func (a *Adapter) accountOf(id string) (Account, bool) {
	for _, acct := range a.accounts {
		if Identifier(a.cfg.ClusterID, acct.Namespace, acct.Name) == id {
			return acct, true
		}
	}
	return Account{}, false
}
