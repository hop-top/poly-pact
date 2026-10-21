package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/http"
	"regexp"
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

// The descriptor of the adapter (profile section 1).
const (
	Protocol        = "postgresql"
	Version         = "3.0"
	MappingRevision = "pact-db-1"
)

// ActionReportRead is the action of route R1 (profile section 2).
const ActionReportRead = "report.read"

// CheckExecutionIdentity is the installed check of profile RA-5 (draft
// 17.5).
const CheckExecutionIdentity = "execution-identity-v1"

// CodeExecutorMismatch is the check reason code of draft 17.5 for a
// connection whose role is not the mapped login role (profile CV-7).
const CodeExecutorMismatch = "EXECUTOR_MISMATCH"

// ClassDedicatedRole is the executor class of every registered statement
// (draft 17.5, profile section 1).
const ClassDedicatedRole = "dedicated-role"

// The approved native paths the role and tenant registry answers (profile
// section 2, F1).
const (
	PathDatabaseRole = "/attributes/environment/database_role"
	PathTenantID     = "/attributes/environment/tenant_id"
)

// SourceRegistry is the source id of the role and tenant registry.
const SourceRegistry = "role-registry"

// The reference values of the profile parameters (profile section 1): an
// illustrative policy choice, not a recommended threshold.
const (
	DefaultMaxConnsPerRole = 2
	DefaultConnMaxLifetime = 300 * time.Second
	// DefaultTimeout bounds each step on a connection: acquisition, the
	// verification, the statement and the reset (profile CR-4).
	DefaultTimeout = 5 * time.Second
)

const (
	maxBody         = 8 << 20
	guardCapacity   = 4096
	headerNormalize = "pact-db-header-normalization-1"
)

// ReportIDPattern is the grammar of report_id in route R1: 1 to 64
// characters of ALPHA, DIGIT and "-" (profile section 2, RB-34).
var ReportIDPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// UnreservedPattern is the baseline parameter grammar of RB-34: 1 to 64
// unreserved characters. A value "." or ".." is refused separately.
var UnreservedPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,64}$`)

// Route maps a method and a path template to an action and a resource
// template. A {name} segment of Path stands for one path segment, whose value
// must match Params[name]; the same placeholder in Resource is replaced by
// it.
type Route struct {
	Method   string
	Path     string
	Action   string
	Resource string
	// Params is the grammar of each placeholder of Path (RB-34). Every
	// placeholder needs one.
	Params map[string]*regexp.Regexp
	// AcceptsBody says that the route accepts a body; a non-empty body on a
	// route that accepts none is refused (RB-37).
	AcceptsBody bool
}

// ReportRoutes is the route table of revision pact-db-1: route R1, GET
// /api/v1/reports/{report_id}, the action report.read on report:{report_id}
// (profile section 2).
func ReportRoutes() []Route {
	return []Route{{
		Method: http.MethodGet, Path: "/api/v1/reports/{report_id}", Action: ActionReportRead, Resource: "report:{report_id}",
		Params: map[string]*regexp.Regexp{"report_id": ReportIDPattern},
	}}
}

// Table is a protected table, by schema and name.
type Table struct{ Schema, Name string }

// Query is an entry of the query registry (profile section 2, QB-1, QB-2):
// the statement an action runs under a mapping revision.
type Query struct {
	Action   string
	Revision string
	// Text is the statement, a constant: one SQL statement with
	// schema-qualified names and $n placeholders.
	Text string
	// Args names, in the order of $1, $2, ..., the route placeholders whose
	// values are bound.
	Args []string
	// Tables are the protected tables the statement reads; V3 runs once for
	// each.
	Tables []Table
}

// ReportQuery is the entry (report.read, pact-db-1) of profile section 2,
// the statement of sample I13.
func ReportQuery() Query {
	return Query{
		Action:   ActionReportRead,
		Revision: MappingRevision,
		Text:     "SELECT report_id, body FROM public.customer_reports WHERE report_id = $1",
		Args:     []string{"report_id"},
		Tables:   []Table{{Schema: "public", Name: "customer_reports"}},
	}
}

// RoleRecord is a record of the role and tenant registry (profile RA-1).
type RoleRecord struct {
	// ClusterID is the cluster of the login role.
	ClusterID string
	// LoginRole is the role the connection authenticates as.
	LoginRole string
	// RoleOID is the role's OID recorded at registration (RA-7).
	RoleOID uint32
	// CredentialRef names the role's credential in the secret store.
	CredentialRef string
	// TenantID is the tenant of the principal.
	TenantID string
	// Revision is the registry revision of the record.
	Revision string
	// ChangedAt is the time of the record's last change; zero when the
	// registry gives none.
	ChangedAt time.Time
}

// ErrNoRecord is the error of a registry that holds no record for the
// principal.
var ErrNoRecord = errors.New("db: the role registry has no record for the principal")

// RoleRegistry is the role and tenant registry, trusted configuration that
// only administrators change (RA-1).
type RoleRegistry interface {
	// Lookup returns the record of the principal in realm: [ErrNoRecord]
	// when there is none, another error when the registry cannot answer.
	Lookup(ctx context.Context, realm adapter.Realm, principal string) (RoleRecord, error)
}

// Dialer opens connections for a login role with that role's own credential
// (RA-3). It holds no other credential: there is no owner, superuser or
// pool-administrator connection to fall back on (RA-5).
type Dialer interface {
	// Connector returns the connector of the role of rec. An error means the
	// broker holds no credential for the role.
	Connector(ctx context.Context, rec RoleRecord) (driver.Connector, error)
}

// PermissionLookup is the broker's native task policy (profile section 3,
// row 4).
type PermissionLookup = installed.PermissionLookup

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

// Config names the broker's native systems and its trusted configuration.
// Every value comes from configuration, never from a request.
type Config struct {
	// Realm is the tenant and environment of the broker.
	Realm adapter.Realm
	// ClusterID is the configured identifier of the cluster, made of
	// unreserved characters.
	ClusterID string
	// Origin is the public HTTPS origin of the broker (draft 10.2).
	Origin string
	// HeaderAllowlist names the application headers an operation context
	// covers besides content-type.
	HeaderAllowlist []string
	// Revision is the installed mapping revision under which Execute runs
	// operations. Empty is [MappingRevision].
	Revision string
	// Mappings are the installed route tables by mapping revision. Nil
	// installs [ReportRoutes] under [MappingRevision].
	Mappings map[string][]Route
	// Queries is the query registry. Nil installs [ReportQuery].
	Queries []Query

	// Registry is the role and tenant registry. Required.
	Registry RoleRegistry
	// Dialer opens the connections of the mapped roles. Required.
	Dialer Dialer
	// MaxConnsPerRole is role_pool_max_connections (CR-1). Zero is
	// [DefaultMaxConnsPerRole].
	MaxConnsPerRole int
	// ConnMaxLifetime is connection_max_lifetime_seconds (CR-6). Zero is
	// [DefaultConnMaxLifetime].
	ConnMaxLifetime time.Duration
	// Timeout bounds each step on a connection. Zero is [DefaultTimeout].
	Timeout time.Duration
	// OnExecute, when set, is called just before the registered statement is
	// sent.
	OnExecute func()

	// Authenticator is the front-door authentication the deployment names
	// (profile section 1). Required.
	Authenticator adapter.NativeAuthenticator
	// Enrollments is the enrollment registry. Required.
	Enrollments enroll.Registry
	// Permissions is the broker's native task policy. Required.
	Permissions PermissionLookup
	// Claims are the sources of the other approved native paths, by path.
	Claims map[string]ClaimSource
	// Checks are the other installed context checks by exact check id.
	Checks map[string]InstalledCheck
	// Guard is the guard against re-stamping that installed checks with
	// freshness limits share. Nil creates an empty one.
	Guard *freshness.Monotonic
	// Reporting signs outcome reports. Nil leaves RecordOutcome unsupported.
	Reporting *Reporting
	// ExecutionVisible says that the broker observes the execution of the
	// operations, which it does when it runs them.
	ExecutionVisible bool

	// Clock is the adapter's only source of the current time. Required.
	Clock clock.Clock
}

// Adapter is the database adapter. It is safe for concurrent use when its
// native systems are.
type Adapter struct {
	cfg      Config
	mappings map[string][]Route
	queries  map[queryKey]Query
	checks   map[string]InstalledCheck

	mu    sync.Mutex
	pools map[poolKey]*sql.DB
}

type queryKey struct{ action, revision string }

type poolKey struct{ cluster, role string }

var _ adapter.Adapter = (*Adapter)(nil)

// New returns the adapter over cfg. It validates the configuration.
func New(cfg Config) (*Adapter, error) {
	switch {
	case cfg.Clock == nil:
		return nil, errors.New("db: no clock")
	case cfg.Realm.TenantID == "" || cfg.Realm.EnvironmentID == "":
		return nil, errors.New("db: the broker realm needs a tenant and an environment")
	case !UnreservedPattern.MatchString(cfg.ClusterID):
		return nil, errors.New("db: the cluster id must be unreserved characters")
	case cfg.Registry == nil:
		return nil, errors.New("db: no role registry")
	case cfg.Dialer == nil:
		return nil, errors.New("db: no dialer")
	case cfg.Authenticator == nil:
		return nil, errors.New("db: no front-door authentication")
	case cfg.Enrollments == nil:
		return nil, errors.New("db: no enrollment registry")
	case cfg.Permissions == nil:
		return nil, errors.New("db: no task policy")
	case cfg.MaxConnsPerRole < 0 || cfg.ConnMaxLifetime < 0 || cfg.Timeout < 0:
		return nil, errors.New("db: negative pool limit or timeout")
	}
	if cfg.Revision == "" {
		cfg.Revision = MappingRevision
	}
	if cfg.MaxConnsPerRole == 0 {
		cfg.MaxConnsPerRole = DefaultMaxConnsPerRole
	}
	if cfg.ConnMaxLifetime == 0 {
		cfg.ConnMaxLifetime = DefaultConnMaxLifetime
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	a := &Adapter{cfg: cfg, mappings: cfg.Mappings, queries: map[queryKey]Query{}, pools: map[poolKey]*sql.DB{}}
	if a.mappings == nil {
		a.mappings = map[string][]Route{MappingRevision: ReportRoutes()}
	}
	for version, routes := range a.mappings {
		if err := a.bindingConfig(version).Validate(); err != nil {
			return nil, fmt.Errorf("db: mapping %q: %w", version, err)
		}
		for _, rt := range routes {
			if err := validateRoute(rt); err != nil {
				return nil, fmt.Errorf("db: mapping %q: %w", version, err)
			}
		}
	}
	queries := cfg.Queries
	if queries == nil {
		queries = []Query{ReportQuery()}
	}
	for _, q := range queries {
		k := queryKey{q.Action, q.Revision}
		if err := validateQuery(q, a.mappings[q.Revision]); err != nil {
			return nil, fmt.Errorf("db: query (%s, %s): %w", q.Action, q.Revision, err)
		}
		if _, dup := a.queries[k]; dup {
			return nil, fmt.Errorf("db: query (%s, %s) has two entries", q.Action, q.Revision)
		}
		a.queries[k] = q
	}
	if _, ok := a.mappings[cfg.Revision]; !ok {
		return nil, fmt.Errorf("db: the revision %q is not installed", cfg.Revision)
	}
	for path, src := range cfg.Claims {
		if src == nil || path == PathDatabaseRole || path == PathTenantID {
			return nil, fmt.Errorf("db: claim source for %s: none, or a path of the role registry", path)
		}
	}
	if _, ok := cfg.Checks[CheckExecutionIdentity]; ok {
		return nil, fmt.Errorf("db: %s is the adapter's own check", CheckExecutionIdentity)
	}
	if err := installed.ValidateChecks(cfg.Checks); err != nil {
		return nil, fmt.Errorf("db: %w", err)
	}
	if err := cfg.Reporting.Validate(); err != nil {
		return nil, fmt.Errorf("db: %w", err)
	}
	if a.cfg.Guard == nil {
		a.cfg.Guard = freshness.NewMonotonic(guardCapacity)
	}
	a.checks = map[string]InstalledCheck{CheckExecutionIdentity: {Check: identityCheck{a}}}
	for id, c := range cfg.Checks {
		a.checks[id] = c
	}
	return a, nil
}

// validateRoute refuses an incomplete route and a placeholder without a
// grammar.
func validateRoute(rt Route) error {
	if err := (installed.Route{Method: rt.Method, Path: rt.Path, Action: rt.Action, Resource: rt.Resource}).Validate(); err != nil {
		return err
	}
	for _, seg := range strings.Split(rt.Path, "/") {
		if name, ok := placeholder(seg); ok && rt.Params[name] == nil {
			return fmt.Errorf("route %s %s: the placeholder %q has no grammar", rt.Method, rt.Path, name)
		}
	}
	return nil
}

// validateQuery refuses an entry whose statement holds more than one
// statement, whose argument is not a placeholder of a route of its action,
// or whose $n do not match its arguments.
func validateQuery(q Query, routes []Route) error {
	switch {
	case q.Action == "" || q.Revision == "" || strings.TrimSpace(q.Text) == "":
		return errors.New("incomplete entry")
	case strings.Contains(q.Text, ";"):
		return errors.New("the statement must be one SQL statement without a semicolon (QB-2)")
	}
	for i := range q.Args {
		if !strings.Contains(q.Text, fmt.Sprintf("$%d", i+1)) {
			return fmt.Errorf("the statement has no $%d", i+1)
		}
	}
	if strings.Contains(q.Text, fmt.Sprintf("$%d", len(q.Args)+1)) {
		return errors.New("the statement has more placeholders than arguments")
	}
	for _, rt := range routes {
		if rt.Action != q.Action {
			continue
		}
		for _, arg := range q.Args {
			if rt.Params[arg] == nil {
				return fmt.Errorf("route %s %s has no placeholder %q", rt.Method, rt.Path, arg)
			}
		}
	}
	return nil
}

func placeholder(seg string) (string, bool) {
	if len(seg) > 2 && strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
		return seg[1 : len(seg)-1], true
	}
	return "", false
}

// Describe returns the descriptor of the profile: postgresql, 3.0,
// pact-db-1.
func (a *Adapter) Describe() adapter.Descriptor {
	return adapter.Descriptor{Protocol: Protocol, Version: Version, MappingRevision: MappingRevision}
}

// Close closes every pool.
func (a *Adapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var errs []error
	for k, p := range a.pools {
		errs = append(errs, p.Close())
		delete(a.pools, k)
	}
	return errors.Join(errs...)
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

// lookup reads the principal's record, refusing a record of another cluster:
// the broker holds pools for its own cluster only.
func (a *Adapter) lookup(ctx context.Context, realm adapter.Realm, principal string) (RoleRecord, error) {
	if principal == "" {
		return RoleRecord{}, fmt.Errorf("no principal: %w", adapter.ErrContextMismatch)
	}
	rec, err := a.cfg.Registry.Lookup(ctx, realm, principal)
	switch {
	case errors.Is(err, ErrNoRecord):
		return RoleRecord{}, fmt.Errorf("%w: %w", err, adapter.ErrDependencyUnavailable)
	case err != nil:
		return RoleRecord{}, fmt.Errorf("the role registry cannot answer: %w", adapter.ErrDependencyUnavailable)
	case rec.ClusterID != a.cfg.ClusterID || rec.LoginRole == "" || rec.RoleOID == 0:
		return RoleRecord{}, fmt.Errorf("the registry record names no login role of the cluster: %w", adapter.ErrDependencyUnavailable)
	}
	if err := installed.SourceTimes(a.cfg.Clock.Now(), rec.ChangedAt); err != nil {
		return RoleRecord{}, err
	}
	return rec, nil
}

// pool returns the pool of the role of rec, opening it on first use. Opening
// a pool opens no connection.
func (a *Adapter) pool(ctx context.Context, rec RoleRecord) (*sql.DB, error) {
	k := poolKey{rec.ClusterID, rec.LoginRole}
	a.mu.Lock()
	defer a.mu.Unlock()
	if p, ok := a.pools[k]; ok {
		return p, nil
	}
	c, err := a.cfg.Dialer.Connector(ctx, rec)
	if err != nil || c == nil {
		return nil, fmt.Errorf("the broker holds no credential for the mapped role: %w", adapter.ErrDependencyUnavailable)
	}
	p := sql.OpenDB(c)
	p.SetMaxOpenConns(a.cfg.MaxConnsPerRole)
	p.SetMaxIdleConns(a.cfg.MaxConnsPerRole)
	p.SetConnMaxLifetime(a.cfg.ConnMaxLifetime)
	a.pools[k] = p
	return p, nil
}

// Identifier is the executor identifier db:{cluster-id}:{login-role}
// (identity mapping section 3.3), each component written under IM-2.
func Identifier(clusterID, loginRole string) string {
	return "db:" + component(clusterID) + ":" + component(loginRole)
}

// component writes s under IM-2: every octet that is not unreserved as %XX
// in upper case.
func component(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// live fails with a dependency error when ctx is already done.
func live(ctx context.Context, fn string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("db: %s: %w: %w", fn, adapter.ErrDependencyUnavailable, err)
	}
	return nil
}
