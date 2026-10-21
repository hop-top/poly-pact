package aws

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
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
	Protocol        = "aws-apigateway-http-api"
	Version         = "payload-format-2.0"
	MappingRevision = "pact-aws-1"
)

// Mechanism is the Mechanism of a principal the adapter authenticates.
const Mechanism adapter.Mechanism = "aws-iam"

// The native paths the profile claims (AR-25).
const (
	PathPrincipalID  = "/attributes/environment/principal_id"
	PathWorkloadRole = "/attributes/environment/workload_role"
	PathAccountID    = "/attributes/environment/account_id"
)

// AttrIAM is the attribute of an authenticated principal that holds
// {"account_id", "role_arn", "status_time"}: the account and the role ARN of
// the role entry, and the status time of AR-25 in Unix seconds.
const AttrIAM = "aws"

// CheckExecutionIdentity is the installed check of AR-22 (draft 17.5).
const CheckExecutionIdentity = "execution-identity-v1"

// CodeExecutorMismatch is the check reason code of draft 17.5 for an executor
// other than the declared one.
const CodeExecutorMismatch = "EXECUTOR_MISMATCH"

// The defaults of the profile's reference configuration (section 8), an
// illustrative policy choice and not a recommended threshold.
const (
	DefaultCheckInterval    = 300 * time.Second
	DefaultPropagationBound = 60 * time.Second
)

// DefaultMaxEventBytes is the size limit of an event when the configuration
// sets none; a configuration choice, not an AWS quota.
const DefaultMaxEventBytes = 8 << 20

// DefaultHeaderNormalizationID names the header rule of AR-18, under which a
// covered header is the value API Gateway put in the event's headers member,
// with duplicates already combined by API Gateway. The gateway publishes it
// (RB-25; profile open item O5).
const DefaultHeaderNormalizationID = "pact-aws-header-normalization-1"

// The source ids the adapter names in what it returns.
const (
	sourceIAMContext = "aws-iam-context"
	sourceExecutor   = "lambda-execution-context"
)

// SessionNameKind is the kind of a session-name rule (AR-10).
type SessionNameKind string

const (
	// SessionNameAny imposes nothing.
	SessionNameAny SessionNameKind = "any"
	// SessionNameExact admits one session name, octet for octet.
	SessionNameExact SessionNameKind = "exact"
	// SessionNamePrefix admits the session names that begin with Value.
	SessionNamePrefix SessionNameKind = "prefix"
)

// SessionNameRule is the session-name rule of a role entry: a filter that the
// role's trust policy enforces through sts:RoleSessionName, never an input to
// the identifier (AR-10).
type SessionNameRule struct {
	Kind  SessionNameKind
	Value string
}

// admits reports whether the rule admits a session name.
func (r SessionNameRule) admits(name string) bool {
	switch r.Kind {
	case SessionNameAny:
		return true
	case SessionNameExact:
		return name == r.Value
	case SessionNamePrefix:
		return strings.HasPrefix(name, r.Value)
	}
	return false
}

// RoleEntry is an entry of the role table (AR-8 to AR-10).
type RoleEntry struct {
	// AccountID is the account of the role.
	AccountID string
	// RoleARN is the ARN of the role with its path.
	RoleARN string
	// RoleID is the role's unique ID.
	RoleID string
	// SessionName is the session-name rule of the entry.
	SessionName SessionNameRule
}

// ErrNoRole is the error a [RoleTable] returns for a role ID with no entry.
var ErrNoRole = errors.New("aws: no role entry")

// RoleTable is the configured role table, read for each event (section 8,
// F3). It changes only through the gateway's administrative controls.
type RoleTable interface {
	// Role returns the entry of the role whose unique ID is roleID,
	// [ErrNoRole] when there is none, and another error when the table
	// cannot answer.
	Role(ctx context.Context, roleID string) (RoleEntry, error)
}

// CheckReport is the result of the last completed configuration check of
// AR-3.
type CheckReport struct {
	// CompletedAt is when the check completed; zero when none has.
	CompletedAt time.Time
	// Passed reports whether every condition of AR-3 held.
	Passed bool
	// Findings names the conditions found violated, for the deployment's
	// log; the adapter does not disclose them.
	Findings []string
}

// ConfigurationCheck reports the last completed check of the API's and the
// integration function's AWS configuration (AR-3). Which management calls it
// makes is the deployment's (profile probe P5).
type ConfigurationCheck interface {
	// Last returns the last completed check, or an error when the check
	// cannot complete.
	Last(ctx context.Context) (CheckReport, error)
}

// Executor reports the identity under which the integration function would
// run the operation (AR-22).
type Executor interface {
	// RunningIdentity returns the ARN of that identity: the execution role's
	// ARN when the function runs under it. An empty ARN or an error means it
	// cannot be established.
	RunningIdentity(ctx context.Context) (string, error)
}

// Route is a row of an installed mapping: the route of package installed,
// and whether the row accepts a request body. A row that accepts none refuses
// a non-empty body (RB-37).
type Route struct {
	installed.Route
	// Body says that the row accepts a request body. Until profile probe P8
	// passes, a claimed row accepts none (AR-19).
	Body bool
}

// MetricsRoutes is the route table of mapping revision pact-aws-1: route R1
// of the profile, GET /metrics/operations, the action metrics.operations.read
// on the constant resource https://metrics.example/operations, with no body.
func MetricsRoutes() []Route {
	return []Route{{Route: installed.Route{
		Method: http.MethodGet, Path: "/metrics/operations",
		Action: "metrics.operations.read", Resource: "https://metrics.example/operations",
	}}}
}

// Config names the gateway's trusted configuration and its native systems.
// Every value comes from configuration, never from an event.
type Config struct {
	// Realm is the tenant and environment of the gateway.
	Realm adapter.Realm
	// Partition is the configured partition of the account. Empty is "aws".
	Partition string
	// AccountID is the account that owns the API and the integration
	// function: twelve digits.
	AccountID string
	// Origin is the public HTTPS origin of the gateway, whose host is the
	// configured custom domain name of the API (AR-1, AR-13, AR-14).
	Origin string
	// HeaderAllowlist names the application headers an operation context
	// covers besides content-type. It never names authorization or a name
	// that begins with x-amz- or x-amzn- (AR-18).
	HeaderAllowlist []string
	// HeaderNormalizationID is published as the gateway's
	// header_normalization_id. Empty is [DefaultHeaderNormalizationID].
	HeaderNormalizationID string
	// Mappings are the installed route tables by mapping revision. Nil
	// installs [MetricsRoutes] under [MappingRevision].
	Mappings map[string][]Route
	// MaxEventBytes bounds the size of an event. Zero is
	// [DefaultMaxEventBytes].
	MaxEventBytes int

	// Roles is the role table. Required.
	Roles RoleTable
	// ConfigCheck reports the configuration check of AR-3. Required.
	ConfigCheck ConfigurationCheck
	// CheckInterval is the interval P of AR-3. Zero is
	// [DefaultCheckInterval].
	CheckInterval time.Duration
	// PropagationBound is the declared IAM propagation bound L (section 8).
	// Zero is [DefaultPropagationBound].
	PropagationBound time.Duration

	// ExecutionRoleARN is the execution role that the mapping declares for
	// every row (AR-22). Required.
	ExecutionRoleARN string
	// Executor reports the identity the function would run the operation
	// under, for [CheckExecutionIdentity]. Required.
	Executor Executor

	// Registry is the enrollment registry. Required.
	Registry enroll.Registry
	// Claims are the sources of approved native paths other than those of
	// AR-25, by path.
	Claims map[string]installed.ClaimSource
	// Checks are the further context checks the deployment installs, by
	// exact id. It cannot name [CheckExecutionIdentity].
	Checks map[string]installed.InstalledCheck
	// Guard is the guard against re-stamping that installed checks with
	// freshness limits share. Nil creates an empty one.
	Guard *freshness.Monotonic
	// Permissions is the business handler's permission check (AR-21).
	// Required.
	Permissions installed.PermissionLookup
	// Reporting signs outcome reports. Nil leaves RecordOutcome unsupported.
	Reporting *installed.Reporting
	// ExecutionVisible says that the gateway observes the execution of the
	// operations it runs.
	ExecutionVisible bool

	// Clock is the adapter's only source of the current time. Required.
	Clock clock.Clock
}

// Adapter is the AWS adapter of one HTTP API. It is safe for concurrent use
// when its native systems are.
type Adapter struct {
	cfg      Config
	host     string
	mappings map[string][]Route
	checks   map[string]installed.InstalledCheck
}

var _ adapter.Adapter = (*Adapter)(nil)

// guardCapacity bounds the guard against re-stamping that New creates when
// the configuration supplies none.
const guardCapacity = 4096

var (
	accountPattern   = regexp.MustCompile(`^[0-9]{12}$`)
	partitionPattern = regexp.MustCompile(`^aws(-[a-z]+)*$`)
)

// New returns the adapter over cfg. It validates the configuration.
func New(cfg Config) (*Adapter, error) {
	switch {
	case cfg.Clock == nil:
		return nil, errors.New("aws: no clock")
	case cfg.Realm.TenantID == "" || cfg.Realm.EnvironmentID == "":
		return nil, errors.New("aws: the gateway realm needs a tenant and an environment")
	case !accountPattern.MatchString(cfg.AccountID):
		return nil, fmt.Errorf("aws: account %q is not twelve digits", cfg.AccountID)
	case cfg.Roles == nil:
		return nil, errors.New("aws: no role table")
	case cfg.ConfigCheck == nil:
		return nil, errors.New("aws: no configuration check")
	case cfg.Executor == nil || !strings.HasPrefix(cfg.ExecutionRoleARN, "arn:"):
		return nil, errors.New("aws: no declared execution role or no executor source")
	case cfg.Registry == nil:
		return nil, errors.New("aws: no enrollment registry")
	case cfg.Permissions == nil:
		return nil, errors.New("aws: no permission check")
	case cfg.CheckInterval < 0 || cfg.PropagationBound < 0 || cfg.MaxEventBytes < 0:
		return nil, errors.New("aws: negative interval, bound or size")
	}
	if cfg.Partition == "" {
		cfg.Partition = "aws"
	}
	if !partitionPattern.MatchString(cfg.Partition) {
		return nil, fmt.Errorf("aws: partition %q is not a partition name", cfg.Partition)
	}
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = DefaultCheckInterval
	}
	if cfg.PropagationBound == 0 {
		cfg.PropagationBound = DefaultPropagationBound
	}
	if cfg.MaxEventBytes == 0 {
		cfg.MaxEventBytes = DefaultMaxEventBytes
	}
	if cfg.HeaderNormalizationID == "" {
		cfg.HeaderNormalizationID = DefaultHeaderNormalizationID
	}
	for _, name := range cfg.HeaderAllowlist {
		n := ascii.ToLower(name)
		if n == "authorization" || strings.HasPrefix(n, "x-amz-") || strings.HasPrefix(n, "x-amzn-") {
			return nil, fmt.Errorf("aws: header %q is never covered (AR-18)", name)
		}
	}
	for path, src := range cfg.Claims {
		if path == PathPrincipalID || path == PathWorkloadRole || path == PathAccountID {
			return nil, fmt.Errorf("aws: %s is answered from the IAM context", path)
		}
		if src == nil {
			return nil, fmt.Errorf("aws: no source for %s", path)
		}
	}
	if _, ok := cfg.Checks[CheckExecutionIdentity]; ok {
		return nil, fmt.Errorf("aws: %s is the adapter's own check", CheckExecutionIdentity)
	}
	if err := installed.ValidateChecks(cfg.Checks); err != nil {
		return nil, fmt.Errorf("aws: %w", err)
	}
	if err := cfg.Reporting.Validate(); err != nil {
		return nil, fmt.Errorf("aws: %w", err)
	}
	if cfg.Guard == nil {
		cfg.Guard = freshness.NewMonotonic(guardCapacity)
	}
	a := &Adapter{cfg: cfg, mappings: cfg.Mappings, checks: map[string]installed.InstalledCheck{}}
	if a.mappings == nil {
		a.mappings = map[string][]Route{MappingRevision: MetricsRoutes()}
	}
	for version, routes := range a.mappings {
		if err := a.bindingConfig(version).Validate(); err != nil {
			return nil, fmt.Errorf("aws: mapping %q: %w", version, err)
		}
		for _, rt := range routes {
			if err := rt.Validate(); err != nil {
				return nil, fmt.Errorf("aws: mapping %q: %w", version, err)
			}
		}
	}
	host, err := originHost(cfg.Origin)
	if err != nil {
		return nil, err
	}
	a.host = host
	for id, c := range cfg.Checks {
		a.checks[id] = c
	}
	a.checks[CheckExecutionIdentity] = installed.InstalledCheck{Check: executionCheck{a: a}}
	return a, nil
}

// originHost returns the host of the configured origin in lowercase, the
// custom domain name an event must name (AR-13).
func originHost(origin string) (string, error) {
	_, rest, ok := strings.Cut(origin, "://")
	if !ok {
		return "", fmt.Errorf("aws: origin %q has no scheme", origin)
	}
	host, _, _ := strings.Cut(rest, ":")
	host, _, _ = strings.Cut(host, "/")
	if host == "" {
		return "", fmt.Errorf("aws: origin %q has no host", origin)
	}
	return ascii.ToLower(host), nil
}

// Describe returns the descriptor of the profile: aws-apigateway-http-api,
// payload-format-2.0, pact-aws-1.
func (a *Adapter) Describe() adapter.Descriptor {
	return adapter.Descriptor{Protocol: Protocol, Version: Version, MappingRevision: MappingRevision}
}

// bindingConfig is the baseline HTTP mapping under one installed revision.
func (a *Adapter) bindingConfig(version string) binding.Config {
	return binding.Config{
		Origin:                a.cfg.Origin,
		HeaderAllowlist:       a.cfg.HeaderAllowlist,
		HeaderNormalizationID: a.cfg.HeaderNormalizationID,
		MappingVersion:        version,
		MaxBody:               int64(a.cfg.MaxEventBytes),
	}
}

// live fails with a dependency error when ctx is already done.
func live(ctx context.Context, fn string) error {
	if err := installed.Live(ctx); err != nil {
		return fmt.Errorf("aws: %s: %w", fn, err)
	}
	return nil
}
