package basic

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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
	Protocol        = "http-basic"
	Version         = "rfc7617"
	MappingRevision = "pact-basic-1"
)

// Mechanism is the Mechanism of a principal the adapter authenticates.
const Mechanism adapter.Mechanism = "basic"

// The approved native paths the account database answers (profile section 3).
const (
	PathPrincipalID    = "/principal/id"
	PathPrincipalRoles = "/principal/roles"
)

// maxBody is the largest request body the adapter reads to digest it.
const maxBody = 8 << 20

// headerNormalizationID names the header normalization of the baseline HTTP
// mapping, which package binding applies.
const headerNormalizationID = "pact-basic-header-normalization-1"

// guardCapacity bounds the guard against re-stamping that New creates when
// the configuration supplies none.
const guardCapacity = 4096

// Config names the gateway's native systems and its trusted configuration.
// Every value comes from gateway configuration, never from a request.
type Config struct {
	// Realm is the tenant and environment of the gateway.
	Realm adapter.Realm
	// Origin is the public HTTPS origin of the gateway, the only source of the
	// scheme, host and port of a target URI (draft 10.2).
	Origin string
	// HeaderAllowlist names the application headers an operation context
	// covers besides content-type. The profile binds none (DR5).
	HeaderAllowlist []string
	// Mappings are the installed route tables by mapping revision. Nil
	// installs [InvoiceRoutes] under [MappingRevision].
	Mappings map[string][]Route

	// Accounts is the account database. Required.
	Accounts AccountStore
	// Decoy is a password hash with the parameters of the account database's
	// hashes. An unknown user-id is checked against it, so that its denial
	// costs what a wrong password costs. Required.
	Decoy PasswordHash
	// RoleMap is the administrator-approved translation of native role names
	// to PACT role names at the installed mapping revision (draft 17.2). A
	// native role that is not a key has no PACT name.
	RoleMap map[string]string
	// Claims are the sources of approved native paths other than
	// [PathPrincipalID] and [PathPrincipalRoles], by path.
	Claims map[string]ClaimSource

	// Checks are the installed context checks by exact check id.
	Checks map[string]InstalledCheck
	// Guard is the guard against re-stamping that installed checks with
	// freshness limits share (freshness profile, section 7). Nil creates an
	// empty one.
	Guard *freshness.Monotonic

	// Registry is the enrollment registry. Required.
	Registry enroll.Registry
	// Permissions is the native permission lookup. Required.
	Permissions PermissionLookup

	// Reporting signs outcome reports. Nil leaves RecordOutcome unsupported.
	Reporting *Reporting
	// ExecutionVisible says that the gateway observes the execution of the
	// operations it forwards. The profile declares admission and authorization
	// visibility only, so it is false there.
	ExecutionVisible bool

	// Clock is the adapter's only source of the current time. Required.
	Clock clock.Clock
}

// Reporting is the signer of outcome reports.
type Reporting = installed.Reporting

// Adapter is the HTTP Basic adapter. It is safe for concurrent use when its
// native systems are.
type Adapter struct {
	cfg      Config
	mappings map[string][]Route
}

var _ adapter.Adapter = (*Adapter)(nil)

// New returns the adapter over cfg. It validates the configuration.
func New(cfg Config) (*Adapter, error) {
	switch {
	case cfg.Clock == nil:
		return nil, errors.New("basic: no clock")
	case cfg.Realm.TenantID == "" || cfg.Realm.EnvironmentID == "":
		return nil, errors.New("basic: the gateway realm needs a tenant and an environment")
	case cfg.Accounts == nil:
		return nil, errors.New("basic: no account database")
	case cfg.Registry == nil:
		return nil, errors.New("basic: no enrollment registry")
	case cfg.Permissions == nil:
		return nil, errors.New("basic: no permission lookup")
	}
	if err := cfg.Decoy.validate(); err != nil {
		return nil, fmt.Errorf("basic: decoy hash: %w", err)
	}
	for path := range cfg.Claims {
		if path == PathPrincipalID || path == PathPrincipalRoles {
			return nil, fmt.Errorf("basic: %s is answered by the account database", path)
		}
		if cfg.Claims[path] == nil {
			return nil, fmt.Errorf("basic: no source for %s", path)
		}
	}
	if err := installed.ValidateChecks(cfg.Checks); err != nil {
		return nil, fmt.Errorf("basic: %w", err)
	}
	if err := cfg.Reporting.Validate(); err != nil {
		return nil, fmt.Errorf("basic: %w", err)
	}
	if cfg.Guard == nil {
		cfg.Guard = freshness.NewMonotonic(guardCapacity)
	}
	a := &Adapter{cfg: cfg, mappings: cfg.Mappings}
	if a.mappings == nil {
		a.mappings = map[string][]Route{MappingRevision: InvoiceRoutes()}
	}
	for version, routes := range a.mappings {
		if err := a.bindingConfig(version).Validate(); err != nil {
			return nil, fmt.Errorf("basic: mapping %q: %w", version, err)
		}
		for _, rt := range routes {
			if err := rt.Validate(); err != nil {
				return nil, fmt.Errorf("basic: mapping %q: %w", version, err)
			}
		}
	}
	return a, nil
}

// Describe returns the descriptor of the profile: http-basic, rfc7617,
// pact-basic-1.
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
		return fmt.Errorf("basic: %s: %w: %w", fn, adapter.ErrDependencyUnavailable, err)
	}
	return nil
}

// dependency returns err as the error of fn, wrapping
// [adapter.ErrDependencyUnavailable] unless err already carries a code.
func dependency(fn string, err error) error {
	if _, ok := adapter.CodeOf(err); ok {
		return fmt.Errorf("basic: %s: %w", fn, err)
	}
	return fmt.Errorf("basic: %s: %w: %w", fn, adapter.ErrDependencyUnavailable, err)
}

// checkSourceTimes refuses source times that are later than now plus the
// skew: such a time did not happen yet, so the source cannot be relied on at
// this moment, which defers the decision (draft A.2; freshness profile,
// section 3.2).
func (a *Adapter) checkSourceTimes(fn string, times ...time.Time) error {
	limit := a.cfg.Clock.Now().Add(clock.BaselineSkew)
	for _, t := range times {
		if !t.IsZero() && t.After(limit) {
			return fmt.Errorf("basic: %s: the source reports a time later than now plus the skew: %w", fn, adapter.ErrDependencyUnavailable)
		}
	}
	return nil
}

// markKey is the context key of the enforcement marker. The type is
// unexported, so nothing outside this package, and no request header, can set
// it.
type markKey struct{}

// Mark returns r marked as accepted by the gateway's filter chain for the
// enforced path. The gateway calls it, or installs [Enforce], where the
// request enters that chain; a request that did not pass through it, such as
// one sent to the backend directly, carries no marker.
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
