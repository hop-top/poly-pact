package saml

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
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
	Protocol        = "saml"
	Version         = "2.0"
	MappingRevision = "pact-saml-1"
)

// The approved native paths the session store answers (profile SB-23).
const (
	PathPrincipalID = "/attributes/environment/principal_id"
	PathIDPRealm    = "/attributes/environment/idp_realm"
)

// CheckNativeDelegation is the id of the installed check that evaluates the
// grant of an operation (profile SB-11).
const CheckNativeDelegation = "native-delegation-v1"

// taskPlaceholder is the route segment that carries the request's task
// reference (profile section 2).
const taskPlaceholder = "{task_id}"

// maxBody is the largest request body the adapter reads to digest it.
const maxBody = 8 << 20

// headerNormalizationID names the header normalization of the baseline HTTP
// mapping, which package binding applies.
const headerNormalizationID = "pact-saml-header-normalization-1"

// guardCapacity bounds the guard against re-stamping that New creates when
// the configuration supplies none.
const guardCapacity = 4096

// Config names the native systems and the trusted configuration of the
// broker. Every value comes from configuration, never from a request.
type Config struct {
	// Realm is the tenant and environment of the broker.
	Realm adapter.Realm
	// Origin is the public HTTPS origin of the broker, the only source of the
	// scheme, host and port of a target URI (draft 10.2).
	Origin string
	// HeaderAllowlist names the application headers an operation context
	// covers besides content-type.
	HeaderAllowlist []string
	// Mappings are the installed route tables by mapping revision. Nil
	// installs [BrokerRoutes] under [MappingRevision]. A route whose path has
	// the segment {task_id} carries the request's task reference.
	Mappings map[string][]Route

	// Agents authenticates each agent's own broker credential. Required.
	Agents AgentAuthenticator
	// Sessions is the SP's session store. Required.
	Sessions SessionStore
	// Grants is the broker's grant store. Required.
	Grants TaskBroker
	// Registry is the enrollment registry. Required.
	Registry enroll.Registry

	// Directory is the directory adapter that answers membership facts at
	// DirectoryPaths (profile SB-22). Nil with no paths reads none.
	Directory adapter.ClaimReader
	// DirectoryPaths are the approved native paths of Directory.
	DirectoryPaths []string

	// Checks are further installed context checks by exact check id. They
	// may not use [CheckNativeDelegation].
	Checks map[string]InstalledCheck
	// DelegationCheck, when set, is a deployment's own implementation of
	// [CheckNativeDelegation] over its native delegation record, run with the
	// rules of the other installed checks. Nil, the profile's choice, uses the
	// adapter's evaluation of the TaskGrant (SB-11).
	DelegationCheck *InstalledCheck
	// Guard is the guard against re-stamping that installed checks with
	// freshness limits share (freshness profile, section 7). Nil creates an
	// empty one.
	Guard *freshness.Monotonic

	// Permissions is the SP's access policy for the requested records.
	// Required.
	Permissions PermissionLookup

	// Reporting signs outcome reports. Nil leaves RecordOutcome unsupported.
	Reporting *Reporting
	// ExecutionVisible says that the adapter observes the execution of the
	// reads. The broker performs them and reports them, so it is false in the
	// profile.
	ExecutionVisible bool

	// Clock is the adapter's only source of the current time. Required.
	Clock clock.Clock
}

// The deployment-supplied parts that do not depend on SAML.
type (
	// Route maps a method and a path template to an action and a resource.
	Route = installed.Route
	// InstalledCheck is a check as the broker installed it.
	InstalledCheck = installed.InstalledCheck
	// PermissionLookup is the SP's access policy.
	PermissionLookup = installed.PermissionLookup
	// Reporting is the signer of outcome reports.
	Reporting = installed.Reporting
)

// BrokerRoutes is the route table of mapping revision pact-saml-1: routes R1
// and R2 of the profile, both reads (profile section 2).
func BrokerRoutes() []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/broker/v1/tasks/{task_id}/records/{record_id}", Action: "record.read", Resource: "record:{record_id}"},
		{Method: http.MethodGet, Path: "/broker/v1/tasks/{task_id}/records", Action: "record.list", Resource: "record-collection"},
	}
}

// Adapter is the SAML SP-session broker adapter. It is safe for concurrent use
// when its native systems are.
type Adapter struct {
	cfg        Config
	mappings   map[string][]Route
	taskRoutes []Route
}

var _ adapter.Adapter = (*Adapter)(nil)

// New returns the adapter over cfg. It validates the configuration.
func New(cfg Config) (*Adapter, error) {
	switch {
	case cfg.Clock == nil:
		return nil, errors.New("saml: no clock")
	case cfg.Realm.TenantID == "" || cfg.Realm.EnvironmentID == "":
		return nil, errors.New("saml: the broker realm needs a tenant and an environment")
	case cfg.Agents == nil:
		return nil, errors.New("saml: no agent authentication")
	case cfg.Sessions == nil:
		return nil, errors.New("saml: no session store")
	case cfg.Grants == nil:
		return nil, errors.New("saml: no grant store")
	case cfg.Registry == nil:
		return nil, errors.New("saml: no enrollment registry")
	case cfg.Permissions == nil:
		return nil, errors.New("saml: no access policy")
	case cfg.Directory == nil && len(cfg.DirectoryPaths) > 0:
		return nil, errors.New("saml: directory paths without a directory adapter")
	}
	for _, p := range cfg.DirectoryPaths {
		if p == PathPrincipalID || p == PathIDPRealm {
			return nil, fmt.Errorf("saml: %s is answered by the session store", p)
		}
	}
	if _, ok := cfg.Checks[CheckNativeDelegation]; ok {
		return nil, fmt.Errorf("saml: %s is the adapter's own check", CheckNativeDelegation)
	}
	if dc := cfg.DelegationCheck; dc != nil {
		if err := installed.ValidateChecks(map[string]InstalledCheck{CheckNativeDelegation: *dc}); err != nil {
			return nil, fmt.Errorf("saml: %w", err)
		}
	}
	if err := installed.ValidateChecks(cfg.Checks); err != nil {
		return nil, fmt.Errorf("saml: %w", err)
	}
	if err := cfg.Reporting.Validate(); err != nil {
		return nil, fmt.Errorf("saml: %w", err)
	}
	if cfg.Guard == nil {
		cfg.Guard = freshness.NewMonotonic(guardCapacity)
	}
	a := &Adapter{cfg: cfg, mappings: cfg.Mappings}
	if a.mappings == nil {
		a.mappings = map[string][]Route{MappingRevision: BrokerRoutes()}
	}
	for version, routes := range a.mappings {
		if err := a.bindingConfig(version).Validate(); err != nil {
			return nil, fmt.Errorf("saml: mapping %q: %w", version, err)
		}
		for _, rt := range routes {
			if err := rt.Validate(); err != nil {
				return nil, fmt.Errorf("saml: mapping %q: %w", version, err)
			}
			if slices.Contains(strings.Split(rt.Path, "/"), taskPlaceholder) {
				a.taskRoutes = append(a.taskRoutes, rt)
			}
		}
	}
	return a, nil
}

// Describe returns the descriptor of the profile: saml, 2.0, pact-saml-1.
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

// now is the current time of the adapter's clock.
func (a *Adapter) now() time.Time { return a.cfg.Clock.Now() }

// taskOf returns the task reference of a method and an escaped path: the
// {task_id} segment of the installed route that matches them. A segment that
// is not a run of unreserved characters matches no placeholder, so an
// escaped or empty task reference names no task.
func (a *Adapter) taskOf(method, path string) (string, bool) {
	segs := strings.Split(path, "/")
	for _, rt := range a.taskRoutes {
		if rt.Method != method {
			continue
		}
		if task, ok := matchTask(strings.Split(rt.Path, "/"), segs); ok {
			return task, true
		}
	}
	return "", false
}

// matchTask matches path segments against a route template and returns the
// segment at {task_id}.
func matchTask(tmpl, segs []string) (string, bool) {
	if len(tmpl) != len(segs) {
		return "", false
	}
	task := ""
	for i, t := range tmpl {
		if strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}") {
			if !unreserved(segs[i]) {
				return "", false
			}
			if t == taskPlaceholder {
				task = segs[i]
			}
			continue
		}
		if t != segs[i] {
			return "", false
		}
	}
	return task, task != ""
}

// unreserved reports whether s is a non-empty run of the unreserved
// characters of RFC 3986, section 2.3.
func unreserved(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}

// live fails with a dependency error when ctx is already done.
func live(ctx context.Context, fn string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("saml: %s: %w: %w", fn, adapter.ErrDependencyUnavailable, err)
	}
	return nil
}

// dependency returns err as the error of fn, wrapping
// [adapter.ErrDependencyUnavailable] unless err already carries a code.
func dependency(fn string, err error) error {
	if _, ok := adapter.CodeOf(err); ok {
		return fmt.Errorf("saml: %s: %w", fn, err)
	}
	return fmt.Errorf("saml: %s: %w: %w", fn, adapter.ErrDependencyUnavailable, err)
}

// markKey is the context key of the enforcement marker. The type is
// unexported, so nothing outside this package, and no request header, can set
// it.
type markKey struct{}

// Mark returns r marked as accepted by the broker's request stage for the
// enforced path. The broker calls it, or installs [Enforce], where the agent
// request enters that stage; a request that did not pass through it carries
// no marker.
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
