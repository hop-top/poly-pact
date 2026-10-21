package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/validator"
)

// Class is how the gateway treats the requests of one route.
type Class string

const (
	// ClassOff: PACT does not apply; the request goes to the wrapped handler
	// untouched.
	ClassOff Class = "off"
	// ClassObserve: a presented request is evaluated and its receipt
	// recorded in observation mode, and every request goes to the wrapped
	// handler unchanged, whatever the evaluation decides (draft 2.3, 4.4).
	ClassObserve Class = "observe"
	// ClassEnforce: only an admitted request that native authorization
	// allows reaches the wrapped handler (draft 2.3).
	ClassEnforce Class = "enforce"
)

func (c Class) valid() bool { return c == ClassOff || c == ClassObserve || c == ClassEnforce }

// The HTTP names of the baseline binding (draft 13.2).
const (
	// HeaderPresentation carries the compact presentation of a protected
	// request.
	HeaderPresentation = "PACT-Presentation"
	// HeaderAdmission carries the compact receipt of an evaluated request in
	// the response, when it fits Config.AdmissionHeaderBytes.
	HeaderAdmission = "PACT-Admission"
	// RequirementsPath is the requirements endpoint the gateway serves.
	RequirementsPath = "/pact/v0.1/requirements"
)

// DefaultAdmissionHeaderBytes is the largest PACT-Admission value the gateway
// sends when Config.AdmissionHeaderBytes is zero: 8 KiB (draft 13.2).
const DefaultAdmissionHeaderBytes = 8192

// Config is the trusted configuration of the gateway (draft 4.2).
type Config struct {
	// Adapter is the native adapter (draft 17.1): authenticate_native,
	// resolve_agent_binding, map_operation and authorize_native run through
	// it. The validator's Native is normally the same adapter.
	Adapter adapter.Adapter
	// Validator evaluates presentations and records their receipts durably
	// before it returns them (draft 11.3, 12.2).
	Validator *validator.Validator
	// Publisher issues the contracts of the requirements endpoint (draft
	// 9.1). Its Replay store is the one the validator consumes nonces from.
	Publisher *contract.Publisher
	// Requirements gives the effective requirements of a proposed operation.
	Requirements RequirementSource
	// Records keeps the mapping version and the proposed operation_id of
	// each issued contract (draft 10.2; request binding RB-42, RB-43).
	Records ContractRecords
	// MappingVersion is the installed operation mapping version (draft
	// 10.2; request binding RB-41).
	MappingVersion string
	// Routes maps net/http ServeMux patterns, such as "GET /invoices/{id}",
	// to the class of the requests they match.
	Routes map[string]Class
	// Default is the class of a request no pattern matches; empty is
	// ClassEnforce.
	Default Class
	// AdmissionHeaderBytes is the largest PACT-Admission value the gateway
	// sends; zero is DefaultAdmissionHeaderBytes and a negative value sends
	// none. A larger receipt is left out, never truncated: the caller reads
	// it through the receipts query (draft 13.2).
	AdmissionHeaderBytes int
	// NativeDenial answers a request that PACT admitted and native
	// authorization denied, with the native system's own denial (draft 2.3,
	// 13.4); nil answers 403 Forbidden with no detail.
	NativeDenial http.Handler
}

// Admission is what the wrapped handler of an enforce route receives in its
// request context: the principal native authentication established, the
// operation the gateway bound, the recorded receipt and the native
// authorization decision.
type Admission struct {
	Principal adapter.Principal
	Operation core.OperationContext
	Receipt   validator.Result
	Native    adapter.Decision
}

// admissionKey is the context key of the Admission; the type is unexported,
// so no value from outside this package can carry it.
type admissionKey struct{}

// FromContext returns the Admission of an admitted request.
func FromContext(ctx context.Context) (Admission, bool) {
	a, ok := ctx.Value(admissionKey{}).(Admission)
	return a, ok
}

// gateway is a configured middleware.
type gateway struct {
	cfg    Config
	routes *http.ServeMux
	class  map[string]Class
	clock  clock.Clock
}

// New returns the middleware of cfg: it serves the requirements endpoint and
// applies the class of each route to the requests for the wrapped handler.
// It returns an error, and no middleware, for a configuration it cannot
// enforce with.
func New(cfg Config) (func(http.Handler) http.Handler, error) {
	g, err := newGateway(cfg)
	if err != nil {
		return nil, err
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { g.serve(w, r, next) })
	}, nil
}

func newGateway(cfg Config) (*gateway, error) {
	switch {
	case cfg.Adapter == nil, cfg.Validator == nil, cfg.Publisher == nil, cfg.Requirements == nil, cfg.Records == nil:
		return nil, errors.New("gateway: Adapter, Validator, Publisher, Requirements and Records are required")
	case cfg.MappingVersion == "":
		return nil, errors.New("gateway: MappingVersion is required")
	case cfg.Validator.Clock == nil:
		return nil, errors.New("gateway: the validator has no Clock")
	case cfg.Publisher.Audience != cfg.Validator.Config.Audience || cfg.Publisher.Realm != cfg.Validator.Config.Realm:
		return nil, errors.New("gateway: the publisher and the validator serve different gateways")
	}
	if cfg.Default == "" {
		cfg.Default = ClassEnforce
	}
	if !cfg.Default.valid() {
		return nil, fmt.Errorf("gateway: default class %q", cfg.Default)
	}
	g := &gateway{cfg: cfg, routes: http.NewServeMux(), class: map[string]Class{}, clock: cfg.Validator.Clock}
	for pattern, c := range cfg.Routes {
		if !c.valid() {
			return nil, fmt.Errorf("gateway: route %q has class %q", pattern, c)
		}
		if err := register(g.routes, pattern); err != nil {
			return nil, err
		}
		g.class[pattern] = c
	}
	return g, nil
}

// register adds a pattern to the route table; ServeMux panics on a pattern
// it cannot use, which is a configuration error here.
func register(mux *http.ServeMux, pattern string) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("gateway: route %q: %v", pattern, p)
		}
	}()
	mux.Handle(pattern, http.NotFoundHandler())
	return nil
}

// classify returns the class of r: that of the pattern ServeMux selects for
// it, or the default. For a path ServeMux would redirect, it is the class of
// the pattern the redirect leads to.
func (g *gateway) classify(r *http.Request) Class {
	_, pattern := g.routes.Handler(r)
	if c, ok := g.class[pattern]; ok {
		return c
	}
	return g.cfg.Default
}

func (g *gateway) serve(w http.ResponseWriter, r *http.Request, next http.Handler) {
	if r.URL != nil && r.URL.Path == RequirementsPath {
		g.requirements(w, r)
		return
	}
	switch g.classify(r) {
	case ClassOff:
		next.ServeHTTP(w, r)
	case ClassObserve:
		g.observe(r)
		next.ServeHTTP(w, r)
	default:
		g.enforce(w, r, next)
	}
}
