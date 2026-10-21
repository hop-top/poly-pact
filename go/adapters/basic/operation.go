package basic

import (
	"context"
	"fmt"
	"net/http"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core"
)

// Route maps a method and a path template to an action and a resource
// template. A {name} segment of Path matches one path segment of unreserved
// characters, and the same placeholder in Resource is replaced by it.
type Route = installed.Route

// InvoiceRoutes is the route table of mapping revision pact-basic-1: route R1
// of the profile, GET /invoices/{id}, the action invoice.read on the resource
// invoice:{id}, the path parameter exactly as received (profile section 2).
func InvoiceRoutes() []Route {
	return []Route{{Method: http.MethodGet, Path: "/invoices/{id}", Action: "invoice.read", Resource: "invoice:{id}"}}
}

// MapOperation derives the operation context of draft 10.2 from the request,
// the authenticated principal and the installed mapping revision.
//
// The baseline HTTP mapping is package binding's [binding.FromRequest]: the
// method, target_uri from the configured origin and the exact path and query,
// body_digest of the exact body, put back for the next reader, and the
// allowlisted headers; Authorization and PACT-Presentation are never covered.
// The action and the resource come from the route that matches the method and
// the bound path, never from the client. A request the baseline mapping
// refuses, such as one with a fragment, userinfo, a content encoding or an
// ambiguous encoding, is an error that wraps [adapter.ErrInvalidMessage]. An
// uninstalled revision, and a request no route matches, are
// [adapter.ErrUnsupportedRequirement]; a principal of another realm is
// [adapter.ErrContextMismatch].
func (a *Adapter) MapOperation(ctx context.Context, r *http.Request, p adapter.Principal, mappingVersion string) (core.OperationContext, error) {
	if err := live(ctx, "map operation"); err != nil {
		return core.OperationContext{}, err
	}
	if r == nil || r.URL == nil {
		return core.OperationContext{}, fmt.Errorf("basic: no request: %w", adapter.ErrInvalidMessage)
	}
	routes, ok := a.mappings[mappingVersion]
	if !ok {
		return core.OperationContext{}, fmt.Errorf("basic: mapping revision %q is not installed: %w", mappingVersion, adapter.ErrUnsupportedRequirement)
	}
	if p.ID == "" || p.Realm != a.cfg.Realm {
		return core.OperationContext{}, fmt.Errorf("basic: the principal does not belong to the gateway's realm: %w", adapter.ErrContextMismatch)
	}
	op, err := installed.MapRequest(a.bindingConfig(mappingVersion), routes, a.cfg.Realm.EnvironmentID, r, p)
	if err != nil {
		return core.OperationContext{}, fmt.Errorf("basic: %w", err)
	}
	return op, nil
}
