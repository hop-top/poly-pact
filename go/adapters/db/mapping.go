package db

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/binding"
)

// emptyDigest is the body digest of an empty body (draft 7.4).
var emptyDigest = func() core.Digest {
	sum := sha256.Sum256(nil)
	return core.Digest(base64.RawURLEncoding.EncodeToString(sum[:]))
}()

// MapOperation derives the operation context of draft 10.2 with the baseline
// HTTP mapping of package binding and the route table of the installed
// revision, and selects the query registry entry of its action (profile
// QB-1). A request the baseline mapping refuses, a placeholder value outside
// its route's grammar, and a non-empty body are [adapter.ErrInvalidMessage]
// (RB-37, RB-38, QB-4); an uninstalled revision, a request no route matches,
// and an action without a query registry entry under the revision are
// [adapter.ErrUnsupportedRequirement] (RB-33, RB-46, QB-1); a principal of
// another realm is [adapter.ErrContextMismatch]. A query parameter is
// covered by target_uri and read for nothing (RB-36). No connection is
// opened.
func (a *Adapter) MapOperation(ctx context.Context, r *http.Request, p adapter.Principal, mappingVersion string) (core.OperationContext, error) {
	if err := live(ctx, "map operation"); err != nil {
		return core.OperationContext{}, err
	}
	if r == nil || r.URL == nil {
		return core.OperationContext{}, fmt.Errorf("db: no request: %w", adapter.ErrInvalidMessage)
	}
	routes, ok := a.mappings[mappingVersion]
	if !ok {
		return core.OperationContext{}, fmt.Errorf("db: mapping revision %q is not installed: %w", mappingVersion, adapter.ErrUnsupportedRequirement)
	}
	if p.ID == "" || p.Realm != a.cfg.Realm {
		return core.OperationContext{}, fmt.Errorf("db: the principal does not belong to the broker's realm: %w", adapter.ErrContextMismatch)
	}
	cfg := a.bindingConfig(mappingVersion)
	bound, err := binding.FromRequest(cfg, r, p.ID, "", nil)
	switch {
	case errors.Is(err, binding.ErrInvalidRequest):
		return core.OperationContext{}, fmt.Errorf("db: %w: %w", err, adapter.ErrInvalidMessage)
	case errors.Is(err, binding.ErrBodyRead):
		return core.OperationContext{}, fmt.Errorf("db: %w: %w", err, adapter.ErrDependencyUnavailable)
	case err != nil:
		return core.OperationContext{}, fmt.Errorf("db: mapping %q: %w: %w", mappingVersion, err, adapter.ErrUnsupportedRequirement)
	}
	rt, _, err := match(routes, bound.Method, boundPath(bound.TargetURI))
	if err != nil {
		return core.OperationContext{}, fmt.Errorf("db: mapping %q: %w", mappingVersion, err)
	}
	if !rt.AcceptsBody && bound.BodyDigest != emptyDigest {
		return core.OperationContext{}, fmt.Errorf("db: route %s %s accepts no body (RB-37): %w", rt.Method, rt.Path, adapter.ErrInvalidMessage)
	}
	if _, ok := a.queries[queryKey{rt.Action, mappingVersion}]; !ok {
		return core.OperationContext{}, fmt.Errorf("db: the action %q has no query registry entry under %q (QB-1): %w", rt.Action, mappingVersion, adapter.ErrUnsupportedRequirement)
	}
	op, err := installed.MapRequest(cfg, []installed.Route{{Method: rt.Method, Path: rt.Path, Action: rt.Action, Resource: rt.Resource}}, a.cfg.Realm.EnvironmentID, r, p)
	if err != nil {
		return core.OperationContext{}, fmt.Errorf("db: %w", err)
	}
	return op, nil
}

// match finds the route for method and path. A placeholder segment matches
// any segment, and its value must then match the grammar of the route
// (RB-34): a value outside it is [adapter.ErrInvalidMessage] (RB-38). No
// route of the shape is [adapter.ErrUnsupportedRequirement] (RB-33).
func match(routes []Route, method, path string) (Route, map[string]string, error) {
	segs := strings.Split(path, "/")
	for _, rt := range routes {
		if rt.Method != method {
			continue
		}
		tmpl := strings.Split(rt.Path, "/")
		if len(tmpl) != len(segs) {
			continue
		}
		vars := map[string]string{}
		matched := true
		for i, t := range tmpl {
			if name, ok := placeholder(t); ok {
				if segs[i] == "" {
					matched = false
					break
				}
				vars[name] = segs[i]
				continue
			}
			if t != segs[i] {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		for name, v := range vars {
			if v == "." || v == ".." || !rt.Params[name].MatchString(v) {
				return Route{}, nil, fmt.Errorf("the value of %s is outside the grammar of route %s %s (RB-34, QB-4): %w", name, rt.Method, rt.Path, adapter.ErrInvalidMessage)
			}
		}
		return rt, vars, nil
	}
	return Route{}, nil, fmt.Errorf("no route for %s %s: %w", method, path, adapter.ErrUnsupportedRequirement)
}

// boundPath returns the path of a target URI the binding built: what follows
// the origin, up to the query.
func boundPath(target string) string {
	rest := strings.TrimPrefix(target, "https://")
	i := strings.IndexByte(rest, '/')
	if i < 0 {
		return "/"
	}
	path, _, _ := strings.Cut(rest[i:], "?")
	return path
}

// bind re-derives the registered statement and its arguments of an
// operation under the installed revision: the route its own method and
// target select, which must give the operation's action and resources, and
// the query registry entry of that action (profile QB-1, QB-4). The values
// are the path segments as bound, never anything else of the request.
func (a *Adapter) bind(op core.OperationContext) (Query, []any, error) {
	routes := a.mappings[a.cfg.Revision]
	rt, vars, err := match(routes, op.Method, boundPath(op.TargetURI))
	if err != nil {
		return Query{}, nil, err
	}
	resource := rt.Resource
	for k, v := range vars {
		resource = strings.ReplaceAll(resource, "{"+k+"}", v)
	}
	if op.Action != rt.Action || len(op.Resources) != 1 || op.Resources[0] != resource {
		return Query{}, nil, fmt.Errorf("the operation context does not match its own method and target under %q: %w", a.cfg.Revision, adapter.ErrContextMismatch)
	}
	q, ok := a.queries[queryKey{rt.Action, a.cfg.Revision}]
	if !ok {
		return Query{}, nil, fmt.Errorf("the action %q has no query registry entry under %q: %w", rt.Action, a.cfg.Revision, adapter.ErrUnsupportedRequirement)
	}
	args := make([]any, len(q.Args))
	for i, name := range q.Args {
		v, ok := vars[name]
		if !ok {
			return Query{}, nil, fmt.Errorf("the route has no value for %s: %w", name, adapter.ErrUnsupportedRequirement)
		}
		args[i] = v
	}
	return q, args, nil
}
