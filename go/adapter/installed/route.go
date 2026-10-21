package installed

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/binding"
)

// Route maps a method and a path template to an action and a resource
// template. A {name} segment of Path matches one path segment of unreserved
// characters, and the same placeholder in Resource is replaced by it.
type Route struct {
	Method   string
	Path     string
	Action   string
	Resource string
}

// Validate refuses a route without a method, an absolute path, an action or a
// resource.
func (rt Route) Validate() error {
	if rt.Method == "" || !strings.HasPrefix(rt.Path, "/") || rt.Action == "" || rt.Resource == "" {
		return fmt.Errorf("route %s %s is incomplete", rt.Method, rt.Path)
	}
	return nil
}

// MapRequest derives the operation context of draft 10.2 from the request
// and the authenticated principal, with the baseline HTTP mapping cfg and the
// route table of the installed mapping revision, in the environment envID.
//
// The baseline HTTP mapping is package binding's [binding.FromRequest]: the
// method, target_uri from the configured origin and the exact path and query,
// body_digest of the exact body, put back for the next reader, and the
// allowlisted headers. The action and the resource come from the route that
// matches the method and the bound path, never from the client. A request the
// baseline mapping refuses is an error that wraps [adapter.ErrInvalidMessage];
// a body that cannot be read wraps [adapter.ErrDependencyUnavailable]; any
// other refusal of the mapping, and a request no route matches, wrap
// [adapter.ErrUnsupportedRequirement].
func MapRequest(cfg binding.Config, routes []Route, envID string, r *http.Request, p adapter.Principal) (core.OperationContext, error) {
	if r == nil || r.URL == nil {
		return core.OperationContext{}, fmt.Errorf("no request: %w", adapter.ErrInvalidMessage)
	}
	op, err := binding.FromRequest(cfg, r, p.ID, "", nil)
	switch {
	case errors.Is(err, binding.ErrInvalidRequest):
		return core.OperationContext{}, fmt.Errorf("%w: %w", err, adapter.ErrInvalidMessage)
	case errors.Is(err, binding.ErrBodyRead):
		return core.OperationContext{}, fmt.Errorf("%w: %w", err, adapter.ErrDependencyUnavailable)
	case err != nil:
		return core.OperationContext{}, fmt.Errorf("mapping %q: %w: %w", cfg.MappingVersion, err, adapter.ErrUnsupportedRequirement)
	}
	path := boundPath(op.TargetURI)
	action, resource, ok := matchRoute(routes, op.Method, path)
	if !ok {
		return core.OperationContext{}, fmt.Errorf("mapping %q has no route for %s %s: %w", cfg.MappingVersion, op.Method, path, adapter.ErrUnsupportedRequirement)
	}
	op.OperationID = operationID(p.ID, op.Method, op.TargetURI, op.BodyDigest, cfg.MappingVersion)
	op.EnvironmentID = envID
	op.Action = action
	op.Resources = []string{resource}
	return op, nil
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

// matchRoute finds the route for method and path and returns its action and
// its resource with the placeholders filled in.
func matchRoute(routes []Route, method, path string) (action, resource string, ok bool) {
	segs := strings.Split(path, "/")
	for _, rt := range routes {
		if rt.Method != method {
			continue
		}
		vars, matched := matchPath(strings.Split(rt.Path, "/"), segs)
		if !matched {
			continue
		}
		res := rt.Resource
		for k, v := range vars {
			res = strings.ReplaceAll(res, "{"+k+"}", v)
		}
		return rt.Action, res, true
	}
	return "", "", false
}

// matchPath matches the segments of a request path against a template. A
// {name} segment matches one non-empty segment of unreserved characters, so a
// segment with an escape matches no placeholder.
func matchPath(tmpl, segs []string) (map[string]string, bool) {
	if len(tmpl) != len(segs) {
		return nil, false
	}
	vars := map[string]string{}
	for i, t := range tmpl {
		if strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}") {
			if !unreserved(segs[i]) {
				return nil, false
			}
			vars[t[1:len(t)-1]] = segs[i]
			continue
		}
		if t != segs[i] {
			return nil, false
		}
	}
	return vars, true
}

// unreserved reports whether s is a non-empty run of the unreserved
// characters of RFC 3986, section 2.3.
func unreserved(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}

// operationID is a stable correlation identifier: the same request of the
// same principal under the same revision has the same id.
func operationID(principal, method, target string, digest core.Digest, revision string) string {
	h := sha256.New()
	for _, part := range []string{principal, method, target, string(digest), revision} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return "op-" + base64.RawURLEncoding.EncodeToString(h.Sum(nil))[:22]
}
