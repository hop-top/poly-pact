package memory

import (
	"context"
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

// maxBody is the largest request body the adapter reads to digest it.
const maxBody = 8 << 20

// headerNormalizationID names the header normalization of the baseline HTTP
// mapping, which package binding applies.
const headerNormalizationID = "memory-header-normalization-1"

// MapOperation derives the operation context of draft 10.2 from the request,
// the authenticated principal and the installed mapping.
//
// The baseline HTTP mapping is package binding's [binding.FromRequest]: method,
// target_uri from the configured origin and the exact path and query of the
// request-target, body_digest of the exact body (put back for the next
// reader), and the allowlisted headers. A Host, Forwarded or X-Forwarded-*
// header cannot choose the target. The adapter adds what the binding leaves to
// it: action and resources from the installed route that matches the method
// and the bound path, never from a list the client supplied; principal_id,
// the authenticated principal; environment_id, from the gateway
// configuration; and operation_id.
//
// A request the baseline mapping refuses, such as one with a fragment,
// userinfo, a content encoding or an ambiguous encoding, is rejected with an
// error that wraps both [adapter.ErrInvalidMessage] (INVALID_MESSAGE, draft
// 13.4) and the [*binding.RequestError] that names the rule. A body that cannot
// be read is [adapter.ErrDependencyUnavailable].
func (a *Adapter) MapOperation(ctx context.Context, r *http.Request, p adapter.Principal, mappingVersion string) (core.OperationContext, error) {
	if err := a.live(ctx, "map operation"); err != nil {
		return core.OperationContext{}, err
	}
	if r == nil || r.URL == nil {
		return core.OperationContext{}, fmt.Errorf("memory: no request: %w", adapter.ErrInvalidMessage)
	}
	m, ok := a.mappings[mappingVersion]
	if !ok {
		return core.OperationContext{}, fmt.Errorf("memory: mapping version %q is not installed: %w", mappingVersion, adapter.ErrUnsupportedRequirement)
	}
	if p.ID == "" || p.Realm != a.realm() {
		return core.OperationContext{}, fmt.Errorf("memory: the principal does not belong to this gateway's realm: %w", adapter.ErrContextMismatch)
	}
	if err := a.matchCredential(r, p); err != nil {
		return core.OperationContext{}, err
	}

	op, err := binding.FromRequest(a.bindingConfig(mappingVersion), r, p.ID, "", nil)
	switch {
	case errors.Is(err, binding.ErrInvalidRequest):
		return core.OperationContext{}, fmt.Errorf("memory: %w: %w", err, adapter.ErrInvalidMessage)
	case errors.Is(err, binding.ErrBodyRead):
		return core.OperationContext{}, fmt.Errorf("memory: %w: %w", err, adapter.ErrDependencyUnavailable)
	case err != nil:
		// New validated the configuration of every installed mapping, so this
		// is not reached; an unusable mapping is not supported.
		return core.OperationContext{}, fmt.Errorf("memory: mapping %q: %w: %w", mappingVersion, err, adapter.ErrUnsupportedRequirement)
	}

	path := boundPath(op.TargetURI)
	action, resource, ok := matchRoute(m, op.Method, path)
	if !ok {
		return core.OperationContext{}, fmt.Errorf("memory: mapping %q has no route for %s %s: %w", mappingVersion, op.Method, path, adapter.ErrUnsupportedRequirement)
	}
	op.OperationID = operationID(p.ID, op.Method, op.TargetURI, op.BodyDigest, mappingVersion)
	op.EnvironmentID = a.st.Gateway.EnvironmentID
	op.Action = action
	op.Resources = []string{resource}
	return op, nil
}

// bindingConfig is the baseline HTTP mapping of the gateway under one
// installed mapping version.
func (a *Adapter) bindingConfig(mappingVersion string) binding.Config {
	return binding.Config{
		Origin:                a.st.Gateway.Origin,
		HeaderAllowlist:       a.st.Gateway.HeaderAllowlist,
		HeaderNormalizationID: headerNormalizationID,
		MappingVersion:        mappingVersion,
		MaxBody:               maxBody,
	}
}

// boundPath returns the path of a target URI that the binding built: what
// follows the origin, up to the query. The origin has no "/" and the path
// starts with one.
func boundPath(target string) string {
	rest := strings.TrimPrefix(target, "https://")
	path, _, _ := strings.Cut(rest[strings.IndexByte(rest, '/'):], "?")
	return path
}

// matchCredential refuses a request whose bearer token authenticates somebody
// other than p. A token the identity store does not know says nothing about
// who sent the request, so it is not a mismatch.
func (a *Adapter) matchCredential(r *http.Request, p adapter.Principal) error {
	token, _ := bearer(r)
	if token == "" {
		return nil
	}
	if id, ok := a.identityBySecret(token); ok {
		if id.ID != p.ID || id.Realm.TenantID != p.Realm.TenantID || id.Realm.EnvironmentID != p.Realm.EnvironmentID {
			return fmt.Errorf("memory: the request authenticates a different principal than the one given: %w", adapter.ErrContextMismatch)
		}
	}
	return nil
}

// matchRoute finds the route for method and path, and returns its action and
// its resource with the placeholders filled in. path is the path as sent, so a
// segment with an escape matches no placeholder.
func matchRoute(m Mapping, method, path string) (action, resource string, ok bool) {
	segs := strings.Split(path, "/")
	for _, rt := range m.Routes {
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
// {name} segment matches one non-empty segment of unreserved characters.
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

// operationID is a stable correlation identifier: the same request of the same
// principal under the same mapping has the same id.
func operationID(principal, method, target string, digest core.Digest, mapping string) string {
	h := sha256.New()
	for _, part := range []string{principal, method, target, string(digest), mapping} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return "op-" + base64.RawURLEncoding.EncodeToString(h.Sum(nil))[:22]
}
