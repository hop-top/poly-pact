package aws

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core"
	"hop.top/pact-go/internal/ascii"
)

// signingParameters are the query-string parameters of Signature Version 4
// (IAM User Guide, "Authentication methods"), compared without regard to
// ASCII case (AR-17).
var signingParameters = []string{
	"x-amz-algorithm", "x-amz-credential", "x-amz-date", "x-amz-expires",
	"x-amz-signedheaders", "x-amz-signature", "x-amz-security-token",
}

// MapOperation derives the operation context of draft 10.2 from the event r
// carries, the authenticated principal and the installed mapping revision.
//
// It refuses with [adapter.ErrInvalidMessage], before any PACT evaluation: a
// request without an event; an event that does not decode, whose version is
// not 2.0, whose stage is not $default, whose domainName is not the host of
// the configured origin, or that has no rawQueryString (AR-13); a header name
// that is not lowercase (AR-18); a query-string signing parameter (AR-17); a
// routeKey, in the event or in its requestContext, other than the route key
// of the row that the method and rawPath select, and the $default route
// (AR-2, AR-13); pathParameters that name another value than rawPath, or a
// name the row does not have (AR-16); a body that is not well-formed base64
// when isBase64Encoded is true, and a non-empty body on a row that accepts
// none (AR-19, RB-37). The rest is the baseline HTTP mapping of package
// binding through [installed.MapRequest], over the request [FromEvent]
// builds: target_uri from the configured origin, rawPath and rawQueryString
// octet for octet with the refusals of draft 10.2, content-encoding refused,
// the body digest, and the allowlisted headers as the event carries them.
// queryStringParameters, requestContext.http.path and the header host never
// enter it (AR-14). An uninstalled revision is
// [adapter.ErrUnsupportedRequirement]; a principal of another realm is
// [adapter.ErrContextMismatch].
func (a *Adapter) MapOperation(ctx context.Context, r *http.Request, p adapter.Principal, mappingVersion string) (core.OperationContext, error) {
	if err := live(ctx, "map operation"); err != nil {
		return core.OperationContext{}, err
	}
	routes, ok := a.mappings[mappingVersion]
	if !ok {
		return core.OperationContext{}, fmt.Errorf("aws: mapping revision %q is not installed: %w", mappingVersion, adapter.ErrUnsupportedRequirement)
	}
	if p.ID == "" || p.Realm != a.cfg.Realm {
		return core.OperationContext{}, fmt.Errorf("aws: the principal does not belong to the gateway's realm: %w", adapter.ErrContextMismatch)
	}
	raw, ok := rawEvent(r)
	if !ok {
		return core.OperationContext{}, fmt.Errorf("aws: the request carries no API Gateway event: %w", adapter.ErrInvalidMessage)
	}
	ev, err := DecodeEvent(raw, a.cfg.MaxEventBytes)
	if err != nil {
		return core.OperationContext{}, err
	}
	if err := a.checkShape(ev); err != nil {
		return core.OperationContext{}, err
	}
	row, err := a.selectRow(ev, routes)
	if err != nil {
		return core.OperationContext{}, err
	}
	req, err := FromEvent(ev, a.cfg.Origin)
	if err != nil {
		return core.OperationContext{}, err
	}
	if !row.Body && req.ContentLength > 0 {
		return core.OperationContext{}, fmt.Errorf("aws: the row %s %s accepts no body: %w", row.Method, row.Path, adapter.ErrInvalidMessage)
	}
	installedRoutes := make([]installed.Route, len(routes))
	for i, rt := range routes {
		installedRoutes[i] = rt.Route
	}
	op, err := installed.MapRequest(a.bindingConfig(mappingVersion), installedRoutes, a.cfg.Realm.EnvironmentID, req.WithContext(ctx), p)
	if err != nil {
		return core.OperationContext{}, fmt.Errorf("aws: %w", err)
	}
	return op, nil
}

// checkShape applies the event checks of AR-13, AR-17 and AR-18.
func (a *Adapter) checkShape(ev Event) error {
	refuse := func(what string) error {
		return fmt.Errorf("aws: %s: %w", what, adapter.ErrInvalidMessage)
	}
	switch {
	case ev.Version != "2.0":
		return refuse("the event is not payload format 2.0")
	case ev.RawQueryString == nil:
		return refuse("the event has no rawQueryString")
	case ev.RequestContext.Stage != "$default":
		return refuse("the event is not of the $default stage")
	case ev.RequestContext.DomainName != a.host:
		return refuse("the event names another domain than the configured one")
	}
	for name := range ev.Headers {
		if name == "" || name != strings.ToLower(name) {
			return refuse("a header name is not lowercase")
		}
	}
	for _, pair := range strings.Split(*ev.RawQueryString, "&") {
		name, _, _ := strings.Cut(pair, "=")
		for _, s := range signingParameters {
			if ascii.EqualFold(name, s) {
				return refuse("the query carries a Signature Version 4 parameter")
			}
		}
	}
	return nil
}

// selectRow returns the row that the method and rawPath select, as API
// Gateway selects a route (a full match of method and path), and checks the
// route keys and the path parameters of the event against it (AR-2, AR-13,
// AR-16).
func (a *Adapter) selectRow(ev Event, routes []Route) (Route, error) {
	refuse := func(what string) error {
		return fmt.Errorf("aws: %s: %w", what, adapter.ErrInvalidMessage)
	}
	method := ev.RequestContext.HTTP.Method
	segs := strings.Split(ev.RawPath, "/")
	for _, rt := range routes {
		if rt.Method != method {
			continue
		}
		params, ok := matchTemplate(rt.Path, segs)
		if !ok {
			continue
		}
		key := rt.Method + " " + rt.Path
		if ev.RouteKey != key || ev.RequestContext.RouteKey != key {
			return Route{}, refuse("the event's route key is not the row's")
		}
		for name, value := range ev.PathParameters {
			want, ok := params[name]
			if !ok || value != want {
				return Route{}, refuse("pathParameters disagree with rawPath")
			}
		}
		return rt, nil
	}
	return Route{}, refuse("no row of the mapping matches the event's route")
}

// matchTemplate matches the raw path segments against a route template. A
// {name} segment matches one non-empty segment, whose value is its
// percent-decoding, as API Gateway decodes path parameters; any other segment
// matches itself.
func matchTemplate(tmpl string, segs []string) (map[string]string, bool) {
	ts := strings.Split(tmpl, "/")
	if len(ts) != len(segs) {
		return nil, false
	}
	params := map[string]string{}
	for i, t := range ts {
		if name, ok := strings.CutPrefix(t, "{"); ok && strings.HasSuffix(name, "}") {
			if segs[i] == "" {
				return nil, false
			}
			v, err := url.PathUnescape(segs[i])
			if err != nil {
				return nil, false
			}
			params[strings.TrimSuffix(name, "}")] = v
			continue
		}
		if t != segs[i] {
			return nil, false
		}
	}
	return params, true
}
