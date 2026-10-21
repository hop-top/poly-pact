package rebac

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/strictjson"
)

// HigherConsistency is the consistency preference every Check sends (profile
// RB-9): it skips the server's caches ([OF-1], [OF-2]). The server answers an
// unknown string as the default, which may come from a cache (profile section
// 14.3), so the value is a constant of the adapter and never configuration.
const HigherConsistency = "HIGHER_CONSISTENCY"

// tupleKey is the tuple_key of a Check request ([OF-2]).
type tupleKey struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

// checkRequest is the body of a Check: the pinned model, the tuple, the
// consistency preference, and never contextual tuples or a context (profile
// RB-2, RB-7, RB-9).
type checkRequest struct {
	TupleKey             tupleKey `json:"tuple_key"`
	AuthorizationModelID string   `json:"authorization_model_id"`
	Consistency          string   `json:"consistency"`
}

// errorCode is the form of the code of an OpenFGA error body ([OF-2]); any
// other text is not repeated in an error.
var errorCode = regexp.MustCompile(`^[a-z_]{1,64}$`)

// AuthorizeNative asks the pinned OpenFGA store, with one Check, whether the
// original principal holds the relation of the operation's action on the
// operation's resource, and returns the answer as the decision (draft 4.3,
// 17.1; profile RB-14). The Check names the pinned store and model and asks
// HIGHER_CONSISTENCY; it carries no contextual tuple and no context, so
// nothing of the request becomes a tuple (RB-2, RB-7 to RB-9).
//
// Before any Check:
//   - the principal and the operation must belong to the gateway's realm, and
//     the operation's principal must be the principal given (RB-3, RB-19);
//   - the operation must be one the pinned mapping revision produces: its
//     method and target select a route whose action and resource are the
//     operation's, so a context bound to document.read is never Checked for
//     an edit (RB-18);
//   - the action must have a row in the relation table (RB-5);
//   - the principal and the resource must have registry entries in the
//     realm (RB-4, RB-6).
//
// A principal, an environment, an operation or a registry entry that does not
// match is [adapter.ErrContextMismatch]; a request no route matches, an action
// without a row and a registry id outside the form of RB-6 are
// [adapter.ErrUnsupportedRequirement]. None sends a Check.
//
// The answer decides only when it is a 200 whose body is a JSON object with
// one boolean allowed, and a string resolution if it has one ([OF-2]): true
// is EffectAllow, false EffectDeny. A 400 or a 404
// is a configuration fault, [adapter.ErrUnsupportedRequirement]; every other
// outcome, no connection, a time-out, a redirect or another status among
// them, is [adapter.ErrDependencyUnavailable] (RB-13). The adapter does not
// retry, weaken the consistency, or fall back to an earlier answer.
//
// The decision names the pinned store as its source and the pinned model as
// its policy revision; it has no obligation, no decision record and no
// decision time, since a Check answer gives none ([OF-2]).
func (a *Adapter) AuthorizeNative(ctx context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	if err := live(ctx, "authorize"); err != nil {
		return adapter.Decision{}, err
	}
	req, err := a.checkFor(ctx, p, op)
	if err != nil {
		return adapter.Decision{}, fmt.Errorf("rebac: authorize: %w", err)
	}
	allowed, err := a.check(ctx, req)
	if err != nil {
		return adapter.Decision{}, fmt.Errorf("rebac: authorize: %w", err)
	}
	d := adapter.Decision{
		Effect:         adapter.EffectDeny,
		Reason:         "the relationship store does not grant " + req.TupleKey.Relation,
		SourceID:       a.cfg.Pin.StoreID,
		PolicyRevision: a.cfg.Pin.AuthorizationModelID,
	}
	if allowed {
		d.Effect, d.Reason = adapter.EffectAllow, "the relationship store grants "+req.TupleKey.Relation
	}
	return d, nil
}

// checkFor builds the Check of the operation, or refuses it.
func (a *Adapter) checkFor(ctx context.Context, p adapter.Principal, op core.OperationContext) (checkRequest, error) {
	realm := a.cfg.Realm
	switch {
	case p.ID == "" || p.Realm != realm:
		return checkRequest{}, fmt.Errorf("the principal does not belong to the gateway's realm: %w", adapter.ErrContextMismatch)
	case op.EnvironmentID != realm.EnvironmentID:
		return checkRequest{}, fmt.Errorf("the operation belongs to another environment: %w", adapter.ErrContextMismatch)
	case op.PrincipalID != p.ID:
		return checkRequest{}, fmt.Errorf("the operation names another principal: %w", adapter.ErrContextMismatch)
	}
	action, resource, ok := a.route(op)
	if !ok {
		return checkRequest{}, fmt.Errorf("the mapping %q has no route for the operation: %w", a.cfg.Pin.MappingRevision, adapter.ErrUnsupportedRequirement)
	}
	if action != op.Action || !slices.Equal(op.Resources, []string{resource}) {
		return checkRequest{}, fmt.Errorf("the operation's action or resources are not those its request maps to: %w", adapter.ErrContextMismatch)
	}
	rel, ok := a.relations[action]
	if !ok {
		return checkRequest{}, fmt.Errorf("the relation table has no row for %q: %w", action, adapter.ErrUnsupportedRequirement)
	}
	subject, ok, err := a.cfg.Registry.Subject(ctx, realm, p.ID)
	if err != nil {
		return checkRequest{}, dependency("the mapping registry", err)
	}
	if !ok {
		return checkRequest{}, fmt.Errorf("the principal has no subject in the realm: %w", adapter.ErrContextMismatch)
	}
	object, ok, err := a.cfg.Registry.Object(ctx, realm, resource)
	if err != nil {
		return checkRequest{}, dependency("the mapping registry", err)
	}
	if !ok {
		return checkRequest{}, fmt.Errorf("the resource has no object in the realm: %w", adapter.ErrContextMismatch)
	}
	k := tupleKey{User: subjectType + ":" + subject, Relation: rel.Relation, Object: rel.ObjectType + ":" + object}
	if !validID(subject) || !validID(object) || len(k.User) > maxUser || len(k.Object) > maxObject {
		return checkRequest{}, fmt.Errorf("the registry gives an identifier outside the form of RB-6: %w", adapter.ErrUnsupportedRequirement)
	}
	return checkRequest{TupleKey: k, AuthorizationModelID: a.cfg.Pin.AuthorizationModelID, Consistency: HigherConsistency}, nil
}

// route returns the action and the resource the pinned mapping gives the
// operation's method and target.
func (a *Adapter) route(op core.OperationContext) (action, resource string, ok bool) {
	rest, found := strings.CutPrefix(op.TargetURI, a.origin)
	if !found || !strings.HasPrefix(rest, "/") {
		return "", "", false
	}
	path, _, _ := strings.Cut(rest, "?")
	segs := strings.Split(path, "/")
	for _, rt := range a.routes {
		if rt.Method != op.Method {
			continue
		}
		if res, matched := fill(rt, segs); matched {
			return rt.Action, res, true
		}
	}
	return "", "", false
}

// fill matches the segments of a path against the route's template, as the
// mapping does: a {name} segment matches one non-empty segment of unreserved
// characters, and the route's resource gets the matched values.
func fill(rt Route, segs []string) (string, bool) {
	tmpl := strings.Split(rt.Path, "/")
	if len(tmpl) != len(segs) {
		return "", false
	}
	res := rt.Resource
	for i, t := range tmpl {
		if strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}") {
			if segs[i] == "" || strings.ContainsFunc(segs[i], func(c rune) bool { return !unreserved(c) }) {
				return "", false
			}
			res = strings.ReplaceAll(res, t, segs[i])
			continue
		}
		if t != segs[i] {
			return "", false
		}
	}
	return res, true
}

// unreserved reports whether c is an unreserved character of RFC 3986,
// section 2.3.
func unreserved(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}

// check sends the Check and reads the answer.
func (a *Adapter) check(ctx context.Context, body checkRequest) (bool, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.checkURL, bytes.NewReader(raw))
	if err != nil {
		return false, fmt.Errorf("the Check request: %w", adapter.ErrUnsupportedRequirement)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if a.cfg.Store.Credential != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.Store.Credential)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		// The transport error names the URL, which carries no credential,
		// and the cause; neither is repeated.
		return false, fmt.Errorf("the relationship store cannot be reached: %w", adapter.ErrDependencyUnavailable)
	}
	defer func() { _ = resp.Body.Close() }()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return false, fmt.Errorf("the relationship store's answer cannot be read: %w", adapter.ErrDependencyUnavailable)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusBadRequest, http.StatusNotFound:
		return false, fmt.Errorf("the relationship store refuses the Check as not matching the pin (%d%s): %w",
			resp.StatusCode, codeOf(answer), adapter.ErrUnsupportedRequirement)
	default:
		return false, fmt.Errorf("the relationship store answers %d%s: %w", resp.StatusCode, codeOf(answer), adapter.ErrDependencyUnavailable)
	}
	if len(answer) > maxAnswer {
		return false, fmt.Errorf("the relationship store's answer is too large: %w", adapter.ErrDependencyUnavailable)
	}
	var members map[string]json.RawMessage
	if err := strictjson.Unmarshal(answer, strictjson.Limits{MaxBytes: maxAnswer}, &members); err != nil {
		return false, fmt.Errorf("the relationship store's answer is not a JSON object: %w", adapter.ErrDependencyUnavailable)
	}
	if r, ok := members["resolution"]; ok {
		var text string
		if json.Unmarshal(r, &text) != nil {
			return false, fmt.Errorf("the relationship store's answer has a resolution that is not a string: %w", adapter.ErrDependencyUnavailable)
		}
	}
	switch v := string(bytes.TrimSpace(members["allowed"])); v {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("the relationship store's answer has no boolean allowed: %w", adapter.ErrDependencyUnavailable)
}

// codeOf returns ", <code>" for an OpenFGA error body with a code of the
// documented form, and "" otherwise.
func codeOf(body []byte) string {
	var e struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(body, &e) != nil || !errorCode.MatchString(e.Code) {
		return ""
	}
	return ", " + e.Code
}

// dependency wraps err of source as a dependency error unless it carries a
// code.
func dependency(source string, err error) error {
	if _, ok := adapter.CodeOf(err); ok {
		return fmt.Errorf("%s: %w", source, err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: %w: %w", source, adapter.ErrDependencyUnavailable, err)
	}
	return fmt.Errorf("%s cannot answer: %w", source, adapter.ErrDependencyUnavailable)
}
