package adaptertest

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"

	"hop.top/pact-go/core"
)

// mapOperation runs a map_operation case.
func (r *run) mapOperation(ctx context.Context) {
	req, body := r.request(ctx)
	if req == nil {
		return
	}
	p := r.principal()
	var (
		op  core.OperationContext
		err error
	)
	if !r.guard("MapOperation", func() {
		op, err = r.subj.Adapter.MapOperation(req.Context(), req, p, r.c.Call.MappingVersion)
	}) {
		return
	}
	r.checkBodyRestored(req, body)
	r.scanError("MapOperation", err)
	if err == nil {
		r.scanValue("MapOperation operation", op)
	}

	e := &r.c.Expect
	switch e.Outcome {
	case outMapped:
		if err != nil {
			r.failf("MapOperation returned %v, want an operation context", err)
			return
		}
		r.checkOperation(op, p.ID, e.Operation)
	case outError:
		if err == nil {
			r.failf("MapOperation mapped the request to %s %s, want an error", op.Method, op.TargetURI)
			return
		}
		r.wantReason("MapOperation", err)
		if !operationEmpty(op) {
			r.failf("MapOperation returned an operation context together with an error; a caller that ignores the error would act on it")
		}
	}
}

// checkBodyRestored fails when the adapter consumed the request body and did
// not put it back (draft 10.2: the digest covers the exact bytes, and the
// request must still be forwardable).
func (r *run) checkBodyRestored(req *http.Request, body []byte) {
	if len(body) == 0 {
		return
	}
	if req.Body == nil {
		r.failf("MapOperation left the request without a body; it must restore what it reads")
		return
	}
	got, err := io.ReadAll(req.Body)
	if err != nil {
		r.failf("reading the body after MapOperation: %v", err)
		return
	}
	if !bytes.Equal(got, body) {
		r.failf("MapOperation left %d body bytes, want the original %d; it must restore what it reads", len(got), len(body))
	}
}

// checkOperation checks a mapped operation against the invariants of the
// baseline HTTP mapping (draft 10.2) and the case.
func (r *run) checkOperation(op core.OperationContext, principalID string, want *ExpectOperation) {
	if op.OperationID == "" {
		r.failf("operation_id is empty")
	}
	if op.PrincipalID != principalID {
		r.failf("principal_id is %q, want the authenticated principal %q: the principal comes from native authentication, never from the request", op.PrincipalID, principalID)
	}
	if op.Method != strings.ToUpper(op.Method) {
		r.failf("method %q is not uppercase", op.Method)
	}
	if !strings.HasPrefix(op.TargetURI, "https://") {
		r.failf("target_uri %q is not an https URI", op.TargetURI)
	}
	if strings.Contains(op.TargetURI, "#") {
		r.failf("target_uri %q carries a fragment", op.TargetURI)
	}
	if err := op.BodyDigest.Validate(); err != nil {
		r.failf("body_digest: %v", err)
	}
	// The wire form has arrays and objects here; a nil slice or map would
	// encode as null.
	if op.Resources == nil {
		r.failf("resources is nil, so it encodes as null; it must be an array")
	}
	if op.Headers == nil {
		r.failf("headers is nil, so it encodes as null; it must be an object")
	}
	for name := range op.Headers {
		if name != strings.ToLower(name) {
			r.failf("header name %q is not lowercase", name)
		}
	}
	if want == nil {
		return
	}
	if want.EnvironmentID != "" && op.EnvironmentID != want.EnvironmentID {
		r.failf("environment_id is %q, want %q", op.EnvironmentID, want.EnvironmentID)
	}
	if want.PrincipalID != "" && op.PrincipalID != want.PrincipalID {
		r.failf("principal_id is %q, want %q", op.PrincipalID, want.PrincipalID)
	}
	if want.Action != "" && op.Action != want.Action {
		r.failf("action is %q, want %q", op.Action, want.Action)
	}
	if want.Resources != nil && !equalStrings(op.Resources, *want.Resources) {
		r.failf("resources are %q, want %q: the resources come from the request and the installed mapping, never from a client-supplied list", op.Resources, *want.Resources)
	}
	if want.Method != "" && op.Method != want.Method {
		r.failf("method is %q, want %q", op.Method, want.Method)
	}
	if want.TargetURI != "" && op.TargetURI != want.TargetURI {
		r.failf("target_uri is %q, want %q", op.TargetURI, want.TargetURI)
	}
	if want.BodyDigest != "" && string(op.BodyDigest) != want.BodyDigest {
		r.failf("body_digest is %q, want %q", op.BodyDigest, want.BodyDigest)
	}
	if want.Headers != nil && !equalMaps(op.Headers, *want.Headers) {
		r.failf("headers are %s, want %s", formatMap(op.Headers), formatMap(*want.Headers))
	}
}
