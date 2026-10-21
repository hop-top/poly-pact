package adapter

import (
	"context"
	"net/http"

	"hop.top/pact-go/core"
)

// OperationMapper is the draft 17.1 function map_operation.
type OperationMapper interface {
	// MapOperation derives the authoritative [core.OperationContext] from the
	// actual authenticated request and the installed mapping named by
	// mappingVersion (draft 10.2). Action, resources and principal come from
	// the request and p, never from a client-supplied resource list, and every
	// consequential part of the request (path, query, body, headers) is
	// covered. An implementation that reads r.Body restores it before it
	// returns.
	//
	// It returns an error that wraps [ErrInvalidMessage] when r violates a rule
	// of the baseline HTTP mapping (draft 10.2, 13.4), such as a fragment or
	// userinfo in the target, an ambiguous encoding as draft 10.2 defines and
	// lists them, or an HTTP content encoding; [ErrUnsupportedRequirement] when
	// mappingVersion is not installed, [ErrContextMismatch] when the request
	// and p disagree, and [ErrDependencyUnavailable] when a lookup the mapping
	// needs cannot be completed.
	MapOperation(ctx context.Context, r *http.Request, p Principal, mappingVersion string) (core.OperationContext, error)
}
