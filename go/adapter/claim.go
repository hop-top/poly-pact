package adapter

import (
	"context"
	"time"

	"hop.top/pact-go/core"
)

// NativeClaim is an authoritative value read from a native source together
// with its provenance.
type NativeClaim struct {
	// Value is the authoritative value as JSON data. It must be a value that
	// encoding/json encodes, and it is compared as JSON data (draft 8.4). A nil
	// Value is JSON null.
	Value any
	// ObservedAt is the original source observation time (draft 8.3), not the
	// time of the read. The zero time means the source gives none.
	ObservedAt time.Time
	// StatusCheckedAt is when the source last confirmed the value is still in
	// force. The zero time means no status check took place.
	StatusCheckedAt time.Time
	// SourceID identifies the configured authoritative source.
	SourceID string
	// SourceRef is an opaque reference into that source; empty when none.
	SourceRef string
}

// ClaimContext is the evaluation context a native claim is read in (draft 17.1:
// "approved native path and context").
//
// The approved mapping of a native path decides which part of the context the
// read uses: a subject path uses Principal, a resource path uses the resources
// of Operation, and a task path uses the task of Intent. An adapter reads
// nothing else from the request.
type ClaimContext struct {
	// Principal is the authenticated principal.
	Principal Principal
	// Intent is the declared intent; Intent.TaskID scopes task facts.
	Intent core.Intent
	// Operation is the actual operation; Operation.Resources scopes resource
	// facts.
	Operation core.OperationContext
}

// ClaimReader is the draft 17.1 function read_native_claim.
type ClaimReader interface {
	// ReadNativeClaim reads the value at nativePath in the context c from the
	// configured authoritative source. nativePath is a path an administrator
	// approved in the versioned mapping (draft 17.2); any other path returns an
	// error that wraps [ErrUnsupportedRequirement]. A fact of a resource is
	// read only for a resource that c.Operation lists, and a fact of a task
	// only for the task of c.Intent.
	//
	// The adapter reports the timestamps the source gives and no others: it
	// does not claim a freshness it cannot establish, and it does not restamp
	// a cached snapshot with the time of the read (draft 8.3, 17.2).
	//
	// A source that cannot be reached returns an error that wraps
	// [ErrDependencyUnavailable], which the validator maps to DEFERRED.
	ReadNativeClaim(ctx context.Context, nativePath string, c ClaimContext) (NativeClaim, error)
}
