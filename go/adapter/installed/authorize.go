package installed

import (
	"context"
	"fmt"
	"maps"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// PermissionLookup is the native permission lookup: whether the principal may
// perform the operation.
type PermissionLookup interface {
	// Decide returns the native decision for the principal and the
	// operation, naming the policy source in SourceID. An error means the
	// lookup could not answer.
	Decide(ctx context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error)
}

// Authorize asks lookup about the original principal and the actual
// operation, at the instant now, and returns its decision unchanged, with its
// obligations and its provenance (draft 4.3, 17.1). PACT cannot rewrite a
// denial, and nothing here substitutes another identity or runs the
// operation. A principal without an id is [adapter.ErrContextMismatch]; a
// decision that names no source, has no defined effect, or was made later
// than now plus the skew is not passed on: the error wraps
// [adapter.ErrDependencyUnavailable].
func Authorize(ctx context.Context, lookup PermissionLookup, p adapter.Principal, op core.OperationContext, now time.Time) (adapter.Decision, error) {
	if p.ID == "" {
		return adapter.Decision{}, fmt.Errorf("no principal: %w", adapter.ErrContextMismatch)
	}
	d, err := lookup.Decide(ctx, p, op)
	if err != nil {
		return adapter.Decision{}, Dependency(err)
	}
	switch {
	case !d.Effect.Valid():
		return adapter.Decision{}, fmt.Errorf("the decision has effect %q: %w", d.Effect, adapter.ErrDependencyUnavailable)
	case d.SourceID == "":
		return adapter.Decision{}, fmt.Errorf("the decision names no policy source: %w", adapter.ErrDependencyUnavailable)
	case !d.DecidedAt.IsZero() && d.DecidedAt.After(now.Add(clock.BaselineSkew)):
		return adapter.Decision{}, fmt.Errorf("the policy source reports a decision after now: %w", adapter.ErrDependencyUnavailable)
	}
	if d.Obligations != nil {
		obl := make([]adapter.Obligation, len(d.Obligations))
		for i, o := range d.Obligations {
			obl[i] = adapter.Obligation{ID: o.ID, Attributes: maps.Clone(o.Attributes)}
		}
		d.Obligations = obl
	}
	return d, nil
}
