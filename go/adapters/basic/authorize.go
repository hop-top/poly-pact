package basic

import (
	"context"
	"fmt"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core"
)

// PermissionLookup is the native permission lookup of the account database:
// whether the account may perform the operation, such as reading an invoice
// of its own department.
type PermissionLookup = installed.PermissionLookup

// AuthorizeNative asks the native permission lookup about the original
// principal and the actual operation and returns its decision unchanged, with
// its obligations and its provenance (draft 4.3, 17.1). PACT cannot rewrite a
// denial, and the adapter never substitutes another identity or runs the
// operation. A decision that names no source, has no defined effect, or was
// made later than now plus the skew is not passed on: the error wraps
// [adapter.ErrDependencyUnavailable].
func (a *Adapter) AuthorizeNative(ctx context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	if err := live(ctx, "authorize"); err != nil {
		return adapter.Decision{}, err
	}
	d, err := installed.Authorize(ctx, a.cfg.Permissions, p, op, a.cfg.Clock.Now())
	if err != nil {
		return adapter.Decision{}, fmt.Errorf("basic: authorize: %w", err)
	}
	return d, nil
}
