package installed

import (
	"context"
	"fmt"
	"slices"
	"time"

	"hop.top/pact-go/adapter"
)

// ClaimSource is the source of an approved native path.
type ClaimSource interface {
	// Claims returns the records the source holds at path for the principal
	// in realm. A record that names a resource or a task is a fact of that
	// resource or task; the adapter selects among them by the claim context.
	// An error means the source could not answer.
	Claims(ctx context.Context, realm adapter.Realm, principal, path string) ([]ClaimRecord, error)
}

// ClaimRecord is one value of a [ClaimSource].
type ClaimRecord struct {
	// Value is a JSON-compatible value.
	Value any
	// Resource, when set, makes the record a fact of that resource, read only
	// for an operation that lists it.
	Resource string
	// TaskID, when set, makes the record a fact of that task, read only for an
	// intent that carries it.
	TaskID string
	// ObservedAt and StatusCheckedAt are the times the source gives; zero
	// when it gives none.
	ObservedAt      time.Time
	StatusCheckedAt time.Time
	SourceID        string
	SourceRef       string
}

// Applies reports whether the record is the value in context cc: its
// resource, when it names one, is a resource of the operation, and its task,
// when it names one, is the task of the intent (draft 17.1).
func (c ClaimRecord) Applies(cc adapter.ClaimContext) bool {
	switch {
	case c.Resource != "" && !slices.Contains(cc.Operation.Resources, c.Resource):
		return false
	case c.TaskID != "" && c.TaskID != cc.Intent.TaskID:
		return false
	}
	return true
}

// ReadClaim reads nativePath from src for the claim context, at the instant
// now. The first record that applies in the context is the value. A record
// that names no source, and a source time later than now plus the skew, are
// [adapter.ErrDependencyUnavailable]; an error of the source is a dependency
// error unless it already carries a code. A source that holds no value in the
// context returns an error that carries no code.
func ReadClaim(ctx context.Context, src ClaimSource, nativePath string, cc adapter.ClaimContext, now time.Time) (adapter.NativeClaim, error) {
	records, err := src.Claims(ctx, cc.Principal.Realm, cc.Principal.ID, nativePath)
	if err != nil {
		return adapter.NativeClaim{}, Dependency(err)
	}
	for _, c := range records {
		if !c.Applies(cc) {
			continue
		}
		if c.SourceID == "" {
			return adapter.NativeClaim{}, fmt.Errorf("the value at %q names no source: %w", nativePath, adapter.ErrDependencyUnavailable)
		}
		if err := SourceTimes(now, c.ObservedAt, c.StatusCheckedAt); err != nil {
			return adapter.NativeClaim{}, err
		}
		return adapter.NativeClaim{
			Value:           c.Value,
			ObservedAt:      c.ObservedAt,
			StatusCheckedAt: c.StatusCheckedAt,
			SourceID:        c.SourceID,
			SourceRef:       c.SourceRef,
		}, nil
	}
	return adapter.NativeClaim{}, fmt.Errorf("the source holds no value at %q in this context", nativePath)
}
