package adaptertest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/jcs"
)

// skew is the clock skew the suite allows between an adapter's timestamps and
// the case's now: the baseline of draft 7.5. An adapter configured with a
// tighter skew passes; one that needs a larger skew does not.
const skew = clock.BaselineSkew

// jsonEqual reports whether a and b are the same JSON data: object member
// order is ignored, array order is significant (draft 8.4). Both are put into
// RFC 8785 canonical form and compared.
func jsonEqual(a, b []byte) (bool, error) {
	ca, err := jcs.Canonicalize(a)
	if err != nil {
		return false, fmt.Errorf("expected value: %w", err)
	}
	cb, err := jcs.Canonicalize(b)
	if err != nil {
		return false, fmt.Errorf("returned value: %w", err)
	}
	return bytes.Equal(ca, cb), nil
}

// adapterSentinels are the sentinel errors of package adapter. An error that
// carries the code of one of them is that sentinel or wraps it, which is how
// callers match it with errors.Is (package adapter, Errors).
var adapterSentinels = []error{
	adapter.ErrInvalidMessage,
	adapter.ErrInvalidProof,
	adapter.ErrContextMismatch,
	adapter.ErrDependencyUnavailable,
	adapter.ErrUnsupportedRequirement,
	adapter.ErrUnsupportedPurpose,
	adapter.ErrMissingField,
}

// wantReason checks the stable code an error carries against the case's
// reason_code, when the case names one, and that the error wraps the sentinel
// of that code.
func (r *run) wantReason(step string, err error) {
	want := r.c.Expect.ReasonCode
	if want == "" || err == nil {
		return
	}
	got, ok := adapter.CodeOf(err)
	switch {
	case !ok:
		r.failf("%s error carries no draft 13.4 code, want %s: %v", step, want, err)
		return
	case string(got) != want:
		r.failf("%s error code is %s, want %s: %v", step, got, want, err)
		return
	}
	for _, s := range adapterSentinels {
		if c, _ := adapter.CodeOf(s); string(c) == want && !errors.Is(err, s) {
			r.failf("%s error carries the code %s but does not wrap the sentinel %q: return the sentinel or wrap it with %%w so that errors.Is matches: %v", step, want, s, err)
		}
	}
}

// wantTime checks a time against an expected member of the case: absent is not
// checked, null requires the zero time, a number requires those Unix seconds.
func (r *run) wantTime(what string, want json.RawMessage, got time.Time) {
	if len(want) == 0 {
		return
	}
	if string(bytes.TrimSpace(want)) == "null" {
		if !got.IsZero() {
			r.failf("%s is %d, want the zero time: the source gives none and the adapter must not supply one", what, got.Unix())
		}
		return
	}
	var sec int64
	if err := json.Unmarshal(want, &sec); err != nil {
		r.failf("%s: expected value %s is not an integer: %v", what, want, err)
		return
	}
	switch {
	case got.IsZero():
		r.failf("%s is the zero time, want %d", what, sec)
	case got.Unix() != sec:
		r.failf("%s is %d, want %d (the time the source gave, not the time of the read)", what, got.Unix(), sec)
	}
}

// notAfter fails when t is later than limit. A zero t passes: it says the
// source gives no such time.
func (r *run) notAfter(what string, t, limit time.Time) {
	if !t.IsZero() && t.After(limit) {
		r.failf("%s is %d, later than the allowed %d", what, t.Unix(), limit.Unix())
	}
}

// isDependencyUnavailable reports whether err says a source cannot answer.
func isDependencyUnavailable(err error) bool {
	return errors.Is(err, adapter.ErrDependencyUnavailable)
}

func principalEmpty(p adapter.Principal) bool {
	return p.ID == "" && p.Workload == "" && p.Realm == (adapter.Realm{})
}

func bindingEmpty(b adapter.AgentBinding) bool {
	return b.AgentID == "" && b.OperatorID == "" && b.HolderJKT == ""
}

func operationEmpty(op core.OperationContext) bool {
	return op.OperationID == "" && op.PrincipalID == "" && op.Action == "" &&
		op.TargetURI == "" && op.BodyDigest == "" && len(op.Resources) == 0
}

// equalStrings compares two string slices.
func equalStrings(a, b []string) bool { return slices.Equal(a, b) }

// equalMaps compares two string maps; nil and empty are equal.
func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// formatMap renders a header map with sorted names, for messages.
func formatMap(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%q: %q", k, m[k])
	}
	return "{" + strings.Join(parts, ", ") + "}"
}
