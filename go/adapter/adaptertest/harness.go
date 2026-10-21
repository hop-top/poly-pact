package adaptertest

import (
	"encoding/json"
	"net/http"
	"slices"
	"sync"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core/clock"
)

// Factory builds the adapter under test for one case. The suite calls it once
// per case, so every case starts from the native state it declares and from
// nothing else.
//
// A Factory reads env.State, the case's native_state member, and builds the
// adapter's native systems from it: the identity store, the enrollment source,
// the claim sources, the policy and the installed checks. The common cases in
// spec/v1.0/fixtures/adapters/_common state it in the neutral "common/1" model that
// the fixture README defines, and an adapter's own cases state it in whatever
// shape its Factory reads. The suite never looks inside.
//
// A Factory that cannot build the adapter returns an error; the case fails
// with it. t is for cleanup and temporary files only.
type Factory func(t testing.TB, env Env) (Subject, error)

// Env is what the suite hands a Factory.
type Env struct {
	// State is the native_state member of the case file, verbatim.
	State json.RawMessage
	// Clock is the adapter's only source of the current time. The suite holds
	// it at the case's now, so an adapter that reads the wall clock instead is
	// caught by every time assertion.
	Clock clock.Clock
	// Hooks records the calls the adapter makes into native execution hooks.
	// An adapter wired to a downstream executor calls Hooks.Fire("execute")
	// where it would run the protected operation; cases then assert, with
	// expect.must_not_call, that a denial ran nothing.
	Hooks *Hooks
}

// Subject is the adapter under test with the few hooks that depend on the
// native mechanism and that the suite cannot supply itself.
type Subject struct {
	// Adapter is the adapter under test.
	Adapter adapter.Adapter

	// Arrive marks r as having reached the adapter through the enforcement
	// point, in the way the adapter's mechanism recognizes. It returns the
	// request to use from then on. A request the suite does not pass through
	// Arrive is a direct request that bypassed the enforcement point; the
	// adapter must not authenticate it. Required.
	Arrive func(r *http.Request) *http.Request

	// Credential attaches to r the credential of the native identity that
	// ref names in the case's native state, in the form the adapter's
	// mechanism reads: a header, a cookie, a peer certificate. It returns an
	// error when ref is unknown. Required by cases that set
	// request.native_state_ref.
	Credential func(r *http.Request, ref string) error

	// VerifyOutcome, when set, verifies the signature of a compact JWS that
	// RecordOutcome returned. Optional.
	VerifyOutcome func(jws string) error
}

// Hooks records the native hooks an adapter fired during a case. It is safe for
// concurrent use.
type Hooks struct {
	mu    sync.Mutex
	fired []string
}

// Fire records that the hook named name ran.
func (h *Hooks) Fire(name string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fired = append(h.fired, name)
}

// Fired returns the names of the hooks that ran, in order.
func (h *Hooks) Fired() []string {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.fired)
}
