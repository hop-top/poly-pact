package adaptertest

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core/clock"
)

// defaultNow is the current time of a case that states none: 2026-10-15T16:00:00Z,
// the timestamp of the draft's worked example.
const defaultNow int64 = 1792080000

// callTimeout bounds each case.
const callTimeout = 10 * time.Second

// Options configures a run of the suite.
type Options struct {
	// Fixtures is the fixture tree, rooted at spec/v1.0/fixtures. When nil, the
	// suite uses the spec/v1.0/fixtures directory next to the Go module: the
	// ../spec/v1.0/fixtures directory relative to the directory that holds go.mod,
	// found by walking up from the working directory. That works inside the
	// source repository. A module that imports this package from the
	// read-only hop-top/pact-go mirror, which carries only the Go code, passes
	// the v1.0/fixtures directory of the spec mirror instead:
	//
	//	adaptertest.Options{Fixtures: os.DirFS("path/to/spec-pact/v1.0/fixtures")}
	Fixtures fs.FS

	// Adapter names the adapter's own cases, the case files directly in
	// adapters/<Adapter> of the fixture tree, to run after the common cases.
	// Empty runs the common cases only.
	Adapter string

	// SharedWorkloads says that the adapter's profile supports workloads
	// shared by several agents (spec/v1.0/profiles/identity-mapping.md, IM-19).
	// The suite then runs the cases whose workloads member is "shared", such
	// as the selection cases of IDENT-09, instead of those whose member is
	// "dedicated". False, the default of every profile, runs the dedicated
	// cases, such as the configuration error of IDENT-10. Cases without the
	// member run either way.
	SharedWorkloads bool

	// Replaced maps the id of a common case to the adapter's own case that
	// replaces it. Run checks every entry before any case runs: the id is a
	// common authenticate_native or authorize_native case, By is a case of
	// adapters/<Adapter> for the same function with the same outcome class
	// (accepted or rejected, as the fixture manifest classifies outcomes), and
	// Reason is not empty. A
	// replaced case is still run and must fail; a replaced case that passes
	// fails the suite, so a stale declaration cannot stand. Evaluate ignores
	// this field and reports every case as run.
	Replaced map[string]Replacement
}

// Replacement names the adapter's own case that stands in for a common case
// the adapter's mechanism cannot realize. Draft 22.2 lets a conformance claim
// replace a required test by one that is no weaker than the original intent;
// the common suite allows it for authenticate_native cases, and for
// authorize_native cases whose expected decision carries a member the
// mechanism's decision answer cannot carry, because every other function's
// native state is deployment-supplied and a harness realizes it
// (spec/v1.0/fixtures/adapters/README.md, "Replaced common cases").
type Replacement struct {
	// By is the id of the adapter's own case that covers the same property.
	By string
	// Reason says what the mechanism cannot carry: the identifier form of the
	// expected principal, the credential form of the pinned denial, or a
	// member of the expected decision, such as an obligation or a decision
	// time.
	Reason string
}

// Run executes the common cases, and the adapter's own cases when
// opts.Adapter is set, as one subtest per case. A case that names a workload
// mode other than the one of opts.SharedWorkloads is not run. newAdapter
// builds the adapter afresh for each case. A failed assertion fails the
// subtest of its case. A common case that opts.Replaced declares replaced is
// run as well, and its subtest fails when the case passes; Run refuses a
// declaration that breaks a rule of [Options.Replaced] before any case runs.
func Run(t *testing.T, newAdapter Factory, opts Options) {
	t.Helper()
	all, err := opts.loadAll()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if err := checkReplaced(all, opts); err != nil {
		t.Fatalf("%v", err)
	}
	cases := opts.applicable(all)
	for i := range cases {
		c := &cases[i]
		rep, replaced := opts.Replaced[c.ID]
		t.Run(c.ID, func(t *testing.T) {
			errs, logs := verdict(c.ID, runCase(t, newAdapter, c), rep, replaced)
			for _, msg := range logs {
				t.Log(msg)
			}
			for _, msg := range errs {
				t.Error(msg)
			}
		})
	}
}

// verdict turns the failures of a case into the errors and the log lines of
// its subtest. A case that is not replaced fails with its failures. A replaced
// case is expected to fail: its failures are logged, and a pass is the error,
// because the declaration is no longer needed.
func verdict(id string, fails []string, rep Replacement, replaced bool) (errs, logs []string) {
	if !replaced {
		return fails, nil
	}
	if len(fails) == 0 {
		return []string{fmt.Sprintf("%s is declared replaced by %s but passes; drop the declaration", id, rep.By)}, nil
	}
	logs = append(logs, fmt.Sprintf("%s is replaced by %s (%s); it fails here as declared:", id, rep.By, rep.Reason))
	return nil, append(logs, fails...)
}

// checkReplaced checks every declaration of opts.Replaced against the loaded
// cases, the common cases and the adapter's own cases of every workload mode.
func checkReplaced(cases []Case, opts Options) error {
	ids := make([]string, 0, len(opts.Replaced))
	for id := range opts.Replaced {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	byID := make(map[string]*Case, len(cases))
	for i := range cases {
		byID[cases[i].ID] = &cases[i]
	}
	for _, id := range ids {
		rep := opts.Replaced[id]
		orig, ok := byID[id]
		switch {
		case !ok || !orig.common:
			return fmt.Errorf("adaptertest: Replaced: %s is not a common case", id)
		case orig.Expect.Function != fnAuthenticate && orig.Expect.Function != fnAuthorize:
			return fmt.Errorf("adaptertest: Replaced: %s is a %s case; only %s and %s cases may be replaced", id, orig.Expect.Function, fnAuthenticate, fnAuthorize)
		case strings.TrimSpace(rep.Reason) == "":
			return fmt.Errorf("adaptertest: Replaced: %s gives no reason", id)
		case rep.By == "":
			return fmt.Errorf("adaptertest: Replaced: %s names no replacement case", id)
		}
		by, ok := byID[rep.By]
		switch {
		case !ok || by.common:
			return fmt.Errorf("adaptertest: Replaced: %s is replaced by %s, which is not a case of adapters/%s", id, rep.By, opts.Adapter)
		case by.Expect.Function != orig.Expect.Function:
			return fmt.Errorf("adaptertest: Replaced: %s is a %s case, but its replacement %s is a %s case", id, orig.Expect.Function, rep.By, by.Expect.Function)
		case accepted(by.Expect.Outcome) != accepted(orig.Expect.Outcome):
			return fmt.Errorf("adaptertest: Replaced: %s expects %s, but its replacement %s expects %s, of the other outcome class", id, orig.Expect.Outcome, rep.By, by.Expect.Outcome)
		}
	}
	return nil
}

// accepted reports whether an outcome lets the stimulus through, the outcome
// class ACCEPTED of the fixture manifest; every other outcome is REJECTED.
func accepted(outcome string) bool {
	switch outcome {
	case outAuthenticated, outBound, outMapped, outClaim, outSigned, outAllow, outPass:
		return true
	}
	return false
}

// Result is the outcome of one case.
type Result struct {
	// ID is the case id.
	ID string
	// Failures lists every assertion the adapter failed, one line each. It is
	// empty when the adapter passed the case.
	Failures []string
}

// Passed reports whether the adapter passed the case.
func (r Result) Passed() bool { return len(r.Failures) == 0 }

// Evaluate runs the same cases as Run and returns their results instead of
// failing a test. It is how a test proves that a deliberately broken adapter
// fails the suite: Run would fail the test that calls it, Evaluate reports what
// failed. tb is passed to newAdapter. An error means the cases could not be
// loaded.
func Evaluate(tb testing.TB, newAdapter Factory, opts Options) ([]Result, error) {
	tb.Helper()
	cases, err := opts.load()
	if err != nil {
		return nil, err
	}
	out := make([]Result, len(cases))
	for i := range cases {
		out[i] = Result{ID: cases[i].ID, Failures: runCase(tb, newAdapter, &cases[i])}
	}
	return out, nil
}

func (o Options) load() ([]Case, error) {
	cases, err := o.loadAll()
	if err != nil {
		return nil, err
	}
	return o.applicable(cases), nil
}

// loadAll loads the cases of every workload mode.
func (o Options) loadAll() ([]Case, error) {
	fsys := o.Fixtures
	if fsys == nil {
		var err error
		if fsys, err = DefaultFixtures(); err != nil {
			return nil, err
		}
	}
	return Load(fsys, o.Adapter)
}

// applicable returns the cases of the workload mode of o.
func (o Options) applicable(cases []Case) []Case {
	return slices.DeleteFunc(cases, func(c Case) bool { return !c.appliesTo(o.SharedWorkloads) })
}

// DefaultFixtures returns the fixture tree of the source repository: the
// ../spec/v1.0/fixtures directory relative to the directory that holds go.mod,
// found by walking up from the working directory.
func DefaultFixtures() (fs.FS, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("adaptertest: %w", err)
	}
	for dir := wd; ; {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			root := filepath.Join(filepath.Dir(dir), "spec", "v1.0", "fixtures")
			if st, err := os.Stat(root); err != nil || !st.IsDir() {
				return nil, fmt.Errorf("adaptertest: no fixture directory at %s; set Options.Fixtures to the spec mirror's v1.0/fixtures", root)
			}
			return os.DirFS(root), nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil, fmt.Errorf("adaptertest: no go.mod above %s; set Options.Fixtures", wd)
		}
		dir = parent
	}
}

// run is the state of one case.
type run struct {
	c     *Case
	now   time.Time
	hooks *Hooks
	subj  Subject
	fails []string
}

func (r *run) failf(format string, args ...any) {
	r.fails = append(r.fails, fmt.Sprintf(format, args...))
}

// guard calls f and records a panic as a failure of the named step. It reports
// whether f returned normally.
func (r *run) guard(step string, f func()) (ok bool) {
	defer func() {
		if p := recover(); p != nil {
			r.failf("%s panicked: %v", step, p)
			ok = false
		}
	}()
	f()
	return true
}

// runCase runs one case against a fresh adapter and returns its failures.
func runCase(tb testing.TB, newAdapter Factory, c *Case) []string {
	tb.Helper()
	nowSec := defaultNow
	if c.Now != nil {
		nowSec = *c.Now
	}
	now := time.Unix(nowSec, 0)
	r := &run{c: c, now: now, hooks: &Hooks{}}

	var err error
	if !r.guard("factory", func() {
		r.subj, err = newAdapter(tb, Env{
			State: c.NativeState,
			Clock: clock.NewFake(now),
			Hooks: r.hooks,
		})
	}) {
		return r.fails
	}
	if err != nil {
		r.failf("factory: %v", err)
		return r.fails
	}
	if r.subj.Adapter == nil {
		r.failf("factory returned no adapter")
		return r.fails
	}
	if r.subj.Arrive == nil {
		r.failf("factory returned no Arrive hook: the suite cannot tell a request through the enforcement point from a bypass")
		return r.fails
	}

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	r.execute(ctx)

	for _, name := range c.Expect.MustNotCall {
		if slices.Contains(r.hooks.Fired(), name) {
			r.failf("hook %q fired; it must not (fired: %v)", name, r.hooks.Fired())
		}
	}
	return r.fails
}

func (r *run) execute(ctx context.Context) {
	switch r.c.Expect.Function {
	case fnAuthenticate:
		r.authenticate(ctx)
	case fnBinding:
		r.binding(ctx)
	case fnMapOperation:
		r.mapOperation(ctx)
	case fnClaim:
		r.claim(ctx)
	case fnCheck:
		r.check(ctx)
	case fnAuthorize:
		r.authorize(ctx)
	case fnRecord:
		r.record(ctx)
	}
}

// request builds the case's request, attaches the credential and marks the
// arrival, and returns it with its body. A nil request means a failure was
// recorded.
func (r *run) request(ctx context.Context) (*http.Request, []byte) {
	cr := r.c.Request
	req, body, err := buildRequest(ctx, cr)
	if err != nil {
		r.failf("%v", err)
		return nil, nil
	}
	if cr.NativeStateRef != "" {
		if r.subj.Credential == nil {
			r.failf("factory returned no Credential hook, and the case presents native identity %q", cr.NativeStateRef)
			return nil, nil
		}
		if err := r.subj.Credential(req, cr.NativeStateRef); err != nil {
			r.failf("credential for native identity %q: %v", cr.NativeStateRef, err)
			return nil, nil
		}
	}
	if cr.Arrival != arrivalDirect {
		req = r.subj.Arrive(req)
		if req == nil {
			r.failf("Arrive returned a nil request")
			return nil, nil
		}
	}
	return req, body
}

// principal returns the case's principal argument as the adapter type.
func (r *run) principal() adapter.Principal {
	p := r.c.Call.Principal
	mech := p.Mechanism
	if mech == "" {
		mech = "test"
	}
	at := r.now
	if p.AuthenticatedAt != nil {
		at = time.Unix(*p.AuthenticatedAt, 0)
	}
	return adapter.Principal{
		ID:              p.ID,
		Realm:           adapter.Realm{TenantID: p.Realm.TenantID, EnvironmentID: p.Realm.EnvironmentID},
		Workload:        adapter.Workload(p.Workload),
		Mechanism:       adapter.Mechanism(mech),
		AuthenticatedAt: at,
		Attributes:      p.Attributes,
	}
}
