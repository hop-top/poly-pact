package sourcetest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/jcs"
)

// skew is the clock skew the harness allows between a source's times and the
// time of a read: the baseline of draft 7.5.
const skew = clock.BaselineSkew

// callTimeout bounds each case.
const callTimeout = 10 * time.Second

// Driver builds the source under test for one case.
type Driver struct {
	// Model is the source model the driver reads, such as scim/1. A case
	// whose source names another model fails.
	Model string
	// Open builds a fresh source from env.Source, the source member of the
	// case. t is for cleanup and temporary files only. An error fails the
	// case.
	Open func(t testing.TB, env Env) (Subject, error)
}

// Env is what the harness hands a Driver.
type Env struct {
	// Source is the source member of the case, verbatim.
	Source json.RawMessage
	// Clock is the source's only source of the current time. The harness
	// sets it to the time of each step and each read.
	Clock clock.Clock
	// Hooks records the calls the source makes that a case can forbid with
	// must_not_call, such as an outbound call of a service provider.
	Hooks *adaptertest.Hooks
}

// Subject is the source under test.
type Subject struct {
	// Reader answers the reads of the case.
	Reader adapter.ClaimReader
	// Apply delivers the inbound message of one step to the source and
	// checks the source's answer against the step's expect member; both are
	// verbatim from the case, and expect is empty when the step has none. It
	// returns an error that says how the answer differs. Required by a case
	// with steps.
	Apply func(ctx context.Context, inbound, expect json.RawMessage) error
}

// Options configures a run.
type Options struct {
	// Fixtures is the fixture tree, rooted at spec/v1.0/fixtures. When nil, the
	// harness uses the tree of [adaptertest.DefaultFixtures].
	Fixtures fs.FS
	// Source names the cases to run: the case files directly in
	// sources/<Source> of the fixture tree. Required.
	Source string
}

// Result is the outcome of one case.
type Result struct {
	// ID is the id member of the case.
	ID string
	// Failures says what the source got wrong; empty when it passed.
	Failures []string
}

// Passed reports whether the source passed the case.
func (r Result) Passed() bool { return len(r.Failures) == 0 }

// Run runs every case of sources/<opts.Source> against the driver, one
// subtest per case.
func Run(t *testing.T, d Driver, opts Options) {
	t.Helper()
	cases, err := opts.load(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			for _, f := range runCase(t, d, c) {
				t.Error(f)
			}
		})
	}
}

// Evaluate runs the same cases as Run and returns their results instead of
// failing tb. An error means the cases could not be read.
func Evaluate(tb testing.TB, d Driver, opts Options) ([]Result, error) {
	cases, err := opts.load(d)
	if err != nil {
		return nil, err
	}
	out := make([]Result, 0, len(cases))
	for _, c := range cases {
		out = append(out, Result{ID: c.ID, Failures: runCase(tb, d, c)})
	}
	return out, nil
}

// load reads and parses the case files of the source, in name order.
func (o Options) load(d Driver) ([]*sourceCase, error) {
	if d.Open == nil {
		return nil, errors.New("sourcetest: the driver has no Open")
	}
	if o.Source == "" || strings.ContainsAny(o.Source, `/\`) || o.Source == "." || o.Source == ".." {
		return nil, fmt.Errorf("sourcetest: source %q is not one directory name", o.Source)
	}
	fsys := o.Fixtures
	if fsys == nil {
		var err error
		if fsys, err = adaptertest.DefaultFixtures(); err != nil {
			return nil, err
		}
	}
	dir := path.Join("sources", o.Source)
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("sourcetest: %w", err)
	}
	var cases []*sourceCase
	for _, e := range entries {
		if e.IsDir() || path.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("sourcetest: %w", err)
		}
		c, err := parseCase(b)
		if err != nil {
			return nil, fmt.Errorf("sourcetest: %s/%s: %w", dir, e.Name(), err)
		}
		cases = append(cases, c)
	}
	if len(cases) == 0 {
		return nil, fmt.Errorf("sourcetest: no case in %s", dir)
	}
	return cases, nil
}

// run is the state of one case.
type run struct {
	c     *sourceCase
	clock *clock.Fake
	fails []string
}

func (r *run) failf(format string, args ...any) {
	r.fails = append(r.fails, fmt.Sprintf(format, args...))
}

// guard runs f and turns a panic into a failure.
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

func (r *run) at(t *int64) time.Time {
	if t == nil {
		return time.Unix(*r.c.Now, 0)
	}
	return time.Unix(*t, 0)
}

// runCase runs one case and returns its failures.
func runCase(tb testing.TB, d Driver, c *sourceCase) []string {
	r := &run{c: c}
	if m := c.model(); m != d.Model {
		r.failf("the case's source model is %s; the driver reads %s", m, d.Model)
		return r.fails
	}
	start := time.Unix(*c.Now, 0)
	if len(c.Steps) > 0 {
		start = r.at(c.Steps[0].At)
	} else if len(c.Reads) > 0 {
		start = r.at(c.Reads[0].At)
	}
	r.clock = clock.NewFake(start)
	hooks := &adaptertest.Hooks{}
	var subj Subject
	var err error
	if !r.guard("Open", func() { subj, err = d.Open(tb, Env{Source: c.Source, Clock: r.clock, Hooks: hooks}) }) {
		return r.fails
	}
	if err != nil {
		r.failf("Open: %v", err)
		return r.fails
	}
	if subj.Reader == nil {
		r.failf("Open returned no Reader")
		return r.fails
	}
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	for i, s := range c.Steps {
		if subj.Apply == nil {
			r.failf("the case has steps and the subject has no Apply")
			return r.fails
		}
		r.clock.Set(r.at(s.At))
		var err error
		if !r.guard(fmt.Sprintf("steps[%d]", i), func() { err = subj.Apply(ctx, s.Inbound, s.Expect) }) {
			continue
		}
		if err != nil {
			r.failf("steps[%d]: %v", i, err)
		}
	}
	for i, rd := range c.Reads {
		r.clock.Set(r.at(rd.At))
		r.read(ctx, i, subj.Reader, rd)
	}
	for _, name := range hooks.Fired() {
		if slices.Contains(c.MustNotCall, name) {
			r.failf("the source called %s, which the case forbids", name)
		}
	}
	return r.fails
}

// read makes one read and checks it.
func (r *run) read(ctx context.Context, i int, reader adapter.ClaimReader, rd read) {
	where := fmt.Sprintf("reads[%d] %s", i, rd.NativePath)
	cc := adapter.ClaimContext{Principal: adapter.Principal{ID: rd.Principal}}
	if rd.Intent != nil {
		cc.Intent = *rd.Intent
	}
	if rd.Operation != nil {
		cc.Operation = *rd.Operation
	}
	var (
		c   adapter.NativeClaim
		err error
	)
	if !r.guard(where, func() { c, err = reader.ReadNativeClaim(ctx, rd.NativePath, cc) }) {
		return
	}
	now := r.clock.Now()
	e := rd.Expect
	if e.Outcome == outError {
		if err == nil {
			r.failf("%s: a claim, want an error", where)
			return
		}
		r.wantReason(where, e.ReasonCode, err)
		return
	}
	if err != nil {
		r.failf("%s: %v, want a claim", where, err)
		return
	}
	limit := now.Add(skew)
	for _, tm := range []struct {
		name string
		t    time.Time
	}{{"observed_at", c.ObservedAt}, {"status_checked_at", c.StatusCheckedAt}} {
		if !tm.t.IsZero() && tm.t.After(limit) {
			r.failf("%s: %s %d is later than the read's time plus the skew, %d", where, tm.name, tm.t.Unix(), limit.Unix())
		}
	}
	if c.SourceID == "" {
		r.failf("%s: the claim names no source", where)
	}
	if e.SourceID != "" && c.SourceID != e.SourceID {
		r.failf("%s: source_id %q, want %q", where, c.SourceID, e.SourceID)
	}
	if len(e.Value) > 0 {
		got, err := json.Marshal(c.Value)
		if err != nil {
			r.failf("%s: the value does not encode as JSON: %v", where, err)
		} else if eq, err := jsonEqual(e.Value, got); err != nil {
			r.failf("%s: value: %v", where, err)
		} else if !eq {
			r.failf("%s: value %s, want %s", where, got, e.Value)
		}
	}
	r.wantTime(where, "observed_at", e.ObservedAt, c.ObservedAt)
	r.wantTime(where, "status_checked_at", e.StatusCheckedAt, c.StatusCheckedAt)
}

// wantTime checks a time against an expected member: absent is not checked,
// null requires the zero time, a number requires those Unix seconds.
func (r *run) wantTime(where, name string, want json.RawMessage, got time.Time) {
	if len(want) == 0 {
		return
	}
	if string(bytes.TrimSpace(want)) == "null" {
		if !got.IsZero() {
			r.failf("%s: %s %d, want none", where, name, got.Unix())
		}
		return
	}
	var sec int64
	if err := json.Unmarshal(want, &sec); err != nil {
		r.failf("%s: expected %s is not Unix seconds: %v", where, name, err)
		return
	}
	if got.IsZero() || got.Unix() != sec {
		g := "none"
		if !got.IsZero() {
			g = fmt.Sprint(got.Unix())
		}
		r.failf("%s: %s %s, want %d", where, name, g, sec)
	}
}

// sentinels are the sentinel errors of package adapter.
var sentinels = []error{
	adapter.ErrInvalidMessage,
	adapter.ErrInvalidProof,
	adapter.ErrContextMismatch,
	adapter.ErrDependencyUnavailable,
	adapter.ErrUnsupportedRequirement,
	adapter.ErrUnsupportedPurpose,
	adapter.ErrMissingField,
}

// wantReason checks the code of err against want, when the case names one,
// and that err wraps the sentinel of that code.
func (r *run) wantReason(where, want string, err error) {
	if want == "" {
		return
	}
	got, ok := adapter.CodeOf(err)
	switch {
	case !ok:
		r.failf("%s: the error carries no draft 13.4 code, want %s: %v", where, want, err)
		return
	case string(got) != want:
		r.failf("%s: error code %s, want %s: %v", where, got, want, err)
		return
	}
	for _, s := range sentinels {
		if c, _ := adapter.CodeOf(s); string(c) == want && !errors.Is(err, s) {
			r.failf("%s: the error carries the code %s but does not wrap its sentinel: %v", where, want, err)
		}
	}
}

// jsonEqual reports whether a and b are the same JSON data: object member
// order is ignored, array order is not (draft 8.4).
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
