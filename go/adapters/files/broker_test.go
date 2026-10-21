package files_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	enrollmem "hop.top/pact-go/adapter/enroll/memory"
	"hop.top/pact-go/adapters/files"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// caseWorld loads the world of the files case id.
func caseWorld(t *testing.T, id string) *world {
	t.Helper()
	fsys, err := adaptertest.DefaultFixtures()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := adaptertest.Load(fsys, "files")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		if c.ID == id {
			w, err := loadWorld(c.NativeState)
			if err != nil {
				t.Fatal(err)
			}
			w.hooks = &adaptertest.Hooks{}
			return w
		}
	}
	t.Fatalf("no case %s", id)
	return nil
}

// testNow is the default now of the cases.
var testNow = time.Unix(1792080000, 0)

// brokerOf builds the broker of a world with its contexts completed, an empty
// enrollment registry and mutate applied to the configuration.
func brokerOf(t *testing.T, w *world, clk *clock.Fake, mutate ...func(*files.Config)) *files.Broker {
	t.Helper()
	sc := &seedClock{base: clk}
	cfg, err := w.config(sc)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Registry = enrollmem.New(enrollmem.WithSharedWorkloads())
	for _, m := range mutate {
		m(&cfg)
	}
	b, err := files.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.seedContexts(b, sc); err != nil {
		t.Fatal(err)
	}
	return b
}

const (
	aliceSID = "S-1-5-21-1004336348-1177238915-682003330-1105"
	alicePID = "files:S-1-5-21-1004336348-1177238915-682003330:" + aliceSID
	bobPID   = "files:S-1-5-21-1004336348-1177238915-682003330:S-1-5-21-1004336348-1177238915-682003330-1106"
	agentA   = "https://agents.acme.example/report-reader"
	agentB   = "https://agents.acme.example/report-summarizer"
)

func aliceOf(w *world) adapter.Principal {
	return adapter.Principal{ID: alicePID, Realm: w.realm(), Workload: alicePID, Mechanism: files.Mechanism, AuthenticatedAt: testNow.Add(-120 * time.Second)}
}

func readOp(w *world, opID string) core.OperationContext {
	return core.OperationContext{
		OperationID: opID, EnvironmentID: w.realm().EnvironmentID, PrincipalID: alicePID,
		Action: files.ActionRead, Resources: []string{"file:report-q3"}, Method: http.MethodGet,
		TargetURI: w.st.Gateway.Origin + "/files/report-q3/content", BodyDigest: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
		Headers: map[string]string{},
	}
}

func fired(w *world, hook string) bool {
	for _, h := range w.hooks.Fired() {
		if h == hook {
			return true
		}
	}
	return false
}

// TestHandleIsolation is FILES-05: a handle opened for one task is never
// served for another task, operation, agent or principal, and such a lookup
// leaves the owner's handle untouched (profile HI-1). The owner then reads the
// contents through the verified handle, once.
func TestHandleIsolation(t *testing.T) {
	w := caseWorld(t, "FILES-03.read-granted")
	clk := clock.NewFake(testNow)
	b := brokerOf(t, w, clk)
	ctx := files.WithTask(context.Background(), files.TaskBinding{TaskID: "task-q3-1", AgentID: agentA})
	d, err := b.AuthorizeNative(ctx, aliceOf(w), readOp(w, "op-1"))
	if err != nil || d.Effect != adapter.EffectAllow {
		t.Fatalf("AuthorizeNative = %+v, %v; want ALLOW", d, err)
	}
	owner := files.HandleKey{Realm: w.realm(), PrincipalID: alicePID, TaskID: "task-q3-1", OperationID: "op-1", AgentID: agentA}
	others := map[string]files.HandleKey{
		"another task":      {Realm: owner.Realm, PrincipalID: alicePID, TaskID: "task-q3-2", OperationID: "op-1", AgentID: agentA},
		"another operation": {Realm: owner.Realm, PrincipalID: alicePID, TaskID: "task-q3-1", OperationID: "op-2", AgentID: agentA},
		"another agent":     {Realm: owner.Realm, PrincipalID: alicePID, TaskID: "task-q3-1", OperationID: "op-1", AgentID: agentB},
		"another principal": {Realm: owner.Realm, PrincipalID: bobPID, TaskID: "task-q3-1", OperationID: "op-1", AgentID: agentA},
		"another realm": {Realm: adapter.Realm{TenantID: "globex", EnvironmentID: owner.Realm.EnvironmentID},
			PrincipalID: alicePID, TaskID: "task-q3-1", OperationID: "op-1", AgentID: agentA},
	}
	for name, k := range others {
		var out bytes.Buffer
		n, err := b.Execute(context.Background(), k, &out)
		if !errors.Is(err, adapter.ErrContextMismatch) || n != 0 || out.Len() != 0 {
			t.Errorf("%s: Execute = %d bytes, %v; want CONTEXT_MISMATCH and no bytes", name, n, err)
		}
	}
	if fired(w, "execute") {
		t.Fatal("a lookup by another tuple read the owner's handle")
	}
	var out bytes.Buffer
	if _, err := b.Execute(context.Background(), owner, &out); err != nil {
		t.Fatalf("owner: Execute = %v", err)
	}
	if got := out.String(); got != "contents of report-q3\n" {
		t.Errorf("owner read %q", got)
	}
	if _, err := b.Execute(context.Background(), owner, &bytes.Buffer{}); !errors.Is(err, adapter.ErrContextMismatch) {
		t.Errorf("second read of the owner's handle = %v; want CONTEXT_MISMATCH: the handle closes when its operation ends", err)
	}
	if w.opens != 1 {
		t.Errorf("%d opens; the broker opens once and reads through that handle (PB-7)", w.opens)
	}
	for i, h := range w.handles {
		if !h.closed {
			t.Errorf("handle %d is still open", i)
		}
	}
}

// TestHandleLifetime: a handle closes when its task ends or its lifetime
// passes, whichever comes first, and is then never read (profile HI-2). A
// handle past its lifetime that nobody asks for is closed at the next access
// of another.
func TestHandleLifetime(t *testing.T) {
	w := caseWorld(t, "FILES-03.read-granted")
	clk := clock.NewFake(testNow)
	b := brokerOf(t, w, clk)
	key := func(task string) files.HandleKey {
		return files.HandleKey{Realm: w.realm(), PrincipalID: alicePID, TaskID: task, OperationID: "op-" + task, AgentID: agentA}
	}
	for _, task := range []string{"t-ends", "t-expires", "t-swept"} {
		ctx := files.WithTask(context.Background(), files.TaskBinding{TaskID: task, AgentID: agentA})
		if _, err := b.AuthorizeNative(ctx, aliceOf(w), readOp(w, "op-"+task)); err != nil {
			t.Fatal(err)
		}
	}
	b.EndTask("t-ends")
	if _, err := b.Execute(context.Background(), key("t-ends"), &bytes.Buffer{}); !errors.Is(err, adapter.ErrContextMismatch) {
		t.Errorf("after EndTask: Execute = %v; want CONTEXT_MISMATCH", err)
	}
	clk.Advance(300*time.Second + time.Nanosecond)
	if _, err := b.Execute(context.Background(), key("t-expires"), &bytes.Buffer{}); err == nil {
		t.Error("a handle older than handle_max_lifetime_seconds was read")
	}
	if fired(w, "execute") {
		t.Error("a closed handle was read")
	}
	for i, h := range w.handles {
		if !h.closed {
			t.Errorf("handle %d is still open", i)
		}
	}
}

// TestRevertFailureMakesBrokerUnhealthy is FILES-09 beyond one call: after a
// failed revert every later protected request is refused with no open, the
// supervisor is told once, and the broker stays unhealthy (profile TA-6).
func TestRevertFailureMakesBrokerUnhealthy(t *testing.T) {
	w := caseWorld(t, "FILES-09.revert-fails")
	clk := clock.NewFake(testNow)
	var told []error
	b := brokerOf(t, w, clk, func(c *files.Config) { c.OnUnhealthy = func(err error) { told = append(told, err) } })
	ok, fails := false, true
	w.revertFails = &ok
	ctx := files.WithTask(context.Background(), files.TaskBinding{TaskID: "task-kept", AgentID: agentA})
	if _, err := b.AuthorizeNative(ctx, aliceOf(w), readOp(w, "op-kept")); err != nil {
		t.Fatalf("healthy broker: AuthorizeNative = %v", err)
	}
	w.revertFails = &fails
	if _, err := b.AuthorizeNative(context.Background(), aliceOf(w), readOp(w, "op-1")); !errors.Is(err, adapter.ErrDependencyUnavailable) {
		t.Fatalf("revert failure: AuthorizeNative = %v; want DEPENDENCY_UNAVAILABLE", err)
	}
	if b.Healthy() == nil {
		t.Fatal("the broker reports healthy after a failed revert")
	}
	w.revertFails = &ok
	opens := w.opens
	if _, err := b.AuthorizeNative(context.Background(), aliceOf(w), readOp(w, "op-2")); !errors.Is(err, adapter.ErrDependencyUnavailable) {
		t.Errorf("later request: AuthorizeNative = %v; want DEPENDENCY_UNAVAILABLE", err)
	}
	unregistered := readOp(w, "op-3")
	unregistered.Resources = []string{"file:not-registered"}
	if d, err := b.AuthorizeNative(context.Background(), aliceOf(w), unregistered); err == nil {
		t.Errorf("later request for an unregistered file: %+v; want a refusal, not a decision", d)
	}
	if out := b.CheckContext(context.Background(), files.CheckExecutionIdentity, adapter.CheckInput{Operation: readOp(w, "op-4")}); out.Result != adapter.VerdictUnknown {
		t.Errorf("later check: %+v; want UNKNOWN", out)
	}
	kept := files.HandleKey{Realm: w.realm(), PrincipalID: alicePID, TaskID: "task-kept", OperationID: "op-kept", AgentID: agentA}
	if n, err := b.Execute(context.Background(), kept, &bytes.Buffer{}); !errors.Is(err, adapter.ErrDependencyUnavailable) || n != 0 {
		t.Errorf("read of a handle opened before: %d bytes, %v; want DEPENDENCY_UNAVAILABLE and no bytes", n, err)
	}
	if w.opens != opens || fired(w, "execute") {
		t.Errorf("an unhealthy broker opened %d more files or read one", w.opens-opens)
	}
	if len(told) != 1 {
		t.Errorf("the supervisor was told %d times; want once", len(told))
	}
	_ = b.Close()
	for i, h := range w.handles {
		if !h.closed {
			t.Errorf("handle %d is still open", i)
		}
	}
}

// twoLegPackage completes an exchange on the second leg: the first token
// "leg-1" gives the output "challenge-1", and "leg-2" then completes it.
type twoLegPackage struct {
	w      *world
	closed *int
}

func (p twoLegPackage) NewExchange() (files.Exchange, error) { return &twoLeg{p: p}, nil }

type twoLeg struct {
	p    twoLegPackage
	legs int
}

func (e *twoLeg) Accept(in []byte) ([]byte, files.Token, error) {
	e.legs++
	switch {
	case e.legs == 1 && string(in) == "leg-1":
		return []byte("challenge-1"), nil, nil
	case e.legs == 2 && string(in) == "leg-2":
		return []byte("final"), &fakeToken{acc: e.p.w.byRef["alice"]}, nil
	}
	return nil, nil, errors.New("unexpected leg")
}

func (e *twoLeg) Close() error { *e.p.closed++; return nil }

func negotiate(r *http.Request, token string) *http.Request {
	r.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString([]byte(token)))
	return r
}

// TestNegotiateContinuation: a leg that needs another is not an
// authentication; its output token goes to the client in the challenge, and
// the next leg on the same connection completes the exchange (profile IA-1 to
// IA-3, RFC 4559 section 5). A failed leg discards the partial context.
func TestNegotiateContinuation(t *testing.T) {
	w := caseWorld(t, "FILES-12.completed-exchange")
	clk := clock.NewFake(testNow)
	closed := 0
	b := brokerOf(t, w, clk, func(c *files.Config) { c.Package = twoLegPackage{w: w, closed: &closed} })

	conn := b.Arrive(httptestRequest(t))
	r1 := negotiate(conn.Clone(conn.Context()), "leg-1")
	_, err := b.AuthenticateNative(r1.Context(), r1)
	var d *adapter.NativeDenial
	if !errors.As(err, &d) {
		t.Fatalf("first leg: %v; want a native denial", err)
	}
	if got, want := b.Challenge(r1), "Negotiate "+base64.StdEncoding.EncodeToString([]byte("challenge-1")); got != want {
		t.Errorf("challenge %q, want %q", got, want)
	}
	r2 := negotiate(conn.Clone(conn.Context()), "leg-2")
	p, err := b.AuthenticateNative(r2.Context(), r2)
	if err != nil || p.ID != alicePID {
		t.Fatalf("second leg: %+v, %v; want %s", p, err, alicePID)
	}
	if !p.AuthenticatedAt.Equal(testNow) {
		t.Errorf("AuthenticatedAt %v, want the instant the final leg returned", p.AuthenticatedAt)
	}

	other := b.Arrive(httptestRequest(t))
	r3 := negotiate(other.Clone(other.Context()), "leg-2")
	before := closed
	if _, err := b.AuthenticateNative(r3.Context(), r3); !errors.As(err, &d) || d.PublicReason() != adapter.DenialCredentialRejected {
		t.Errorf("out-of-order leg: %v; want CREDENTIAL_REJECTED", err)
	}
	if closed != before+1 {
		t.Error("the failed exchange's partial context was not deleted")
	}
	if got := b.Challenge(r3); got != "Negotiate" {
		t.Errorf("challenge after a failure %q, want a new exchange", got)
	}
}

func httptestRequest(t *testing.T) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "https://files.acme.example/files/report-q3/content", nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// identificationToken can identify its user but not be impersonated.
type identificationToken struct{ fakeToken }

func (identificationToken) Level() files.Level { return files.LevelIdentification }

type identificationPackage struct{ w *world }

func (p identificationPackage) NewExchange() (files.Exchange, error) {
	return identificationExchange(p), nil
}

type identificationExchange struct{ w *world }

func (e identificationExchange) Accept([]byte) ([]byte, files.Token, error) {
	return nil, &identificationToken{fakeToken{acc: e.w.byRef["alice"]}}, nil
}

func (identificationExchange) Close() error { return nil }

// TestIdentificationLevelRefused: a context whose token is below the
// impersonation level does not authenticate a request (profile IA-6).
func TestIdentificationLevelRefused(t *testing.T) {
	w := caseWorld(t, "FILES-12.completed-exchange")
	b := brokerOf(t, w, clock.NewFake(testNow), func(c *files.Config) { c.Package = identificationPackage{w: w} })
	r := b.Arrive(negotiate(httptestRequest(t), "any"))
	var d *adapter.NativeDenial
	if _, err := b.AuthenticateNative(r.Context(), r); !errors.As(err, &d) || d.PublicReason() != adapter.DenialCredentialRejected {
		t.Errorf("identification-level token: %v; want CREDENTIAL_REJECTED", err)
	}
}

// TestRegister: registration records the final path, the volume serial and
// the file identifier from one handle, and refuses a path that is not a fully
// qualified local path (profile PB-2).
func TestRegister(t *testing.T) {
	w := caseWorld(t, "FILES-03.read-granted")
	e, err := files.Register(fakeFS{w: w}, "file:report-q3", `D:\Shares\Reports\q3-summary.txt`)
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := w.registry()
	if want := reg["file:report-q3"]; e != want {
		t.Errorf("Register = %+v, want %+v", e, want)
	}
	for _, bad := range []string{
		`Shares\Reports\q3-summary.txt`,
		`D:Shares\q3-summary.txt`,
		`D:\Shares\..\Restricted\payroll-2026-09.txt`,
		`\\.\D:\Shares\Reports\q3-summary.txt`,
		`\\?\D:\Shares\Reports\q3-summary.txt`,
		`\\fs02\reports\q3-summary.txt`,
		`D:\Shares\Reports\q3-summary.txt:secret`,
		`D:/Shares/Reports/q3-summary.txt`,
	} {
		if _, err := files.Register(fakeFS{w: w}, "file:x", bad); err == nil {
			t.Errorf("Register(%q) succeeded", bad)
		}
	}
}

// TestCancelledRequestOpensNothing: a request whose context is already done
// is not authorized and opens nothing.
func TestCancelledRequestOpensNothing(t *testing.T) {
	w := caseWorld(t, "FILES-03.read-granted")
	b := brokerOf(t, w, clock.NewFake(testNow))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.AuthorizeNative(ctx, aliceOf(w), readOp(w, "op-1")); err == nil {
		t.Error("a cancelled request was authorized")
	}
	if w.opens != 0 {
		t.Errorf("a cancelled request opened %d files", w.opens)
	}
}

// TestPrincipalID checks the identifier of identity-mapping section 3.3.
func TestPrincipalID(t *testing.T) {
	got, err := files.PrincipalID(aliceSID)
	if err != nil || got != alicePID {
		t.Errorf("PrincipalID = %q, %v; want %q", got, err, alicePID)
	}
	for _, bad := range []string{"", "S-1", "s-1-5-21-1-2", "S-1-5-21-1-2 ", "ACME\\alice", "S-1-5-21-x-2"} {
		if _, err := files.PrincipalID(bad); err == nil {
			t.Errorf("PrincipalID(%q) succeeded", bad)
		}
	}
}
